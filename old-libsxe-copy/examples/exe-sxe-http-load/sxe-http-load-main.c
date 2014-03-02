/* Copyright (c) 2010 Sophos Group.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h> /* for fork() */
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>

#include "ev.h"
#include "sxe.h"
#include "sxe-log.h"
#include "sxe-time.h"
#include "sxe-pool.h"
#include "sxe-util.h"

#define DEFAULT_HOST_STRING             "www.google.com"
#define DEFAULT_CLIENT_IP_START         "127.0.0"
#define DEFAULT_CLIENT_IP_LOW           1
#define DEFAULT_CLIENT_IP_HIGH          1
#define DEFAULT_SERVER_IP               "127.0.0.1"
#define DEFAULT_SERVER_PORT             80
#define DEFAULT_CONCURRENT_CONNECTIONS  1

#define DEFAULT_TOTAL_DESIRED_QUERIES   1
#define DEFAULT_QUERIES_PER_CONNECT     2
#define DEFAULT_SLURP_COUNT             1
#define DEFAULT_LOITER_TIME             5
#define DEFAULT_QUERY_TIMEOUT           10
#define DEFAULT_STOP_ON_SERVER_CLOSE    1
#define DEFAULT_CONNECT_RAMP         10

// Reserve a 500 MB of virtual memory to pre-calculate packets into
// Set an arbitrary limit on pre-calculate packets of 0.5 million
#define SXE_LOAD_SLURP_BUF_SIZE        (512*1024*1024)
#define SXE_LOAD_SLURP_MAXIMUM         (500000)

//                         e.g.  255 .   255 .   255 .   255 \0 */
#define MAX_CHARS_IN_IP_ADDRESS (3 + 1 + 3 + 1 + 3 + 1 + 3 + 1)

#define HTTP_OK "HTTP/1.1 200 OK"
#define HTTP_OK_LENGTH (sizeof(HTTP_OK) - 1)

typedef enum SXE_LOAD_CONNECTION_STATES {
    SXE_LOAD_CONNECTION_STATE_FREE = 0,
    SXE_LOAD_CONNECTION_STATE_AWAITING_CONNECT,
    SXE_LOAD_CONNECTION_STATE_AWAITING_FIRST_PACKET,
    SXE_LOAD_CONNECTION_STATE_AWAITING_REMAINING_PACKETS,
    SXE_LOAD_CONNECTION_NUMBER_OF_STATES
} SXE_LOAD_CONNECTION_STATES;

typedef struct SXE_LOAD_CONNECTION {
    SXE_TIME       connecting_time;
    SXE_TIME       connected_time;
    SXE_TIME       start_query_time;
    SXE_TIME       finished_query_time;
    SXE          * connection;
    unsigned int   queries_completed;
    unsigned int   query_response_size;
    unsigned int   query_read_so_far;
} SXE_LOAD_CONNECTION;

static SXE_LOAD_CONNECTION * sxe_load_connection_pool;

static const char          * sxe_load_client_ip_range_start                                 = DEFAULT_CLIENT_IP_START;
static unsigned int          sxe_load_client_ip_range_low                                   = DEFAULT_CLIENT_IP_LOW;
static unsigned int          sxe_load_client_ip_range_high                                  = DEFAULT_CLIENT_IP_HIGH;
static char                  sxe_load_client_ip_as_text[256][MAX_CHARS_IN_IP_ADDRESS];
static unsigned int          sxe_load_client_ip_count                                       = 0;
static unsigned int          sxe_load_client_ip_index                                       = 0;
static unsigned int          sxe_load_next_port                                             = 65535;
static const char          * sxe_load_server_ip                                             = DEFAULT_SERVER_IP;
static unsigned int          sxe_load_server_port                                           = DEFAULT_SERVER_PORT;

static const char          * sxe_load_host_string                                           = DEFAULT_HOST_STRING;;
static unsigned int          sxe_load_concurrent_connections                                = DEFAULT_CONCURRENT_CONNECTIONS;
static unsigned int          sxe_load_queries_per_connect                                   = DEFAULT_QUERIES_PER_CONNECT;
static unsigned int          sxe_load_connect_ramp                                          = DEFAULT_CONNECT_RAMP;

static unsigned int          sxe_load_total_desired_queries                                 = DEFAULT_TOTAL_DESIRED_QUERIES;
static unsigned int          sxe_load_total_queries_count                                   = 0;
static unsigned int          sxe_load_total_queries_count_last_second                       = 0;
static unsigned int          sxe_load_connect_count                                         = 0;
static unsigned int          sxe_load_connect_count_last_second                             = 0;
static unsigned int          sxe_load_close_count                                           = 0;
static unsigned int          sxe_load_close_count_last_second                               = 0;
static unsigned int          sxe_load_writen_bytes                                          = 0;
static unsigned int          sxe_load_read_bytes                                            = 0;
static SXE_TIME              sxe_load_query_latency_sum_last_second                         = 0;
static SXE_TIME              sxe_load_query_latency_best_last_second                        = 0;
static SXE_TIME              sxe_load_query_latency_worst_last_second                       = 0;

static unsigned char         sxe_load_precalculated_query_memory[SXE_LOAD_SLURP_BUF_SIZE];
static unsigned char       * sxe_load_precalculated_query[SXE_LOAD_SLURP_MAXIMUM];
static size_t                sxe_load_precalculated_query_size[SXE_LOAD_SLURP_MAXIMUM];
static unsigned int          sxe_load_precalculated_querys_count                            = 0;
static unsigned int          sxe_load_precalculated_querys_index                            = 0;
static unsigned int          sxe_load_slurp_count                                           = DEFAULT_SLURP_COUNT;

static unsigned int          sxe_load_query_timeout                                         = DEFAULT_QUERY_TIMEOUT;
static unsigned int          sxe_load_seconds_without_a_read_event                          = 0;
static unsigned int          sxe_load_loiter_time                                           = DEFAULT_LOITER_TIME;
static unsigned int          sxe_load_stop_on_server_close                                  = DEFAULT_STOP_ON_SERVER_CLOSE;
ev_timer                     sxe_load_reporter_timer;

static const char canned_query_keep_alive[] = "GET %.*s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nUser-Agent: sxe-http-load\r\nAccept: */*\r\n\r\n";

static void sxe_load_event_close_tcp(SXE * this);
static void sxe_load_event_connect_tcp(SXE * this);
static void sxe_load_event_read_client_tcp(SXE * this, int length);
static void sxe_load_send_next_query(SXE * this);


static int
parse_content_length(const char * buf, int buf_len)
{
#define CONT_LEN     "Content-Length: "
#define CONT_LEN_LEN (sizeof(CONT_LEN) - 1)
    int    i;
    int    start_of_num;
    int    num_len;
    int    num;
    int    actual_con_len;
    char   con_len_str[11];

    for (i = 0; i < buf_len; i++) {
        if (buf[i] == 'C') {
            if (strncmp(buf + i, CONT_LEN, CONT_LEN_LEN) == 0) {
                start_of_num = i + CONT_LEN_LEN;
                goto PARSE_LENGTH;
            }
        }
    }
    return -1;

PARSE_LENGTH:
    for (i = start_of_num; i < buf_len; i++) {
        if (buf[i] == '\r') {
            if (buf[i + 1] == '\n') {
                num_len = i - start_of_num;
                if (num_len > (int)sizeof(con_len_str) - 1) {
                    return -1;
                }
                goto COUNT_LENGTH;
            }
            return -1;
        }
    }
    return -1;

COUNT_LENGTH:
    memcpy(con_len_str, buf + start_of_num, num_len);
    con_len_str[num_len] = '\0';
    num = atoi(con_len_str);

#define END_HEADER "\r\n\r\n"
#define END_HEADER_LEN (sizeof(END_HEADER) - 1)
    for(i = start_of_num + num_len + 1; i < buf_len; i++) {
        if (buf[i] == '\r') {
            if (strncmp(buf + i, END_HEADER, END_HEADER_LEN) == 0) {
                goto COUNT_HEADER_REMAINING;
            }
        }
    }
    return -1;

COUNT_HEADER_REMAINING:
    actual_con_len = buf_len - (i + END_HEADER_LEN);
    if (actual_con_len > num) {
        return -1;
    }
    return num - actual_con_len;
}


static void
sxe_load_connect_ramp_tcp(void)
{
    unsigned int   i;
    SXE_RETURN     result;
    unsigned int   connection_id;

    SXEE60("tcp_connect_ramp()");

    for (i = 0; i < sxe_load_connect_ramp; i++) {
        connection_id = sxe_pool_set_oldest_element_state(sxe_load_connection_pool, SXE_LOAD_CONNECTION_STATE_FREE,
                                                                                    SXE_LOAD_CONNECTION_STATE_AWAITING_CONNECT);
        if (connection_id == SXE_POOL_NO_INDEX) {
            SXEL60("All connections established");
            goto SXE_EARLY_OUT;
        }

        /* loop until we can bind and connect successfully (port/ip chosen might already be inuse by the system) */
        do {
            sxe_load_connection_pool[connection_id].connection = sxe_new_tcp(NULL, sxe_load_client_ip_as_text[sxe_load_client_ip_index],
                                                                            sxe_load_next_port, sxe_load_event_connect_tcp,
                                                                            sxe_load_event_read_client_tcp, sxe_load_event_close_tcp);
            result = sxe_connect(sxe_load_connection_pool[connection_id].connection, sxe_load_server_ip, sxe_load_server_port);

            sxe_load_client_ip_index++;
            if (sxe_load_client_ip_index == sxe_load_client_ip_count) {
                sxe_load_client_ip_index = 0;
                sxe_load_next_port--;
                if (sxe_load_next_port <= 1024) {
                    sxe_load_next_port = 65535;
                }
            }

            if (result != SXE_RETURN_OK) {
                sxe_close(sxe_load_connection_pool[connection_id].connection);
            }
        } while (result != SXE_RETURN_OK);

        SXEL60("Starting new tcp connection");
        /* save the pool index in the SXE extra data */
        SXE_USER_DATA_AS_INT(sxe_load_connection_pool[connection_id].connection) = connection_id;
        sxe_load_connection_pool[connection_id].connecting_time = sxe_time_get();
        sxe_load_connection_pool[connection_id].queries_completed = 0;
    }

SXE_EARLY_OR_ERROR_OUT:
    SXER60("return");
}


static void
sxe_load_event_close_tcp(SXE * this)
{
    SXE_UNUSED_ARGUMENT(this);
    SXEE60I("event_close()");
    SXEL10I("Server sent load tool a tcp close!");
    if (sxe_load_stop_on_server_close) {
        exit(0);
    }
    SXER60I("return");
}


static void
sxe_load_event_connect_tcp(SXE * this)
{
    unsigned int  connection_id = SXE_USER_DATA_AS_INT(this);

    SXEE60I("event_connect()");

    sxe_pool_set_indexed_element_state(sxe_load_connection_pool, connection_id, SXE_LOAD_CONNECTION_STATE_AWAITING_CONNECT,
                                                                                SXE_LOAD_CONNECTION_STATE_AWAITING_FIRST_PACKET);
    sxe_load_connection_pool[connection_id].connected_time = sxe_time_get();
    SXE_TIME seconds_to_connect = sxe_load_connection_pool[connection_id].connected_time
                                - sxe_load_connection_pool[connection_id].connecting_time;

    if (seconds_to_connect > sxe_time_from_unix_time(2)) {
        SXEL11I("finished connection to peer in %f seconds (suspiciously long time)", sxe_time_to_double_seconds(seconds_to_connect));
    } else {
        SXEL61I("finished connection to peer in %f seconds", sxe_time_to_double_seconds(seconds_to_connect));
    }
    sxe_load_connect_count++;

    sxe_load_connection_pool[connection_id].start_query_time = sxe_load_connection_pool[connection_id].connected_time;
    sxe_load_send_next_query(this);
    sxe_load_connect_ramp_tcp();

SXE_EARLY_OR_ERROR_OUT:
    SXER60I("return");
}


static void
sxe_load_send_next_query(SXE * this)
{
    SXEE60I("sxe_load_send_next_query()");

    if (sxe_load_total_queries_count == sxe_load_total_desired_queries) {
        SXEL60I("Completed all queries, closing this connection");
        sxe_close(this);
        sxe_load_close_count++;
        goto SXE_EARLY_OUT;
    }
    sxe_load_total_queries_count++;

    sxe_write(this, sxe_load_precalculated_query[sxe_load_precalculated_querys_index],
                    sxe_load_precalculated_query_size[sxe_load_precalculated_querys_index]);

    SXEL62I("Sending tcp query: '%.*s'", sxe_load_precalculated_query_size[sxe_load_precalculated_querys_index],
           sxe_load_precalculated_query[sxe_load_precalculated_querys_index]);

    sxe_load_writen_bytes += sxe_load_precalculated_query_size[sxe_load_precalculated_querys_index];
    sxe_load_precalculated_querys_index++;
    sxe_load_precalculated_querys_index = (sxe_load_precalculated_querys_index >= sxe_load_precalculated_querys_count)
                                           ? 0 : sxe_load_precalculated_querys_index;
SXE_EARLY_OR_ERROR_OUT:
    SXER60I("return");
}


static void
sxe_load_event_read_client_tcp(SXE * this, int length)
{
    unsigned int  connection_id = SXE_USER_DATA_AS_INT(this);
    int           content_len;
    SXE_TIME      latency;

    SXEE61I("event_read(length=%d)", length);
    sxe_load_read_bytes += length;

    if (sxe_pool_index_to_state(sxe_load_connection_pool, connection_id) == SXE_LOAD_CONNECTION_STATE_AWAITING_FIRST_PACKET) {
        sxe_pool_set_indexed_element_state(sxe_load_connection_pool, connection_id, SXE_LOAD_CONNECTION_STATE_AWAITING_FIRST_PACKET,
                                                                                    SXE_LOAD_CONNECTION_STATE_AWAITING_REMAINING_PACKETS);
        SXEL60I("This is the first responce packet for this query");
        if (memcmp(SXE_BUF(this), HTTP_OK, HTTP_OK_LENGTH) != 0) {
            SXEL10I("Query returned non-200 response code!");
            SXED50I(SXE_BUF(this), length);
            goto SXE_LOAD_CLOSE_THIS_CONNECTION;
        }

        content_len = parse_content_length(SXE_BUF(this), length);
        if (content_len < 0) {
            SXEL10I("Couldn't find a content length header in first packet!");
            SXED50I(SXE_BUF(this), length);
            goto SXE_LOAD_CLOSE_THIS_CONNECTION;
        }
        SXEL61I("Remaing bytes to read on this connection: '%u'", content_len);
        sxe_load_connection_pool[connection_id].query_response_size = content_len;
        sxe_load_connection_pool[connection_id].query_read_so_far   = 0;
    }
    else {
        SXEL60I("Sinking non-header packet");
        sxe_load_connection_pool[connection_id].query_read_so_far += length;
    }

    SXE_BUF_CLEAR(this);

    if (sxe_load_connection_pool[connection_id].query_read_so_far >= sxe_load_connection_pool[connection_id].query_response_size) {
        sxe_load_connection_pool[connection_id].queries_completed++;
        SXEL61I("Completed %u queries on this connection", sxe_load_connection_pool[connection_id].queries_completed);

        /* Latency stuff */
        sxe_load_connection_pool[connection_id].finished_query_time = sxe_time_get();
        latency = sxe_load_connection_pool[connection_id].finished_query_time - sxe_load_connection_pool[connection_id].start_query_time;
        sxe_load_query_latency_sum_last_second += latency;
        if (latency > sxe_load_query_latency_worst_last_second) { sxe_load_query_latency_worst_last_second = latency; }
        if (latency < sxe_load_query_latency_best_last_second)  { sxe_load_query_latency_best_last_second  = latency; }


        if (sxe_load_connection_pool[connection_id].queries_completed == sxe_load_queries_per_connect) {
SXE_LOAD_CLOSE_THIS_CONNECTION:
            SXEL60I("Closing and reopening this connection");
            sxe_close(this);
            sxe_load_close_count++;
            sxe_pool_set_indexed_element_state(sxe_load_connection_pool, connection_id, SXE_LOAD_CONNECTION_STATE_AWAITING_REMAINING_PACKETS,
                                                                                        SXE_LOAD_CONNECTION_STATE_FREE);
            sxe_load_connect_ramp_tcp();
        }
        else {
            sxe_pool_set_indexed_element_state(sxe_load_connection_pool, connection_id, SXE_LOAD_CONNECTION_STATE_AWAITING_REMAINING_PACKETS,
                                                                                        SXE_LOAD_CONNECTION_STATE_AWAITING_FIRST_PACKET);
            sxe_load_connection_pool[connection_id].start_query_time = sxe_time_get();
            sxe_load_send_next_query(this);
        }
    }

SXE_EARLY_OR_ERROR_OUT:
    SXER60I("return");
}


static void
sxe_load_event_timer_reporter_callback(EV_P_ ev_timer *timer, int revents)
{
    SXE_UNUSED_ARGUMENT(loop);
    SXE_UNUSED_ARGUMENT(timer);
    SXE_UNUSED_ARGUMENT(revents);

    unsigned int queries_in_last_second = (sxe_load_total_queries_count - sxe_load_total_queries_count_last_second);

    SXEE62("sxe_load_event_timer_reporter_callback(timer=%p, revents=%d)", timer, revents);

    SXEL19("conc/clos %5u / %5u | query/tot %5u / %7u | read/write %9u / %6u | lat %1.3f/%1.3f/%1.3f",
        sxe_load_connect_count - sxe_load_connect_count_last_second,
        sxe_load_close_count - sxe_load_close_count_last_second,
        queries_in_last_second,
        sxe_load_total_queries_count,
        sxe_load_read_bytes,
        sxe_load_writen_bytes,
        queries_in_last_second ? sxe_time_to_double_seconds(sxe_load_query_latency_best_last_second) : 0,
        queries_in_last_second ? sxe_time_to_double_seconds(sxe_load_query_latency_sum_last_second) / queries_in_last_second : 0,
        queries_in_last_second ? sxe_time_to_double_seconds(sxe_load_query_latency_worst_last_second) : 0);

    /* exit if no packets read for some seconds */
    if (sxe_load_read_bytes == 0) {
        sxe_load_seconds_without_a_read_event++;
    } else {
        sxe_load_seconds_without_a_read_event = 0;
    }

    if (sxe_load_seconds_without_a_read_event >= sxe_load_loiter_time) {
       SXEL11("Received no packets for %d seconds, stopping load-tool", sxe_load_loiter_time);
       exit(0);
    }

    sxe_load_query_latency_best_last_second  = -1;
    sxe_load_query_latency_sum_last_second   = 0;
    sxe_load_query_latency_worst_last_second = 0;

    sxe_load_connect_count_last_second       = sxe_load_connect_count;
    sxe_load_close_count_last_second         = sxe_load_close_count;
    sxe_load_total_queries_count_last_second = sxe_load_total_queries_count;
    sxe_load_read_bytes   = 0;
    sxe_load_writen_bytes = 0;

    SXER60("return");
}


static void
sxe_load_init_ip_range(void)
{
    sxe_load_client_ip_count = sxe_load_client_ip_range_high - sxe_load_client_ip_range_low + 1;
    SXEL15("generating %u client ip's from '%s.%u' to '%s.%u'", sxe_load_client_ip_count, sxe_load_client_ip_range_start,
           sxe_load_client_ip_range_low, sxe_load_client_ip_range_start, sxe_load_client_ip_range_high);
    for (unsigned int i = 0; i < sxe_load_client_ip_count; i++) {
        snprintf(&sxe_load_client_ip_as_text[i][0], MAX_CHARS_IN_IP_ADDRESS, "%s.%u", sxe_load_client_ip_range_start,
                 i + sxe_load_client_ip_range_low);
        SXEL62("generated ip: '%.*s' at index: '%u'", &sxe_load_client_ip_as_text[i][0], i);
    }

    SXEL14("connecting %d sockets to peer ip:port %s:%d from local ip %s.*", sxe_load_concurrent_connections,
           sxe_load_server_ip, sxe_load_server_port, sxe_load_client_ip_range_start);
}


static void
sxe_load_prep_slurp_data(void)
{
    char          url[8192];
    int           url_length;
    unsigned int  query_offset_tcp = 0;

    SXEL60("sxe_load_prep_slurp_data()");
    SXEL10("slurping urls...");

    do {
        if (   (NULL                   == fgets(url, sizeof(url), stdin)     )   /* read line from stdin */
            || (0                      == (url_length = strlen(url) - 1)     )   /* minus 1 ignores \n */
            || (sxe_load_slurp_count   == sxe_load_precalculated_querys_count)   /* we're only sending this many packets */
            || (SXE_LOAD_SLURP_MAXIMUM == sxe_load_precalculated_querys_count) ) /* never pre-calculate more packets than this */
        {
            SXEA10(sxe_load_precalculated_querys_count != 0, "need to read at least one url!");
            goto SXE_LOAD_FINISHED_SLURPING_URLS;
        }

        url[1 + url_length] = '\0';

        sxe_load_precalculated_query[sxe_load_precalculated_querys_count] = &sxe_load_precalculated_query_memory[query_offset_tcp];

        sxe_load_precalculated_query_size[sxe_load_precalculated_querys_count] =
            snprintf((char *)sxe_load_precalculated_query[sxe_load_precalculated_querys_count], 512, canned_query_keep_alive,
                     url_length, url, sxe_load_host_string);

        if (sxe_load_precalculated_querys_count < 1) {
            SXEL50("Example request query packet:");
            SXEL52("%.*s", sxe_load_precalculated_query_size[sxe_load_precalculated_querys_count],
                           sxe_load_precalculated_query[sxe_load_precalculated_querys_count]);
        }

        query_offset_tcp += sxe_load_precalculated_query_size[sxe_load_precalculated_querys_count];
        sxe_load_precalculated_querys_count++;

        if (sxe_load_precalculated_querys_count % 250000 == 0) {
            SXEL11("pre-calculated query packets: %u", sxe_load_precalculated_querys_count);
        }
    } while (1);

SXE_LOAD_FINISHED_SLURPING_URLS:
    return;
}


static void
sxe_load_event_timeout_query(void * array, unsigned i, void * caller_info)
{
    SXE_UNUSED_ARGUMENT(array);
    SXE_UNUSED_ARGUMENT(caller_info);
    SXE_UNUSED_ARGUMENT(i);
    SXEL10("A query timed out! (Was left in a waiting state for too long) Exiting...");
    exit(0);
}


int
main(int argc, char *argv[])
{
    int     c;
    double  state_timeouts_query[SXE_LOAD_CONNECTION_NUMBER_OF_STATES];

    struct option longopts[] = {
       { "host_string",            required_argument, NULL, 'a' },
       { "client_ip_start",        required_argument, NULL, 'b' },
       { "client_ip_low",          required_argument, NULL, 'c' },
       { "client_ip_high",         required_argument, NULL, 'd' },
       { "server_ip",              required_argument, NULL, 'e' },
       { "server_port",            required_argument, NULL, 'f' },
       { "concurrent_connections", required_argument, NULL, 'g' },
       { "slurp_count",            required_argument, NULL, 'h' },
       { "total_desired_queries",  required_argument, NULL, 'i' },
       { "loiter_time",            required_argument, NULL, 'j' },
       { "query_timeout",          required_argument, NULL, 'k' },
       { "stop_on_server_close",   required_argument, NULL, 'l' },
       { "queries_per_connect",    required_argument, NULL, 'm' },
       { "connect_ramp",            required_argument, NULL, 'n' },
       { 0, 0, 0, 0 }
    };

    if (1 == argc) { goto USAGE; }

    while ((c = getopt_long(argc, argv, "a:b:c:d:e:f:g:h:i:j:k:l:m:n:", longopts, NULL)) != -1) {
        switch (c) {
        case 'a': sxe_load_host_string            = optarg;       break;
        case 'b': sxe_load_client_ip_range_start  = optarg;       break;
        case 'c': sxe_load_client_ip_range_low    = atoi(optarg); break;
        case 'd': sxe_load_client_ip_range_high   = atoi(optarg); break;
        case 'e': sxe_load_server_ip              = optarg;       break;
        case 'f': sxe_load_server_port            = atoi(optarg); break;
        case 'g': sxe_load_concurrent_connections = atoi(optarg); break;
        case 'h': sxe_load_slurp_count            = atoi(optarg); break;
        case 'i': sxe_load_total_desired_queries  = atoi(optarg); break;
        case 'j': sxe_load_loiter_time            = atoi(optarg); break;
        case 'k': sxe_load_query_timeout          = atoi(optarg); break;
        case 'l': sxe_load_stop_on_server_close   = atoi(optarg); break;
        case 'm': sxe_load_queries_per_connect    = atoi(optarg); break;
        case 'n': sxe_load_connect_ramp           = atoi(optarg); break;

        case 0:
            break;
        case ':':   /* missing option argument */
            SXEL11("option '-%c' requires an argument", optopt);
            goto USAGE;
        case '?':   /* invalid option */
            SXEL11("sxld-load: bad option '%c'", optopt);
        default:
USAGE:      fprintf(stderr, "\nUsage: sxld-load OPTIONS...\n");
            fprintf(stderr, "  -a, --%-24s (default = %-15s)\n", "host_string"           , DEFAULT_HOST_STRING           );
            fprintf(stderr, "  -b, --%-24s (default = %-15s)\n", "client_ip_start"       , DEFAULT_CLIENT_IP_START       );
            fprintf(stderr, "  -c, --%-24s (default = %-15u)\n", "client_ip_low"         , DEFAULT_CLIENT_IP_LOW         );
            fprintf(stderr, "  -d, --%-24s (default = %-15u)\n", "client_ip_high"        , DEFAULT_CLIENT_IP_HIGH        );
            fprintf(stderr, "  -e, --%-24s (default = %-15s)\n", "server_ip"             , DEFAULT_SERVER_IP             );
            fprintf(stderr, "  -f, --%-24s (default = %-15u)\n", "server_port"           , DEFAULT_SERVER_PORT           );
            fprintf(stderr, "  -g, --%-24s (default = %-15u)\n", "concurrent_connections", DEFAULT_CONCURRENT_CONNECTIONS);
            fprintf(stderr, "  -h, --%-24s (default = %-15u)\n", "slurp_count"           , DEFAULT_SLURP_COUNT           );
            fprintf(stderr, "  -i, --%-24s (default = %-15u)\n", "total_desired_queries" , DEFAULT_TOTAL_DESIRED_QUERIES );
            fprintf(stderr, "  -j, --%-24s (default = %-15u)\n", "loiter_time"           , DEFAULT_LOITER_TIME           );
            fprintf(stderr, "  -k, --%-24s (default = %-15u)\n", "query_timeout"         , DEFAULT_QUERY_TIMEOUT         );
            fprintf(stderr, "  -l, --%-24s (default = %-15u)\n", "stop_on_server_close"  , DEFAULT_STOP_ON_SERVER_CLOSE  );
            fprintf(stderr, "  -m, --%-24s (default = %-15u)\n", "queries_per_connect"   , DEFAULT_QUERIES_PER_CONNECT   );
            fprintf(stderr, "  -n, --%-24s (default = %-15u)\n", "connect_ramp"          , DEFAULT_CONNECT_RAMP          );
            exit(1);
        }
    }

    SXEL13("using option: --%-24s= %-15s (default = %-15s)", "host_string"           , sxe_load_host_string           , DEFAULT_HOST_STRING           );
    SXEL13("using option: --%-24s= %-15s (default = %-15s)", "client_ip_start"       , sxe_load_client_ip_range_start , DEFAULT_CLIENT_IP_START       );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "client_ip_low"         , sxe_load_client_ip_range_low   , DEFAULT_CLIENT_IP_LOW         );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "client_ip_high"        , sxe_load_client_ip_range_high  , DEFAULT_CLIENT_IP_HIGH        );
    SXEL13("using option: --%-24s= %-15s (default = %-15s)", "server_ip"             , sxe_load_server_ip             , DEFAULT_SERVER_IP             );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "server_port"           , sxe_load_server_port           , DEFAULT_SERVER_PORT           );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "concurrent_connections", sxe_load_concurrent_connections, DEFAULT_CONCURRENT_CONNECTIONS);
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "slurp_count"           , sxe_load_slurp_count           , DEFAULT_SLURP_COUNT           );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "total_desired_queries" , sxe_load_total_desired_queries , DEFAULT_TOTAL_DESIRED_QUERIES );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "loiter_time"           , sxe_load_loiter_time           , DEFAULT_LOITER_TIME           );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "query_timeout"         , sxe_load_query_timeout         , DEFAULT_QUERY_TIMEOUT         );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "stop_on_server_close"  , sxe_load_stop_on_server_close  , DEFAULT_STOP_ON_SERVER_CLOSE  );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "queries_per_connect"   , sxe_load_queries_per_connect   , DEFAULT_QUERIES_PER_CONNECT   );
    SXEL13("using option: --%-24s= %-15u (default = %-15u)", "connect_ramp"          , sxe_load_connect_ramp          , DEFAULT_CONNECT_RAMP          );

    sxe_register(sxe_load_concurrent_connections + 1, 0);
    SXEV10(sxe_init(), == SXE_RETURN_OK, "failed to initialize SXE library");

    SXEA10(sxe_load_slurp_count != 0, "sxe_load_slurp_count must be greater then 0");
    sxe_load_prep_slurp_data();
    sxe_load_init_ip_range();

    sxe_timer_init (&sxe_load_reporter_timer, sxe_load_event_timer_reporter_callback, 1, 1);
    sxe_timer_start(&sxe_load_reporter_timer);

    state_timeouts_query[SXE_LOAD_CONNECTION_STATE_FREE]                       = 0;
    state_timeouts_query[SXE_LOAD_CONNECTION_STATE_AWAITING_CONNECT]           = sxe_load_query_timeout;
    state_timeouts_query[SXE_LOAD_CONNECTION_STATE_AWAITING_FIRST_PACKET]      = sxe_load_query_timeout;
    state_timeouts_query[SXE_LOAD_CONNECTION_STATE_AWAITING_REMAINING_PACKETS] = sxe_load_query_timeout;

    sxe_load_connection_pool = sxe_pool_new_with_timeouts("connection-pool", sxe_load_concurrent_connections, sizeof(SXE_LOAD_CONNECTION),
                                                          SXE_LOAD_CONNECTION_NUMBER_OF_STATES, state_timeouts_query,
                                                          sxe_load_event_timeout_query, NULL);

    sxe_load_connect_ramp_tcp();
    ev_loop(ev_default_loop(EVFLAG_AUTO), 0);

    SXEL60("sxe-load exiting");
    return 0;
}

