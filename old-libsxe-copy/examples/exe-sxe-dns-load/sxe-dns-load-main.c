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
#include <inttypes.h>
#include <getopt.h>

#include "ev.h"
#include "sxe.h"
#include "sxe-log.h"
#include "sxe-time.h"
#include "sxe-pool.h"
#include "sxe-util.h"
#include "sxe-dns.h"

#define DEFAULT_SERVER_PORT            53
#define DEFAULT_SERVER_IP              "127.0.0.1"
#define DEFAULT_CLIENT_PORT            53053
#define DEFAULT_CLIENT_IP              "127.0.0.1"
#define DEFAULT_CONCURRENT_QUERIES     1
#define DEFAULT_TOTAL_DESIRED_QUERIES  1
#define DEFAULT_QUERY_TIME_OUT         10
#define DEFAULT_SLURP_COUNT            1
#define DEFAULT_LOITER_TIME            5
#define DEFAULT_REPORT_TITLE_FREQ      20

/**
 * Reserve 500 MB of virtual memory to pre-calculate dns packets into :-)
 * Set an arbitrary limit on pre-calculate packets of 1 million :-)
 **/
#define DNS_LOAD_DNS_BUF_SIZE          (512*1024*1024)
#define DNS_LOAD_DNS_MAXIMUM           (1000000)
#define DNS_LOAD_UDP_PORTS_RANGE       256
#define DNS_LOAD_UDP_WRITE_RAMP        10

typedef enum DNS_LOAD_UDP_QUERY_STATE {
    DNS_LOAD_UDP_QUERY_STATE_FREE = 0,
    DNS_LOAD_UDP_QUERY_STATE_AWAITING_REPLY,
    DNS_LOAD_UDP_QUERY_NUMBER_OF_STATES
} DNS_LOAD_UDP_QUERY_STATE;

typedef struct DNS_LOAD_UDP_QUERY {
    SXE_TIME     query_time;
    unsigned int query_number;
    unsigned int query_port;
} DNS_LOAD_UDP_QUERY;


static unsigned int          dns_load_server_port                               = DEFAULT_SERVER_PORT;
static const char          * dns_load_server_ip                                 = DEFAULT_SERVER_IP;
static unsigned int          dns_load_client_port                               = DEFAULT_CLIENT_PORT;
static const char          * dns_load_client_ip                                 = DEFAULT_CLIENT_IP;
static SXE                 * dns_load_udp_listener[DNS_LOAD_UDP_PORTS_RANGE];
static unsigned char         dns_load_precalculated[DNS_LOAD_DNS_BUF_SIZE];
static unsigned char       * dns_load_precalculated_addr[DNS_LOAD_DNS_MAXIMUM];
static unsigned              dns_load_precalculated_size[DNS_LOAD_DNS_MAXIMUM];
static unsigned int          dns_load_precalculated_packets_count               = 0;
static unsigned int          dns_load_precalculated_packets_index               = 0;
struct sockaddr_in           dns_load_udp_addr;
static DNS_LOAD_UDP_QUERY  * dns_load_udp_query_pool                            = NULL;

// stats
static unsigned long long    dns_load_udp_bytes_read                            = 0;
static unsigned long long    dns_load_udp_bytes_read_last                       = 0;
static unsigned long long    dns_load_udp_bytes_written                         = 0;
static unsigned long long    dns_load_udp_bytes_written_last                    = 0;
static unsigned long long    dns_load_packets_timed_out                         = 0;
static unsigned long long    dns_load_packets_timed_out_last                    = 0;

static double                dns_load_packet_latency_per_second                 = 0;
static double                dns_load_packet_latency_per_second_lo              = 65535;
static double                dns_load_packet_latency_per_second_hi              = 0.001;

static unsigned long long    dns_load_udp_query_sent_count                      = 0;
static unsigned long long    dns_load_udp_query_sent_count_last                 = 0;
static unsigned long long    dns_load_udp_query_response_count                  = 0;
static unsigned long long    dns_load_udp_query_response_count_last             = 0;
static unsigned int          dns_load_udp_query_in_flight_count                 = 0;
static unsigned int          dns_load_concurrent_queries                        = DEFAULT_CONCURRENT_QUERIES;
static unsigned long long    dns_load_total_desired_queries                     = DEFAULT_TOTAL_DESIRED_QUERIES;
static unsigned int          dns_load_seconds_without_packet                    = 0;

static unsigned int          dns_load_query_time_out                            = DEFAULT_QUERY_TIME_OUT;
static unsigned int          dns_load_slurp_count                               = DEFAULT_SLURP_COUNT;
//static unsigned long long    dns_load_nxdomain_count                            = 0;
static unsigned int          dns_load_loiter_time                               = DEFAULT_LOITER_TIME;
static double                dns_load_report_title_freq                         = 0;

static SXE_TIME              dns_load_time_at_start;
ev_timer                     dns_load_timer_report;

#define ROUND_TRIP_BUCKET_COUNT       10
#define ROUND_TRIP_BUCKET_MAX_SECONDS 2.0
#define ROUND_TRIP_BUCKET_INCREMENTS (ROUND_TRIP_BUCKET_MAX_SECONDS / ROUND_TRIP_BUCKET_COUNT)
static unsigned int          dns_load_query_round_trip_times[ROUND_TRIP_BUCKET_COUNT];

static void dns_load_event_read(SXE * this, int length);
static void dns_load_write_ramp(void);
static void dns_load_add_query_to_time_bucket(SXE_TIME);

static void
dns_load_write_ramp(void)
{
    int             i;
    unsigned char * dns_addr;
    size_t          dns_size;
    unsigned int    item;
    unsigned int    client_port;

    SXEE60("dns_load_write_ramp()");

    SXEL61("sending off up to %u udp queries (DNS_LOAD_UDP_WRITE_RAMP)", DNS_LOAD_UDP_WRITE_RAMP);
    for (i = 0; i < DNS_LOAD_UDP_WRITE_RAMP; i++)
    {
        if (dns_load_udp_query_in_flight_count == dns_load_concurrent_queries) {
            SXEL60("UDP inflight has reach UDP concurrent queries");
            goto SXE_EARLY_OUT;
        }

        if (dns_load_udp_query_sent_count == dns_load_total_desired_queries) {
            SXEL60("Total sent count has reach desired queries");
            goto SXE_EARLY_OUT;
        }

        item = sxe_pool_set_oldest_element_state(dns_load_udp_query_pool, DNS_LOAD_UDP_QUERY_STATE_FREE,
                                                 DNS_LOAD_UDP_QUERY_STATE_AWAITING_REPLY);
        if (item == SXE_POOL_NO_INDEX) {
            SXEL10("No free queries in udp query pool");
            goto SXE_EARLY_OUT;
        }

        client_port = item % DNS_LOAD_UDP_PORTS_RANGE;
        SXEA11(client_port < DNS_LOAD_UDP_PORTS_RANGE, "client port out of range: %u", client_port)

        dns_addr = dns_load_precalculated_addr[dns_load_precalculated_packets_index];
        dns_size = dns_load_precalculated_size[dns_load_precalculated_packets_index];

        // the udp seqence is the index of the pool element
        (*(unsigned short *)dns_addr) = htons(item);

        dns_load_precalculated_packets_index++;
        dns_load_precalculated_packets_index = (dns_load_precalculated_packets_index >= dns_load_precalculated_packets_count)
                                             ? 0 : dns_load_precalculated_packets_index;

        //sxe_write_to(dns_load_udp_listener[client_port], dns_addr, dns_size, &dns_load_udp_addr);
        // send everything from the same ip/port for now...

        sxe_write_to(dns_load_udp_listener[0], dns_addr, dns_size, &dns_load_udp_addr);
        SXEL60("sent udp query");

        dns_load_udp_bytes_written += dns_size;
        dns_load_udp_query_in_flight_count++;
        dns_load_udp_query_sent_count++;

        dns_load_udp_query_pool[item].query_time   = sxe_time_get();
        dns_load_udp_query_pool[item].query_number = dns_load_udp_query_sent_count;
        dns_load_udp_query_pool[item].query_port   = client_port;
    }

SXE_EARLY_OR_ERROR_OUT:
    SXER60("return (udp write ramp)");
}


static void
dns_load_add_query_to_time_bucket(SXE_TIME start)
{
    SXE_TIME      now       = sxe_time_get();
    SXE_TIME      sxe_diff  = now - start;
    double        dbl_diff  = sxe_time_to_double_seconds(sxe_diff);
    unsigned int  bindex    = dbl_diff / ROUND_TRIP_BUCKET_INCREMENTS;

    dns_load_packet_latency_per_second += dbl_diff;

    if (dbl_diff < dns_load_packet_latency_per_second_lo) { dns_load_packet_latency_per_second_lo = dbl_diff; }
    if (dbl_diff > dns_load_packet_latency_per_second_hi) { dns_load_packet_latency_per_second_hi = dbl_diff; }

    if (dbl_diff > 10.0) {
         SXEL65("Bucket latency time over 10 seconds, dbl_diff %f, start %08x %08x, now %08x %08x",
                dbl_diff, (unsigned) (start >> 32), (unsigned) start, (unsigned) (now >> 32), (unsigned) now);
    }

    if (bindex > (ROUND_TRIP_BUCKET_COUNT - 1)) { bindex = (ROUND_TRIP_BUCKET_COUNT - 1); }

    SXEL62("A query time of '%f', goes in bucket '%d'", dbl_diff, bindex);
    SXEA10(bindex < ROUND_TRIP_BUCKET_COUNT, "bad index into bucket!");
    dns_load_query_round_trip_times[bindex]++;
}


static void
dns_load_event_read(SXE * this, int length)
{
    unsigned short   item;
    char           * dns_packet = SXE_BUF(this);

    SXEE61I("dns_load_event_read(length=%d)", length);

    dns_load_udp_bytes_read += length;
    item = ntohs(*(unsigned short *)dns_packet);
    sxe_pool_set_indexed_element_state(dns_load_udp_query_pool, item, DNS_LOAD_UDP_QUERY_STATE_AWAITING_REPLY, DNS_LOAD_UDP_QUERY_STATE_FREE);

    dns_load_add_query_to_time_bucket(dns_load_udp_query_pool[item].query_time);
    dns_load_udp_query_response_count++;
    dns_load_udp_query_in_flight_count--;

    if (dns_load_udp_query_response_count < dns_load_total_desired_queries) {
        dns_load_write_ramp();
    }

SXE_EARLY_OR_ERROR_OUT:
    SXE_BUF_CLEAR(this);
    SXER60I("return");
}


static void
dns_load_event_reporter_timer_callback(EV_P_ ev_timer *timer, int revents)
{
    SXE_UNUSED_ARGUMENT(loop);
    SXE_UNUSED_ARGUMENT(timer);
    SXE_UNUSED_ARGUMENT(revents);
    SXEE6("dns_load_event_reporter_timer_callback(timer=%p, revents=%d)", timer, revents);

    sxe_pool_check_timeouts();

    if (dns_load_report_title_freq == 0) {
        dns_load_report_title_freq = DEFAULT_REPORT_TITLE_FREQ;
        SXEL1("      Last Second              |  In    |  K-Query  |Timeouts| Latency (sec) ");
        SXEL1("Snt-q Snt-byte  Rec-q Rec-byte | flight | Countdown |  /sec  | lo    avg   hi");
        //     12345  1234567  12345  1234567    12345   123456789   123456   12345 12345 12345
        //     1      2        3      4          5       6           7        8     9     10
    } else {
        dns_load_report_title_freq--;
    }

    //     1      2       3      4        5    6       7       8     9     10
    SXEL5("%5llu  %7llu  %5llu  %7llu    %5u   %9llu   %6llu   %1.3f %1.3f %1.3f",
          dns_load_udp_query_sent_count     - dns_load_udp_query_sent_count_last,
          dns_load_udp_bytes_written        - dns_load_udp_bytes_written_last,
          dns_load_udp_query_response_count - dns_load_udp_query_response_count_last,
          dns_load_udp_bytes_read           - dns_load_udp_bytes_read_last,
          dns_load_udp_query_in_flight_count,
          (dns_load_total_desired_queries - dns_load_udp_query_response_count) / 1000,
          dns_load_packets_timed_out      - dns_load_packets_timed_out_last,
          dns_load_packet_latency_per_second ?  dns_load_packet_latency_per_second_lo : 0,
          dns_load_packet_latency_per_second ? (dns_load_packet_latency_per_second / (double)(dns_load_udp_query_response_count  - dns_load_udp_query_response_count_last)) : 0,
          dns_load_packet_latency_per_second ?  dns_load_packet_latency_per_second_hi : 0
    );

    /* exit if no packets read for some seconds */
    if (dns_load_udp_query_response_count_last != dns_load_udp_query_response_count) {
        dns_load_seconds_without_packet = 0;
    } else {
        dns_load_seconds_without_packet++;
    }

    if (dns_load_seconds_without_packet >= dns_load_loiter_time) {
       SXEL1("Received no packets for %d seconds, stopping...", dns_load_loiter_time);
       /* print bucket times */
       for (int x = 0 ; x < ROUND_TRIP_BUCKET_COUNT - 1 ; x++) {
           SXEL1("MaxTime %3.1f, Count %u", (ROUND_TRIP_BUCKET_INCREMENTS * (x + 1)), dns_load_query_round_trip_times[x]);
       }
       SXEL1("Over    2.0, Count %u", dns_load_query_round_trip_times[9]);
       SXEL1("UDP Bytes Read: %" PRIu64 ", UDP Bytes Written: %" PRIu64, dns_load_udp_bytes_read, dns_load_udp_bytes_written);
       exit(0);
    }

    /* reset this after reporting */
    dns_load_packet_latency_per_second    = 0;
    dns_load_packet_latency_per_second_lo = 65535;
    dns_load_packet_latency_per_second_hi = 0.001;
    dns_load_udp_query_response_count_last = dns_load_udp_query_response_count;
    dns_load_udp_query_sent_count_last     = dns_load_udp_query_sent_count;
    dns_load_udp_bytes_read_last           = dns_load_udp_bytes_read;
    dns_load_udp_bytes_written_last        = dns_load_udp_bytes_written;
    dns_load_packets_timed_out_last        = dns_load_packets_timed_out;

    SXER6("return");
}


static void
dns_load_timeout_cb_query_pool(void * array, unsigned i, void * caller_info)
{
    SXE_UNUSED_ARGUMENT(i);
    SXE_UNUSED_ARGUMENT(array);
    SXE_UNUSED_ARGUMENT(caller_info);
    SXEE6("(array=%p, i=%u)", array, i);
    SXEL6("A query timed out. Timeout: %u", dns_load_query_time_out);
    dns_load_packets_timed_out++;
    sxe_pool_set_indexed_element_state(dns_load_udp_query_pool, i, DNS_LOAD_UDP_QUERY_STATE_AWAITING_REPLY, DNS_LOAD_UDP_QUERY_STATE_FREE);
    SXER6("");
}


static void
dns_load_init(void)
{
    int    i;
    double state_timeouts[DNS_LOAD_UDP_QUERY_NUMBER_OF_STATES];

    SXEE6("()");

    for (i = 0; i < DNS_LOAD_UDP_PORTS_RANGE; i++) {
        dns_load_udp_listener[i] = sxe_new_udp(NULL, dns_load_client_ip, i + dns_load_client_port, dns_load_event_read);
        SXEV10(sxe_listen(dns_load_udp_listener[i]), == SXE_RETURN_OK, "dns-load client failed to listen");
    }

    SXEL6("creating 64k query pool");
    state_timeouts[DNS_LOAD_UDP_QUERY_STATE_FREE]           = 0;
    state_timeouts[DNS_LOAD_UDP_QUERY_STATE_AWAITING_REPLY] = dns_load_query_time_out;
    dns_load_udp_query_pool = sxe_pool_new_with_timeouts("udp-query-pool", dns_load_concurrent_queries,
                                                         sizeof(DNS_LOAD_UDP_QUERY), DNS_LOAD_UDP_QUERY_NUMBER_OF_STATES,
                                                         state_timeouts, dns_load_timeout_cb_query_pool, NULL);

    sxe_timer_init (&dns_load_timer_report, dns_load_event_reporter_timer_callback, 1, 1);
    sxe_timer_start(&dns_load_timer_report);

    SXER6("return");
}


static void
dns_load_prep_slurp_data(void)
{
    char          url[8192]               ;
    int           url_length              ;
    unsigned char question[254]           ;
    int           question_length         ;
    unsigned int  query_offset_udp = 0    ;

    SXEL10("dns_load_prep_slurp_data()");

    do {
        if (   (NULL                  == fgets(url, sizeof(url), stdin)   )     /* read line from stdin */
            || (0                     == (url_length = strlen(url) - 1)   )     /* minus 1 ignores \n */
            || (dns_load_slurp_count == dns_load_precalculated_packets_count)   /* we're only sending this many packets */
            || (DNS_LOAD_DNS_MAXIMUM == dns_load_precalculated_packets_count) ) /* never pre-calculate more packets than this */
        {
            SXEA10(dns_load_precalculated_packets_count != 0, "need to read at least one url!");
            goto DNS_LOAD_FINISHED_SLURPING_URLS;
        }

        dns_load_precalculated_addr[dns_load_precalculated_packets_count] = &dns_load_precalculated[query_offset_udp];

        if (url_length >= (int)sizeof(question)) {
            SXEL5("Query is too big for question buffer: '%d'", url_length);
            continue;
        }

        // Dump a sample URL we're going to encode
        if (dns_load_precalculated_packets_count < 1) {
            SXEL1("example inputted url='%.*s' %d bytes", url_length, url, url_length);
        }

        ////////////////////////////// ENCODE ////////////////////////////////

        if ((question_length = sxe_dns_encode_question(question, url, url_length, NULL, 0)) == -1) {
            SXEL23("Encode failed: url='%.*s' %d bytes", url_length, url, url_length);
            continue; /* ignore this url because it didn't encode for some reason */
        }

        question_length--; // don't count the null on the end...

        // Dump a sample encoded question
        if (dns_load_precalculated_packets_count < 1) {
            SXEL1("example encoded question='%.*s' %d bytes", question_length, question, question_length);
        }

        if (sxe_dns_create_query_of_type_txt(dns_load_precalculated_addr[dns_load_precalculated_packets_count],
                                             512,
                                             &dns_load_precalculated_size[dns_load_precalculated_packets_count],
                                             0,
                                             (char *)question,
                                             question_length,
                                             NULL, 0) != SXE_RETURN_OK)
        {
            SXEL6("Create query failed:'%.*s' %d bytes", url_length, url, url_length);
            continue; /* ignore this url because it didn't convert to dns for some reason */
        }

        // Dump a sample DNS packet
        if (dns_load_precalculated_packets_count < 1) {
            SXEL1("example encoded UDP packet:");
            SXED1(dns_load_precalculated_addr[dns_load_precalculated_packets_count],
                   dns_load_precalculated_size[dns_load_precalculated_packets_count]);
            SXEL1(" ");
        }

        // NON-DNS ENCODE //
        // NOTE: leave room for an "ID" on the front (if these were real dns packets they would have one...)
        //(&(dns_load_precalculated_addr[dns_load_precalculated_packets_count]) + 2)[0] = 0x00;
        //(&(dns_load_precalculated_addr[dns_load_precalculated_packets_count]) + 2)[1] = 0x00;
        //memcpy(dns_load_precalculated_addr[dns_load_precalculated_packets_count] + 2, question, question_length);
        //dns_load_precalculated_size[dns_load_precalculated_packets_count] = question_length + 2;

        ////////////////////////////// ENCODE ////////////////////////////////

        query_offset_udp += dns_load_precalculated_size[dns_load_precalculated_packets_count];
        dns_load_precalculated_packets_count++;

        if (dns_load_precalculated_packets_count % 250000 == 0) {
            SXEL11("pre-calculated dns query packets: %u", dns_load_precalculated_packets_count);
        }
    } while (1);

DNS_LOAD_FINISHED_SLURPING_URLS:

    SXEL1("Slurped and encoded '%u' queries (max slurp: %u)", dns_load_precalculated_packets_count, dns_load_slurp_count);
    return;
}

int
main(int argc, char *argv[])
{
    struct option longopts[] = {
       { "server_port",           required_argument, NULL, 'a' },
       { "server_ip",             required_argument, NULL, 'b' },
       { "client_port_base",      required_argument, NULL, 'c' },
       { "client_ip",             required_argument, NULL, 'd' },
       { "concurrent_queries",    required_argument, NULL, 'e' },
       { "slurp_count",           required_argument, NULL, 'f' },
       { "total_desired_queries", required_argument, NULL, 'g' },
       { "query_time_out",        required_argument, NULL, 'h' },
       { "loiter_time",           required_argument, NULL, 'i' },
       { 0, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "a:b:c:d:e:f:g:h:i:", longopts, NULL)) != -1) {
        switch (c) {
            case 'a': dns_load_server_port            = atoi (optarg); break;
            case 'b': dns_load_server_ip              =       optarg ; break;
            case 'c': dns_load_client_port            = atoi (optarg); break;
            case 'd': dns_load_client_ip              =       optarg ; break;
            case 'e': dns_load_concurrent_queries     = atoi (optarg); break;
            case 'f': dns_load_slurp_count            = atoi (optarg); break;
            case 'g': dns_load_total_desired_queries  = atoll(optarg); break;
            case 'h': dns_load_query_time_out         = atoi (optarg); break;
            case 'i': dns_load_loiter_time            = atoi (optarg); break;

            case 0:
                break;
            case ':':   /* missing option argument */
                SXEL11("option '-%c' requires an argument", optopt);
                goto USAGE;
            case '?':   /* invalid option */
                SXEL11("dns-load: bad option '%c'", optopt);
            default:
USAGE:          printf("Usage:\n");
                printf(" -a, --%-24s (default = %-20u)\n", "server_port"          , DEFAULT_SERVER_PORT          );
                printf(" -b, --%-24s (default = %-20s)\n", "server_ip"            , DEFAULT_SERVER_IP            );
                printf(" -c, --%-24s (default = %-20u)\n", "client_port_base"     , DEFAULT_CLIENT_PORT          );
                printf(" -d, --%-24s (default = %-20s)\n", "client_ip"            , DEFAULT_CLIENT_IP            );
                printf(" -e, --%-24s (default = %-20u)\n", "concurrent_queries"   , DEFAULT_CONCURRENT_QUERIES   );
                printf(" -f, --%-24s (default = %-20u)\n", "slurp_count"          , DEFAULT_SLURP_COUNT          );
                printf(" -g, --%-24s (default = %-20u)\n", "total_desired_queries", DEFAULT_TOTAL_DESIRED_QUERIES);
                printf(" -h, --%-24s (default = %-20u)\n", "query_time_out"       , DEFAULT_QUERY_TIME_OUT       );
                printf(" -i, --%-24s (default = %-20u)\n", "loiter_time"          , DEFAULT_LOITER_TIME          );
                exit(1);
        }
    }
    if (1 == argc) {
        goto USAGE;
    }

    SXEL1("--%-24s= %-25u (default = %-20u)"  , "server_port"          , dns_load_server_port          , DEFAULT_SERVER_PORT          );
    SXEL1("--%-24s= %-25s (default = %-20s)"  , "server_ip"            , dns_load_server_ip            , DEFAULT_SERVER_IP            );
    SXEL1("--%-24s= %-25u (default = %-20u)"  , "client_port_base"     , dns_load_client_port          , DEFAULT_CLIENT_PORT          );
    SXEL1("--%-24s= %-25s (default = %-20s)"  , "client_ip"            , dns_load_client_ip            , DEFAULT_CLIENT_IP            );
    SXEL1("--%-24s= %-25u (default = %-20u)"  , "concurrent_queries"   , dns_load_concurrent_queries   , DEFAULT_CONCURRENT_QUERIES   );
    SXEL1("--%-24s= %-25u (default = %-20u)"  , "slurp_count"          , dns_load_slurp_count          , DEFAULT_SLURP_COUNT          );
    SXEL1("--%-24s= %-25llu (default = %-20u)", "total_desired_queries", dns_load_total_desired_queries, DEFAULT_TOTAL_DESIRED_QUERIES);
    SXEL1("--%-24s= %-25u (default = %-20u)"  , "query_time_out"       , dns_load_query_time_out       , DEFAULT_QUERY_TIME_OUT       );
    SXEL1("--%-24s= %-25u (default = %-20u)"  , "loiter_time"          , dns_load_loiter_time          , DEFAULT_LOITER_TIME          );

    /* Sanity check options */
    SXEA10(dns_load_concurrent_queries <= 65536, "dns_load_concurrent_queries must be <= than 65536");
    SXEA10(dns_load_slurp_count != 0, "dns_load_slurp_count must be greater then 0");

    dns_load_prep_slurp_data();

    memset(&dns_load_udp_addr, 0x00, sizeof(dns_load_udp_addr));
    dns_load_udp_addr.sin_family       = AF_INET;
    dns_load_udp_addr.sin_port         = htons(dns_load_server_port);
    dns_load_udp_addr.sin_addr.s_addr  = inet_addr(dns_load_server_ip);

    sxe_register(1 + DNS_LOAD_UDP_PORTS_RANGE, 0);
    SXEV60(sxe_init (), == SXE_RETURN_OK, "failed to initialize SXE library");

    dns_load_init();

    dns_load_time_at_start = sxe_time_get();
    dns_load_write_ramp();

    ev_loop(ev_default_loop(EVFLAG_AUTO), 0);

    SXEL60("dns-load exiting");
    return 0;
}

