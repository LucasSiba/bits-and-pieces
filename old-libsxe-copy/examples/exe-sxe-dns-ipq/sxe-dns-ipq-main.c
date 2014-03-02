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
#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ev.h"
#include "sxe.h"
#include "sxe-log.h"
#include "sxe-time.h"
#include "sxe-pool.h"
#include "sxe-util.h"
#include "sxe-hash.h"
#include "sha1.h"

#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <libipq.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define REQUEST_TIMEOUT            2
#define DEFAULT_BLOCK_ALL          0
#define PACKET_BUF_SIZE            2048
#define DNS_PORT                   53
#define MAX_DNS_DATA_SIZE          512
#define MAX_PACKET_IN_STORE        1000000

// this number comes from: sysctl net.core.wmem_max
#define MAX_SO_RCVBUF 131071

#define DEFAULT_IN_DATA_FILE_PATH  "./in_file.dat"
#define DEFAULT_OUT_DATA_FILE_PATH "./out_file.dat"


/*
 *   modprobe iptable_filter
 *   modprobe ip_queue
 *   apt-get install iptables-dev
 *
 *   // About djbdns:
 *   http://cr.yp.to/djbdns/run-cache-x.html
 *   http://cr.yp.to/djbdns/dnscache-conf.html
 *   http://cr.yp.to/djbdns/dnscache.html
 *
 */

static unsigned       block_all              = DEFAULT_BLOCK_ALL;
static int            raw_socket;
static int            nameserver_socket;
static unsigned short nameserver_socket_local_port;

static FILE         * in_data_file;
static const char   * in_data_file_path  = DEFAULT_IN_DATA_FILE_PATH;
static FILE         * out_data_file;
static const char   * out_data_file_path = DEFAULT_OUT_DATA_FILE_PATH;
static unsigned       write_cnt  = 0; // packets writen to file
static unsigned       lookup_cnt = 0; // packets from the nameserver
static unsigned       already_had_cnt = 0; // packets we had the answer too

typedef struct HASH_DATA_DNS_PACKET
{
    unsigned char data[MAX_DNS_DATA_SIZE];
    unsigned      data_len;
    SOPHOS_SHA1   sha1;
} HASH_DATA_DNS_PACKET;

static HASH_DATA_DNS_PACKET* hash_data_store;

struct dnshdr {
    uint16_t   id;
    uint16_t   flag;
    uint16_t   ques;
    uint16_t   ans;
    uint16_t   auth;
    uint16_t   add;
};

// current packet context
static struct iphdr  * cur_ip_hdr;
static struct udphdr * cur_udp_hdr;
static struct dnshdr * cur_dns;
static unsigned        cur_dns_len;

static void exit_sig_handler(int the_signal);

static void
construct_packet_and_respond(unsigned char * dns_response, unsigned dns_response_len)
{
    struct sockaddr_in addr;
    int                ret;

    unsigned char      buf[PACKET_BUF_SIZE];
    struct iphdr     * new_ip_hdr;
    struct udphdr    * new_udp_hdr;
    unsigned char    * new_udp_data;
    unsigned           new_udp_data_len = 0;
    struct dnshdr    * new_dns_hdr;
    unsigned           new_tot_len = 0;

    SXEE6("()");

    new_ip_hdr   = (struct iphdr  *)buf;
    new_udp_hdr  = (struct udphdr *)(buf + sizeof(struct iphdr));
    new_udp_data = buf + sizeof(struct iphdr) + sizeof(struct udphdr);
    new_dns_hdr = (struct dnshdr *)new_udp_data;

    // UDP Data
    memcpy(new_udp_data, (unsigned char *)dns_response, dns_response_len);
    new_udp_data_len = dns_response_len;
    new_dns_hdr->id  = cur_dns->id;

    // UDP HDR
    new_udp_hdr->source = cur_udp_hdr->dest;
    new_udp_hdr->dest   = cur_udp_hdr->source;
    new_udp_hdr->len    = htons(new_udp_data_len + sizeof(struct udphdr));
    new_udp_hdr->check  = 0x0; // the RFC allows this to just be zero's...

    new_tot_len = new_udp_data_len + sizeof(struct udphdr) + sizeof(struct iphdr);

    // IP HDR
    new_ip_hdr->ihl      = 5;
    new_ip_hdr->version  = 4;
    new_ip_hdr->tos      = 0;
    new_ip_hdr->tot_len  = htons(new_tot_len);
    new_ip_hdr->id       = htonl(rand());
    new_ip_hdr->frag_off = 0;
    new_ip_hdr->ttl      = 255;
    new_ip_hdr->protocol = 0x11;
    new_ip_hdr->check    = 0;
    new_ip_hdr->saddr    = cur_ip_hdr->daddr;
    new_ip_hdr->daddr    = cur_ip_hdr->saddr;

    // Sendto want's an address anyway...
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = cur_udp_hdr->source;
    addr.sin_addr.s_addr = cur_ip_hdr->saddr;

    SXEL7("New packet:");
    SXED7(buf, new_tot_len);
    ret = sendto(raw_socket, buf, new_tot_len, 0, (struct sockaddr*)&addr, sizeof(addr));

    if (ret == -1) {
        perror("sendto:");
        exit(1);
    }

    SXER6("");
}

static int
look_up_packet_and_respond(void)
{
    unsigned id;
    unsigned ret = 0;
    SOPHOS_SHA1 sha1;
    SXEE6("()");

    // + 2 skips the dns id
    SXEA1(sophos_sha1(((char *)cur_dns) + 2, cur_dns_len - 2,
                      (char *)&sha1) != NULL, "SHA1 failed!");

    if ((id = sxe_hash_look(hash_data_store, &sha1)) != SXE_HASH_KEY_NOT_FOUND) {
        SXEL6("Found an answer");
        already_had_cnt++;
        construct_packet_and_respond(hash_data_store[id].data, hash_data_store[id].data_len);
        ret = 1;
    }

    SXER6("(result: %u)", ret);
    return ret;
}

static void
add_packet_to_store(unsigned char * data, unsigned data_len)
{
    unsigned id;
    SXEE6("()");

    if ((id = sxe_hash_take(hash_data_store)) == SXE_HASH_FULL) {
        SXEL1("Hash full!!!");
        exit_sig_handler(0);
    }

    memcpy(hash_data_store[id].data, data, data_len);
    hash_data_store[id].data_len = data_len;

    // + 2 skips the dns id
    SXEA1(sophos_sha1(((char *)cur_dns) + 2, cur_dns_len - 2,
                      (char *)&hash_data_store[id].sha1) != NULL, "SHA1 failed!");

    sxe_hash_add(hash_data_store, id);
    SXER6("()");
}

static void
spoof_packet(void)
{
    fd_set             rfds;
    struct timeval     tv;
    int                retval;
    struct sockaddr_in nameserver_addr;
    unsigned char      buf[PACKET_BUF_SIZE];
    unsigned           buf_len;

    SXEE6("()");

    if (look_up_packet_and_respond() == 0) {
        lookup_cnt++;
        SXEL6("Don't have an answer, looking up in real nameserver (%u)", lookup_cnt);

        // the nameserver that the request was originally headed to
        memset(&nameserver_addr, 0, sizeof(nameserver_addr));
        nameserver_addr.sin_family      = AF_INET;
        nameserver_addr.sin_port        = cur_udp_hdr->dest;
        nameserver_addr.sin_addr.s_addr = cur_ip_hdr->daddr;

        SXEA1(sendto(nameserver_socket, (char *)cur_dns, cur_dns_len, 0,
                     (struct sockaddr *)&nameserver_addr, sizeof(nameserver_addr)) == cur_dns_len,
              "sendto did not write the whole packet???");

READ_AGAIN:
        tv.tv_sec  = REQUEST_TIMEOUT;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(nameserver_socket, &rfds);

        retval = select((nameserver_socket + 1), &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");
        }
        else if (retval) {
            SXEL6("Received and answer");
            SXEA6(FD_ISSET(nameserver_socket, &rfds), "Our descriptor is actually ready");
            buf_len = recv(nameserver_socket, buf, PACKET_BUF_SIZE, 0);
            SXED7(buf, buf_len);
            struct dnshdr * dns;
            dns = (struct dnshdr *)buf;
            SXEL7("dns_id:      '0x%hx'", ntohs(dns->id));
            SXEL7("dns_flag:    '0x%hx'", ntohs(dns->flag));
            SXEL7("dns_ques:    '0x%hx'", ntohs(dns->ques));
            SXEL7("dns_ans:     '0x%hx'", ntohs(dns->ans));
            SXEL7("dns_auth:    '0x%hx'", ntohs(dns->auth));
            SXEL7("dns_add:     '0x%hx'", ntohs(dns->add));

            // don't cache certain error codes...
            uint16_t rcode = ntohs(dns->flag) & 0x000F;
            if (rcode) {
                if (rcode == 0x0003) {
                    SXEL6("Domain doesn't exist...");
                }
                else {
                    SXEL1("Not saving packet, Rcode error: %hx", rcode);
                    goto SXE_EARLY_OUT;
                }
            }

            if (dns->id != cur_dns->id) {
                SXEL5("Answers ID doesn't match question (stale response), read again...");
                goto READ_AGAIN;
            }
            SXEA1(buf_len <= MAX_DNS_DATA_SIZE, "Read a packet bigger then 512 bytes???");
            add_packet_to_store(buf, buf_len);
            construct_packet_and_respond(buf, buf_len);
        }
        else {
            SXEL5("Nameserver request timed out");
        }
    }

SXE_EARLY_OUT:
    SXER6("");
}


static unsigned
filter_packet(ipq_packet_msg_t * packet)
{
    unsigned        ret = block_all ? NF_DROP : NF_ACCEPT;

    struct iphdr  * ip;
    struct udphdr * udp;
    struct dnshdr * dns;
    unsigned        dns_len      = 0;
    unsigned char * dns_data     = NULL;
    unsigned        dns_data_len = 0;

    SXEE6("(packet=%p, payload=%p, payload_len=%u)", packet, packet->payload, packet->data_len);

    ip  = (struct iphdr  *)   packet->payload;
    if (packet->data_len != ntohs(ip->tot_len)) {
        SXEL1("ipq payload length does not match ip header length?");
        goto SXE_ERROR_OUT;
    }
    SXEL7("ip_ptr:      '%p'",    ip);
    SXEL7("ip_ihl:      '0x%x'",  ip->ihl);
    SXEL7("ip_version:  '0x%x'",  ip->version);
    SXEL7("ip_tos:      '0x%x'",  ip->tos);
    SXEL7("ip_tot_len:  '%hu'",   ntohs(ip->tot_len));
    SXEL7("ip_id:       '%hu'",   ntohs(ip->id));
    SXEL7("ip_frag_off: '0x%hx'", ntohs(ip->frag_off));
    SXEL7("ip_ttl:      '0x%x'",  ip->ttl);
    SXEL7("ip_protocol: '0x%x'",  ip->protocol);
    SXEL7("ip_check:    '0x%hx'", ntohs(ip->check));
    SXEL7("ip_saddr:    '0x%x'",  ntohl(ip->saddr));
    SXEL7("ip_daddr:    '0x%x'",  ntohl(ip->daddr));

    udp = (struct udphdr *)  (packet->payload + (4 * ip->ihl));
    if (((unsigned char *)udp) + ntohs(udp->len) != packet->payload + packet->data_len) {
        SXEL1("UDP data length is wrong!");
        goto SXE_ERROR_OUT;
    }
    SXEL7("udp_ptr:     '%p'",    udp);
    SXEL7("udp_source:  '%hu'",   ntohs(udp->source));
    SXEL7("udp_dest:    '%hu'",   ntohs(udp->dest));
    SXEL7("udp_len:     '%hu'",   ntohs(udp->len)); // includes the length of the header
    SXEL7("udp_check:   '0x%hx'", ntohs(udp->check));

    // Port checking is now done by the IPTABLES rule created at run time
    //if (ntohs(udp->dest) != DNS_PORT || ntohs(udp->source) == nameserver_socket_local_port) {
    //    SXEL5("Destination port is wrong, or source port is our nameserver request");
    //    goto SKIP_DNS_CHECK;
    //}

    dns      = (struct dnshdr *) ((unsigned char *)udp + sizeof(struct udphdr));
    dns_len  = ntohs(udp->len) - sizeof(struct udphdr);;

    dns_data     = (unsigned char *) ((unsigned char *)dns + sizeof(struct dnshdr));
    dns_data_len = ntohs(udp->len) - sizeof(struct udphdr) - sizeof(struct dnshdr);
    // sanity checks...
    if ( (dns_data + dns_data_len != packet->payload + packet->data_len)
    ||   ((unsigned char *)dns + dns_len != packet->payload + packet->data_len)
    ||   (dns_data_len > MAX_DNS_DATA_SIZE) )
    {
        SXEL1("DNS data length calculation is wrong!");
        goto SXE_ERROR_OUT;
    }
    SXEL7("dns_id:      '0x%hx'", ntohs(dns->id));
    SXEL7("dns_flag:    '0x%hx'", ntohs(dns->flag));
    SXEL7("dns_ques:    '0x%hx'", ntohs(dns->ques));
    SXEL7("dns_ans:     '0x%hx'", ntohs(dns->ans));
    SXEL7("dns_auth:    '0x%hx'", ntohs(dns->auth));
    SXEL7("dns_add:     '0x%hx'", ntohs(dns->add));
    SXEL7("dns_data_len:'%u'",    dns_data_len);
    SXED7(dns_data, dns_data_len);

    cur_ip_hdr  = ip;
    cur_udp_hdr = udp;
    cur_dns     = dns;
    cur_dns_len = dns_len;

    spoof_packet();
    ret = NF_DROP;
    goto SXE_EARLY_OUT;

SXE_ERROR_OUT:
    SXEL6("Letting packet through");
SXE_EARLY_OUT:
    SXER6("return(%u)", ret);
    return ret;
}


static void
run_ipq_filter(void)
{
    unsigned            verdict;
    int                 status;
    unsigned char       pbuf[PACKET_BUF_SIZE];
    ipq_packet_msg_t  * packet;
    struct ipq_handle * handle;
    unsigned            loop_cnt = 0;

    handle = ipq_create_handle(0, PF_INET);
    if (handle == NULL) { goto SXE_ERROR_OUT; }

    status = ipq_set_mode(handle, IPQ_COPY_PACKET, PACKET_BUF_SIZE);
    if (status < 0) { goto SXE_ERROR_OUT; }

    int rcvbuf = MAX_SO_RCVBUF;
    status = setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (status) { goto SXE_ERROR_OUT; }

    while (true) {
        status = ipq_read(handle, pbuf, PACKET_BUF_SIZE, 0);
        if (status < 0) { goto SXE_ERROR_OUT; }

        switch (ipq_message_type(pbuf)) {

        case NLMSG_ERROR:
            SXEL1("Received error code: %d", ipq_get_msgerr(pbuf));
            exit(-1);
            break;

        case IPQM_PACKET:
            packet = ipq_get_packet(pbuf);
            SXEL6("");
            SXEL6("Packet received from queue");
            SXED6(packet->payload, packet->data_len);
            verdict = filter_packet(packet);
            status = ipq_set_verdict(handle, packet->packet_id, verdict, 0, NULL);
            if (status < 0) { goto SXE_ERROR_OUT; }
            break;

        default:
            SXEA1(false, "Unknown message type!");
            break;
        }
        loop_cnt++;
        if (loop_cnt == 10000) {
            SXEL1("Last 10K packets: '%u' answers, '%u' look ups", already_had_cnt, lookup_cnt);
            loop_cnt = 0;
            already_had_cnt = 0;
            lookup_cnt = 0;
        }
    }

    goto SXE_EARLY_OUT;
SXE_ERROR_OUT:
    ipq_perror(NULL);
SXE_EARLY_OUT:
    ipq_destroy_handle(handle);
}

static void
load_data_hash(void)
{
    unsigned id;
    unsigned x = 0;
    SXEL5("Reading data file: '%s'", in_data_file_path);

    if ((in_data_file = fopen(in_data_file_path, "r")) == 0) {
        perror("fopen:");
        exit(-1);
    }

    while(1) {
        SXEA1((id = sxe_hash_take(hash_data_store)) != SXE_HASH_FULL, "Hash full!");
        if (fread((char *)&hash_data_store[id], sizeof(HASH_DATA_DNS_PACKET), 1, in_data_file) != 1)
        { break; }
        sxe_hash_add(hash_data_store, id);
        SXEL7("ID: %u", id);
        SXED7(hash_data_store[id].data, hash_data_store[id].data_len);
        SXED7((char *)&hash_data_store[id].sha1, sizeof(SOPHOS_SHA1));
        x++;
    }

    sxe_hash_give(hash_data_store, id);
    SXEL5("Loaded '%u' packets from data file (max: '%u')", x, MAX_PACKET_IN_STORE);
    fclose(in_data_file);
}

static void
dump_data_hash_cb(unsigned id)
{
    write_cnt++;
    SXEL7("ID: %u", id);
    SXED7(hash_data_store[id].data, hash_data_store[id].data_len);
    SXED7((char *)&hash_data_store[id].sha1, sizeof(SOPHOS_SHA1));
    SXEA1(fwrite((char *)&hash_data_store[id], sizeof(HASH_DATA_DNS_PACKET), 1,out_data_file)
          == 1, "fwrite failed to write whole entry");
}

static void
exit_sig_handler(int the_signal)
{
    SXEL1("Writing Data file before exit: signal:%d", the_signal);
    if ((out_data_file = fopen(out_data_file_path, "w")) == 0) {
        perror("fopen:");
        exit(-1);
    }

    sxe_hash_walk(hash_data_store, dump_data_hash_cb);
    fclose(out_data_file);
    SXEL1("Data file writen: '%s' ('%u' packets)", out_data_file_path, write_cnt);
    exit(0);
}

int
main(int argc, char *argv[])
{
    putenv((char *)(intptr_t)"SXE_LOG_LEVEL_LIBSXE=5");

    struct option longopts[] = {
       { "block_all_queued_packets", required_argument, NULL, 'a' },
       { "in_data_file_path",        required_argument, NULL, 'b' },
       { "out_data_file_path",       required_argument, NULL, 'c' },
       { 0, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "a:b:c:", longopts, NULL)) != -1) {
        switch (c) {
            case 'a': block_all          = atoi(optarg); break;
            case 'b': in_data_file_path  =      optarg;  break;
            case 'c': out_data_file_path =      optarg;  break;
            case 0:
                break;
            case ':':   /* missing option argument */
                SXEL11("option '-%c' requires an argument", optopt);
                goto USAGE;
            case '?':   /* invalid option */
                SXEL11("bad option '%c'", optopt);
            default:
USAGE:          printf("Usage:\n");
                printf(" -a, --block_all_queued_packets (default = %-20u)\n", DEFAULT_BLOCK_ALL         );
                printf(" -b, --in_data_file_path        (default = %-20s)\n", DEFAULT_IN_DATA_FILE_PATH );
                printf(" -c, --out_data_file_path       (default = %-20s)\n", DEFAULT_OUT_DATA_FILE_PATH);
                exit(1);
        }
    }

    SXEL1("--block_all_queued_packets =%15u (default = %15u)", block_all,          DEFAULT_BLOCK_ALL         );
    SXEL1("--in_data_file_path        =%15s (default = %15s)", in_data_file_path,  DEFAULT_IN_DATA_FILE_PATH );
    SXEL1("--out_data_file_path       =%15s (default = %15s)", out_data_file_path, DEFAULT_OUT_DATA_FILE_PATH);

    // raw socket for spoofing responses
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_socket == -1) {
        perror("raw socket():");
        exit(1);
    }

    // Tell the socket, despite the 'sendto' call, we're supplying our own header
    int val = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
        SXEL1("Warning: Cannot set HDRINCL!");
        return -1;
    }

    // nameserver request udp socket
    if ((nameserver_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
       perror("socket():");
       exit(1);
    }
    struct sockaddr      local_addr;
    struct sockaddr_in * local_addr_in = (struct sockaddr_in *)&local_addr;
    memset((char *) &local_addr, 0, sizeof(local_addr));
    local_addr_in->sin_family = AF_INET;
    local_addr_in->sin_port = htons(0);
    local_addr_in->sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(nameserver_socket, &local_addr, sizeof(local_addr)) == -1) {
       perror("bind():");
       exit(1);
    }

    // get the local bound port
    struct sockaddr_in bound_addr;
    unsigned bound_addr_len = sizeof(bound_addr);
    if(getsockname(nameserver_socket, (struct sockaddr *)&bound_addr, &bound_addr_len) != 0) {
        perror("getsockname():");
        exit(1);
    }
    nameserver_socket_local_port = ntohs(bound_addr.sin_port);

    // don't filter our own packets
    char cmd[1024] = {0};
    snprintf(cmd, sizeof(cmd),  "iptables -A OUTPUT -p udp ! --source-port %hu --destination-port 53 -j QUEUE", nameserver_socket_local_port);
    SXEL1("%s", cmd);
    SXEA1(system(cmd) == 0, "Failed to create iptables rule");


    // create the hash dns packet store
    hash_data_store = sxe_hash_new_plus("hash_data_store", MAX_PACKET_IN_STORE, sizeof(HASH_DATA_DNS_PACKET),
                                        offsetof(HASH_DATA_DNS_PACKET, sha1), sizeof(SOPHOS_SHA1), SXE_HASH_OPTION_UNLOCKED);
    load_data_hash();

    // dump the data hash on exit
    signal(SIGINT, exit_sig_handler);

    SXEL1("sxe-dns-ipq running...");

    run_ipq_filter();
    return 0;
}

