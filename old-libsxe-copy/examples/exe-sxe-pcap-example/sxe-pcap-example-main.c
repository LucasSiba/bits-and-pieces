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
#include "sxe-util.h"

#include <pcap/pcap.h>

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;         /* The compiled filter expression */
    char filter_exp[] = "port 53"; /* The filter expression */
    bpf_u_int32 mask;              /* The netmask of our sniffing device */
    bpf_u_int32 net;               /* The IP of our sniffing device */
    struct pcap_pkthdr header;     /* The header that pcap gives us */
    const u_char *packet;          /* The actual packet */

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            fprintf(stderr, "You might need to run as root...\n");
            return(2);
    }
    printf("Using device: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
         fprintf(stderr, "Can't get netmask for device %s\n", dev);
         net = 0;
         mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 0, 10000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);

    // Dump it
    SXED1(packet, header.caplen);

    /* And close the session */
    pcap_close(handle);

    return(0);
}

