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

#define DEFAULT_INNER_PORT         43
#define DEFAULT_INNER_IP           "127.0.0.1"
#define DEFAULT_REPORT_TITLE_FREQ  20

ev_timer            timer_report;
unsigned            report_title_freq;

unsigned long long  inner_read_last  = 0;
unsigned long long  inner_read       = 0;
unsigned long long  outer_write_last = 0;
unsigned long long  outer_write      = 0;

unsigned short      inner_port      = DEFAULT_INNER_PORT;
static const char * inner_ip        = DEFAULT_INNER_IP;
SXE               * inner_listener;

struct sockaddr_in inner_addr;

static void
event_inner_read(SXE * this, int length)
{
    inner_read++;
    SXEL6("Inner Read Event");
    SXED6(SXE_BUF(this), length);
    SXEL6(" ");

    outer_write++;
    sxe_write_to(this, SXE_BUF(this), length, SXE_PEER_ADDR(this));

    SXE_BUF_CLEAR(this);
}

static void
reporter_timer_cb(EV_P_ ev_timer *timer, int revents)
{
    SXE_UNUSED_ARGUMENT(loop);
    SXE_UNUSED_ARGUMENT(timer);
    SXE_UNUSED_ARGUMENT(revents);

    if (report_title_freq == 0) {
        report_title_freq = DEFAULT_REPORT_TITLE_FREQ;
        SXEL1("Inner-Red  Outer-Wrt");
        //       1234567    1234567
        //       1          2
    } else {
        report_title_freq--;
    }

    //       1        2
    SXEL1("  %7llu    %7llu",
          inner_read  - inner_read_last,
          outer_write - outer_write_last
    );

    inner_read_last  = inner_read;
    outer_write_last = outer_write;
}


int
main(int argc, char *argv[])
{
    SXE_RETURN result;

    struct option longopts[] = {
       { "inner_port",      required_argument, NULL, 'a' },
       { "inner_ip",        required_argument, NULL, 'b' },
       { 0, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "a:b:c:d:e:f:", longopts, NULL)) != -1) {
        switch (c) {
            case 'a': inner_port      = atoi(optarg); break;
            case 'b': inner_ip        =      optarg ; break;

            case 0:
                break;
            case ':':   /* missing option argument */
                SXEL11("option '-%c' requires an argument", optopt);
                goto USAGE;
            case '?':   /* invalid option */
                SXEL11("bad option '%c'", optopt);
            default:
USAGE:          printf("Usage:\n");
                printf(" -a, --%-24s (default = %-20u)\n", "inner_port",      DEFAULT_INNER_PORT);
                printf(" -b, --%-24s (default = %-20s)\n", "inner_ip"  ,      DEFAULT_INNER_IP  );
                exit(1);
        }
    }
    if (1 == argc) { goto USAGE; }

    SXEL1("--%-24s=%-25u (default = %-20u)", "inner_port",      inner_port,      DEFAULT_INNER_PORT);
    SXEL1("--%-24s=%-25s (default = %-20s)", "inner_ip"  ,      inner_ip  ,      DEFAULT_INNER_IP  );

    sxe_register(1024, 0);
    SXEV60(sxe_init (), == SXE_RETURN_OK, "failed to initialize SXE library");

    inner_listener = sxe_new_udp(NULL, inner_ip, inner_port, event_inner_read);
    result = sxe_listen(inner_listener);
    SXEA10(SXE_RETURN_OK == result, "failed to listen on inner socket");

    sxe_timer_init (&timer_report, reporter_timer_cb, 1, 1);
    sxe_timer_start(&timer_report);

    ev_loop(ev_default_loop(EVFLAG_AUTO), 0);
    return 0;
}

