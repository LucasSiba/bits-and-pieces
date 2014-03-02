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
#ifndef __SXE_DNS_H__
#define __SXE_DNS_H__

#include <stdint.h>
#include <stddef.h>   /* Required for size_t */

#include "sxe-log.h"
#include "sxe-socket.h"

#define SXE_DNS_PORT                  53
#define SXE_DNS_HEADER_SIZE           sizeof(struct dns_header)
#define SXE_DNS_QUESTION_OFFSET       SXE_DNS_HEADER_SIZE
#define SXE_DNS_NAME_LENGTH_MAXIMUM   255
#define SXE_DNS_LABEL_LENGTH_MAXIMUM  63
#define SXE_DNS_PACKET_LENGTH_MAXIMUM 512
#define SXE_DNS_HEADERFLAG_RD         0x0100
#define SXE_DNS_QSECTION_FOOTER_SIZE  sizeof(struct dns_qsection_footer)

struct dns_qsection_footer {
    unsigned short qtype;
    unsigned short qclass;
};

/* Response codes - this 4 bit field is set as part of responses.
 */
typedef enum SXE_DNS_RCODE {
    SXE_DNS_RCODE_NO_ERROR        = 0,
    SXE_DNS_RCODE_FORMAT_ERROR    = 1,   /* The name server was unable to interpret the query.                                      */
    SXE_DNS_RCODE_SERVER_FAILURE  = 2,   /* The name server was unable to process this query due to a problem with the name server. */
    SXE_DNS_RCODE_NXDOMAIN        = 3,   /* Name Error: The domain name does not exist (from an authoritative name server only)     */
    SXE_DNS_RCODE_NOT_IMPLEMENTED = 4,   /* The name server does not support the requested kind of query.                           */
    SXE_DNS_RCODE_REFUSED         = 5    /* The name server refuses to perform the specified operation for policy reasons.          */
                                 /* 6-15    Reserved for future use.                                                                */
} SXE_DNS_RCODE;

enum {
    RR_CLASS_IN = 1, /* the Internet */
    RR_CLASS_CS = 2, /* the CSNET class (Obsolete - used only for examples in some obsolete RFCs) */
    RR_CLASS_CH = 3, /* the CHAOS class */
    RR_CLASS_HS = 4  /* Hesiod [Dyer 87] */
} sxe_dns_resource_class;

enum {
    RR_TYPE_A       = 1 ,   /* a host address                           */
    RR_TYPE_NS      = 2 ,   /* an authoritative name server             */
    RR_TYPE_MD      = 3 ,   /* a mail destination (Obsolete - use MX)   */
    RR_TYPE_MF      = 4 ,   /* a mail forwarder (Obsolete - use MX)     */
    RR_TYPE_CNAME   = 5 ,   /* the canonical name for an alias          */
    RR_TYPE_SOA     = 6 ,   /* marks the start of a zone of authority   */
    RR_TYPE_MB      = 7 ,   /* a mailbox domain name (EXPERIMENTAL)     */
    RR_TYPE_MG      = 8 ,   /* a mail group member (EXPERIMENTAL)       */
    RR_TYPE_MR      = 9 ,   /* a mail rename domain name (EXPERIMENTAL) */
    RR_TYPE_NULL    = 10,   /* a null RR (EXPERIMENTAL)                 */
    RR_TYPE_WKS     = 11,   /* a well known service description         */
    RR_TYPE_PTR     = 12,   /* a domain name pointer                    */
    RR_TYPE_HINFO   = 13,   /* host information                         */
    RR_TYPE_MINFO   = 14,   /* mailbox or mail list information         */
    RR_TYPE_MX      = 15,   /* mail exchange                            */
    RR_TYPE_TXT     = 16    /* text strings                             */
} sxe_dns_resource_type;

/* Needed here for inlining
 */
struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short question_count;
    unsigned short answer_count;
    unsigned short authority_count;
    unsigned short additional_count;
};

typedef enum SXE_DNS_QTYPE {
    SXE_DNS_QTYPE_A       = RR_TYPE_A,
    SXE_DNS_QTYPE_NS      = RR_TYPE_NS,
    SXE_DNS_QTYPE_MD      = RR_TYPE_MD,
    SXE_DNS_QTYPE_MF      = RR_TYPE_MF,
    SXE_DNS_QTYPE_CNAME   = RR_TYPE_CNAME,
    SXE_DNS_QTYPE_SOA     = RR_TYPE_SOA,
    SXE_DNS_QTYPE_MB      = RR_TYPE_MB,
    SXE_DNS_QTYPE_MG      = RR_TYPE_MG,
    SXE_DNS_QTYPE_MR      = RR_TYPE_MR,
    SXE_DNS_QTYPE_NULL    = RR_TYPE_NULL,
    SXE_DNS_QTYPE_WKS     = RR_TYPE_WKS,
    SXE_DNS_QTYPE_PTR     = RR_TYPE_PTR,
    SXE_DNS_QTYPE_HINFO   = RR_TYPE_HINFO,
    SXE_DNS_QTYPE_MINFO   = RR_TYPE_MINFO,
    SXE_DNS_QTYPE_MX      = RR_TYPE_MX,
    SXE_DNS_QTYPE_TXT     = RR_TYPE_TXT,
    SXE_DNS_QTYPE_AXFR    = 252, /* A request for a transfer of an entire zone */
    SXE_DNS_QTYPE_MAILB   = 253, /* A request for mailbox-related records (MB, MG or MR) */
    SXE_DNS_QTYPE_MAILA   = 254, /* A request for mail agent RRs (Obsolete - see MX) */
    SXE_DNS_QTYPE_STAR    = 255, /* A request for all records */
} SXE_DNS_QTYPE;

#define SXE_DNS_BUFFER_GET_QUESTION(buffer) (&((const unsigned char *)(buffer))[SXE_DNS_QUESTION_OFFSET])

typedef struct SXE_DNS_PACKET {
    const unsigned char * buffer;
    unsigned              question_length;
    unsigned short        qtype;
} SXE_DNS_PACKET;

#define SXE_DNS_PACKET_GET_QTYPE(          packet) ((packet)->qtype)
#define SXE_DNS_PACKET_GET_QUESTION(       packet) (&(packet)->buffer[SXE_DNS_QUESTION_OFFSET])
#define SXE_DNS_PACKET_GET_QUESTION_LENGTH(packet) ((packet)->question_length)
#define SXE_DNS_PACKET_GET_QUESTION_OFFSET(packet) SXE_DNS_QUESTION_OFFSET

#include "lib-sxe-dns-proto.h"

#endif /* __SXE_DNS_H__ */
