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

/* TODO: Consider creating and maintaining a context structure which can be filled in only once (e.g. by validate()), and subsequently used by all the other functions so that performance can be maximized */

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef WINDOWS_NT
#include <Winsock2.h> /* for htons */
#else
#include <arpa/inet.h>
#endif

#include "sha1.h"
#include "sxe-dns.h"
#include "sxe-log.h"
#include "sxe-util.h"

#define SXE_DNS_LENGTH_INVALID       -1
#define SXE_DNS_HEX_ENCODE_LENGTH    3
#define SXE_BUF_SIZE                 512
#define SXE_DNS_LABEL_LENGTH_POINTER 0xc0
#define SXE_DNS_HEADER_RCODE_OFFSET  3
#define SXE_DNS_HEADER_RCODE_MASK    0x0F
#define SXE_DNS_HEADER_QR_OFFSET     2
#define SXE_DNS_HEADER_QR_MASK       0x80
#define SXE_DNS_HEADER_QR_QUERY      0
#define SXE_DNS_HEADER_QR_RESPONSE   0x80

/* Make a host byte ordered short from the potentially unaligned network byte order short at the ptr.
 */
#define SXE_UNALIGNED_GET_NTOHS(ptr) (((ptr)[0] << 8) | (ptr)[1])

/* Note that the decoded_name will be NUL terminated, and therefore the
 * maximum_name_length_maximum should probably be 254 and not 253 (though, with
 * pointers, the decoded name could well be *longer* than 253 characters!
 */
static SXE_RETURN
sxe_dns_decode_name(
    const unsigned char * dns_packet                 ,
    unsigned                dns_packet_length          ,
    unsigned              name_offset                ,
    char                * decoded_name               ,
    unsigned                decoded_name_length_maximum,
    unsigned              * decoded_name_length        )
{
    SXE_RETURN result = SXE_RETURN_ERROR_INTERNAL;
    unsigned   decoded_name_offset = 0;

    SXEE86("sxe_dns_decode_name(dns_packet=%p, dns_packet_length=%u, name_offset=%u, decoded_name=%p, decoded_name_length_maximum=%u, decoded_name_length=%p)", dns_packet, dns_packet_length, name_offset, decoded_name, decoded_name_length_maximum, decoded_name_length);
    SXEA10(decoded_name_length != 0,                                 "A value for decoded_name_length must be provided");
    SXEA10(decoded_name == NULL || decoded_name_length_maximum != 0, "NAME can not be decoded into an empty buffer");

    while (name_offset < dns_packet_length) {
        unsigned char len = dns_packet[name_offset];

        if (len == '\0') {
            SXEL60("NAME is terminated normally");
            if (decoded_name_offset > 0) {
                --decoded_name_offset;
            }

            if (decoded_name != NULL) {
                decoded_name[decoded_name_offset] = '\0';
            }
            *decoded_name_length = decoded_name_offset;
            result = SXE_RETURN_OK;
            goto SXE_EARLY_OUT;
        }
        else if ((len & SXE_DNS_LABEL_LENGTH_POINTER) == 0) {
            SXEL73("Normal label of length %u '%.*s'", len, len, &dns_packet[name_offset + 1]);

            /* Don't allow the NAME to exceed the known packet length */
            if ((decoded_name != NULL) && (decoded_name_offset + len + 1 >= decoded_name_length_maximum)) {
                SXEL51("sxe_dns_decode_name(): NAME is invalid; Decoded NAME is longer than the provided buffer length %u", decoded_name_length_maximum);
                goto SXE_ERROR_OUT;
            }

            /* Copy the label */
            if (decoded_name != NULL) {
                memcpy((unsigned char*)(decoded_name + decoded_name_offset), dns_packet + name_offset + 1, len);
                decoded_name[decoded_name_offset + len] = '.';
            }

            decoded_name_offset += len + 1;
        }
        else if ((len & SXE_DNS_LABEL_LENGTH_POINTER) == SXE_DNS_LABEL_LENGTH_POINTER) {
            SXEL60("NAME includes a pointer");
            name_offset = (len & ~SXE_DNS_LABEL_LENGTH_POINTER) + dns_packet[name_offset + 1];
            SXEL61("New NAME offset is %u", name_offset);

            /* Prevent looping forever - a pointer should never point to a pointer
             */
            if ((dns_packet[name_offset] & SXE_DNS_LABEL_LENGTH_POINTER) != 0) {
                SXEL51("sxe_dns_decode_name(): NAME contains a pointer which points to another pointer at packet offset %u",
                       name_offset);
                goto SXE_ERROR_OUT;
            }

            continue;
        }
        else {
            SXEL51("sxe_dns_decode_name(): NAME is invalid; NAME contains an invalid length/pointer value at packet offset %u", name_offset);
            goto SXE_ERROR_OUT;
        }

        name_offset += len + 1;
    }

    SXEL60("NAME is invalid because it extends outside the packet");

SXE_ERROR_OUT:
SXE_EARLY_OUT:
    SXER81("return // result=%s", sxe_return_to_string(result));
    return result;
}

/* Given a DNS query or reply, extract the DNS question from the DNS packet.
 *
 * Note that the encoded question may be rot13 transformed - see the
 * sxe_dns_rot13_on_string() function to correct this.
 *
 *  dns_packet - DNS packet containting encoded question
 *  question - character buffer into which the decoded zero terminated question text will be written
 *  question_length_maximum - length of 'question'
 *  question_length - pointer (or NULL) which will be set to actual question length
 *
 *  Returns
 *   SXE_RETURN_OK on success
 */
SXE_RETURN
sxe_dns_get_question(const unsigned char * dns_packet, char * question, unsigned question_length_maximum, unsigned * question_length)
{
    SXE_RETURN result = SXE_RETURN_ERROR_INTERNAL;

    SXEE84("sxe_dns_get_question(dns_packet=%p, question=%p, question_length_maximum=%d, question_length=%p)",
           dns_packet, question, question_length_maximum, question_length);

    result = sxe_dns_decode_name(dns_packet, SXE_BUF_SIZE, SXE_DNS_QUESTION_OFFSET, question, question_length_maximum, question_length);

    SXER81("return // result = %s", sxe_return_to_string(result));
    return result;
}

unsigned short
sxe_dns_get_query_id(const unsigned char * dns_packet)
{
    return (dns_packet[0] << 8) | dns_packet[1];
}

void
sxe_dns_set_query_id(unsigned char* dns_packet, unsigned short query_id)
{
    dns_packet[0] = (query_id >> 8);
    dns_packet[1] = query_id & 0xff;
}

int
sxe_dns_is_response(const unsigned char* dns_packet)
{
    return (dns_packet[SXE_DNS_HEADER_QR_OFFSET] & SXE_DNS_HEADER_QR_MASK) != SXE_DNS_HEADER_QR_QUERY;
}

int
sxe_dns_get_opcode(const unsigned char* dns_packet)
{
    return (dns_packet[2] >> 3) & 0xf;
}

int
sxe_dns_is_authoritative(const unsigned char* dns_packet_reply)
{
    return (dns_packet_reply[2] & 4) != 0;
}

int
sxe_dns_is_truncated(const unsigned char* dns_packet)
{
    return (dns_packet[2] & 2) != 0;
}

int
sxe_dns_is_recursion_desired(const unsigned char* dns_packet)
{
    return (dns_packet[2] & 1) != 0;
}

int
sxe_dns_is_recursion_available(const unsigned char* dns_packet_reply)
{
    return (dns_packet_reply[3] & 0x80) != 0;
}

int
sxe_dns_get_question_count(const unsigned char* dns_packet)
{
    return (dns_packet[4] << 8) | dns_packet[5];
}

static void
sxe_dns_set_answer_count(unsigned char* dns_packet, int count)
{
    dns_packet[6] = (count >> 8) & 0xff;
    dns_packet[7] =  count       & 0xff;
}

int
sxe_dns_get_answer_count(const unsigned char * dns_packet_reply)
{
    return (dns_packet_reply[6] << 8) | dns_packet_reply[7];
}

static void
sxe_dns_set_authority_count(unsigned char* dns_packet_reply, int value)
{
    dns_packet_reply[8] = (value >> 8) & 0xff;
    dns_packet_reply[9] =  value       & 0xff;
}

int
sxe_dns_get_authority_count(const unsigned char* dns_packet_reply)
{
    return (dns_packet_reply[8] << 8) | dns_packet_reply[9];
}

static void
sxe_dns_set_additional_count(unsigned char* dns_packet_reply, int value)
{
    dns_packet_reply[10] = (value >> 8) & 0xff;
    dns_packet_reply[11] =  value       & 0xff;
}

int
sxe_dns_get_additional_count(const unsigned char* dns_packet_reply)
{
    return (dns_packet_reply[10] << 8) | dns_packet_reply[11];
}

void
sxe_dns_set_response(unsigned char * dns_packet, SXE_DNS_RCODE rcode)
{
    SXEA11((rcode & SXE_DNS_HEADER_RCODE_MASK) == rcode, "sxe_dns_set_rcode: rcode %u is invalid", rcode);
    dns_packet[SXE_DNS_HEADER_QR_OFFSET]   |= SXE_DNS_HEADER_QR_RESPONSE;
    dns_packet[SXE_DNS_HEADER_RCODE_OFFSET] = (dns_packet[SXE_DNS_HEADER_RCODE_OFFSET] & ~SXE_DNS_HEADER_RCODE_MASK) | rcode;
}

SXE_DNS_RCODE
sxe_dns_get_rcode(const unsigned char * dns_packet)
{
    return dns_packet[SXE_DNS_HEADER_RCODE_OFFSET] & SXE_DNS_HEADER_RCODE_MASK;
}

static int
sxe_dns_get_name_length(const unsigned char* question, unsigned max_length)
{
    int result = SXE_DNS_LENGTH_INVALID;
    unsigned offset = 0;

    SXEE82("sxe_dns_get_name_length(question=%p, max_length=%d)", question, max_length);

    /* Walk our way along the labels for the QNAME section */
    for (;;) {
        int len;
        if ((max_length != 0) && (offset + 1 >= max_length)) {
            SXEL80("label length exceeds available remaining space");
            goto SXE_ERROR_OUT;
        }
        len = question[offset++];
        if (len == 0) {
            result = offset;
            SXEL80("Label is complete");
            goto SXE_EARLY_OUT;
        }
        else if ((len & 0xc0) == 0xc0) {
            result = offset + 1; /* cater for the additional byte for the pointer offset */
            SXEL80("Label is terminated with a pointer");
            goto SXE_EARLY_OUT;
        }
        else if ((len & 0xc0) != 0) {
            SXEL52("sxe_dns_get_name_length(): Label 'length' value (0x%02x) at offset %u of the name uses a reserved value, and is therefore invalid", len, offset);
            goto SXE_ERROR_OUT;
        }

        offset += len;
    }
    /* never gets here */
SXE_EARLY_OR_ERROR_OUT:
    SXER81("return %d", result);
    return result;
}

/**
 * Retrieves the first TXT answer record from the DNS reply.
 *
 * @param dns_packet_reply - DNS encoded reply
 * @param answer_pointer   - Pointer to the answer pointer filled by this function (answer will NOT be '\0' terminated!)
 * @param answer_length    - Pointer which will be set to the length of the answer
 *
 * @return SXE_RETURN_OK on success
 *
 * @note An NXDOMAIN reply will not contain a TXT answer record, and
 * therefore it is probably important that the sxe_dns_is_nxdomain() function
 * is called before this one.
 */
SXE_RETURN
sxe_dns_get_answer_of_type_txt(const unsigned char* dns_packet_reply, char ** answer_pointer, unsigned * answer_length)
{
    SXE_RETURN              result = SXE_RETURN_ERROR_INTERNAL;
    int                     question_count;
    int                     answer_count;
    const unsigned char   * q;
    int                     len;
    int                     i;
    int                     type;
    int                     class;
    const unsigned char   * txt_data;
    int                     txt_data_length;

    SXEE83("sxe_dns_get_answer_of_type_txt(dns_packet_reply=%p, answer_pointer=%p, answer_length=%p)", dns_packet_reply,
           answer_pointer, answer_length);
    SXEA10(answer_length != NULL, "sxe_dns_get_answer_of_type_txt: Must pass an answer pointer");

    question_count = sxe_dns_get_question_count(dns_packet_reply);
    answer_count   = sxe_dns_get_answer_count(  dns_packet_reply);
    q = dns_packet_reply + SXE_DNS_HEADER_SIZE;

    if (answer_count <= 0) {
        /* no point doing anything else if there are no answers */
        SXEL80("No answer");
        goto SXE_ERROR_OUT;
    }

    for (i = 0 ; i < question_count ; ++i) {
        len = sxe_dns_get_name_length(q, 0);

        if (len == SXE_DNS_LENGTH_INVALID) {
            SXEL80("Failed to determine name length for question");
            goto SXE_ERROR_OUT;
        }

        q += len + 4; /* skip QNAME, QTYPE and QCLASS records */
    }

    /* q now points to the first response record */

    len = sxe_dns_get_name_length(q, 0);
    type  = (q[len + 0] << 8) + q[len + 1];
    class = (q[len + 2] << 8) + q[len + 3];

    if (type != RR_TYPE_TXT || class != RR_CLASS_IN) {
        SXEL80("Resource record is not of type TXT");
        goto SXE_ERROR_OUT;
    }

    txt_data         = q + len + 10;
    txt_data_length  = txt_data[0];
    *answer_pointer  = (char *)(unsigned long)(txt_data + 1);

    SXEL81("DNS answer is %d bytes including the leading length specifier", txt_data_length + 1);
    SXED80(txt_data, txt_data_length + 1);

    SXEL81("Setting length of answer to %d", txt_data_length);
    *answer_length = txt_data_length;
    result = SXE_RETURN_OK;

SXE_EARLY_OR_ERROR_OUT:
    SXER81("return %d", result);
    return result;
}

/* Determines whether the DNS reply is NXDOMAIN.
 *
 *  dns_packet_reply - DNS encoded reply
 *
 * Returns
 *  1 on NXDOMAIN, 0 otherwise
 */
int
sxe_dns_is_nxdomain(const unsigned char* dns_packet_reply)
{
    if ((sxe_dns_get_rcode(dns_packet_reply) == 3) && (sxe_dns_get_answer_count(dns_packet_reply) == 0)) {
        return 1;
    }

    return 0;
}

static int
sxe_dns_add_txt_resource_record(unsigned char* resource /* may be NULL */, int label_offset, const char* txt_data, unsigned txt_data_length)
{
    SXEE84("sxe_dns_add_txt_resource_record(resource=%p, label_offset=%d, txt_data=%p, txt_data_length=%d)", resource, label_offset, txt_data, txt_data_length);
    if (resource != NULL) {
        int             len         = 2;
        int             type        = RR_TYPE_TXT;
        int             class       = RR_CLASS_IN;
        unsigned long   ttl         = 10;
        int             rdlength    = 1 + txt_data_length;

        SXEL80("Setting resource record");

        resource[0]         = 0xc0 | ((label_offset >> 8) & 0x3f);
        resource[1]         = label_offset      & 0xff;
        resource[len + 0]   = (type >> 8)       & 0xff;
        resource[len + 1]   = type              & 0xff;
        resource[len + 2]   = (class >> 8)      & 0xff;
        resource[len + 3]   = class             & 0xff;
        resource[len + 4]   = (ttl >> 24)       & 0xff;
        resource[len + 5]   = (ttl >> 16)       & 0xff;
        resource[len + 6]   = (ttl >> 8)        & 0xff;
        resource[len + 7]   = ttl               & 0xff;
        resource[len + 8]   = (rdlength >> 8)   & 0xff;
        resource[len + 9]   = rdlength          & 0xff;
        resource[len + 10]  = txt_data_length;

        memcpy(resource + len + 11, txt_data, txt_data_length);
    }

    SXER81("return %d", 2 + 11 + txt_data_length);
    return 2 + 11 + txt_data_length;
}

/* Modifies a DNS reply, and sets a TXT answer.
 *
 * Any authority or additional resource records will be removed.
 *
 *  dns_packet_reply - DNS reply
 *  dns_packet_reply_length_maximum - Length of buffer containing reply
 *  answer - Textual data to be written as the TXT answer record
 *  answer_length - Length of answer text
 *  dns_packet_reply_length - Encoded length of modified DNS packet
 *
 * Returns
 *   SXE_RETURN_OK on error
 */
SXE_RETURN
sxe_dns_set_answer_of_type_txt(unsigned char* dns_packet_reply, unsigned dns_packet_reply_length_maximum, const char* answer,
                               unsigned answer_length, unsigned *dns_packet_reply_length)
{
    SXE_RETURN      result = SXE_RETURN_ERROR_INTERNAL;
    int             question_count;
    unsigned char * q;
    int             len;
    int             i;

    SXEE85("sxe_dns_set_answer_of_type_txt(dns_packet_reply=%p, dns_packet_reply_length_maximum=%d, answer=%p, answer_length=%d, dns_packet_reply_length=%p)", dns_packet_reply, dns_packet_reply_length_maximum, answer, answer_length, dns_packet_reply_length);

    question_count  = sxe_dns_get_question_count(dns_packet_reply);
    q               = dns_packet_reply + SXE_DNS_HEADER_SIZE;

    if (question_count <= 0) {
        SXEL80("There is no question, so setting an answer makes no sense");
        goto SXE_ERROR_OUT;
    }

    for (i = 0 ; i < question_count ; ++i) {
        len = sxe_dns_get_name_length(q, dns_packet_reply_length_maximum - (q - dns_packet_reply));
        if (len == SXE_DNS_LENGTH_INVALID) {
            SXEL80("Unable to determine question name length");
            goto SXE_ERROR_OUT;
        }
        q += len + 4; /* skip QNAME, QTYPE and QCLASS records */
    }

    len = sxe_dns_add_txt_resource_record(0, SXE_DNS_HEADER_SIZE, answer, answer_length); /* gets length of resource record */

    if ((q - dns_packet_reply) + len > (int)dns_packet_reply_length_maximum) {
        SXEL82("Encoded DNS reply (%d) will exceed the remaining space in the dns packet buffer (%d)", (q - dns_packet_reply) + len, dns_packet_reply_length_maximum);
        goto SXE_ERROR_OUT;
    }

    len = sxe_dns_add_txt_resource_record(q, SXE_DNS_HEADER_SIZE, answer, answer_length);

    sxe_dns_set_response(        dns_packet_reply, SXE_DNS_RCODE_NO_ERROR);
    sxe_dns_set_answer_count(    dns_packet_reply, 1);
    sxe_dns_set_authority_count (dns_packet_reply, 0);
    sxe_dns_set_additional_count(dns_packet_reply, 0);

    if (dns_packet_reply_length != NULL) {
        *dns_packet_reply_length = (q - dns_packet_reply) + len;
        SXEL81("Setting length of encoded packet to %d", *dns_packet_reply_length);
    }

    result = SXE_RETURN_OK;

SXE_EARLY_OR_ERROR_OUT:
    SXER81("return %d", result);
    return result;
}

static int
sxe_dns_get_resource_record_length(const unsigned char* record, unsigned record_length)
{
    int         result;
    unsigned      len;
    unsigned    rdlength;

    SXEE82("sxe_dns_get_resource_record_length(record=%p, record_length=%d)", record, record_length);

    len = sxe_dns_get_name_length(record, record_length);
    SXEL81("name length=%d", len);
    SXEL81("resource record header length=%d", len + 10);

    rdlength = (record[len + 8] << 8) | record[len + 9];
    SXEL81("resource record RDLENGTH record=%d", rdlength);
    result = len + 10 + rdlength;
    if (result > (int)(record_length)) {
        result = SXE_DNS_LENGTH_INVALID;
        errno = EINVAL;
        SXEL80("Encoded resource record RDLENGTH is too big for buffer");
        goto SXE_ERROR_OUT;
    }

    SXEL81("actual resource record length=%d", result);

SXE_EARLY_OR_ERROR_OUT:
    SXER82("return %d%s", result, result == SXE_DNS_LENGTH_INVALID ? " // SXE_DNS_LENGTH_INVALID" : "");
    return result;
}

/**
 * Decode a DNS packet, validating it along the way.
 *
 * This function should be used to confirm that the DNS query or reply is
 * complete, since for efficiency, the other functions in this library will
 * assume that the DNS packet is complete.
 *
 * @param dns_packet DNS encoded query or reply
 * @param dns_packet_length - Length of the DNS packet
 *
 * @return SXE_RETURN_OK on success
 */

SXE_RETURN
sxe_dns_packet_decode(SXE_DNS_PACKET      * packet,
                      const unsigned char * buffer,
                      unsigned                buffer_length,
                      char                * decoded_question,
                      unsigned                decoded_question_length_maximum)
{
    SXE_RETURN            result = SXE_RETURN_ERROR_INTERNAL;
    unsigned              question_count;
    unsigned              answer_count;
    unsigned              authority_count;
    unsigned              additional_count;
    const unsigned char * question = SXE_DNS_BUFFER_GET_QUESTION(buffer);
    int                   len;
    unsigned              i;

    SXEE82("sxe_dns_packet_decode(buffer=%p, buffer_length=%d)", buffer, buffer_length);
    /* Note: buffer may not be two-byte aligned - indeed we now have test cases
     * which create packets which are not aligned.  As it happens, this
     * function works just fine when non-aligned
     */

    packet->question_length = 0;

    if (buffer_length < SXE_DNS_HEADER_SIZE) {
        SXEL52("DNS packet is truncated (length %u < header size %u)", buffer_length, SXE_DNS_HEADER_SIZE);
        goto SXE_ERROR_OUT;
    }

    question_count      = sxe_dns_get_question_count(  buffer);
    answer_count        = sxe_dns_get_answer_count(    buffer);
    authority_count     = sxe_dns_get_authority_count( buffer);
    additional_count    = sxe_dns_get_additional_count(buffer);

    if (question_count == 0) {
        SXEL50("DNS packet has no question");
        goto SXE_EARLY_OUT;
    }

    for (i = 0 ; i < question_count ; i++) {
        SXEL81("DNS packet question %u", i);
        len = sxe_dns_get_name_length(question, buffer_length - (question - buffer));

        if (len == SXE_DNS_LENGTH_INVALID) {
            SXEL80("DNS question length exceeds reported packet length");
            goto SXE_ERROR_OUT;
        }

        if (len > SXE_DNS_NAME_LENGTH_MAXIMUM)
        {
            SXEL50("DNS question length exceeds maximum permitted size");
            goto SXE_ERROR_OUT;
        }

        if (sxe_dns_decode_name(buffer, buffer_length, (question - buffer), decoded_question, decoded_question_length_maximum,
                                &packet->question_length) != SXE_RETURN_OK)
        {
            SXEL50("DNS name is invalid");
            goto SXE_ERROR_OUT;
        }

        /* TODO: Do we need to save multiple QTYPES? Do we even allow multiple questions, or is that an error?
         */
        if (i == 0) {
            packet->qtype = SXE_UNALIGNED_GET_NTOHS(question + len);
        }

        question += len + 4;     /* skip QNAME, QTYPE and QCLASS records */
    }

    SXEL81("length after question section=%d", question - buffer);
    /* question now points to the first response record */
    SXEL81("must now read %d resource records", answer_count + authority_count + additional_count);

    for (i = answer_count + authority_count + additional_count; i > 0 ; --i) {
        SXEL81("resource records remaining: %d", i);
        len = sxe_dns_get_resource_record_length(question, buffer_length - (question - buffer));

        if (len == SXE_DNS_LENGTH_INVALID) {
            SXEL50("DNS encoded resource record exceeds reported packet length");
            goto SXE_ERROR_OUT;
        }

        question += len;
    }

    packet->question_length += 2;
    packet->buffer           = buffer;

SXE_EARLY_OUT:
    result = SXE_RETURN_OK;
    /* We currently have no need to know the calculated packet size - but we do know it.
     *     packet_length = question - buffer
     */
SXE_ERROR_OUT:
    SXER81("return %d", result);
    return result;
}

/**
 * Validate the TLD within the question.
 *
 * Confirm that the question within the DNS query or reply ends with a '.', followed by the correct TLD.
 *
 * @param dns_packet          - DNS encoded query or reply packet
 * @param dns_packet_length   - Length of the DNS packet
 * @param expected_tld        - The final labels expected within the question (should not begin with a '.')
 * @param expected_tld_length - String length of expected_tld
 *
 * @return SXE_RETURN_OK when the final labels match the expected_tld parameter
 */
SXE_RETURN
sxe_dns_validate_tld(const char * dns_question, unsigned dns_question_length,
                     const char * expected_tld, unsigned expected_tld_length)
{
    SXE_RETURN result = SXE_RETURN_ERROR_INTERNAL;
    unsigned   tld_offset;

    SXEE86("sxe_dns_validate_tld(dns_question='%.*s', dns_question_length=%u, expected_tld='%.*s', expected_tld_length=%u",
           dns_question_length, dns_question, dns_question_length, expected_tld_length, expected_tld, expected_tld_length);
    SXEA82(expected_tld[0] != '.', "Expected TLD '%.*s' begins with a '.'", expected_tld_length, expected_tld);

    if (dns_question_length <= expected_tld_length + 1) {
        SXEL52("sxe_dns_validate_tld: DNS question was not long enough to contain the expected TLD '%.*s'",
               expected_tld_length, expected_tld);
        goto SXE_ERROR_OUT;
    }

    tld_offset = dns_question_length - expected_tld_length;

    if ((dns_question[tld_offset - 1] != '.') || (memcmp(&dns_question[tld_offset], expected_tld, expected_tld_length) != 0)) {
        SXEL52("sxe_dns_validate_tld: End of DNS question didn't match expected TLD '%.*s'", expected_tld_length, expected_tld);
        goto SXE_ERROR_OUT;
    }

    result = SXE_RETURN_OK;

SXE_ERROR_OUT:
    SXER81("return // %s", sxe_return_to_string(result));
    return result;
}

/**
 * @param domain_name     Buffer to encode the DNS question (query name) into
 * @param question        DNS name to query
 * @param question_length Length of DNS name to query
 * @param tld             TLD to append to DNS name to query (or NULL)
 * @param tld_length      Length of TLD to append to DNS name to query (not used if tld == NULL)
 *
 * @return Length of the encoded question or -1 on error
 *
 * @note The caller must verify that there is sufficient space to encode the question
 */
int
sxe_dns_encode_question(unsigned char * domain_name, const char * question, unsigned question_length, const char * tld,
                        unsigned tld_length)
{
    int          result = -1;
    int          label_start;
    const char * source;
    unsigned     length;
    unsigned     i;

    SXE_UNUSED_PARAMETER(tld);
    SXE_UNUSED_PARAMETER(tld_length);
    SXEE87("sxe_dns_encode_question(domain_name=%p, question='%.*s', question_length=%u, tld='%.*s', tld_length=%u)",
           domain_name, question_length, question, question_length, tld_length, tld, tld_length);

    if (question[question_length - 1] == '.') {
        SXEL22("sxe_dns_encode_question(): Error: Question '%.*s' ends with a dot", question_length, question);
        goto SXE_ERROR_OUT;
    }

    domain_name +=  1;    /* Skip the first label length byte     */
    label_start  = -1;    /* Index of that first label length     */

    for (source = question, length = question_length; source != NULL; source = tld, length = tld_length) {

        /* For each label in the current source
         */
        for (; label_start < (int)length; label_start = i) {
            SXEL81("Current label = '%s'", &source[label_start + 1]);

            /* copy a label; labels end at a dot or at end of question
             */
            for (i = label_start + 1; (i < length) && (source[i] != '.'); i++) {
                if (i - label_start > SXE_DNS_LABEL_LENGTH_MAXIMUM) {
                    SXEL22("sxe_dns_encode_question(): Error: Question '%.*s' has a label that is too long", question_length, question);
                    goto SXE_ERROR_OUT;
                }

                /* Explicit check for a NUL within the question
                 */
                if (source[i] == '\0') {
                    SXEL22("sxe_dns_encode_question(): Error: Question '%.*s' contains a NUL character", question_length, question);
                    goto SXE_ERROR_OUT;
                }

                /* Copy each character of the label
                 */
                domain_name[i] = source[i];
            }

            if (i == (unsigned)(label_start + 1)) {
                SXEL22("sxe_dns_encode_question(): Error: Question '%.*s' has a zero lenth label", question_length, question);
                goto SXE_ERROR_OUT;
            }

            SXEL82("Question name label '%.*s'", i - label_start + 1, &source[label_start + 1]);

            /* set the length of the label now we've written it
             */
            domain_name[label_start] = i - label_start - 1;
        }

        domain_name = &domain_name[label_start + 1];
        label_start = -1;

        if (source == tld) {
            break;
        }
    }

    SXEL82("Domain name = %p ('%s')", domain_name, domain_name);
    domain_name[label_start] = 0;
    result                   =  question_length + 2 + (tld != NULL ? (tld_length + 1) : 0);

SXE_ERROR_OUT:
    SXER81("return %d", result);
    return result;
}

SXE_RETURN
sxe_dns_uri_decode(char       * decoded_uri                , /* Output */
                   unsigned       decoded_uri_length_maximum ,
                   unsigned     * decoded_uri_length         , /* Output */
                   const char * encoded_uri                ,
                   unsigned       encoded_uri_length         )
{
    SXE_RETURN result = SXE_RETURN_ERROR_INTERNAL;
    unsigned encoded_uri_index = 0;
    unsigned decoded_uri_index = 0;
    unsigned host_start        = 0;
    unsigned num_path_labels   = 0;
    unsigned label_count       = 0;
    unsigned host_part_length;
    int      ch;

    SXE_UNUSED_ARGUMENT(decoded_uri_length_maximum); /* We currently don't validate against this buffer length, this function is only called internally */
    SXEE85("sxe_dns_uri_decode(decoded_uri=%p, decoded_uri_length_maximum=%u, decoded_uri_length=%p, encoded_uri='%s', encoded_uri_length=%u",
        decoded_uri, decoded_uri_length_maximum, decoded_uri_length, encoded_uri, encoded_uri_length);

    SXEA80(decoded_uri        != NULL, "Need a buffer to fill with the decoded uri");
    SXEA80(decoded_uri_length != NULL, "Need a length output parameter to fill");
    SXEA80(encoded_uri        != NULL, "Need an input uri to decode");
    SXEA80(encoded_uri_length >  0   , "Input uri to decode needs a length");
    SXEA80(decoded_uri_length_maximum >= encoded_uri_length, "Output buffer needs to be larger than input");

    SXEL80("Locating start of host part by skipping over path part");

    if (isdigit(encoded_uri[0])) {
        num_path_labels = encoded_uri[0] - '0';

        if (encoded_uri[1] != '.') {
            SXEL50("sxe_dns_uri_decode(): Invalid URL: it needs to start with a single digit label, or a non-digit");
            result = SXE_RETURN_ERROR_INVALID_URI;
            goto SXE_ERROR_OUT;
        }

        SXEL81("URL starts with %u, bypassing this many path labels", num_path_labels);

        for (encoded_uri_index = 2; label_count < num_path_labels; ++encoded_uri_index) {
            if (encoded_uri_index >= encoded_uri_length) {
                SXEL52("sxe_dns_uri_decode(): Invalid URL: label count (in first label) '%u.' is greater than the number of labels %u",
                    num_path_labels, label_count);
                result = SXE_RETURN_ERROR_INVALID_URI;
                goto SXE_ERROR_OUT;
            }

            if (encoded_uri[encoded_uri_index] == '.') {
                /* TODO: investigate a possible perf improvement in dash-encoding here
                 *       into a tmp buffer to avoid a double scan of the path part */
                ++label_count;
            }
        }

        /* Skip the path portion.
         */
        host_start = encoded_uri_index;
    }

    SXEL81("Copying host part (and rot13'ing each char) starting at index %u of source url buffer", host_start);
    host_part_length = encoded_uri_length - host_start;
    sxe_strn_rot13(&decoded_uri[decoded_uri_index], &encoded_uri[host_start], host_part_length);
    encoded_uri_index                = host_start + host_part_length;
    decoded_uri_index               += host_part_length;
    decoded_uri[decoded_uri_index++] = '/';

    if (num_path_labels > 0) {
        encoded_uri_index = 2;
        SXEL80("Peeking ahead to see if path starts with a '/' and skip it since we added it above");

        if ((encoded_uri[2] == SXE_ROT13_CHAR('x')) && (encoded_uri[3] == '-')
         && (sxe_rot13_hex_to_unsigned(&encoded_uri[4], 2) == '/'))
        {
            SXEL80("Path starts with a dash encoded '/'; skipping it");
            encoded_uri_index += 4;
        }

        SXEL81("Decoding the path starting at index %u; skipped the first label '#.' and possibly a '/'", encoded_uri_index);

        while(encoded_uri_index < host_start) {
            ch = SXE_ROT13_CHAR(encoded_uri[encoded_uri_index]);

            /* ignore '.' (added just to give us < 64 characters per label)
             */
            if (ch == '.') {
                encoded_uri_index++;
                continue;
            }

            /* Skip 'x-' & '-' that prefix 2 hex digits
             */
            if (ch == 'x' && encoded_uri[encoded_uri_index + 1] == '-') {
                encoded_uri_index += 2;
            }
            else if(ch == '-') {
                encoded_uri_index += 1;
            }
            else {
                /* Otherwise, rot13 alpha character and move on
                 */
                decoded_uri[decoded_uri_index++] = ch;
                SXEL92("Decoded '%c' into '%c'", encoded_uri[encoded_uri_index], ch);
                encoded_uri_index++;
                continue;
            }

            /* Decode 2 hex digits that follow 'x-' or '-'
             */
            ch = sxe_rot13_hex_to_unsigned(&encoded_uri[encoded_uri_index], 2);

            if (ch < 0) {
                SXEL51("sxe_dns_uri_decode(): Invalid URL: hex value 0x%.2s is not within a (rot13'ed) hex range", &encoded_uri[encoded_uri_index]);
                result = SXE_RETURN_ERROR_INVALID_URI;
                goto SXE_ERROR_OUT;
            }

            decoded_uri[decoded_uri_index++] = ch;
            SXEL92("Decoded '-%.2s' into '%c'", &encoded_uri[encoded_uri_index], ch);
            encoded_uri_index += 2;
        }
    }

    decoded_uri[decoded_uri_index] = '\0';
    *decoded_uri_length            = decoded_uri_index;
    SXEL82("Resulting decoded URL is %u chars: '%s'", *decoded_uri_length, decoded_uri);
    result = SXE_RETURN_OK;

SXE_ERROR_OUT:
    SXER81("return // %s", sxe_return_to_string(result));
    return result;
}

/**
 * Construct a DNS query packet using a specific DNS name as the question
 *
 * @param dns_packet_query                  buffer into which the dns packet will be written
 * @param dns_packet_query_length_maximum   buffer length available
 * @param dns_packet_query_length           buffer length used (returned via pointer)
 * @param query_id                          query ID
 * @param question                          question string, dot-separated (e.g. "www.sophos.com.w.01.sophoxl.net")
 * @param question_length                   question string length
 * @param tld                               TLD to append to question (e.g. "01.sophoxl.net") or NULL
 * @param tld_length                        TLD string length if tld != NULL
 *
 * @return SXE_RETURN_OK on success, SXE_RETURN_ERROR_INTERNAL on error.
 */

SXE_RETURN
sxe_dns_create_query_of_type_txt(unsigned char  * dns_packet_query               ,
                                 unsigned         dns_packet_query_length_maximum,
                                 unsigned       * dns_packet_query_length        , /* Output */
                                 unsigned short   query_id                       ,
                                 const char     * question                       ,
                                 unsigned         question_length                ,
                                 const char     * tld                            ,
                                 unsigned         tld_length                     )
{
    SXE_RETURN result = SXE_RETURN_ERROR_INTERNAL;
    int        qlen;
    unsigned   dns_packet_query_calculated_length;

    SXEE86("sxe_dns_create_query_of_type_txt(dns_packet_query=%p, dns_packet_query_length_maximum=%d, dns_packet_query_length=%p, question=%p, question_length=%d, query_id=%hu)", dns_packet_query, dns_packet_query_length_maximum, dns_packet_query_length, question, question_length, query_id);
    SXEL81("question has length of %d bytes", question_length);
    SXED80(question, question_length);

    if (dns_packet_query_length == NULL) {
        dns_packet_query_length = &dns_packet_query_calculated_length;
    }

    dns_packet_query_calculated_length = SXE_DNS_HEADER_SIZE + question_length + 2 + SXE_DNS_QSECTION_FOOTER_SIZE;

    if (tld != NULL) {
        dns_packet_query_calculated_length += tld_length + 1;
    }

    /* We can accurately calculate the length of the DNS query up front */
    if (dns_packet_query_length_maximum < dns_packet_query_calculated_length) {
        SXEL20("sxe_dns_create_query_of_type_txt(): Insufficient space to encode the DNS header");
        goto SXE_ERROR_OUT;
    }

    /* Could be an assert - though we do have a test and coverage for this condition */
    if (question_length == 0) {
        SXEL20("sxe_dns_create_query_of_type_txt(): Zero length questions are not allowed");
        goto SXE_ERROR_OUT;
    }

    {
        struct dns_header * header;

        header                   = (struct dns_header*)dns_packet_query;
        header->id               = htons(query_id);           /* offset 0  */
        header->flags            = htons(SXE_DNS_HEADERFLAG_RD); /* offset 2  */
        header->question_count   = htons(1);                  /* offset 4  */
        header->answer_count     = 0;                         /* offset 6  */
        header->authority_count  = 0;                         /* offset 8  */
        header->additional_count = 0;                         /* offset 10 */
    }

    /* We've already checked that the dns_packet_query has enough space for encoding the NAME
     */
    qlen = sxe_dns_encode_question(dns_packet_query + SXE_DNS_HEADER_SIZE, question, question_length, tld, tld_length);

    if (qlen == -1) {
        SXEL80("Failed to encode question");
        goto SXE_ERROR_OUT;
    }

    {
        /* Note: Some processors will not write unsigned short to odd addresses
         */
        struct dns_qsection_footer type_and_class;

        type_and_class.qtype  = htons(RR_TYPE_TXT);
        type_and_class.qclass = htons(RR_CLASS_IN);

        /* Copy to potentially unaligned address */
        memcpy(dns_packet_query + SXE_DNS_HEADER_SIZE + qlen, &type_and_class, SXE_DNS_QSECTION_FOOTER_SIZE);
        *dns_packet_query_length = SXE_DNS_HEADER_SIZE + qlen + SXE_DNS_QSECTION_FOOTER_SIZE;
    }

    SXEL81("Constructed query is %d bytes long", *dns_packet_query_length);
    SXED80(dns_packet_query, *dns_packet_query_length);
    result = SXE_RETURN_OK;

SXE_EARLY_OR_ERROR_OUT:
    SXER81("return result=%d", result);
    return result;
}

unsigned
sxe_dns_get_question_qtype(const unsigned char * dns_packet, unsigned dns_packet_length)
{
    unsigned result = 0;
    unsigned name_length;
    struct dns_qsection_footer flags;

    SXEE82("sxe_dns_get_question_qtype(dns_packet=%p, dns_packet_length)", dns_packet, dns_packet_length);

    name_length = sxe_dns_get_name_length(dns_packet + SXE_DNS_QUESTION_OFFSET, dns_packet_length - SXE_DNS_QUESTION_OFFSET);
    memcpy(&flags, &dns_packet[SXE_DNS_QUESTION_OFFSET + name_length], sizeof(flags));
    result = ntohs(flags.qtype);

    SXER81("return // QTYPE=%u", result);
    return result;
}

SXE_RETURN
sxe_dns_set_question_qtype(unsigned char * dns_packet, unsigned dns_packet_length, SXE_DNS_QTYPE qtype)
{
    SXE_RETURN result = SXE_RETURN_ERROR_INTERNAL;
    unsigned   name_length;
    struct dns_qsection_footer flags;

    SXEE83("sxe_dns_set_question_qtype(dns_packet=%p, dns_packet_length=%u, qtype=%u)", dns_packet, dns_packet_length, qtype);

    name_length = sxe_dns_get_name_length(dns_packet + SXE_DNS_QUESTION_OFFSET, dns_packet_length - SXE_DNS_QUESTION_OFFSET);
    memcpy(&flags, &dns_packet[SXE_DNS_QUESTION_OFFSET + name_length], sizeof(flags));
    flags.qtype = htons(qtype);
    memcpy(&dns_packet[SXE_DNS_QUESTION_OFFSET + name_length], &flags, sizeof(flags));
    result = SXE_RETURN_OK;

    SXER81("return // result=%s", sxe_return_to_string(result));
    return result;
}
