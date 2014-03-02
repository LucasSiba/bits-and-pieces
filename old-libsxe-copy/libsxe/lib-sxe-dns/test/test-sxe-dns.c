#include <assert.h>
#include <errno.h>
#include <stddef.h> /* needed before sxe-dns-proto.h */
#include <stdint.h> /* needed before sxe-dns-proto.h */
#include <string.h> /* memcpy */

#include "sxe-dns.h"
#include "sxe-log.h"
#include "sxe-util.h"
#include "tap.h"

#define TEST_DOMAIN "www.foo.com"

static void
test_case_decoding_query(const unsigned char* response, unsigned response_length)
{
    char           question[1024];
    unsigned       question_length;
    SXE_DNS_PACKET dns_packet;
    SXE_RETURN     result;

    is(sxe_dns_get_question(response, question, 10              , &question_length), SXE_RETURN_ERROR_INTERNAL, "Buffer is too short");
    is(sxe_dns_get_question(response, question, sizeof(question), &question_length), SXE_RETURN_OK,             "Extract query text");
    is(question_length,                                                              26,                        "Check length of question");

    sxe_strn_rot13_in_place(question, sizeof(question));
    is_eq(question,                                      "ship.it.h.pn.10.99.131.240", "Query text matches expectations");
    is_strncmp(SXE_DNS_BUFFER_GET_QUESTION(response),    "\004fuvc\002vg", 8,          "First 8 bytes of question are correct in buffer");

    result = sxe_dns_packet_decode(&dns_packet, response, response_length, question, sizeof(question));
    is(result,                                           SXE_RETURN_OK,                "Decode the packet");
    is(SXE_DNS_PACKET_GET_QUESTION_OFFSET(&dns_packet),  SXE_DNS_QUESTION_OFFSET,      "Got the correct DNS question offset");
    is(SXE_DNS_PACKET_GET_QUESTION_LENGTH(&dns_packet),  28,                           "Got the correct DNS question length");
    is_strncmp(SXE_DNS_PACKET_GET_QUESTION(&dns_packet), "\004fuvc\002vg", 8,          "First 8 bytes of question are correct");
    sxe_strn_rot13_in_place(question, sizeof(question));
    is_eq(question,                                      "ship.it.h.pn.10.99.131.240", "partially decoded ROT13 decoded SXL URI is correct");
    is(SXE_DNS_PACKET_GET_QTYPE(&dns_packet),            SXE_DNS_QTYPE_TXT,            "Got the correct DNS QTYPE of TXT");

    result = sxe_dns_packet_decode(&dns_packet, response, response_length, NULL, 0);
    is(result,                                           SXE_RETURN_OK,                "Decode the packet (no decoded question)");
    is(SXE_DNS_PACKET_GET_QUESTION_OFFSET(&dns_packet),  SXE_DNS_QUESTION_OFFSET,      "Got the correct DNS question offset (no decoded question)");
    is(SXE_DNS_PACKET_GET_QUESTION_LENGTH(&dns_packet),  28,                           "Got the correct DNS question length (no decoded question)");
    is_strncmp(SXE_DNS_PACKET_GET_QUESTION(&dns_packet), "\004fuvc\002vg", 8,          "First 8 bytes of question are correct (no decoded question)");
}

static void
test_case_response_result(const unsigned char* response, unsigned response_length)
{
    char   * query_text;
    unsigned answer_length;

    is(sxe_dns_get_query_id          (response), 0xfdff, "Check query id"                              );
    is(sxe_dns_is_response           (response), 1     , "Check whether this is a query or a response" );
    is(sxe_dns_get_opcode            (response), 0     , "Check the opcode"                            );
    is(sxe_dns_is_authoritative      (response), 1     , "Check that the result is authoritative"      );
    is(sxe_dns_is_truncated          (response), 0     , "Check that the result is not truncated"      );
    is(sxe_dns_is_recursion_desired  (response), 1     , "Check that recursion was desired"            );
    is(sxe_dns_is_recursion_available(response), 0     , "Check whether recursion was available"       );
    is(sxe_dns_get_question_count    (response), 1     , "Check that there was one query"              );
    is(sxe_dns_get_answer_count      (response), 1     , "Check that there was one answer"             );
    is(sxe_dns_get_authority_count   (response), 0     , "Check that there was no authority record"    );
    is(sxe_dns_get_additional_count  (response), 0     , "Check that there was no additional record"   );
    is(sxe_dns_get_rcode             (response), 0     , "Check the rcode"                             );
    is(sxe_dns_get_question_qtype    (response, response_length), SXE_DNS_QTYPE_TXT, "Check the question QTYPE"         );
    is(sxe_dns_is_nxdomain           (response), 0     , "Confirm not an NXDOMAIN"                     );

    is(sxe_dns_get_answer_of_type_txt(response, &query_text, &answer_length), SXE_RETURN_OK, "Extracted response from query"           );
    is(answer_length,                                                         5,             "Answer length is 5");
    is_strncmp(query_text, "d wow", answer_length,                                           "Answer is 'd wow'");
}

static void
test_case_change_question_type(void)
{
    unsigned char packet[512];
    unsigned packet_length;

    SXEE61("%s()", __func__);

    sxe_dns_create_query_of_type_txt(packet, sizeof(packet), &packet_length, 123, TEST_DOMAIN, sizeof(TEST_DOMAIN) - 1, NULL, 0);
    is(sxe_dns_get_question_qtype(packet, packet_length), SXE_DNS_QTYPE_TXT, "sxe_dns_create_query_of_type_txt generates questions with a qtype TXT");
    is(sxe_dns_set_question_qtype(packet, packet_length, SXE_DNS_QTYPE_A), SXE_RETURN_OK, "set the question qtype");
    is(sxe_dns_get_question_qtype(packet, packet_length), SXE_DNS_QTYPE_A, "confirmed that the question qtype was changed");

    SXER60("return");
}

static void
test_case_bogus_label(void)
{
    char   * query_text;
    unsigned answer_length;

    unsigned char response[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        0x63, 0x84, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        /*    ^^^^  bogus label length */
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10,
        0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77, 0x6f, 0x77
    };

    is(sxe_dns_get_answer_of_type_txt(response, &query_text, &answer_length), SXE_RETURN_ERROR_INTERNAL,
       "Query contains an invalid label 'length' value");
}

static void
test_case_no_answers(void)
{
    char   * query_text;
    unsigned answer_length;

    unsigned char response[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        /*                                  ^^^^^^^^^^ answer count */
        0x63, 0x02, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10,
        0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77, 0x6f, 0x77
    };

    is(sxe_dns_get_answer_of_type_txt(response, &query_text, &answer_length), SXE_RETURN_ERROR_INTERNAL,
       "query contains no answers");
}

static void
test_case_not_a_txt_result(void)
{
    char   * query_text;
    unsigned answer_length;

    unsigned char response[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        0x63, 0x02, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0f,
        /*                                                                           TYPE   ^^^^^^^^^^ */
        0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77, 0x6f, 0x77
    };

    is(sxe_dns_get_answer_of_type_txt(response, &query_text, &answer_length), SXE_RETURN_ERROR_INTERNAL,
       "query doesn't contain a TXT result");
}

static void
test_case_nxdomain(void)
{
    unsigned char response[] = {
        0xfd, 0xff, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        0x63, 0x02, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0x00, 0x00, 0x10, 0x00, 0x01
    };

    is(sxe_dns_is_nxdomain(response), 1, "Confirm NXDOMAIN");
}

static void
test_case_add_result_to_nxdomain(void)
{
    char   * query_text;
    unsigned answer_length;
    char     saved;
    unsigned reply_length;

    unsigned char response[1024] = {
        0xfd, 0xff, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        0x63, 0x02, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0x00, 0x00, 0x10, 0x00, 0x01
    };

    saved       = response[5];
    response[5] = 0; /* remove query count */
    is(sxe_dns_set_answer_of_type_txt(response, sizeof(response), "a bcdefg", 8, &reply_length), SXE_RETURN_ERROR_INTERNAL,
       "Can't add response if there are no queries");
    response[5] = saved; /* restore query count */

    saved        = response[12];
    response[12] = 0x80;
    is(sxe_dns_set_answer_of_type_txt(response, sizeof(response), "a bcdefg", 8, &reply_length), SXE_RETURN_ERROR_INTERNAL,
       "Can't add response if label is corrupt"    );
    response[12] = saved;

    is(sxe_dns_set_answer_of_type_txt(response, 64              , "a bcdefg", 8, &reply_length), SXE_RETURN_ERROR_INTERNAL,
       "Not enough room to append result"          );
    is(sxe_dns_set_answer_of_type_txt(response, sizeof(response), "a bcdefg", 8, &reply_length), SXE_RETURN_OK,
       "Added txt answer"                          );

    is(sxe_dns_is_nxdomain(response), 0,          "Confirm response is no longer 'NXDOMAIN'");
    is(reply_length,                  65,         "Check the length of the newly encoded result packet");
    is(sxe_dns_get_answer_of_type_txt(response, &query_text, &answer_length), SXE_RETURN_OK, "Extracted response from query");
    is_eq(query_text,                 "a bcdefg", "Check TXT record result");
    is(sxe_dns_get_rcode(response),   0,          "Check that response record rcode is correct");
    is(sxe_dns_is_response(response), 1,          "Check that this is a response"              );

    /* we should be able to 'add' a TXT record to an existing response - this will remove the existing reply and replace it with
     * our new one.  We can also call this function without specifying the out_dns_packet_length parameter.
     */
    is(sxe_dns_set_answer_of_type_txt(response, sizeof(response), "z yxwvut", 8, 0), SXE_RETURN_OK, "Added txt answer");
    is(sxe_dns_get_answer_of_type_txt(response, &query_text, &answer_length),        SXE_RETURN_OK, "Extracted response from query");
    is_eq(query_text,                                                                "z yxwvut",    "Check TXT record result");
}

static void
test_case_dns_length_validity(const unsigned char * response, unsigned real_size)
{
    unsigned char  copy[1024];
    SXE_DNS_PACKET packet;
    char           question[SXE_DNS_NAME_LENGTH_MAXIMUM + 1];

    is(sxe_dns_packet_decode(&packet, response, 0,             question, sizeof(question)), SXE_RETURN_ERROR_INTERNAL, "Far far too short"                                 );
    is(sxe_dns_packet_decode(&packet, response, 13,            question, sizeof(question)), SXE_RETURN_ERROR_INTERNAL, "Far too short"                                 );
    is(sxe_dns_packet_decode(&packet, response, real_size - 6, question, sizeof(question)), SXE_RETURN_ERROR_INTERNAL, "Missing part of the answer"                        );
    is(sxe_dns_packet_decode(&packet, response, real_size - 1, question, sizeof(question)), SXE_RETURN_ERROR_INTERNAL, "Just too short"                                    );
    is(sxe_dns_packet_decode(&packet, response, real_size,     question, sizeof(question)), SXE_RETURN_OK,             "just right");

    memcpy(copy, response, real_size);
    copy[4] = 0; /* Modify the question count */
    copy[5] = 0;
    is(sxe_dns_packet_decode(&packet, copy, sizeof(copy), question, sizeof(question)), SXE_RETURN_OK, "DNS packet has no question");
}


#define TEST_VALIDATE_TLD(question, tld, expected_result, string) \
    is(sxe_dns_validate_tld(question, strlen(question), tld, strlen(tld)), expected_result, string)

static void
test_case_tld_zone_validation(void)
{
    TEST_VALIDATE_TLD("foo.com.w.01.sophosxl.net", "w.01.sophosxl.net" , SXE_RETURN_OK,             "happy path, tld is correct");
    TEST_VALIDATE_TLD("foo.com.w.01.sophosxl.net", "t"                 , SXE_RETURN_ERROR_INTERNAL, "TLD must be preceded by a '.'");
    TEST_VALIDATE_TLD("foo.com.w.01.sophoSxl.net", "w.01.sophosxl.net" , SXE_RETURN_ERROR_INTERNAL, "capital doesn't match");
    TEST_VALIDATE_TLD("foo.com.w.01.sophozxl.net", "w.01.sophosxl.net" , SXE_RETURN_ERROR_INTERNAL, "one letter out doesn't match");
    TEST_VALIDATE_TLD("foo.com.z.01.sophosxl.net", "w.01.sophosxl.net" , SXE_RETURN_ERROR_INTERNAL, "zone wrong");
    TEST_VALIDATE_TLD(".w.01.sophosxl.net",        "w.01.sophosxl.net" , SXE_RETURN_ERROR_INTERNAL, "question too short");
    TEST_VALIDATE_TLD(".w.01.sophosxl.net",        ""                  , SXE_RETURN_ERROR_INTERNAL, "no TLD parameter");
    TEST_VALIDATE_TLD("a",                         "w.01.sophosxl.net" , SXE_RETURN_ERROR_INTERNAL, "one letter question string");
}

#define PAD 0x00

static void
test_case_test_dns(void)
{
    SXE_DNS_PACKET packet;
    char           question[SXE_DNS_NAME_LENGTH_MAXIMUM + 1];

    /* Here's a response we manufactured earler...
     */
    unsigned char response[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        0x63, 0x02, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10,
        0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77, 0x6f, 0x77
    };

    unsigned char empty_question[] = {                                       /* vvvv first label is terminator */
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20,
        0x77, 0x6f, 0x77, PAD
    };

    /* potentially invalid, since pointers might not be valid when pointing forwards */
    unsigned char question_with_pointer[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x66, 0x75, 0x76,
        0x63, 0x02, 0x76, 0x67, 0x01, 0x75, 0x02, 0x63, 0x61, 0x02, 0x31, 0x30, 0x02, 0x39, 0x39, 0x03,
        0x31, 0x33, 0x31, 0x03, 0x32, 0x34, 0x30, 0xC0, 0x2d, 0x00, 0x10, 0x00, 0x01, 0x03, 0x31, 0x33,
        0x31, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77,
        0x6f, 0x77
    };

    unsigned char question_with_invalid_pointer[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,                         /* 12 byte DNS header */
        0xff, 0x10,                                                                                     /* question (invalid pointer) */
        0x00, 0x10, 0x00, 0x01,                                                                         /* class and type */
        0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77, /* answer RR */
        0x6f, 0x77                                                                                      /* answer RR */
    };

    /* when testing for valid names, we have to have the get_name_length()
     * pass, but decode_name() fail.  This test achieves this by having the
     * question point to an invalid NAME */
    unsigned char question_with_invalid_length_argument[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,                         /* 12 byte DNS header */
        0xc0, 0x12,                                                                                     /* question (valid pointer which jumps to resource record) */
        0x00, 0x10, 0x00, 0x01,                                                                         /* class and type */
        0x01, 0x41, 0x80, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, /* answer RR */
        0x20, 0x77, 0x6f, 0x77                                                                          /* answer RR */
    };

    unsigned char question_with_pointer_loop[] = {
        0xfd, 0xff, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,                         /* 12 byte DNS header */
        0xc0, 0x12,                                                                                     /* question (pointer to back pointer) */
        0x00, 0x10, 0x00, 0x01,                                                                         /* class and type */
        0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x08, 0x34, 0x00, 0x06, 0x05, 0x64, 0x20, 0x77, /* answer RR */
        0x6f, 0x77                                                                                      /* answer RR */
    };

    /* Actual query created by bind9 */
    unsigned char bind9_query[] = {
        0x71,0x5d,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x03,0x6a,0x6a,0x6a,
        0x07,0x63,0x79,0x6e,0x6c,0x6f,0x62,0x6c,0x03,0x70,0x62,0x7a,0x01,0x77,0x02,0x73,
        0x73,0x01,0x73,0x08,0x65,0x70,0x70,0x73,0x78,0x6c,0x32,0x32,0x03,0x6e,0x65,0x74,
        0x00,0x00,0x10,0x00,0x01,
        /* Resource record */
        0x00,                /* name */
        0x00,0x29,           /* type (16 bit)*/
        0x10,0x00,           /* class (16 bit) */
        0x00,0x00,0x80,0x00, /* TTL (32 bit) */
        0x00,0x00            /* RDLENGTH (16 bit) */
    };

    /* Invalid resource record - it is too long */
    unsigned char bind9_query_truncated[] = {
        0x71,0x5d,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x03,0x6a,0x6a,0x6a,
        0x07,0x63,0x79,0x6e,0x6c,0x6f,0x62,0x6c,0x03,0x70,0x62,0x7a,0x01,0x77,0x02,0x73,
        0x73,0x01,0x73,0x08,0x65,0x70,0x70,0x73,0x78,0x6c,0x32,0x32,0x03,0x6e,0x65,0x74,
        0x00,0x00,0x10,0x00,0x01,
        /* Resource record */
        0x00,                /* name */
        0x00,0x29,           /* type (16 bit)*/
        0x10,0x00,           /* class (16 bit) */
        0x00,0x00,0x80,0x00, /* TTL (32 bit) */
        0x00,0x01            /* RDLENGTH (16 bit) */
    };
    /* Invalid resource record - it is too long */
    unsigned char bind9_query_with_rdata[] = {
        0x71,0x5d,0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x03,0x6a,0x6a,0x6a,
        0x07,0x63,0x79,0x6e,0x6c,0x6f,0x62,0x6c,0x03,0x70,0x62,0x7a,0x01,0x77,0x02,0x73,
        0x73,0x01,0x73,0x08,0x65,0x70,0x70,0x73,0x78,0x6c,0x32,0x32,0x03,0x6e,0x65,0x74,
        0x00,0x00,0x10,0x00,0x01,
        /* Resource record */
        0x00,                /* name */
        0x00,0x29,           /* type (16 bit)*/
        0x10,0x00,           /* class (16 bit) */
        0x00,0x00,0x80,0x00, /* TTL (32 bit) */
        0x00,0x01,           /* RDLENGTH (16 bit) */
        0x00                 /* RDATA */

    };


    test_case_dns_length_validity   (response,       sizeof(response));
    test_case_dns_length_validity   (empty_question, sizeof(empty_question) - 1);   /* Exclude the PAD byte */
    test_case_decoding_query        (response,       sizeof(response));
    test_case_response_result       (response,       sizeof(response));
    test_case_bogus_label           ();
    test_case_no_answers            ();
    test_case_not_a_txt_result      ();
    test_case_nxdomain              ();
    test_case_add_result_to_nxdomain();
    test_case_tld_zone_validation   ();
    test_case_change_question_type  ();

#define VALIDATE_PACKET(type, res, test) \
    is(sxe_dns_packet_decode(&packet, type, sizeof(type), question, sizeof(question)), res, test)

    VALIDATE_PACKET(question_with_pointer,                 SXE_RETURN_OK,             "Check for use of a pointer in the question");
    VALIDATE_PACKET(question_with_invalid_pointer,         SXE_RETURN_ERROR_INTERNAL, "Check for invalid use of a pointer in the question");
    VALIDATE_PACKET(question_with_invalid_length_argument, SXE_RETURN_ERROR_INTERNAL, "Check for invalid length argument");
    VALIDATE_PACKET(question_with_pointer_loop,            SXE_RETURN_ERROR_INTERNAL, "Check for pointer loop");
    VALIDATE_PACKET(bind9_query,                           SXE_RETURN_OK,             "Validate bind9 generated packet");
    VALIDATE_PACKET(bind9_query_truncated,                 SXE_RETURN_ERROR_INTERNAL, "Check for truncated RDATA");
    VALIDATE_PACKET(bind9_query_with_rdata,                SXE_RETURN_OK,             "Check for a valid record which contains RDATA");
}

int main(void)
{
    plan_tests(79);

    test_case_test_dns();

    return exit_status();
}
