#include <stdio.h>
#include "sxe-dns.h"

int
main(int argc, char **argv)
{
    char line[2056];
    char decoded[2056];
    int i;
    unsigned len;

    if (argc != 2) {
        printf("usage: %s -use_stdio\n", argv[0]);
        return 0;
    }

    while (fgets(line, sizeof(line), stdin) != NULL) {

        i = 0;

        while ((line[i] != ' ') && (line[i] != '\0') && (line[i] != '\n')) {
            i++;
        }

        line[i] = '\0';
        //i++;

        SXEA11(sxe_dns_uri_decode(decoded, sizeof(decoded), &len, line, i) == SXE_RETURN_OK, "decode failed for %s", line);
        printf("%.*s\n", len, decoded);
    }

    return 0;
}
