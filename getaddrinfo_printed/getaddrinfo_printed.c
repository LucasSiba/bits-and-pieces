#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int
main(int argc, char ** argv) {
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], "http", &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {

        if (p->ai_family == AF_INET) {
            printf("AF_INET  (IPv4) - ");
        } else {
            printf("AF_INET6 (IPv6) - ");
        }

        if (p->ai_socktype == SOCK_STREAM) {
            printf("SOCK_STREAM - ");
        } else {
            printf("SOCK_DGRAM - ");
        }

        if (p->ai_protocol == IPPROTO_TCP) {
            printf("IPPROTO_TCP - ");
        } else {
            printf("IPPROTO_UDP - ");
        }

        char buf[INET6_ADDRSTRLEN];
        switch (p->ai_addr->sa_family) {
            case AF_INET:
                printf("%s", inet_ntop(p->ai_addr->sa_family, &((struct sockaddr_in*)p->ai_addr)->sin_addr, buf, sizeof(buf)));
                break;
            case AF_INET6:
                printf("%s", inet_ntop(p->ai_addr->sa_family, &((struct sockaddr_in6*)p->ai_addr)->sin6_addr, buf, sizeof(buf)));
                break;
            default:
                printf("unknown");
        }

        printf("\n");
    }

    freeaddrinfo(servinfo);
    return 0;
}
