#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char** argv)
{
    fd_set fdset;
    struct timeval tv;
    int sockfd;  
    struct addrinfo hints, *servinfo, *p;
    int rv;

    if (argc != 3) {
        printf("Usage: %s <domain> <port>\n", argv[0]);
        return 1;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
        printf("getaddrinfo failed lookup for %s: %s\n", argv[1], gai_strerror(rv));
        exit(1);
    }

    // for(p = servinfo; p != NULL; p = p->ai_next) {
    p = servinfo;

    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
        perror("socket");
        return 1;
    }

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    connect(sockfd, p->ai_addr, p->ai_addrlen);

    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec =  2;
    tv.tv_usec = 0;

    if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1)
    {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            printf("Connected to %s on port %s\n", argv[1], argv[2]);
        }
    } else {
        printf("Failed to connect to %s on port %s\n", argv[1], argv[2]);
    }

    close(sockfd);
    freeaddrinfo(servinfo);

    return 0;
}
