#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "purr.h"

int clean_up_link(const char *dirty, char *clean, char *path, char *port)
{
    // detect protocol, remove protocol prefix
    int portn = 0;
    const char *first_colon = strchr(dirty, ':');
    const char *start_link = NULL;
    if (first_colon == NULL) {
        // no protocol specified, default to HTTP
        portn = HTTP_PORT;
        start_link = dirty;
    } else {
        if (strstr(dirty, "https://") != NULL) {
            portn = HTTPS_PORT;
        } else if (strstr(dirty, "http://") != NULL) {
            portn = HTTP_PORT;
        } else {
            fputs("clean_up_link(): unknown protocol!\n", stderr);
            return -1;
        }

        if (first_colon[1] == '/' && first_colon[2] == '/') {
            // correct format
            start_link = first_colon + 3;
        } else {
            fputs("clean_up_link(): bad header!\n", stderr);
            return -1;
        }
    }

    // maximum size necessary
    strlcpy(clean, start_link, 254);
    char *slash = strchr(clean, '/');
    if (slash != NULL) {
        // copy to path
        strlcpy(path, slash, 1024);
        // slashes found at the end of the link
        *slash = 0;
    } else {
        path[0] = '/';
        path[1] = 0;
    }

    sprintf(port, "%d", portn);

    return portn;
}

int host_connect(const char *host, const char *port, bool debug)
{
    struct addrinfo hints = { 0 }, *si = NULL;
    int fd = 0, err = 0;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &si);
    if (err) {
        fprintf(stderr, "fail at getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    for (struct addrinfo *p = si; p != NULL; p = p->ai_next) {
        void *addr;
        char ip_addr[INET6_ADDRSTRLEN] = { 0 };

        // use struct based on connection type
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *remote = (struct sockaddr_in *)p->ai_addr;
            addr = &remote->sin_addr;
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6 *remote = (struct sockaddr_in6 *)p->ai_addr;
            addr = &remote->sin6_addr;
        } else {
            fputs("host_connect(): unsupported addr result\n", stderr);
            continue;
        }

        inet_ntop(p->ai_family, addr, ip_addr, INET6_ADDRSTRLEN);
        if (debug) fprintf(stderr, "IP addr: %s\n", ip_addr);

        // try to establish connection
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("couldn't create socket");
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            perror("couldn't connect to socket");
            close(fd);
            continue;
        }

        // only use first addr, for now
        break;
    }
    freeaddrinfo(si);

    return fd;
}
