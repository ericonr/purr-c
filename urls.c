#define _POSIX_C_SOURCE 200112L /* addrinfo */
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#ifndef HAVE_SOCK_CLOEXEC_H
#include <fcntl.h>
#endif /* HAVE_SOCK_CLOEXEC_H */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "purr.h"

#define MAX_DOMAIN_LEN 254
#define MAX_SHORTY_LEN 16

/* enable atomic close-on-exec for socket */
#ifdef HAVE_SOCK_CLOEXEC_H
#define SOCKET_FLAG SOCK_CLOEXEC
#else
#define SOCKET_FLAG 0
#endif /* HAVE_SOCK_CLOEXEC_H */

static const char *http_sch = "http://";
static const char *https_sch = "https://";
static const char *gemini_sch = "gemini://";

int get_port_from_link(const char *url)
{
    int portn = -1;
    const char *scheme_separator = strstr(url, "://");
    if (scheme_separator) {
        // found protocol specified, otherwise return error
        if (scheme_separator - url + 3 > MAX_SHORTY_LEN) {
            fputs("get_port_from_link(): scheme is too long!\n", stderr);
            return portn;
        }
        size_t scheme_len = scheme_separator - url + 3;
        if (memcmp(url, https_sch, scheme_len) == 0) {
            portn = HTTPS_PORT;
        } else if (memcmp(url, http_sch, scheme_len) == 0) {
            portn = HTTP_PORT;
        } else if (memcmp(url, gemini_sch, scheme_len) == 0) {
            portn = GEMINI_PORT;
        } else {
            portn = UNKNOWN_PORT;
            fputs("clean_up_link(): unknown protocol!\n", stderr);
        }
    }

    return portn;
}

/*
 * This function cleans up the link in dirty, providing each of its parts in the
 * buffers pointed to by schemep, cleanp, pathp and portp.
 * The path will include the hash property of the link.
 *
 * The buffers are expected to be zeroed out, so passing NULL pointers is recommended,
 * as the function can calloc them itself.
 */
int clean_up_link(const char *dirty, char **schemep, char **cleanp, char **pathp, char **portp)
{
    int portn = -1;

    // allocate strings, if they don't already exist
    size_t allocate = strlen(dirty);
    char *scheme = *schemep ? *schemep : calloc(MAX_SHORTY_LEN, 1);
    char *clean = *cleanp ? *cleanp : calloc(MAX_DOMAIN_LEN, 1);
    char *path = *pathp ? *pathp : calloc(allocate, 1);
    char *port = *portp ? *portp : calloc(MAX_SHORTY_LEN, 1);

    if (scheme == NULL || clean == NULL || path == NULL || port == NULL) {
        perror("allocation failure");
        return portn;
    }

    *schemep = scheme;
    *cleanp = clean;
    *pathp = path;
    *portp = port;

    // detect protocol, remove protocol prefix
    const char *start_link = NULL;
    portn = get_port_from_link(dirty);
    bool get_scheme_len = true;
    if (portn == UNKNOWN_PORT) {
        fputs("clean_up_link(): unknown protocol!\n", stderr);
        return portn;
    } else if (portn == NO_INFO_PORT || portn == HTTP_PORT) {
        // no scheme defined -> default to HTTP
        // if no scheme defined -> no need to advance scheme
        get_scheme_len = portn != NO_INFO_PORT;
        portn = HTTP_PORT;
        strcpy(scheme, http_sch);
    } else if (portn == HTTPS_PORT) {
        strcpy(scheme, https_sch);
    } else if (portn == GEMINI_PORT) {
        strcpy(scheme, gemini_sch);
    }
    start_link = dirty + (get_scheme_len ? strlen(scheme) : 0);

    // maximum size necessary
    // use strncpy for portability
    // fill up to buffer size minus 1, which is fine for termination, since buffer is calloc'd
    strncpy(clean, start_link, MAX_DOMAIN_LEN - 1);
    char *slash = strchr(clean, '/');
    if (slash != NULL) {
        // copy to path
        strncpy(path, slash, allocate - 1);
        // slashes found at the end of the link
        *slash = 0;
    } else {
        path[0] = '/';
        path[1] = 0;
    }

    sprintf(port, "%d", portn);

    return portn;
}

#define MALFORM_ERROR(p) do{if((p) == NULL || (p)[1] == 0) {fputs("get_encryption_params(): malformed URL\n", stderr); return rv;}}while(0);

/*
 * This function extracts encryption parameters from a path.
 * It expects paths in the format "/paste.html#<actual_path>_<key>[_<iv>]",
 * and will update the path arg to an appropriate value.
 */
int get_encryption_params(char *path, uint8_t **keyp, uint8_t **ivp)
{
    int rv = -1;
    // parse path in format: "/paste.html#<actual_path>_<key>[_<iv>]"
    // will update path to point to the proper piece
    uint8_t *key = calloc(KEY_LEN, 1);
    uint8_t *iv = calloc(IV_LEN, 1);
    char *path_temp = calloc(strlen(path), 1);
    if (key == NULL || iv == NULL || path_temp == NULL) {
        perror("calloc()");
        return rv;
    }
    *keyp = key;
    *ivp = iv;

    char *hash = strchr(path, '#');
    MALFORM_ERROR(hash);
    char *underscore = strchr(hash + 1, '_');
    MALFORM_ERROR(underscore);
    underscore[0] = 0;

    sprintf(path_temp, "/%s", hash + 1);

    char *key_start = underscore + 1;
    underscore = strchr(key_start, '_');
    MALFORM_ERROR(underscore);
    underscore[0] = 0;
    char *iv_start = underscore + 1;

    size_t key_s_len = strlen(key_start), iv_s_len = strlen(iv_start);
    // odd number of chars is an error, as well as being too big
    if (key_s_len & 1 || iv_s_len & 1 || key_s_len / 2 > KEY_LEN || iv_s_len / 2 > IV_LEN) {
        fputs("get_encryption_params(): malformed KEY and/or IV input\n", stderr);
        return rv;
    }

    int err = decode_hex(key_start, key, key_s_len / 2)
        | decode_hex(iv_start, iv, iv_s_len / 2);
    if (err) {
        fputs("get_encryption_params(): malformed KEY and/or IV input\n", stderr);
        return rv;
    }

    strcpy(path, path_temp);
    free(path_temp);

    rv = 0;
    return rv;
}

int host_connect(const char *host, const char *port, bool debug)
{
    struct addrinfo hints = { 0 }, *si = NULL;
    int fd = -1, err = 0;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &si);
    if (err) {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(err));
        // if there's an error, si isn't allocated
        return fd;
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
        fd = socket(p->ai_family, p->ai_socktype | SOCKET_FLAG, p->ai_protocol);
        if (fd < 0) {
            perror("socket()");
            continue;
        }
        #ifndef HAVE_SOCK_CLOEXEC_H
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        #endif /* HAVE_SOCK_CLOEXEC_H */

        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            // connect errors can be caused server-side
            if (debug) perror("connect()");
            close(fd);
            fd = -1;
            continue;
        }

        // only use first addr, for now
        break;
    }

    freeaddrinfo(si);
    return fd;
}
