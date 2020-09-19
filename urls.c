#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "purr.h"

#define MAX_DOMAIN_LEN 254
#define MAX_SHORTY_LEN 16

static const char *http_sch = "http://";
static const char *https_sch = "https://";
static const char *gemini_sch = "gemini://";

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
    const char *scheme_separator = strstr(dirty, "://");
    const char *start_link = NULL;
    if (scheme_separator == NULL) {
        // no protocol specified, default to HTTP
        portn = HTTP_PORT;
        strcpy(scheme, http_sch);
        start_link = dirty;
    } else {
        if (scheme_separator - dirty + 3 > MAX_SHORTY_LEN) {
            fputs("clean_up_link(): scheme is too long!\n", stderr);
            return -1;
        }
        memcpy(scheme, dirty, scheme_separator - dirty + 3);
        if (strcmp(scheme, https_sch) == 0) {
            portn = HTTPS_PORT;
        } else if (strcmp(scheme, http_sch) == 0) {
            portn = HTTP_PORT;
        } else if (strcmp(scheme, gemini_sch) == 0) {
            portn = GEMINI_PORT;
        } else {
            fputs("clean_up_link(): unknown protocol!\n", stderr);
            return -1;
        }

        start_link = dirty + strlen(scheme);
    }

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
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("socket()");
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            perror("connect()");
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
