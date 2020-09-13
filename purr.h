#ifndef __PURR_H_
#define __PURR_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <bearssl.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define HEADER_MAX_LEN 8192

#define KEY_LEN 32
#define IV_LEN br_aes_big_BLOCK_SIZE

#define NO_RANDOMIZE_IV

struct strip_header_info {
    FILE *output;
    char *header;
    int counter, header_counter;
    bool no_strip, debug;
};

struct connection_information {
    br_sslio_context *ioc;
    br_ssl_client_context *sc;
    const char *request;
    size_t request_size;
    FILE *input, *output;
    int socket;
    bool send, ssl;
    bool no_strip, debug;
};

struct transmission_information {
    br_sslio_context *ioc;
    FILE *file;
    int socket;
    bool no_strip, debug, ssl;
};

/* sockets.c */
int socket_read(void *, uint8_t *, size_t);
int socket_write(void *, const uint8_t *, size_t);

/* urls.c */
int clean_up_link(const char *, char *, char *, char *);
int host_connect(const char *, const char *, bool);

/* files.c */
size_t fwrite_strip(const uint8_t *, int, struct strip_header_info *);
size_t ssl_to_FILE(struct transmission_information);
size_t FILE_to_ssl(struct transmission_information);

/* comm.c */
int send_and_receive(struct connection_information *);

/* formats.c */
char *print_hex(uint8_t *, int, bool);

/* encrypt.c */
int encrypt_FILE(FILE **, uint8_t **, uint8_t **);

#endif // __PURR_H_
