#ifndef __PURR_H_
#define __PURR_H_

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <bearssl.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define HEADER_MAX_LEN 8192

#define NET_BLOCK_SIZE 512

#define KEY_LEN 32
#define IV_LEN br_aes_big_BLOCK_SIZE

#define RANDOMIZE_IV
#define ENCODE_BASE_64
#define DECODE_BASE_64

struct connection_information {
    br_sslio_context *ioc;
    br_ssl_client_context *sc;
    const char *request;
    const char **alpn_list;
    size_t alpn_n;
    size_t request_size;
    struct mmap_file *input, *output;
    int socket;
    bool send, ssl;
    bool no_strip, debug;
};

struct transmission_information {
    br_sslio_context *ioc;
    struct mmap_file *file;
    int socket;
    bool no_strip, debug, ssl;
};

/* socket.c */
int socket_read(void *, uint8_t *, size_t);
int socket_write(void *, const uint8_t *, size_t);

/* urls.c */
int clean_up_link(const char *, char **, char **, char **, char **);
int get_encryption_params(char *, uint8_t **, uint8_t **);
int host_connect(const char *, const char *, bool);

/* files.c */
size_t ssl_to_mmap(struct transmission_information);
size_t mmap_to_ssl(struct transmission_information);

/* comm.c */
int send_and_receive(struct connection_information *);

/* formats.c */
char *print_hex(const uint8_t *, int, bool);
int decode_hex(const char *, uint8_t *, int);

#endif // __PURR_H_
