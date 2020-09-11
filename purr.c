#define _ALL_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/mman.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define HEADER_MAX_LEN 8192

#define KEY_LEN 32
#define IV_LEN br_aes_big_BLOCK_SIZE

// helper functions
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
static int socket_read(void *, uint8_t *, size_t);
static int socket_write(void *, const uint8_t *, size_t);
static int clean_up_link(const char *, char *, char *, char *);
static int host_connect(const char *, const char *, bool);
static size_t fwrite_strip(const uint8_t *, int, struct strip_header_info *);
static size_t ssl_to_FILE(struct transmission_information);
static size_t FILE_to_ssl(struct transmission_information);
static int send_and_receive(struct connection_information *);
static void print_hex(uint8_t *, int);

__attribute__ ((noreturn))
static void usage(bool fail)
{
    puts("Usage: purrito [options] <action> [FILE]\n"
         "    action: send | recv\n"
         "Options:\n"
         "    -a <algo>: choose algorithm, none available\n"
         "    -u <url>: URL to use for send functionality\n"
         "    -p <port>: port to use for send\n"
         "    -o <output_file>: use file instead of stdout\n"
         "    -n: don't strip HTTP header from response\n"
         "    -e: encrypt content\n"
         "    -d: debug"
         "    -h: show this dialog"
    );

    exit(fail? EXIT_FAILURE : EXIT_SUCCESS);
}

int main (int argc, char **argv)
{
    int rv = EXIT_SUCCESS;

    if (argc < 2) {
        usage(true);
    }

    int c;
    char *algo = NULL, *url_opt = NULL, *port_opt = NULL, *output_file = NULL;
    bool no_strip = false, encrypt = false, debug = false;
    while ((c = getopt(argc, argv, "a:u:p:o:nedh")) != -1) {
        switch (c) {
            case 'a':
                algo = optarg;
                // algo is unused for now
                (void) algo;
                usage(true);
                break;
            case 'u':
                url_opt = optarg;
                break;
            case 'p':
                port_opt = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'n':
                no_strip = true;
                break;
            case 'e':
                encrypt = true;
                break;
            case 'd':
                debug = true;
                break;
            case 'h':
                usage(false);
            default:
                usage(true);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage(true);
    }

    bool send = false, recv = false;
    if (strcmp(argv[0], "recv") == 0) {
        recv = true;
    } else if (strcmp(argv[0], "send") == 0) {
        send = true;
    } else {
        usage(true);
    }

    FILE *input = stdin;
    FILE *output = stdout;
    char *url;
    if (recv) {
        if (argc != 2) {
            usage(true);
        }
        if (output_file && strcmp(output_file, "-")) {
            output = fopen(output_file, "w");
            if (output == NULL) {
                perror("couldn't open output file");
                exit(EXIT_FAILURE);
            }
        }
        if (url_opt) {
            fputs("discarding url...\n", stderr);
        }
        url = argv[1];
    } else if (send) {
        if (argc == 2 && strcmp(argv[1], "-")) {
            input = fopen(argv[1], "r");
            if (input == NULL) {
                perror("couln't open input file");
                exit(EXIT_FAILURE);
            }
        } else if (argc > 2) {
            usage(true);
        }

        if (url_opt) {
            url = url_opt;
        } else {
            // http for now
            url = "http://bsd.ac";
        }
    }

    size_t allocate = strlen(url) + 1;
    char *link = calloc(allocate, 1);
    char *path = calloc(allocate, 1);
    char *port = calloc(16, 1);
    if (link == NULL || path == NULL || port == NULL) {
        perror("allocation failure");
        exit(EXIT_FAILURE);
    }
    int portn = clean_up_link(url, link, path, port);
    if (portn == -1) {
        fputs("couldn't parse URL!\n", stderr);
        rv = EXIT_FAILURE;
        goto early_out;
    } else if (portn != HTTPS_PORT && portn != HTTP_PORT) {
        fputs("only supports HTTP and HTTPS for now!\n", stderr);
        rv = EXIT_FAILURE;
        goto early_out;
    }

    // TODO: fix size
    const int going_to_write = HEADER_MAX_LEN;
    char *request = calloc(going_to_write, 1);
    if (request == NULL) {
        perror("allocation failure");
        rv = EXIT_FAILURE;
        goto early_out;
    }

    // assemble request
    // based on https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
    int written = 0;
    if (recv) {
        written = snprintf(request, going_to_write,
                           "GET %s HTTP/1.0\r\n"
                           "Host: %s\r\n"
                           "Accept: */*\r\n"
                           "\r\n",
                           path, link);
    } else if (send) {
        struct stat st;
        fstat(fileno(input), &st);
        if (port_opt) {
            strncpy(port, port_opt, 16);
        } else if (url_opt == NULL) {
            // purrito by default uses port 42069
            strcpy(port, "42069");
        }
        // use header similar to curl's
        written = snprintf(request, going_to_write,
                           "POST %s HTTP/1.0\r\n"
                           "Host: %s:%s\r\n"
                           "Accept: */*\r\n"
                           "Content-Length: %lu\r\n"
                           "Content-Type: application/x-www-form-urlencoded\r\n"
                           "\r\n",
                           path, link, port, st.st_size);
    }
    if (written >= going_to_write) {
        fputs("warning: truncated request!\n", stderr);
    }
    if (debug) {
        fputs("request header: -------------\n", stderr);
        fputs(request, stderr);
        fputs("-----------------------------\n", stderr);
    }

    // TODO: use only bearssl
    genalloc ta_list = GENALLOC_ZERO;
    stralloc ta_content = STRALLOC_ZERO;
    size_t num_ta;
    br_x509_trust_anchor *btas;

    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    uint8_t iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;

    if (portn == HTTPS_PORT) {
        if (debug) {
            fputs("reading certs...\n", stderr);
        }
        sbearssl_ta_readdir("/usr/share/ca-certificates/mozilla", &ta_list, &ta_content);
        num_ta = genalloc_len(sbearssl_ta, &ta_list);
        btas = calloc(num_ta, sizeof *btas);
        {
            size_t i = num_ta;
            while(i--) sbearssl_ta_to(genalloc_s(sbearssl_ta, &ta_list) + i, btas + i, ta_content.s);
            genalloc_free(sbearssl_ta, &ta_list);
            stralloc_free(&ta_content);
        }

        br_ssl_client_init_full(&sc, &xc, btas, num_ta);
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
        br_ssl_client_reset(&sc, link, 0);
    }

    uint8_t *key = NULL;
    uint8_t *iv = NULL;
    char *temp = NULL;
    if (send && encrypt) {
        if (input == stdin)  {
            fputs("currently can't encrypt stdin!\n", stderr);
            goto early_out;
        }
        struct stat s;
        int errs = fstat(fileno(input), &s);
        if (errs != 0) {
            perror("couldn't stat output!");
            goto early_out;
        }
        off_t file_size = s.st_size;
        ssize_t blocks = file_size / br_aes_big_BLOCK_SIZE;
        if (blocks * br_aes_big_BLOCK_SIZE < file_size) blocks++;
        file_size = blocks * br_aes_big_BLOCK_SIZE;

        key = calloc(KEY_LEN, 1);
        iv = calloc(IV_LEN, 1);
        if (key == NULL || iv == NULL) {
            perror("allocation failure");
            goto early_out;
        }

        ssize_t err = getrandom(key, KEY_LEN, 0);
        if (err != KEY_LEN) {
            fputs("getrandom() error!\n", stderr);
            goto early_out;
        }
        err = getrandom(iv, IV_LEN, 0);
        if (err != IV_LEN) {
            fputs("getrandom() error!\n", stderr);
            goto early_out;
        }

        temp = strdup("/tmp/purrito.XXXXXX");
        int tfd = mkstemp(temp);
        if (tfd < 0) {
            perror("couldn't create temp file");
            goto early_out;
        }
        int errfa = posix_fallocate(tfd, 0, file_size);
        if (errfa) {
            perror("error while fallocating");
            goto early_out;
        }
        uint8_t *temp_map =
            mmap(NULL, file_size, PROT_WRITE, MAP_SHARED, tfd, 0);
        if (temp_map == NULL) {
            perror("mmap failure");
            goto early_out;
        }
        close(tfd);

        for (ssize_t i = 0; i < blocks; i++) {
            // zero padding for the last round
            uint8_t tmp[br_aes_big_BLOCK_SIZE]  = { 0 };
            fread(tmp, 1, br_aes_big_BLOCK_SIZE, output);
            memcpy(temp_map + i * br_aes_big_BLOCK_SIZE, tmp, br_aes_big_BLOCK_SIZE);
        }

        br_aes_big_cbcenc_keys br = { 0 };
        br_aes_big_cbcenc_init(&br, key, KEY_LEN);
        br_aes_big_cbcenc_run(&br, iv, temp_map, file_size);

        fclose(output);
        munmap(temp_map, file_size);

        output = fopen(temp, "r");
        if (output == NULL) {
            perror("couldn't read temp file");
            goto early_out;
        }
        fstat(fileno(output), &s);
        fprintf(stderr, "output file size: %lu\n", s.st_size);
    }

    int socket = host_connect(link, port, debug);
    // avoid crashing on socket release
    signal(SIGPIPE, SIG_IGN);

    if (portn == HTTPS_PORT) {
        br_sslio_init(&ioc, &sc.eng, socket_read, &socket, socket_write, &socket);
    }

    struct connection_information ci =
        {.ioc = &ioc, .sc = &sc,
         .request = request, .request_size = written,
         .input = input, .output = output,
         .socket = socket,
         .send = send, .ssl = (portn == HTTPS_PORT),
         .no_strip = no_strip, .debug = debug};

    rv = send_and_receive(&ci);

  //out:
    close(socket);
    free(link);
    free(path);
    free(port);
    free(request);
    free(key);
    free(iv);
    free(temp);
  early_out:
    if (input != stdin) fclose(input);
    if (output != stdout) fclose(output);

    return rv;
}

static int socket_read(void *ctx, uint8_t *buf, size_t len)
{
    int fd = *(int *)ctx;
    while (1) {
        ssize_t rlen = read(fd, buf, len);
        if (rlen <= 0) {
            if (rlen < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        return (int)rlen;
    }
}

static int socket_write(void *ctx, const uint8_t *buf, size_t len)
{
    int fd = *(int *)ctx;
    while (1) {
        ssize_t wlen = write(fd, buf, len);
        if (wlen <= 0) {
            if (wlen < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        return (int)wlen;
    }
}

static int clean_up_link(const char *dirty, char *clean, char *path, char *port)
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

static int host_connect(const char *host, const char *port, bool debug)
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

static size_t fwrite_strip(const uint8_t *buf, int rlen, struct strip_header_info *st)
{
    if (st->no_strip) {
        return fwrite(buf, 1, rlen, st->output);
    }

    const char *separator = "\r\n\r\n";
    const int len = 4;

    int i = 0;
    if (st->counter != len) {
        for (; i < rlen; i++) {
            if (buf[i] == separator[st->counter]) {
                st->counter++;
            } else {
                st->counter = 0;
                if (buf[i] == separator[st->counter]) {
                    st->counter++;
                }
            }

            if (st->debug) {
                fputc(buf[i], stderr);
            }

            if (st->header_counter < HEADER_MAX_LEN - 1) {
                // protect from buffer overflow
                // the header buffer is calloc'd, so no need to terminate it manually
                st->header[st->header_counter++] = buf[i];
            }

            if (st->counter == len) {
                // eat last matching char
                i++;
                break;
            }
        }
    }

    return fwrite(buf + i, 1, rlen - i, st->output);
}

static size_t ssl_to_FILE(struct transmission_information ti)
{
    size_t rv = 0;
    struct strip_header_info st =
        {.output = ti.file, .header = calloc(HEADER_MAX_LEN, 1), .debug = ti.debug, .no_strip = ti.no_strip};
    if (st.header == NULL) {
        perror("allocation failure");
        return -1;
    }

    char *length = NULL;
    size_t transmission_size = 0;
    bool tried_content_length = false;
    while (1) {
        uint8_t tmp[512];
        int rlen;
        if (ti.ssl) {
            rlen = br_sslio_read(ti.ioc, tmp, sizeof tmp);
        } else {
            rlen = socket_read(&ti.socket, tmp, sizeof tmp);
        }

        if (rlen < 0) {
            break;
        }

        rv += fwrite_strip(tmp, rlen, &st);

        // check if header is done
        // TODO: currently works only in strip mode
        if (st.counter == 4) {
            if (length == NULL && !tried_content_length) {
                tried_content_length = true;
                const char *needle = "Content-Length: ";
                length = strstr(st.header, needle);
                if (length) {
                    transmission_size = atoll(length + strlen(needle));
                }
            }
            if (transmission_size) {
                if (transmission_size == rv) break;
            }
        }
    }

    free(st.header);
    return rv;
}

static size_t FILE_to_ssl(struct transmission_information ti)
{
    size_t rv = 0;
    while (1) {
        uint8_t tmp[512];
        size_t wlen = fread(tmp, 1, sizeof tmp, ti.file);
        if (wlen == 0) {
            break;
        }
        int err;
        if (ti.ssl) {
            err = br_sslio_write_all(ti.ioc, tmp, wlen);
        } else {
            ssize_t wlen_local = wlen;
            while (wlen_local) {
                ssize_t written = write(ti.socket, tmp, wlen_local);
                if (written > 0) wlen_local -= written;
                // TODO: add error checking
                err = 0;
            }
        }
        if (err == 0) {
            rv += wlen;
        }
        if (wlen < sizeof tmp) {
            break;
        }
    }

    return rv;
}

static int send_and_receive(struct connection_information *ci)
{
    struct transmission_information ti =
        {.ioc = ci->ioc,
         .no_strip = ci->no_strip, .debug = ci->debug,
         .socket = ci->socket,
         .ssl = ci->ssl};

    ti.file = ci->input;

    if (ti.ssl) {
        br_sslio_write_all(ci->ioc, ci->request, ci->request_size);
    } else {
        while (ci->request_size) {
            ssize_t wlen;
            wlen = socket_write(&ci->socket, (uint8_t *)ci->request, ci->request_size);
            if (wlen > 0) ci->request_size -= wlen;
            // TODO: doesn't treat sending errors
        }
    }

    if (ci->send) {
        size_t sent = FILE_to_ssl(ti);
        if (sent == 0) {
            fputs("warning: empty input file...\n", stderr);
        }
        if (ci->debug) {
            fprintf(stderr, "wrote %lu bytes!\n", sent);
        }
    }
    if (ti.ssl) br_sslio_flush(ci->ioc);

    ti.file = ci->output;

    if (ssl_to_FILE(ti) == 0) {
        fputs("warning: empty response...\n", stderr);
    }

    int rv = 0;
    if (ti.ssl) {
        if (br_sslio_close(ci->ioc) != 0) {
            fputs("couldn't close SSL connection!\n", stderr);
        }

        // check whether everything was closed properly
        if (br_ssl_engine_current_state(&ci->sc->eng) == BR_SSL_CLOSED) {
            int err = br_ssl_engine_last_error(&ci->sc->eng);
            if (err == 0) {
                if (ci->debug) fputs("all good!\n", stderr);
                rv = EXIT_SUCCESS;
            } else {
                fprintf(stderr, "SSL error: %d\n", err);
                rv = EXIT_FAILURE;
            }
        } else {
            fputs("socket closed without terminating ssl!\n", stderr);
            rv = EXIT_FAILURE;
        }
    }

    return rv;
}

// for keys...
// still needs to base64 encode / decode the whole mess
static void print_hex(uint8_t *buf, int len)
{
    puts("");
}
