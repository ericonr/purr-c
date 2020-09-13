#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

#include "purr.h"

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

    struct mmap_file input;
    struct mmap_file output = create_mmap_from_file(NULL, PROT_WRITE | PROT_READ);
    if (ERROR_MMAP(output)) {
        perror("couldn't open output file");
        exit(EXIT_FAILURE);
    }
    FILE * output_print = stdout;
    char *url;
    if (recv) {
        if (argc != 2) {
            usage(true);
        }
        if (output_file && strcmp(output_file, "-")) {
            output_print = fopen(output_file, "w");
            if (output_print == NULL) {
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
            input = create_mmap_from_file(argv[1], PROT_READ);
            if (ERROR_MMAP(input)) {
                perror("couln't open input file");
                exit(EXIT_FAILURE);
            }
        } else if (argc > 2) {
            usage(true);
        } else {
            fputs("stdin not supported for now!\n", stderr);
            exit(EXIT_FAILURE);
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
                           path, link, port, input.size);
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
        }

        br_ssl_client_init_full(&sc, &xc, btas, num_ta);
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
        br_ssl_client_reset(&sc, link, 0);
    }

    uint8_t *key = NULL;
    uint8_t *iv = NULL;
    if (send && encrypt) {
        // requires error checking
        input = encrypt_mmap(input, &key, &iv);
        if(ERROR_MMAP(input)) {
            rv = EXIT_FAILURE;
            goto early_out;
        }
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
         .input = &input, .output = &output,
         .socket = socket,
         .send = send, .ssl = (portn == HTTPS_PORT),
         .no_strip = no_strip, .debug = debug};

    rv = send_and_receive(&ci);

    if (fwrite(output.data, 1, output.offset, output_print) < output.offset) {
        fputs("might not have written all data\n", stderr);
    }
    if (encrypt) {
        print_hex(key, KEY_LEN, true);
    }

  //out:
    close(socket);
    free(link);
    free(path);
    free(port);
    free(request);
    free(key);
    free(iv);
  early_out:
    CLOSE_MMAP(input);
    CLOSE_MMAP(output);

    return rv;
}
