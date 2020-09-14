#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bearssl.h>

#include "purr.h"
#include "mmap_file.h"
#include "read_certs.h"

__attribute__ ((noreturn))
static void usage(bool fail)
{
    char *proghelp;
    if (strcmp(program_invocation_short_name, "meow") == 0) {
        proghelp =
            "Usage: meow [options] <file>\n"
            "    send <file> in encrypted format\n";
    } else if (strcmp(program_invocation_short_name, "meowd") == 0) {
        proghelp =
            "Usage meowd [options] <url>\n"
            "    receive encrypted file from <url>\n";
    } else {
       proghelp =
           "Usage: purr [options] <action> <file>|<url>\n"
           "    action: send | recv\n";
    }

    printf(
        "%s"
        "Options:\n"
        "    -a <algo>: choose algorithm, none available\n"
        "    -u <url>: URL to use for send functionality\n"
        "    -p <port>: port to use for send\n"
        "    -o <output_file>: use file instead of stdout\n"
        "    -n: don't strip HTTP header from response\n"
        "    -e: encrypt content\n"
        "    -d: debug\n"
        "    -h: show this dialog\n"
        "Environment:\n"
        "    CA_CERT_SSL_FILE: certificates file, default is /etc/ssl/certs.pem\n",
        proghelp
    );

    exit(fail? EXIT_FAILURE : EXIT_SUCCESS);
}

int main (int argc, char **argv)
{
    int rv = EXIT_SUCCESS;

    char *algo = NULL, *url_opt = NULL, *port_opt = NULL, *output_file = NULL;
    bool no_strip = false, encrypt = false, debug = false;

    bool send = false, recv = false;

    if (strcmp(program_invocation_short_name, "meow") == 0) {
        // encrypted send mode
        send = true;
        encrypt = true;
    } else if (strcmp(program_invocation_short_name, "meowd") == 0) {
        // encrypted recv mode
        recv = true;
        encrypt = true;
    } else if (argc < 2) {
        usage(true);
    }

    int c;
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

    if (recv || send) {
        argc++;
        argv--;
    } else {
        if (argc < 1) {
            usage(true);
        }

        if (strcmp(argv[0], "recv") == 0) {
            recv = true;
        } else if (strcmp(argv[0], "send") == 0) {
            send = true;
        } else {
            usage(true);
        }
    }

    struct mmap_file input;
    struct mmap_file output = create_mmap_from_file(NULL, PROT_MEM);
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
            fputs("stdin not supported for ~now~ meow!\n", stderr);
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

    uint8_t *key = NULL;
    uint8_t *iv = NULL;
    if (send && encrypt) {
        // requires error checking
        input = encrypt_mmap(input, &key, &iv);
        if(ERROR_MMAP(input)) {
            rv = EXIT_FAILURE;
            goto early_out;
        }
    } else if (recv && encrypt) {
        int err = get_encryption_params(path, &key, &iv);
        if (err) {
            fputs("get_encription_params(): error decoding url\n", stderr);
            goto early_out;
        }
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

        num_ta = bearssl_read_certs(&btas);
        if (num_ta == 0) {
            fputs("couldn't open certs\n", stderr);
            goto early_out;
        }
        br_ssl_client_init_full(&sc, &xc, btas, num_ta);
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
        br_ssl_client_reset(&sc, link, 0);
    }

    int socket = host_connect(link, port, debug);
    if (socket < 0) {
        fputs("couldn't open socket / find domain\n", stderr);
        goto early_out;
    }
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

    if (send && encrypt) {
        size_t allocate_res = strlen((char *)output.data) + 1;
        char *link_res = calloc(allocate_res, 1);
        char *path_res = calloc(allocate_res, 1);
        char *port_res = calloc(16, 1);
        if (link_res == NULL || path_res == NULL || port_res == NULL) {
            perror("allocation failure");
            exit(EXIT_FAILURE);
        }
        clean_up_link((char *)output.data, link_res, path_res, port_res);

        // clean up linebreak
        char *linebreak = strchr(path_res, '\n');
        if(linebreak) {
            *linebreak = 0;
        }

        char *key_s = print_hex(key, KEY_LEN, false);
        char *iv_s = print_hex(iv, IV_LEN, false);
        if (key_s == NULL || iv_s == NULL) {
            perror("malloc()");
            goto early_out;
        }

        // TODO: fix hack for https link
        fprintf(output_print, "https://%s/paste.html#%s_%s_%s",
                link_res, path_res + 1, key_s, iv_s);

        free(link_res);
        free(path_res);
        free(port_res);
        free(key_s);
        free(iv_s);
    } else if (recv && encrypt) {
        output = decrypt_mmap(output, key, iv);
        fwrite(output.data, 1, output.size, output_print);
    } else if ((off_t)fwrite(output.data, 1, output.offset, output_print) < output.offset) {
        fputs("might not have written all data\n", stderr);
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
    if (output_print != stdout) fclose(output_print);
    CLOSE_MMAP(input);
    CLOSE_MMAP(output);

    return rv;
}
