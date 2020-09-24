#ifdef HAVE_PROG_INVOCATION
#define _GNU_SOURCE
#include <errno.h>
#endif

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bearssl.h>

#include "purr.h"
#include "mmap_file.h"
#include "read_certs.h"

const char *progname;

// value defined in
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
// used for https://tools.ietf.org/html/rfc7301
const char *alpn_list[] = { "http/1.0" };
const size_t alpn_n = 1;

__attribute__ ((noreturn))
static void usage(bool fail)
{
    char *proghelp;
    if (strcmp(progname, "meow") == 0) {
        proghelp =
            "Usage: meow [options] <file>\n"
            "    send <file> in encrypted format\n";
    } else if (strcmp(progname, "meowd") == 0) {
        proghelp =
            "Usage meowd [options] <url>\n"
            "    receive encrypted file from <url>\n";
    } else {
       proghelp =
           "Usage: purr [options] <action> <file>|<url>\n"
           "    action: s[end] | r[ecv]\n";
    }

    printf(
        "%s"
        "Options:\n"
        "    -a <algo>: choose algorithm, none available\n"
        "    -u <url>: URL to use for send functionality\n"
        "    -p <port>: port to use for send\n"
        "    -o <output_file>: use file instead of stdout\n"
        "    -n: don't strip HTTP header from response\n"
        "    -e: encrypt content: limited to 128KiB files\n"
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

    #ifdef HAVE_PROG_INVOCATION
    progname = program_invocation_short_name;
    #elif HAVE_GETPROGNAME
    progname = getprogname();
    #else
    #error "no progname impl"
    #endif /* PROG_INVOCATION & GETPROGNAME */

    // check program name:
    // symlinks to original program with special behavior
    if (strcmp(progname, "meow") == 0) {
        // encrypted send mode
        send = true;
        encrypt = true;
    } else if (strcmp(progname, "meowd") == 0) {
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
        // means the symlink variants are being used
        argc++;
        argv--;
    } else {
        if (argc < 1) {
            usage(true);
        }

        if (strcmp(argv[0], "recv") == 0 || strcmp(argv[0], "r") == 0) {
            recv = true;
        } else if (strcmp(argv[0], "send") == 0 || strcmp(argv[0], "s") == 0) {
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
            output_print = fopen(output_file, "we");
            if (output_print == NULL) {
                perror("couldn't open output file");
                exit(EXIT_FAILURE);
            }
        }

        if (url_opt) {
            fputs("discarding url arg...\n", stderr);
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

    char *scheme = NULL, *link = NULL, *path = NULL, *port = NULL;
    int portn = clean_up_link(url, &scheme, &link, &path, &port);
    if (portn == -1) {
        fputs("couldn't parse URL!\n", stderr);
        rv = EXIT_FAILURE;
        goto early_out;
    } else if (portn != HTTPS_PORT && portn != HTTP_PORT) {
        fputs("only supports HTTP and HTTPS for now!\n", stderr);
        rv = EXIT_FAILURE;
        goto early_out;
    }

    // clean up hash property, if present
    char *hash_prop;
    if (!encrypt && (hash_prop = strchr(path, '#'))) {
        *hash_prop = 0;
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
            rv = EXIT_FAILURE;
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
    // using HTTP/1.0, to avoid implementation complexity
    // https://stackoverflow.com/questions/246859/http-1-0-vs-1-1
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

    size_t num_ta = 0;
    br_x509_trust_anchor *btas = NULL;

    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    uint8_t iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;

    int socket;
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

        // this function only takes the pointer to socket, so it's safe
        // to use unitialized socket
        br_sslio_init(&ioc, &sc.eng, socket_read, &socket, socket_write, &socket);
    }

    socket = host_connect(link, port, debug);
    if (socket < 0) {
        fputs("couldn't open socket / find domain\n", stderr);
        goto early_out;
    }
    // avoid crashing on socket release
    signal(SIGPIPE, SIG_IGN);

    struct connection_information ci =
        {.ioc = &ioc, .sc = &sc,
         .alpn_list = alpn_list, .alpn_n = alpn_n,
         .request = request, .request_size = written,
         .input = &input, .output = &output,
         .socket = socket,
         .send = send, .ssl = (portn == HTTPS_PORT),
         .no_strip = no_strip, .debug = debug};

    rv = send_and_receive(&ci);
    // clean-up
    close(socket);
    bearssl_free_certs(&btas, num_ta);

    if (send && encrypt) {
        // backend can't distinguish between a normal and an encrypted paste,
        // but the links for accessing each are different,
        // so we need to fix it locally
        char *scheme_res = NULL, *link_res = NULL, *path_res = NULL, *port_res = NULL;
        int portn_res =
            clean_up_link((char *)output.data, &scheme_res, &link_res, &path_res, &port_res);
        if (portn_res == -1) {
            fprintf(stderr, "couldn't clean up received link: %s\n", (char *)output.data);
            goto out;
        }

        // clean up linebreak
        char *linebreak = strchr(path_res, '\n');
        if(linebreak) {
            *linebreak = 0;
        }

        char *key_s = print_hex(key, KEY_LEN, false);
        char *iv_s = print_hex(iv, IV_LEN, false);
        if (key_s == NULL || iv_s == NULL) {
            perror("malloc()");
            goto out;
        }

        fprintf(output_print, "%s%s/paste.html#%s_%s_%s",
                scheme_res, link_res, path_res + 1, key_s, iv_s);

        free(scheme_res);
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

  out:
    free(scheme);
    free(link);
    free(path);
    free(port);
    free(request);
    free(key);
    free(iv);
  early_out:
    if (output_print != stdout) fclose(output_print);
    free_mmap(&input);
    free_mmap(&output);

    return rv;
}
