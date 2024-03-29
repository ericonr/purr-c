#define _POSIX_C_SOURCE 200112L /* getopt */
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bearssl.h>

#include "purr.h"
#include "compat.h"
#include "mmap_file.h"
#include "read_certs.h"
#include "translation.h"

__attribute__ ((noreturn))
static void usage(bool fail)
{
    char *proghelp;
    if (strcmp(program_name(), "meow") == 0) {
        proghelp = _(
            "Usage: meow [options] <file>\n"
            "    send <file> in encrypted format\n");
    } else if (strcmp(program_name(), "meowd") == 0) {
        proghelp = _(
            "Usage meowd [options] <url>\n"
            "    receive encrypted file from <url>\n");
    } else {
        proghelp = _(
            "Usage: purr [options] <action> <file>|<url>\n"
            "    action: s[end] | r[ecv]\n");
    }

    FILE *stream = fail ? stderr : stdout;
    fprintf(stream,
        _("%s"
        "Options:\n"
        "    -a <algo>: choose algorithm, none available\n"
        "    -u <url>: URL to use for send functionality\n"
        "    -p <port>: port to use for send\n"
        "    -o <output_file>: use file instead of stdout\n"
        "    -s: use settings for " "pastebin" /*garbage*/ ".stratumzero." /*garbage*/ "date\n"
        "    -n: don't strip HTTP header from response\n"
        "    -e: encrypt content: limited to 128KiB files\n"
        "    -d: debug\n"
        "    -h: show this dialog\n"
        "Environment:\n"),
        proghelp
    );
    bearssl_read_certs_help(stream);

    exit(fail? EXIT_FAILURE : EXIT_SUCCESS);
}

int main (int argc, char **argv)
{
    int rv = EXIT_SUCCESS;

    char *algo = NULL, *url_opt = NULL, *port_opt = NULL, *output_file = NULL;
    bool no_strip = false, encrypt = false, debug = false, stratum = false;

    bool send = false, recv = false;

    loc_init();

    // check program name:
    // symlinks to original program with special behavior
    if (strcmp(program_name(), "meow") == 0) {
        // encrypted send mode
        send = true;
        encrypt = true;
    } else if (strcmp(program_name(), "meowd") == 0) {
        // encrypted recv mode
        recv = true;
        encrypt = true;
    } else if (argc < 2) {
        usage(true);
    }

    int c;
    while ((c = getopt(argc, argv, "a:u:p:o:snedh")) != -1) {
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
            case 's':
                stratum = true;
                url_opt = "https://" /*garbage*/ "pastebin" /*garbage*/ ".stratumzero." /*garbage*/ "date/" /*garbage*/ "upload";
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

    // output matters for all modes
    FILE * output_print = stdout;
    if (output_file && strcmp(output_file, "-")) {
        output_print = fopen(output_file, "we");
        if (output_print == NULL) {
            perror(_("couldn't open output stream"));
            exit(EXIT_FAILURE);
        }
    }

    // initialize, since we will free_mmap() them
    struct mmap_file input = { 0 };
    struct mmap_file output = { 0 };
    if (encrypt) {
        // encryption happens in-place,
        // easiest way to do it is with mmap
        output = create_mmap_from_file(NULL, PROT_MEM);
    } else {
        output = create_mmap_from_FILE(output_print, "w");
    }
    if (ERROR_MMAP(output)) {
        perror(_("couldn't open output file"));
        exit(EXIT_FAILURE);
    }

    bool using_stdin = false;
    char *url;
    if (recv) {
        if (argc != 2) {
            usage(true);
        }

        if (url_opt) {
            fputs(_("discarding url arg...\n"), stderr);
        }
        url = argv[1];
    } else if (send) {
        if (argc > 2) {
            usage(true);
        } else if (argc == 2 && strcmp(argv[1], "-")) {
            input = create_mmap_from_file(argv[1], PROT_READ);
        } else {
            // it is necessary to read from stdin instead of streaming a file,
            // because the HTTP header includes a Content-Length field,
            // which needs to be populated.
            input = create_mmap_from_file(NULL, PROT_MEM);
            using_stdin = true;
        }

        if (ERROR_MMAP(input)) {
            perror("create_mmap_from_file()");
            exit(EXIT_FAILURE);
        }

        if (using_stdin) {
            input.size = fread(input.data, 1, OUTPUT_FILE_SIZE, stdin);
        }

        if (url_opt) {
            url = url_opt;
        } else {
            // http for now
            url = "https://bsd.ac";
        }
    }

    char *scheme = NULL, *link = NULL, *path = NULL, *port = NULL;
    int portn = clean_up_link(url, &scheme, &link, &path, &port);
    if (portn == -1) {
        fputs(_("couldn't parse URL!\n"), stderr);
        rv = EXIT_FAILURE;
        goto early_out;
    } else if (portn != HTTPS_PORT && portn != HTTP_PORT) {
        fputs(_("only supports HTTP and HTTPS for now!\n"), stderr);
        rv = EXIT_FAILURE;
        goto early_out;
    }

    if (port_opt) {
        strncpy(port, port_opt, 16);
    } else if (send && url_opt == NULL) {
        // purrito by default uses port 42069
        strcpy(port, "42069");
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
            fprintf(stderr, "get_encryption_params(): %s\n", _("error decoding url"));
            rv = EXIT_FAILURE;
            goto early_out;
        }
    }

    // values defined in
    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
    // used for https://tools.ietf.org/html/rfc7301
    const char *alpn_list[2] = { "http/1.1", "http/1.0" };
    const size_t alpn_n = 2;

    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    uint8_t iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;
    struct trust_anchors btas = { 0 };

    bool ssl = (portn == HTTPS_PORT);
    int socket;
    if (ssl) {
        if (debug) {
            fputs(_("reading certs...\n"), stderr);
        }

        if (bearssl_read_certs(&btas, NULL) == 0) {
            fputs(_("couldn't open certs\n"), stderr);
            goto early_out;
        }
        br_ssl_client_init_full(&sc, &xc, btas.ta, btas.n);
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
        br_ssl_engine_set_protocol_names(&sc.eng, alpn_list, alpn_n);
        br_ssl_client_reset(&sc, link, 0);

        // this function only takes the pointer to socket, so it's safe
        // to use unitialized socket
        br_sslio_init(&ioc, &sc.eng, socket_read, &socket, socket_write, &socket);
    }

    socket = host_connect(link, port, debug);
    if (socket < 0) {
        host_connect_error_message();
        goto early_out;
    }

    const char *alpn = NULL;
    if (ssl) {
        // flush the io context in order to force it to perform a handshake.
        // the handshake might include ALPN negotiation.
        br_sslio_flush(&ioc);
        alpn = br_ssl_engine_get_selected_protocol(&sc.eng);
        if (debug) {
            if (alpn) {
                fprintf(stderr, "ALPN: %s\n", alpn);
            } else {
                fputs(_("ALPN mismatch\n"), stderr);
            }
        }
    }

    // https://stackoverflow.com/questions/246859/http-1-0-vs-1-1
    // the important fields in use here are common to both
    // HTTP/1.0: https://tools.ietf.org/html/rfc1945
    // HTTP/1.1: https://tools.ietf.org/html/rfc2616
    const char *http_ver;
    if (alpn == NULL || strcmp(alpn, "http/1.0") == 0) {
        http_ver = "HTTP/1.0";
    } else if (strcmp(alpn, "http/1.1") == 0) {
        http_ver = "HTTP/1.1";
    } else {
        fputs("ERROR: execution shouldn't have gotten here!\n", stderr);
        abort();
    }

    const int going_to_write = HEADER_MAX_LEN;
    char request[HEADER_MAX_LEN];
    char footer[HEADER_MAX_LEN] = "";
    int written = 0;
    if (recv) {
        written = snprintf(
            request, going_to_write,
            "GET %s %s\r\n"
            "Host: %s\r\n" // most 1.0 servers require it
            "Accept: */*\r\n" // some servers can complain if it isn't present
            "Accept-Encoding: identity\r\n" // avoid compressed content
            "\r\n",
            path, http_ver, link);
    } else if (send) {
        char multipart[HEADER_MAX_LEN];
        int multipart_written = 0;
        if (stratum) {
            #define PURR_BOUNDARY_MIN "----purr-boundary"
            #define PURR_BOUNDARY "--" PURR_BOUNDARY_MIN "\r\n"

            multipart_written = snprintf(
                multipart, going_to_write,
                "Content-Type: multipart/form-data; boundary=" PURR_BOUNDARY_MIN "\r\n"
                "\r\n");
            multipart_written = snprintf(
                multipart + multipart_written, going_to_write - multipart_written,
                PURR_BOUNDARY
                "Content-Disposition: form-data; name=\"s\"\r\n"
                "\r\n"
                "1\r\n"
                PURR_BOUNDARY
                "Content-Disposition: form-data; name=\"o\"\r\n"
                "\r\n"
                "0\r\n"
                PURR_BOUNDARY
                "Content-Disposition: form-data; name=\"p\"; filename=\"%s\"\r\n"
                "Content-Type: application/octet-stream\r\n"
                "\r\n",
                using_stdin ? "stream" : basename(argv[1]));

            multipart_written += snprintf(footer, going_to_write, "\r\n--" PURR_BOUNDARY_MIN "\r\n");
        }
        if (multipart_written >= going_to_write) goto truncate_request;

        written = snprintf(
            request, going_to_write,
            "POST %s %s\r\n"
            "Host: %s\r\n"
            "Accept: */*\r\n"
            "Content-Length: %lu\r\n", // required in most cases and good practice
            path, http_ver, link, input.size + multipart_written);

        if (written < going_to_write) {
            if (stratum) {
                written += snprintf(request + written, going_to_write - written, "%s", multipart);
            } else {
                written += snprintf(
                    request + written, going_to_write - written,
                    "Content-Type: application/octet-stream\r\n"
                    "\r\n");
            }
        }
    }

    if (written >= going_to_write) {
truncate_request:
        fputs(_("error: truncated request!\n"), stderr);
        goto out;
    }
    if (debug) {
        fputs("request header: -------------\n", stderr);
        fputs(request, stderr);
        fputs("-----------------------------\n", stderr);

        if (footer[0]) {
            fputs("request footer: -------------\n", stderr);
            fputs(footer, stderr);
            fputs("-----------------------------\n", stderr);
        }
    }

    struct connection_information ci =
        {.ioc = &ioc, .sc = &sc,
         .request = request, .request_size = written,
         .footer = footer, .footer_size = strlen(footer),
         .input = &input, .output = &output,
         .socket = socket,
         .send = send, .ssl = ssl,
         // ALPN verification is performed before send_and_receive()
         .alpn= false,
         .no_strip = no_strip, .debug = debug};

    rv = send_and_receive(&ci);
    // clean-up
    close(socket);
    bearssl_free_certs(btas);

    if (send && encrypt) {
        // backend can't distinguish between a normal and an encrypted paste,
        // but the links for accessing each are different,
        // so we need to fix it locally
        char *scheme_res = NULL, *link_res = NULL, *path_res = NULL, *port_res = NULL;
        int portn_res =
            clean_up_link((char *)output.data, &scheme_res, &link_res, &path_res, &port_res);
        if (portn_res == -1) {
            fprintf(stderr, "%s: %s\n", _("couldn't clean up received link"), (char *)output.data);
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
        fwrite(output.data, 1, output.offset, output_print);
    } else if ((off_t)fwrite(output.data, 1, output.offset, output_print) < output.offset) {
        // offset is 0 when use_stream is true, so no double printing is done
        fputs(_("might not have written all data\n"), stderr);
    }

  out:
    free(scheme);
    free(link);
    free(path);
    free(port);
    free(key);
    free(iv);
  early_out:
	 // will be fclosed in free_mmap sometimes, figure out the leakage
	 // if stdout, we don't want free_mmap to kill it, I think
	 // but if not stdout, we don't want to have to worry about closing it either
    //if (output_print != stdout) fclose(output_print);
    free_mmap(&input);
    free_mmap(&output);

    return rv;
}
