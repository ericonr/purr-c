#define _XOPEN_SOURCE /* getopt */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "purr.h"
#include "mmap_file.h"
#include "read_certs.h"
#include "gemini.h"

#define GEMINI_REQUEST 1024

__attribute__ ((noreturn))
static void usage(bool fail)
{
    printf(
        "Usage: gemi [options] <url>\n"
        "Options:\n"
        "    -b: browse mode (experimental)\n"
        "    -n: don't strip header\n"
        "    -d: debug\n"
        "    -h: show this dialog\n"
        "    -r: number of redirections (internal use)\n"
    );

    exit(fail? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int rv = EXIT_FAILURE;
    bool debug = false, no_strip = false, browse = false;
    int redirections = 0, redirections_pos = 0;

    int c;
    while ((c = getopt(argc, argv, "+bndhr:")) != -1) {
        switch (c) {
            case 'b':
                browse = true;
                break;
            case 'n':
                no_strip = true;
                break;
            case 'd':
                debug = true;
                break;
            case 'h':
                usage(false);
            case 'r':
                redirections = atoi(optarg);
                redirections_pos = optind - 1;
                break;
            default:
                usage(true);
        }
    }

    // store how to call myself
    char *progpath = argv[0];
    // 32 is an arbitrary number assumed to be big enough for arguments
    char *new_argv[32] = {progpath, NULL};
    // needs to leave the last 4 positions for:
    // - "-r" flag
    // - # of redirects
    // - new argument
    // - NULL pointer
    for (int i = 1; i < 32 - 4 && i < optind; i++) {
        new_argv[i] = argv[i];
    }
    // zero out the redirection counter
    if (redirections_pos) {
        new_argv[redirections_pos] = "0";
    }
    // index for where to store the new arg
    const int new_arg_pos = optind;

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        usage(true);
    }

    const char *url = argv[0];
    char *scheme = NULL, *domain = NULL, *path = NULL, *port = NULL;
    int portn = clean_up_link(url, &scheme, &domain, &path, &port);
    if (portn != GEMINI_PORT) {
        fputs("this isn't a gemini url!\n", stderr);
        goto early_out;
    }
    // shouldn't need to normalize path output for things such as trailing slash,
    // since redirects should take care of most cases

    int socket = host_connect(domain, port, debug);
    if (socket < 0) {
        fputs("host_connect(): couldn't open socket or find domain\n", stderr);
    }

    const int going_to_write = GEMINI_REQUEST;
    char *request = calloc(going_to_write, 1);
    int written = snprintf(request, going_to_write, "%s%s%s\r\n", scheme, domain, path);
    if (written >= going_to_write) {
        fputs("truncated request!\n", stderr);
        goto early_out;
    }
    if (debug) fprintf(stderr, "request: %s", request);

    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    uint8_t iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;
    br_x509_trust_anchor *btas;
    size_t num_ta = bearssl_read_certs(&btas);
    if (num_ta == 0) {
        fputs("bearssl_read_certs(): couldn't read certs!\n", stderr);
        goto early_out;
    }
    br_ssl_client_init_full(&sc, &xc, btas, num_ta);
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
    br_ssl_client_reset(&sc, domain, 0);
    br_sslio_init(&ioc, &sc.eng, socket_read, &socket, socket_write, &socket);

    signal(SIGPIPE, SIG_IGN);

    // writes directly into stdout
    struct mmap_file output;
    if (browse) {
        output = create_mmap_from_file(NULL, PROT_MEM);
    } else {
        output = create_mmap_from_FILE(stdout, "w");
    }
    if (ERROR_MMAP(output)) {
        return rv;
    }

    struct connection_information ci =
        {.ioc = &ioc, .sc =&sc,
         .request = request, .request_size = written,
         .output = &output,
         .ssl = true, .send = false,
         .debug = debug, .no_strip = no_strip,
         .type = GEMINI_CONN, .header_callback = store_gemini_redirect_link};
    rv = send_and_receive(&ci);

    // free resources
    bearssl_free_certs(&btas, num_ta);
    close(socket);

    if (rv == EXIT_FAILURE) {
        goto early_out;
    }

    if (redirect_link) {
        redirections += 1;
        // redirect link was stored in callback
        fprintf(stderr, "redirecting to %s...\n", redirect_link);
        if (strcmp(redirect_link, url) == 0) {
            rv = EXIT_FAILURE;
            fputs("error: redirect loop detected!\n", stderr);
            goto early_out;
        }

        if (redirections > 4) {
            rv = EXIT_FAILURE;
            fputs("error: too many redirections!\n", stderr);
            goto early_out;
        }
        char redirections_s[24] = { 0 };
        sprintf(redirections_s, "%02d", redirections);

        if (redirections_pos) {
            // replace current -r arg
            new_argv[redirections_pos] = redirections_s;
            new_argv[new_arg_pos] = redirect_link;
        } else {
            // add -r arg
            new_argv[new_arg_pos] = "-r";
            new_argv[new_arg_pos + 1] = redirections_s;
            new_argv[new_arg_pos + 2] = redirect_link;
        }
        execvp(progpath, new_argv);
    }

    // generic way of outputting data:
    // - if using FILE backend, offset is 0 and nothing happens
    // - if using memory backend, offset is used
    fwrite(output.data, 1, output.offset, stdout);
    if (browse) {
        struct gemini_link_node *head = NULL;
        int n = get_links_from_gmi((char *)output.data, &head);
        fprintf(stderr, "Links found: %d\n", n);
        if (n > 0) {
            while (1) {
                fputs("Input link number (starts at 0) or control char ('?' or 'i'): ", stderr);
                int in;
                int err = scanf("%d", &in);
                char *new_arg;
                if (err == EOF) {
                    // exit cleanly on EOF
                    rv = EXIT_SUCCESS;
                    goto early_out;
                } else if (err == 1) {
                    // if it leaves this part, it's a bad exit
                    rv = EXIT_FAILURE;

                    if (in >= 0 && in < n) {
                        // in is a valid link number
                        new_arg = get_gemini_node_by_n(head, in)->path;
                        fprintf(stderr, "Selected link: #%02d: %s\n", in, new_arg);
                    } else {
                        fprintf(stderr, "Bad number: %d\n", in);
                        continue;
                    }
                } else {
                    // if it leaves this part, it's a bad exit
                    rv = EXIT_FAILURE;

                    // use character controls
                    char pick = fgetc(stdin);
                    if (pick == '?') {
                        print_gemini_nodes(head, stderr);
                        continue;
                    } else if (pick == 'i') {
                        // XXX: doesn't leak, because the application will necessarily exit
                        new_arg = calloc(1, 1024);
                        if (new_arg == NULL) {
                            perror("calloc()");
                            goto early_out;
                        }
                        fputs("Input new link or path: ", stderr);
                        err = scanf("%1023s", new_arg);
                        if (err == EOF) {
                            // clean exit on EOF
                            rv = EXIT_SUCCESS;
                            goto early_out;
                        }
                    } else {
                        fputs("Bad input!\n", stderr);
                        continue;
                    }
                }

                new_argv[new_arg_pos] = new_arg;
                int new_portn = get_port_from_link(new_arg);
                if (new_portn == NO_INFO_PORT) {
                    // link is not absolute path
                    // TODO: path resolution
                    // TODO: better error msgs
                    // TODO: treat error codes from server -> bad links (lacking trailing /, for example),
                    // can probably be solved locally with a smarter client
                    // Perhaps make header parsing a virtual function kind of thing?
                    char *new_url = calloc(1, strlen(url) + strlen(new_arg) + 1);
                    if (new_url == NULL) {
                        perror("calloc()");
                        goto early_out;
                    }
                    sprintf(new_url, "%s%s%s%s", scheme, domain, path, new_arg);
                    new_argv[new_arg_pos] = new_url;
                } else if (new_portn != GEMINI_PORT) {
                    fputs("Unsupported protocol!\n", stderr);
                    goto early_out;
                }

                execvp(progpath, new_argv);
            }
        }
    }

  early_out:
    free(scheme);
    free(domain);
    free(path);
    free(port);
    return rv;
}
