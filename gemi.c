#define _POSIX_C_SOURCE 200809L /* getopt, openat, fdopendir */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "purr.h"
#include "mmap_file.h"
#include "read_certs.h"
#include "gemini.h"
#include "pager.h"

#define GEMINI_REQUEST 1024

__attribute__ ((noreturn))
static void usage(bool fail)
{
    FILE *stream = fail ? stderr : stdout;
    fprintf(stream,
        "Usage: gemi [options] <url>\n"
        "Options:\n"
        "    -b: browse mode (experimental)\n"
        "    -p: use pager: value of PAGER (default is less)\n"
        "    -s: don't check server name\n"
        "    -a: accept server's public key\n"
        "    -n: don't strip header\n"
        "    -d: debug\n"
        "    -h: show this dialog\n"
        "    -r: number of redirections (internal use)\n"
        "Environment:\n"
    );
    bearssl_read_certs_help(stream);

    exit(fail? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int rv = EXIT_FAILURE;
    bool browse = false, pager = false, check_name = true, accept_pkey = false;
    bool debug = false, no_strip = false;
    int redirections = 0, redirections_pos = 0;

    int c;
    while ((c = getopt(argc, argv, "+bpsandhr:")) != -1) {
        switch (c) {
            case 'b':
                browse = true;
                break;
            case 'p':
                pager = true;
                break;
            case 's':
                check_name = false;
                break;
            case 'a':
                accept_pkey = true;
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

    const int going_to_write = GEMINI_REQUEST;
    char request[GEMINI_REQUEST];
    int written = snprintf(request, going_to_write, "%s%s%s\r\n", scheme, domain, path);
    if (written >= going_to_write) {
        fputs("truncated request!\n", stderr);
        goto early_out;
    }
    if (debug) fprintf(stderr, "request: %s", request);

    struct trust_anchors btas = { 0 };
    if (bearssl_read_certs(&btas, NULL) == 0) {
        fputs("bearssl_read_certs(): couldn't read certs!\n", stderr);
        goto early_out;
    }

    // read certificates in config directory
    // errors here aren't critical
    const char *home = getenv("HOME");
    if (home) {
        char config[PATH_MAX];
        if (snprintf(config, PATH_MAX, "%s/%s", home, ".config/gemi") >= PATH_MAX) {
            if (debug) fputs("HOME is too long!\n", stderr);
            goto stop_config;
        }
        // can't use O_PATH here, since it's an invalid fd for fdopendir, even duplicated.
        // XXX: find optimal order of open() and opendir() calls
        int config_fd = open(config, O_DIRECTORY | O_CLOEXEC);
        if (config_fd < 0) {
            if (debug) perror("open()");
            goto stop_config;
        }

        int config_fd_tmp = dup(config_fd);
        if (config_fd_tmp < 0) {
            perror("dup()");
            goto stop_search;
        }
        // POSIX doesn't specify whether fdopendir sets close-on-exec
        fcntl(config_fd_tmp, F_SETFD, FD_CLOEXEC);
        DIR *config_dir = fdopendir(config_fd_tmp);
        if (config_dir == NULL) {
            perror("fdopendir()");
            close(config_fd_tmp);
            goto stop_search;
        }

        struct dirent *config_file;
        while ((config_file = readdir(config_dir))) {
            const char *name = config_file->d_name;
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            int new_file = openat(config_fd, name, O_RDONLY | O_CLOEXEC);
            if (new_file < 0) {
                perror("openat()");
                continue;
            }

            struct stat st;
            fstat(new_file, &st);
            if ((st.st_mode & S_IFMT) == S_IFREG) {
                FILE *file_stream = fdopen(new_file, "re");
                if (file_stream == NULL) {
                    close(new_file);
                    continue;
                }

                if (bearssl_read_certs(&btas, file_stream) == 0) {
                    if (debug) fprintf(stderr, "error reading cert file: '%s'\n", name);
                }
            } else {
                close(new_file);
            }

        }

        closedir(config_dir);
      stop_search:
        close(config_fd);
    }

    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    uint8_t iobuf[BR_SSL_BUFSIZE_BIDI];
    br_sslio_context ioc;
    int socket;

  // label belongs to block above
  stop_config:

    br_ssl_client_init_full(&sc, &xc, btas.ta, btas.n);
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
    br_ssl_client_reset(&sc, check_name ? domain : NULL, 0);
    br_sslio_init(&ioc, &sc.eng, socket_read, &socket, socket_write, &socket);


    if ((socket = host_connect(domain, port, debug)) < 0) {
        fputs("host_connect(): couldn't open socket or find domain\n", stderr);
    }

    signal(SIGPIPE, SIG_IGN);

    FILE *output_stream = stdout;
    struct pager_proc pager_info;
    if (pager) {
        if (launch_pager(&pager_info) < 0) {
            return rv;
        }
        output_stream = pager_info.file;
    }

    struct mmap_file output;
    if (browse) {
        output = create_mmap_from_file(NULL, PROT_MEM);
    } else {
        output = create_mmap_from_FILE(output_stream, "w");
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

    // socket can always be closed after connection
    close(socket);

    if (rv == EXIT_FAILURE) {
        // try to get server's public key from x509 context
        unsigned int usages;
        const br_x509_pkey *pkey = xc.vtable->get_pkey(&xc.vtable, &usages);
        if (pkey == NULL) {
            if (debug) fputs("null public key\n", stderr);
            goto early_out;
        } else {
            if (debug) fprintf(stderr, "keytype: %d\n", pkey->key_type);

            if (!accept_pkey) {
                fputs("run with -a to use the obtained public key!\n", stderr);
                goto early_out;
            }
            fputs("trying to connect with obtained public key!\n", stderr);

            br_x509_knownkey_context kkc;
            if (pkey->key_type == BR_KEYTYPE_RSA) {
                br_x509_knownkey_init_rsa(&kkc, &pkey->key.rsa, usages);
            } else if (pkey->key_type == BR_KEYTYPE_EC) {
                br_x509_knownkey_init_ec(&kkc, &pkey->key.ec, usages);
            } else {
                fprintf(stderr, "unknown key type: %d\n", pkey->key_type);
                goto early_out;
            }

            // create new minimal_context to preserve the pkey from above
            br_x509_minimal_context nxc;

            // XXX: this could instead be done with the exec-self mechanism and
            // shared memory shenanigans, but this solution is much simpler

            // fully reset SSL-related structs; use client_init_full for simplicity
            br_ssl_client_init_full(&sc, &nxc, btas.ta, btas.n);
            br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
            br_ssl_client_reset(&sc, NULL, 0);
            br_sslio_init(&ioc, &sc.eng, socket_read, &socket, socket_write, &socket);

            // use the knownkey x509 context
            br_ssl_engine_set_x509(&sc.eng, &kkc.vtable);

            if ((socket = host_connect(domain, port, debug)) < 0) {
                perror("host_connect()");
                goto early_out;
            }
            if ((rv = send_and_receive(&ci)) == EXIT_FAILURE) {
                goto early_out;
            }
        }
    }

    // free certs now that they won't be used anymore
    bearssl_free_certs(btas);

    // generic way of outputting data:
    // - if using FILE backend, offset is 0 and nothing happens
    // - if using memory backend, offset is used
    // data output should happen _before_ dealing with links
    fwrite(output.data, 1, output.offset, output_stream);
    // pager must always be closed before exec'ing into self
    // if redirect_link exists, should also kill pager
    // XXX: add some flag to not kill pager when performing redirection?
    char *redirect_link = get_gemini_redirect_link();
    if (pager) wait_for_pager(pager_info, (bool)redirect_link);

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
                bool new_arg_alloc = false;
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
                        new_arg = calloc(1, 1024);
                        new_arg_alloc = true;
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
                    char *clean_path = walk_gemini_path(path, new_arg);
                    if (clean_path == NULL) {
                        perror("walk_gemini_path()");
                        goto early_out;
                    }

                    char *new_url =
                        calloc(1, strlen(scheme) + strlen(domain) + strlen(clean_path) + 1);
                    if (new_url == NULL) {
                        perror("calloc()");
                        goto early_out;
                    }
                    sprintf(new_url, "%s%s%s", scheme, domain, clean_path);
                    new_argv[new_arg_pos] = new_url;
                } else if (new_portn != GEMINI_PORT) {
                    fputs("Unsupported protocol!\n", stderr);
                    goto link_error;
                }

                execvp(progpath, new_argv);
              link_error:
                if (new_arg_alloc) free(new_arg);
                continue;
            }
        }
    }

  early_out:
    free(scheme);
    free(domain);
    free(path);
    free(port);
    free_gemini_redirect_link();
    return rv;
}
