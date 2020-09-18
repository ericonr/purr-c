#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "purr.h"
#include "mmap_file.h"
#include "read_certs.h"

#define GEMINI_REQUEST 1024

__attribute__ ((noreturn))
static void usage(bool fail)
{
    printf(
        "Usage: gemi <url>\n"
    );

    exit(fail? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int rv = EXIT_SUCCESS;
    bool debug = false, no_strip = false;

    if (argc != 2) {
        usage(true);
    }

    char *scheme = NULL, *domain = NULL, *path = NULL, *port = NULL;
    int portn = clean_up_link(argv[1], &scheme, &domain, &path, &port);
    if (portn != GEMINI_PORT) {
        fputs("this isn't a gemini url!\n", stderr);
        goto early_out;
    }
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

    struct mmap_file output = create_mmap_from_file(NULL, PROT_MEM);
    struct connection_information ci =
        {.ioc = &ioc, .sc =&sc,
         .request = request, .request_size = written,
         .output = &output,
         .ssl = true, .send = false,
         .debug = debug, .no_strip = no_strip,
         .type = GEMINI_CONN};
    rv = send_and_receive(&ci);

    bearssl_free_certs(&btas, num_ta);

    fwrite(output.data, 1, output.size, stdout);

  early_out:
    free(scheme);
    free(domain);
    free(path);
    free(port);
    return rv;
}
