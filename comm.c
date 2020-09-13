#include <stdlib.h>

#include "purr.h"

int send_and_receive(struct connection_information *ci)
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
        size_t sent = mmap_to_ssl(ti);
        if (sent == 0) {
            fputs("warning: empty input file...\n", stderr);
        }
        if (ci->debug) {
            fprintf(stderr, "wrote %lu bytes!\n", sent);
        }
    }
    if (ti.ssl) br_sslio_flush(ci->ioc);

    ti.file = ci->output;

    if (ssl_to_mmap(ti) == 0) {
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
