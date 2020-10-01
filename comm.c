#define _POSIX_C_SOURCE 200112L /* fdopen */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "purr.h"

int send_and_receive(struct connection_information *ci)
{
    int rv = 0;

    int socket_write = dup(ci->socket);
    if (socket_write < 0) {
        perror("dup()");
        return rv;
    }

    struct transmission_information ti =
        {.ioc = ci->ioc,
         .no_strip = ci->no_strip, .debug = ci->debug,
         .socket = ci->socket,
         .socket_write_stream = fdopen(socket_write, "w"),
         .ssl = ci->ssl,
         .type = ci->type,
         .header_callback = ci->header_callback};

    if (ti.socket_write_stream == NULL) {
        perror("fdopen()");
        return rv;
    }
    // remove buffering from the socket stream
    setbuf(ti.socket_write_stream, NULL);

    ti.file = ci->input;

    if (ti.ssl) {
        if (ci->alpn_list) {
            if (ci->debug) fputs("sending ALPN message\n", stderr);
            br_ssl_engine_set_protocol_names(&ci->sc->eng, ci->alpn_list, ci->alpn_n);
            if (br_ssl_engine_get_selected_protocol(&ci->sc->eng) == NULL) {
                // don't treat as fatal error
                if (ci->debug) fputs("error setting ALPN type\n", stderr);
            }
        }
        br_sslio_write_all(ci->ioc, ci->request, ci->request_size);
    } else {
        fwrite(ci->request, 1, ci->request_size, ti.socket_write_stream);
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

    if (ti.ssl) {
        // situation around close_notify is fuzzy:
        // relevant RFCs say it is required, but lots of server impls
        // don't respond to it, due to HTTP/1.0 onward requiring self-termination
        // (in the form of Content-Length, for our case).
        // therefore, only complain about it in debug mode.
        // source: https://security.stackexchange.com/questions/82028/ssl-tls-is-a-server-always-required-to-respond-to-a-close-notify
        if (br_sslio_close(ci->ioc) != 0) {
            if (ci->debug) {
                fputs("couldn't close SSL connection!\n", stderr);
            }
        }

        // check whether everything was closed properly:
        // leaving the connection hanging is ok, per the above comment.
        // errors checked relate to certificate errors and the kind.
        // the caller shouldn't use the buffers passed to this function if it
        // returns an error.
        if (br_ssl_engine_current_state(&ci->sc->eng) == BR_SSL_CLOSED) {
            const int err = br_ssl_engine_last_error(&ci->sc->eng);
            if (err == BR_ERR_OK) {
                if (ci->debug) fputs("all good!\n", stderr);
                rv = EXIT_SUCCESS;
            } else if (err == BR_ERR_IO) {
                if (ci->debug) fputs("I/O error, not critical\n", stderr);
                rv = EXIT_SUCCESS;
            } else {
                fprintf(stderr, "SSL error: %d\n", err);
                rv = EXIT_FAILURE;
            }
        } else {
            // this case shouldn't happen, since br_sslio_close is called above.
            if (ci->debug) fputs("socket closed without terminating ssl!\n", stderr);
            rv = EXIT_SUCCESS;
        }
    }

    fclose(ti.socket_write_stream);

    return rv;
}
