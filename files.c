#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include "purr.h"
#include "mmap_file.h"

struct strip_header_info {
    struct mmap_file *output;
    char *header;
    int counter, header_counter;
    int content_size;
    bool no_strip, debug;
    enum connection_type type;
};

const int header_separator_len[] = { [HTTP_CONN] = 4, [GEMINI_CONN] = 2 };
const char *header_separator[] = { [HTTP_CONN] = "\r\n\r\n", [GEMINI_CONN] = "\r\n" };

static size_t fwrite_strip(const uint8_t *buf, int rlen, struct strip_header_info *st)
{
    const char *separator = header_separator[st->type];
    const int len = header_separator_len[st->type];
    int i = 0;
    if (st->counter != len) {
        for (; i < rlen; i++) {
            // state machine to detect the HTTP or Gemini header separator
            if (buf[i] == separator[st->counter]) {
                st->counter++;
            } else {
                st->counter = 0;
                if (buf[i] == separator[st->counter]) {
                    st->counter++;
                }
            }

            if (st->header_counter < HEADER_MAX_LEN - 1) {
                // protect from buffer overflow
                // the header buffer is calloc'd, so no need to null-terminate it manually
                st->header[st->header_counter++] = buf[i];
            }

            if (st->counter == len) {
                // eat last matching char
                i++;
                break;
            }
        }
    }

    // no_strip mode -> show header in stdout
    // debug mode -> show header in stderr
    // otherwise -> hide header
    if (st->no_strip) {
        write_into_mmap(st->output, buf, i);
    } else if (st->debug) {
        fwrite(buf, 1, i, stderr);
    }

    return write_into_mmap(st->output, buf + i, rlen - i);
}

size_t ssl_to_mmap(struct transmission_information ti)
{
    size_t rv = 0;
    struct strip_header_info st =
        {.output = ti.file,
         .header = calloc(HEADER_MAX_LEN, 1),
         .debug = ti.debug, .no_strip = ti.no_strip,
         .type = ti.type};
    if (st.header == NULL) {
        perror("allocation failure");
        goto early_out;
    }

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
        if (st.counter == header_separator_len[ti.type] && !tried_content_length) {
            if (ti.type == HTTP_CONN) {
                // http headers need to be parsed for content length
                const char *needle = "Content-Length: ";
                char *length = strstr(st.header, needle);
                if (length == NULL) {
                    fputs("header didn't contain content-length field\n", stderr);
                    rv = 0;
                    goto early_out;
                }

                transmission_size = atoll(length + strlen(needle));
                if (transmission_size == 0) {
                    fputs("couldn't parse content-length\n", stderr);
                    rv = 0;
                    goto early_out;
                }

            }
            tried_content_length = true;
        }

        if (transmission_size) {
            // limit transmission size
            if (rv >= transmission_size) {
                rv = transmission_size;
                break;
            }
        }
    }

  early_out:
    free(st.header);
    return rv;
}

size_t mmap_to_ssl(struct transmission_information ti)
{
    size_t rv = 0;
    while (1) {
        int wlen = read_from_mmap(ti.file, NET_BLOCK_SIZE);
        int err = 0;
        if (ti.ssl) {
            err = br_sslio_write_all(ti.ioc, ti.file->cursor, wlen);
        } else {
            ssize_t wlen_local = wlen;
            while (wlen_local) {
                ssize_t written =
                    socket_write(&ti.socket, ti.file->cursor + (wlen - wlen_local), wlen_local);
                if (written > 0) wlen_local -= written;
                // TODO: add error checking
                err = 0;
            }
        }
        if (err == 0) {
            rv += wlen;
        }
        if (wlen < NET_BLOCK_SIZE) {
            break;
        }
    }

    return rv;
}
