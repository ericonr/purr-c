#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

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
    bool parsed_header = false;
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
        if (st.counter == header_separator_len[ti.type] && !parsed_header) {
            parsed_header = true;

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
            } else if (ti.type == GEMINI_CONN) {
                // gemini headers can be checked for information
                // <STATUS: 2 chars><SPACE><META>
                char first = st.header[0], second = st.header[1], *meta = st.header + 2;
                if (first < '1' || first > '6' || second < '0' || second > '9' || *meta != ' ') {
                    fputs("out-of-spec header!\n", stderr);
                    goto early_out;
                }
                // eat the space
                meta++;

                if (ti.header_callback) {
                    ti.header_callback(first, strdup(meta));
                }

                switch (first) {
                    case '1':
                        fputs("INPUT not supported\n", stderr);
                        rv = 0;
                        goto early_out;
                        break;
                    case '2':
                        if (ti.debug) fprintf(stderr, "success code: %c mime: %s\n", second, meta);
                        break;
                    case '3':
                        fprintf(stderr, "redirect code: %c url: %s\n", second, meta);
                        rv = 0;
                        goto early_out;
                        break;
                    case '4':
                        fprintf(stderr, "temp failure code: %c msg: %s\n", second, meta);
                        rv = 0;
                        goto early_out;
                        break;
                    case '5':
                        fprintf(stderr, "perm failure code: %c msg: %s\n", second, meta);
                        rv = 0;
                        goto early_out;
                        break;
                    case '6':
                        fprintf(stderr, "client cert code: %c msg: %s\n", second, meta);
                        rv = 0;
                        goto early_out;
                        break;
                }
            }
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
        uint8_t tmp[NET_BLOCK_SIZE];
        int wlen = read_from_mmap(ti.file, tmp, NET_BLOCK_SIZE);
        int err = 0;
        if (ti.ssl) {
            err = br_sslio_write_all(ti.ioc, tmp, wlen);
        } else {
            fwrite(tmp, 1, wlen, ti.socket_write_stream);
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
