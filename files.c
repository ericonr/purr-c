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
};

static size_t fwrite_strip(const uint8_t *buf, int rlen, struct strip_header_info *st)
{
    const char *separator = "\r\n\r\n";
    const int len = 4;
    int i = 0;
    if (st->counter != len) {
        for (; i < rlen; i++) {
            if (buf[i] == separator[st->counter]) {
                st->counter++;
            } else {
                st->counter = 0;
                if (buf[i] == separator[st->counter]) {
                    st->counter++;
                }
            }

            if (st->debug) {
                fputc(buf[i], stderr);
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

    //return fwrite(buf + i, 1, rlen - i, stdout);
    return write_into_mmap(st->output, buf + i, rlen - i);
}

size_t ssl_to_mmap(struct transmission_information ti)
{
    size_t rv = 0;
    struct strip_header_info st =
        {.output = ti.file, .header = calloc(HEADER_MAX_LEN, 1), .debug = ti.debug, .no_strip = ti.no_strip};
    if (st.header == NULL) {
        perror("allocation failure");
        return -1;
    }

    char *length = NULL;
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
        // TODO: currently works only in strip mode
        if (st.counter == 4) {
            if (length == NULL && !tried_content_length) {
                tried_content_length = true;
                const char *needle = "Content-Length: ";
                length = strstr(st.header, needle);
                if (length) {
                    transmission_size = atoll(length + strlen(needle));
                }
            }
            if (transmission_size) {
                if (transmission_size == rv) break;
            }
        }
    }

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
