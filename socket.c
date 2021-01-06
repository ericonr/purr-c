#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "purr.h"

int socket_read(void *ctx, uint8_t *buf, size_t len)
{
    int fd = *(int *)ctx;
    while (1) {
        ssize_t rlen = read(fd, buf, len);
        if (rlen <= 0) {
            if (rlen < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        return (int)rlen;
    }
}

int socket_write(void *ctx, const uint8_t *buf, size_t len)
{
    int fd = *(int *)ctx;
    while (1) {
        ssize_t wlen = send(fd, buf, len, MSG_NOSIGNAL);
        if (wlen <= 0) {
            if (wlen < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        return (int)wlen;
    }
}
