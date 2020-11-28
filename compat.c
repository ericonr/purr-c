#if defined(HAVE_PIPE2) || defined (HAVE_PROG_INVOCATION)
#define _GNU_SOURCE /* pipe2 or program_invocation_short_name */
#endif /* HAVE_PIPE2 */

/* pipe_cloexec */
#include <unistd.h>
#include <fcntl.h>

/* socket_cloexec */
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>

/* program_name */
#include <errno.h>
#include <stdlib.h>

#include "compat.h"

int pipe_cloexec(int fds[2])
{
    #ifdef HAVE_PIPE2
    // atomic (on newer kernels) application of close-on-exec
    if (pipe2(fds, O_CLOEXEC) < 0) {
        return 1;
    }
    #else
    // delayed application of close-on-exec
    if (pipe(fds) < 0) {
        return 1;
    }
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    #endif /* HAVE_PIPE2 */

    return 0;
}

int socket_cloexec(int domain, int type, int protocol)
{
    #ifdef HAVE_SOCK_CLOEXEC_H
    return socket(domain, (type | SOCK_CLOEXEC), protocol);
    #else
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        return fd;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
    #endif /* HAVE_SOCK_CLOEXEC_H */
}

const char *program_name(void)
{
    #ifdef HAVE_PROG_INVOCATION
    return program_invocation_short_name;
    #elif HAVE_GETPROGNAME
    return getprogname();
    #else
    #error "no progname impl"
    #endif /* PROG_INVOCATION & GETPROGNAME */
}
