#define _POSIX_C_SOURCE 200112L /* fdopen, nanosleep */
#ifdef HAVE_PIPE2
#define _GNU_SOURCE /* pipe2 */
#endif /* HAVE_PIPE2 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <spawn.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h> /* O_CLOEXEC or fcntl */

#include "pager.h"

int launch_pager(struct pager_proc *p)
{
    int rv = -1;

    int pipes[2];

    // using close-on-exec here is safe, because fds created by dup don't
    // inherit flags
    #ifdef HAVE_PIPE2
    // atomic application of close-on-exec
    if (pipe2(pipes, O_CLOEXEC) < 0) {
        perror("pipe2()");
    }
    #else
    // delayed application of close-on-exec
    if (pipe(pipes) < 0) {
        perror("pipe()");
        return rv;
    }
    fcntl(pipes[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
    #endif /* HAVE_PIPE2 */

    char *pager = getenv("PAGER");
    if (pager == NULL || *pager == 0) {
        pager = "less";
    }
    char *const pager_cmd[] = {pager, NULL};

    // only overwrite LESS if it doesn't exist.
    // set less to exit if output fits in terminal.
    setenv("LESS", "-F", 0);

    posix_spawnattr_t spawn;
    if (posix_spawnattr_init(&spawn) < 0) {
        perror("posix_spawnattr_init()");
        goto err_out;
    }

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) < 0) {
        perror("posix_spawn_file_actions_init()");
        goto spawn_out;
    }
    if (posix_spawn_file_actions_adddup2(&actions, pipes[0], STDIN_FILENO) < 0
        || posix_spawn_file_actions_addclose(&actions, pipes[1]) < 0) {
        perror("posix_spawn_file_actions_add*()");
        goto actions_out;
    }

    extern char **environ;
    pid_t pid;
    if (posix_spawnp(&pid, pager, &actions, &spawn, pager_cmd, environ) != 0) {
        perror("posix_spawnp()");
        goto actions_out;
    }

    // applying close-on-exec to fd here shouldn't change anything, but it's
    // also cheap, so there's no reason not to do it.
    p->file = fdopen(pipes[1], "we");
    if (p->file == NULL) {
        perror("fdopen()");
        goto actions_out;
    }
    p->pid = pid;
    rv = 0;

  actions_out:
    posix_spawn_file_actions_destroy(&actions);
  spawn_out:
    posix_spawnattr_destroy(&spawn);
  err_out:
    close(pipes[0]);
    if (rv) close(pipes[1]);

    return rv;
}

int wait_for_pager(struct pager_proc p, bool should_kill)
{
    int status = 0;
    fclose(p.file);

    if (should_kill) {
        // quick interval to make redirection noticeable
        struct timespec sleep_time = { .tv_nsec = 200L * 1000L * 1000L };
        nanosleep(&sleep_time, NULL);
        kill(p.pid, SIGTERM);
    }

    waitpid(p.pid, &status, 0);

    return status;
}
