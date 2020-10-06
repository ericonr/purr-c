#define _POSIX_C_SOURCE 200112L /* fdopen */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>

#include "pager.h"

int launch_pager(struct pager_proc *p)
{
    int rv = -1;

    int pipes[2];
    if (pipe(pipes) < 0) {
        perror("pipe()");
        return rv;
    }

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

    p->file = fdopen(pipes[1], "w");
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
        sleep(1);
        kill(p.pid, SIGTERM);
    }

    waitpid(p.pid, &status, 0);

    return status;
}
