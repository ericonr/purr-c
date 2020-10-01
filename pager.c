#define _POSIX_C_SOURCE 200112L /* fdopen */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
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

    p->pid = fork();
    if (p->pid < 0) {
        perror("fork()");
        return rv;
    }

    if (p->pid == 0) {
        close(pipes[1]);
        dup2(pipes[0], STDIN_FILENO);
        if (execvp(pager, pager_cmd) < 0) {
            perror("execvp()");
            return rv;
        }
    } else {
        close(pipes[0]);
        p->file = fdopen(pipes[1], "w");
        if (p->file == NULL) {
            perror("fdopen()");
            return rv;
        }
        rv = 0;
    }

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
