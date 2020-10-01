#ifndef __PAGER_H_
#define __PAGER_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct pager_proc {
    FILE *file;
    pid_t pid;
};

int launch_pager(struct pager_proc *);
int wait_for_pager(struct pager_proc, bool);

#endif // __PAGER_H_
