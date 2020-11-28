#ifndef __COMPAT_H_
#define __COMPAT_H_

int pipe_cloexec(int [2]);
int socket_cloexec(int, int, int);
const char *program_name(void);

#endif // __COMPAT_H_
