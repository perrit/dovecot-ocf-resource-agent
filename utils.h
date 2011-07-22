#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED

#include <sys/types.h>

char *ltrim (const char *, const char *);
char *rtrim (char *, const char *);
char *trim (char *, const char *);

ssize_t readline (int, char *, size_t);

pid_t run (const char *, char *const [], int *, int *, int *);

pid_t *getproccpids (pid_t);
pid_t getprocppid (pid_t);
char *getprocname (pid_t);
void *malloc0 (size_t bytes);

#endif
