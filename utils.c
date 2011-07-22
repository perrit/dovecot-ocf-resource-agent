/* system includes */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* includes */
#include "utils.h"

#define PROCFS "/proc"

void *
malloc0 (size_t bytes)
{
  void *mem;

  if ((mem = malloc (bytes)))
    memset (mem, 0, bytes);

  return mem;
}

char *
ltrim (const char *str, const char *chars)
{
  char *p1, *p2;

  for (p1=(char*)str; *p1; p1++) {
    for (p2=(char*)chars; *p2 && *p2 != *p1; p2++)
      ;

    if (*p2 != *p1)
      break;
  }

  return p1;
}

char *
rtrim (char *str, const char *chars)
{
  char *p1, *p2;

  for (p1=(char*)str; *p1; p1++)
    ;

  for (--p1; *p1 && p1 > str; p1--) {
    for (p2=(char*)chars; *p2 && *p2 != *p1; p2++)
      ;

    if (*p2 != *p1)
      break;
  }

  *(++p1) = '\0';

  return (char*)str;
}

char *
trim (char *str, const char *chars)
{
  return rtrim (ltrim (str, chars), chars);
}

ssize_t
readline (int fd, char *buf, size_t len)
{
  char *p;
  size_t n;
  ssize_t i;

  for (p=buf, n=0; n < len; ) {
    i = read (fd, p, 1);

    if (i < 0) {
      if (errno != EINTR)
        return i;
    } else if (i > 0) {
      n++;
      if (*p++ == '\n')
        break;
    } else {
      break;
    }
  }

 *p = '\0';

  return n;
}

pid_t
run (const char *path, char *const argv[], int *fdin, int *fdout, int *fderr)
{
  int errnum = -1;
  int pipein[] = {-1,-1};
  int pipeout[] = {-1,-1};
  int pipeerr[] = {-1,-1};
  int status;
  pid_t pid;

  if (pipe (pipein) < 0)
    goto failure_pipe;
  if (pipe (pipeout) < 0)
    goto failure_pipe;
  if (pipe (pipeerr) < 0)
    goto failure_pipe;

  switch ((pid = fork ())) {
    case -1: /* error */
      goto failure_pipe;
      break;
    case 0: /* child */
      if (close (pipein[1])
       || close (pipeout[0])
       || close (pipeerr[0]))
        exit (EXIT_FAILURE);
      if (dup2 (pipein[0], STDIN_FILENO) < 0
       || dup2 (pipeout[1], STDOUT_FILENO) < 0
       || dup2 (pipeerr[1], STDERR_FILENO) < 0)
        exit (EXIT_FAILURE);

      execv (path, argv);

      exit (EXIT_FAILURE); /* never reached */
    default: /* parent */
      if ((close (pipein[0]) && (pipein[0] = -1))
       || (close (pipeout[1]) && (pipeout[1] = -1))
       || (close (pipeerr[1]) && (pipeerr[1] = -1)))
        goto failure_fork;
      break;
  }

 *fdin = pipein[1];
 *fdout = pipeout[0];
 *fderr = pipeerr[0];

  return pid;

failure_fork:
  errnum = errno;

  if (pid > 0 && kill (pid, SIGTERM) == 0)
    waitpid (pid, &status, WNOHANG);

failure_pipe:
  if (errnum < 0)
    errnum = errno;

  if (pipein[0] != -1)
    close (pipein[0]);
  if (pipein[1] != -1)
    close (pipein[1]);
  if (pipeout[0] != -1)
    close (pipeout[0]);
  if (pipeout[1] != -1)
    close (pipeout[1]);
  if (pipeerr[0] != -1)
    close (pipeerr[0]);
  if (pipeerr[1] != -1)
    close (pipeerr[1]);

  errno = errnum;

  return -1;
}

pid_t *
getproccpids (pid_t ppid)
{
#define BUFSIZE (128)

  char *ptr;
  DIR *dir;
  int ret;
  pid_t *newpids, *pids, pid, someppid;
  size_t cnt, len;
  struct dirent *entry;

  /* start with an initial value of four, if more memory is required later,
     we'll use realloc to do so. */
  len = 5;
  cnt = 0;
  if ((pids = malloc ((sizeof (pid_t) * len))) == NULL)
    return NULL;
  if ((dir = opendir (PROCFS)) == NULL)
    return NULL;

  while ((entry = readdir (dir))) {
    /* read the process identifier */
    for (pid=0,ptr=entry->d_name; isdigit (*ptr); pid=((pid*10)+(*ptr-'0')),ptr++)
      ;

    /* the name consisted of all digits */
    if (*ptr == '\0') {
      if ((someppid = getprocppid (pid)) == (pid_t)-1) {
        goto failure;
      } else if (someppid == ppid) {
        /* the array is full, reallocate memory */
        if (cnt >= len) {
          len *= 2;
          newpids = realloc (pids, (sizeof (pid_t)*len));
          if (newpids == NULL)
            goto failure;
          pids = newpids;
        }

       *(pids+cnt++) = pid;
      }
    }
  }

 *(pids+cnt) = (pid_t)0;

  for (; (ret = closedir (dir)) && errno == EINTR; )
    ;
  if (ret)
    goto failure;

  return pids;

failure:
  if (pids)
    free (pids);
  return NULL;
#undef BUFSIZE
}

char *
getprocinfo (pid_t pid, const char *name)
{
#define BUFSIZE (128)
#define LINESIZE (128)
#define PATHSIZE (32)
#define PRENAME (0)
#define NAME (1)
#define PREVALUE (2)
#define VALUE (3)
#define IGNORE (4)

  int fd;
  /* vars used for line buffer */
  char line[LINESIZE+1], *lend, *lptr;
  size_t llen;
  ssize_t lcnt;
  /* vars used for path buffer */
  char path[PATHSIZE+1];
  int pcnt;
  /* vars used to keep state */
  char *nptr;
  int state;
  /* vars used for info buffer */
  char *buf, *bnew, *bptr;
  size_t bcnt, blen;

  errno = 0;
  pcnt = snprintf (path, PATHSIZE, PROCFS"/%d/status", pid);
  if (pcnt < 0)
    return NULL;
  if (pcnt > PATHSIZE) {
    if (errno == 0)
      errno = ENOMEM;
    return NULL;
  }

  bcnt = 0;
  blen = sizeof (char) * BUFSIZE;
  buf = malloc (blen);
  if (buf == NULL)
    return NULL;
  if ((fd = open (path, O_RDONLY)) < 0)
    goto failure;

  for (llen=LINESIZE, lend=line, state=PRENAME,nptr=(char*)name;;) {
    errno = 0;
    lcnt = read (fd, lend, llen);

    if (lcnt > 0) {
      if (lcnt > 0) {
        llen -= lcnt;
        lend += lcnt;
      }

      if (errno) {
        if (errno == EINTR)
          continue;
        goto failure;
      }

      for (lptr=line; lptr < lend; lptr++) {
        if (state == PRENAME) {
          if (*lptr == *nptr || tolower (*lptr) == tolower (*nptr)) {
            nptr++;
            state = NAME;
          } else if (! isspace (*lptr)) {
            nptr = (char*)name;
            state = IGNORE;
          }
        } else if (state == NAME) {
          if (*lptr == ':') {
            state = PREVALUE;
          } else if (*lptr == *nptr || tolower (*lptr) == tolower (*nptr)) {
            nptr++;
          } else if (isalnum (*lptr)) {
            nptr = (char*)name;
            state = IGNORE;
          } else {
            errno = EILSEQ;
            goto failure;
          }
        } else if (state == PREVALUE) {
          if (*lptr == '\n') {
            goto success;
          } else if (! isspace (*lptr)) {
           *(buf+bcnt++) = *lptr;
          }
        } else if (state == VALUE) {
          if (*lptr == '\n') {
            goto success;
          } else {
            if (bcnt >= blen) {
              blen *= 2;
              bnew = realloc (buf, blen);
              if (bnew == NULL)
                goto failure;
              buf = bnew;
            }
           *(buf+bcnt++) = *lptr;
          }
        } else if (state == IGNORE) {
          if (*lptr == '\n')
            state = PRENAME;
        } else {
          errno = EILSEQ;
          goto failure;
        }
      }

      /* reached end of file if number of bytes read is less than number of
         bytes available in buffer */
      if (llen)
        break;
    } else {
      /* reached end of file */
      break;
    }

    lend = lptr = line;
    llen = LINESIZE;
  }

success:
  if (fd >= 0 && close (fd))
    goto failure;

  bptr = bcnt ? (char*)((buf+bcnt)-1) : buf;
  for (; bptr > buf && isspace (*bptr); bptr--)
    ;
 *(++bptr) = '\0';

  return buf;

failure:
  if (buf)
    free (buf);
  if (fd)
    close (fd);
  return NULL;
#undef BUFSIZE
#undef LINESIZE
#undef PATHSIZE
#undef PRENAME
#undef NAME
#undef PREVALUE
#undef VALUE
#undef IGNORE
}

pid_t
getprocppid (pid_t pid)
{
  char *info;
  pid_t ppid;

  if ((info = getprocinfo (pid, "ppid")))
    ppid = strtol (info, NULL, 10);
  else
    ppid = (pid_t)-1;

  free (info);

  return ppid;
}

char *
getprocname (pid_t pid)
{
  return getprocinfo (pid, "name");
}
