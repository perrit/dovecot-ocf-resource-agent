/*
IMPORTANT:
This file must be linked agains glib and libcluster-glue stuff... I used the
following:
gcc -o ocf-log -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -lplumb ocf.c utils.c ocf-log.c
*/

/* system includes */
//#include <lha_internal.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <clplumbing/loggingdaemon.h>
#include <time.h>

/* includes */
#include "ocf.h"
#include "utils.h"

#define HADATEFMT "%Y/%m/%d_%T"
#define HADATEFMTMAXLEN (32)

/* prototypes for functions only used internally */
ssize_t ocf_logfiledesc (const int, const char *, ...);
ssize_t ocf_logfile (const char *, const char *, ...);
size_t hadate (char *, size_t);
ssize_t ocf_vsnprintf (char **, size_t *, const char *, va_list);
int LogToDaemon (int, const char *, int, gboolean);

char *ha_logfile = NULL;
char *ha_logtag = NULL;
int ha_debug = 0;
char *ha_debuglog = NULL;
int ha_logd = 0;
int ha_logfacility = 0;

int
ocf_log_facility (const char *str)
{
  if (strcasecmp (str, "kern")   == 0)
    return LOG_KERN;
  if (strcasecmp (str, "user")   == 0)
    return LOG_USER;
  if (strcasecmp (str, "mail")   == 0)
    return LOG_MAIL;
  if (strcasecmp (str, "news")   == 0)
    return LOG_NEWS;
  if (strcasecmp (str, "uucp")   == 0)
    return LOG_UUCP;
  if (strcasecmp (str, "daemon") == 0)
    return LOG_DAEMON;
  if (strcasecmp (str, "auth")   == 0)
    return LOG_AUTH;
  if (strcasecmp (str, "cron")   == 0)
    return LOG_CRON;
  if (strcasecmp (str, "lpr")    == 0)
    return LOG_LPR;
  if (strcasecmp (str, "local0") == 0)
    return LOG_LOCAL0;
  if (strcasecmp (str, "local1") == 0)
    return LOG_LOCAL1;
  if (strcasecmp (str, "local2") == 0)
    return LOG_LOCAL2;
  if (strcasecmp (str, "local3") == 0)
    return LOG_LOCAL3;
  if (strcasecmp (str, "local4") == 0)
    return LOG_LOCAL4;
  if (strcasecmp (str, "local5") == 0)
    return LOG_LOCAL5;
  if (strcasecmp (str, "local6") == 0)
    return LOG_LOCAL6;
  if (strcasecmp (str, "local7") == 0)
    return LOG_LOCAL7;

  errno = EINVAL;
  return -1;
}

int
ocf_log_init (const char *logtag)
{
  char *p1, *p2, *ep;

  if (logtag == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (p1=(char*)logtag, p2=NULL; *p1; p1++) {
    if (*p1 == '/')
      p2 = p1;
  }

  if ((  p2 && (ha_logtag = strdup (++p2)) == NULL) ||
      (! p2 && (ha_logtag = strdup (logtag)) == NULL))
    /* errno set by strdup */
    return -1;

  ha_logfacility = 0;
  ha_logfile = NULL;
  ha_debug = ocf_is_decimal (getenv ("HA_debug"));
  ha_debuglog = NULL;
  //ha_logd = ocf_is_true (getenv ("HA_LOGD"));

  /* test if ha log daemon is available if it is... initialize some more stuff
   *
   */
  if (ocf_is_true (getenv ("HA_LOGD")) && cl_log_test_logd ()) {
    ha_logd = 1;
    cl_log_set_entity (ha_logtag);
  } else {
    ha_logd = 0;
  }

  ep = getenv ("HA_LOGFACILITY");
  if (ep && (ha_logfacility = ocf_log_facility (ep)) < 0)
    return -1;

  if (ha_logfacility) {
    openlog (ha_logtag, LOG_PID | LOG_ODELAY, ha_logfacility);
  }

  ep = getenv ("HA_LOGFILE");
  if ((ep && (ha_logfile = strdup (ep)) == NULL))
    /* errno set by strdup */
    return -1;

  ep = getenv ("HA_DEBUGLOG");
  // FIXME: this is actually pretty dumb... DOH!
  //if ((ep && (ha_debuglog = strdup (ep)) == NULL) ||
  //           (ha_debuglog = strdup (DEFAULT_HA_DEBUGLOG)) == NULL)
  //  /* errno set by strdup */
  //  return -1;
  if (( ep && (ha_debuglog = strdup (ep)) == NULL) ||
      (!ep && (ha_debuglog = strdup (DEFAULT_HA_DEBUGLOG)) == NULL))
    return -1;

  return 0;
}

void
ocf_log_deinit (void)
{
  if (ha_logfile)
    free (ha_logfile);
  if (ha_logtag)
    free (ha_logtag);
  ha_debug = 0;
  if (ha_debuglog)
    free (ha_debuglog);
  ha_logfacility = 0;
  ha_logd = 0;
}


#define BUFSIZE (1024)

ssize_t
ocf_vsnprintf (char **buf, size_t *len, const char *fmt, va_list args)
{
  char *nbuf;
  size_t nlen;
  ssize_t num;

  if (*buf == NULL) {
    if (*len < 1)
      nlen = BUFSIZE;
    if ((nbuf = malloc (nlen)) == NULL)
      return -1; /* errno set by malloc */
   *buf = nbuf;
   *len = nlen;
  }

  for (;;) {
    num = vsnprintf (*buf, *len, fmt, args);

    if (num < 0) {
      return -1;
    } else if (num > *len) {
      nlen = num + 1;
      if ((nbuf = realloc (*buf, nlen)) == NULL)
        return -1;
     *buf = nbuf;
     *len = nlen;
    } else {
      break;
    }
  }

  return num;
}

#undef BUFSIZE

int
ocf_log (int prio, const char *fmt, ...)
{
  char date[HADATEFMTMAXLEN];
  int errnum;
  static char *buf = NULL;
  static size_t len = 0;
  va_list args;
  ssize_t num;

  if (hadate (date, HADATEFMTMAXLEN) == 0)
    return -1;

  va_start (args, fmt);
  num = ocf_vsnprintf (&buf, &len, fmt, args);
  va_end (args);

  if (num < 0)
    return -1; /* errno set by ocf_vsnprintf */

  /* if we're connected to a tty, then output to stderr */
  errnum = errno;
  if (isatty (STDOUT_FILENO)) {
    if (! ha_debuglog && prio == LOG_DEBUG)
      return -1;

    ocf_logfiledesc (STDERR_FILENO, "%s: %s\n", ha_logtag, buf);
    return 0;
  }
  errno = errnum; /* if STDOUT_FILENO wasn't a tty errno has been set */

  if (ha_logd) {
    LogToDaemon (prio, buf, len, FALSE);
    return 0;
  }

  /* original implementation of ocf_log continues if ha_logger fails */
  if (ha_logfacility)
    syslog (prio, buf);
  if (ha_logfile && prio != LOG_DEBUG)
    ocf_logfile (ha_logfile, "%s: %s: %s\n", ha_logtag, date, buf);
  if (ha_debuglog)
    ocf_logfile (ha_debuglog, "%s: %s: %s\n", ha_logtag, date, buf);
  if (! ha_logfacility && ! ha_logfile)
    ocf_logfiledesc (STDERR_FILENO, "%s: %s\n", date, buf);

  return 0;
}

ssize_t
ocf_logfiledesc (const int fd, const char *fmt, ...)
{
  static char *buf = NULL;
  static size_t len = 0;

  int errnum;
  size_t nleft, ntotal;
  ssize_t nwritten;
  va_list args;

  va_start (args, fmt);
  nwritten = ocf_vsnprintf (&buf, &len, fmt, args);
  va_end (args);

  if (nwritten < 0)
    return -1;

  errnum = 0;

  for (nleft=nwritten, ntotal=0; nleft > 0;) {
    nwritten = write (fd, (buf+ntotal), nleft);

    if (nwritten > 0) {
      ntotal += nwritten;
      nleft -= nwritten;
    }

    if (nleft && (errnum = errno) != EINTR)
      break;
  }

  if (nleft && errno != EINTR)
    errnum = errno;
  if (errnum)
    errno = errnum;

  return nleft ? -1 : ntotal;
}

ssize_t
ocf_logfile (const char *path, const char *fmt, ...)
{
  static char *buf = NULL;
  static size_t len = 0;

  int fd, errnum;
  size_t nleft, ntotal;
  ssize_t nwritten;
  va_list args;

  va_start (args, fmt);
  nwritten = ocf_vsnprintf (&buf, &len, fmt, args);
  va_end (args);

  if (nwritten < 0)
    return -1;
  if ((fd = open (path, O_WRONLY | O_APPEND | O_CREAT)) < 0)
    return -1;

  errnum = 0;

  for (nleft=nwritten, ntotal=0; nleft > 0;) {
    nwritten = write (fd, (buf+ntotal), nleft);

    if (nwritten > 0) {
      ntotal += nwritten;
      nleft -= nwritten;
    }

    if (nleft && (errnum = errno) != EINTR)
      break;
  }

  if (nleft && errno != EINTR)
    errnum = errno;
  if (close (fd) < 0 && errnum == 0)
    errnum = errno;
  if (errnum)
    errno = errnum;

  return nleft ? -1 : ntotal;
}

size_t
hadate (char *buf, size_t len)
{
  time_t now;

  if ((now = time(NULL)) == (time_t)-1)
    return (size_t)0;

  return strftime(buf, len, HADATEFMT, localtime (&now));
}

int
ocf_is_decimal (const char *value) {

  if (value)
    return (int) strtol (value, NULL, 10);

  errno = EINVAL;
  return 0;
}

int
ocf_is_true(const char *value) {

  int true = 0;

  if (value) {
    if (strncasecmp (value, "yes",  3) == 0
     || strncasecmp (value, "true", 4) == 0
     || strncasecmp (value, "ja",   2) == 0
     || strncasecmp (value, "on",   2) == 0)
      true = 1;
    if (strtol (value, NULL, 10) != 0)
      true = 1;
  }

  return true;
}

char *
ocf_reskey (char *name, const char *empty)
{
  char *buf, *value;
  size_t cnt, len;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  len = strlen (name) + 13;
  buf = malloc (len);
  if (buf == NULL)
    goto end;

  cnt = snprintf (buf, len, "OCF_RESKEY_%s", name);
  if (cnt < 0 || cnt >= len)
    goto end;
  if ((value = getenv (buf)))
    value = strdup (value);
  else if (empty)
    value = strdup (empty);

end:
  if (buf)
    free (buf);
  return value;
}

#define BUFSIZE (4096)

pid_t
ocf_pidfile_status (const char *pidfile)
{
  char buf[BUFSIZE], *eod, *ptr;
  int error, fd;
  pid_t pid;
  size_t cnt, len;

  pid = (pid_t)-1;

  if ((fd = open (pidfile, O_RDONLY)) != -1) {
    for (eod=buf, len=BUFSIZE;;) {
      errno = 0;
      cnt = read (fd, eod, len);
      if (cnt < len) {
        if (cnt > 0) {
          eod += cnt;
          len -= cnt;
        }
        if (errno) {
          if (errno == EINTR)
            continue;
          pid = (pid_t)-1;
          break;
        }
      } else {
        eod += cnt;
        len -= cnt;
      }

      for (ptr=buf; ptr < eod; ptr++) {
        if (pid != (pid_t)-1) {
          if (isdigit (*ptr))
            pid = (pid*10) + (*ptr - '0');
          else
            goto done;
        } else {
          if (isdigit (*ptr))
            pid = (*ptr - '0');
        }
      }

      if (cnt < len)
        break;

      eod = buf;
      len = BUFSIZE;
    }
done:
    error = errno;
    if (close (fd) < 0 && error)
      errno = error;
    if (errno)
      pid = (pid_t)-1;

    /* check if process is running */
    if (pid > (pid_t)0 && kill (pid, 0)) {
      if (errno == ESRCH)
        pid = (pid_t)0;
      else
        pid = (pid_t)-1;
    }
  }

  return pid;
}

#undef BUFSIZE


/* returns 0 if the process was terminated or didn't exist... returns 1 if the
   process didn't die or an other error (other than the process didn't exist)
   occurred! */

int
ocf_kill (pid_t pid, int sig, unsigned int secs)
{
  unsigned int sec;

  if (secs == 0)
    secs = 1;

  if (kill (pid, sig) == 0) {
    for (sec=0; sec < secs; sec++) {
      if (kill (pid, 0)) {
        if (errno == ESRCH) {
          errno = 0;
          return 0;
        } else {
          return -1;
        }
      }
      sleep (1);
    }
    errno = ETIMEDOUT;
  } else if (errno == ESRCH) {
    errno = 0;
    return 0;
  }

  return -1;
}

int
ocf_kill_tree (pid_t ppid, int sig, unsigned int secs)
{
  pid_t *pid, *pids;

  if ((pids = getproccpids (ppid)) == NULL)
    return -1;
  for (pid=pids; *pid; pid++) {
    if (ocf_kill_tree (*pid, sig, secs) < 0)
      goto failure;
  }

  free (pids);

  return ocf_kill (ppid, sig, secs);

failure:
  if (pids)
    free (pids);
  return -1;
}
