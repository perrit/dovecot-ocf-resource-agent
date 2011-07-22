/* system includes */
#include <ctype.h>
#include <errno.h>
#include <stdio.h> // FIXME: remove, use for testing
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* includes */
#include "dovecot.h"
#include "ocf.h"
#include "utils.h"

#define DOVECOT_STAT_MAIN (0)
#define DOVECOT_STAT_SERVICE (1)
#define DOVECOT_STAT_INET_LISTENER (2)

#define BUFSIZE (1024)

/* prototypes */
int dovecot_config_read_option (char **, const char *);
int dovecot_config_read_line (const char *, int *);

char *base_dir;
char *pid_file;
char *listen;
char *shutdown_clients;
iface_list_t *ifaces;

int
dovecot_config_init (void)
{
  base_dir = NULL;
  pid_file = NULL;
  listen   = NULL;
  shutdown_clients = NULL;
  ifaces   = NULL;

  return DOVECOT_SUCCESS;
}

int
dovecot_config_read_option (char **option, const char *str)
{
  char *p, *value;

  if ((p = strchr (str, '=')) == NULL) {
    ocf_log (LOG_ERR, "%s: missing value '%s'", __func__, str);
    return DOVECOT_ERR_PARSER;
  }

  p = ltrim (p, " =");

  if (*p == '\0') {
    value = NULL;
  } else if ((value = strdup (p)) == NULL) {
    ocf_log (LOG_ERR, "%s: strdup: %s", __func__, strerror (errno));
    return DOVECOT_ERR_SYSTEM;
  }

 *option = value;
  return DOVECOT_SUCCESS;
}

#define CLEAR(var)  \
  if ((var)) {      \
    free ((var));   \
    (var) = NULL;   \
  }

int
dovecot_config_read_line (const char *str, int *state)
{
  iface_t *iface;
  iface_list_t *cur;
  static char *service, *host, *port, *ssl;
  char *p;

  if (*state == DOVECOT_STAT_MAIN) {
    if (strncmp (str, "listen", 6) == 0) {
      return dovecot_config_read_option (&listen, str);

    } else if (strncmp (str, "base_dir", 8) == 0) {
      return dovecot_config_read_option (&base_dir, str);

    } else if (strncmp (str, "shutdown_clients", 16) == 0) {
      return dovecot_config_read_option (&shutdown_clients, str);

    } else if (strncmp (str, "service", 7) == 0) {
      p = ltrim (str+7, " \t");

      if ((p = strndup (p, 4)) == NULL) {
        ocf_log (LOG_ERR, "%s: strdup: %s", __func__, strerror (errno));
        return DOVECOT_ERR_SYSTEM;
      }

      p = rtrim (p, "{ \t");

      if (strncmp (p, "imap", 4) == 0
       || strncmp (p, "pop3", 4) == 0) {
       *state = DOVECOT_STAT_SERVICE;
        service = p;
      } else {
        free (p);
      }
    }
  } else if (*state == DOVECOT_STAT_SERVICE) {
    if (strncmp (str, "inet_listener", 13) == 0)
     *state = DOVECOT_STAT_INET_LISTENER;
    else if (*str == '}')
     *state = DOVECOT_STAT_MAIN;

  } else if (*state == DOVECOT_STAT_INET_LISTENER) {
    if (strncmp (str, "address", 7) == 0) {
      return dovecot_config_read_option (&host, str);

    } else if (strncmp (str, "port", 4) == 0) {
      return dovecot_config_read_option (&port, str);

    } else if (strncmp (str, "ssl", 3) == 0) {
      return dovecot_config_read_option (&ssl, str);

    } else if (*str == '}') {
     *state = DOVECOT_STAT_SERVICE;

      if ((iface = iface_create (service, host, port, ssl)) == NULL) {
        ocf_log (LOG_ERR, "%s: iface_create: %s", __func__, strerror (errno));
        goto failure;
      }
      if ((cur = iface_list_create (ifaces, iface)) == NULL) {
        ocf_log (LOG_ERR, "%s: iface_list_create: %s", __func__, strerror (errno));
        goto failure;
      }

      if (ifaces == NULL)
        ifaces = cur;

      CLEAR(host);
      CLEAR(port);
      CLEAR(ssl);
    }
  } else {
    ocf_log (LOG_ERR, "%s: invalid parser state", __func__);
    return DOVECOT_ERR_PARSER;
  }

  return DOVECOT_SUCCESS;

failure:
  CLEAR(service);
  CLEAR(host);
  CLEAR(port);
  CLEAR(ssl);

  return DOVECOT_ERR_SYSTEM;
}

#undef CLEAR

int
dovecot_config_read (const char *path, const char *config_path)
{
  iface_list_t *cur;
  iface_t *iface;
  char *host;
  int state = DOVECOT_STAT_MAIN;
  int ret, result;
  pid_t pid;
  int fdin, fdout, fderr;
  int fd, fdmin, fdmax;

  struct timeval timeout; // we definiteley need a timeout...
  fd_set fds, rdfds;
  char buf[BUFSIZE];
  char *p, *p1, *p2;
  int errors = 0;
  char *basename;
  ssize_t cnt;





  if ((basename = strrchr (path, '/')))
    basename++;
  else
    basename = (char*)path;

  char *argv[9];
        argv[0] = basename;
        argv[1] = "-c";
        argv[2] = (char*)config_path;
        argv[3] = "base_dir";
        argv[4] = "listen";
        argv[5] = "shutdown_clients";
        argv[6] = "service/imap-login/inet_listener";
        argv[7] = "service/pop3-login/inet_listener";
        argv[8] = NULL;

  pid = run (path, argv, &fdin, &fdout, &fderr);

  close (fdin); /* doveconf does not use STDIN */

  FD_ZERO (&fds);
  FD_SET (fdout, &fds);
  FD_SET (fderr, &fds);

  fdmin = (fdout < fderr) ? fdout : fderr;
  fdmax = (fdout > fderr) ? fdout+1 : fderr+1;

  for (; FD_ISSET (fdout, &fds) || FD_ISSET (fderr, &fds); ) {
    timeout.tv_sec = 1;
		timeout.tv_usec = 0;

    rdfds = fds;

    switch (select (fdmax, &rdfds, NULL, NULL, &timeout)) {
      case -1: /* error */
        if (errno != EINTR) {
          ocf_log (LOG_ERR, "%s: select: %s", __func__, strerror (errno));
          goto error;
        }
        break;
      case 0: /* timeout */
        ocf_log (LOG_ERR, "%s: timed out", __func__);
        goto error;
        break;
      default:
        for (fd=fdmin; fd < fdmax; fd++) {
          if (! FD_ISSET (fd, &rdfds))
            continue;

          cnt = readline (fd, buf, BUFSIZE);

          if (cnt > 0) {
            p = trim (buf, " \n\t");

            if (fd == fdout) {
              ret = dovecot_config_read_line (p, &state);

              if (ret != DOVECOT_SUCCESS)
                return ret;
            } else {
              ocf_log (LOG_ERR, "%s: %s", __func__, p);
              errors++;
            }

          } else if (cnt < 0) {
            ocf_log (LOG_ERR, "%s: readline: %s", __func__, strerror (errno));
          } else {
            /* fd empty, skip next time */
            FD_CLR (fd, &fds);
          }
        }
        break;
    }
  }

  if (base_dir) {
    pid_file = malloc (strlen (base_dir)+12);
    sprintf (pid_file, "%s/master.pid", base_dir);
  }

  /* iterate over all interfaces and fill in first listen address where host is
     empty */
  if (listen) {
    for (p1=listen; isspace (*p1); p1++)
      ; /* ignore leading whitespace */

    if (*p1 != '*' && *p1 != '\0') {
      for (p2=p1; *p2 && ! isspace (*p2) && *p2 != ','; p2++)
        ;

      if (p2 > p1) {
        if ((host = strndup (p1, (p2-p1))) == NULL)
          goto error;
      } else {
        host = NULL;
      }
    } else if (*p1 == '*') {
      if ((host = strdup ("localhost")) == NULL)
        goto error;
    } else {
      host = NULL;
    }
  } else {
    host = NULL;
  }

  /* host being NULL is only considered an error if there's an interface where
     host is NULL. */
  for (cur=ifaces; cur; cur=cur->next) {
    iface = cur->iface;
    if (iface && iface->host == NULL) {
      if (host == NULL) {
        ocf_log (LOG_ERR, "%s: \"listen\" was empty, but there where one or "
          "more interfaces where \"address\" was also empty", __func__);
        goto error_config;
      }
      if ((iface->host = strdup (host)) == NULL)
        goto error; /* errno set by strdup */
    }
  }

  result = DOVECOT_SUCCESS;

  if (0) {
error:
    result = DOVECOT_ERR_SYSTEM;
  }

  if (errors) {
error_config:
    result = DOVECOT_ERR_CONFIG;
    errors++;
  }

  if (host)
    free (host);

  return result;
}

int
dovecot_config_deinit (void)
{
  if (base_dir) {
    free (base_dir);
    base_dir = NULL;
  }
  if (pid_file) {
    free (pid_file);
    pid_file = NULL;
  }
  if (listen) {
    free (listen);
    listen = NULL;
  }
  if (shutdown_clients) {
    free (shutdown_clients);
    shutdown_clients = NULL;
  }
  if (ifaces) {
    iface_list_free (ifaces, 1);
    ifaces = NULL;
  }

  return DOVECOT_SUCCESS;
}
