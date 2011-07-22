/*
 * Dovecot
 *
 * Description:  Manages Dovecot as an OCF resource in an high-availability
 *               setup.
 *
 * Author:       Jeroen Koekkoek
 * License:      GNU General Public License (GPL)
 * Copyright:    (C) 2011 Pagelink B.V.
 *
 * OCF parameters:
 *   OCF_RESKEY_dovecot
 *   OCF_RESKEY_doveconf
 *   OCF_RESKEY_config_file
 *   OCF_RESKEY_inet_listeners
 *   OCF_RESKEY_exclude_inet_listeners
 *   OCF_RESKEY_user
 *   OCF_RESKEY_password
 *   OCF_RESKEY_ca_file
 *   OCF_RESKEY_ca_path
 *   OCF_RESKEY_starttls
 *
 */

/* system includes */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* dovecot-ocf includes */
#include "dovecot.h"
#include "iface.h"
#include "imap.h"
#include "pop3.h"
#include "ocf.h"
#include "utils.h"

char *dovecot;
char *doveconf;
char *config_file;
char *user;
char *password;
char *inet_listeners;
char *exclude_inet_listeners;
char *ca_file;
char *ca_path;
char *starttls;

/* prototypes */
void init_ocf_reskeys (void);
void deinit_ocf_reskeys (void);

void
init_ocf_reskeys (void)
{
  if ((dovecot = ocf_reskey ("dovecot", "/usr/sbin/dovecot")) == NULL)
    goto failure;
  if ((doveconf = ocf_reskey ("doveconf", "/usr/bin/doveconf")) == NULL)
    goto failure;
  if ((config_file = ocf_reskey ("config_file", "/etc/dovecot/dovecot.conf")) == NULL)
    goto failure;
  if ((user = ocf_reskey ("user", NULL)) == NULL)
    goto failure;
  if ((password = ocf_reskey ("password", NULL)) == NULL)
    goto failure;
  ca_file = ocf_reskey ("ca_file", NULL);
  ca_path = ocf_reskey ("ca_path", NULL);
  inet_listeners = ocf_reskey ("inet_listeners", NULL);
  exclude_inet_listeners = ocf_reskey ("exclude_inet_listeners", NULL);

  if ((starttls = ocf_reskey ("starttls", "yes")) == NULL)
    goto failure;

  return;
failure:
  deinit_ocf_reskeys ();
  exit (OCF_ERR_ARGS);
}

void
deinit_ocf_reskeys (void)
{
  if (dovecot)
    free (dovecot);
  if (doveconf)
    free (doveconf);
  if (config_file)
    free (config_file);
  if (user)
    free (user);
  if (password)
    free (password);
  if (ca_file)
    free (ca_file);
  if (ca_path)
    free (ca_path);
  if (starttls)
    free (starttls);
  return;
}

int
usage (const char *cmd)
{
  const char *fmt =
"Usage: %s (start|stop|reload|status|monitor|validate-all|meta-data)\n";

  fprintf (stderr, fmt, cmd);
  return OCF_ERR_ARGS;
}

int
meta_data (void)
{
  const char *fmt =
"<?xml version=\"1.0\"?>\n"
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
"<resource-agent name=\"dovecot\">\n"
"<version>0.1</version>\n"
"<longdesc lang=\"en\">\n"
"Resource script for Dovecot. It manages a Dovecot instance as an OCF resource.\n"
"</longdesc>\n"
"<shortdesc lang=\"en\">Manages a Dovecot instance</shortdesc>\n"
"<parameters>\n"
"<parameter name=\"dovecot\" unique=\"0\" required=\"0\">\n"
"<longdesc lang=\"en\">\n"
"Full path to the dovecot binary.\n"
"For example, \"/usr/sbin/dovecot\".\n"
"</longdesc>\n"
"<shortdesc lang=\"en\">Full path to dovecot binary</shortdesc>\n"
"<content type=\"string\" default=\"/usr/sbin/dovecot\" />\n"
"</parameter>\n"
"<parameter name=\"doveconf\" unique=\"0\" required=\"0\">\n"
"<longdesc lang=\"en\">\n"
"Full path to the doveconf binary.\n"
"For example, \"/usr/bin/doveconf\".\n"
"</longdesc>\n"
"<shortdesc lang=\"en\">Full path to doveconf binary</shortdesc>\n"
"<content type=\"string\" default=\"/usr/bin/doveconf\" />\n"
"</parameter>\n"
"<parameter name=\"config_file\" unique=\"1\" required=\"0\">\n"
"<longdesc>\n"
"Full pathname of the Dovecot configuration file.\n"
"For example, \"/etc/dovecot/dovecot.conf\"\n"
"</longdesc>\n"
"<shortdesc>Full pathname of configuration file</shortdesc>\n"
"<content type=\"string\" default=\"/etc/dovecot/dovecot.conf\" />\n"
"</parameter>\n"
"<parameter name=\"inet_listeners\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"IMAP and POP3 interfaces to monitor.\n"
"For example, \"imap://localhost/\" or \"pop3s://localhost:1234/\"\n"
"inet_listeners overwrites inet_listeneres defined in Dovecot configuration\n"
"file and exclude_inet_listeners.\n"
"</longdesc>\n"
"<shortdesc>IMAP and POP3 interfaces to monitor.</shortdesc>\n"
"<content type=\"string\" default=\"\" />\n"
"</parameter>\n"
"<parameter name=\"exclude_inet_listeners\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"IMAP and POP3 interfaces not to monitor.\n"
"For example, \"imap://localhost/\" to not monitor IMAP on localhost, or\n"
"\"pop3:///\" not to monitor any POP3 interface.\n"
"</longdesc>\n"
"<shortdesc>IMAP and POP3 interfaces not to monitor.</shortdesc>\n"
"<content type=\"string\" default=\"\" />\n"
"</parameter>\n"
"<parameter name=\"user\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"Username that will be used for logging into IMAP and POP3 interfaces.\n"
"</longdesc>\n"
"<shortdesc>Username used for logging into IMAP and POP3 interfaces</shortdesc>\n"
"<content type=\"string\" default=\"\" />\n"
"</parameter>\n"
"<parameter name=\"password\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"Password that will be used for logging into IMAP and POP3 interfaces.\n"
"</longdesc>\n"
"<shortdesc>Password used for logging into IMAP and POP3 interfaces</shortdesc>\n"
"<content type=\"string\" default=\"\" />\n"
"</parameter>\n"
"<parameter name=\"ca_file\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"A file containing trusted certificates used for building the client\n"
"certificate chain.\n"
"</longdesc>\n"
"<shortdesc>File containing trusted certificates used for building certificate chain.</shortdesc>\n"
"<content type=\"string\" default=\"\" />\n"
"</parameter>\n"
"<parameter name=\"ca_path\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"The directory used for building the certificate chain. This directory must\n"
"be in \"hash format\"."
"</longdesc>\n"
"<shortdesc>Directory in \"hash format\" used for building certificate chain</shortdesc>\n"
"<content type=\"string\" default=\"\" />\n"
"</parameter>\n"
"<parameter name=\"starttls\" unique=\"0\" required=\"0\">\n"
"<longdesc>\n"
"Turn support for STARTTLS on or off if it's available during the session.\n"
"</longdesc>\n"
"<shortdesc>Turn support for STARTTLS on or off</shortdesc>\n"
"<content type=\"bool\" default=\"yes\" />\n"
"</parameter>\n"
"</parameters>\n"
"<actions>\n"
"<action name=\"start\" timeout=\"20s\" />\n"
"<action name=\"stop\" timeout=\"20s\" />\n"
"<action name=\"reload\" timeout=\"20s\" />\n"
"<action name=\"monitor\" depth=\"0\" timeout=\"20s\" interval=\"60s\" />\n"
"<action name=\"monitor\" depth=\"10\" timeout=\"20s\" interval=\"120s\" />\n"
"<action name=\"validate-all\" timeout=\"20s\" />\n"
"<action name=\"meta-data\" timeout=\"5s\" />\n"
"</actions>\n"
"</resource-agent>\n";

  printf ("%s", fmt);
  return OCF_SUCCESS;
}


int
dovecot_status (void)
{
  pid_t pid;

  if (pid_file == NULL) {
    ocf_log (LOG_ERR, "%s: pid_file empty", __func__);
    return OCF_ERR_GENERIC;
  }

  pid = ocf_pidfile_status (pid_file);

  if (pid == (pid_t)-1) {
    ocf_log (LOG_ERR, "%s: ocf_pidfile_status: %s", __func__,
      strerror (errno));
    if (errno && errno != ENOENT)
      return OCF_ERR_GENERIC;
  }
  if (pid) {
    ocf_log (LOG_INFO, "Dovecot is running.");
    return OCF_SUCCESS;
  }

  ocf_log (LOG_INFO, "Dovecot is stopped.");
  return OCF_NOT_RUNNING;
}

int
dovecot_monitor (void)
{
  int level, rv;
  char *errstr, *ev;
  iface_t *iface;
  iface_list_t *list, *cur, *listeners;
  pid_t pid;

  ev = getenv ("OCF_RESKEY_OCF_CHECK_LEVEL");

  if (ev == NULL)
    level = 0;
  else
    level = strtol (ev, NULL, 10);

  ocf_log (LOG_INFO, "%s: level %d, pid file: %s", __func__, level, pid_file);

  if (level == 0)
    return dovecot_status ();

  /* run deeper tests only if Dovecot is currently running */
  if (pid_file == NULL) {
    ocf_log (LOG_ERR, "%s: pid_file empty", __func__);
    return OCF_ERR_GENERIC;
  }

  pid = ocf_pidfile_status (pid_file);
  ocf_log (LOG_INFO, "%s: pid: %d", __func__, pid);

  if (pid == (pid_t)-1) {
    ocf_log (LOG_ERR, "%s: ocf_pidfile_status: %s", __func__,
      strerror (errno));
    if (errno && errno == ENOENT)
      return OCF_NOT_RUNNING;
    return OCF_ERR_GENERIC;
  }
  if (pid == (pid_t)0) {
    ocf_log (LOG_INFO, "Dovecot is stopped.");
    return OCF_NOT_RUNNING;
  }

  if (inet_listeners) {
    errstr = NULL;
    listeners = iface_list_from_uris (inet_listeners, &errstr);

    if (listeners == NULL && errstr) {
      ocf_log (LOG_ERR, "%s: iface_list_from_uris: %s", __func__, errstr);
      return OCF_ERR_GENERIC;
    }

    list = listeners;
  } else {
    list = NULL;
  }

  /* only parse exclude_inet_listeners if inet_listeners was empty */
  if (list == NULL) {
    errstr = NULL;
    listeners = iface_list_from_uris (exclude_inet_listeners, &errstr);

    if (listeners == NULL && errstr) {
      ocf_log (LOG_ERR, "%s: exclude_inet_listeners: %s", __func__, errstr);
      return OCF_ERR_GENERIC;
    }

    if (listeners) {
      list = iface_list_exclude (ifaces, listeners);
      if (list == NULL && errstr) {
        ocf_log (LOG_ERR, "%s: iface_list_exclude: %s", __func__, errstr);
        iface_list_free (listeners, 1);
        return OCF_ERR_GENERIC;
      }
    } else {
      list = ifaces;
    }
  }

  for (cur=list; cur; cur=cur->next) {
    iface = cur->iface;
    if (iface && iface->service) {
      if (strcmp (iface->service, "imap") == 0) {
        rv = imap_iface_test (iface, user, password, ca_file, ca_path, ocf_is_true (starttls));
        if (rv != IMAP_SUCCESS) {
          iface_list_free (listeners, 1);
          return OCF_ERR_GENERIC;
        }
      } else if (strcmp (iface->service, "pop3") == 0) {
        rv = pop3_iface_test (iface, user, password, ca_file, ca_path, ocf_is_true (starttls));
        if (rv != POP3_SUCCESS) {
          iface_list_free (listeners, 1);
          return OCF_ERR_GENERIC;
        }
      } else {
        ocf_log (LOG_ERR, "%s: service not supported: %s", __func__,
          iface->service);
        iface_list_free (listeners, 1);
        return OCF_ERR_ARGS;
      }
    }
  }

  return OCF_SUCCESS;
}

#define BUFSIZE (4096)

int
dovecot_start (void)
{
  char *argv[4], *basename;
  char buf[BUFSIZE], *p;
  fd_set fds, rdfds;
  int fd, fdmin, fdmax, status;
  int fdin, fdout, fderr;
  int errors;
  pid_t pid;
  ssize_t cnt;
  struct timeval tv;

  if ((pid = ocf_pidfile_status (pid_file)) > (pid_t)0) {
    ocf_log (LOG_INFO, "Dovecot already running.");
    return OCF_SUCCESS;
  } else if (pid < (pid_t)0) {
    if (errno != ENOENT) {
      ocf_log (LOG_ERR, "%s: ocf_pidfile_status: %s", __func__, strerror (errno));
      return OCF_ERR_GENERIC;
    }
  }

  if ((basename = strrchr (dovecot, '/')))
    basename++;
  else
    basename = (char*)dovecot;

  argv[0] = basename;
  argv[1] = "-c";
  argv[2] = config_file;
  argv[3] = NULL;

  if ((pid = run (dovecot, argv, &fdin, &fdout, &fderr)) < 0) {
    ocf_log (LOG_ERR, "%s: run: %s", __func__, strerror (errno));
    return OCF_ERR_GENERIC;
  }

  close (fdin);
  fcntl (fdout, F_SETFL, O_NONBLOCK);
  fcntl (fderr, F_SETFL, O_NONBLOCK);

  FD_ZERO (&fds);
  FD_SET (fdout, &fds);
  FD_SET (fderr, &fds);

  fdmin = (fdout < fderr) ? fdout   : fderr;
  fdmax = (fdout > fderr) ? fdout+1 : fderr+1;

  for (; FD_ISSET (fdout, &fds) || FD_ISSET (fderr, &fds); ) {
    tv.tv_sec = 1;
		tv.tv_usec = 0;

    rdfds = fds;

    switch (select (fdmax, &rdfds, NULL, NULL, &tv)) {
      case -1: /* error */
        if (errno != EINTR) {
          ocf_log (LOG_ERR, "%s: select: %s", __func__, strerror (errno));
          return OCF_ERR_GENERIC;
        }
        break;
      default:
        for (fd=fdmin; fd < fdmax; fd++) {
          if (! FD_ISSET (fd, &fds))
            continue;

         *buf = '\0';
          cnt = readline (fd, buf, BUFSIZE);

          if (cnt > 0) {
            p = trim (buf, " \n\t");

            if (fd == fdout) {
              ocf_log (LOG_INFO, "%s: %s", __func__, p);
            } else {
              ocf_log (LOG_ERR, "%s: %s", __func__, p);
              errors++;
            }

          } else if (cnt < 0) {
            if (errno == EAGAIN) {
              FD_CLR (fd, &fds); /* fd closed, skip next time */
            } else {
              ocf_log (LOG_ERR, "%s: readline: %s", __func__, strerror (errno));
              errors++;
            }
          } else {
            FD_CLR (fd, &fds); /* fd closed, skip next time */
          }
        }
        break;
    }
  }

  waitpid (pid, &status, 0);

  if (WEXITSTATUS (status) != 0) {
    ocf_log (LOG_ERR, "Dovecot returned error.");
    return OCF_ERR_GENERIC;
  }

  ocf_log (LOG_INFO, "Dovecot started.");
  return OCF_SUCCESS;
}

int
dovecot_stop (void)
{
#define EXISTING_SESSIONS (1<<1)
#define ANVIL (1<<2)
#define CONFIG (1<<3)
#define LOG (1<<4)
#define MASTER (1<<5)

  int term;
  pid_t ppid, *pid, anvil_pid, config_pid, log_pid, *pids;
  char *name;

  if ((ppid = ocf_pidfile_status (pid_file)) < 1) {
    if (errno && errno != ENOENT) {
      ocf_log (LOG_ERR, "%s: ocf_pidfile_status: %s", __func__,
        strerror (errno));
      return OCF_ERR_GENERIC;
    } else {
      ocf_log (LOG_INFO, "Dovecot already stopped.");
      return OCF_SUCCESS;
    }
  }

  name = NULL;
  pids = NULL;

  if (ocf_kill (ppid, SIGTERM, 5)) {
    ocf_log (LOG_ERR, "Dovecot failed to stop. Escalating to KILL.");
    pids = getproccpids (ppid);

    if (pids == NULL) {
      ocf_log (LOG_ERR, "%s: getpidsbyppid: %s", __func__,
        strerror (errno));
      return OCF_ERR_GENERIC;
    }

    /* now based on whether shutdown_clients is enabled or not we want to kill
       all or a select number of processes under the dovecot process */
    if (ocf_is_true (shutdown_clients))
      term = EXISTING_SESSIONS | ANVIL | CONFIG | LOG | MASTER;
    else
      term = CONFIG | MASTER;

    for (pid=pids; *pid; pid++) {
      if ((name = getprocname (*pid)) == NULL) {
        ocf_log (LOG_ERR, "%s: getprocname: %s", __func__,
          strerror (errno));
        goto error;
      }

      if (strcmp (name, "anvil") == 0) {
        anvil_pid = *pid;
      } else if (strcmp (name, "config") == 0) {
        config_pid = *pid;
      } else if (strcmp (name, "log") == 0) {
        log_pid = *pid;
      } else {
        if ((term ^ EXISTING_SESSIONS) &&
            (strncmp (name, "pop3", 4) == 0 || strncmp (name, "imap", 4) == 0))
          continue;
        if (ocf_kill_tree (*pid, SIGKILL, 5) == 0) {
          ocf_log (LOG_DEBUG, "%s: %s (%d) killed", __func__, name, *pid);
        } else {
          ocf_log (LOG_ERR, "%s: %s (%d) process refused to die",
            __func__, name, *pid);
          term &= ~(ANVIL|CONFIG|LOG|MASTER);
        }
      }

      free (name);
      name = NULL;
    }

    /* config should always be terminated */
    if (config_pid > 0 && (term & CONFIG)
     && ocf_kill (config_pid, SIGKILL, 5) != 0)
    {
      ocf_log (LOG_ERR, "%s: config (%d) process refused to die",
        __func__, config_pid);
      term &= ~(ANVIL|CONFIG|LOG|MASTER);
    }
    /* anvil should only be killed if shutdown_clients is true and all existing
       sessions where successfully killed */
    if (anvil_pid > 0 && (term & ANVIL)
     && ocf_kill (anvil_pid, SIGKILL, 5) != 0)
    {
      ocf_log (LOG_ERR, "%s: anvil (%d) process refused to die", __func__,
        anvil_pid);
      term &= ~(ANVIL|CONFIG|LOG|MASTER);
    }
    /* log should only be killed if shutdown_clients is true and all existing
       sessions where successfully killed */
    if (log_pid > 0 && (term & LOG)
     && ocf_kill (log_pid, SIGKILL, 5) != 0)
    {
      ocf_log (LOG_ERR, "%s: log (%d) process refused to die", __func__,
        log_pid);
      term &= ~(ANVIL|CONFIG|LOG|MASTER);
    }

    if ((term & MASTER) && ocf_kill (ppid, SIGKILL, 5) != 0) {
      ocf_log (LOG_ERR, "%s: master (%d) process refused to die",
        __func__, ppid);
    }

    free (pids);
  }

  ocf_log (LOG_INFO, "Dovecot stopped.");
  return OCF_SUCCESS;

error:
  if (name)
    free (name);
  if (pids)
    free (pids);
  ocf_log (LOG_ERR, "Dovecot failed to stop.");
  return OCF_ERR_GENERIC;
}

#undef BUFSIZE

int
dovecot_reload (void)
{
  pid_t pid;

  if ((pid = ocf_pidfile_status (pid_file)) < 1) {
    if (errno && errno != ENOENT) {
      ocf_log (LOG_ERR, "%s: ocf_pidfile_status: %s", __func__,
        strerror (errno));
      return OCF_ERR_GENERIC;
    } else {
      ocf_log (LOG_INFO, "Dovecot not running.");
      return OCF_NOT_RUNNING;
    }
  }

  if (kill (pid, SIGHUP) != 0) {
    ocf_log (LOG_ERR, "%s: kill: %s", __func__, strerror (errno));
    return OCF_ERR_GENERIC;
  }

  ocf_log (LOG_DEBUG, "Dovecot reloaded.");
  return OCF_SUCCESS;
}

int
dovecot_validate_all(void)
{
  struct stat buf;

  /* test if dovecot binary exists */
  if (! dovecot || ! strlen (dovecot)) {
    ocf_log (LOG_ERR, "%s: dovecot parameter empty", __func__);
    return OCF_ERR_GENERIC;
  }
  if (stat (dovecot, &buf) < 0) {
    ocf_log (LOG_ERR, "%s: stat: %s", __func__, strerror (errno));
    return OCF_ERR_GENERIC;
  }

  /* test if doveconf binary exists */
  if (! doveconf || ! strlen (doveconf)) {
    ocf_log (LOG_ERR, "%s: doveconf parameter empty", __func__);
    return OCF_ERR_GENERIC;
  }
  if (stat (doveconf, &buf) < 0) {
    ocf_log (LOG_ERR, "%s: stat: %s", __func__, strerror (errno));
    return OCF_ERR_GENERIC;
  }

  /* test if configuration file exists */
  if (! config_file || ! strlen (config_file)) {
    ocf_log (LOG_ERR, "%s: config_file parameter empty", __func__);
    return OCF_ERR_GENERIC;
  }
  if (stat (config_file, &buf) < 0) {
    ocf_log (LOG_ERR, "%s: stat: %s", __func__, strerror (errno));
    return OCF_ERR_GENERIC;
  }

  return OCF_SUCCESS;
}

int
main (int argc, char *argv[])
{
  int rv;

  if (argc != 2)
    return usage (argv[0]);
  if (strncmp (argv[1], "meta-data", 9) == 0)
    return meta_data ();

  init_ocf_reskeys ();
  dovecot_config_init ();

  if ((rv = dovecot_config_read (doveconf, config_file)) != DOVECOT_SUCCESS) {
    if (rv == DOVECOT_ERR_CONFIG)
      goto error_configured;
    goto error_generic;
  }

  ocf_log_init (argv[0]);

  if ((rv = dovecot_validate_all()) != OCF_SUCCESS)
    goto error_generic;

  if (strncmp (argv[1], "status", 6) == 0)
    rv = dovecot_status ();
  else if (strncmp (argv[1], "start", 5) == 0)
    rv = dovecot_start ();
  else if (strncmp (argv[1], "stop", 4) == 0)
    rv = dovecot_stop ();
  else if (strncmp (argv[1], "validate-all", 12) == 0)
    rv = OCF_SUCCESS; /* always validated before this part */
  else if (strncmp (argv[1], "monitor", 7) == 0)
    rv = dovecot_monitor ();
  else if (strncmp (argv[1], "reload", 6) == 0)
    rv = dovecot_reload ();
  else
    rv = usage (argv[0]);

  if (0) {
error_configured:
    rv = OCF_ERR_CONFIGURED;
  }

  if (0) {
error_generic:
    rv = OCF_ERR_GENERIC;
  }

  deinit_ocf_reskeys ();
  dovecot_config_deinit ();
  ocf_log_deinit ();

  return rv;
}
