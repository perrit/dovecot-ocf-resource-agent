#ifndef OCF_H_INCLUDED
#define OCF_H_INCLUDED

/* system includes */
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

/* OCF return codes */
#define OCF_SUCCESS           (0)
#define OCF_ERR_GENERIC       (1)
#define OCF_ERR_ARGS          (2)
#define OCF_ERR_UNIMPLEMENTED (3)
#define OCF_ERR_PERM          (4)
#define OCF_ERR_INSTALLED     (5)
#define OCF_ERR_CONFIGURED    (6)
#define OCF_NOT_RUNNING       (7)
#define OCF_RUNNING_MASTER    (8)
#define OCF_FAILED_MASTER     (9)

/* OCF log levels are the same as the levels defined in syslog.h */

#define DEFAULT_HA_LOGFACILITY "daemon"
#define DEFAULT_HA_DEBUGLOG "/dev/null"



int ocf_log_init (const char *);
void ocf_log_deinit (void);
int ocf_log (int, const char *, ...);
char *ocf_reskey (char *, const char *);
pid_t ocf_pidfile_status (const char *);

int ocf_kill (pid_t pid, int sig, unsigned int secs);
int ocf_kill_tree (pid_t ppid, int sig, unsigned int secs);

int ocf_is_decimal (const char *);
int ocf_is_true(const char *);

#endif
