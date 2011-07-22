#ifndef DOVECOT_H_INCLUDED
#define DOVECOT_H_INCLUDED

#include "iface.h"

/* defines */
#define DOVECOT_SUCCESS (0)
#define DOVECOT_ERR_PARSER (1)
#define DOVECOT_ERR_CONFIG (2)
#define DOVECOT_ERR_SYSTEM (3)

extern char *pid_file;
extern char *listen;
extern char *shutdown_clients;
extern iface_list_t *ifaces;

int dovecot_config_init (void);
int dovecot_config_read (const char *, const char *);
int dovecot_config_deinit (void);

#endif
