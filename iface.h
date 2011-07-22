#ifndef IFACE_H_INCLUDED
#define IFACE_H_INCLUDED

/* system includes */
#include <stdbool.h>

typedef struct iface_struct iface_t;

struct iface_struct {
  char *service;
  char *host;
  char *port;
  bool  ssl;
};

typedef struct iface_list_struct iface_list_t;

struct iface_list_struct {
  iface_t *iface;
  iface_list_t *next;
};

iface_t *iface_create (const char *, const char *, const char *, const char *);
void iface_free (iface_t *);
iface_t *iface_from_uri (const char *uri, char **);
iface_list_t *iface_list_create (iface_list_t *, iface_t *);
void iface_list_free (iface_list_t *, int);
iface_list_t *iface_list_from_uris (const char *, char **);
iface_list_t *iface_list_exclude (iface_list_t *, iface_list_t *);

#endif
