#ifndef IMAP_H_INCLUDED
#define IMAP_H_INCLUDED

#include "iface.h"

#define IMAP_SUCCESS      (0)
#define IMAP_ERR_PROTOCOL (1)
#define IMAP_ERR_BUFSIZE  (2)
#define IMAP_ERR_SYSTEM   (3)

int imap_iface_test (iface_t *, const char *, const char *, const char *,
  const char *, const int);

#endif
