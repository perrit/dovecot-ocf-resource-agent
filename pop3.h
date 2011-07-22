#ifndef POP3_H_INCLUDED
#define POP3_H_INCLUDED

#define POP3_SUCCESS      (0)
#define POP3_ERR_PROTOCOL (1)
#define POP3_ERR_BUFSIZE  (2)
#define POP3_ERR_SYSTEM   (3)

int pop3_iface_test (iface_t *iface, const char *, const char *, const char *,
  const char *, const int);

#endif
