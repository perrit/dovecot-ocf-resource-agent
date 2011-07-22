#ifndef STREAM_H_INCLUDED
#define STREAM_H_INCLUDED

/* system includes */
#include <stdarg.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define IOSTREAM_ERRSTR_ENOTCONN "The stream is not connected"
#define IOSTREAM_ERRSTR_EALREADY "Connection already secured"
#define IOSTREAM_ERRSTR_ETIMEDOUT "Connection timed out"

typedef struct iostream_struct iostream_t;

struct iostream_struct {
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *buf_bio;
  BIO *ssl_bio;
  BIO *io_bio;
};

iostream_t *iostream_init (char **);
void iostream_deinit (iostream_t *);
int iostream_connect (iostream_t *, const char *, const char *, char **);
void iostream_disconnect (iostream_t *);
int iostream_encrypt (iostream_t *, const char *, const char *, char **);
int iostream_encrypted (iostream_t *);
ssize_t iostream_gets (iostream_t *, char *, size_t, char **);
ssize_t iostream_puts (iostream_t *, const char *, char **);

#endif
