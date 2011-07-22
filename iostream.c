/* system includes */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* includes */
#include "iostream.h"
#include "utils.h"

/* defines */
#define TIMEOUT_SECONDS (5)
#define TIMEOUT_MICROSECONDS (0)

int
socket_timeout (int fd, int rdwr)
{
  int rv;
  fd_set fds;
  struct timeval tv;

  if (fd < 1) {
    errno = EBADF;
    return -1;
  }

  FD_ZERO (&fds);
  FD_SET (fd, &fds);

  tv.tv_sec = TIMEOUT_SECONDS;
  tv.tv_usec = TIMEOUT_MICROSECONDS;

  for (;;) {
    if (rdwr == O_RDWR)
      rv = select (fd+1, &fds, &fds, NULL, &tv);
    else if (rdwr == O_WRONLY)
      rv = select (fd+1, NULL, &fds, NULL, &tv);
    else
      rv = select (fd+1, &fds, NULL, NULL, &tv);

    if (rv < 0) {
      if (errno != EINTR)
        return -1;
    } else if (rv > 0) {
      break;
    } else {
      errno = ETIMEDOUT;
      return -1;
    }
  }

  return 0;
}

int
BIO_should_retry_timed (BIO *bio)
{
  int type, fd, rdwr, retry;

  if ((retry = BIO_should_retry (bio)) == 0)
    return 0;

  /* BIO_should_retry returns either true (BIO_FLAGS_SHOULD_RETRY, 0x08) or
     false (0x00). See http://www.openssl.org/docs/crypto/BIO_should_retry.html
     for details. */

  if ((fd = BIO_get_fd (bio, NULL)) < 0)
    return 0;

  type = BIO_retry_type (bio);

  if ((type & BIO_FLAGS_WRITE) && (type & BIO_FLAGS_READ))
    rdwr = O_RDWR;
  else if ((type & BIO_FLAGS_WRITE))
    rdwr = O_WRONLY;
  else if ((type & BIO_FLAGS_WRITE))
    rdwr = O_RDONLY;

  if ((type & BIO_FLAGS_WRITE) || (type & BIO_FLAGS_READ)) {
    if (socket_timeout (fd, rdwr) < 0)
      return -1; /* should be safe */
  }

  return retry;
}

iostream_t *
iostream_init (char **errstr)
{
  SSL_load_error_strings();

  iostream_t *stream;

  if ((stream = malloc0 (sizeof (iostream_t))))
    return stream;

 *errstr = strerror (errno);
  return NULL;
}

void
iostream_deinit (iostream_t *stream)
{
  if (stream) {
    iostream_disconnect (stream);
    free (stream);
  }

  return;
}

int
iostream_connect (iostream_t *stream, const char *host, const char *port,
                  char **errstr)
{
  unsigned long err;

  /* The io_bio is used for the network io and is merely a wrapper around the
     library functions used to communicate with a remote host. */
  stream->io_bio = BIO_new (BIO_s_connect ());

  if (stream->io_bio == NULL)
    goto error;
  BIO_set_conn_hostname (stream->io_bio, host);
  BIO_set_conn_port (stream->io_bio, port);

  BIO_set_nbio (stream->io_bio, 1);

  for (;;) {
    if (BIO_do_connect (stream->io_bio) == 1)
      break;

    switch (BIO_should_retry_timed (stream->io_bio)) {
      case -1:
        goto timeout;
      case  0:
        goto error;
    }
  }

  return 0;

timeout:
 *errstr = IOSTREAM_ERRSTR_ETIMEDOUT;
  return -1;
error:
  if ((err = ERR_get_error ()))
   *errstr = (char *)ERR_reason_error_string (err);
  else
   *errstr = NULL;
  return -1;
}

void
iostream_disconnect (iostream_t *stream)
{
  if (stream->ssl_bio)
    (void)BIO_reset (stream->ssl_bio); /* will also handle disconnect of io_bio */
  else if (stream->io_bio)
    (void)BIO_reset (stream->io_bio);

  /* SSL_free also frees the buffering BIO, and the read and write BIOs. */
  if (stream->ssl) {
    SSL_free (stream->ssl);
    if (stream->ctx)
      SSL_CTX_free (stream->ctx);
  } else {
    if (stream->io_bio)
      BIO_free (stream->io_bio);
    if (stream->buf_bio)
      BIO_free (stream->buf_bio);
  }

  memset (stream, 0, sizeof (iostream_t));

  return;
}

int
iostream_encrypt (iostream_t *stream, const char *ca_file, const char *ca_path,
                 char **errstr)
{
  int fd, rv;
  SSL_METHOD *method;
  unsigned long err;

  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  /* iostream_t must already be connected to remote host before connection
     can be secured. */
  if (stream->io_bio == NULL) {
   *errstr = IOSTREAM_ERRSTR_ENOTCONN;
    return -1;
  }

  /* iostream_t can only be secured if it isn't already. */
  if (stream->ssl_bio != NULL) {
   *errstr = IOSTREAM_ERRSTR_EALREADY;
    return -1;
  }

  /* Connection can be secured at the beginning or after communication has
     taken place. */
  if (stream->buf_bio) {
    (void)BIO_pop (stream->io_bio);
    method = TLSv1_client_method ();
  } else {
    method = SSLv23_client_method ();
  }

  if ((stream->ctx = SSL_CTX_new (method)) == NULL)
    goto error;
  if (SSL_CTX_load_verify_locations(stream->ctx, ca_file, ca_path) != 1)
    goto error;
  if ((stream->ssl = SSL_new (stream->ctx)) == NULL)
    goto error;

  /* Creation of new SSL succeeded. Appointed the network BIO so it can
     negotiate/communicate. */
  SSL_set_bio (stream->ssl, stream->io_bio, stream->io_bio);
  
  for (;;) {
    if ((rv = SSL_connect (stream->ssl)) == 1)
      break;

    err = SSL_get_error (stream->ssl, rv);

    if (err != SSL_ERROR_WANT_READ
     && err != SSL_ERROR_WANT_WRITE)
      goto error;

    fd = BIO_get_fd (stream->io_bio, NULL);

    if (socket_timeout (fd, O_RDWR) < 0) {
      if (errno == ETIMEDOUT) {
       *errstr = IOSTREAM_ERRSTR_ETIMEDOUT;
        return -1;
      }
      goto error;
    }
  }

  /* A new BIO that wraps arround the newly created SSL must be created. */
  if ((stream->ssl_bio = BIO_new (BIO_f_ssl ())) == NULL)
    goto error;

  BIO_set_ssl (stream->ssl_bio, stream->ssl, 0);

  /* If called in the middle of a conversation, the buffered BIO must know
     about the newly create SSL BIO. */
  if (stream->buf_bio) {
    (void)BIO_push (stream->buf_bio, stream->ssl_bio);
  }

  return 0;

error:
  if ((err = ERR_get_error ()))
   *errstr = (char*)ERR_reason_error_string (err);
  else
   *errstr = NULL;
  return -1;
}

int
iostream_encrypted (iostream_t *stream)
{
  return stream->ssl ? 1 : 0;
}

ssize_t
iostream_gets (iostream_t *stream, char *buf, size_t len, char **errstr)
{
  unsigned long err;
  ssize_t num;

  /* Create the buffering BIO if it wasn't already. */
  if (stream->buf_bio == NULL) {
    if ((stream->buf_bio = BIO_new (BIO_f_buffer())) == NULL)
      goto error;

    if (stream->ssl_bio)
      (void)BIO_push (stream->buf_bio, stream->ssl_bio);
    else
      (void)BIO_push (stream->buf_bio, stream->io_bio);
  }

  for (;;) {
    if ((num = BIO_gets (stream->buf_bio, buf, len)) > 0)
      break;

    switch (BIO_should_retry_timed (stream->buf_bio)) {
      case -1:
        goto timeout;
      case  0:
        goto error;
    }
  }

  return num;

timeout:
 *errstr = IOSTREAM_ERRSTR_ETIMEDOUT;
  return -1;
error:
  if ((err = ERR_get_error ())) {
   *errstr = (char*)ERR_reason_error_string (err);
  } else
   *errstr = NULL;
  return -1;
}

ssize_t
iostream_puts (iostream_t *stream, const char *buf, char **errstr)
{
  unsigned long err;
  ssize_t num;

  /* Create the buffering BIO if it wasn't already. */
  if (stream->buf_bio == NULL) {
    if ((stream->buf_bio = BIO_new (BIO_f_buffer())) == NULL)
      goto error;

    if (stream->ssl_bio)
      (void)BIO_push (stream->buf_bio, stream->ssl_bio);
    else
      (void)BIO_push (stream->buf_bio, stream->io_bio);
  }

  for (;;) {
    if ((num = BIO_puts (stream->buf_bio, buf)) >= 0)
      break;
    switch (BIO_should_retry_timed (stream->buf_bio)) {
      case -1:
        goto timeout;
      case  0:
        goto error;
    }
  }

  if (num) {
    for (;;) {
      if (BIO_flush (stream->buf_bio) > 0)
        break;
      switch (BIO_should_retry_timed (stream->buf_bio)) {
        case -1:
          goto timeout;
        case  0:
          goto error;
      }
    }
  }

  return num;

timeout:
 *errstr = IOSTREAM_ERRSTR_ETIMEDOUT;
  return -1;
error:
  if ((err = ERR_get_error ()))
   *errstr = (char*)ERR_reason_error_string (err);
  else
   *errstr = NULL;
  return -1;
}
