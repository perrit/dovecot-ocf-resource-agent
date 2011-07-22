/* system includes */
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* dovecot-ocf includes */
#include "iface.h"
#include "iostream.h"
#include "ocf.h"
#include "pop3.h"
#include "utils.h"

/* definitions */
#define POP3_RESP_TYPE_EMPTY         (0)
#define POP3_RESP_TYPE_OK            (1)
#define POP3_RESP_TYPE_ERR           (2)
#define POP3_RESP_TYPE_MULTILINE     (3)
#define POP3_RESP_TYPE_MULTILINE_END (4)

#define POP3_STAT_CONN (0)
#define POP3_STAT_CAPA (1)
#define POP3_STAT_STLS (2)
#define POP3_STAT_USER (3)
#define POP3_STAT_PASS (4)
#define POP3_STAT_STAT (5)
#define POP3_STAT_QUIT (6)

typedef struct pop3_info_struct pop3_info_t;

struct pop3_info_struct {
  char   *buf;
  size_t  len;
  char   *command;
};

typedef struct pop3_resp_struct pop3_resp_t;

struct pop3_resp_struct {
  char   *buf;
  size_t  len;
  int     type;
  char   *status;
  char   *extra;
};

/* prototypes */
pop3_info_t *pop3_resp_info (size_t);
void pop3_info_free (pop3_info_t *);
pop3_resp_t *pop3_resp_alloc (size_t);
void pop3_resp_free (pop3_resp_t *);
void pop3_resp_reset (pop3_resp_t *);
int pop3_recv (iostream_t *, pop3_resp_t *);
int pop3_send (iostream_t *, pop3_info_t *, const char *, ...);

pop3_info_t *
pop3_info_alloc (size_t len)
{
  pop3_info_t *info;

  if ((info = malloc (sizeof (pop3_info_t))) == NULL) {
    return NULL;
  }
  if ((info->buf = malloc (len)) == NULL) {
    free (info);
    return NULL;
  }

  memset (info->buf, 0, len);
  info->len = len;
  info->command = NULL;

  return info;
}

void
pop3_info_free (pop3_info_t *info)
{
  if (info) {
    if (info->buf)
      free (info->buf);
    free (info);
  }
  return;
}

pop3_resp_t *
pop3_resp_alloc (size_t len)
{
  pop3_resp_t *resp;

  if ((resp = malloc (sizeof (pop3_resp_t))) == NULL) {
    return NULL;
  }
  if ((resp->buf = malloc (len)) == NULL) {
    free (resp);
    return NULL;
  }

  memset (resp->buf, 0, len);
  resp->len = len;
  resp->type = POP3_RESP_TYPE_EMPTY;
  resp->status = NULL;
  resp->extra = NULL;

  return resp;
}

void
pop3_resp_free (pop3_resp_t *resp)
{
  if (resp) {
    if (resp->buf)
      free (resp->buf);
    free (resp);
  }
  return;
}

void
pop3_resp_reset (pop3_resp_t *resp)
{
  memset (resp->buf, 0, resp->len);
  resp->type = POP3_RESP_TYPE_EMPTY;
  resp->status = NULL;
  resp->extra = NULL;
  return;
}

int
pop3_recv (iostream_t *stream, pop3_resp_t *resp)
{
  char *errstr, *p1, *p2;

  pop3_resp_reset (resp);

  if (iostream_gets (stream, resp->buf, resp->len, &errstr) < 0) {
    ocf_log (LOG_ERR, "%s: iostream_gets: %s", __func__, errstr);
    return POP3_ERR_SYSTEM;
  }

  p1 = trim (resp->buf, " \t"); /* ignore leading and trailing whitespace */
  p2 = NULL;

  if (*p1 == '.') {
    resp->type = POP3_RESP_TYPE_MULTILINE_END;
  } else if (strncmp (p1, "+OK", 3) == 0) {
    resp->type = POP3_RESP_TYPE_OK;
    resp->status = p1;
    p2 = ltrim (p1+3, " \t");
  } else if (strncmp (p1, "-ERR", 4) == 0) {
    resp->type = POP3_RESP_TYPE_ERR;
    resp->status = p1;
    p2 = ltrim (p1+4, " \t");
  } else {
    resp->type = POP3_RESP_TYPE_MULTILINE;
    resp->extra = p1;
  }

  if (p2 && *p2)
    resp->extra = p2;

  return POP3_SUCCESS;
}

int
pop3_send (iostream_t *stream, pop3_info_t *info, const char *fmt, ...)
{
  char *errstr, *fmt_start, *ptr;
  size_t cnt;
  va_list ap;

  for (fmt_start=(char*)fmt; isspace (*fmt_start); fmt_start++)
    ; /* remove leading whitespace */

  if (! *fmt_start) {
    ocf_log (LOG_ERR, "%s: command empty", __func__);
    return POP3_ERR_PROTOCOL;
  }

  /* write command to buffer */
  va_start (ap, fmt);
  cnt = vsnprintf (info->buf, info->len, fmt_start, ap);
  va_end (ap);

  info->command = info->buf;

  if (cnt < 0) {
    ocf_log (LOG_ERR, "%s: vsnprintf: %s", __func__, strerror (errno));
    return POP3_ERR_SYSTEM;
  }
  if (cnt > info->len) {
    ocf_log (LOG_ERR, "%s: not enough space available in output buffer",
      __func__);
    return POP3_ERR_BUFSIZE;
  }

  /* remove trailing whitespace */
  for (ptr=info->buf; *ptr; ptr++)
    ;
  for (--ptr; isspace (*ptr); ptr--)
    ;

  if (((ptr - info->buf) + 3) > info->len) {
    ocf_log (LOG_ERR, "%s: not enough space available in output buffer",
      __func__);
    return POP3_ERR_BUFSIZE;
  }

  strcpy (++ptr, "\r\n");

  /* write command to iostream */
  if (iostream_puts (stream, info->buf, &errstr) < 0) {
    ocf_log (LOG_ERR, "%s: iostream_puts: %s", __func__, errstr);
    return POP3_ERR_SYSTEM;
  }

  return POP3_SUCCESS;
}

#define BUFSIZE (4096)
#define STRNULLCMP(s1,s2,n) ((s1 == NULL) ? -1 : strncmp ((s1),(s2),(n)))

int
pop3_iface_test (iface_t *iface, const char *user, const char *passwd,
  const char *ca_file, const char *ca_path, const int starttls)
{
  bool plain_auth_avail=0, starttls_avail=0;
  char *errstr;
  int state, result;
  iostream_t *stream;
  pop3_info_t *info = NULL;
  pop3_resp_t *resp = NULL;

  if ((stream = iostream_init (&errstr)) == NULL) {
    ocf_log (LOG_ERR, "%s: iostream_alloc: %s", __func__, errstr);
    goto failure;
  }
  if ((info = pop3_info_alloc (BUFSIZE)) == NULL) {
    ocf_log (LOG_ERR, "%s: pop3_info_alloc: %s", __func__,
      strerror (errno));
    goto failure;
  }
  if ((resp = pop3_resp_alloc (BUFSIZE)) == NULL) {
    ocf_log (LOG_ERR, "%s: pop3_resp_alloc: %s", __func__,
      strerror (errno));
    goto failure;
  }
  if (iostream_connect (stream, iface->host, iface->port, &errstr) == 0) {
    ocf_log (LOG_DEBUG, "%s: connected to %s%s://%s:%s/", __func__,
      iface->service, iface->ssl ? "s" : "", iface->host, iface->port);
  } else {
    ocf_log (LOG_ERR, "%s: iostream_connect: %s", __func__, errstr);
    goto failure;
  }
  if (iface->ssl && iostream_encrypt (stream, ca_file, ca_path, &errstr) == 0) {
    ocf_log (LOG_DEBUG, "%s: connection encrypted", __func__);
  } else if (iface->ssl) {
    ocf_log (LOG_ERR, "%s: iostream_encrypt: %s", __func__, errstr);
    goto failure;
  }

  for (state=POP3_STAT_CONN, result=POP3_SUCCESS; ; ) {

    if (pop3_recv (stream, resp) != POP3_SUCCESS)
      goto failure;

    if (state == POP3_STAT_CONN) {
      if (resp->type == POP3_RESP_TYPE_OK) {
        state = POP3_STAT_CAPA;
        if (pop3_send (stream, info, "CAPA") < 0)
          goto failure;
        continue;
      }
    } else if (state == POP3_STAT_CAPA) {
      if (resp->type == POP3_RESP_TYPE_MULTILINE_END) {
        if (! plain_auth_avail) {
          ocf_log (LOG_DEBUG, "%s: plain text passwords not enabled",
            __func__);
          state = POP3_STAT_QUIT;
          if (pop3_send (stream, info, "QUIT") < 0)
            goto failure;
        } else if (starttls_avail && starttls) {
          state = POP3_STAT_STLS;
          if (pop3_send (stream, info, "STLS") < 0)
            goto failure;
        } else {
          state = POP3_STAT_USER;
          if (pop3_send (stream, info, "USER %s", user) < 0)
            goto failure;
        }
        continue;
      } else if (resp->type == POP3_RESP_TYPE_MULTILINE) {
        if (STRNULLCMP (resp->extra, "STLS", 4) == 0) {
          ocf_log (LOG_DEBUG, "%s: connection can be encrypted", __func__);
          starttls_avail = true;
        } else if (STRNULLCMP (resp->extra, "SASL", 4) == 0 && strstr (resp->extra, "PLAIN")) {
          ocf_log (LOG_DEBUG, "%s: plain text passwords enabled", __func__);
          plain_auth_avail = true;
        }
        continue;
      } else if (resp->type == POP3_RESP_TYPE_OK) {
        continue;
      }
    } else if (state == POP3_STAT_STLS) {
      if (resp->type == POP3_RESP_TYPE_OK) {
        if (iostream_encrypt (stream, ca_file, ca_path, &errstr) < 0) {
          ocf_log (LOG_ERR, "%s: iostream_encrypt: %s", __func__, errstr);
          goto failure;
        }
        ocf_log (LOG_DEBUG, "%s: connection encrypted", __func__);
      } else if (resp->type == POP3_RESP_TYPE_ERR) {
        ocf_log (LOG_WARNING, "%s: connection could not be encrypted: %s",
          __func__, resp->extra);
      }

      if (resp->type == POP3_RESP_TYPE_OK ||
          resp->type == POP3_RESP_TYPE_ERR)
      {
        state = POP3_STAT_USER;
        if (pop3_send (stream, info, "USER %s", user) < 0)
          goto failure;
        continue;
      }
    } else if (state == POP3_STAT_USER) {
      if (resp->type == POP3_RESP_TYPE_OK) {
        ocf_log (LOG_DEBUG, "%s: logged in", __func__);
        state = POP3_STAT_PASS;
        if (pop3_send (stream, info, "PASS %s", passwd) < 0)
          goto failure;
        continue;
      }
    } else if (state == POP3_STAT_PASS) {
      if (resp->type == POP3_RESP_TYPE_OK) {
        state = POP3_STAT_STAT;
        if (pop3_send (stream, info, "STAT") < 0)
          goto failure;
        continue;
      }
    } else if (state == POP3_STAT_STAT) {
      if (resp->type == POP3_RESP_TYPE_OK) {
        state = POP3_STAT_QUIT;
        if (pop3_send (stream, info, "QUIT") < 0)
          goto failure;
        continue;
      }
    } else if (state == POP3_STAT_QUIT) {
      if (resp->type == POP3_RESP_TYPE_OK) {
        ocf_log (LOG_DEBUG, "%s: logged out", __func__);
        break;
      }
    }

    /* error condition, extra information may be available */
    if (resp->status && resp->extra && strncmp (resp->status, "-ERR", 4) == 0)
      ocf_log (LOG_ERR, "%s: %s", __func__, resp->extra);
    else
      ocf_log (LOG_ERR, "%s: unknown error", __func__);
    goto failure_protocol;
  }

  if (0) {
failure:
    result = POP3_ERR_SYSTEM;
  }

  if (0) {
failure_protocol:
    result = POP3_ERR_PROTOCOL;
  }

  iostream_deinit (stream); /* also calls iostream_disconnect */
  pop3_info_free (info);
  pop3_resp_free (resp);

  return result;
}

#undef STRNULLCMP
#undef BUFSIZE
