/* Simple IMAP4rev1 client implementation for testing connectivity. */

/* system includes */
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* dovecot-ocf includes */
#include "iface.h"
#include "imap.h"
#include "iostream.h"
#include "ocf.h"
#include "utils.h"

/*
See chapter 7 (Server Responses) for an overview of possible responses.
http://tools.ietf.org/html/rfc2060#section-7
*/

/* defines */
#define IMAP_STAT_CONNECT (0)
#define IMAP_STAT_CAPABILITY (1)
#define IMAP_STAT_STARTTLS (2)
#define IMAP_STAT_LOGIN (3)
#define IMAP_STAT_SELECT (4)
#define IMAP_STAT_LOGOUT (5)
#define IMAP_STAT_DISCONNECT (6)

#define IMAP_RESP_TYPE_EMPTY                        (0)
#define IMAP_RESP_TYPE_TAGGED                       (1)
#define IMAP_RESP_TYPE_UNTAGGED                     (2)
#define IMAP_RESP_TYPE_COMMAND_CONTINUATION_REQUEST (3)



typedef struct imap_info_struct imap_info_t;

struct imap_info_struct {
  char   *buf;
  size_t  len;
  int     index;
  char   *tag;
  char   *command;
};

typedef struct imap_resp_struct imap_resp_t;

struct imap_resp_struct {
  char   *buf;
  size_t  len;
  int     type; /* empty, tagged, untagged, command continuation request */
  char   *tag; /* points to 1st character of tag. */
  char   *status; /* points to 1st character of status. */
  char   *code; /* points to 1st character inside square brackets. */
  char   *command; /* points to 1st character of command. */
  char   *extra; /* points to 1st non whitespace character not part of any of the above. */
};

/* prototypes */
imap_info_t *imap_info_alloc (size_t);
void imap_info_free (imap_info_t *);
imap_resp_t *imap_resp_alloc (size_t);
void imap_resp_free (imap_resp_t *);
void imap_resp_reset (imap_resp_t *);
int imap_recv (iostream_t *, imap_info_t *, imap_resp_t *);
int imap_send (iostream_t *, imap_info_t *, const char *, ...);

imap_resp_t *
imap_resp_alloc (size_t len)
{
  imap_resp_t *resp;

  if ((resp = malloc0 (sizeof (imap_resp_t))) == NULL) {
    return NULL;
  }
  if ((resp->buf = malloc0 (len)) == NULL) {
    free (resp->buf);
    return NULL;
  }

  resp->len = len;

  return resp;
}

void
imap_resp_free (imap_resp_t *resp)
{
  if (resp) {
    if (resp->buf)
      free (resp->buf);
    free (resp);
  }
  return;
}

void
imap_resp_reset (imap_resp_t *resp)
{
  memset (resp->buf, 0, resp->len);
  resp->type = IMAP_RESP_TYPE_EMPTY;
  resp->tag = NULL;
  resp->command = NULL;
  resp->status = NULL;
  resp->extra = NULL;

  return;
}

imap_info_t *
imap_info_alloc (size_t len)
{
  imap_info_t *info;

  if ((info = malloc0 (sizeof (imap_info_t))) == NULL) {
    return NULL;
  }
  if ((info->buf = malloc0 (len)) == NULL) {
    free (info);
    return NULL;
  }

  info->len = len;

  return info;
}

void
imap_info_free (imap_info_t *info)
{
  if (info) {
    if (info->buf)
      free (info->buf);
    free (info);
  }
  return;
}

int
imap_recv (iostream_t *stream, imap_info_t *info, imap_resp_t *resp)
{
  int status_response;
  char *errstr, *p1, *p2, *p3;

  imap_resp_reset (resp);

  if (iostream_gets (stream, resp->buf, resp->len, &errstr) < 0) {
    ocf_log (LOG_ERR, "%s: iostream_gets: %s", __func__, errstr);
    return IMAP_ERR_SYSTEM;
  }

  rtrim (resp->buf, " \t\r\n");

  /* find out what type of response we got */
  for (p1=resp->buf; isspace (*p1); p1++)
    ; /* ignore leading whitespace */
//fprintf (stderr, "S: %s\n", resp->buf);
  p2 = p1;

  if (*p1 == '*') {
    resp->type = IMAP_RESP_TYPE_UNTAGGED;
  } else if (*p1 == '+') {
    resp->type = IMAP_RESP_TYPE_COMMAND_CONTINUATION_REQUEST;
  } else {
    for (p3=info->tag; isalnum (*p1) && *p1 == *p3; p1++, p3++)
      ;

    if (p3 > info->tag && ! isalnum (*p3)) {
      resp->tag = p2;
      resp->type = IMAP_RESP_TYPE_TAGGED;
    }
  }

  for (++p1; isspace (*p1); p1++)
    ;

  /* command continuation request responses aren't used */
  if (resp->type == IMAP_RESP_TYPE_COMMAND_CONTINUATION_REQUEST)
    return IMAP_SUCCESS;

  status_response = 1;

  if (resp->type == IMAP_RESP_TYPE_TAGGED) {
    if ((strncmp (p1, "OK",  2) == 0 && (p2 = p1+2))
     || (strncmp (p1, "NO",  2) == 0 && (p2 = p1+2))
     || (strncmp (p1, "BAD", 3) == 0 && (p2 = p1+3)))
    {
      status_response = 1;
      resp->status = p1;
    } else {
      ocf_log (LOG_ERR, "%s: expected OK, NO, or BAD after tag", __func__);
      return IMAP_ERR_PROTOCOL;
    }

  } else if (resp->type == IMAP_RESP_TYPE_UNTAGGED) {
    if ((strncmp (p1, "OK",      2) == 0 && (p2 = p1+2))
     || (strncmp (p1, "NO",      2) == 0 && (p2 = p1+2))
     || (strncmp (p1, "BAD",     3) == 0 && (p2 = p1+3))
     || (strncmp (p1, "PREAUTH", 7) == 0 && (p2 = p1+7))
     || (strncmp (p1, "BYE",     3) == 0 && (p2 = p1+3)))
    {
      status_response = 1;
      resp->status = p1;
    } else {
      for (p2=p1, p3=info->command; isalnum (*p1) && *p1 == *p3; p1++, p3++)
        ;

      if (p3 > info->command && ! isalnum (*p3)) {
        resp->command = p2;
        if (*(p1 = ltrim (p1, " \t")))
          resp->extra = p1;
      } else if (*p2) {
        resp->extra = p2;
      }
    }
  }

  if (status_response) {
    /* status response may include additional response code */
    if (*(p1 = ltrim (p2, " \t")) == '[') {
      resp->code = p1;

      if ((p1 = strchr (p1, ']'))) {
        if (*(p1 = ltrim (p1, " \t")))
          resp->extra = p1;
      } else {
       //*errstr = "expected ] as delimiter of optional response code";
        ocf_log (LOG_ERR, "%s: expected ] as delimiter of optional response code",
          __func__);
        return IMAP_ERR_PROTOCOL;
      }
    } else if (*p1) {
      resp->extra = p1;
    }
  }

  return IMAP_SUCCESS;
}

int
imap_send (iostream_t *stream, imap_info_t *info, const char *fmt, ...)
{
  char *buf, *errstr, *fmt_start, *ptr;
  size_t cnt, len;
  va_list ap;

  /* generate and write tag to buffer */
  cnt = snprintf (info->buf, info->len, "A%04d ", ++info->index);

  if (cnt < 0) {
    ocf_log (LOG_ERR, "%s: snprintf: %s", __func__, strerror (errno));
    return IMAP_ERR_SYSTEM;
  }
  if (cnt > info->len) {
    ocf_log (LOG_ERR, "%s: not enough space available in output buffer",
      __func__);
    return IMAP_ERR_BUFSIZE;
  }

  info->tag = info->buf;
  buf = info->buf + cnt;
  len = info->len - cnt;

  for (fmt_start=(char*)fmt; isspace (*fmt_start); fmt_start++)
    ; /* remove leading whitespace */

  if (! *fmt_start) {
    ocf_log (LOG_ERR, "%s: command empty", __func__);
    return IMAP_ERR_PROTOCOL;
  }

  /* write command to buffer */
  va_start (ap, fmt);
  cnt = vsnprintf (buf, len, fmt_start, ap);
  va_end (ap);

  info->command = buf;

  if (cnt < 0) {
    ocf_log (LOG_ERR, "%s: vsnprintf: %s", __func__, strerror (errno));
    return IMAP_ERR_SYSTEM;
  }
  if (cnt > len) {
    ocf_log (LOG_ERR, "%s: not enough space available in output buffer",
      __func__);
    return IMAP_ERR_BUFSIZE;
  }

  /* remove trailing whitespace */
  for (ptr=buf; *ptr; ptr++)
    ;
  for (--ptr; isspace (*ptr); ptr--)
    ;

  if (((ptr - info->buf) + 3) > info->len) {
    ocf_log (LOG_ERR, "%s: not enough space available in output buffer",
      __func__);
    return IMAP_ERR_BUFSIZE;
  }

  strcpy (++ptr, "\r\n");
//fprintf (stderr, "C: %s", info->buf);
  /* write command to iostream */
  if (iostream_puts (stream, info->buf, &errstr) < 0) {
    ocf_log (LOG_ERR, "%s: iostream_puts: %s", __func__, errstr);
    return IMAP_ERR_SYSTEM;
  }

  return IMAP_SUCCESS;
}

#define BUFSIZE (4096)
#define STRNULLCMP(s1,s2,n) ((s1 == NULL) ? -1 : strncmp ((s1),(s2),(n)))

int
imap_iface_test (iface_t *iface, const char *user, const char *passwd,
  const char *ca_file, const char *ca_path, const int starttls)
{
  bool plain_auth_avail, starttls_avail;
  char *errstr;
  imap_info_t *info = NULL;
  imap_resp_t *resp = NULL;
  int state, result;
  iostream_t *stream;

  plain_auth_avail = false;
  starttls_avail = false;

  if ((stream = iostream_init (&errstr)) == NULL) {
    ocf_log (LOG_ERR, "%s: iostream_init: %s", __func__, errstr);
    return IMAP_ERR_SYSTEM;
  }
  if ((info = imap_info_alloc (BUFSIZE)) == NULL) {
    ocf_log (LOG_ERR, "%s: imap_info_alloc: %s", __func__, strerror (errno));
    goto failure;
  }
  if ((resp = imap_resp_alloc (BUFSIZE)) == NULL) {
    ocf_log (LOG_ERR, "%s: imap_resp_alloc: %s", __func__, strerror (errno));
    goto failure;
  }

  /* Connect to defined interface. */
  if (iostream_connect (stream, iface->host, iface->port, &errstr) < 0) {
    ocf_log (LOG_ERR, "%s: iostream_connect: %s", __func__, errstr);
    goto failure;
  }
  if (iface->ssl && iostream_encrypt (stream, ca_file, ca_path, &errstr) < 0) {
    ocf_log (LOG_ERR, "%s: iostream_encrypt: %s", __func__, errstr);
    goto failure;
  }

  for (state=IMAP_STAT_CONNECT, result=IMAP_SUCCESS; ; ) {

    if (imap_recv (stream, info, resp) != IMAP_SUCCESS)
      goto failure; /* error logged by imap_recv */

    if (resp->type == IMAP_RESP_TYPE_UNTAGGED
     && resp->status && strncmp (resp->status, "BYE", 3) == 0)
    {
      if (state == IMAP_STAT_LOGOUT) {
        continue;
      } else if (resp->extra) {
        ocf_log (LOG_ERR, "%s: connection terminated by server: %s",
          __func__, resp->extra);
      } else {
        ocf_log (LOG_ERR, "%s: connection terminated by server",
          __func__);
      }

    } else if (state == IMAP_STAT_CONNECT) {
      if (resp->type == IMAP_RESP_TYPE_UNTAGGED) {
        if (STRNULLCMP (resp->status, "OK", 2) == 0) {
          ocf_log (LOG_DEBUG, "%s: connected to %s%s://%s:%s/", __func__,
            iface->service, iface->ssl ? "s" : "", iface->host, iface->port);
          state = IMAP_STAT_CAPABILITY;
          if (imap_send (stream, info, "CAPABILITY") != IMAP_SUCCESS)
            goto failure;
          continue;
        }
      }
    } else if (state == IMAP_STAT_CAPABILITY) {
      if (resp->type == IMAP_RESP_TYPE_UNTAGGED) {

        if (STRNULLCMP (resp->command, "CAPABILITY", 10) == 0) {
          if (! plain_auth_avail && strstr (resp->command, "AUTH=PLAIN") != NULL) {
            ocf_log (LOG_DEBUG, "%s: plain text passwords enabled",
              __func__);
            plain_auth_avail = true;
          }
          if (! iostream_encrypted (stream) && ! starttls_avail
           && strstr (resp->command, "STARTTLS") != NULL) {
            ocf_log (LOG_DEBUG, "%s: connection can be encrypted",
              __func__);
            starttls_avail = true;
          }
        }
        continue;
      } else if (resp->type == IMAP_RESP_TYPE_TAGGED) {
        if (STRNULLCMP (resp->status, "OK", 2) == 0) {
          if (! starttls_avail) {
            ocf_log (LOG_DEBUG, "%s: connection cannot be encrypted",
              __func__);
          }
          /* We don't support password encryption yet, bail if plain text
             password aren't enabled. */
          if (! plain_auth_avail) {
            ocf_log (LOG_WARNING, "%s: plain text passwords not enabled",
              __func__);
            state = IMAP_STAT_LOGOUT;
            if (imap_send (stream, info, "LOGOUT") < 0)
              goto failure;
          } else if (starttls_avail && starttls) {
            state = IMAP_STAT_STARTTLS;
            if (imap_send (stream, info, "STARTTLS") < 0)
              goto failure;
          } else {
            state = IMAP_STAT_LOGIN;
            if (imap_send (stream, info, "LOGIN %s %s", user, passwd) < 0)
              goto failure;
          }
          continue;
        }
      }
    } else if (state == IMAP_STAT_STARTTLS) {
      if (resp->type == IMAP_RESP_TYPE_TAGGED) {
        if (STRNULLCMP (resp->status, "OK", 2) == 0) {
          /* It appears the connection can be encrypted, initiate handshaking
             and continue over an encrypted connection. */
          if (iostream_encrypt (stream, ca_file, ca_path, &errstr) < 0) {
            ocf_log (LOG_ERR, "%s: iostream_encrypt: %s", __func__,
              errstr);
            goto failure;
          }
          ocf_log (LOG_DEBUG, "%s: encrypted connection", __func__);
          state = IMAP_STAT_LOGIN;
          if (imap_send (stream, info, "LOGIN %s %s", user, passwd) < 0)
            goto failure;
          continue;
        }
      }
    } else if (state == IMAP_STAT_LOGIN) {
      if (resp->type == IMAP_RESP_TYPE_TAGGED) {
        if (STRNULLCMP (resp->status, "OK", 2) == 0) {
          ocf_log (LOG_DEBUG, "%s: logged in", __func__);
          state = IMAP_STAT_SELECT;
          if (imap_send (stream, info, "SELECT INBOX") < 0)
            goto failure;
          continue;
        }
      } else if (STRNULLCMP (resp->extra, "CAPABILITY", 10) == 0) {
        /* server is allowed to send CAPABILITY in response to LOGIN */
        continue;
      }
    } else if (state == IMAP_STAT_SELECT) {
      if (resp->type == IMAP_RESP_TYPE_UNTAGGED) {
        continue;

      } else if (resp->type == IMAP_RESP_TYPE_TAGGED) {
        if (STRNULLCMP (resp->status, "OK", 2) == 0) {
          ocf_log (LOG_DEBUG, "%s: selected INBOX", __func__);
          state = IMAP_STAT_LOGOUT;
          if (imap_send (stream, info, "LOGOUT") < 0)
            goto failure;
          continue;
        }
      }
    } else if (state == IMAP_STAT_LOGOUT) {
      /* The expected BYE response is handled above. */
      if (resp->type == IMAP_RESP_TYPE_TAGGED) {
        if (STRNULLCMP (resp->status, "OK", 2) == 0) {
          ocf_log (LOG_DEBUG, "%s: logged out", __func__);
          break;
        }
      }
    } else {
      ocf_log (LOG_ERR, "%s: unknown state, bailing", __func__);
      state = IMAP_STAT_LOGOUT;
      if (imap_send (stream, info, "LOGOUT") < 0)
        goto failure;
    }

    /* error condition, extra information might be available */
    if (resp->status && resp->extra && (strncmp (resp->status, "NO",  2) == 0 ||
                                        strncmp (resp->status, "BAD", 3) == 0))
      ocf_log (LOG_ERR, "%s: %s", __func__, resp->extra);
    else
      ocf_log (LOG_ERR, "%s: unknown error", __func__);
    goto failure_protocol;
  }

  if (0) {
failure:
    result = IMAP_ERR_SYSTEM;
  }

  if (0) {
failure_protocol:
    result = IMAP_ERR_PROTOCOL;
  }

  iostream_deinit (stream); /* also calls iostream_disconnect */
  imap_info_free (info);
  imap_resp_free (resp);

  return result;
}

#undef STRNULLCMP
#undef BUFSIZE
