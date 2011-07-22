/* system includes */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/* includes */
#include "iface.h"
#include "utils.h"

iface_t *
iface_create (const char *service, const char *host, const char *port,
              const char *ssl)
{
  iface_t *iface;

  if ((iface = malloc0 (sizeof (iface_t)))) {

    if (ssl && *ssl == 'y')
      iface->ssl = true;
    else
      iface->ssl = false;

    if (service && (iface->service = strdup (service)) == NULL)
      goto failure;
    if (host && (iface->host = strdup (host)) == NULL)
      goto failure;
    if (port && (iface->port = strdup (port)) == NULL)
      goto failure;
  }

  return iface;

failure:
  iface_free (iface);
  return NULL;
}

iface_t *
iface_duplicate (iface_t *iface)
{
  iface_t *newiface;

  if ((newiface = malloc (sizeof (iface_t))) == NULL)
    goto failure;
  if (iface->service && (newiface->service = strdup (iface->service)) == NULL)
    goto failure;
  if (iface->host && (newiface->host = strdup (iface->host)) == NULL)
    goto failure;
  if (iface->port && (newiface->port = strdup (iface->port)) == NULL)
    goto failure;
  newiface->ssl = iface->ssl;

  return newiface;

failure:
  iface_free (newiface);
  return NULL;
}

void
iface_free (iface_t *iface)
{
  if (iface) {
    if (iface->service)
      free (iface->service);
    if (iface->host)
      free (iface->host);
    if (iface->port)
      free (iface->port);
    free (iface);
  }

  return;
}

#define isscheme(c) (((c) >= 'a' && (c) <= 'z') \
                  || ((c) >= '0' && (c) <= '9') \
                  || ((c) >= 'A' && (c) <= 'Z') \
                  ||  (c) == '=' || (c) == '-'  \
                  ||  (c) == '-')

#define ishost(c) (((c) >= 'a' && (c) <= 'z') \
                || ((c) >= '0' && (c) <= '9') \
                || ((c) >= 'A' && (c) <= 'Z') \
                ||  (c) == '.')

iface_t *
iface_from_uri (const char *uri, char **errstr)
{
  char *p1, *p2;
  iface_t *iface;
  size_t len;

  if ((iface = malloc0 (sizeof (iface_t))) == NULL) {
   *errstr = strerror (errno);
    return NULL;
  }

  for (p1=(char*)uri; isspace (*p1); p1++)
    ; /* ignore leading white space */

  if (! isalpha (*p1)) {
   *errstr = "invalid URI: scheme does not start with alphabetic character";
    iface_free (iface);
    return NULL;
  }

  for (p2=p1; isscheme (*p1); p1++)
    ;

  /* scheme is plain scheme + s if ssl encrypted */
  if (*(--p1) == 's') {
    iface->ssl = true;
    len = (size_t) (p1 - p2);
  } else {
    iface->ssl = false;
    len = (size_t) (p1 - p2) + 1;
  }

  if (len < 1) {
   *errstr = "invalid URI: scheme is empty";
    iface_free (iface);
    return NULL;
  }

  if ((iface->service = strndup (p2, len)) == NULL) {
   *errstr = strerror (errno);
    iface_free (iface);
    return NULL;
  }

  if (strncmp ((++p1), "://", 3) != 0) {
   *errstr = "invalid URI: expected :// after scheme";
    goto failure;
  }

  for (p1+=3, p2=p1; ishost (*p1); p1++)
    ;

  if (p1 == p2) {
    iface->host = NULL;
  } else if ((iface->host = strndup (p2, (size_t) (p1 - p2))) == NULL) {
   *errstr = strerror (errno);
    goto failure;
  }

  if (*p1 == ':') {
    for (p2=++p1; isdigit (*p1); p1++)
      ;

    if (p1 == p2) {
      iface->port = NULL;
    } else if ((iface->port = strndup (p2, (size_t) (p1 - p2))) == NULL) {
     *errstr = strerror (errno);
      goto failure;
    }
  }

  if (*p1 != '/' || *p1 != '\0' || ! isspace (*p1)) {
   *errstr = "invalid URI: URI not properly terminated";
  }

  return iface;

failure:
  iface_free (iface);
  return NULL;
}

iface_list_t *
iface_list_create (iface_list_t *list, iface_t *iface)
{
  iface_list_t *cur, *next;

  if ((next = malloc0 (sizeof (iface_list_t)))) {
    next->iface = iface;

    if (list) {
      for (cur=list; cur->next; cur=cur->next)
        ;
      cur->next = next;
    }
  }

  return next;
}

void
iface_list_free (iface_list_t *list, int recursive)
{
  iface_list_t *cur, *next;

  for (cur=list; cur; ) {
    next = cur->next;
    iface_free (cur->iface);

    if (! recursive)
      break;

    cur = next;
  }

  return;
}

iface_list_t *
iface_list_from_uris (const char *str, char **errstr)
{
  iface_t *iface;
  iface_list_t *root, *cur;
  char *p;

  root = NULL;

  if (str) {
    for (p=(char*)str; *p; ) {
      for (; isspace (*p); p++)
        ; /* ignore leading whitespace */

      if (*p) {
        if ((iface = iface_from_uri (p, errstr)) == NULL) {
          goto failure;
        }
        if ((cur = iface_list_create (root, iface)) == NULL) {
         *errstr = strerror (errno);
          goto failure;
        }

        if (root == NULL)
          root = cur;
      }

      for (; *p && isspace (*p) == 0; p++)
        ;
    }
  }

  return root;

failure:
  if (root)
    iface_list_free (root, 1);
  return NULL;
}

iface_list_t *
iface_list_exclude (iface_list_t *list, iface_list_t *exclude)
{
#define ARRAYLEN (4)
  // IMPLEMENT
  // 1. loop through exclude list
  // 2. expand interfaces
  // 3. create array of ifaces that are to be exclude
  // 4. create new list
  // 5. loop through original and copy to new list, but skip if in array of
  //    interfaces that are to be excluded!

  bool skip;
  iface_t **newia, **ia, **ip;
  int ian=ARRAYLEN, iac=0;

  if ((ia = malloc ((sizeof (iface_t *) * ian))) == NULL)
    return NULL;

 *ia = NULL;
  iface_t *e, *i;
  iface_list_t *el=NULL, *il=NULL, *root=NULL, *cur=NULL;

  struct addrinfo hints;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo *ail1=NULL, *ail2=NULL, *ai1=NULL, *ai2=NULL;
  struct sockaddr_in *ip41, *ip42;
  struct sockaddr_in6 *ip61, *ip62;

  for (el=exclude; el; el=el->next) {
    e = el->iface;

    /* now walk list of interfaces to include */
    for (il=list; il; il=il->next) {
      i = il->iface;
      skip = false;
  fprintf (stderr, "%s (%d)\n", __func__, __LINE__);
      for (ip=ia; *ip && ! skip; ip++) {
        if (*ip == i)
          skip = true;
      }
  fprintf (stderr, "%s (%d)\n", __func__, __LINE__);
      if (skip)
        continue;
      if (e->service && i->service && strcmp (i->service, e->service) != 0)
        continue;
      if (i->ssl != e->ssl)
        continue;
      if (e->port && i->port && strcmp (e->port, i->port) != 0)
        continue;

      /* Exclude host matches everything if it's NULL, so services can be
         excluded completely. It also matches if hosts match. */
      if (e->host && strcmp (e->host,i->host) == 0) {
        /* In case hosts didn't match, the exclude host might resolve to the
           same address as the include host uses, or the same IPv6 addresses
           might be presented in another notation. */
        if (getaddrinfo (e->host, NULL, &hints, &ail1) != 0)
          goto failure;
        if (getaddrinfo (i->host, NULL, &hints, &ail2) != 0)
          goto failure;
        for (ai1=ail1, skip=true; ai1 && skip; ai1=ai1->ai_next) {
          for (ai2=ail2; ai2 && skip; ai2=ai2->ai_next) {
            if (ai1->ai_family != ai2->ai_family)
              continue;
            if (ai1->ai_family == AF_INET) { // IPv4
              ip41 = (struct sockaddr_in *)ai1->ai_addr;
              ip42 = (struct sockaddr_in *)ai2->ai_addr;
              if (memcmp ((void*)&ip41->sin_addr,
                          (void*)&ip42->sin_addr,
                          sizeof (struct in_addr)) == 0)
                skip = false;
            } else { // IPv6
              ip61 = (struct sockaddr_in6 *)ai1->ai_addr;
              ip62 = (struct sockaddr_in6 *)ai2->ai_addr;
              if (memcmp ((void*)&ip61->sin6_addr,
                          (void*)&ip62->sin6_addr,
                          sizeof(struct in6_addr)) == 0)
                skip = false;
            }
          }
        }

        freeaddrinfo (ail1); ail1=NULL;
        freeaddrinfo (ail2); ail2=NULL;

        if (skip)
          continue;
      }

      if (iac == ian) {
        ian *= 2;
        if ((newia = realloc (ia, ian)) == NULL)
          goto failure;
        ia = newia;
      }
     *(ia+iac++) = i;
     *(ia+iac) = NULL;
    }
  }
  fprintf (stderr, "%s (%d)\n", __func__, __LINE__);
  /* create new list of interfaces */
  for (il=list; il; il=il->next) {
    // 1. check if in array of interfaces to exclude
    // 2. if not... clone interface and add to new list!
    for (ip=ia, skip=false; *ip && ! skip; ip++) {
      if (*ip == il->iface)
        skip = true;
    }

    if (skip)
      continue;

    if ((i = iface_duplicate (il->iface)) == NULL) {
      goto failure;
    }
    if ((cur = iface_list_create (root, i)) == NULL) {
      iface_free (i);
      goto failure;
    }

    if (root == NULL)
      root = cur;
  }

  if (ia)
    free (ia);

  return root;

failure:
  if (ail1)
    freeaddrinfo (ail1);
  if (ail2)
    freeaddrinfo (ail2);
  if (ia)
    free (ia);
  return NULL;
#undef ARRAYLEN
}
