#ifndef QMERGE_H
#define QMERGE_H

#include "dns.h"

struct qmerge_key {
  char *q;
  char qtype[2];
  char *control;
};

struct qmerge {
  int active;
  struct qmerge_key key;
  struct dns_transmit dt;
  int state; /* -1 = error, 0 = need io, 1 = need get, 2 = got packet */
};

extern int qmerge_start(struct qmerge **,const char *,int,const char *,const char *,const char *,const char *);
extern void qmerge_io(struct qmerge *,iopause_fd *,struct taia *);
extern int qmerge_get(struct qmerge **,const iopause_fd *,const struct taia *);
extern void qmerge_free(struct qmerge **);

#endif /* QMERGE_H */
