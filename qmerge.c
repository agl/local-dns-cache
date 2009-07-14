#include "qmerge.h"
#include "byte.h"
#include "log.h"
#include "maxclient.h"

#define QMERGE_MAX (MAXUDP+MAXTCP)
struct qmerge inprogress[QMERGE_MAX];

static
int qmerge_key_init(struct qmerge_key *qmk, const char *q, const char qtype[2],
    const char *control)
{
  if (!dns_domain_copy(&qmk->q, q)) return 0;
  byte_copy(qmk->qtype, 2, qtype);
  if (!dns_domain_copy(&qmk->control, control)) return 0;
  return 1;
}

static
int qmerge_key_equal(struct qmerge_key *a, struct qmerge_key *b)
{
  return
    byte_equal(a->qtype, 2, b->qtype) &&
    dns_domain_equal(a->q, b->q) &&
    dns_domain_equal(a->control, b->control);
}

static
void qmerge_key_free(struct qmerge_key *qmk)
{
  dns_domain_free(&qmk->q);
  dns_domain_free(&qmk->control);
}

void qmerge_free(struct qmerge **x)
{
  struct qmerge *qm;

  qm = *x;
  *x = 0;
  if (!qm || !qm->active) return;

  qm->active--;
  if (!qm->active) {
    qmerge_key_free(&qm->key);
    dns_transmit_free(&qm->dt);
  }
}

int qmerge_start(struct qmerge **qm, const char servers[64], int flagrecursive,
    const char *q, const char qtype[2], const char localip[4],
    const char *control)
{
  struct qmerge_key k;
  int i;
  int r;

  qmerge_free(qm);

  byte_zero(&k, sizeof k);
  if (!qmerge_key_init(&k, q, qtype, control)) return -1;
  for (i = 0; i < QMERGE_MAX; i++) {
    if (!inprogress[i].active) continue;
    if (!qmerge_key_equal(&k, &inprogress[i].key)) continue;
    log_tx_piggyback(q, qtype, control);
    inprogress[i].active++;
    *qm = &inprogress[i];
    qmerge_key_free(&k);
    return 0;
  }

  for (i = 0; i < QMERGE_MAX; i++)
    if (!inprogress[i].active)
      break;
  if (i == QMERGE_MAX) return -1;

  log_tx(q, qtype, control, servers, 0);
  r = dns_transmit_start(&inprogress[i].dt, servers, flagrecursive, q, qtype, localip);
  if (r == -1) { qmerge_key_free(&k); return -1; }
  inprogress[i].active++;
  inprogress[i].state = 0;
  qmerge_key_free(&inprogress[i].key);
  byte_copy(&inprogress[i].key, sizeof k, &k);
  *qm = &inprogress[i];
  return 0;
}

void qmerge_io(struct qmerge *qm, iopause_fd *io, struct taia *deadline)
{
  if (qm->state == 0) {
    dns_transmit_io(&qm->dt, io, deadline);
    qm->state = 1;
  }
  else {
    io->fd = -1;
    io->events = 0;
  }
}

int qmerge_get(struct qmerge **x, const iopause_fd *io, const struct taia *when)
{
  int r;
  struct qmerge *qm;

  qm = *x;
  if (qm->state == -1) return -1; /* previous error */
  if (qm->state == 0) return 0; /* no packet */
  if (qm->state == 2) return 1; /* already got packet */

  r = dns_transmit_get(&qm->dt, io, when);
  if (r == -1) { qm->state = -1; return -1; } /* error */
  if (r == 0) { qm->state = 0; return 0; } /* must wait for i/o */
  if (r == 1) { qm->state = 2; return 1; } /* got packet */
  return -1; /* bug */
}
