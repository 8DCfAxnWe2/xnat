#ifndef _TCPPEER_H_
#define _TCPPEER_H_

#include "common.h"


/*
  Peer status bits.

Description:
  1). connecting      -> PEER_NREADY
  2). connection made -> PEER_UP
  3). connection lost -> PEER_DOWN
*/
#define TCPPEER_NREADY  0x1
#define TCPPEER_UP      0x2
#define TCPPEER_DOWN    0x4


#define TCPPEER_BUF_SIZE   20480

struct tcpbuffer{
  void *dat;
  size_t datlen, size;
};


struct tcppeer{
  int fd;
  unsigned status;
  struct tcpbuffer *w_buf;
};


struct tcpdbpeer{
  struct tcppeer *l, *r;
};


struct tcpdbpeer*
dbp_new(void);

void
dbp_free(struct tcpdbpeer **dbp);

struct tcpdbpeer*
accept_con(int fd);

void
tcppeer_rready(struct tcppeer *pa, struct tcpbuffer *buf);

void
tcppeer_wready(struct tcppeer *pa, struct tcpbuffer *buf);

int
tcppeer_fillfdset(struct array *dbplist, fd_set *rfds, fd_set *wfds);

void
tcppeer_checkevent(struct array *dbplist, fd_set *rfds, fd_set *wfds);

#endif

