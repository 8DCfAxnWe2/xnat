#ifndef _UDPPEER_H_
#define _UDPPEER_H_

#include "common.h"


#define UDPPEER_BUF_SIZE   0xFFFF
#define UDPPEER_TIMEOUT    300   // seconds.


struct udpbuffer{
  struct sockaddr_in src, dst;
  void *dat;
  size_t datlen, size;
};


/*
 UDP peer.

@lact: last active time, get from time(...).
@baddr: real binding address, get from getsockname(...).
@addr: address of origin source on l-side. [r-side only].

@routes: list of route info about all out pkts, use to lookup back-path
  when recv pkt. [r-side only].

@r_buf: A real buffer store pkt recv.
@w_buf: Just a pointer, reference to some r_buf on other side.
*/
struct udppeer{
  int socket;
  time_t lact;
  struct sockaddr_in baddr, addr;
  
  struct array *routes;

  struct udpbuffer *r_buf;
  struct udpbuffer *w_buf;
};


/*
 Route info.

@addr: the origin dst.
@taddr: the transform dst.
*/
struct routeinfo{
  struct sockaddr_in addr, taddr;
};


ssize_t
socket_recvmsg(int fd,
	       void *buf, size_t buflen, struct sockaddr_in *src,
	       int *hasorigdst, struct sockaddr_in *origdst);

struct routeinfo*
routeinfo_new(const struct sockaddr_in *addr, const struct sockaddr_in *taddr);

void
routeinfo_free(struct routeinfo **info);

struct udppeer*
udppeer_new(const struct sockaddr_in *baddr, const struct sockaddr_in *addr);

void
udppeer_free(struct udppeer **pr);

void
udppeer_rready(struct udppeer *pr);

void
udppeer_wready(struct udppeer *pr);

int
addrouteinfo(struct array *routes,
	     const struct sockaddr_in *addr,
	     const struct sockaddr_in *taddr);

int
getrouteinfo(const struct array *routes,
	     const struct sockaddr_in *taddr,
	     struct sockaddr_in *addr);

struct udppeer*
udppeer_find(const struct array *peers,
	     const struct sockaddr_in *baddr, const struct sockaddr_in *addr);

void
udppeer_deliver(struct array *lpeers, struct array *rpeers);

int
udppeer_fillfdset(struct array **peers, size_t size, fd_set *rfds, fd_set *wfds);

void
udppeer_checkevent(struct array **peers, size_t size, fd_set *rfds, fd_set *wfds);

void
udppeer_deliver(struct array *lpeers, struct array *rpeers);


#endif
