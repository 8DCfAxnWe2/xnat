#ifndef _ROUTE_H_
#define _ROUTE_H_

#include "common.h"


int
route_default(const struct sockaddr_in *src, const struct sockaddr_in *dst,
	      struct sockaddr_in *nxtsrc, struct sockaddr_in *nxtdst,
	      const char *qname);

int
tcp_route(const struct sockaddr_in *src, const struct sockaddr_in *dst,
	  struct sockaddr_in *nxtsrc, struct sockaddr_in *nxtdst);

int
udp_route(const void *data, size_t datalen,
	  const struct sockaddr_in *src, const struct sockaddr_in *dst,
	  struct sockaddr_in *nxtsrc, struct sockaddr_in *nxtdst);

void
udp_route2(const void *data, size_t datalen,
	   const struct sockaddr_in *src, const struct sockaddr_in *dst);

int
updateroute(const char *name, unsigned ip);

#endif
