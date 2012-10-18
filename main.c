#include "common.h"

extern struct array *route_rules;


int
run(const struct sockaddr_in *tcpbaddr, const struct sockaddr_in *udpbaddr)
{
  if(tcpbaddr == NULL || udpbaddr == NULL){ errno = EINVAL; return -1; }
  
  // TCP setup.
  int tcpfd = -1;
  if((tcpfd = tsocket(SOCK_STREAM, tcpbaddr)) < 0 || listen(tcpfd, 10) < 0){
    error("could not setup tcp default socket"); return -1;
  }
  info("TCP work on %08X:%u", FADDR(tcpbaddr));

  struct array *tcpdbplist = ary_new();
  if(tcpdbplist == NULL){ error("could not init dbpeer list"); return 1; }


  // UDP setup.
  struct udppeer *udppr = udppeer_new(udpbaddr, NULL);
  struct array *udppeers[] = {ary_new(), ary_new()};
  struct array *lpeers = udppeers[0], *rpeers = udppeers[1];
  if(udppr == NULL || lpeers == NULL || rpeers == NULL ||
     ary_append(lpeers, udppr) < 0){
    error("could not setup udp default socket");
    return -1;
  }
  info("UDP work on %08X:%u", FADDR(udpbaddr));


  // Message loop.
  fd_set rfds, wfds;
  int maxfd;
  while(1){
    FD_ZERO(&rfds); FD_ZERO(&wfds);

    // TCP, fill fdset.
    FD_SET(tcpfd, &rfds);  // Always track READ on default socket.
    maxfd = tcppeer_fillfdset(tcpdbplist, &rfds, &wfds);
    if(tcpfd > maxfd) maxfd = tcpfd;

    // UDP, fill fdset.
    int tmp = udppeer_fillfdset(udppeers, sizeof(udppeers)/sizeof(struct array*),
				&rfds, &wfds);
    if(tmp > maxfd) maxfd = tmp;

    // Select(...)
    if(select(maxfd + 1, &rfds, &wfds, NULL, NULL) < 0){
      error("select(...) failed"); break;
    }
    debug("select(...) done");

    // TCP, check event.
    // Always check listening socket for new coming con.
    if(FD_ISSET(tcpfd, &rfds)){
      struct tcpdbpeer *dbp = accept_con(tcpfd);
      if(dbp == NULL){ warn("could not accept incoming con"); }
      else if(ary_append(tcpdbplist, dbp) < 0){
	error("could not append dbpeer, con lost");
	dbp_free(&dbp);
      }else{ debug("new con(lfd: %d, rfd: %d)", dbp->l->fd, dbp->r->fd); }
    }
    tcppeer_checkevent(tcpdbplist, &rfds, &wfds);

    // UDP, check event.
    udppeer_checkevent(udppeers, sizeof(udppeers)/sizeof(struct array*),
		       &rfds, &wfds);
    udppeer_deliver(lpeers, rpeers);
  }

  // TODO: Free resources.
  return -1;
}


int
main(int argc, char **argv)
{
  struct sockaddr_in addr1, addr2;
  addr1.sin_family = AF_INET;
  addr1.sin_addr.s_addr = ntohl(0x01010101);
  addr1.sin_port = ntohs(8000);

  addr2.sin_family = AF_INET;
  addr2.sin_addr.s_addr = ntohl(0x02020202);
  addr2.sin_port = ntohs(5300);

  const char *cfgfile = "route.conf";
  //
  debug("generate route rule from config file ...");
  route_rules = genrulelist(cfgfile);
  if(route_rules == NULL) return 1;

  debug("startup message loop ...");
  int r = run(&addr1, &addr2);
  info("program quit with code %d", r);
  return r;
}
