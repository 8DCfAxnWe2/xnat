#include "udppeer.h"


/*
@hasorigdst: set to NULL when don't want origin dst info.
*/
ssize_t
socket_recvmsg(int fd,
	       void *buf, size_t buflen, struct sockaddr_in *src,
	       int *hasorigdst, struct sockaddr_in *origdst)
{
  if(buf == NULL || buflen == 0 || src == NULL ||
     (hasorigdst != NULL && origdst == NULL)){ errno = EINVAL; return -1; }
  
  struct msghdr msg;
  msg.msg_name = src;
  msg.msg_namelen = ADDRSIZE;

  struct iovec vec;
  vec.iov_base = buf;
  vec.iov_len = buflen;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  const size_t ctlbuflen = 0xFF;
  unsigned char ctlbuf[ctlbuflen];
  msg.msg_control = ctlbuf;
  msg.msg_controllen = ctlbuflen;

  msg.msg_flags = 0;

  ssize_t brecv = recvmsg(fd, &msg, MSG_DONTWAIT);
  if(brecv <= 0) return brecv;
  if(msg.msg_namelen != sizeof(struct sockaddr_in)){
    error("unexpected len of msg_name %d on fd_%d", msg.msg_namelen, fd);
    return -1;
  }

  debug("recv %ld bytes on fd_%d, src %x:%u", brecv, fd, FADDR(src));
  if(hasorigdst == NULL) return brecv;

  // Check if origin dst exists.
  *hasorigdst = 0;
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  while(cmsg != NULL){
    if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR){
      if(cmsg->cmsg_len - sizeof(struct cmsghdr) != ADDRSIZE){
	error("unexpected len of origin dst, cmsg len %ld", cmsg->cmsg_len);
	return -1;
      }

      *hasorigdst = 1;
      memcpy(origdst, CMSG_DATA(cmsg), ADDRSIZE);
      break;
    }
    
    // Loop.
    cmsg = CMSG_NXTHDR(&msg, cmsg);
  }

  return brecv;
}


struct routeinfo*
routeinfo_new(const struct sockaddr_in *addr, const struct sockaddr_in *taddr)
{
  if(addr == NULL || taddr == NULL){errno = EINVAL; return NULL; }
  
  struct routeinfo *info = (struct routeinfo*) calloc(sizeof(struct routeinfo), 1);
  if(info == NULL) return NULL;

  memcpy(&(info->addr), addr, ADDRSIZE);
  memcpy(&(info->taddr), taddr, ADDRSIZE);
  return info;
}


void
routeinfo_free(struct routeinfo **info)
{
  if(info == NULL || *info == NULL) return;

  free(*info);
  *info = NULL;
}


/*
  Create new udppeer, without init member @routes and @w_buf.
*/
struct udppeer*
udppeer_new(const struct sockaddr_in *baddr, const struct sockaddr_in *addr)
{
  if(baddr == NULL){ errno = EINVAL; return NULL; }

  struct udppeer *pr = NULL;
  // Create socket with transparent and recvorigindst options, then bind on @baddr.
  int fd = tsocket(SOCK_DGRAM, baddr);
  if(fd < 0) return NULL;

  // Create udp peer, DO NOT initialize @routes and @w_buf.
  pr = (struct udppeer*)
    calloc(sizeof(struct udppeer) + sizeof(struct udpbuffer) + UDPPEER_BUF_SIZE, 1);
  if(pr == NULL){ error("create udppeer failed"); goto onfail; }

  pr->socket = fd;
  pr->lact = time(NULL);
  pr->r_buf = (struct udpbuffer*) (((unsigned char*) pr) + sizeof(struct udppeer));
  pr->r_buf->dat = ((unsigned char*) (pr->r_buf)) + sizeof(struct udpbuffer);
  pr->r_buf->size = UDPPEER_BUF_SIZE;

  // Get binded address via getsockname, useful when port is zero.
  socklen_t baddrlen = ADDRSIZE;
  if(getsockname(fd, &(pr->baddr), &baddrlen) < 0 || baddrlen != ADDRSIZE){
    error("get sock name on fd_%d failed", fd); goto onfail;
  }

  if(addr != NULL) memcpy(&(pr->addr), addr, ADDRSIZE);
  return pr;

 onfail:
  close(fd);
  if(pr != NULL) free(pr);  
  return NULL;
}


void
udppeer_free(struct udppeer **pr)
{
  if(pr == NULL || *pr == NULL) return;

  close((*pr)->socket);
  if((*pr)->routes != NULL){
    for(size_t i=0; i<(*pr)->routes->_size; i++){
      struct routeinfo *i_info = (struct routeinfo*) (*pr)->routes->_warehouse[i];
      routeinfo_free(&i_info);
    }
    ary_free(&((*pr)->routes));
  }

  free(*pr);
  *pr = NULL;
}


/* Called when udppeer recv READ event. */
void
udppeer_rready(struct udppeer *pr)
{
  // No action when buffer not empty.
  if(pr->r_buf->datlen) return;

  int hasorigdst;
  ssize_t brecv = socket_recvmsg(pr->socket, pr->r_buf->dat, pr->r_buf->size,
				 &(pr->r_buf->src), &hasorigdst, &(pr->r_buf->dst));
  if(brecv < 0){
    if(errno == EAGAIN || errno == EWOULDBLOCK) return;
    error("read udppeer(fd: %d) failed", pr->socket);
    return;
  }

  // Use current @baddr as @dst when no origin dst found.
  if(! hasorigdst) memcpy(&(pr->r_buf->dst), &(pr->baddr), ADDRSIZE);

  // Accept it.
  pr->r_buf->datlen = brecv;
  return;
}


/*
  Write data on @w_buf to @dst.
*/
void
udppeer_wready(struct udppeer *pr)
{
  if(pr->w_buf == NULL) return;

  ssize_t bsent = sendto(pr->socket, pr->w_buf->dat, pr->w_buf->datlen,
			 MSG_DONTWAIT, &(pr->w_buf->dst), ADDRSIZE);
  if(bsent < 0){
    if(errno == EAGAIN || errno == EWOULDBLOCK) return;
    error("send pkt(src: %x:%u, dst: %x:%u) on fd_%d failed, data lost",
	  FADDR(&(pr->w_buf->src)), FADDR(&(pr->w_buf->dst)), pr->socket);
    pr->w_buf->datlen = 0;
    pr->w_buf = NULL;
    return;
  }
  debug("pkt(dst: %x:%u, fd: %d, size: %ld, sent: %ld) sent",
	FADDR(&(pr->w_buf->dst)), pr->socket, pr->w_buf->datlen, bsent);

  // Warn when bytes sent not expected.
  if(bsent != pr->w_buf->datlen)
    warn("data lost at pkt(dst: %x:%u, fd: %d, size: %ld, sent: %ld) sent",
	 FADDR(&(pr->w_buf->dst)), pr->socket, pr->w_buf->datlen, bsent);

  pr->w_buf->datlen = 0;
  pr->w_buf = NULL;
  return;
}

int
addrouteinfo(struct array *routes,
	     const struct sockaddr_in *addr,
	     const struct sockaddr_in *taddr)
{
  if(routes == NULL || addr == NULL || taddr == NULL){ errno = EINVAL; return -1; }

  // Check if same record exists.
  for(size_t i=0; i<routes->_size; i++){
    struct routeinfo *i_info = (struct routeinfo*) routes->_warehouse[i];
    if(ISSAMEADDR(&(i_info->addr), addr) && ISSAMEADDR(&(i_info->taddr), taddr))
      return 0;  // record exists.
  }

  struct routeinfo *info = routeinfo_new(addr, taddr);
  if(info == NULL) return -1;

  if(ary_append(routes, info) < 0) return -1;
  return 0;
}


int
getrouteinfo(const struct array *routes,
	     const struct sockaddr_in *taddr,
	     struct sockaddr_in *addr)
{
  if(routes == NULL || taddr == NULL || addr == NULL){ errno = EINVAL; return -1; }

  for(size_t i=0; i<routes->_size; i++){
    struct routeinfo *i_info = (struct routeinfo*) routes->_warehouse[i];
    if(ISSAMEADDR(&(i_info->taddr), taddr)){
      memcpy(addr, &(i_info->addr), ADDRSIZE);
      return 0;
    }
  }
  return -1;
}


/*
 Find peer on condition.
*/
struct udppeer*
udppeer_find(const struct array *peers,
	     const struct sockaddr_in *baddr, const struct sockaddr_in *addr)
{
  if(peers == NULL || baddr == NULL){ errno = EINVAL; return NULL; }

  for(size_t i=0; i<peers->_size; i++){
    struct udppeer *i_pr = (struct udppeer*) peers->_warehouse[i];
    if(ISSAMEADDR(&(i_pr->baddr), baddr)){
      if(addr == NULL || ISSAMEADDR(&(i_pr->addr), addr)) return i_pr;	
    }
  }
  return NULL;
}


void
udppeer_deliver(struct array *lpeers, struct array *rpeers)
{
  struct sockaddr_in nxtsrc, nxtdst;

  // For each peer on l-side, process whose r-buf not empty.
  for(size_t i=0; i<lpeers->_size; i++){
    struct udppeer *i_lp = (struct udppeer*) lpeers->_warehouse[i];
    if(! (i_lp->r_buf->datlen)) continue;
    
    // Get route, drop pkt when failed.
    if(udp_route(i_lp->r_buf->dat, i_lp->r_buf->datlen, &(i_lp->r_buf->src),
		 &(i_lp->r_buf->dst), &nxtsrc, &nxtdst) < 0){
      error("drop pkt(src: %x:%u, dst: %x:%u) on fd_%d when route failed",
	    FADDR(&(i_lp->r_buf->src)), FADDR(&(i_lp->r_buf->dst)), i_lp->socket);
      i_lp->r_buf->datlen = 0;
      continue;
    }
    debug("udp_route(src: %x:%u, dst: %x:%u, nsrc: %x:%u, ndst: %x:%u",
	  FADDR(&(i_lp->r_buf->src)), FADDR(&(i_lp->r_buf->dst)),
	  FADDR(&nxtsrc), FADDR(&nxtdst));

    // Find a r-side peer to send pkt, create a new one when non existed.
    struct udppeer *i_rp = udppeer_find(rpeers, &nxtsrc, &(i_lp->r_buf->src));
    if(i_rp == NULL){
      // Create a new r-side peer to send the pkt, drop it when failed.
      if((i_rp = udppeer_new(&nxtsrc, &(i_lp->r_buf->src))) == NULL ||
	 (i_rp->routes = ary_new()) == NULL ||
	 ary_append(rpeers, i_rp) < 0){
	error("creat r-side peer for pkt(src: %x:%u, dst: %x:%u) on fd_%d failed",
	      FADDR(&(i_lp->r_buf->src)), FADDR(&(i_lp->r_buf->dst)), i_lp->socket);
	i_lp->r_buf->datlen = 0;
	// free resource.
	if(i_rp != NULL){
	  if(i_rp->routes != NULL) ary_free(&i_rp->routes);
	  ary_del(rpeers, i_rp);
	  udppeer_free(&i_rp);
	}
	continue;
      }
      debug("new r-side peer(baddr: %x:%u, addr: %x:%u) added",
	    FADDR(&(i_rp->baddr)), FADDR(&(i_rp->addr)));
    }else if(i_rp->w_buf != NULL) continue;

    // Bind w_buf on r-side to r_buf on l-side,
    // then save route info in @routes at r-side.
    if(addrouteinfo(i_rp->routes, &(i_lp->r_buf->dst), &nxtdst) < 0){
      error("failed to add route info %x:%u ~ %x:%u on fd_%d, data lost",
	    FADDR(&(i_lp->r_buf->dst)), FADDR(&nxtdst), i_rp->socket);
      i_lp->r_buf->datlen = 0;
      continue;
    }
    
    // Change dst of pkt.
    memcpy(&(i_lp->r_buf->dst), &nxtdst, ADDRSIZE);
    i_rp->w_buf = i_lp->r_buf;
  }

  // For each peer on r-side, process whose r_buf not empty.
  for(size_t i=0; i<rpeers->_size; i++){
    struct udppeer *i_rp = (struct udppeer*) rpeers->_warehouse[i];
    if(! (i_rp->r_buf->datlen)) continue;

    // Get route info from @routes.
    if(getrouteinfo(i_rp->routes, &(i_rp->r_buf->src), &nxtsrc) < 0){
      warn("drop pkt(src: %x:%u) on fd_%d when get route info failed",
	   FADDR(&(i_rp->r_buf->src)), i_rp->socket);
      i_rp->r_buf->datlen = 0;
      continue;
    }

    // Find a l-side peer to send the pkt, create a new one when non existed.
    struct udppeer *i_lp = udppeer_find(lpeers, &nxtsrc, NULL);
    if(i_lp == NULL){
      if((i_lp = udppeer_new(&nxtsrc, NULL)) == NULL ||
	 ary_append(lpeers, i_lp) < 0){
	warn("drop pkt(src: %x:%u) on fd_%d when create l-peer(baddr: %x:%u) failed",
	   FADDR(&(i_rp->r_buf->src)), i_rp->socket, FADDR(&nxtsrc));
	i_rp->r_buf->datlen = 0;
	// Free resource.
	if(i_lp != NULL){
	  ary_del(lpeers, i_lp);
	  udppeer_free(&i_lp);
	}
	continue;
      }
      debug("new l-side peer(baddr: %x:%u) added", FADDR(&nxtsrc));
    }else if(i_lp->w_buf != NULL) continue;

    // Change dst of pkt.
    memcpy(&(i_rp->r_buf->dst), &(i_rp->addr), ADDRSIZE);
    i_lp->w_buf = i_rp->r_buf;

    // Hook DNS response.
    udp_route2(i_rp->r_buf->dat, i_rp->r_buf->datlen,
	       &(i_rp->r_buf->src), &(i_rp->r_buf->dst));
  }
}


/*
 Track peer on status of r_buf and w_buf, remove peer when
 1). NOT the first one.(usually live forever).
 2). NO WRITE track
 3). timeout.

@return: max fd to be tracked.
*/
int
udppeer_fillfdset(struct array **peers, size_t size, fd_set *rfds, fd_set *wfds)
{
  int maxfd = 0;
  time_t currtime = time(NULL);
  
  for(size_t i=0; i<size; i++){
    size_t j = -1;
    while(++j < peers[i]->_size){
      struct udppeer *ij_pr = (struct udppeer*) peers[i]->_warehouse[j];
      int ij_fd = ij_pr->socket, tr = 0, tw = 0;

      // Track READ when r_buf is empty.
      if(! (ij_pr->r_buf->datlen)){
	FD_SET(ij_fd, rfds);
	tr = 1;
      }

      // Track WRITE when w_buf not NULL.
      if(ij_pr->w_buf != NULL){
	FD_SET(ij_fd, wfds);
	tw = 1;
      }

      // Remove timeout peer.
      if((i+j != 0) && (! tw) && (currtime - ij_pr->lact > UDPPEER_TIMEOUT)){
	debug("remove fd_%d when timeout", ij_pr->socket);
	FD_CLR(ij_pr->socket, rfds); // make sure not track anymore.
	ary_del(peers[i], ij_pr);
	udppeer_free(&ij_pr);
	--j;
      }

      if(tr || tw){
	if(ij_fd > maxfd) maxfd = ij_fd;
	debug("track fd_%d on R(%d), W(%d)", ij_fd, tr, tw);
      }
    }
  }

  return maxfd;
}


void
udppeer_checkevent(struct array **peers, size_t size, fd_set *rfds, fd_set *wfds)
{
  // Invoke RW event handler, then update last active time.
  for(size_t i=0; i<size; i++){
    for(size_t j=0; j<peers[i]->_size; j++){
      struct udppeer *ij_pr = (struct udppeer*) peers[i]->_warehouse[j];
      if(FD_ISSET(ij_pr->socket, rfds)){
	udppeer_rready(ij_pr);
	ij_pr->lact = time(NULL);
      }
      
      if(FD_ISSET(ij_pr->socket, wfds)){
	udppeer_wready(ij_pr);
	ij_pr->lact = time(NULL);
      }
    }
  }
}

