#include "tcppeer.h"


struct tcpdbpeer*
dbp_new(void)
{
  size_t totalsize = sizeof(struct tcpdbpeer) +
    (sizeof(struct tcppeer) + sizeof(struct tcpbuffer) + TCPPEER_BUF_SIZE) * 2;
  struct tcpdbpeer *dbp = (struct tcpdbpeer*) calloc(totalsize, 1);
  if(dbp == NULL) return NULL;

  unsigned char *curr = (unsigned char*) dbp;
  curr += sizeof(struct tcpdbpeer);
  struct tcppeer **ps[] = {&(dbp->l), &(dbp->r)};
  for(size_t i=0; i<sizeof(ps)/sizeof(struct tcppeer**); i++){
    struct tcppeer **i_p = ps[i];
    *i_p = (struct tcppeer*) curr;
    
    curr += sizeof(struct tcppeer);
    (*i_p)->w_buf = (struct tcpbuffer*) curr;

    curr += sizeof(struct tcpbuffer);
    (*i_p)->w_buf->dat = curr;
    (*i_p)->w_buf->size = TCPPEER_BUF_SIZE;

    curr += TCPPEER_BUF_SIZE;
  }
  return dbp;
}


void
dbp_free(struct tcpdbpeer **dbp)
{
  if(dbp == NULL || *dbp == NULL) return;
  close((*dbp)->l->fd);
  close((*dbp)->r->fd);
  free(*dbp);
  *dbp = NULL;
}


struct tcpdbpeer*
accept_con(int fd)
{
  int lfd = -1, rfd = -1;
  struct sockaddr_in src, dst, laddr;
  socklen_t srclen = ADDRSIZE;
  socklen_t dstlen = srclen, laddrlen = srclen;

  if((lfd = accept4(fd, &src, &srclen, SOCK_NONBLOCK)) < 0) return NULL;

  // Give up when got a truncated address.
  if(srclen != ADDRSIZE){
    warn("addr truncated, from %x:%u, real size %u", FADDR(&src), srclen);
    goto giveup;
  }

  // Give up when no origin dst found.
  if(getsockopt(lfd, SOL_IP, SO_ORIGINAL_DST, &dst, &dstlen) < 0 ||
     dstlen != ADDRSIZE){
    // TODO: should i use binding addr instead origdst?
    warn("no oridst found in pkt from %x:%d", FADDR(&src));
    
    // Treat binding addr of @lfd as origdst.
    dstlen = ADDRSIZE;
    if(getsockname(lfd, &dst, &dstlen) < 0 || dstlen != ADDRSIZE){
      error("getsockname(...) of l-side(fd: %d) failed", lfd);
      goto giveup;
    }
  }
  
  // Get name of listening socket @fd, to compare with @src and @dst.
  if(getsockname(fd, &laddr, &laddrlen) < 0 ||
     laddrlen != ADDRSIZE){
    error("could not fetch name of listening socket"); goto giveup;
  }
  if(src.sin_addr.s_addr == laddr.sin_addr.s_addr ||
     dst.sin_addr.s_addr == laddr.sin_addr.s_addr){
    error("either src or dst has same ip with listening socket");
    goto giveup;
  }

  // Get a route from @src to @dst.
  struct sockaddr_in nxtsrc, nxtdst;
  if(tcp_route(&src, &dst, &nxtsrc, &nxtdst) < 0){
    error("could not route from %x:%u to %x:%u", FADDR(&src), FADDR(&dst));
    goto giveup;
  }
  debug("route %x:%d ~ %x:%d as %x:%d ~ %x:%d",
	FADDR(&src), FADDR(&dst), FADDR(&nxtsrc), FADDR(&nxtdst));

  // Create a right-side socket, bind with @nxtsrc, then connect to @nxtdst.
  
  if((rfd = tsocket(SOCK_STREAM, &nxtsrc)) < 0){
    error("failed to create r-side socket");
    goto giveup;
  }
  if(connect(rfd, &nxtdst, ADDRSIZE) < 0 && errno != EINPROGRESS){
    error("failed to connect to @nxtdst"); goto giveup;
  }
  
  // Both side had been setup.
  struct tcpdbpeer *dbp = dbp_new();
  if(dbp == NULL){ error("failed to create dbpeer"); goto giveup; }
  dbp->l->fd = lfd;
  dbp->l->status = TCPPEER_UP;
  dbp->r->fd = rfd;
  dbp->r->status = TCPPEER_NREADY;
  debug("new dbpeer(lfd: %d, rfd: %d) created", dbp->l->fd, dbp->r->fd);
  return dbp;

  
 giveup:
  if(lfd != -1) close(lfd);
  if(rfd != -1) close(rfd);
  return NULL;
}


/*
 @pa: Peer had been ready to read.
 @buf: Buffer to store data read.
*/
void
tcppeer_rready(struct tcppeer *pa, struct tcpbuffer *buf)
{
  size_t freesize = buf->size - buf->datlen;
  if(freesize){
    ssize_t brecv = recv(pa->fd, buf->dat + buf->datlen, freesize, MSG_DONTWAIT);
    if(brecv < 0){
      if(errno == EAGAIN || errno == EWOULDBLOCK) return;
      error("recv from fd_%d failed", pa->fd);
      pa->status = TCPPEER_DOWN;
      return;
    }

    if(brecv == 0){
      debug("peer(fd: %d) down", pa->fd);
      pa->status = TCPPEER_DOWN;
      return;
    }

    debug("recv %ld bytes from peer(fd: %d)", brecv, pa->fd);
    buf->datlen += brecv;
    return;
  }

  debug("no free buffer while fd_%d ready to read", pa->fd);
}


/*
 @pa: Peer had been ready to write.
 @buf: Data to be sent.
*/
void
tcppeer_wready(struct tcppeer *pa, struct tcpbuffer *buf)
{
  if(pa->status == TCPPEER_UP){
    if(buf->datlen != 0){
      ssize_t bsent = send(pa->fd, buf->dat, buf->datlen, MSG_DONTWAIT);
      if(bsent < 0){
	if(errno == EAGAIN || errno == EWOULDBLOCK) return;
	error("send on fd_%d failed", pa->fd);
	pa->status = TCPPEER_DOWN;
	return;
      }

      debug("send %ld bytes on fd_%d", bsent, pa->fd);
      memcpy(buf->dat, buf->dat + bsent, buf->datlen - bsent);
      buf->datlen -= bsent;
      return;
    }

    debug("no data to send on fd_%d while ready on W", pa->fd);
    return;
  }
  
  if(pa->status & TCPPEER_NREADY){
    // Place to check if connec(...) succ, see connect(2).
    int err; socklen_t errlen = sizeof(int);
    if(getsockopt(pa->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0){
      error("failed to check if fd_%d connect(...) succ", pa->fd);
      pa->status = TCPPEER_DOWN;
      return;
    }

    if(err){
      errno = err;
      error("connect(...) failed at fd_%d", pa->fd);
      pa->status = TCPPEER_DOWN;
      return;
    }

    debug("fd_%d connect(...) succ", pa->fd);
    pa->status = TCPPEER_UP;
    return;
  }
}


int
tcppeer_fillfdset(struct array *dbplist, fd_set *rfds, fd_set *wfds)
{
  int maxfd = 0;
  
  // Decide which event to be tracked on which peer.
  size_t i = -1;
  while(++i < dbplist->_size){
    struct tcpdbpeer *i_dbp = (struct tcpdbpeer*) dbplist->_warehouse[i];
    struct tcppeer *pa = i_dbp->l, *pb = i_dbp->r;

    // Clean up closed peer, try to flush buffer before closing any open peer.
    if((pb->status & TCPPEER_DOWN) && (! (pa->status & TCPPEER_DOWN)) &&
       (pa->w_buf->datlen == 0)){
      debug("close l-peer(fd: %d, status: %d) forcely", pa->fd, pa->status);
      pa->status = TCPPEER_DOWN;
    }

    if((pa->status & TCPPEER_DOWN) && (! (pb->status & TCPPEER_DOWN)) &&
       (pb->w_buf->datlen == 0)){
      debug("close r-peer(fd: %d, status: %d) forcely", pb->fd, pb->status);
      pb->status = TCPPEER_DOWN;
    }
      
    // Remove dbpeer when both side had been shutdown.
    if((pa->status & TCPPEER_DOWN) && (pb->status && TCPPEER_DOWN)){
      debug("remove closed dbpeer(lfd: %d, rfd: %d)", pa->fd, pb->fd);
      ary_del(dbplist, i_dbp);
      dbp_free(&i_dbp);
      --i;
      continue;
    }

    // For R:
    // 1). when both TCPPEER_UP, with free buffer in other side.
    if((pa->status & TCPPEER_UP) && (pb->status & TCPPEER_UP)){
      if(pb->w_buf->datlen < pb->w_buf->size) FD_SET(pa->fd, rfds);
      if(pa->w_buf->datlen < pa->w_buf->size) FD_SET(pb->fd, rfds);
    }

    // For W:
    // 1). TCPPEER_NREADY.
    // 2). TCPPEER_UP, with not empty buffer in self side.
    if((pa->status & TCPPEER_NREADY) ||
       ((pa->status & TCPPEER_UP) && pa->w_buf->datlen != 0)) FD_SET(pa->fd, wfds);
    if((pb->status & TCPPEER_NREADY) ||
       ((pb->status & TCPPEER_UP) && pb->w_buf->datlen != 0)) FD_SET(pb->fd, wfds);

    // Update the max fd.
    unsigned tr = FD_ISSET(pa->fd, rfds), tw = FD_ISSET(pa->fd, wfds);
    debug("track l-peer(fd: %d, status: %d) on R(%d), W(%d)",
	  pa->fd, pa->status, tr, tw);
    if((tr || tw) && pa->fd > maxfd) maxfd = pa->fd;

    tr = FD_ISSET(pb->fd, rfds), tw = FD_ISSET(pb->fd, wfds);
    debug("track r-peer(fd: %d, status: %d) on R(%d), W(%d)",
	  pb->fd, pb->status, tr, tw);
    if((tr || tw) && pb->fd > maxfd) maxfd = pb->fd;
  }

  return maxfd;
}


void
tcppeer_checkevent(struct array *dbplist, fd_set *rfds, fd_set *wfds)
{
  // Check any RW fd.
  for(size_t i=0; i<dbplist->_size; i++){
    struct tcpdbpeer *i_dbp = (struct tcpdbpeer*) dbplist->_warehouse[i];
    if(FD_ISSET(i_dbp->l->fd, rfds)) tcppeer_rready(i_dbp->l, i_dbp->r->w_buf);
    if(FD_ISSET(i_dbp->l->fd, wfds)) tcppeer_wready(i_dbp->l, i_dbp->l->w_buf);

    if(FD_ISSET(i_dbp->r->fd, rfds)) tcppeer_rready(i_dbp->r, i_dbp->l->w_buf);
    if(FD_ISSET(i_dbp->r->fd, wfds)) tcppeer_wready(i_dbp->r, i_dbp->r->w_buf);
  }
}
