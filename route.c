#include "route.h"

// List of struct hostrule, see hostrule.h
struct array *route_rules = NULL;


int
route_default(const struct sockaddr_in *src, const struct sockaddr_in *dst,
	      struct sockaddr_in *nxtsrc, struct sockaddr_in *nxtdst,
	      const char *qname)
{
  // Default route.
  nxtsrc->sin_family = AF_INET;
  nxtsrc->sin_addr.s_addr = ntohl(0x01020304);
  nxtsrc->sin_port = 0;

  nxtdst->sin_family = AF_INET;
  nxtdst->sin_addr.s_addr = dst->sin_addr.s_addr;
  nxtdst->sin_port = dst->sin_port;

  int ipmatch = 0;
  for(size_t i=0; i<route_rules->_size; i++){
    struct hostrule *i_hr = (struct hostrule*) route_rules->_warehouse[i];
    for(size_t j=0; j<i_hr->ips->_size; j++){
      unsigned ij_ip = (size_t) (i_hr->ips->_warehouse[j]);
      if(ij_ip != ntohl(dst->sin_addr.s_addr)) continue;
      // Match.
      info("rule on section(src: %08X, dns: %08X) match [IP]", i_hr->src, i_hr->dns);
      nxtsrc->sin_addr.s_addr = ntohl(i_hr->src);
      ipmatch = 1; break;
    }

    if(ipmatch) break;
  }

  if(qname == NULL) return 0;
  // Route again when @qname not NULL.
  for(size_t i=0; i<route_rules->_size; i++){
    struct hostrule *i_hr = (struct hostrule*) route_rules->_warehouse[i];
    for(size_t j=0; j<i_hr->regs->_size; j++){
      regex_t *ij_reg = (regex_t*) (i_hr->regs->_warehouse[j]);
      if(regexec(ij_reg, qname, 0, NULL, 0)) continue;
      // Match.
      info("rule on section(src: %08X, dns: %08X) match [HOST]",
	   i_hr->src, i_hr->dns);
      nxtsrc->sin_addr.s_addr = ntohl(i_hr->src);
      nxtdst->sin_addr.s_addr = ntohl(i_hr->dns);
      return 0;
    }
  }
  return 0;
}


/*
  @Return: 0 when succ, or -1 when fail.
*/
int
tcp_route(const struct sockaddr_in *src, const struct sockaddr_in *dst,
	  struct sockaddr_in *nxtsrc, struct sockaddr_in *nxtdst)
{
  if(src == NULL || dst == NULL || nxtsrc == NULL || nxtdst == NULL){
    errno = EINVAL; return -1;
  }

  return route_default(src, dst, nxtsrc, nxtdst, NULL);
}


/*
 Route udp packet.
*/
int
udp_route(const void *data, size_t datalen,
	  const struct sockaddr_in *src, const struct sockaddr_in *dst,
	  struct sockaddr_in *nxtsrc, struct sockaddr_in *nxtdst)
{
  if(data == NULL || datalen == 0 || src == NULL || dst == NULL ||
     nxtsrc == NULL || nxtdst == NULL){ errno = EINVAL; return -1; }

  // Go route without QNAME when not a DNS pkt.
  if(ntohs(dst->sin_port) != 53) goto passit;

  // Now, treat it as a DNS pkt, mark as failed when process error.
  struct dnshdr *dns;
  if(datalen < sizeof(struct dnshdr)){ warn("too short of DNS pkt"); goto passit; }

  // Verify status of pkt.
  dns = (struct dnshdr*) data;
  if(dns->opcode != 0 || dns->qr != 0){
    warn("unexpected status of DNS pkt"); goto passit;
  }
  // TODO: support multi-qname.
  if(ntohs(dns->qd_count) != 1){
    warn("unsupported question count %u", ntohs(dns->qd_count)); goto passit;
  }

  // Read question section.
  size_t start = sizeof(struct dnshdr);
  struct dnsques ques;
  if(readdnsques(data, datalen, &start, &ques) < 0){
    error("can not read question section"); return -1;
  }
  return route_default(src, dst, nxtsrc, nxtdst, ques.name);

 passit:
  return route_default(src, dst, nxtsrc, nxtdst, NULL);
}


/*
 Called when pkt deliver from r to l(response pkt).
*/
void
udp_route2(const void *data, size_t datalen,
	   const struct sockaddr_in *src, const struct sockaddr_in *dst)
{
  if(data == NULL || datalen == 0 || datalen < sizeof(struct dnshdr) ||
     src == NULL || dst == NULL) return;

  // Only care DNS Response.
  if(ntohs(src->sin_port) != 53) return;

  struct dnshdr *dns = (struct dnshdr*) data;
  unsigned short qdlen = ntohs(dns->qd_count),
    anlen = ntohs(dns->an_count),
    nslen = ntohs(dns->ns_count),
    arlen = ntohs(dns->ar_count);
  debug("got DNS RES(src: %08X, qd: %u, an: %u, ns: %u, ar: %u)",
	ntohl(src->sin_addr.s_addr), qdlen, anlen, nslen, arlen);

  // Question section.
  char qname[DNSNAMEBUFLEN], cname[DNSNAMEBUFLEN];
  qname[0] = 0; cname[0] = 0;
  size_t start = sizeof(struct dnshdr);
  struct dnsques ques;
  for(size_t i=0; i<qdlen; i++){
    if(readdnsques(data, datalen, &start, &ques) < 0){
      error("read dns question %ld failed", i); return;
    }
    info("Question %ld: \"%s\", type(%u), class(%u)",
	 i, ques.name, ques.type, ques.class);
    // TODO: fix me, support multi-qname.
    strncpy(qname, ques.name, DNSNAMEBUFLEN - 1);
  }
  
  // Answer, Authority records, and Additional records section.
  struct dnsrr rr;
  const char *descs[] = {"Answer", "Authority records", "Additional records"};
  size_t lens[] = {anlen, nslen, arlen};
  for(size_t i=0; i<sizeof(descs)/sizeof(const char*); i++){
    for(size_t j=0; j<lens[i]; j++){
      // Read a dns resource record.
      if(readdnsrr(data, datalen, &start, &rr) < 0){
	error("read %s section %ld failed", descs[i], j); return;
      }
      info("%s %ld: \"%s\", type(%u), class(%u), ttl(%u), rdatlen(%u)",
	   descs[i], j, rr.name, rr.type, rr.class, rr.ttl, rr.rdatlen);

      // Just IN class.
      if(rr.class != 1) continue;

      // A type.
      if(rr.type == 1){
	if(rr.rdatlen != 4){  // IPv4.
	  warn("unexpected rdatalen in A record(name: \"%s\", rdatlen: %u)",
	       rr.name, rr.rdatlen);
	  continue;
	}
	unsigned ij_ip = ntohl(*((unsigned*) rr.rdat));

	// TODO: fixe me, support multi-qname.
	if(strncmp(rr.name, qname, DNSNAMEBUFLEN) == 0 ||
	   strncmp(rr.name, cname, DNSNAMEBUFLEN) == 0){
	  if(updateroute(qname, ij_ip) < 0){ warn("update route failed"); }
	}else warn("A record \"%s\" ~ %08X info lost", rr.name, ij_ip);
	continue;
      }// else: not A type.

      // CNAME type.
      if(rr.type == 5){
	// TODO: fixe me, support multi-qname.
	size_t tmpstart = ((unsigned char*) rr.rdat) - ((unsigned char*) data);
	if(readdnsname(data, datalen, &tmpstart, cname, DNSNAMEBUFLEN - 1) < 0){
	  warn("could not read CNAME");
	  cname[0] = 0;
	}
	continue;
      }// else: not CNAME type.

    } // end of single section.
  } // end of all sections.
}


/*
 Find regex who match @name, then add @ip.
*/
int
updateroute(const char *name, unsigned ip)
{
  for(size_t i=0; i<route_rules->_size; i++){
    struct hostrule *i_hr = (struct hostrule*) route_rules->_warehouse[i];
    for(size_t j=0; j<i_hr->regs->_size; j++){
      regex_t *j_reg = (regex_t*) (i_hr->regs->_warehouse[j]);
      if(regexec(j_reg, name, 0, NULL, 0)) continue;

      // Regex match, check if same ip exists before adding.
      for(size_t k=0; k<i_hr->ips->_size; k++){
	unsigned ijk_ip = (size_t) (i_hr->ips->_warehouse[k]);
	if(ijk_ip == ip) return 0; // Same ip found.
      }

      // No same ip found, add it.
      if(ary_append(i_hr->ips, (void*) (size_t) ip) < 0){
	error("could not update route for \"%s\" ~ %08X", name, ip);
	return -1;
      }
      info("new route \"%s\" ~ %08X added", name, ip);
      return 0;
    }
  }

  // No regex match.
  return 0;
}
