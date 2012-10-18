#include "dns.h"


/* Buffer to store DNS NAME(global) */
char dnsnamebuf[DNSNAMEBUFLEN];


/*
  Read name in dns pkt.
 
  @pkt: dns pkt, header [ + content].
  @pktlen: length of pkt, include header.
  @start: start point to read name, when succ, it would be set as the
    next start point to process other info.
  @name: buffer to store name had been read, may be truncked, always ends with '\0'.
  @namelen: provide the length of @name.

  @Return: -1 when error, or bytes had been written to @name(include '\0').
*/
ssize_t
readdnsname(const void *pkt, size_t pktlen, size_t *start, void *name, size_t namelen)
{
  if(pkt == NULL || pktlen < sizeof(struct dnshdr) ||
     start == NULL || (*start) < sizeof(struct dnshdr) || (*start) >= pktlen ||
     name == NULL || namelen <= 1) goto invaformat;

  unsigned char *curr = ((unsigned char*) pkt) + (*start),
    *maxcurr = NULL,
    *end = ((unsigned char*) pkt) + pktlen,
    *namecurr = (unsigned char*) name,
    *nameend = ((unsigned char*) name) + namelen;
  unsigned char ctl, flag;
  unsigned short lenoroff;
  size_t counter = 0;

  while(counter++ < 100){
    // Read control field.
    if(curr + 1 > end){ trace("control field over boundary"); goto invaformat; }
    
    ctl = *curr++;
    flag = (ctl >> 6);
    lenoroff = (flag != 3) ? (ctl & 0x3F) : (((ctl & 0x3F) << 8) | *curr++);
    if(curr > maxcurr) maxcurr = curr;

    // A pointer.
    if(flag == 3){
      curr = ((unsigned char*) pkt) + lenoroff;
      continue;
    }

    // A label.
    if(flag == 0){
      // End of name?
      if(lenoroff == 0){
	*namecurr++ = 0;
	*start = maxcurr - ((unsigned char*) pkt);
	return (namecurr - ((unsigned char*) name));
      }

      // Read label.
      if(curr + lenoroff > end)	goto invaformat;
      if(namecurr + lenoroff + 1 > nameend - 1){
	trace("label overflow"); goto invaformat;
      }
      if(namecurr != (unsigned char*) name) *namecurr++ = '.';
      memcpy(namecurr, curr, lenoroff);
      namecurr += lenoroff;
      curr += lenoroff;
      continue;
    }

    // Invalid flag.
    trace("invalid control flag(%u), ctl(%u)", flag, ctl); goto invaformat;
  }// End of limited loop.
  // Got here when exceed limited loop, may be an infinate loop.

 invaformat:
  errno = EINVAL;
  return -1;
}


int
readdnsques(const void *pkt, size_t pktlen, size_t *start, struct dnsques *ques)
{
  if(pkt == NULL || pktlen == 0 || start == NULL || *start < sizeof(struct dnshdr) ||
     ques == NULL){ errno = EINVAL; return -1; }

  if(readdnsname(pkt, pktlen, start, dnsnamebuf, DNSNAMEBUFLEN) < 0){
    error("can not read the qname"); return -1;
  }
  ques->name = dnsnamebuf;

  // Check if overflow.
  size_t tmplen = (*start) + 2*2;  // See struct dnsques.
  if(tmplen > pktlen){
    error("uncomplete DNS pkt(len: %ld), expected more than %ld",
	  pktlen, tmplen);
    return -1;
  }
  
  unsigned short *curr_2 = (unsigned short*) (((unsigned char*) pkt) + (*start));
  ques->type = ntohs(*curr_2 ++);
  ques->class = ntohs(*curr_2 ++);

  *start = ((unsigned char*) curr_2) - ((unsigned char*) pkt);
  return 0;
}


int
readdnsrr(const void *pkt, size_t pktlen, size_t *start, struct dnsrr *rr)
{
  if(pkt == NULL || pktlen < sizeof(struct dnshdr) || start == NULL ||
     *start >= pktlen || rr == NULL){ errno = EINVAL; return -1; }

  if(readdnsname(pkt, pktlen, start, dnsnamebuf, DNSNAMEBUFLEN) < 0){
    error("read dns name failed"); return -1;
  }
  rr->name = dnsnamebuf;
  
  // Check if overflow.
  size_t tmplen = (*start) + 2*2 + 4 + 2;  // For how to calculate, see struct dnsrr.
  if(tmplen > pktlen){
    error("uncomplete DNS pkt(len: %ld), expected more than %ld",
	  pktlen, tmplen);
    return -1;
  }

  unsigned short *curr_2 = (unsigned short*) (((unsigned char*) pkt) + (*start));
  rr->type = ntohs(*curr_2 ++);
  rr->class = ntohs(*curr_2 ++);

  unsigned *curr_4 = (unsigned*) curr_2;
  rr->ttl = ntohl(*curr_4++);

  curr_2 = (unsigned short*) curr_4;
  rr->rdatlen = ntohs(*curr_2 ++);
  rr->rdat = curr_2;

  // Verify rdata length.
  tmplen = ((unsigned char*) curr_2) - ((unsigned char*) pkt);
  if(tmplen + rr->rdatlen > pktlen){
    error("uncomplete DNS pkt(len: %ld, curr: %ld, rdatlen: %u)",
	  pktlen, tmplen, rr->rdatlen);
    return -1;
  }

  *start = tmplen + rr->rdatlen;
  return 0;
}
