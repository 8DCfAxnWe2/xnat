#ifndef _DNS_H_
#define _DNS_H_

#include "common.h"


#define DNSNAMEBUFLEN    1024

/*
 Header of DNS record.

Ref:
http://tools.ietf.org/html/rfc1035
*/
struct dnshdr {
  unsigned short id;

#if defined(__LITTLE_ENDIAN_BITFIELD)
  unsigned char rd: 1, // Recursion desired.
    tc: 1, // TrunCation.
    aa: 1, // Authoritative answer.
    opcode: 4, // QUERY(0), IQUERY(1), STATUS(2), reserved(3-15).
    qr: 1; // query(0), response(1).
#elif defined(__BIG_ENDIAN_BITFIELD)
  unsigned char qr: 1,
    opcode: 4,
    aa: 1,
    tc: 1,
    rd: 1;
#else
#error "Not impletemented type of byte order"
#endif

#if defined(__LITTLE_ENDIAN_BITFIELD)
  unsigned char rcode: 4, // no_error(0), format_error(1), server_failure(2), name_error(3), not_implemented(4), refused(5), reserved(6-15).
    z: 3, // Reserved, must be zero.
    ra: 1; // Recursion available.
#elif defined(__BIG_ENDIAN_BITFIELD)
  unsigned char ra: 1,
    z: 3,
    rcode: 4;
#else
#error "Not implemented type of byte order"
#endif

  unsigned short qd_count; // Question section.
  unsigned short an_count; // Answer section.
  unsigned short ns_count; // Authority records section.
  unsigned short ar_count; // Additional records section.
};


struct dnsques{
  const char *name;
  unsigned short type, class;
};


struct dnsrr{
  const char *name;
  unsigned short type, class;
  unsigned ttl;
  unsigned short rdatlen;
  void *rdat;
};


ssize_t
readdnsname(const void *pkt, size_t pktlen, size_t *start, void *name, size_t namelen);


int
readdnsques(const void *pkt, size_t pktlen, size_t *start, struct dnsques *ques);


int
readdnsrr(const void *pkt, size_t pktlen, size_t *start, struct dnsrr* rr);

#endif
