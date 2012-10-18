#ifndef _HOSTRULE_H_
#define _HOSTRULE_H_

#include "common.h"


/*
@dns: should treat as NULL when zero.
@regs: list of compiled regex_t to check if host name matches.
@ips: list of ipv4 that match.
*/
struct hostrule{
  unsigned src, dns;
  struct array *regs, *ips;
};


regex_t*
reg_new(const char *expr);

void
reg_free(regex_t **reg);

struct hostrule*
hostrule_new(unsigned src, unsigned dns);

void
hostrule_free(struct hostrule **hr);

unsigned
parse_ipv4(const unsigned char *data, size_t datalen, size_t *start);

int
isemptystr(const char *text);

int
parse_sect(const char *section, unsigned *src, unsigned *dns);

struct array*
genrulelist(const char *cfgfile);

#endif
