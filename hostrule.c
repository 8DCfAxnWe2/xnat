#include "hostrule.h"


/* Regex error buffer(global) */
#define regerrbuflen  1024
char regerrbuf[regerrbuflen];

regex_t*
reg_new(const char *expr)
{
  if(expr == NULL){ errno = EINVAL; return NULL; }

  regex_t *reg = (regex_t*) calloc(sizeof(regex_t), 1);
  if(reg == NULL) return NULL;

  int r = regcomp(reg, expr, REG_ICASE | REG_EXTENDED);
  if(r){
    regerror(r, reg, regerrbuf, regerrbuflen);
    error("compile regex failed: %s", regerrbuf);
    goto onfail;
  }
  return reg;

 onfail:
  regfree(reg);
  free(reg);
  return NULL;
}

void
reg_free(regex_t **reg)
{
  if(reg == NULL || *reg == NULL) return;

  regfree(*reg);
  free(*reg);
  *reg = NULL;
}


struct hostrule*
hostrule_new(unsigned src, unsigned dns)
{
  if(src == 0){ errno = EINVAL; return NULL; }

  struct hostrule *hr = (struct hostrule*) calloc(sizeof(struct hostrule), 1);
  if(hr == NULL) return NULL;

  hr->src = src;
  hr->dns = dns;
  
  hr->regs = ary_new();
  if(hr->regs == NULL){
    error("could not create member @regs of hostrule"); goto onfail;
  }

  hr->ips = ary_new();
  if(hr->ips == NULL){
    error("could not create member @ips of hostrule"); goto onfail;
  }
  return hr;

 onfail:
  if(hr != NULL){
    if(hr->regs != NULL) ary_free(&(hr->regs));
    if(hr->ips != NULL) ary_free(&(hr->ips));
    free(hr);
  }
  return NULL;
}

void
hostrule_free(struct hostrule **hr)
{
  if(hr == NULL || *hr == NULL) return;

  for(size_t i=0; i<(*hr)->regs->_size; i++){
    regex_t *i_reg = (regex_t*) ((*hr)->regs->_warehouse[i]);
    reg_free(&i_reg);
  }
  ary_free(&((*hr)->regs));
  free(*hr);
  *hr = NULL;
}


/*
  Parse IP from text "1.2.3.4".

  @Return: 0 when failed.
*/
unsigned
parse_ipv4(const unsigned char *data, size_t datalen, size_t *start)
{
  if(data == NULL || datalen < 7 || start == NULL || *start > datalen){
    errno = EINVAL; return 0;
  }

  unsigned int ip = 0, num = 0, numcount = 0;
  int status = -1; size_t i = *start;
  for(; i<datalen; i++){
    unsigned char c = data[i];

    if(c >= '0' && c <= '9'){
      if(status == 1) return 0;
      if(status == -1) status = 0;
      num = num * 10 + (c - '0');
      continue;
    }

    if(c == '.'){
      if(status != 0) return 0;
      if((numcount == 0 && num == 0) || num > 0xFF) return 0;
      ip = (ip << 8) | num;
      num = 0;
      if(++numcount >= 4) return 0;
      continue;
    }

    if(c == ' ' || c == '\t'){
      if(status == -1) continue;
      if(status == 0){ ++i; status = 1; break; }
      return 0;
    }

    return 0;
  }

  if(status != -1 && numcount == 3 && num < 0xFF){
    *start = i;
    return (ip << 8) | num;
  }
  return 0;
}


/*
@Return: 0 when NOT an empty string.
*/
int
isemptystr(const char *text)
{
  for(size_t i=0; i<strlen(text); i++){
    if(text[i] == ' ' || text[i] == '\t') continue;
    return 0;
  }
  return 1;
}


/*
  @Return: -1 when error, 0 when succ.
*/
int
parse_sect(const char *section, unsigned *src, unsigned *dns)
{
  size_t seclen = strlen(section), start = 0;

  unsigned ip = parse_ipv4((const unsigned char*) section, seclen, &start);
  if(! ip){ error("could not parse source address"); return -1; }
  *src = ip;

  ip = parse_ipv4((const unsigned char*) section, seclen, &start);
  if(! ip){ error("could not parse dns address"); return -1; }
  *dns = ip;

  // Check if remain empty string.
  if(isemptystr(section + start)) return 0;

  error("unexpected string after dns");
  return -1;
}


/*
 Generate rule list on config file like:

#comment line
#max line length is 1023.

#section line started with "@@", followed by two ip address:
#  translated src(the 1st one) and dns server(the 2nd one).
@@1.2.3.4  8.8.8.8

# A regex expression to select host.
.*\.google\.com

# Or an destination IP address.
210.210.210.1

# Another section starts.
@@2.3.4.5  4.4.2.2
.*\.yahoo\.com


@Return: list of struct hostrule.
*/
struct array*
genrulelist(const char *cfgfile)
{
  if(cfgfile == NULL){ errno = EINVAL; return NULL; }

  FILE *f = NULL;
  const size_t buflen = 1024;
  char buf[buflen];
  size_t i = 0;
  struct hostrule *currrule = NULL;

  // Prepare array to store host rule.
  struct array *rulelist = ary_new();
  if(rulelist == NULL){ error("could not create rule list"); return NULL; }

  // Open config file.
  f = fopen(cfgfile, "r");
  if(f == NULL){ error("could not open config file"); goto onfail; }

  while(1){
    ++i;

    // Read line.
    if(fgets(buf, buflen, f) == NULL){
      if(! errno) break; // EOF.
      error("read config file failed at line %ld", i); goto onfail;
    }

    // Fail when long line found.
    size_t i_linelen = strlen(buf);
    if(i_linelen == 0) continue;  // Empty line.
    if(i_linelen == buflen - 1){
      error("long line at %ld, max length allowed %ld", i, buflen - 1); goto onfail;
    }

    // Is a comment line?
    if(buf[0] == '#') continue;

    // Remove '\n' and '\r' at the end of line.
    if(buf[i_linelen - 1] == '\n'){
      if(i_linelen >= 2 && buf[i_linelen - 2] == '\r'){
	buf[i_linelen - 2] = 0;
	i_linelen -= 2;
      }else{
	buf[i_linelen - 1] = 0;
	--i_linelen;
      }
    }
    if(i_linelen == 0) continue; // Empty line.

    // Is a section line?
    if(buf[0] == '@' && buf[1] == '@'){
      unsigned src, dns;
      if(parse_sect(buf + 2, &src, &dns) < 0){
	error("syntax error on section(line: %ld)", i);
	goto onfail;
      }

      // Create rule for new section.
      if((currrule = hostrule_new(src, dns)) == NULL){
	error("could not create host rule(line: %ld)", i); goto onfail;
      }

      // Append new rule to list.
      if(ary_append(rulelist, currrule) < 0){
	error("could not append rule(line: %ld)", i); goto onfail;
      }
      debug("new section(src: %08X, dns: %08X) created", src, dns);
      continue;
    }

    // Any rule must followed a section line.
    if(currrule == NULL){
      error("no section for line %ld", i); goto onfail;
    }

    // Check if an IP address, if not so, treat as regex expression.
    size_t i_start = 0;
    unsigned i_ip = parse_ipv4((const unsigned char*) buf, i_linelen, &i_start);
    if(i_ip && isemptystr(buf + i_start)){
      if(ary_append(currrule->ips, (void*)(size_t) i_ip) < 0){
	error("could not append IP(line: %ld)", i); goto onfail;
      }
      debug("IP %08X added", i_ip);
      continue;
    }
    
    regex_t *i_reg = reg_new(buf);
    if(i_reg == NULL){ error("could not compile regex(line: %ld)", i); goto onfail; }
    if(ary_append(currrule->regs, i_reg) < 0){
      error("could not append compiled regex(line: %ld)", i); goto onfail;
    }
    debug("Host \"%s\" added", buf);
  }
  
  fclose(f);
  debug("got %ld section", rulelist->_size);
  return rulelist;
  

 onfail:
  for(size_t j=0; j<rulelist->_size; j++){
    struct hostrule *i_hr= (struct hostrule*) (rulelist->_warehouse[j]);
    hostrule_free(&i_hr);
  }
  ary_free(&rulelist);
  
  if(f != NULL) fclose(f);
  return NULL;  
}

