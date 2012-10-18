#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <regex.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <asm/byteorder.h>
#include <linux/netfilter_ipv4.h>

#include "array.h"
#include "dns.h"
#include "udppeer.h"
#include "tcppeer.h"
#include "hostrule.h"
#include "route.h"


//#define trace(...) {fprintf(stdout, "[TRACE] ");fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");}
#define trace(...) {}
//#define debug(...) {fprintf(stdout, "[DEBUG] ");fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");}
#define debug(...) {}
#define info(...) {fprintf(stdout, "[INFO] ");fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");}
#define warn(...) {fprintf(stdout, "[WARN] ");fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");}
#define error(...) {fprintf(stderr, "[ERROR] ");fprintf(stderr, __VA_ARGS__);fprintf(stderr, " (%d) ", errno);perror(NULL);}



#define ADDRSIZE  sizeof(struct sockaddr_in)
#define FADDR(addr)   ntohl((addr)->sin_addr.s_addr),ntohs((addr)->sin_port)
#define ISSAMEADDR(a1,a2)  ((a1)->sin_addr.s_addr == (a2)->sin_addr.s_addr && \
			    ((a1)->sin_port == 0 || (a2)->sin_port == 0 || \
			     (a1)->sin_port == (a2)->sin_port))


int
tsocket(int type, const struct sockaddr_in *baddr);

#endif
