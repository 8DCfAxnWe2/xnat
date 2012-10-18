#include "common.h"


int
tsocket(int type, const struct sockaddr_in *baddr)
{
  int fd = socket(AF_INET, type | SOCK_NONBLOCK, 0);
  if(fd < 0) goto onfail;

  // Enable transparent & recvorigdstaddr.
  int enable = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &enable, sizeof(int)) < 0 ||
     setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &enable, sizeof(int)) < 0)
    goto onfail;

  // Bind address.
  if(baddr != NULL && bind(fd, (const struct sockaddr*) baddr, ADDRSIZE) < 0)
    goto onfail;
  
  return fd;

 onfail:
  if(fd > 0) close(fd);
  return -1;
}
