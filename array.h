#ifndef _ARRAY_H_
#define _ARRAY_H_

#include "common.h"


struct array{
  size_t _size;
  
  void **_warehouse;
  size_t _capa;  // Capacity of warehouse.
};


ssize_t ary_size(const struct array *ary);

int ary_ele(const struct array *ary, size_t idx, void **dat);

int ary_append(struct array *ary, void *data);

struct array* ary_new(void);

void ary_free(struct array **ary);

void ary_del(struct array *ary, void *todel);


#endif
