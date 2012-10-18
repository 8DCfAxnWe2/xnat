#include "array.h"


ssize_t ary_size(const struct array *ary)
{
  if(ary == NULL){
    errno = EINVAL;
    return -1;
  }

  return ary->_size;
}


int ary_ele(const struct array *ary, size_t idx, void **dat)
{
  if(ary == NULL || idx >= ary->_size || dat == NULL){
    errno = EINVAL;
    return -1;
  }

  *dat = ary->_warehouse[idx];
  return 0;
}


int ary_append(struct array *ary, void *data)
{
  if(ary->_capa == ary->_size){
    size_t newcapa = ary->_size * 2;
    size_t totalsize = newcapa * sizeof(void*);
    void *buf = malloc(totalsize);
    if(buf == NULL){
      return -1;
    }
    memset(buf, 0, totalsize);
    memcpy(buf, ary->_warehouse, ary->_size * sizeof(void*));
    free(ary->_warehouse);
    ary->_warehouse = buf;
    ary->_capa = newcapa;
  }

  ary->_warehouse[ary->_size++] = data;
  return 0;
}


struct array* ary_new(void)
{
  struct array *ary = (struct array*) malloc(sizeof(struct array));
  if(ary == NULL){
    return NULL;
  }
  memset(ary, 0, sizeof(struct array));

  // Initalize an empty warehouse.
  ary->_capa = 3; // TODO:
  void *buf = malloc(ary->_capa * sizeof(void*));
  if(buf == NULL){
    free(ary);
    return NULL;
  }
  memset(buf, 0, ary->_capa * sizeof(void*));
  ary->_warehouse = buf;
  return ary;
}


void ary_free(struct array **ary)
{
  if(ary == NULL || *ary == NULL)
    return;

  if((*ary)->_warehouse != NULL){
    free((*ary)->_warehouse);
  }

  free(*ary);
  *ary = NULL;
}


void ary_del(struct array *ary, void *todel)
{
  if(ary == NULL){
    return;
  }

  for(size_t i=0; i<ary->_size; i++){
    if(ary->_warehouse[i] == todel){
      if(i+1 < ary->_size){
	memcpy(&(ary->_warehouse[i]), &(ary->_warehouse[i+1]), (ary->_size - (i+1)) * sizeof(void*));
      }
      ary->_size --;
      break;
    }
  }
}


