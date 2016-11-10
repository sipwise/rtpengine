#ifndef _GARBAGE_H_
#define _GARBAGE_H_

typedef void free_func_t(void *);

unsigned int garbage_new_thread_num(void);
void garbage_add(void *ptr, free_func_t *free_func);
void garbage_collect(unsigned int num);
void garbage_collect_all(void);

#endif
