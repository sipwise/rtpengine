#ifndef __KERNEL_H__
#define __KERNEL_H__



#include <sys/types.h>
#include <glib.h>
#include <netinet/in.h>




struct mediaproxy_target_info;



int kernel_create_table(unsigned int);
int kernel_open_table(unsigned int);

int kernel_add_stream(int, struct mediaproxy_target_info *, int);
int kernel_del_stream(int, u_int16_t);
GList *kernel_list(unsigned int);




#endif
