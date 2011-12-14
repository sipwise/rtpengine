#ifndef __KERNEL_H__
#define __KERNEL_H__



#include <sys/types.h>
#include <glib.h>




struct ip_port {
	int			family;
	union {
		u_int32_t	ipv4;
		unsigned char	ipv6[16];
	};
	u_int16_t               port;
};

struct kernel_stream {
	u_int16_t               local_port;
	struct ip_port          src;
	struct ip_port          dest;
	struct ip_port          mirror;
	unsigned char		tos;
};




int kernel_create_table(unsigned int);
int kernel_open_table(unsigned int);

int kernel_add_stream(int, struct kernel_stream *, int);
int kernel_del_stream(int, u_int16_t);
GList *kernel_list(unsigned int);




#endif
