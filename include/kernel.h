#ifndef __KERNEL_H__
#define __KERNEL_H__



#include <sys/types.h>
#include <glib.h>
#include <netinet/in.h>
#include "xt_RTPENGINE.h"




#define UNINIT_IDX ((unsigned int) -1)




struct rtpengine_target_info;
struct rtpengine_destination_info;
struct re_address;
struct rtpengine_ssrc_stats;



struct kernel_interface {
	unsigned int table;
	int fd;
	int is_open;
	int is_wanted;
};
extern struct kernel_interface kernel;



int kernel_setup_table(unsigned int);

int kernel_add_stream(struct rtpengine_target_info *);
int kernel_add_destination(struct rtpengine_destination_info *);
int kernel_del_stream(const struct re_address *);
GList *kernel_list(void);
int kernel_update_stats(const struct re_address *a, struct rtpengine_stats_info *out);

unsigned int kernel_add_call(const char *id);
int kernel_del_call(unsigned int);

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id);




#endif
