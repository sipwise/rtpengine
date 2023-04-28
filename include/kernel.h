#ifndef __KERNEL_H__
#define __KERNEL_H__



#include <sys/types.h>
#include <glib.h>
#include <netinet/in.h>
#include "xt_RTPENGINE.h"




#define UNINIT_IDX ((unsigned int) -1)




struct rtpengine_target_info;
struct rtpengine_destination_info;
struct rtpengine_send_packet_info;
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
int kernel_del_stream_stats(struct rtpengine_command_del_target_stats *);
GList *kernel_list(void);
int kernel_update_stats(struct rtpengine_command_stats *);

unsigned int kernel_add_call(const char *id);
int kernel_del_call(unsigned int);

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id);

int kernel_send_rtcp(struct rtpengine_send_packet_info *info, const char *buf, size_t len);



#endif
