#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <sys/types.h>
#include <glib.h>
#include <netinet/in.h>

#include "containers.h"
#include "auxlib.h"

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
	bool is_open;
	bool is_wanted;
};
extern struct kernel_interface kernel;



bool kernel_setup_table(unsigned int);
bool kernel_init_table(void);
void kernel_shutdown_table(void);

void kernel_add_stream(struct rtpengine_target_info *);
void kernel_add_destination(struct rtpengine_destination_info *);
bool kernel_del_stream(struct rtpengine_command_del_target *);

unsigned int kernel_add_call(const char *id);
void kernel_del_call(unsigned int);

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id);

void kernel_send_rtcp(struct rtpengine_send_packet_info *info, const char *buf, size_t len);



#endif
