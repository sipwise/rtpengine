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
struct re_address;
struct rtpengine_ssrc_stats;

struct kernel_interface {
	unsigned int table;
	int fd;
	bool is_open;
	bool is_wanted;
	bool use_player;
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

bool kernel_init_player(int num_media, int num_sessions);
unsigned int kernel_get_packet_stream(void);
bool kernel_add_stream_packet(unsigned int, const char *, size_t, unsigned long ms, uint32_t ts, uint32_t dur);
unsigned int kernel_start_stream_player(struct rtpengine_play_stream_info *);
bool kernel_stop_stream_player(unsigned int idx);
bool kernel_free_packet_stream(unsigned int);

#endif
