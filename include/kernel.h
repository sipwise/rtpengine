#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <sys/types.h>
#include <glib.h>
#include <netinet/in.h>

#include "containers.h"
#include "auxlib.h"
#include "socket.h"

#include "nft_rtpengine.h"

#define UNINIT_IDX ((unsigned int) -1)

struct rtpengine_target_info;
struct rtpengine_destination_info;
struct re_address;
struct rtpengine_ssrc_stats;
struct uring_req;

struct kernel_interface {
	unsigned int table;
	int fd;
	bool is_open;
	bool is_wanted;
	bool use_player;
};
extern struct kernel_interface kernel;


struct kernel_ring_buf {
	int eventfd;
	void *buf[2];
	struct rtpengine_buf_slot *slots[2];
	struct rtpengine_buf_metadata *metadata[2];
	struct rtpengine_ring_buf_shm *shm[2];
	atomic_t *buf_idx;

	// stats
	atomic_t errors;
	atomic_t read_preempt;
	atomic_t write_preempt;
	atomic_t slots_full;
	atomic_t buf_full;
};


bool kernel_setup_table(unsigned int);
bool kernel_create_table(unsigned int);
bool kernel_delete_table(unsigned int);
bool kernel_init_table(void);
void kernel_shutdown_table(void);

void *kernel_shm_alloc(size_t s);
void *kernel_shm_alloc0(size_t s);

bool kernel_add_stream(struct rtpengine_command_add_target *);
void kernel_add_destination(struct rtpengine_command_destination *);

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


extern unsigned int kernel_poller_start_idx;
extern unsigned int kernel_pollers_num;

extern unsigned int kernel_sender_start_idx;
extern unsigned int kernel_senders_num;
extern unsigned int kernel_sender_cur_idx;

extern struct kernel_ring_buf *kernel_ring_bufs;
extern struct poller_thread *kernel_poller_threads;

void kernel_init_pollers(unsigned int);
void kernel_poller_loop(void *);
void kernel_cleanup_pollers(void);

void kernel_thread_init(void);
ssize_t kernel_sendmsg(socket_t *s, struct msghdr *msg, const endpoint_t *dst,
			struct sockaddr_storage *src, struct uring_req *req);

#endif
