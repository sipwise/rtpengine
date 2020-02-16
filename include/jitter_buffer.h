#ifndef _JITTER_BUFFER_H_
#define _JITTER_BUFFER_H_

#include "auxlib.h"
#include "socket.h"
#include "timerthread.h"
#include "media_socket.h"
//#include "codec.h"
//
//struct packet_handler_ctx;
struct jb_packet;
struct media_packet;
//
struct jb_packet {
	struct timerthread_queue_entry ttq_entry;
	char *buf;
	struct media_packet mp;
};

struct jitter_buffer {
	struct timerthread_queue ttq;
	mutex_t        		lock;
	unsigned long 		first_send_ts;
	struct timeval 		first_send;
	unsigned int            first_seq;
	unsigned int            rtptime_delta;
	unsigned int            next_exp_seq;
	unsigned int            cont_frames;
	unsigned int            cont_miss;
	unsigned int            clock_rate;
	unsigned int            payload_type;
	unsigned int            num_resets;
	unsigned int            initial_pkts;
	unsigned int            drift_mult_factor;
	int            		buffer_len;
	int                     clock_drift_val;
	int                     buf_decremented;
	struct call             *call;
	int			disabled;
};

void jitter_buffer_init(void);

struct jitter_buffer *jitter_buffer_new(struct call *);
void jitter_buffer_free(struct jitter_buffer **);

int buffer_packet(struct media_packet *mp, const str *s);
void jb_packet_free(struct jb_packet **jbp);

void jitter_buffer_loop(void *p);

INLINE void jb_put(struct jitter_buffer **jb) {
	if (!*jb)
		return;
	obj_put(&(*jb)->ttq.tt_obj);
	*jb = NULL;
}

#endif
