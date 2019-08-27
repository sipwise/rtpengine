#ifndef _JITTER_BUFFER_H_
#define _JITTER_BUFFER_H_

#include "media_socket.h"
#include "codec.h"

struct packet_handler_ctx;
struct codec_packet;
struct media_packet;

struct jb_packet {
	endpoint_t fsin; // source address of received packet
	struct stream_fd *sfd;
	struct timeval tv; // timestamp when packet was received
	int buffered;
};

struct jitter_buffer {
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
	unsigned int            cont_buff_err;
	int            		buffer_len;
	int                     clock_drift_val;
	int                     clock_drift_enable; //flag for buffer overflow underflow
	int                     buf_decremented;
	struct codec_packet 	*p;
	struct call             *call;
};

void jitter_buffer_init(int min, int max);

int buffer_packet(struct media_packet *mp, str *s);

int set_jitter_values(struct media_packet *mp);

#endif
