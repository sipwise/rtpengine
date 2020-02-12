#include "jitter_buffer.h"
#include "timerthread.h"
#include "media_socket.h"
#include "call.h"
#include "codec.h"
#include "main.h"
#include <math.h>
#include <errno.h>

#define INITIAL_PACKETS 0x1E
#define CONT_SEQ_COUNT 0x64
#define CONT_MISS_COUNT 0x0A
#define CLOCK_DRIFT_MULT 0x14


static struct timerthread jitter_buffer_thread;


void jitter_buffer_init(void) {
	ilog(LOG_INFO, "jitter_buffer_init");
	timerthread_init(&jitter_buffer_thread, timerthread_queue_run);
}

// jb is locked
static void reset_jitter_buffer(struct jitter_buffer *jb) {
	ilog(LOG_INFO, "reset_jitter_buffer");

	jb->first_send_ts  	= 0;
	jb->first_send.tv_sec 	= 0;
	jb->first_send.tv_usec 	= 0;
	jb->first_seq     	= 0;
	jb->rtptime_delta 	= 0;
	jb->buffer_len    	= 0;
	jb->cont_frames		= 0;
	jb->cont_miss		= 0;
	jb->next_exp_seq  	= 0;
	jb->clock_rate    	= 0;
	jb->payload_type  	= 0;
	jb->drift_mult_factor   = 0;
	jb->buf_decremented     = 0;
	jb->clock_drift_val     = 0;

	jb->num_resets++;

	//disable jitter buffer in case of more than 2 resets
	if(jb->num_resets > 2 && jb->call)
		jb->disabled = 1;
}

static int get_clock_rate(struct media_packet *mp, int payload_type) {
	const struct rtp_payload_type *rtp_pt = NULL;
	struct jitter_buffer *jb = mp->stream->jb;
	int clock_rate = 0;

	if(jb->clock_rate && jb->payload_type == payload_type)
		return jb->clock_rate;

	struct codec_handler *transcoder = codec_handler_get(mp->media, payload_type);
	if(transcoder) {
		if(transcoder->source_pt.payload_type == payload_type)
			rtp_pt = &transcoder->source_pt;
		if(transcoder->dest_pt.payload_type == payload_type)
			rtp_pt = &transcoder->dest_pt;
	}

	if(rtp_pt) {
		clock_rate = jb->clock_rate = rtp_pt->clock_rate;
		jb->payload_type = payload_type;
	}
	else
		ilog(LOG_DEBUG, "clock_rate not present payload_type = %d", payload_type);

	return clock_rate;
}

static struct jb_packet* get_jb_packet(struct media_packet *mp, const str *s) {
	char *buf = malloc(s->len + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM);
	if (!buf) {
		ilog(LOG_ERROR, "Failed to allocate memory: %s", strerror(errno));
		return NULL;
	}

	struct jb_packet *p = g_slice_alloc0(sizeof(*p));

	p->buf = buf;
	p->mp = *mp;
	obj_hold(p->mp.sfd);

	str_init_len(&p->mp.raw, buf + RTP_BUFFER_HEAD_ROOM, s->len);
	memcpy(p->mp.raw.s, s->s, s->len);

	if(rtp_payload(&p->mp.rtp, &p->mp.payload, &p->mp.raw)) {
		jb_packet_free(&p);
		return NULL;
	}

	return p;
}

// jb is locked
static void check_buffered_packets(struct jitter_buffer *jb) {
	if (g_tree_nnodes(jb->ttq.entries) >= (2* rtpe_config.jb_length)) {
		ilog(LOG_DEBUG, "Jitter reset due to buffer overflow");
		reset_jitter_buffer(jb);
	}
}

// jb is locked
static int queue_packet(struct media_packet *mp, struct jb_packet *p) {
	struct jitter_buffer *jb = mp->stream->jb;
	unsigned long ts = ntohl(mp->rtp->timestamp);
	int payload_type =  (mp->rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(mp, payload_type);

	if(!clockrate || !jb->first_send.tv_sec) {
		ilog(LOG_DEBUG, "Jitter reset due to clockrate");
		reset_jitter_buffer(jb);
		return 1;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	int seq_diff = ntohs(mp->rtp->seq_num) - jb->first_seq;
	if(!jb->rtptime_delta && seq_diff) {
		jb->rtptime_delta = ts_diff/seq_diff;
	}
	p->ttq_entry.when = jb->first_send;
	long long ts_diff_us =
		(long long) (ts_diff + (jb->rtptime_delta * jb->buffer_len))* 1000000 / clockrate;

	ts_diff_us += (jb->clock_drift_val * seq_diff); 

	if(jb->buf_decremented) {
		ts_diff_us += 5000; //add 5ms delta when 2 packets are scheduled around same time
		jb->buf_decremented = 0;
	}
	timeval_add_usec(&p->ttq_entry.when, ts_diff_us);

	ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);

	if (ts_diff_us > 3000000) { // more than three second, can't be right
		jb->first_send.tv_sec = 0;
		jb->rtptime_delta = 0;
	}

	timerthread_queue_push(&jb->ttq, &p->ttq_entry);

	return 0;
}

static void handle_clock_drift(struct media_packet *mp) {
	ilog(LOG_DEBUG, "handle_clock_drift");
	struct jitter_buffer *jb = mp->stream->jb;
	int seq_diff = ntohs(mp->rtp->seq_num) - jb->first_seq;

	int mult_factor = pow(2, jb->drift_mult_factor);

	if(seq_diff < (mult_factor * CLOCK_DRIFT_MULT))
		return;

	unsigned long ts = ntohl(mp->rtp->timestamp);
	int payload_type =  (mp->rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(mp, payload_type);
	if(!clockrate) {
		return;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	long long ts_diff_us =
		(long long) (ts_diff)* 1000000 / clockrate;
	struct timeval to_send = jb->first_send;
	timeval_add_usec(&to_send, ts_diff_us);
	long long time_diff = timeval_diff(&rtpe_now, &to_send);

	jb->clock_drift_val = time_diff/seq_diff;
	jb->drift_mult_factor++;
}

int buffer_packet(struct media_packet *mp, const str *s) {
	struct jb_packet *p = NULL;
	int ret = 1; // must call stream_packet

	mp->stream = mp->sfd->stream;
	mp->media = mp->stream->media;
	mp->call = mp->sfd->call;
	struct call *call = mp->call;

	rwlock_lock_r(&call->master_lock);

	struct jitter_buffer *jb = mp->stream->jb;
	if (!jb || jb->disabled)
		goto end;

	ilog(LOG_DEBUG, "Handling JB packet on: %s:%d", sockaddr_print_buf(&mp->stream->endpoint.address),
			mp->stream->endpoint.port);

	p = get_jb_packet(mp, s);
	if (!p)
		goto end;

	mp = &p->mp;

	int payload_type = (mp->rtp->m_pt & 0x7f);

	mutex_lock(&jb->lock);

	if(jb->clock_rate && jb->payload_type != payload_type) { //reset in case of payload change
		jb->first_send.tv_sec = 0;
		jb->rtptime_delta = 0;
	}

	if (jb->first_send.tv_sec) {
		if(rtpe_config.jb_clock_drift)
			handle_clock_drift(mp);
		ret = queue_packet(mp,p);
	}
	else {
		// store data from first packet and use for successive packets and queue the first packet
		unsigned long ts = ntohl(mp->rtp->timestamp);
		int payload_type =  (mp->rtp->m_pt & 0x7f);
		int clockrate = get_clock_rate(mp, payload_type);
		if(!clockrate){
			jb->initial_pkts++;
			if(jb->initial_pkts > INITIAL_PACKETS) {      //Ignore initial Payload Type 126 if any
				reset_jitter_buffer(jb);
			}
			goto end_unlock;
		}

		p->ttq_entry.when = jb->first_send = rtpe_now;
		jb->first_send_ts = ts;
		jb->first_seq = ntohs(mp->rtp->seq_num);
	}

	// packet consumed?
	if (ret == 0)
		p = NULL;

	check_buffered_packets(jb);

end_unlock:
	mutex_unlock(&jb->lock);

end:
	rwlock_unlock_r(&call->master_lock);
	if (p)
		jb_packet_free(&p);
	return ret;
}

static void increment_buffer(struct jitter_buffer *jb) {
	if(jb->buffer_len < rtpe_config.jb_length)
		jb->buffer_len++;
}

static void decrement_buffer(struct jitter_buffer *jb) {
	if(jb->buffer_len > 0) {
		jb->buffer_len--;
		jb->buf_decremented = 1;
	}
}

static void set_jitter_values(struct media_packet *mp) {
	struct jitter_buffer *jb = mp->stream->jb;
	if(!jb || !mp->rtp)
		return;
	int curr_seq = ntohs(mp->rtp->seq_num); 
	if(jb->next_exp_seq) {
		mutex_lock(&jb->lock);
		if(curr_seq > jb->next_exp_seq) {
			ilog(LOG_DEBUG, "missing seq exp seq =%d, received seq= %d", jb->next_exp_seq, curr_seq);
			increment_buffer(jb);
			jb->cont_frames = 0;
			jb->cont_miss++;
		}
		else if(curr_seq < jb->next_exp_seq) { //Might be duplicate or sequence already crossed
			jb->cont_frames = 0;
			jb->cont_miss++;
		}
		else {
			jb->cont_frames++;
			jb->cont_miss = 0;
			if(jb->cont_frames >= CONT_SEQ_COUNT) {
				decrement_buffer(jb);
				jb->cont_frames = 0;
				ilog(LOG_DEBUG, "Received continous frames Buffer len=%d", jb->buffer_len);
			}
		}

		if(jb->cont_miss >= CONT_MISS_COUNT)
			reset_jitter_buffer(jb);
		mutex_unlock(&jb->lock);
	}
	if(curr_seq >= jb->next_exp_seq)
		jb->next_exp_seq = curr_seq + 1;
}

static void __jb_send_later(struct timerthread_queue *ttq, void *p) {
	struct jb_packet *cp = p;
	set_jitter_values(&cp->mp);
	play_buffered(p);
};
// jb and call are locked
static void __jb_send_now(struct timerthread_queue *ttq, void *p) {
	struct jitter_buffer *jb = (void *) ttq;

	mutex_unlock(&jb->lock);
	rwlock_unlock_r(&jb->call->master_lock);

	__jb_send_later(ttq, p);

	rwlock_lock_r(&jb->call->master_lock);
	mutex_lock(&jb->lock);
};
static void __jb_free(void *p) {
	struct jitter_buffer *jb = p;
	jitter_buffer_free(&jb);
}
void __jb_packet_free(void *p) {
	struct jb_packet *jbp = p;
	jb_packet_free(&jbp);
}

void jitter_buffer_loop(void *p) {
	ilog(LOG_DEBUG, "jitter_buffer_loop");
	timerthread_run(&jitter_buffer_thread);
}

struct jitter_buffer *jitter_buffer_new(struct call *c) {
	ilog(LOG_DEBUG, "creating jitter_buffer");

	struct jitter_buffer *jb = timerthread_queue_new("jitter_buffer", sizeof(*jb),
			&jitter_buffer_thread,
			__jb_send_now,
			__jb_send_later,
			__jb_free, __jb_packet_free);
	mutex_init(&jb->lock);
	jb->call = obj_get(c);
	return jb;
}

void jitter_buffer_free(struct jitter_buffer **jbp) {
	if (!jbp || !*jbp)
		return;

	ilog(LOG_DEBUG, "freeing jitter_buffer");

	mutex_destroy(&(*jbp)->lock);
	if ((*jbp)->call)
		obj_put((*jbp)->call);
}

void jb_packet_free(struct jb_packet **jbp) {
	if (!jbp || !*jbp)
		return;

	free((*jbp)->buf);
	if ((*jbp)->mp.sfd)
		obj_put((*jbp)->mp.sfd);
	g_slice_free1(sizeof(**jbp), *jbp);
	*jbp = NULL;
}
