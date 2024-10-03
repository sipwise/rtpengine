#include "jitter_buffer.h"

#include <math.h>
#include <errno.h>

#include "timerthread.h"
#include "media_socket.h"
#include "call.h"
#include "codec.h"
#include "main.h"
#include "rtcplib.h"
#include "bufferpool.h"

#define INITIAL_PACKETS 0x1E
#define CONT_SEQ_COUNT 0x1F4
#define CONT_MISS_COUNT 0x0A
#define CLOCK_DRIFT_MULT 0x28
#define DELAY_FACTOR 0x64
#define COMFORT_NOISE 0x0D


static struct timerthread jitter_buffer_thread;


void jitter_buffer_init(void) {
	//ilog(LOG_DEBUG, "jitter_buffer_init");
	unsigned int num_threads = rtpe_config.jb_length > 0 ? rtpe_config.media_num_threads : 0;
	timerthread_init(&jitter_buffer_thread, num_threads, timerthread_queue_run);
}

void jitter_buffer_init_free(void) {
	//ilog(LOG_DEBUG, "jitter_buffer_free");
	timerthread_free(&jitter_buffer_thread);
}

static void jitter_buffer_flush(struct jitter_buffer *jb) {
	mutex_unlock(&jb->lock);
	timerthread_queue_flush_data(&jb->ttq);
	mutex_lock(&jb->lock);
}


// jb is locked
static void reset_jitter_buffer(struct jitter_buffer *jb) {
	//ilog(LOG_INFO, "reset_jitter_buffer");

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
	jb->clock_drift_val     = 0;
	jb->prev_seq_ts         = rtpe_now;
	jb->prev_seq            = 0;

	jb->num_resets++;
	if(g_tree_nnodes(jb->ttq.entries) > 0)
		jitter_buffer_flush(jb);

	//disable jitter buffer in case of more than 2 resets
	if(jb->num_resets >= 2)
		jb->disabled = 1;
}

static rtp_payload_type *codec_rtp_pt(struct media_packet *mp, int payload_type) {
	rtp_payload_type *rtp_pt = NULL;
	struct codec_handler *transcoder = codec_handler_get(mp->media, payload_type, mp->media_out, NULL);
	if(transcoder) {
		if(transcoder->source_pt.payload_type == payload_type)
			rtp_pt = &transcoder->source_pt;
		if(transcoder->dest_pt.payload_type == payload_type)
			rtp_pt = &transcoder->dest_pt;
	}
	return rtp_pt;
}

static int get_clock_rate(struct media_packet *mp, int payload_type) {
	struct jitter_buffer *jb = mp->stream->jb;
	int clock_rate = 0;

	if(jb->clock_rate && jb->payload_type == payload_type)
		return jb->clock_rate;

	const rtp_payload_type *rtp_pt = codec_rtp_pt(mp, payload_type);
	if(rtp_pt) {
		if(rtp_pt->codec_def && !rtp_pt->codec_def->dtmf) {
			clock_rate = jb->clock_rate = rtp_pt->clock_rate;
			jb->payload_type = payload_type;
		}
		else
			clock_rate = jb->clock_rate; //dtmf packet continue with same clockrate
	}
	else
		ilog(LOG_DEBUG, "clock_rate not present payload_type = %d", payload_type);

	return clock_rate;
}

static struct jb_packet* get_jb_packet(struct media_packet *mp, const str *s) {
	if (rtp_payload(&mp->rtp, &mp->payload, s))
		return NULL;

	char *buf = bufferpool_alloc(media_bufferpool, s->len + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM);
	if (!buf) {
		ilog(LOG_ERROR, "Failed to allocate memory: %s", strerror(errno));
		return NULL;
	}

	struct jb_packet *p = g_slice_alloc0(sizeof(*p));

	p->buf = buf;
	media_packet_copy(&p->mp, mp);

	p->mp.raw = STR_LEN(buf + RTP_BUFFER_HEAD_ROOM, s->len);
	memcpy(p->mp.raw.s, s->s, s->len);

	return p;
}

// jb is locked
static void check_buffered_packets(struct jitter_buffer *jb) {
	if (g_tree_nnodes(jb->ttq.entries) >= (3* rtpe_config.jb_length)) {
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
	int curr_seq = ntohs(mp->rtp->seq_num);

	if(!clockrate || !jb->first_send.tv_sec) {
		ilog(LOG_DEBUG, "Jitter reset due to clockrate");
		reset_jitter_buffer(jb);
		return 1;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	int seq_diff = curr_seq - jb->first_seq;
	if(seq_diff < 0) {
		jb->first_send.tv_sec = 0;
		return 1;
	}

	if(!jb->rtptime_delta && seq_diff) {
		jb->rtptime_delta = ts_diff/seq_diff;
	}

	p->ttq_entry.when = jb->first_send;
	long long ts_diff_us =
		(long long) (ts_diff + (jb->rtptime_delta * jb->buffer_len))* 1000000 / clockrate;

	ts_diff_us += ((long long) jb->clock_drift_val * seq_diff);
	ts_diff_us += ((long long) jb->dtmf_mult_factor * DELAY_FACTOR);

	timeval_add_usec(&p->ttq_entry.when, ts_diff_us);

	ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);

	if (ts_diff_us > 1000000) { // more than one second, can't be right
		ilog(LOG_DEBUG, "Partial reset due to timestamp");
		jb->first_send.tv_sec = 0;
		p->ttq_entry.when = rtpe_now;
	}

	if(jb->prev_seq_ts.tv_sec == 0)
		jb->prev_seq_ts = rtpe_now;

	if((timeval_diff(&p->ttq_entry.when, &jb->prev_seq_ts) < 0) &&  (curr_seq > jb->prev_seq)) {
		p->ttq_entry.when =  jb->prev_seq_ts;
		timeval_add_usec(&p->ttq_entry.when, DELAY_FACTOR);
	}

	if(timeval_diff(&p->ttq_entry.when, &jb->prev_seq_ts) > 0) {
		jb->prev_seq_ts = p->ttq_entry.when;
		jb->prev_seq = curr_seq;
	}

	if(seq_diff > 3000)  //readjust after 3k packets
		jb->first_send.tv_sec = 0;

	timerthread_queue_push(&jb->ttq, &p->ttq_entry);

	return 0;
}

static int handle_clock_drift(struct media_packet *mp) {
	ilog(LOG_DEBUG, "handle_clock_drift");
	struct jitter_buffer *jb = mp->stream->jb;
	int seq_diff = ntohs(mp->rtp->seq_num) - jb->first_seq;

	if(((seq_diff % CLOCK_DRIFT_MULT) != 0) || !seq_diff)
		return 0;

	unsigned long ts = ntohl(mp->rtp->timestamp);
	int payload_type =  (mp->rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(mp, payload_type);
	if(!clockrate) {
		return 0;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	long long ts_diff_us =
		(long long) (ts_diff)* 1000000 / clockrate;
	struct timeval to_send = jb->first_send;
	timeval_add_usec(&to_send, ts_diff_us);
	long long time_diff = timeval_diff(&rtpe_now, &to_send);

	jb->clock_drift_val = time_diff/seq_diff;
	if(jb->clock_drift_val < -10000 || jb->clock_drift_val > 10000) { //disable jb if clock drift greater than 10 ms
		jb->disabled = 1;
		jitter_buffer_flush(jb);
		ilog(LOG_DEBUG, "JB disabled due to clock drift");
		return 1;
	}
	return 0;
}

int buffer_packet(struct media_packet *mp, const str *s) {
	struct jb_packet *p = NULL;
	int ret = 1; // must call stream_packet

	mp->call = mp->sfd->call;
	call_t *call = mp->call;

	rwlock_lock_r(&call->master_lock);

	mp->stream = mp->sfd->stream;
	mp->media = mp->stream->media;

	struct jitter_buffer *jb = mp->stream->jb;
	if (!jb || jb->disabled || !PS_ISSET(mp->sfd->stream, RTP))
		goto end;

	if(jb->initial_pkts < INITIAL_PACKETS) { //Ignore initial Payload Type 126 if any
		jb->initial_pkts++;
		goto end;
	}

	p = get_jb_packet(mp, s);
	if (!p)
		goto end;

        if (PS_ISSET(mp->sfd->stream, RTCP) && rtcp_demux_is_rtcp((void *) &p->mp.raw)){
            ilog(LOG_DEBUG, "Discarding from JB. This is RTCP packet. SSRC %u Payload %d", ntohl(p->mp.rtp->ssrc), (p->mp.rtp->m_pt & 0x7f));
            goto end;
        }
	
	ilog(LOG_DEBUG, "Handling JB packet on: %s:%d (RTP SSRC %u Payload: %d)", sockaddr_print_buf(&mp->stream->endpoint.address),
            mp->stream->endpoint.port, ntohl(p->mp.rtp->ssrc), (p->mp.rtp->m_pt & 0x7f));

	mp = &p->mp;

	mutex_lock(&jb->lock);

	int payload_type = (mp->rtp->m_pt & 0x7f);
	int seq = ntohs(mp->rtp->seq_num);
	int marker = (mp->rtp->m_pt & 0x80) ? 1 : 0;
	int dtmf = 0;
	const rtp_payload_type *rtp_pt = codec_rtp_pt(mp, payload_type);
	if(rtp_pt) {
		if(rtp_pt->codec_def && rtp_pt->codec_def->dtmf)
			dtmf = 1;
	}

	if(marker || (jb->ssrc != ntohl(mp->rtp->ssrc)) || seq == 0 ) { //marker or ssrc change or sequence wrap
		jb->first_send.tv_sec =  0;
        }

	if(jb->clock_rate && jb->payload_type != payload_type) { //reset in case of payload change
			if(!dtmf)
				jb->first_send.tv_sec = 0;
			else
				jb->dtmf_mult_factor++;
	}

        if(!dtmf && jb->dtmf_mult_factor) { //reset after DTMF ends
		jb->first_send.tv_sec = 0;
		jb->dtmf_mult_factor=0;
	}


	if (jb->first_send.tv_sec) {
		if(rtpe_config.jb_clock_drift) {
			if(handle_clock_drift(mp))
				goto end_unlock;
		}
		ret = queue_packet(mp,p);
	}
	else {
		// store data from first packet and use for successive packets and queue the first packet
		unsigned long ts = ntohl(mp->rtp->timestamp);
		payload_type =  (mp->rtp->m_pt & 0x7f);
		int clockrate = get_clock_rate(mp, payload_type);
		if(!clockrate){
			if(jb->rtptime_delta &&  payload_type != COMFORT_NOISE) { //ignore CN
				ilog(LOG_DEBUG, "Jitter reset due to unknown payload = %d", payload_type);
				reset_jitter_buffer(jb);
			}
			goto end_unlock;
		}
		p->ttq_entry.when = jb->first_send = rtpe_now;
		jb->first_send_ts = ts;
		jb->first_seq = ntohs(mp->rtp->seq_num);
		jb->ssrc = ntohl(mp->rtp->ssrc);
		if(jb->rtptime_delta)
			ret = queue_packet(mp,p);
                if(!dtmf)
			jb->rtptime_delta = 0;
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
	if(jb->buffer_len > 0)
		jb->buffer_len--;
}

static void set_jitter_values(struct media_packet *mp) {
	struct jitter_buffer *jb = mp->stream->jb;
	if(!jb || !mp->rtp)
		return;
	int curr_seq = ntohs(mp->rtp->seq_num); 
	int payload_type = (mp->rtp->m_pt & 0x7f);
	int dtmf = 0;
	const rtp_payload_type *rtp_pt = codec_rtp_pt(mp, payload_type);
	if(rtp_pt) {
		if(rtp_pt->codec_def && rtp_pt->codec_def->dtmf)
			dtmf = 1;
	}
	mutex_lock(&jb->lock);
	if(jb->next_exp_seq && !dtmf) {
		if(curr_seq > jb->next_exp_seq) {
			int marker = (mp->rtp->m_pt & 0x80) ? 1 : 0;
			if(!marker) {
				ilog(LOG_DEBUG, "missing seq exp seq =%d, received seq= %d", jb->next_exp_seq, curr_seq);
				increment_buffer(jb);
				jb->cont_frames = 0;
				jb->cont_miss++;
			}
		}
		else if(curr_seq < jb->next_exp_seq) { //Might be duplicate or sequence already crossed
			jb->cont_frames = 0;
                        if((curr_seq == 0) || (jb->next_exp_seq - curr_seq) > 65500) //sequence wrap
				jb->next_exp_seq = 0;
		}
		else {
			jb->cont_frames++;
			jb->cont_miss = 0;
			if(jb->cont_frames >= CONT_SEQ_COUNT) {
				decrement_buffer(jb);
				jb->cont_frames = 0;
			}
		}

		if(jb->cont_miss >= CONT_MISS_COUNT)
			reset_jitter_buffer(jb);
	}
	if(curr_seq >= jb->next_exp_seq)
		jb->next_exp_seq = curr_seq + 1;
	mutex_unlock(&jb->lock);
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

void jitter_buffer_launch(void) {
	timerthread_launch(&jitter_buffer_thread, rtpe_config.scheduling, rtpe_config.priority, "jitter buffer");
}

struct jitter_buffer *jitter_buffer_new(call_t *c) {
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

	bufferpool_unref((*jbp)->buf);
	media_packet_release(&(*jbp)->mp);
	g_slice_free1(sizeof(**jbp), *jbp);
	*jbp = NULL;
}
