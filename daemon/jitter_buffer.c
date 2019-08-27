#include "jitter_buffer.h"
#include "media_socket.h"
#include "media_player.h"
#include "call.h"

#define CONT_SEQ_COUNT 0x64
#define CONT_MISS_COUNT 0x0A
#define INITIAL_PACKETS 0x1E
#define CONT_INCORRECT_BUFFERING 0x14


static struct jitter_buffer_config *jb_config; 

struct jitter_buffer_config {
	int    min_jb_len;
	int    max_jb_len;
	int    enable_jb;
};

void jitter_buffer_init(int min, int max) {
	struct jitter_buffer_config *config;

	ilog(LOG_DEBUG, "jitter_buffer_init");

	if (jb_config)
		return;

	config = malloc(sizeof(*config));
	ZERO(*config);
	config->min_jb_len = min;
	config->max_jb_len = max;
	config->enable_jb  = 1;

	if(config->min_jb_len <= 0)
		config->min_jb_len=1;

	if(config->max_jb_len <= 0)
		config->max_jb_len=1;

	if(config->max_jb_len <= config->min_jb_len)
		config->max_jb_len=config->min_jb_len+1;

	jb_config = config;

	return;
}

static void reset_jitter_buffer(struct jitter_buffer *jb) {
	ilog(LOG_DEBUG, "reset_jitter_buffer");

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
	jb->cont_buff_err       = 0;
	jb->buf_decremented     = 0;
	jb->clock_drift_val     = 0;
	jb->clock_drift_enable  = 0;

	if(jb->p) {
		g_slice_free1(sizeof(*jb->p->packet), jb->p->packet);
		codec_packet_free(jb->p);
		jb->p = NULL;
	}

	jb->num_resets++;

	//disable jitter buffer in case of more than 2 resets
	if(jb->num_resets > 2 && jb->call)
		jb->call->enable_jb = 0;

}

static int get_clock_rate(struct media_packet *mp, int payload_type) {
	const struct rtp_payload_type *rtp_pt = NULL;
	struct jitter_buffer *jb = &mp->stream->rtp_sink->jb;
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
		ilog(LOG_ERROR, "ERROR clock_rate not present");

	return clock_rate;
}

static struct codec_packet* get_codec_packet(struct media_packet *mp, str *s) {
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s = *s;
	p->packet = g_slice_alloc0(sizeof(*p->packet));
	p->packet->sfd = mp->sfd;
	p->packet->fsin = mp->fsin;
	p->packet->tv = mp->tv;
	p->free_func = free;
	p->packet->buffered =1;

	return p;
}

static void check_buffered_packets(struct jitter_buffer *jb, unsigned int len) {
	if(len >= (2* jb_config->max_jb_len)) {
		ilog(LOG_DEBUG, "Jitter reset due to buffer overflow");
		mutex_lock(&jb->lock);
		reset_jitter_buffer(jb);
		mutex_unlock(&jb->lock);
	}
}

static int queue_packet(struct media_packet *mp, struct codec_packet *p) {
	struct jitter_buffer *jb = &mp->stream->rtp_sink->jb;
	unsigned long ts = ntohl(mp->rtp->timestamp);
	int payload_type =  (mp->rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(mp, payload_type);
	int ret = 0;

	if(!clockrate || !jb->first_send.tv_sec) {
		reset_jitter_buffer(jb);
		mutex_unlock(&jb->lock);
		p->packet->buffered = 0;
		play_buffered(mp->stream->rtp_sink, p);
		return 1;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	int seq_diff = ntohs(mp->rtp->seq_num) - jb->first_seq;
	if(!jb->rtptime_delta) {
		jb->rtptime_delta = ts_diff/seq_diff;
	}
	p->to_send = jb->first_send;
	long long ts_diff_us =
		(long long) (ts_diff + (jb->rtptime_delta * jb->buffer_len))* 1000000 / clockrate;

	ts_diff_us += (jb->clock_drift_val * seq_diff); 

	if(jb->buf_decremented) {
		ts_diff_us += 5000; //add 5ms delta when 2 packets are scheduled around same time
		jb->buf_decremented = 0;
	}
	timeval_add_usec(&p->to_send, ts_diff_us);

	ts_diff_us = timeval_diff(&p->to_send, &rtpe_now);

	if (ts_diff_us > 3000000) { // more than three second, can't be right
		jb->first_send.tv_sec = 0;
		jb->rtptime_delta = 0;
	}

	mutex_unlock(&jb->lock);
	mutex_lock(&mp->stream->rtp_sink->out_lock);
	g_queue_push_tail(&mp->packets_out, p);
	ret =  media_socket_dequeue(mp, mp->stream->rtp_sink);
	mutex_unlock(&mp->stream->rtp_sink->out_lock);

	return ret;

}

static void handle_clock_drift(struct media_packet *mp) {
	ilog(LOG_DEBUG, "handle_clock_drift");
	unsigned long ts = ntohl(mp->rtp->timestamp);
	struct jitter_buffer *jb = &mp->stream->rtp_sink->jb;
	int payload_type =  (mp->rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(mp, payload_type);
	if(!clockrate) {
		return;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	int seq_diff = ntohs(mp->rtp->seq_num) - jb->first_seq;
	long long ts_diff_us =
		(long long) (ts_diff)* 1000000 / clockrate;
	struct timeval to_send = jb->first_send;
	timeval_add_usec(&to_send, ts_diff_us);
	long long time_diff = timeval_diff(&rtpe_now, &to_send);

	jb->clock_drift_val = time_diff/seq_diff;
	jb->clock_drift_enable = 0;
	jb->cont_buff_err = 0;
}

int buffer_packet(struct media_packet *mp, str *s) {
	int ret=1;
	str buf;

	mp->stream = mp->sfd->stream;
	mp->media = mp->stream->media;
	mp->call = mp->sfd->call;
	struct jitter_buffer *jb = &mp->stream->rtp_sink->jb;

	if(mp->stream->rtp_sink) {
		ilog(LOG_DEBUG, "Handling packet on: %s:%d", sockaddr_print_buf(&mp->stream->endpoint.address),
				mp->stream->endpoint.port);
		ret=0;
		rwlock_lock_r(&mp->call->master_lock);
		mutex_lock(&jb->lock);
		buf.s = malloc(s->len);
		memcpy(buf.s, s->s, s->len);
		buf.len = s->len;

		struct codec_packet *p = get_codec_packet(mp, &buf);
		rtp_payload(&mp->rtp, &mp->payload, &p->s);
		int payload_type =  (mp->rtp->m_pt & 0x7f);

		if(jb->clock_rate && jb->payload_type != payload_type) { //reset in case of payload change
			jb->first_send.tv_sec = 0;
			jb->rtptime_delta = 0;
		}

		if(jb->clock_drift_enable)
			handle_clock_drift(mp);

		if (jb->first_send.tv_sec) {
			ret = queue_packet(mp,p);
			if(!ret && jb->p) {
				// push first packet into jitter buffer
				mutex_lock(&jb->lock);
				rtp_payload(&mp->rtp, &mp->payload, &jb->p->s);
				queue_packet(mp,jb->p);
				jb->p = NULL;
			}
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
					ret = 1;
				}
				mutex_unlock(&jb->lock);
				rwlock_unlock_r(&mp->call->master_lock);
				p->packet->buffered = 0;
				play_buffered(mp->stream->rtp_sink, p);
				goto end;
			}

			p->to_send = jb->first_send = rtpe_now;
			jb->first_send_ts = ts;
			jb->first_seq = ntohs(mp->rtp->seq_num);
			jb->buffer_len = jb_config->min_jb_len;
			jb->p = p;
			jb->call = mp->stream->rtp_sink->call;
			mutex_unlock(&jb->lock);
		}
		check_buffered_packets(jb, get_queue_length(mp->stream->rtp_sink->buffer_timer));
		rwlock_unlock_r(&mp->call->master_lock);
	}
	else
		ilog(LOG_DEBUG, "Jitter Buffer sink is NULL");

end:
	return ret;
}

static void increment_buffer(struct jitter_buffer *jb) {
	if(jb->buffer_len < jb_config->max_jb_len)
		jb->buffer_len++;
}

static void decrement_buffer(struct jitter_buffer *jb) {
	if(jb->buffer_len > jb_config->min_jb_len) {
		jb->buffer_len--;
		jb->buf_decremented = 1;
	}
}


int set_jitter_values(struct media_packet *mp) {
	int ret=0;
	int curr_seq = ntohs(mp->rtp->seq_num); 
	struct jitter_buffer *jb = &mp->stream->rtp_sink->jb;
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
			ret=1;
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

	int len = get_queue_length(mp->stream->rtp_sink->buffer_timer);

	if(len > jb->buffer_len || len < jb->buffer_len) {
		jb->cont_buff_err++;
		if(jb->cont_buff_err > CONT_INCORRECT_BUFFERING)
			jb->clock_drift_enable=1; 
	}
	else
		jb->cont_buff_err = 0;

	return ret;
}
