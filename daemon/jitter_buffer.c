#include "jitter_buffer.h"
#include "media_socket.h"
#include "media_player.h"
#include "call.h"

#define CONT_SEQ_COUNT 0x64
#define CONT_MISS_COUNT 0x0A
#define INITIAL_PACKETS 0x1E


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

        jb_config = config;

        return;
}

static void reset_jitter_buffer(struct jitter_buffer *jb) {
        ilog(LOG_DEBUG, "reset_jitter_buffer");

	mutex_lock(&jb->lock);
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

	if(jb->p) {
		g_slice_free1(sizeof(*jb->p->packet), jb->p->packet);
		codec_packet_free(jb->p);
		jb->p = NULL;
	}

	jb->num_resets++;

        //disable jitter buffer in case of 2 or more resets
	if(jb->num_resets >= 2 && jb->call)
		jb->call->enable_jb = 0;

	mutex_unlock(&jb->lock);

}

static int get_clock_rate(struct packet_handler_ctx *phc, int payload_type) {
	const struct rtp_payload_type *rtp_pt = NULL;
	int clock_rate = 0;

	if(phc->sink->jb.clock_rate && phc->sink->jb.payload_type == payload_type)
		return phc->sink->jb.clock_rate;

	struct codec_handler *transcoder = codec_handler_get(phc->mp.media, payload_type);
	if(transcoder) {
		if(transcoder->source_pt.payload_type == payload_type)
			rtp_pt = &transcoder->source_pt;
		if(transcoder->dest_pt.payload_type == payload_type)
			rtp_pt = &transcoder->dest_pt;
	}

	if(rtp_pt) {
		clock_rate = phc->sink->jb.clock_rate = rtp_pt->clock_rate;
		phc->sink->jb.payload_type = payload_type;
	}
	else
		ilog(LOG_ERROR, "ERROR clock_rate not present");

	return clock_rate;
}

static struct codec_packet* get_codec_packet(struct packet_handler_ctx *phc) {
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s = phc->s;
	p->packet = g_slice_alloc0(sizeof(*p->packet));
	p->packet->sfd = phc->mp.sfd;
	p->packet->fsin = phc->mp.fsin;
	p->packet->tv = phc->mp.tv;
	p->free_func = free;
	p->packet->buffered =1;

	return p;
}

static void check_buffered_packets(struct jitter_buffer *jb, unsigned int len) {
	if(len >= (2* jb_config->max_jb_len))
		reset_jitter_buffer(jb);
}

static int queue_packet(struct packet_handler_ctx *phc, struct codec_packet *p) {

	rtp_payload(&phc->mp.rtp, &phc->mp.payload, &p->s);
	unsigned long ts = ntohl(phc->mp.rtp->timestamp);
	int payload_type =  (phc->mp.rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(phc, payload_type);
	int ret = 0;

	if(!clockrate) {
		reset_jitter_buffer(&phc->sink->jb);
		p->packet->buffered = 0;
		play_buffered(phc->sink, p);
		return 1;
	}
	uint32_t ts_diff = (uint32_t) ts - (uint32_t) phc->sink->jb.first_send_ts; // allow for wrap-around
	if(!phc->sink->jb.rtptime_delta) {
		int seq_diff = ntohs(phc->mp.rtp->seq_num) - phc->sink->jb.first_seq;
		phc->sink->jb.rtptime_delta = ts_diff/seq_diff;
	}
	p->to_send = phc->sink->jb.first_send;
	unsigned long long ts_diff_us =
		(unsigned long long) (ts_diff + (phc->sink->jb.rtptime_delta * phc->sink->jb.buffer_len))* 1000000 / clockrate;

	timeval_add_usec(&p->to_send, ts_diff_us);

	// how far in the future is this?
	ts_diff_us = timeval_diff(&p->to_send, &rtpe_now); // negative wrap-around to positive OK

	if (ts_diff_us > 1000000) // more than one second, can't be right
		phc->sink->jb.first_send.tv_sec = 0; // fix it up below

	mutex_lock(&phc->sink->out_lock);
	g_queue_push_tail(&phc->mp.packets_out, p);
	ret =  media_socket_dequeue(&phc->mp, phc->sink);
	mutex_unlock(&phc->sink->out_lock);

	return ret;

}

int buffer_packet(struct packet_handler_ctx *phc) {
	int ret=1;
	char *buffer;

	phc->mp.stream = phc->mp.sfd->stream;
	phc->sink = phc->mp.stream->rtp_sink;
	phc->mp.media = phc->mp.stream->media;
	phc->mp.call = phc->mp.sfd->call;

	if(phc->sink) {
		__C_DBG("Handling packet on: %s:%d", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		ret=0;
		rwlock_lock_r(&phc->mp.call->master_lock);
		mutex_lock(&phc->sink->jb.lock);
		buffer = malloc(phc->s.len);
		memcpy(buffer, phc->s.s, phc->s.len);
		str_init_len(&phc->s, buffer, phc->s.len);

		struct codec_packet *p = get_codec_packet(phc);
		if (phc->sink->jb.first_send.tv_sec) {
			mutex_unlock(&phc->sink->jb.lock);
			ret = queue_packet(phc,p);
			if(!ret && phc->sink->jb.p) {
                                // push first packet into jitter buffer
				queue_packet(phc,phc->sink->jb.p);
				phc->sink->jb.p = NULL;
			}
		}
		else {
                        // store data from first packet and use for successive packets and queue the first packet
			rtp_payload(&phc->mp.rtp, &phc->mp.payload, &p->s);
			unsigned long ts = ntohl(phc->mp.rtp->timestamp);
			int payload_type =  (phc->mp.rtp->m_pt & 0x7f);
			int clockrate = get_clock_rate(phc, payload_type);
			if(!clockrate){
				phc->sink->jb.initial_pkts++;
				if(phc->sink->jb.initial_pkts > INITIAL_PACKETS) {      //Ignore initial Payload Type 126 if any
					reset_jitter_buffer(&phc->sink->jb);
					ret = 1;
				}
				mutex_unlock(&phc->sink->jb.lock);
				rwlock_unlock_r(&phc->mp.call->master_lock);
				p->packet->buffered = 0;
				play_buffered(phc->sink, p);
				goto end;
			}

			p->to_send = phc->sink->jb.first_send = rtpe_now;
			phc->sink->jb.first_send_ts = ts;
			phc->sink->jb.first_seq = ntohs(phc->mp.rtp->seq_num);
			phc->sink->jb.buffer_len = jb_config->min_jb_len;
			phc->sink->jb.p = p;
			phc->sink->jb.call = phc->sink->call;
			mutex_unlock(&phc->sink->jb.lock);
		}
		check_buffered_packets(&phc->sink->jb, get_queue_length(phc->sink->buffer_timer));
		rwlock_unlock_r(&phc->mp.call->master_lock);
	}
	else
		ilog(LOG_DEBUG, "Jitter Buffer sink is NULL");

end:
	return ret;
}

static void increment_buffer(int* buffer_len) {
	if(*buffer_len < jb_config->max_jb_len)
		(*buffer_len)++;
}

static void decrement_buffer(int *buffer_len) {
	if(*buffer_len > jb_config->min_jb_len)
		(*buffer_len)--;
}

int set_jitter_values(struct packet_handler_ctx *phc) {
	int ret=0;
	int curr_seq = ntohs(phc->mp.rtp->seq_num); 
	struct jitter_buffer *jb = &phc->sink->jb;
	if(jb->next_exp_seq) {
		mutex_lock(&jb->lock);
		if(curr_seq > jb->next_exp_seq) {
			ilog(LOG_DEBUG, "missing seq exp seq =%d, received seq= %d", jb->next_exp_seq, curr_seq);
			increment_buffer(&jb->buffer_len);
			jb->cont_frames = 0;
			jb->cont_miss++;
			if(jb->cont_miss >= CONT_MISS_COUNT)
				reset_jitter_buffer(jb);
		}
		else if(curr_seq < jb->next_exp_seq) //Might be duplicate or sequence already crossed
			ret=1;
		else {
			jb->cont_frames++;
			jb->cont_miss = 0;
			if(jb->cont_frames >= CONT_SEQ_COUNT) {
				decrement_buffer(&jb->buffer_len);
				jb->cont_frames = 0;
				ilog(LOG_DEBUG, "Received continous frames Buffer len=%d", jb->buffer_len);
			}
		}
		mutex_unlock(&jb->lock);
	}
	jb->next_exp_seq = curr_seq + 1;

	return ret;
}

void play_buffered(struct packet_stream *sink, struct codec_packet *cp) {
        struct packet_handler_ctx phc;
        ZERO(phc);
        phc.mp.sfd = cp->packet->sfd;
        phc.mp.fsin = cp->packet->fsin;
        phc.mp.tv = cp->packet->tv;
        phc.s = cp->s;
        phc.buffered_packet = 1;
        stream_packet(&phc);
        g_slice_free1(sizeof(*cp->packet), cp->packet);
        codec_packet_free(cp);
}
