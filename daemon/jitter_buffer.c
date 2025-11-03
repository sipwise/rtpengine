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

#define JB_ADAPTIVE_MIN_SAMPLES 0x0A      // Minimum samples before calculating buffer size (10)
#define JB_ADAPTIVE_RECALC_INTERVAL 0x0A  // Recalculate buffer size every N packets (10)
#define JB_MAX_BURST_SIZE 0x03E8          // Maximum burst size to prevent overflow (1000 packets = 20 sec)
#define JB_MAX_JITTER_US 0x1E8480         // Maximum jitter value (2000000 µs = 2 seconds)


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
	jb->jitter_mean         = 0.0;
	jb->jitter_variance     = 0.0;
	jb->jitter_m2           = 0.0;
	jb->jitter_samples      = 0;
	jb->dynamic_capacity    = 0;

	jb->num_resets++;
	if(g_tree_nnodes(jb->ttq.entries) > 0)
		jitter_buffer_flush(jb);

	//disable jitter buffer in case of more than 2 resets
	if(jb->num_resets >= 2)
		jb->disabled = 1;
}

static inline rtp_payload_type *codec_rtp_pt(struct media_packet *mp, int payload_type) {
	return t_hash_table_lookup(mp->media->codecs.codecs, GINT_TO_POINTER(payload_type));
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


// jb is locked
static int get_target_capacity(struct jitter_buffer *jb) {
	if (rtpe_config.jb_adaptive && jb->dynamic_capacity > 0)
		return jb->dynamic_capacity;
	return rtpe_config.jb_length;
}

// jb is locked
static void update_jitter_statistics(struct jitter_buffer *jb, int64_t jitter_sample_us) {
	if (!rtpe_config.jb_adaptive)
		return;
	
	if (jitter_sample_us < 0 || jitter_sample_us > JB_MAX_JITTER_US) {
		ilog(LOG_WARN, "Extreme jitter value detected: %lld µs, ignoring", 
		     (long long)jitter_sample_us);
		return;
	}
	
	jb->jitter_samples++;
	
	double delta = (double)jitter_sample_us - jb->jitter_mean;
	jb->jitter_mean += delta / (double)jb->jitter_samples;
	double delta2 = (double)jitter_sample_us - jb->jitter_mean;
	jb->jitter_m2 += delta * delta2;
	
	if (jb->jitter_samples > 1)
		jb->jitter_variance = jb->jitter_m2 / (double)(jb->jitter_samples - 1);
}

// jb is locked
static void calculate_adaptive_buffer_size(struct jitter_buffer *jb) {
	if (!rtpe_config.jb_adaptive || jb->jitter_samples < JB_ADAPTIVE_MIN_SAMPLES)
		return;
	
	// Protect against negative variance due to floating-point errors
	double std_dev_us = sqrt(jb->jitter_variance < 0.0 ? 0.0 : jb->jitter_variance);
	
	double optimal_buffer_us = jb->jitter_mean + (4.0 * std_dev_us);
	
	int optimal_buffer_ms = (int)(optimal_buffer_us / 1000.0);
	
	int min_capacity = rtpe_config.jb_adaptive_min;
	int max_capacity = rtpe_config.jb_adaptive_max;

	if (max_capacity <= 0)
		max_capacity = 300;
	if (min_capacity < 0)
		min_capacity = 0;
	if (min_capacity > max_capacity)
		min_capacity = max_capacity;
	
	if (optimal_buffer_ms < min_capacity)
		optimal_buffer_ms = min_capacity;
	if (optimal_buffer_ms > max_capacity)
		optimal_buffer_ms = max_capacity;
	
	jb->dynamic_capacity = optimal_buffer_ms;
	
	ilog(LOG_DEBUG, "Adaptive JB: mean=%.2fms, stddev=%.2fms, capacity=%dms (samples=%u)",
	     jb->jitter_mean / 1000.0, std_dev_us / 1000.0, jb->dynamic_capacity, jb->jitter_samples);
}

static struct jb_packet* get_jb_packet(struct media_packet *mp, const str *s) {
	if (!(mp->rtp = rtp_payload(&mp->payload, s, NULL)))
		return NULL;

	char *buf = bufferpool_alloc(media_bufferpool, s->len + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM);
	if (!buf) {
		ilog(LOG_ERROR, "Failed to allocate memory: %s", strerror(errno));
		return NULL;
	}

	struct jb_packet *p = g_new0(__typeof(*p), 1);

	p->buf = buf;
	media_packet_copy(&p->mp, mp);

	p->mp.raw = STR_LEN(buf + RTP_BUFFER_HEAD_ROOM, s->len);
	memcpy(p->mp.raw.s, s->s, s->len);

	return p;
}

// jb is locked (temporarily unlocked during operation, then relocked)
static int remove_oldest_packets(struct jitter_buffer *jb, int num_to_remove) {
	if (num_to_remove <= 0)
		return 0;
	
	int removed = 0;
	mutex_unlock(&jb->lock);
	
	for (int i = 0; i < num_to_remove; i++) {
		struct timerthread_queue_entry *ttqe = rtpe_g_tree_first(jb->ttq.entries);
		if (!ttqe)
			break;
		
		g_tree_remove(jb->ttq.entries, ttqe);
		if (jb->ttq.entry_free_func)
			jb->ttq.entry_free_func(ttqe);
		removed++;
	}
	
	mutex_lock(&jb->lock);
	return removed;
}

// jb is locked
static int try_burst_aware_discard(struct jitter_buffer *jb, int current_buffer_size) {
	if (!jb->rtptime_delta || !jb->clock_rate || !jb->prev_seq_ts) {
		ilog(LOG_DEBUG, "Burst-aware discard: insufficient data for calculation");
		return 0;
	}
	
	int64_t packetization_interval_us = ((int64_t)jb->rtptime_delta * 1000000) / jb->clock_rate;
	if (packetization_interval_us <= 0) {
		ilog(LOG_DEBUG, "Burst-aware discard: invalid packetization interval");
		return 0;
	}
	
	int64_t delta_t = rtpe_now - jb->prev_seq_ts;
	if (delta_t < 0) {
		ilog(LOG_DEBUG, "Burst-aware discard: negative time delta");
		return 0;
	}
	
	int64_t burst_calc = delta_t / packetization_interval_us;
	if (burst_calc > JB_MAX_BURST_SIZE) {
		ilog(LOG_DEBUG, "Burst size exceeds maximum (%d packets), capping", JB_MAX_BURST_SIZE);
		burst_calc = JB_MAX_BURST_SIZE;
	}
	int estimated_burst_size = (int)burst_calc;
	
	int target_capacity = get_target_capacity(jb);
	
	int packets_to_remove = estimated_burst_size - target_capacity;
	
	if (packets_to_remove <= 0) {
		ilog(LOG_DEBUG, "Burst-aware discard: no removal needed (burst: %d, capacity: %d)", 
		     estimated_burst_size, target_capacity);
		return 1;
	}
	
	if (packets_to_remove >= current_buffer_size) {
		ilog(LOG_DEBUG, "Burst-aware discard: would remove all packets (burst: %d, capacity: %d, buffer: %d)",
		     estimated_burst_size, target_capacity, current_buffer_size);
		return 0;
	}
	
	int packets_saved = current_buffer_size - packets_to_remove;
	ilog(LOG_DEBUG, "Burst-aware discard: burst of %d packets detected, removing %d (saving %d packets)",
	     estimated_burst_size, packets_to_remove, packets_saved);
	
	int removed = remove_oldest_packets(jb, packets_to_remove);
	
	if (removed > 0) {
		ilog(LOG_DEBUG, "Burst-aware discard: successfully removed %d packets", removed);
		return 1;
	}
	
	return 0;
}

// jb is locked
static void check_buffered_packets(struct jitter_buffer *jb) {
	int current_buffer_size = g_tree_nnodes(jb->ttq.entries);
	int target_capacity = get_target_capacity(jb);
	
	if (current_buffer_size > target_capacity) {
		if (jb->rtptime_delta && jb->clock_rate && jb->prev_seq_ts) {
			if (try_burst_aware_discard(jb, current_buffer_size)) {
				return;
			}
		}
	}
	
	if (current_buffer_size >= (3 * rtpe_config.jb_length)) {
		ilog(LOG_DEBUG, "Emergency buffer overflow at 3x capacity - forcing reset");
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

	if(!clockrate || !jb->first_send) {
		ilog(LOG_DEBUG, "Jitter reset due to clockrate");
		reset_jitter_buffer(jb);
		return 1;
	}
	long ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	int seq_diff = curr_seq - jb->first_seq;
	if(seq_diff < 0) {
		jb->first_send = 0;
		return 1;
	}

	if(!jb->rtptime_delta && seq_diff) {
		jb->rtptime_delta = ts_diff/seq_diff;
	}

	p->ttq_entry.when = jb->first_send;
	int64_t ts_diff_us =
		(ts_diff + (jb->rtptime_delta * jb->buffer_len))* 1000000 / clockrate;

	ts_diff_us += jb->clock_drift_val * seq_diff;
	ts_diff_us += jb->dtmf_mult_factor * DELAY_FACTOR;

	p->ttq_entry.when += ts_diff_us;

	ts_diff_us = p->ttq_entry.when - rtpe_now;

	if (ts_diff_us > 1000000) { // more than one second, can't be right
		ilog(LOG_DEBUG, "Partial reset due to timestamp");
		jb->first_send = 0;
		p->ttq_entry.when = rtpe_now;
	}

	if(jb->prev_seq_ts == 0)
		jb->prev_seq_ts = rtpe_now;

	if((p->ttq_entry.when - jb->prev_seq_ts < 0) && (curr_seq > jb->prev_seq)) {
		p->ttq_entry.when = jb->prev_seq_ts;
		p->ttq_entry.when += DELAY_FACTOR;
	}

	if(p->ttq_entry.when - jb->prev_seq_ts > 0) {
		jb->prev_seq_ts = p->ttq_entry.when;
		jb->prev_seq = curr_seq;
	}

	if(seq_diff > 3000)  //readjust after 3k packets
		jb->first_send = 0;

	timerthread_queue_push(&jb->ttq, &p->ttq_entry);

	return 0;
}

static int handle_clock_drift(struct media_packet *mp) {
	ilog(LOG_DEBUG, "handle_clock_drift");
	struct jitter_buffer *jb = mp->stream->jb;
	int seq_diff = ntohs(mp->rtp->seq_num) - jb->first_seq;

	if(((seq_diff % CLOCK_DRIFT_MULT) != 0) || !seq_diff)
		return 0;

	uint32_t ts = ntohl(mp->rtp->timestamp);
	int payload_type =  (mp->rtp->m_pt & 0x7f);
	int clockrate = get_clock_rate(mp, payload_type);
	if(!clockrate) {
		return 0;
	}
	int64_t ts_diff = (uint32_t) ts - (uint32_t) jb->first_send_ts;
	int64_t ts_diff_us =
		ts_diff* 1000000 / clockrate;
	int64_t to_send = jb->first_send;
	to_send += ts_diff_us;
	int64_t time_diff = rtpe_now - to_send;

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
		jb->first_send =  0;
        }

	if(jb->clock_rate && jb->payload_type != payload_type) { //reset in case of payload change
			if(!dtmf)
				jb->first_send = 0;
			else
				jb->dtmf_mult_factor++;
	}

        if(!dtmf && jb->dtmf_mult_factor) { //reset after DTMF ends
		jb->first_send = 0;
		jb->dtmf_mult_factor=0;
	}


	if (jb->first_send) {
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
		jb->first_send = rtpe_now;
		p->ttq_entry.when = rtpe_now;
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
	
	// Update adaptive jitter buffer statistics
	if (rtpe_config.jb_adaptive && jb->first_send && jb->rtptime_delta && jb->clock_rate) {
		unsigned long ts = ntohl(mp->rtp->timestamp);
		long ts_diff = (uint32_t)ts - (uint32_t)jb->first_send_ts;
		int64_t expected_arrival = jb->first_send + (ts_diff * 1000000LL / jb->clock_rate);
		
		int64_t jitter_us = llabs(rtpe_now - expected_arrival);
		
		update_jitter_statistics(jb, jitter_us);
		
		if (jb->jitter_samples % JB_ADAPTIVE_RECALC_INTERVAL == 0)
			calculate_adaptive_buffer_size(jb);
	}

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
	g_free(*jbp);
	*jbp = NULL;
}
