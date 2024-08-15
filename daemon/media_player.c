#include "media_player.h"

#include <glib.h>
#ifdef WITH_TRANSCODING
#include <mysql.h>
#include <mysql/errmsg.h>
#endif

#include "obj.h"
#include "log.h"
#include "timerthread.h"
#include "call.h"
#include "str.h"
#include "rtplib.h"
#include "codec.h"
#include "media_socket.h"
#include "ssrc.h"
#include "log_funcs.h"
#include "main.h"
#include "rtcp.h"
#ifdef WITH_TRANSCODING
#include "fix_frame_channel_layout.h"
#endif
#include "kernel.h"
#include "bufferpool.h"
#include "uring.h"

#define DEFAULT_AVIO_BUFSIZE 4096

typedef enum {
	MPC_OK = 0,
	MPC_ERR = -1,
	MPC_CACHED = 1,
} mp_cached_code;

#ifdef WITH_TRANSCODING
static struct timerthread media_player_thread;
static __thread MYSQL *mysql_conn;


struct media_player_cache_packet;
static void cache_packet_free(struct media_player_cache_packet *p);
TYPED_GPTRARRAY_FULL(cache_packet_arr, struct media_player_cache_packet, cache_packet_free)


struct media_player_cache_index {
	struct media_player_content_index index;
	rtp_payload_type dst_pt;
};
TYPED_DIRECT_FUNCS(media_player_direct_hash, media_player_direct_eq, struct media_player)
TYPED_GHASHTABLE(media_player_ht, struct media_player, struct media_player, media_player_direct_hash,
		media_player_direct_eq, NULL, NULL) // XXX ref counting players
struct media_player_cache_entry {
	volatile bool finished;
	// "unfinished" elements, only used while decoding is active:
	mutex_t lock;
	cond_t cond; // to wait for more data to be decoded

	cache_packet_arr *packets; // read-only except for decoder thread, which uses finished flags and locks
	unsigned long duration; // cumulative in ms, summed up while decoding
	unsigned int kernel_idx; // -1 if not in use
	media_player_ht wait_queue; // players waiting on decoder to finish

	struct codec_scheduler csch;
	struct media_player_coder coder; // de/encoder data

	char *info_str; // for logging
};
struct media_player_cache_packet {
	char *buf;
	str s;
	long long pts;
	long long duration; // us
	long long duration_ts;
};

static mutex_t media_player_cache_lock;
static GHashTable *media_player_cache; // keys and values only ever freed at shutdown

static bool media_player_read_packet(struct media_player *mp);
#endif

static struct timerthread send_timer_thread;



static void send_timer_send_nolock(struct send_timer *st, struct codec_packet *cp);
static void send_timer_send_lock(struct send_timer *st, struct codec_packet *cp);




#ifdef WITH_TRANSCODING
// called with call->master lock in W
static unsigned int send_timer_flush(struct send_timer *st, void *ptr) {
	if (!st)
		return 0;
	return timerthread_queue_flush(&st->ttq, ptr);
}


static void media_player_coder_shutdown(struct media_player_coder *c) {
	avformat_close_input(&c->fmtctx);
	codec_handler_free(&c->handler);
	if (c->avioctx) {
		if (c->avioctx->buffer)
			av_freep(&c->avioctx->buffer);
		av_freep(&c->avioctx);
	}
	c->avstream = NULL;
	if (c->blob)
		free(c->blob);
	c->blob = NULL;
	c->read_pos = STR_NULL;
}

// called with call->master lock in W
static void media_player_shutdown(struct media_player *mp) {
	if (!mp)
		return;

	//ilog(LOG_DEBUG, "shutting down media_player");
	timerthread_obj_deschedule(&mp->tt_obj);
	mp->next_run.tv_sec = 0;

	if (mp->sink) {
		unsigned int num = send_timer_flush(mp->sink->send_timer, mp->coder.handler);
		ilog(LOG_DEBUG, "%u packets removed from send queue", num);
		// roll back seq numbers already used
		mp->ssrc_out->parent->seq_diff -= num;
	}

	if (mp->opts.block_egress)
		MEDIA_CLEAR(mp->media, BLOCK_EGRESS);

	mp->media = NULL;
	media_player_coder_shutdown(&mp->coder);

	if (mp->kernel_idx != -1)
		kernel_stop_stream_player(mp->kernel_idx);
	else if (mp->cache_entry) {
		mutex_lock(&mp->cache_entry->lock);
		if (t_hash_table_is_set(mp->cache_entry->wait_queue))
			t_hash_table_remove(mp->cache_entry->wait_queue, mp);
		mutex_unlock(&mp->cache_entry->lock);
	}

	mp->cache_index.type = MP_OTHER;
	if (mp->cache_index.file.s)
		g_free(mp->cache_index.file.s);
	mp->cache_index.file = STR_NULL;// coverity[missing_lock : FALSE]
	mp->cache_entry = NULL; // coverity[missing_lock : FALSE]
	mp->cache_read_idx = 0;
	mp->kernel_idx = -1;
}
#endif


long long media_player_stop(struct media_player *mp) {
#ifdef WITH_TRANSCODING
	media_player_shutdown(mp);
	if (!mp)
		return 0;
	return mp->last_frame_ts;
#else
	return 0;
#endif
}


#ifdef WITH_TRANSCODING
static void __media_player_free(void *p) {
	struct media_player *mp = p;

	media_player_shutdown(mp);
	ssrc_ctx_put(&mp->ssrc_out);
	mutex_destroy(&mp->lock);
	obj_put(mp->call);
	av_packet_free(&mp->coder.pkt);
	if (mp->cache_index.file.s)
		g_free(mp->cache_index.file.s);
}
#endif


// call->master_lock held in W
void media_player_new(struct media_player **mpp, struct call_monologue *ml) {
#ifdef WITH_TRANSCODING
	if (*mpp)
		return;

	//ilog(LOG_DEBUG, "creating media_player");

	uint32_t ssrc = 0;
	while (ssrc == 0)
		ssrc = ssl_random();
	struct ssrc_ctx *ssrc_ctx = get_ssrc_ctx(ssrc, ml->ssrc_hash, SSRC_DIR_OUTPUT, ml);
	ssrc_ctx->next_rtcp = rtpe_now;

	struct media_player *mp = *mpp = obj_alloc0("media_player", sizeof(*mp), __media_player_free);

	mp->tt_obj.tt = &media_player_thread;
	mutex_init(&mp->lock);
	mp->kernel_idx = -1;

	mp->run_func = media_player_read_packet; // default
	mp->call = obj_get(ml->call);
	mp->ml = ml;
	mp->seq = ssl_random();
	mp->buffer_ts = ssl_random();
	mp->ssrc_out = ssrc_ctx;

	mp->coder.pkt = av_packet_alloc();
	mp->coder.pkt->data = NULL;
	mp->coder.pkt->size = 0;
#else
	return;
#endif
}


static void __send_timer_free(void *p) {
	struct send_timer *st = p;
	obj_put(st->call);
}


static void __send_timer_send_now(struct timerthread_queue *ttq, void *p) {
	send_timer_send_nolock((void *) ttq, p);
};
static void __send_timer_send_later(struct timerthread_queue *ttq, void *p) {
	send_timer_send_lock((void *) ttq, p);
};

// call->master_lock held in W
struct send_timer *send_timer_new(struct packet_stream *ps) {
	struct send_timer *st = timerthread_queue_new("send_timer", sizeof(*st),
			&send_timer_thread,
			__send_timer_send_now,
			__send_timer_send_later,
			__send_timer_free, codec_packet_free);
	st->call = obj_get(ps->call);
	st->sink = ps;

	return st;
}

// call is locked in R
static void send_timer_rtcp(struct send_timer *st, struct ssrc_ctx *ssrc_out) {
	struct call_media *media = st->sink ? st->sink->media : NULL;
	if (!media)
		return;

	rtcp_send_report(media, ssrc_out);

	ssrc_out->next_rtcp = rtpe_now;
	timeval_add_usec(&ssrc_out->next_rtcp, 5000000 + (ssl_random() % 2000000));
}

struct async_send_req {
	struct uring_req req; // must be first
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_storage sin;
	void *buf;
};
static void async_send_req_free(struct uring_req *p, int32_t res, uint32_t flags) {
	struct async_send_req *req = (__typeof__(req)) p;
	bufferpool_unref(req->buf);
	uring_req_free(p);
}

static bool __send_timer_send_1(struct rtp_header *rh, struct packet_stream *sink, struct codec_packet *cp) {
	stream_fd *sink_fd = sink->selected_sfd;

	if (!sink_fd || sink_fd->socket.fd == -1 || sink->endpoint.address.family == NULL)
		return false;

	log_info_stream_fd(sink->selected_sfd);

	if (rh) {
		ilog(LOG_DEBUG, "Forward to sink endpoint: local %s -> remote %s%s%s "
				"(RTP seq %u TS %u SSRC %x)",
				endpoint_print_buf(&sink_fd->socket.local),
				FMT_M(endpoint_print_buf(&sink->endpoint)),
				ntohs(rh->seq_num),
				ntohl(rh->timestamp),
				ntohl(rh->ssrc));
		codec_calc_jitter(cp->ssrc_out, ntohl(rh->timestamp), cp->clockrate, &rtpe_now);
	}
	else
		ilog(LOG_DEBUG, "Forward to sink endpoint: local %s -> remote %s%s%s",
				endpoint_print_buf(&sink_fd->socket.local),
				FMT_M(endpoint_print_buf(&sink->endpoint)));

	struct async_send_req *req = uring_alloc_req(sizeof(*req), async_send_req_free);
	req->iov = (__typeof(req->iov)) {
		.iov_base = cp->s.s,
		.iov_len = cp->s.len,
	};
	req->msg = (__typeof(req->msg)) {
		.msg_iov = &req->iov,
		.msg_iovlen = 1,
	};
	req->buf = bufferpool_ref(cp->s.s);
	uring_sendmsg(&sink_fd->socket, &req->msg, &sink->endpoint, &req->sin, &req->req);

	if (sink->call->recording && rtpe_config.rec_egress) {
		// fill in required members
		struct media_packet mp = {
			.call = sink->call,
			.stream = sink,
			.sfd = sink_fd,
			.fsin = sink->endpoint,
		};
		dump_packet(&mp, cp->plain.s ? &cp->plain : &cp->s);
	}

	atomic64_inc_na(&sink->stats_out->packets);
	atomic64_add_na(&sink->stats_out->bytes, cp->s.len);
	atomic64_inc_na(&sink_fd->local_intf->stats->out.packets);
	atomic64_add_na(&sink_fd->local_intf->stats->out.bytes, cp->s.len);

	log_info_pop();

	return true;
}

static void __send_timer_send_common(struct send_timer *st, struct codec_packet *cp) {
	if (!__send_timer_send_1(cp->rtp, st->sink, cp))
		goto out;

	if (cp->ssrc_out && cp->rtp) {
		atomic64_inc_na(&cp->ssrc_out->stats->packets);
		atomic64_add_na(&cp->ssrc_out->stats->bytes, cp->s.len);
		if (cp->ts)
			atomic_set_na(&cp->ssrc_out->stats->timestamp, cp->ts);
		else
			atomic_set_na(&cp->ssrc_out->stats->timestamp, ntohl(cp->rtp->timestamp));
		payload_tracker_add(&cp->ssrc_out->tracker, cp->rtp->m_pt & 0x7f);
	}

	// do we send RTCP?
	struct ssrc_ctx *ssrc_out = cp->ssrc_out;
	if (ssrc_out && ssrc_out->next_rtcp.tv_sec) {
		mutex_lock(&ssrc_out->parent->h.lock);
		long long diff = timeval_diff(&ssrc_out->next_rtcp, &rtpe_now);
		mutex_unlock(&ssrc_out->parent->h.lock);
		if (diff < 0)
			send_timer_rtcp(st, ssrc_out);
	}

out:
	codec_packet_free(cp);
}

static void send_timer_send_lock(struct send_timer *st, struct codec_packet *cp) {
	call_t *call = st->call;
	if (!call)
		return;

	log_info_call(call);
	rwlock_lock_r(&call->master_lock);
	mutex_lock(&st->sink->out_lock);

	__send_timer_send_common(st, cp);

	mutex_unlock(&st->sink->out_lock);
	rwlock_unlock_r(&call->master_lock);
	log_info_pop();

}
// st->stream->out_lock (or call->master_lock/W) must be held already
static void send_timer_send_nolock(struct send_timer *st, struct codec_packet *cp) {
	call_t *call = st->call;
	if (!call)
		return;

	log_info_call(call);

	__send_timer_send_common(st, cp);

	log_info_pop();
}


// st->stream->out_lock (or call->master_lock/W) must be held already
void send_timer_push(struct send_timer *st, struct codec_packet *cp) {
	timerthread_queue_push(&st->ttq, &cp->ttq_entry);
}


#ifdef WITH_TRANSCODING


#if LIBAVFORMAT_VERSION_INT >= AV_VERSION_INT(57, 26, 0)
#define CODECPAR codecpar
#else
#define CODECPAR codec
#endif


static void media_player_coder_add_packet(struct media_player_coder *c,
		void (*fn)(void *p, char *buf, size_t len,
		long long us_dur, unsigned long long pts), void *p) {
	// scale pts and duration according to sample rate

	long long duration_scaled = c->pkt->duration * c->avstream->CODECPAR->sample_rate
		* c->avstream->time_base.num / c->avstream->time_base.den;
	unsigned long long pts_scaled = c->pkt->pts * c->avstream->CODECPAR->sample_rate
		* c->avstream->time_base.num / c->avstream->time_base.den;

	long long us_dur = c->pkt->duration * 1000000LL * c->avstream->time_base.num
		/ c->avstream->time_base.den;
	ilog(LOG_DEBUG, "read media packet: pts %llu duration %lli (scaled %llu/%lli, %lli us), "
			"sample rate %i, time_base %i/%i",
			(unsigned long long) c->pkt->pts,
			(long long) c->pkt->duration,
			pts_scaled,
			duration_scaled,
			us_dur,
			c->avstream->CODECPAR->sample_rate,
			c->avstream->time_base.num, c->avstream->time_base.den);

	fn(p, (char *) c->pkt->data, c->pkt->size, us_dur, pts_scaled);
}


static bool media_player_read_decoded_packet(struct media_player *mp) {
	struct media_player_cache_entry *entry = mp->cache_entry;
	if (!entry)
		return false;

	unsigned int read_idx = mp->cache_read_idx;
	ilog(LOG_DEBUG, "Buffered media player reading packet #%u", read_idx);

retry:;
	bool finished = entry->finished; // hold lock or not

	if (!finished) {
		// slow track with locking
		mutex_lock(&entry->lock);
		// confirm that we are indeed not finished
		if (entry->finished) {
			// preempted, good to go
			mutex_unlock(&entry->lock);
			finished = true;
		}
	}

	if (read_idx >= entry->packets->len) {
		if (!finished) {
			// wait for more
			cond_wait(&entry->cond, &entry->lock);
			mutex_unlock(&entry->lock);
			goto retry;
		}

		// EOF

		if (mp->opts.repeat <= 1) {
			ilog(LOG_DEBUG, "EOF reading from media buffer (%s), stopping playback",
					entry->info_str);
			return true;
		}

		ilog(LOG_DEBUG, "EOF reading from media buffer (%s) but will repeat %i time",
				entry->info_str, mp->opts.repeat);
		mp->opts.repeat--;
		read_idx = mp->cache_read_idx = 0;
		goto retry;
	}

	// got a packet
	struct media_player_cache_packet *pkt = entry->packets->pdata[read_idx];
	long long us_dur = pkt->duration;

	mp->cache_read_idx++;

	if (!finished)
		mutex_unlock(&entry->lock);

	// make a copy to send out
	size_t len = pkt->s.len + sizeof(struct rtp_header) + RTP_BUFFER_TAIL_ROOM;
	char *buf = bufferpool_alloc(media_bufferpool, len);
	memcpy(buf, pkt->buf, len);

	struct media_packet packet = {
		.tv = rtpe_now,
		.call = mp->call,
		.media = mp->media,
		.media_out = mp->media,
		.rtp = (void *) buf,
		.ssrc_out = mp->ssrc_out,
	};

	mp->last_frame_ts = pkt->pts;

	codec_output_rtp(&packet, &entry->csch, mp->coder.handler, buf, pkt->s.len, mp->buffer_ts,
			read_idx == 0, mp->seq++, 0, -1, 0);

	mp->buffer_ts += pkt->duration_ts;
	mp->sync_ts_tv = rtpe_now;

	media_packet_encrypt(mp->crypt_handler->out->rtp_crypt, mp->sink, &packet);

	mutex_lock(&mp->sink->out_lock);
	if (media_socket_dequeue(&packet, mp->sink))
		ilog(LOG_ERR, "Error sending playback media to RTP sink");
	mutex_unlock(&mp->sink->out_lock);

	// schedule our next run
	timeval_add_usec(&mp->next_run, us_dur);
	timerthread_obj_schedule_abs(&mp->tt_obj, &mp->next_run);

	return false;
}

static void media_player_kernel_player_start_now(struct media_player *mp) {
	struct media_player_cache_entry *entry = mp->cache_entry;
	if (!entry)
		return;
	const rtp_payload_type *dst_pt = &entry->coder.handler->dest_pt;

	ilog(LOG_DEBUG, "Starting kernel media player index %i (PT %i)", entry->kernel_idx, dst_pt->payload_type);

	struct rtpengine_play_stream_info info = {
		.packet_stream_idx = entry->kernel_idx,
		.pt = dst_pt->payload_type,
		.seq = mp->seq,
		.ts = mp->buffer_ts,
		.ssrc = mp->ssrc_out->parent->h.ssrc,
		.repeat = mp->opts.repeat,
		.stats = mp->sink->stats_out,
		.iface_stats = mp->sink->selected_sfd->local_intf->stats,
		.ssrc_stats = mp->ssrc_out->stats,
	};
	mp->sink->endpoint.address.family->endpoint2kernel(&info.dst_addr, &mp->sink->endpoint); // XXX unify with __re_address_translate_ep
	mp->sink->selected_sfd->socket.local.address.family->endpoint2kernel(&info.src_addr, &mp->sink->selected_sfd->socket.local); // XXX unify with __re_address_translate_ep
	mp->crypt_handler->out->kernel(&info.encrypt, mp->sink);

	unsigned int idx = kernel_start_stream_player(&info);
	if (idx == -1)
		ilog(LOG_ERR, "Failed to start kernel media player (index %i): %s", info.packet_stream_idx, strerror(errno));
	else
		mp->kernel_idx = idx;
}

static void media_player_kernel_player_start(struct media_player *mp) {
	struct media_player_cache_entry *entry = mp->cache_entry;
	if (!entry)
		return;

	// decoder finished yet? try unlocked read first
	bool finished = entry->finished;

	if (!finished) {
		mutex_lock(&entry->lock);
		// check flag again in case it happened just now
		if (!entry->finished) {
			// add us to wait list
			ilog(LOG_DEBUG, "Decoder not finished yet, waiting to start kernel player index %i",
					entry->kernel_idx);
			t_hash_table_insert(entry->wait_queue, mp, mp); // XXX reference needed?
			mutex_unlock(&entry->lock);
			return;
		}
		// finished now, drop down below
		mutex_unlock(&entry->lock);
	}

	media_player_kernel_player_start_now(mp);
}

static void media_player_cached_reader_start(struct media_player *mp, str_case_value_ht codec_set) {
	struct media_player_cache_entry *entry = mp->cache_entry;
	const rtp_payload_type *dst_pt = &entry->coder.handler->dest_pt;

	if (entry->kernel_idx != -1) {
		media_player_kernel_player_start(mp);
		return;
	}

	// create dummy codec handler and start timer

	mp->coder.handler = codec_handler_make_dummy(&entry->coder.handler->dest_pt, mp->media, codec_set);

	mp->run_func = media_player_read_decoded_packet;
	mp->next_run = rtpe_now;
	mp->coder.duration = entry->coder.duration;

	// if we played anything before, scale our sync TS according to the time
	// that has passed
	if (mp->sync_ts_tv.tv_sec) {
		long long ts_diff_us = timeval_diff(&rtpe_now, &mp->sync_ts_tv);
		mp->buffer_ts += fraction_divl(ts_diff_us * dst_pt->clock_rate / 1000000, &dst_pt->codec_def->default_clockrate_fact);
	}

	mp->sync_ts_tv = rtpe_now;

	media_player_read_decoded_packet(mp);
}


static void cache_packet_free(struct media_player_cache_packet *p) {
	bufferpool_unref(p->buf);
	g_slice_free1(sizeof(*p), p);
}


// returns: true = entry exists, decoding handled separately, use entry for playback
//          false = no entry exists, OR entry is a new one, proceed to open decoder, then call _play_start
static bool media_player_cache_get_entry(struct media_player *mp,
		const rtp_payload_type *dst_pt, str_case_value_ht codec_set)
{
	if (!rtpe_config.player_cache)
		return false;
	if (mp->cache_index.type <= 0)
		return false;
	if (!dst_pt)
		return false;

	struct media_player_cache_index lookup;
	lookup.index = mp->cache_index;
	lookup.dst_pt = *dst_pt;

	mutex_lock(&media_player_cache_lock);
	struct media_player_cache_entry *entry = mp->cache_entry
		= g_hash_table_lookup(media_player_cache, &lookup);

	bool ret = true; // entry exists, use cached data
	if (entry) {
		media_player_cached_reader_start(mp, codec_set);
		goto out;
	}

	ret = false; // new entry, open decoder, then call media_player_play_start

	// initialise object

	struct media_player_cache_index *ins_key = g_slice_alloc(sizeof(*ins_key));
	*ins_key = lookup;
	ins_key->index.file = str_dup_str(&lookup.index.file);
	codec_init_payload_type(&ins_key->dst_pt, MT_UNKNOWN); // duplicate contents

	entry = mp->cache_entry = g_slice_alloc0(sizeof(*entry));
	mutex_init(&entry->lock);
	cond_init(&entry->cond);
	entry->packets = cache_packet_arr_new_sized(64);
	entry->wait_queue = media_player_ht_new();

	switch (lookup.index.type) {
		case MP_DB:
			entry->info_str = g_strdup_printf("DB media file #%llu", lookup.index.db_id);
			break;
		case MP_FILE:
			entry->info_str = g_strdup_printf("media file '" STR_FORMAT "'",
					STR_FMT(&lookup.index.file));
			break;
		case MP_BLOB:
			entry->info_str = g_strdup_printf("binary media blob");
			break;
		default:;
	}

	g_hash_table_insert(media_player_cache, ins_key, entry);

	entry->kernel_idx = -1;
	if (kernel.use_player) {
		entry->kernel_idx = kernel_get_packet_stream();
		if (entry->kernel_idx == -1)
			ilog(LOG_ERR, "Failed to get kernel packet stream entry (%s)", strerror(errno));
		else
			ilog(LOG_DEBUG, "Using kernel packet stream index %i", entry->kernel_idx);
	}

out:
	mutex_unlock(&media_player_cache_lock);

	return ret;
}

static void media_player_cache_packet(struct media_player_cache_entry *entry, char *buf, size_t len,
		long long us_dur, unsigned long long pts)
{
	// synthesise fake RTP header and media_packet context

	struct rtp_header rtp = {
		.timestamp = pts, // taken verbatim by handler_func_playback w/o byte swap
	};
	struct media_packet packet = {
		.rtp = &rtp,
		.cache_entry = entry,
	};
	packet.raw = STR_LEN(buf, len);
	packet.payload = packet.raw;

	entry->coder.handler->handler_func(entry->coder.handler, &packet);
}

static void media_player_cache_entry_decoder_thread(void *p) {
	struct media_player_cache_entry *entry = p;

	ilog(LOG_DEBUG, "Launching media decoder thread for %s", entry->info_str);

	while (true) {
		// let us be cancelled
		thread_cancel_enable();
		pthread_testcancel();
		thread_cancel_disable();

		int ret = av_read_frame(entry->coder.fmtctx, entry->coder.pkt);
		if (ret < 0) {
			if (ret != AVERROR_EOF)
				ilog(LOG_ERR, "Error while reading from media stream");
			break;
		}

		media_player_coder_add_packet(&entry->coder, (void *) media_player_cache_packet, entry);

		av_packet_unref(entry->coder.pkt);
	}

	ilog(LOG_DEBUG, "Decoder thread for %s finished", entry->info_str);

	mutex_lock(&entry->lock);
	entry->finished = true;
	cond_broadcast(&entry->cond);

	media_player_ht_iter iter;
	t_hash_table_iter_init(&iter, entry->wait_queue);
	struct media_player *mp;
	while (t_hash_table_iter_next(&iter, &mp, NULL)) {
		if (mp->media)
			media_player_kernel_player_start_now(mp);
	}
	t_hash_table_destroy(entry->wait_queue); // not needed any more
	entry->wait_queue = media_player_ht_null();

	mutex_unlock(&entry->lock);
}

static void packet_encoded_cache(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		str *s, char *buf, unsigned int pkt_len, const struct fraction *cr_fact)
{
	struct media_player_cache_entry *entry = mp->cache_entry;

	struct media_player_cache_packet *ep = g_slice_alloc0(sizeof(*ep));

	*ep = (__typeof__(*ep)) {
		.buf = buf,
		.s = *s,
		.pts = pkt->pts,
		.duration_ts = pkt->duration,
		.duration = (long long) pkt->duration * 1000000LL
			/ entry->coder.handler->dest_pt.clock_rate,
	};

	mutex_lock(&entry->lock);
	t_ptr_array_add(entry->packets, ep);

	if (entry->kernel_idx != -1) {
		ilog(LOG_DEBUG, "Adding media packet (length %zu, TS %" PRIu64 ", delay %lu ms) to kernel packet stream %i",
				s->len, pkt->pts, entry->duration, entry->kernel_idx);
		if (!kernel_add_stream_packet(entry->kernel_idx, s->s, s->len, entry->duration, pkt->pts,
					pkt->duration))
			ilog(LOG_ERR, "Failed to add packet to kernel player (%s)", strerror(errno));
	}

	entry->duration += ep->duration / 1000;

	cond_broadcast(&entry->cond);
	mutex_unlock(&entry->lock);
}

static int media_player_packet_cache(encoder_t *enc, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	packet_encoded_packetize(enc->avpkt, ch, mp, enc->def->packetizer, enc, &enc->clockrate_fact,
			packet_encoded_cache);

	return 0;
}


// called from media_player_play_start, which is called after media_player_cache_get_entry returned true.
// this can mean that either we don't have a cache entry and should continue normally, or if we
// do have a cache entry, initialise it, set up the thread, take over decoding, and then proceed as a
// media player consuming the data from the decoder thread.
// returns: false = continue normally decode in-thread, true = take data from other thread
static bool media_player_cache_entry_init(struct media_player *mp, const rtp_payload_type *dst_pt,
		str_case_value_ht codec_set)
{
	struct media_player_cache_entry *entry = mp->cache_entry;
	if (!entry)
		return false;

	// steal coder data
	entry->coder = mp->coder;
	ZERO(mp->coder);
	mp->coder.duration = entry->coder.duration; // retain this for reporting

	entry->coder.handler->packet_encoded = media_player_packet_cache;

	// use low priority (10 nice)
	thread_create_detach_prio(media_player_cache_entry_decoder_thread, entry, NULL, 10, "mp decoder");

	media_player_cached_reader_start(mp, codec_set);

	return true;
}



// find suitable output payload type
static rtp_payload_type *media_player_get_dst_pt(struct media_player *mp) {
	rtp_payload_type *dst_pt = NULL;
	for (__auto_type l = mp->media->codecs.codec_prefs.head; l; l = l->next) {
		dst_pt = l->data;
		ensure_codec_def(dst_pt, mp->media);
		if (dst_pt->codec_def && !dst_pt->codec_def->supplemental)
			goto found;
	}
	if (!dst_pt) {
		ilog(LOG_ERR, "No supported output codec found in SDP");
		return NULL;
	}
found:
	ilog(LOG_DEBUG, "Output codec for media playback is " STR_FORMAT,
			STR_FMT(&dst_pt->encoding_with_params));
	return dst_pt;
}


bool media_player_pt_match(const struct media_player *mp, const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt)
{
	if (!mp->coder.handler)
		return true; // not initialised yet -> doesn't need a reset
	if (!rtp_payload_type_eq_exact(&mp->coder.handler->dest_pt, dst_pt))
		return false;
	if (!rtp_payload_type_eq_exact(&mp->coder.handler->source_pt, src_pt))
		return false;
	return true;
}


static int media_player_setup_common(struct media_player *mp, const rtp_payload_type *src_pt,
		const rtp_payload_type **dst_pt)
{
	if (!*dst_pt)
		*dst_pt = media_player_get_dst_pt(mp);
	if (!*dst_pt)
		return -1;

	// if we played anything before, scale our sync TS according to the time
	// that has passed
	if (mp->sync_ts_tv.tv_sec) {
		long long ts_diff_us = timeval_diff(&rtpe_now, &mp->sync_ts_tv);
		mp->sync_ts += fraction_divl(ts_diff_us * (*dst_pt)->clock_rate / 1000000, &(*dst_pt)->codec_def->default_clockrate_fact);
	}

	// if we already have a handler, see if anything needs changing
	if (!media_player_pt_match(mp, src_pt, *dst_pt)) {
		ilog(LOG_DEBUG, "Resetting codec handler for media player");
		codec_handler_free(&mp->coder.handler);
	}

	return 0;
}

// used for generic playback (audio_player, t38_gateway)
int media_player_setup(struct media_player *mp, const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, str_case_value_ht codec_set)
{
	int ret = media_player_setup_common(mp, src_pt, &dst_pt);
	if (ret)
		return ret;

	if (!mp->coder.handler)
		mp->coder.handler = codec_handler_make_playback(src_pt, dst_pt, mp->sync_ts, mp->media,
				mp->ssrc_out->parent->h.ssrc, codec_set);
	if (!mp->coder.handler)
		return -1;

	return 0;
}
// used for "play media" player
static int __media_player_setup_internal(struct media_player *mp, const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, str_case_value_ht codec_set)
{
	int ret = media_player_setup_common(mp, src_pt, &dst_pt);
	if (ret)
		return ret;

	if (!mp->coder.handler)
		mp->coder.handler = codec_handler_make_media_player(src_pt, dst_pt, mp->sync_ts, mp->media,
				mp->ssrc_out->parent->h.ssrc, codec_set);
	if (!mp->coder.handler)
		return -1;

	return 0;
}

static int __ensure_codec_handler(struct media_player *mp, const rtp_payload_type *dst_pt,
		str_case_value_ht codec_set)
{
	if (mp->coder.handler)
		return 0;

	// synthesise rtp payload type
	rtp_payload_type src_pt = { .payload_type = -1 };
	src_pt.codec_def = codec_find_by_av(mp->coder.avstream->CODECPAR->codec_id);
	if (!src_pt.codec_def) {
		ilog(LOG_ERR, "Attempting to play media from an unsupported file format/codec");
		return -1;
	}
	src_pt.encoding = src_pt.codec_def->rtpname_str;
	src_pt.channels = GET_CHANNELS(mp->coder.avstream->CODECPAR);
	src_pt.clock_rate = mp->coder.avstream->CODECPAR->sample_rate;
	codec_init_payload_type(&src_pt, MT_AUDIO);

	if (__media_player_setup_internal(mp, &src_pt, dst_pt, codec_set))
		return -1;

	mp->coder.duration = mp->coder.avstream->duration * 1000 * mp->coder.avstream->time_base.num
		/ mp->coder.avstream->time_base.den;

	payload_type_clear(&src_pt);
	return 0;
}


// appropriate lock must be held
void media_player_add_packet(struct media_player *mp, char *buf, size_t len,
		long long us_dur, unsigned long long pts)
{
	// synthesise fake RTP header and media_packet context

	struct rtp_header rtp = {
		.timestamp = pts, // taken verbatim by handler_func_playback w/o byte swap
		.seq_num = htons(mp->seq),
	};
	struct media_packet packet = {
		.tv = rtpe_now,
		.call = mp->call,
		.media = mp->media,
		.media_out = mp->media,
		.rtp = &rtp,
		.ssrc_out = mp->ssrc_out,
	};
	packet.raw = STR_LEN(buf, len);
	packet.payload = packet.raw;

	mp->coder.handler->handler_func(mp->coder.handler, &packet);

	// as this is timing sensitive and we may have spent some time decoding,
	// update our global "now" timestamp
	gettimeofday(&rtpe_now, NULL);

	// keep track of RTP timestamps and real clock. look at the last packet we received
	// and update our sync TS.
	if (packet.packets_out.head) {
		struct codec_packet *p = packet.packets_out.head->data;
		if (p->rtp) {
			mp->sync_ts = ntohl(p->rtp->timestamp);
			mp->sync_ts_tv = p->ttq_entry.when;
		}
	}

	media_packet_encrypt(mp->crypt_handler->out->rtp_crypt, mp->sink, &packet);

	mutex_lock(&mp->sink->out_lock);
	if (media_socket_dequeue(&packet, mp->sink))
		ilog(LOG_ERR, "Error sending playback media to RTP sink");
	mutex_unlock(&mp->sink->out_lock);

	timeval_add_usec(&mp->next_run, us_dur);
	timerthread_obj_schedule_abs(&mp->tt_obj, &mp->next_run);
}


// appropriate lock must be held
static bool media_player_read_packet(struct media_player *mp) {
	if (!mp->coder.fmtctx)
		return true;

	int ret = av_read_frame(mp->coder.fmtctx, mp->coder.pkt);
	if (ret < 0) {
		if (ret == AVERROR_EOF) {
			if (mp->opts.repeat > 1) {
				ilog(LOG_DEBUG, "EOF reading from media stream but will repeat %i time",
						mp->opts.repeat);
				mp->opts.repeat = mp->opts.repeat - 1;
				int64_t ret64 = avio_seek(mp->coder.fmtctx->pb, 0, SEEK_SET);
				if (ret64 != 0)
					ilog(LOG_ERR, "Failed to seek to beginning of media file");
				ret = av_seek_frame(mp->coder.fmtctx, -1, 0, 0);
				if (ret < 0)
					ilog(LOG_ERR, "Failed to seek to beginning of media file");
				ret = av_read_frame(mp->coder.fmtctx, mp->coder.pkt);
			} else {
				ilog(LOG_DEBUG, "EOF reading from media stream");
				return true;

			}

		}
		if (ret < 0 && ret != AVERROR_EOF) { 
			ilog(LOG_ERR, "Error while reading from media stream");
			return true;
		}

	}

	mp->last_frame_ts = mp->coder.pkt->pts;

	media_player_coder_add_packet(&mp->coder, (void *) media_player_add_packet, mp);

	av_packet_unref(mp->coder.pkt);

	return false;
}


// call->master_lock held in W
void media_player_set_media(struct media_player *mp, struct call_media *media) {
	mp->media = media;
	if (media->streams.head) {
		mp->sink = media->streams.head->data;
		mp->crypt_handler = determine_handler(&transport_protocols[PROTO_RTP_AVP], media, true);
	}
}


// call->master_lock held in W
// returns destination payload type, or NULL on failure
static const rtp_payload_type *media_player_play_setup(struct media_player *mp) {
	// find call media suitable for playback
	struct call_media *media;
	for (unsigned int i = 0; i < mp->ml->medias->len; i++) {
		media = mp->ml->medias->pdata[i];
		if (media->type_id != MT_AUDIO)
			continue;
		if (!MEDIA_ISSET(media, SEND))
			continue;
		if (media->streams.length == 0)
			continue;
		goto found;
	}
	media = NULL;
found:
	if (!media) {
		ilog(LOG_ERR, "No suitable SDP section for media playback");
		return NULL;
	}
	media_player_set_media(mp, media);
	return media_player_get_dst_pt(mp);
}

// call->master_lock held in W
// returns destination payload type, or NULL on failure
static const rtp_payload_type *media_player_play_init(struct media_player *mp) {
	media_player_shutdown(mp);
	return media_player_play_setup(mp);
}


// call->master_lock held in W
static bool media_player_play_start(struct media_player *mp, const rtp_payload_type *dst_pt,
		str_case_value_ht codec_set)
{
	// needed to have usable duration for some formats. ignore errors.
	if (!mp->coder.fmtctx->streams || !mp->coder.fmtctx->streams[0])
		avformat_find_stream_info(mp->coder.fmtctx, NULL);

	mp->coder.avstream = mp->coder.fmtctx->streams[0];
	if (!mp->coder.avstream) {
		ilog(LOG_ERR, "No AVStream present in format context");
		return false;
	}

	if (__ensure_codec_handler(mp, dst_pt, codec_set))
		return false;

	if (mp->opts.block_egress)
		MEDIA_SET(mp->media, BLOCK_EGRESS);

	if (media_player_cache_entry_init(mp, dst_pt, codec_set))
		return true;

	mp->next_run = rtpe_now;
	// give ourselves a bit of a head start with decoding
	timeval_add_usec(&mp->next_run, -50000);

	// if start_pos is positive, try to seek to that position
	if (mp->opts.start_pos > 0) {
		ilog(LOG_DEBUG, "Seeking to position %lli", mp->opts.start_pos);
		av_seek_frame(mp->coder.fmtctx, 0, mp->opts.start_pos, 0);
	}
	else // in case this is a repeated start
		av_seek_frame(mp->coder.fmtctx, 0, 0, 0);

	media_player_read_packet(mp);

	return true;
}
#endif


// call->master_lock held in W
static mp_cached_code __media_player_init_file(struct media_player *mp, const str *file,
		media_player_opts_t opts,
		const rtp_payload_type *dst_pt)
{
#ifdef WITH_TRANSCODING
	mp->cache_index.type = MP_FILE;
	mp->cache_index.file = str_dup_str(file);

	mp->opts = opts;

	if (media_player_cache_get_entry(mp, dst_pt, opts.codec_set))
		return MPC_CACHED;

	char file_s[PATH_MAX];
	snprintf(file_s, sizeof(file_s), STR_FORMAT, STR_FMT(file));

	int ret = avformat_open_input(&mp->coder.fmtctx, file_s, NULL, NULL);
	if (ret < 0) {
		ilog(LOG_ERR, "Failed to open media file for playback: %s", av_error(ret));
		return MPC_ERR;
	}

	return MPC_OK;
#else
	return MPC_ERR;
#endif
}

// call->master_lock held in W
bool media_player_play_file(struct media_player *mp, const str *file, media_player_opts_t opts) {
#ifdef WITH_TRANSCODING
	const rtp_payload_type *dst_pt = media_player_play_init(mp);
	if (!dst_pt)
		return false;

	mp_cached_code ret = __media_player_init_file(mp, file, opts, dst_pt);
	if (ret == MPC_CACHED)
		return true;
	if (ret == MPC_ERR)
		return false;

	return media_player_play_start(mp, dst_pt, opts.codec_set);
#else
	return false;
#endif
}

// call->master_lock held in W
bool media_player_init_file(struct media_player *mp, const str *file, media_player_opts_t opts) {
	int ret = __media_player_init_file(mp, file, opts, NULL);
	return ret == 0;
}


#ifdef WITH_TRANSCODING
static int __mp_avio_read_wrap(void *opaque, uint8_t *buf, int buf_size) {
	struct media_player_coder *c = opaque;
	if (buf_size < 0)
		return AVERROR(EINVAL);
	if (buf_size == 0)
		return 0;
	if (!c->read_pos.len)
		return AVERROR_EOF;

	int len = buf_size;
	if (len > c->read_pos.len)
		len = c->read_pos.len;
	memcpy(buf, c->read_pos.s, len);
	str_shift(&c->read_pos, len);
	return len;
}
static int __mp_avio_read(void *opaque, uint8_t *buf, int buf_size) {
	ilog(LOG_DEBUG, "__mp_avio_read(%i)", buf_size);
	int ret = __mp_avio_read_wrap(opaque, buf, buf_size);
	ilog(LOG_DEBUG, "__mp_avio_read(%i) = %i", buf_size, ret);
	return ret;
}
static int64_t __mp_avio_seek_set(struct media_player_coder *c, int64_t offset) {
	ilog(LOG_DEBUG, "__mp_avio_seek_set(%" PRIi64 ")", offset);
	if (offset < 0)
		return AVERROR(EINVAL);
	c->read_pos = *c->blob;
	if (str_shift(&c->read_pos, offset))
		return AVERROR_EOF;
	return offset;
}
static int64_t __mp_avio_seek(void *opaque, int64_t offset, int whence) {
	ilog(LOG_DEBUG, "__mp_avio_seek(%" PRIi64 ", %i)", offset, whence);
	struct media_player_coder *c = opaque;
	if (whence == SEEK_SET)
		return __mp_avio_seek_set(c, offset);
	if (whence == SEEK_CUR)
		return __mp_avio_seek_set(c, ((int64_t) (c->read_pos.s - c->blob->s)) + offset);
	if (whence == SEEK_END)
		return __mp_avio_seek_set(c, ((int64_t) c->blob->len) + offset);
	return AVERROR(EINVAL);
}




// call->master_lock held in W
static mp_cached_code __media_player_init_blob_id(struct media_player *mp, const str *blob,
		media_player_opts_t opts,
		long long db_id, const rtp_payload_type *dst_pt)
{
	const char *err;
	int av_ret = 0;

	mp->opts = opts;

	if (db_id >= 0) {
		mp->cache_index.type = MP_DB;
		mp->cache_index.db_id = db_id;

		if (media_player_cache_get_entry(mp, dst_pt, opts.codec_set))
			return MPC_CACHED;
	}
	else {
		mp->cache_index.type = MP_BLOB;
		mp->cache_index.file = str_dup_str(blob);

		if (media_player_cache_get_entry(mp, dst_pt, opts.codec_set))
			return MPC_CACHED;
	}

	mp->coder.blob = str_dup(blob);
	err = "out of memory";
	if (!mp->coder.blob)
		goto err;
	mp->coder.read_pos = *mp->coder.blob;

	err = "could not allocate AVFormatContext";
	mp->coder.fmtctx = avformat_alloc_context();
	if (!mp->coder.fmtctx)
		goto err;

	void *avio_buf = av_malloc(DEFAULT_AVIO_BUFSIZE);
	err = "failed to allocate AVIO buffer";
	if (!avio_buf)
		goto err;

	mp->coder.avioctx = avio_alloc_context(avio_buf, DEFAULT_AVIO_BUFSIZE, 0, &mp->coder, __mp_avio_read,
			NULL, __mp_avio_seek);
	err = "failed to allocate AVIOContext";
	if (!mp->coder.avioctx)
		goto err;

	mp->coder.fmtctx->pb = mp->coder.avioctx;

	// consumes allocated mp->coder.fmtctx
	err = "failed to open AVFormatContext input";
	av_ret = avformat_open_input(&mp->coder.fmtctx, "dummy", NULL, NULL);
	if (av_ret < 0)
		goto err;

	return MPC_OK;

err:
	ilog(LOG_ERR, "Failed to start media playback from memory: %s", err);
	if (av_ret)
		ilog(LOG_ERR, "Error returned from libav: %s", av_error(av_ret));
	return MPC_ERR;
}


// call->master_lock held in W
bool media_player_play_blob(struct media_player *mp, const str *blob, media_player_opts_t opts) {
	const rtp_payload_type *dst_pt = media_player_play_init(mp);
	if (!dst_pt)
		return false;

	mp_cached_code ret = __media_player_init_blob_id(mp, blob, opts, -1, dst_pt);
	if (ret == MPC_CACHED)
		return true;
	if (ret == MPC_ERR)
		return false;

	return media_player_play_start(mp, dst_pt, opts.codec_set);
}

// call->master_lock held in W
bool media_player_init_blob(struct media_player *mp, const str *blob, media_player_opts_t opts) {
	int ret = __media_player_init_blob_id(mp, blob, opts, -1, NULL);
	return ret == 0;
}


static int __connect_db(void) {
	if (mysql_conn) {
		mysql_close(mysql_conn);
		mysql_conn = NULL;
	}
	mysql_conn = mysql_init(NULL);
	if (!mysql_conn)
		return -1;
	if (!mysql_real_connect(mysql_conn, rtpe_config.mysql_host, rtpe_config.mysql_user, rtpe_config.mysql_pass, NULL, rtpe_config.mysql_port,
			NULL, CLIENT_IGNORE_SIGPIPE))
		goto err;

	return 0;

err:
	ilog(LOG_ERR, "Couldn't connect to database: %s", mysql_error(mysql_conn));
	mysql_close(mysql_conn);
	mysql_conn = NULL;
	return -1;
}


// call->master_lock held in W
static mp_cached_code __media_player_init_db(struct media_player *mp, long long id, media_player_opts_t opts,
		const rtp_payload_type *dst_pt)
{
	const char *err;
	g_autoptr(char) query = NULL;

	err = "missing configuration";
	if (!rtpe_config.mysql_host || !rtpe_config.mysql_query)
		goto err;

	query = g_strdup_printf(rtpe_config.mysql_query, (unsigned long long) id);
	size_t len = strlen(query);

	for (int retries = 0; retries < 5; retries++) {
		if (!mysql_conn || retries != 0) {
			err = "failed to connect to database";
			if (__connect_db())
				goto err;
		}

		int ret = mysql_real_query(mysql_conn, query, len);
		if (ret == 0)
			goto success;

		ret = mysql_errno(mysql_conn);
		if (ret == CR_SERVER_GONE_ERROR || ret == CR_SERVER_LOST)
			continue;

		ilog(LOG_ERR, "Failed to query from database: %s", mysql_error(mysql_conn));
	}
	err = "exceeded max number of database retries";
	goto err;

success:;

	MYSQL_RES *res = mysql_store_result(mysql_conn);
	err = "failed to get result from database";
	if (!res)
		goto err;
	MYSQL_ROW row = mysql_fetch_row(res);
	unsigned long *lengths = mysql_fetch_lengths(res);
	err = "empty result from database";
	if (!row || !lengths || !row[0] || !lengths[0]) {
		mysql_free_result(res);
		goto err;
	}

	str blob = STR_LEN(row[0], lengths[0]);
	mp_cached_code ret = __media_player_init_blob_id(mp, &blob, opts, id, dst_pt);

	mysql_free_result(res);

	return ret;

err:
	if (query)
		ilog(LOG_ERR, "Failed to start media playback from database (used query '%s'): %s", query, err);
	else
		ilog(LOG_ERR, "Failed to start media playback from database: %s", err);
	return MPC_ERR;
}

// call->master_lock held in W
bool media_player_play_db(struct media_player *mp, long long id, media_player_opts_t opts) {
	const rtp_payload_type *dst_pt = media_player_play_init(mp);
	if (!dst_pt)
		return false;

	mp_cached_code ret = __media_player_init_db(mp, id, opts, dst_pt);
	if (ret == MPC_CACHED)
		return true;
	if (ret == MPC_ERR)
		return false;

	return media_player_play_start(mp, dst_pt, opts.codec_set);
}

// call->master_lock held in W
bool media_player_init_db(struct media_player *mp, long long id, media_player_opts_t opts) {
	int ret = __media_player_init_db(mp, id, opts, NULL);
	return ret == 0;
}


static void media_player_run(void *ptr) {
	struct media_player *mp = ptr;
	call_t *call = mp->call;

	log_info_media(mp->media);

	//ilog(LOG_DEBUG, "running scheduled media_player");

	rwlock_lock_r(&call->master_lock);
	mutex_lock(&mp->lock);

	bool finished = false;
	if (mp->next_run.tv_sec)
		finished = mp->run_func(mp);

	mutex_unlock(&mp->lock);
	rwlock_unlock_r(&call->master_lock);

	if (finished) {
		rwlock_lock_w(&call->master_lock);

		mp->next_run.tv_sec = 0;

		if (mp->opts.block_egress)
			MEDIA_CLEAR(mp->media, BLOCK_EGRESS);

		codec_update_all_source_handlers(mp->media->monologue, NULL);
		update_init_subscribers(mp->media->monologue, OP_PLAY_MEDIA);

		rwlock_unlock_w(&call->master_lock);
	}

	log_info_pop();
}


bool media_player_is_active(struct call_monologue *ml) {
	if (!ml)
		return false;
	if (!ml->player)
		return false;
	if (!ml->player->next_run.tv_sec)
		return false;
	return true;
}

static unsigned int media_player_cache_entry_hash(const void *p) {
	const struct media_player_cache_index *i = p;
	unsigned int ret;
	switch (i->index.type) {
		case MP_DB:
			ret = i->index.db_id;
			break;
		case MP_FILE:
		case MP_BLOB:
			ret = str_hash(&i->index.file);
			break;
		default:
			abort();
	}
	ret ^= str_hash(&i->dst_pt.encoding_with_full_params);
	ret ^= i->index.type;
	return ret;
}
static gboolean media_player_cache_entry_eq(const void *A, const void *B) {
	const struct media_player_cache_index *a = A, *b = B;
	if (a->index.type != b->index.type)
		return FALSE;
	switch (a->index.type) {
		case MP_DB:
			if (a->index.db_id != b->index.db_id)
				return FALSE;
			break;
		case MP_FILE:
		case MP_BLOB:
			if (!str_equal(&a->index.file, &b->index.file))
				return FALSE;
			break;
		default:
			abort();
	}
	return str_equal(&a->dst_pt.encoding_with_full_params, &b->dst_pt.encoding_with_full_params);
}
static void media_player_cache_index_free(void *p) {
	struct media_player_cache_index *i = p;
	g_free(i->index.file.s);
	payload_type_clear(&i->dst_pt);
	g_slice_free1(sizeof(*i), i);
}
static void media_player_cache_entry_free(void *p) {
	struct media_player_cache_entry *e = p;
	t_ptr_array_free(e->packets, true);
	mutex_destroy(&e->lock);
	g_free(e->info_str);
	if (t_hash_table_is_set(e->wait_queue))
		t_hash_table_destroy(e->wait_queue); // XXX release references?
	media_player_coder_shutdown(&e->coder);
	av_packet_free(&e->coder.pkt);
	kernel_free_packet_stream(e->kernel_idx);
	g_slice_free1(sizeof(*e), e);
}
#endif


// call->master_lock held in W
bool media_player_start(struct media_player *mp) {
#ifdef WITH_TRANSCODING
	if (!mp->coder.fmtctx) // initialised?
		return false;

	const rtp_payload_type *dst_pt = media_player_play_setup(mp);
	if (!dst_pt)
		return false;

	return media_player_play_start(mp, dst_pt, str_case_value_ht_null());
#else
	return false;
#endif
}

void media_player_init(void) {
#ifdef WITH_TRANSCODING
	if (rtpe_config.player_cache) {
		media_player_cache = g_hash_table_new_full(media_player_cache_entry_hash,
				media_player_cache_entry_eq, media_player_cache_index_free,
				media_player_cache_entry_free);
		mutex_init(&media_player_cache_lock);
	}

	timerthread_init(&media_player_thread, rtpe_config.media_num_threads, media_player_run);
#endif
	timerthread_init(&send_timer_thread, rtpe_config.media_num_threads, timerthread_queue_run);
}

void media_player_free(void) {
#ifdef WITH_TRANSCODING
	timerthread_free(&media_player_thread);

	if (media_player_cache) {
		mutex_destroy(&media_player_cache_lock);
		g_hash_table_destroy(media_player_cache);
	}
#endif
	timerthread_free(&send_timer_thread);
}


void media_player_launch(void) {
#ifdef WITH_TRANSCODING
	timerthread_launch(&media_player_thread, rtpe_config.scheduling, rtpe_config.priority, "media player");
#endif
}
void send_timer_launch(void) {
	//ilog(LOG_DEBUG, "send_timer_loop");
	timerthread_launch(&send_timer_thread, rtpe_config.scheduling, rtpe_config.priority, "media player");
}
