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



#define DEFAULT_AVIO_BUFSIZE 4096



#ifdef WITH_TRANSCODING
static struct timerthread media_player_thread;
static MYSQL __thread *mysql_conn;
#endif
static struct timerthread send_timer_thread;



static void send_timer_send_nolock(struct send_timer *st, struct codec_packet *cp);
static void send_timer_send_lock(struct send_timer *st, struct codec_packet *cp);



#ifdef WITH_TRANSCODING
// called with call->master lock in W
static unsigned int send_timer_flush(struct send_timer *st, void *ptr) {
	return timerthread_queue_flush(&st->ttq, ptr);
}


// called with call->master lock in W
static void media_player_shutdown(struct media_player *mp) {
	if (!mp)
		return;

	ilog(LOG_DEBUG, "shutting down media_player");
	timerthread_obj_deschedule(&mp->tt_obj);
	avformat_close_input(&mp->fmtctx);

	if (mp->sink) {
		unsigned int num = send_timer_flush(mp->sink->send_timer, mp->handler);
		ilog(LOG_DEBUG, "%u packets removed from send queue", num);
		// roll back seq numbers already used
		mp->ssrc_out->parent->seq_diff -= num;
	}

	mp->media = NULL;
	if (mp->handler)
		codec_handler_free(mp->handler);
	mp->handler = NULL;
	if (mp->avioctx) {
		if (mp->avioctx->buffer)
			av_freep(&mp->avioctx->buffer);
		av_freep(&mp->avioctx);
	}
	if (mp->blob)
		free(mp->blob);
	mp->blob = NULL;
	mp->read_pos = STR_NULL;
}
#endif


void media_player_stop(struct media_player *mp) {
#ifdef WITH_TRANSCODING
	media_player_shutdown(mp);
#endif
}


#ifdef WITH_TRANSCODING
static void __media_player_free(void *p) {
	struct media_player *mp = p;

	ilog(LOG_DEBUG, "freeing media_player");

	media_player_shutdown(mp);
	if (mp->ssrc_out)
		obj_put(&mp->ssrc_out->parent->h);
	mp->ssrc_out = NULL;
	mutex_destroy(&mp->lock);
	obj_put(mp->call);
}
#endif


// call->master_lock held in W
struct media_player *media_player_new(struct call_monologue *ml) {
#ifdef WITH_TRANSCODING
	ilog(LOG_DEBUG, "creating media_player");

	uint32_t ssrc = 0;
	while (ssrc == 0)
		ssrc = random();
	struct ssrc_ctx *ssrc_ctx = get_ssrc_ctx(ssrc, ml->call->ssrc_hash, SSRC_DIR_OUTPUT);

	struct media_player *mp = obj_alloc0("media_player", sizeof(*mp), __media_player_free);

	mp->tt_obj.tt = &media_player_thread;
	mutex_init(&mp->lock);
	mp->call = obj_get(ml->call);
	mp->ml = ml;
	mp->seq = random();
	mp->ssrc_out = ssrc_ctx;

	av_init_packet(&mp->pkt);
	mp->pkt.data = NULL;
	mp->pkt.size = 0;

	return mp;
#else
	return NULL;
#endif
}


static void __send_timer_free(void *p) {
	struct send_timer *st = p;

	ilog(LOG_DEBUG, "freeing send_timer");

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
	ilog(LOG_DEBUG, "creating send_timer");

	struct send_timer *st = timerthread_queue_new("send_timer", sizeof(*st),
			&send_timer_thread,
			__send_timer_send_now,
			__send_timer_send_later,
			__send_timer_free, codec_packet_free);
	st->call = obj_get(ps->call);
	st->sink = ps;

	return st;
}


static void __send_timer_send_common(struct send_timer *st, struct codec_packet *cp) {
	if (!st->sink->selected_sfd)
		goto out;

	struct rtp_header *rh = (void *) cp->s.s;
	ilog(LOG_DEBUG, "Forward to sink endpoint: %s%s:%d%s (RTP seq %u TS %u)",
			FMT_M(sockaddr_print_buf(&st->sink->endpoint.address),
			st->sink->endpoint.port),
			ntohs(rh->seq_num),
			ntohl(rh->timestamp));

	socket_sendto(&st->sink->selected_sfd->socket,
			cp->s.s, cp->s.len, &st->sink->endpoint);

out:
	codec_packet_free(cp);
}

static void send_timer_send_lock(struct send_timer *st, struct codec_packet *cp) {
	struct call *call = st->call;
	if (!call)
		return;

	log_info_call(call);
	rwlock_lock_r(&call->master_lock);

	__send_timer_send_common(st, cp);

	rwlock_unlock_r(&call->master_lock);

}
// st->stream->out_lock (or call->master_lock/W) must be held already
static void send_timer_send_nolock(struct send_timer *st, struct codec_packet *cp) {
	struct call *call = st->call;
	if (!call)
		return;

	log_info_call(call);

	__send_timer_send_common(st, cp);
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

static int __ensure_codec_handler(struct media_player *mp, AVStream *avs) {
	if (mp->handler)
		return 0;

	// synthesise rtp payload type
	struct rtp_payload_type src_pt = { .payload_type = -1 };
	// src_pt.codec_def = codec_find_by_av(avs->codec->codec_id);  `codec` is deprecated
	src_pt.codec_def = codec_find_by_av(avs->CODECPAR->codec_id);
	if (!src_pt.codec_def) {
		ilog(LOG_ERR, "Attempting to play media from an unsupported file format/codec");
		return -1;
	}
	src_pt.encoding = src_pt.codec_def->rtpname_str;
	src_pt.channels = avs->CODECPAR->channels;
	src_pt.clock_rate = avs->CODECPAR->sample_rate;
	codec_init_payload_type(&src_pt, mp->media);

	// find suitable output payload type
	struct rtp_payload_type *dst_pt;
	for (GList *l = mp->media->codecs_prefs_send.head; l; l = l->next) {
		dst_pt = l->data;
		if (dst_pt->codec_def && !dst_pt->codec_def->supplemental)
			goto found;
	}
	dst_pt = NULL;
found:
	if (!dst_pt) {
		ilog(LOG_ERR, "No supported output codec found in SDP");
		return -1;
	}
	ilog(LOG_DEBUG, "Output codec for media playback is " STR_FORMAT,
			STR_FMT(&dst_pt->encoding_with_params));

	// if we played anything before, scale our sync TS according to the time
	// that has passed
	if (mp->sync_ts_tv.tv_sec) {
		long long ts_diff_us = timeval_diff(&rtpe_now, &mp->sync_ts_tv);
		mp->sync_ts += ts_diff_us * dst_pt->clock_rate / 1000000 / dst_pt->codec_def->clockrate_mult;
	}

	mp->handler = codec_handler_make_playback(&src_pt, dst_pt, mp->sync_ts);
	if (!mp->handler)
		return -1;

	mp->duration = avs->duration * 1000 * avs->time_base.num / avs->time_base.den;

	return 0;
}


// appropriate lock must be held
static void media_player_read_packet(struct media_player *mp) {
	if (!mp->fmtctx)
		return;

	int ret = av_read_frame(mp->fmtctx, &mp->pkt);
	if (ret < 0) {
		if (ret == AVERROR_EOF) {
			ilog(LOG_DEBUG, "EOF reading from media stream");
			return;
		}
		ilog(LOG_ERR, "Error while reading from media stream");
		return;
	}

	if (!mp->fmtctx->streams) {
		ilog(LOG_ERR, "No AVStream present in format context");
		goto out;
	}

	AVStream *avs = mp->fmtctx->streams[0];
	if (!avs) {
		ilog(LOG_ERR, "No AVStream present in format context");
		goto out;
	}

	if (__ensure_codec_handler(mp, avs))
		goto out;

	// scale pts and duration according to sample rate

	long long duration_scaled = mp->pkt.duration * avs->CODECPAR->sample_rate
		* avs->time_base.num / avs->time_base.den;
	unsigned long long pts_scaled = mp->pkt.pts * avs->CODECPAR->sample_rate
		* avs->time_base.num / avs->time_base.den;

	long long us_dur = mp->pkt.duration * 1000000LL * avs->time_base.num / avs->time_base.den;
	ilog(LOG_DEBUG, "read media packet: pts %llu duration %lli (scaled %llu/%lli, %lli us), "
			"sample rate %i, time_base %i/%i",
			(unsigned long long) mp->pkt.pts,
			(long long) mp->pkt.duration,
			pts_scaled,
			duration_scaled,
			us_dur,
			avs->CODECPAR->sample_rate,
			avs->time_base.num, avs->time_base.den);

	// synthesise fake RTP header and media_packet context

	struct rtp_header rtp = {
		.timestamp = pts_scaled, // taken verbatim by handler_func_playback w/o byte swap
		.seq_num = htons(mp->seq),
	};
	struct media_packet packet = {
		.tv = rtpe_now,
		.call = mp->call,
		.media = mp->media,
		.rtp = &rtp,
		.ssrc_out = mp->ssrc_out,
	};
	str_init_len(&packet.raw, (char *) mp->pkt.data, mp->pkt.size);
	packet.payload = packet.raw;

	mp->handler->func(mp->handler, &packet);

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

out:
	av_packet_unref(&mp->pkt);
}


// call->master_lock held in W
static int media_player_play_init(struct media_player *mp) {
	media_player_shutdown(mp);

	// find call media suitable for playback
	struct call_media *media;
	for (GList *l = mp->ml->medias.head; l; l = l->next) {
		media = l->data;
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
		return -1;
	}
	mp->media = media;
	mp->sink = media->streams.head->data;
	mp->crypt_handler = determine_handler(&transport_protocols[PROTO_RTP_AVP], media, 1);

	return 0;
}


// call->master_lock held in W
static void media_player_play_start(struct media_player *mp) {
	// needed to have usable duration for some formats. ignore errors.
	avformat_find_stream_info(mp->fmtctx, NULL);

	mp->next_run = rtpe_now;
	// give ourselves a bit of a head start with decoding
	timeval_add_usec(&mp->next_run, -50000);
	media_player_read_packet(mp);
}
#endif


// call->master_lock held in W
int media_player_play_file(struct media_player *mp, const str *file) {
#ifdef WITH_TRANSCODING
	if (media_player_play_init(mp))
		return -1;

	char file_s[PATH_MAX];
	snprintf(file_s, sizeof(file_s), STR_FORMAT, STR_FMT(file));

	int ret = avformat_open_input(&mp->fmtctx, file_s, NULL, NULL);
	if (ret < 0) {
		ilog(LOG_ERR, "Failed to open media file for playback: %s", av_error(ret));
		return -1;
	}

	media_player_play_start(mp);

	return 0;
#else
	return -1;
#endif
}


#ifdef WITH_TRANSCODING
static int __mp_avio_read_wrap(void *opaque, uint8_t *buf, int buf_size) {
	struct media_player *mp = opaque;
	if (buf_size < 0)
		return AVERROR(EINVAL);
	if (buf_size == 0)
		return 0;
	if (!mp->read_pos.len)
		return AVERROR_EOF;

	int len = buf_size;
	if (len > mp->read_pos.len)
		len = mp->read_pos.len;
	memcpy(buf, mp->read_pos.s, len);
	str_shift(&mp->read_pos, len);
	return len;
}
static int __mp_avio_read(void *opaque, uint8_t *buf, int buf_size) {
	ilog(LOG_DEBUG, "__mp_avio_read(%i)", buf_size);
	int ret = __mp_avio_read_wrap(opaque, buf, buf_size);
	ilog(LOG_DEBUG, "__mp_avio_read(%i) = %i", buf_size, ret);
	return ret;
}
static int64_t __mp_avio_seek_set(struct media_player *mp, int64_t offset) {
	ilog(LOG_DEBUG, "__mp_avio_seek_set(%" PRIi64 ")", offset);
	if (offset < 0)
		return AVERROR(EINVAL);
	mp->read_pos = *mp->blob;
	if (str_shift(&mp->read_pos, offset))
		return AVERROR_EOF;
	return offset;
}
static int64_t __mp_avio_seek(void *opaque, int64_t offset, int whence) {
	ilog(LOG_DEBUG, "__mp_avio_seek(%" PRIi64 ", %i)", offset, whence);
	struct media_player *mp = opaque;
	if (whence == SEEK_SET)
		return __mp_avio_seek_set(mp, offset);
	if (whence == SEEK_CUR)
		return __mp_avio_seek_set(mp, ((int64_t) (mp->read_pos.s - mp->blob->s)) + offset);
	if (whence == SEEK_END)
		return __mp_avio_seek_set(mp, ((int64_t) mp->blob->len) + offset);
	return AVERROR(EINVAL);
}
#endif



// call->master_lock held in W
int media_player_play_blob(struct media_player *mp, const str *blob) {
#ifdef WITH_TRANSCODING
	const char *err;
	int av_ret = 0;

	if (media_player_play_init(mp))
		return -1;

	mp->blob = str_dup(blob);
	err = "out of memory";
	if (!mp->blob)
		goto err;
	mp->read_pos = *mp->blob;

	err = "could not allocate AVFormatContext";
	mp->fmtctx = avformat_alloc_context();
	if (!mp->fmtctx)
		goto err;

	void *avio_buf = av_malloc(DEFAULT_AVIO_BUFSIZE);
	err = "failed to allocate AVIO buffer";
	if (!avio_buf)
		goto err;

	mp->avioctx = avio_alloc_context(avio_buf, DEFAULT_AVIO_BUFSIZE, 0, mp, __mp_avio_read,
			NULL, __mp_avio_seek);
	err = "failed to allocate AVIOContext";
	if (!mp->avioctx)
		goto err;

	mp->fmtctx->pb = mp->avioctx;

	// consumes allocated mp->fmtctx
	err = "failed to open AVFormatContext input";
	av_ret = avformat_open_input(&mp->fmtctx, "dummy", NULL, NULL);
	if (av_ret < 0)
		goto err;

	media_player_play_start(mp);

	return 0;

err:
	ilog(LOG_ERR, "Failed to start media playback from memory: %s", err);
	if (av_ret)
		ilog(LOG_ERR, "Error returned from libav: %s", av_error(av_ret));
#endif
	return -1;
}


#ifdef WITH_TRANSCODING
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
int media_player_play_db(struct media_player *mp, long long id) {
	const char *err;
	AUTO_CLEANUP_BUF(query);

	err = "missing configuration";
	if (!rtpe_config.mysql_host || !rtpe_config.mysql_query)
		goto err;

	int len = asprintf(&query, rtpe_config.mysql_query, (unsigned long long) id);
	err = "query print error";
	if (len <= 0)
		goto err;

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

	str blob;
	str_init_len(&blob, row[0], lengths[0]);
	int ret = media_player_play_blob(mp, &blob);

	mysql_free_result(res);

	return ret;

err:
	if (query)
		ilog(LOG_ERR, "Failed to start media playback from database (used query '%s'): %s", query, err);
	else
		ilog(LOG_ERR, "Failed to start media playback from database: %s", err);
	return -1;
}


static void media_player_run(void *ptr) {
	struct media_player *mp = ptr;
	struct call *call = mp->call;

	log_info_call(call);

	ilog(LOG_DEBUG, "running scheduled media_player");

	rwlock_lock_r(&call->master_lock);
	mutex_lock(&mp->lock);

	media_player_read_packet(mp);

	mutex_unlock(&mp->lock);
	rwlock_unlock_r(&call->master_lock);

	log_info_clear();
}
#endif


void media_player_init(void) {
#ifdef WITH_TRANSCODING
	timerthread_init(&media_player_thread, media_player_run);
#endif
	timerthread_init(&send_timer_thread, timerthread_queue_run);
}


#ifdef WITH_TRANSCODING
void media_player_loop(void *p) {
	ilog(LOG_DEBUG, "media_player_loop");
	timerthread_run(&media_player_thread);
}
#endif
void send_timer_loop(void *p) {
	ilog(LOG_DEBUG, "send_timer_loop");
	timerthread_run(&send_timer_thread);
}
