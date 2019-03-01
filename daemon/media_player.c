#include "media_player.h"
#include <glib.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
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



#define DEFAULT_AVIO_BUFSIZE 4096



static struct timerthread media_player_thread;
static struct timerthread send_timer_thread;



// appropriate lock must be held
static void media_player_shutdown(struct media_player *mp) {
	ilog(LOG_DEBUG, "shutting down media_player");
	timerthread_obj_deschedule(&mp->tt_obj);
	avformat_close_input(&mp->fmtctx);
	mp->media = NULL;
	if (mp->handler)
		codec_handler_free(mp->handler);
	mp->handler = NULL;
	if (mp->ssrc_out)
		obj_put(&mp->ssrc_out->parent->h);
	mp->ssrc_out = NULL;
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


void media_player_stop(struct media_player *mp) {
	media_player_shutdown(mp);
}


static void __media_player_free(void *p) {
	struct media_player *mp = p;

	ilog(LOG_DEBUG, "freeing media_player");

	media_player_shutdown(mp);
	mutex_destroy(&mp->lock);
	obj_put(mp->call);
}


// call->master_lock held in W
struct media_player *media_player_new(struct call_monologue *ml) {
	ilog(LOG_DEBUG, "creating media_player");

	struct media_player *mp = obj_alloc0("media_player", sizeof(*mp), __media_player_free);

	mp->tt_obj.tt = &media_player_thread;
	mutex_init(&mp->lock);
	mp->call = obj_get(ml->call);
	mp->ml = ml;
	mp->seq = random();

	av_init_packet(&mp->pkt);
	mp->pkt.data = NULL;
	mp->pkt.size = 0;

	return mp;
}


static void __send_timer_free(void *p) {
	struct send_timer *st = p;

	ilog(LOG_DEBUG, "freeing send_timer");

	g_queue_clear_full(&st->packets, codec_packet_free);
	mutex_destroy(&st->lock);
	obj_put(st->call);
}


// call->master_lock held in W
struct send_timer *send_timer_new(struct packet_stream *ps) {
	ilog(LOG_DEBUG, "creating send_timer");

	struct send_timer *st = obj_alloc0("send_timer", sizeof(*st), __send_timer_free);
	st->tt_obj.tt = &send_timer_thread;
	mutex_init(&st->lock);
	st->call = obj_get(ps->call);
	st->sink = ps;
	g_queue_init(&st->packets);

	return st;
}


// st->stream->out_lock (or call->master_lock/W) must be held already
static int send_timer_send(struct send_timer *st, struct codec_packet *cp) {
	if (cp->to_send.tv_sec && timeval_cmp(&cp->to_send, &rtpe_now) > 0)
		return -1; // not yet

	__C_DBG("Forward to sink endpoint: %s:%d", sockaddr_print_buf(&st->sink->endpoint.address),
			st->sink->endpoint.port);

	socket_sendto(&st->sink->selected_sfd->socket,
			cp->s.s, cp->s.len, &st->sink->endpoint);

	codec_packet_free(cp);

	return 0;
}


// st->stream->out_lock (or call->master_lock/W) must be held already
void send_timer_push(struct send_timer *st, struct codec_packet *cp) {
	// can we send immediately?
	if (!send_timer_send(st, cp))
		return;

	// queue for sending

	mutex_lock(&st->lock);
	unsigned int qlen = st->packets.length;
	// this hands over ownership of cp, so we must copy the timeval out
	struct timeval tv_send = cp->to_send;
	g_queue_push_tail(&st->packets, cp);
	mutex_unlock(&st->lock);

	// first packet in? we're probably not scheduled yet
	if (!qlen)
		timerthread_obj_schedule_abs(&st->tt_obj, &tv_send);
}


static int __ensure_codec_handler(struct media_player *mp, AVStream *avs) {
	if (mp->handler)
		return 0;

	// synthesise rtp payload type
	struct rtp_payload_type src_pt = { .payload_type = -1 };
	// src_pt.codec_def = codec_find_by_av(avs->codec->codec_id);  `codec` is deprecated
	src_pt.codec_def = codec_find_by_av(avs->codecpar->codec_id);
	if (!src_pt.codec_def) {
		ilog(LOG_ERR, "Attempting to play media from an unsupported file format/codec");
		return -1;
	}
	src_pt.encoding = src_pt.codec_def->rtpname_str;
	src_pt.channels = avs->codecpar->channels;
	src_pt.clock_rate = avs->codecpar->sample_rate;
	codec_init_payload_type(&src_pt, mp->media);

	// find suitable output payload type
	struct rtp_payload_type *dst_pt;
	for (GList *l = mp->media->codecs_prefs_send.head; l; l = l->next) {
		dst_pt = l->data;
		if (dst_pt->codec_def && !dst_pt->codec_def->pseudocodec)
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

	mp->handler = codec_handler_make_playback(&src_pt, dst_pt);
	if (!mp->handler)
		return -1;
	mp->ssrc_out = get_ssrc_ctx(random(), mp->call->ssrc_hash, SSRC_DIR_OUTPUT);
	if (!mp->ssrc_out)
		return -1;

	return 0;
}


// appropriate lock must be held
static void media_player_read_packet(struct media_player *mp) {
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

	long long duration_scaled = mp->pkt.duration * avs->codecpar->sample_rate
		* avs->time_base.num / avs->time_base.den;
	unsigned long long pts_scaled = mp->pkt.pts * avs->codecpar->sample_rate
		* avs->time_base.num / avs->time_base.den;

	long long us_dur = mp->pkt.duration * 1000000LL * avs->time_base.num / avs->time_base.den;
	ilog(LOG_DEBUG, "read media packet: pts %llu duration %lli (scaled %llu/%lli, %lli us), "
			"sample rate %i, time_base %i/%i",
			(unsigned long long) mp->pkt.pts,
			(long long) mp->pkt.duration,
			pts_scaled,
			duration_scaled,
			us_dur,
			avs->codecpar->sample_rate,
			avs->time_base.num, avs->time_base.den);

	// synthesise fake RTP header and media_packet context

	struct rtp_header rtp = {
		.timestamp = pts_scaled, // taken verbatim by handler_func_playback w/o byte swap
		.seq_num = htons(mp->seq++),
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

	return 0;
}


// call->master_lock held in W
static void media_player_play_start(struct media_player *mp) {
	mp->next_run = rtpe_now;
	// give ourselves a bit of a head start with decoding
	timeval_add_usec(&mp->next_run, -50000);
	media_player_read_packet(mp);
}


// call->master_lock held in W
int media_player_play_file(struct media_player *mp, const str *file) {
	if (media_player_play_init(mp))
		return -1;

	char file_s[PATH_MAX];
	snprintf(file_s, sizeof(file_s), STR_FORMAT, STR_FMT(file));

	int ret = avformat_open_input(&mp->fmtctx, file_s, NULL, NULL);
	if (ret < 0)
		return -1;

	media_player_play_start(mp);

	return 0;
}


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

// call->master_lock held in W
int media_player_play_blob(struct media_player *mp, const str *blob) {
	const char *err;

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
	int ret = avformat_open_input(&mp->fmtctx, "dummy", NULL, NULL);
	if (ret < 0)
		return -1;

	media_player_play_start(mp);

	return 0;

err:
	ilog(LOG_ERR, "Failed to start media playback from memory: %s", err);
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


static void send_timer_run(void *ptr) {
	struct send_timer *st = ptr;
	struct call *call = st->call;

	log_info_call(call);

	ilog(LOG_DEBUG, "running scheduled send_timer");

	struct timeval next_send = {0,};

	rwlock_lock_r(&call->master_lock);
	mutex_lock(&st->lock);

	while (st->packets.length) {
		struct codec_packet *cp = st->packets.head->data;
		// XXX this could be made lock-free
		if (!send_timer_send(st, cp)) {
			g_queue_pop_head(&st->packets);
			continue;
		}
		// couldn't send the last one. remember time to schedule
		next_send = cp->to_send;
		break;
	}

	mutex_unlock(&st->lock);
	rwlock_unlock_r(&call->master_lock);

	if (next_send.tv_sec)
		timerthread_obj_schedule_abs(&st->tt_obj, &next_send);

	log_info_clear();
}


void media_player_init(void) {
	timerthread_init(&media_player_thread, media_player_run);
	timerthread_init(&send_timer_thread, send_timer_run);
}


void media_player_loop(void *p) {
	ilog(LOG_DEBUG, "media_player_loop");
	timerthread_run(&media_player_thread);
}
void send_timer_loop(void *p) {
	ilog(LOG_DEBUG, "send_timer_loop");
	timerthread_run(&send_timer_thread);
}
