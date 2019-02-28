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



static struct timerthread media_player_thread;



// appropriate lock must be held
static void media_player_shutdown(struct media_player *mp) {
	ilog(LOG_DEBUG, "shutting down media_player");
	timerthread_obj_deschedule(&mp->tt_obj);
	avformat_free_context(mp->fmtctx);
	mp->fmtctx = NULL;
	mp->media = NULL;
	if (mp->handler)
		codec_handler_free(mp->handler);
	mp->handler = NULL;
	if (mp->ssrc_out)
		obj_put(&mp->ssrc_out->parent->h);
	mp->ssrc_out = NULL;
}


void media_player_stop(struct media_player *mp) {
	media_player_shutdown(mp);
}


static void __media_player_free(void *p) {
	struct media_player *mp = p;

	ilog(LOG_DEBUG, "freeing media_player");

	media_player_shutdown(mp);
	mutex_destroy(&mp->lock);
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
int media_player_play_file(struct media_player *mp, const str *file) {
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

	char file_s[PATH_MAX];
	snprintf(file_s, sizeof(file_s), STR_FORMAT, STR_FMT(file));

	int ret = avformat_open_input(&mp->fmtctx, file_s, NULL, NULL);
	if (ret < 0)
		return -1;

	// start playback now

	mp->next_run = rtpe_now;
	media_player_read_packet(mp);

	return 0;
}


static void media_player_run(void *ptr) {
	struct media_player *mp = ptr;
	struct call *call = mp->call;

	ilog(LOG_DEBUG, "running scheduled media_player");

	rwlock_lock_r(&call->master_lock);
	mutex_lock(&mp->lock);

	media_player_read_packet(mp);

	mutex_unlock(&mp->lock);
	rwlock_unlock_r(&call->master_lock);
}


void media_player_init(void) {
	timerthread_init(&media_player_thread, media_player_run);
}


void media_player_loop(void *p) {
	ilog(LOG_DEBUG, "media_player_loop");
	timerthread_run(&media_player_thread);
}
