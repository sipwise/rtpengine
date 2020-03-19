#ifndef _MEDIA_PLAYER_H_
#define _MEDIA_PLAYER_H_


#include "auxlib.h"
#include "timerthread.h"
#include "str.h"



struct call;
struct call_media;
struct call_monologue;
struct codec_handler;
struct ssrc_ctx;
struct packet_stream;
struct codec_packet;
struct media_player;
struct rtp_payload_type;


#ifdef WITH_TRANSCODING

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>


typedef void (*media_player_run_func)(struct media_player *);


struct media_player {
	struct timerthread_obj tt_obj;
	mutex_t lock;
	media_player_run_func run_func;
	struct call *call;
	struct call_monologue *ml;
	struct call_media *media;
	struct packet_stream *sink;
	const struct streamhandler *crypt_handler;

	struct timeval next_run;

	AVFormatContext *fmtctx;
	unsigned long duration; // in milliseconds
	AVPacket pkt;
	struct codec_handler *handler;
	struct ssrc_ctx *ssrc_out;
	unsigned long seq;
	unsigned long sync_ts;
	struct timeval sync_ts_tv;

	AVIOContext *avioctx;
	str *blob;
	str read_pos;
};

INLINE void media_player_put(struct media_player **mp) {
	if (!*mp)
		return;
	obj_put(&(*mp)->tt_obj);
	*mp = NULL;
}

#else

INLINE void media_player_put(struct media_player **mp) {
}

#endif

struct send_timer {
	struct timerthread_queue ttq;
	struct call *call; // main reference that keeps this alive
	struct packet_stream *sink;
};


struct media_player *media_player_new(struct call_monologue *);
int media_player_play_file(struct media_player *, const str *);
int media_player_play_blob(struct media_player *, const str *);
int media_player_play_db(struct media_player *, long long);
void media_player_stop(struct media_player *);

int media_player_setup(struct media_player *mp, const struct rtp_payload_type *src_pt);
void media_player_set_media(struct media_player *mp, struct call_media *media);
void media_player_add_packet(struct media_player *mp, char *buf, size_t len,
		long long us_dur, unsigned long long pts);

void media_player_init(void);
void media_player_loop(void *);

struct send_timer *send_timer_new(struct packet_stream *);
void send_timer_push(struct send_timer *, struct codec_packet *);

void send_timer_loop(void *p);



INLINE void send_timer_put(struct send_timer **st) {
	if (!*st)
		return;
	obj_put(&(*st)->ttq.tt_obj);
	*st = NULL;
}


#endif
