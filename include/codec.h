#ifndef __CODEC_H__
#define __CODEC_H__


#include <glib.h>
#include <sys/time.h>
#include <stdbool.h>
#include "str.h"
#include "codeclib.h"
#include "aux.h"
#include "rtplib.h"
#include "timerthread.h"


struct call_media;
struct codec_handler;
struct media_packet;
struct ssrc_hash;
struct sdp_ng_flags;
struct codec_ssrc_handler;
struct rtp_header;
struct stream_params;
struct supp_codec_tracker;
struct rtcp_timer;
struct mqtt_timer;
struct call;
struct codec_store;
struct call_monologue;
struct delay_buffer;
struct sink_handler;


typedef int codec_handler_func(struct codec_handler *, struct media_packet *);


struct codec_handler {
	struct rtp_payload_type source_pt; // source_pt.payload_type = hashtable index
	struct rtp_payload_type dest_pt;
	int dtmf_payload_type;
	int real_dtmf_payload_type;
	int cn_payload_type;
	codec_handler_func *handler_func;
	unsigned int passthrough:1;
	unsigned int kernelize:1;
	unsigned int transcoder:1;
	unsigned int pcm_dtmf_detect:1;

	struct ssrc_hash *ssrc_hash;
	struct codec_handler *input_handler; // == main handler for supp codecs
	struct codec_handler *output_handler; // == self, or other PT handler
	struct call_media *media;
	struct call_media *sink;
#ifdef WITH_TRANSCODING
	int (*packet_encoded)(encoder_t *enc, void *u1, void *u2);
	int (*packet_decoded)(decoder_t *, AVFrame *, void *, void *);
#endif

	// for media playback
	struct codec_ssrc_handler *ssrc_handler;
	// for DTMF injection
	struct codec_handler *dtmf_injector;
	struct delay_buffer *delay_buffer;

	// stats entry
	char *stats_chain;
	struct codec_stats *stats_entry;
};

struct codec_packet {
	struct timerthread_queue_entry ttq_entry;
	str s;
	struct rtp_header *rtp;
	unsigned long ts;
	unsigned int clockrate;
	struct ssrc_ctx *ssrc_out;
	void (*free_func)(void *);
};

struct codec_scheduler {
	unsigned long first_ts; // for output TS scaling
	unsigned long last_ts; // to detect input lag and handle lost packets
	struct timeval first_send;
	unsigned long first_send_ts;
	long output_skew;
};


void codecs_init(void);
void codecs_cleanup(void);
void codec_timers_loop(void *);
void rtcp_timer_stop(struct rtcp_timer **);
void codec_timer_callback(struct call *, void (*)(struct call *, void *), void *, uint64_t delay);

void mqtt_timer_stop(struct mqtt_timer **);
void mqtt_timer_start(struct mqtt_timer **mqtp, struct call *call, struct call_media *media);

struct codec_handler *codec_handler_get(struct call_media *, int payload_type, struct call_media *sink,
		struct sink_handler *);
void codec_handlers_free(struct call_media *);
struct codec_handler *codec_handler_make_playback(const struct rtp_payload_type *src_pt,
		const struct rtp_payload_type *dst_pt, unsigned long ts, struct call_media *);
struct codec_handler *codec_handler_make_dummy(const struct rtp_payload_type *dst_pt, struct call_media *media);
void codec_calc_jitter(struct ssrc_ctx *, unsigned long ts, unsigned int clockrate, const struct timeval *);
void codec_update_all_handlers(struct call_monologue *ml);

void codec_store_cleanup(struct codec_store *cs);
void codec_store_init(struct codec_store *cs, struct call_media *);
void codec_store_populate(struct codec_store *, struct codec_store *, GHashTable *, bool answer_only);
void codec_store_populate_reuse(struct codec_store *, struct codec_store *, GHashTable *, bool answer_only);
void codec_store_add_raw(struct codec_store *cs, struct rtp_payload_type *pt);
void codec_store_strip(struct codec_store *, GQueue *strip, GHashTable *except);
void codec_store_offer(struct codec_store *, GQueue *, struct codec_store *);
void codec_store_check_empty(struct codec_store *, struct codec_store *);
void codec_store_accept(struct codec_store *, GQueue *, struct codec_store *);
int codec_store_accept_one(struct codec_store *, GQueue *, bool accept_any);
void codec_store_track(struct codec_store *, GQueue *);
void codec_store_transcode(struct codec_store *, GQueue *, struct codec_store *);
void codec_store_answer(struct codec_store *dst, struct codec_store *src, struct sdp_ng_flags *flags);
void codec_store_synthesise(struct codec_store *dst, struct codec_store *opposite);
bool codec_store_is_full_answer(const struct codec_store *src, const struct codec_store *dst);

void codec_add_raw_packet(struct media_packet *mp, unsigned int clockrate);
void codec_packet_free(void *);
struct codec_packet *codec_packet_dup(struct codec_packet *p);
bool codec_packet_copy(struct codec_packet *p);

void payload_type_free(struct rtp_payload_type *p);
void payload_type_destroy(struct rtp_payload_type **p);
struct rtp_payload_type *rtp_payload_type_dup(const struct rtp_payload_type *pt);

// special return value `(void *) 0x1` to signal type mismatch
struct rtp_payload_type *codec_make_payload_type(const str *codec_str, enum media_type);

// handle string allocation
void codec_init_payload_type(struct rtp_payload_type *, enum media_type);
void payload_type_clear(struct rtp_payload_type *p);



#ifdef WITH_TRANSCODING

void ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media);
void codec_handler_free(struct codec_handler **handler);
bool codec_handlers_update(struct call_media *receiver, struct call_media *sink, const struct sdp_ng_flags *,
		const struct stream_params *);
void codec_add_dtmf_event(struct codec_ssrc_handler *ch, int code, int level, uint64_t ts);
uint64_t codec_last_dtmf_event(struct codec_ssrc_handler *ch);
uint64_t codec_encoder_pts(struct codec_ssrc_handler *ch);
void codec_decoder_skip_pts(struct codec_ssrc_handler *ch, uint64_t);
uint64_t codec_decoder_unskip_pts(struct codec_ssrc_handler *ch);
void codec_tracker_update(struct codec_store *);
void codec_handlers_stop(GQueue *);


void packet_encoded_packetize(encoder_t *enc, struct codec_ssrc_handler *ch, struct media_packet *mp,
		void (*fn)(encoder_t *, struct codec_ssrc_handler *, struct media_packet *, str *,
			char *, unsigned int));
void codec_output_rtp(struct media_packet *mp, struct codec_scheduler *,
		struct codec_handler *handler, // normally == ch->handler except for DTMF
		char *buf, // malloc'd, room for rtp_header + filled-in payload
		unsigned int payload_len,
		unsigned long payload_ts,
		int marker, int seq, int seq_inc, int payload_type,
		unsigned long ts_delay);

#else

INLINE bool codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, const struct stream_params *sp)
{
	return false;
}
INLINE void codec_handler_free(struct codec_handler **handler) { }
INLINE void codec_tracker_update(struct codec_store *cs) { }
INLINE void codec_handlers_stop(GQueue *q) { }
INLINE void ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media) { }

#endif



#endif
