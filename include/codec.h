#ifndef __CODEC_H__
#define __CODEC_H__

#include <glib.h>
#include <sys/time.h>
#include <stdbool.h>

#include "str.h"
#include "codeclib.h"
#include "helpers.h"
#include "rtplib.h"
#include "timerthread.h"
#include "types.h"

struct call_media;
struct codec_handler;
struct media_packet;
struct ssrc_hash;
struct codec_ssrc_handler;
struct rtp_header;
struct stream_params;
struct supp_codec_tracker;
struct rtcp_timer;
struct mqtt_timer;
struct codec_store;
struct call_monologue;
struct delay_buffer;
struct sink_handler;


typedef int codec_handler_func(struct codec_handler *, struct media_packet *);


struct codec_handler {
	rtp_payload_type source_pt; // source_pt.payload_type = hashtable index
	rtp_payload_type dest_pt;
	int dtmf_payload_type;
	int real_dtmf_payload_type;
	int cn_payload_type;
	codec_handler_func *handler_func;
	unsigned int passthrough:1;
	unsigned int kernelize:1;
	unsigned int transcoder:1;
	unsigned int pcm_dtmf_detect:1;

	size_t payload_len; // for short-packet blocking

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
	str plain;
	struct rtp_header *rtp;
	unsigned long ts;
	unsigned int clockrate;
	struct ssrc_ctx *ssrc_out;
	void (*free_func)(void *);
	void (*plain_free_func)(void *);
};

struct codec_scheduler {
	unsigned long first_ts; // for output TS scaling
	unsigned long last_ts; // to detect input lag and handle lost packets
	struct timeval first_send;
	unsigned long first_send_ts;
	long output_skew;
};

typedef union {
	struct call_monologue *ml;
} codec_timer_callback_arg_t __attribute__ ((__transparent_union__));


void codecs_init(void);
void codecs_cleanup(void);
void codec_timers_launch(void);
void rtcp_timer_stop(struct rtcp_timer **);
void codec_timer_callback(call_t *, void (*)(call_t *, codec_timer_callback_arg_t),
		codec_timer_callback_arg_t, uint64_t delay);

void mqtt_timer_stop(struct mqtt_timer **);
void mqtt_timer_start(struct mqtt_timer **mqtp, call_t *call, struct call_media *media);

struct codec_handler *codec_handler_get(struct call_media *, int payload_type, struct call_media *sink,
		struct sink_handler *);
void codec_handlers_free(struct call_media *);
struct codec_handler *codec_handler_make_playback(const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, unsigned long ts, struct call_media *, uint32_t ssrc,
		str_case_value_ht codec_set);
struct codec_handler *codec_handler_make_media_player(const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, unsigned long ts, struct call_media *, uint32_t ssrc,
		str_case_value_ht codec_set);
struct codec_handler *codec_handler_make_dummy(const rtp_payload_type *dst_pt, struct call_media *media,
		str_case_value_ht codec_set);
void codec_calc_jitter(struct ssrc_ctx *, unsigned long ts, unsigned int clockrate, const struct timeval *);
void codec_update_all_handlers(struct call_monologue *ml);
void codec_update_all_source_handlers(struct call_monologue *ml, const sdp_ng_flags *flags);

struct codec_store_args {
	str_case_value_ht codec_set;
	bool answer_only;
	bool allow_asymmetric;
	struct codec_store *merge_cs;
};

__attribute__((nonnull(1)))
void codec_store_cleanup(struct codec_store *cs);
__attribute__((nonnull(1)))
void codec_store_init(struct codec_store *cs, struct call_media *);
__attribute__((nonnull(1, 2)))
void __codec_store_populate(struct codec_store *dst, struct codec_store *src, struct codec_store_args);
#define codec_store_populate(dst, src, ...) \
	__codec_store_populate(dst, src, (struct codec_store_args) {__VA_ARGS__})
__attribute__((nonnull(1, 2)))
void __codec_store_populate_reuse(struct codec_store *, struct codec_store *, struct codec_store_args);
#define codec_store_populate_reuse(dst, src, ...) \
	__codec_store_populate_reuse(dst, src, (struct codec_store_args) {__VA_ARGS__})
__attribute__((nonnull(1, 2)))
void codec_store_copy(struct codec_store *, struct codec_store *);
void codec_store_add_raw(struct codec_store *cs, rtp_payload_type *pt);
__attribute__((nonnull(1, 2)))
void codec_store_strip(struct codec_store *, str_q *strip, str_case_ht except);
__attribute__((nonnull(1, 2, 3)))
void codec_store_offer(struct codec_store *, str_q *, struct codec_store *);
__attribute__((nonnull(1, 2, 3)))
void codec_store_check_empty(struct codec_store *, struct codec_store *, sdp_ng_flags *);
__attribute__((nonnull(1, 2)))
void codec_store_accept(struct codec_store *, str_q *, struct codec_store *);
__attribute__((nonnull(1, 2)))
int codec_store_accept_one(struct codec_store *, str_q *, bool accept_any);
__attribute__((nonnull(1, 2)))
void codec_store_track(struct codec_store *, str_q *);
__attribute__((nonnull(1, 2, 3)))
void codec_store_transcode(struct codec_store *, str_q *, struct codec_store *);
__attribute__((nonnull(1, 2, 3)))
void __codec_store_answer(struct codec_store *dst, struct codec_store *src, sdp_ng_flags *flags,
		struct codec_store_args);
#define codec_store_answer(dst, src, flags, ...) \
	__codec_store_answer(dst, src, flags, (struct codec_store_args) {__VA_ARGS__})
__attribute__((nonnull(1, 2)))
void codec_store_synthesise(struct codec_store *dst, struct codec_store *opposite);
__attribute__((nonnull(1, 2)))
bool codec_store_is_full_answer(const struct codec_store *src, const struct codec_store *dst);

void codec_add_raw_packet(struct media_packet *mp, unsigned int clockrate);
void codec_packet_free(void *);
struct codec_packet *codec_packet_dup(struct codec_packet *p);
bool codec_packet_copy(struct codec_packet *p);

void payload_type_free(rtp_payload_type *p);
rtp_payload_type *rtp_payload_type_dup(const rtp_payload_type *pt);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(rtp_payload_type, payload_type_free)


// special return value `(void *) 0x1` to signal type mismatch
rtp_payload_type *codec_make_payload_type(const str *codec_str, enum media_type);

// handle string allocation
void codec_init_payload_type(rtp_payload_type *, enum media_type);
void payload_type_clear(rtp_payload_type *p);


struct chu_args {
	const sdp_ng_flags *flags;
	const struct stream_params *sp;
	bool allow_asymmetric;
	bool reset_transcoding;
};
#define codec_handlers_update(r, s, ...) \
	__codec_handlers_update(r, s, (struct chu_args) {__VA_ARGS__})

#ifdef WITH_TRANSCODING

void ensure_codec_def(rtp_payload_type *pt, struct call_media *media);
void codec_handler_free(struct codec_handler **handler);
__attribute__((nonnull(1, 2)))
void __codec_handlers_update(struct call_media *receiver, struct call_media *sink, struct chu_args);
void codec_add_dtmf_event(struct codec_ssrc_handler *ch, int code, int level, uint64_t ts, bool injected);
uint64_t codec_last_dtmf_event(struct codec_ssrc_handler *ch);
uint64_t codec_encoder_pts(struct codec_ssrc_handler *ch, struct ssrc_ctx *);
void codec_decoder_skip_pts(struct codec_ssrc_handler *ch, uint64_t);
uint64_t codec_decoder_unskip_pts(struct codec_ssrc_handler *ch);
void codec_tracker_update(struct codec_store *, struct codec_store *);
void codec_handlers_stop(codec_handlers_q *, struct call_media *sink);


void packet_encoded_packetize(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		packetizer_f pkt_f, void *pkt_f_data, const struct fraction *cr_fact,
		void (*tx_f)(AVPacket *, struct codec_ssrc_handler *, struct media_packet *, str *,
			char *, unsigned int, const struct fraction *cr_fact));
void codec_output_rtp(struct media_packet *mp, struct codec_scheduler *,
		struct codec_handler *handler, // normally == ch->handler except for DTMF
		char *buf, // malloc'd, room for rtp_header + filled-in payload
		unsigned int payload_len,
		unsigned long payload_ts,
		int marker, int seq, int seq_inc, int payload_type,
		unsigned long ts_delay);


INLINE struct codec_handler __codec_handler_lookup_struct(int pt, struct call_media *sink) {
	struct codec_handler lookup = {
		.source_pt = {
			.payload_type = pt,
		},
		.sink = sink,
	};
	return lookup;
}
INLINE struct codec_handler *codec_handler_lookup(codec_handlers_ht ht, int pt, struct call_media *sink) {
	struct codec_handler lookup = __codec_handler_lookup_struct(pt, sink);
	return t_hash_table_lookup(ht, &lookup);
}



#else

INLINE void __codec_handlers_update(struct call_media *receiver, struct call_media *sink, struct chu_args a)
{
}
INLINE void codec_handler_free(struct codec_handler **handler) { }
INLINE void codec_tracker_update(struct codec_store *cs, struct codec_store *ocs) { }
INLINE void codec_handlers_stop(codec_handlers_q *q, struct call_media *sink) { }
INLINE void ensure_codec_def(rtp_payload_type *pt, struct call_media *media) { }

#endif



#endif
