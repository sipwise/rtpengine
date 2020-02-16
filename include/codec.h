#ifndef __CODEC_H__
#define __CODEC_H__


#include <glib.h>
#include <sys/time.h>
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


typedef int codec_handler_func(struct codec_handler *, struct media_packet *);


struct codec_handler {
	struct rtp_payload_type source_pt; // source_pt.payload_type = hashtable index
	struct rtp_payload_type dest_pt;
	int dtmf_payload_type;
	codec_handler_func *func;
	int kernelize:1;
	int transcoder:1;
	int dtmf_scaler:1;
	int pcm_dtmf_detect:1;

	struct ssrc_hash *ssrc_hash;
	struct codec_handler *output_handler; // == self, or other PT handler

	// for media playback
	struct codec_ssrc_handler *ssrc_handler;
};

struct codec_packet {
	struct timerthread_queue_entry ttq_entry;
	str s;
	struct rtp_header *rtp;
	void (*free_func)(void *);
};


struct codec_handler *codec_handler_get(struct call_media *, int payload_type);
void codec_handlers_free(struct call_media *);
struct codec_handler *codec_handler_make_playback(struct rtp_payload_type *src_pt,
		struct rtp_payload_type *dst_pt, unsigned long ts);
void codec_handler_free(struct codec_handler *handler);

void codec_add_raw_packet(struct media_packet *mp);
void codec_packet_free(void *);

void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, struct sdp_ng_flags *flags);

str *codec_print_payload_type(const struct rtp_payload_type* pt);
// special return value `(void *) 0x1` to signal type mismatch
struct rtp_payload_type *codec_make_payload_type(const str *codec_str, struct call_media *media);
void codec_init_payload_type(struct rtp_payload_type *, struct call_media *);


// used by redis
void __rtp_payload_type_add_recv(struct call_media *media, struct rtp_payload_type *pt);
void __rtp_payload_type_add_send(struct call_media *other_media, struct rtp_payload_type *pt);



#ifdef WITH_TRANSCODING

void codec_handlers_update(struct call_media *receiver, struct call_media *sink, const struct sdp_ng_flags *);
void codec_add_dtmf_event(struct codec_ssrc_handler *ch, int code, int level, uint64_t ts);
uint64_t codec_last_dtmf_event(struct codec_ssrc_handler *ch);
uint64_t codec_encoder_pts(struct codec_ssrc_handler *ch);
void codec_decoder_skip_pts(struct codec_ssrc_handler *ch, uint64_t);
uint64_t codec_decoder_unskip_pts(struct codec_ssrc_handler *ch);

#else

INLINE void codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags) { }

#endif



#endif
