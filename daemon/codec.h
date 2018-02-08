#ifndef __CODEC_H__
#define __CODEC_H__


#include <glib.h>
#include "str.h"
#include "codeclib.h"
#include "aux.h"
#include "rtplib.h"


struct call_media;
struct codec_handler;
struct media_packet;
struct ssrc_hash;


typedef int codec_handler_func(struct codec_handler *, struct call_media *, struct media_packet *);


struct codec_handler {
	struct rtp_payload_type source_pt; // source_pt.payload_type = hashtable index
	struct rtp_payload_type dest_pt;
	codec_handler_func *func;

	struct ssrc_hash *ssrc_hash;
};

struct codec_packet {
	str s;
	void (*free_func)(void *);
};


struct codec_handler *codec_handler_get(struct call_media *, int payload_type);
void codec_handlers_free(struct call_media *);

void codec_add_raw_packet(struct media_packet *mp);
void codec_packet_free(void *);

void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, GHashTable *strip,
		const GQueue *offer, const GQueue *transcode);



#ifdef WITH_TRANSCODING

void codec_handlers_update(struct call_media *receiver, struct call_media *sink);

#else

INLINE void codec_handlers_update(struct call_media *receiver, struct call_media *sink) { }

#endif



#endif
