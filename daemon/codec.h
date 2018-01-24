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


typedef int codec_handler_func(struct codec_handler *, struct call_media *, const struct media_packet *,
		GQueue *);


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


void codec_handlers_update(struct call_media *receiver, struct call_media *sink);

struct codec_handler *codec_handler_get(struct call_media *, int payload_type);

void codec_handlers_free(struct call_media *);

void codec_packet_free(void *);

void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, GHashTable *strip,
		const GQueue *offer, const GQueue *transcode);




#endif
