#ifndef _T38_H_
#define _T38_H_


#ifdef WITH_TRANSCODING



#include <inttypes.h>
#include <sys/types.h>
#include <spandsp/telephony.h>
#include <spandsp/logging.h>
#include <spandsp/t38_core.h>
#include <spandsp/t38_gateway.h>

#include "rtplib.h"
#include "aux.h"
#include "obj.h"



struct call_media;
struct media_packet;
struct media_player;


struct t38_gateway {
	struct obj obj; // use refcount as this struct is shared between two medias
	mutex_t lock;
	struct call_media *t38_media;
	struct call_media *pcm_media;
	struct rtp_payload_type pcm_pt; // PCM input for spandsp
	t38_gateway_state_t *gw;

	// udptl stuff
	uint16_t seqnum;
	GQueue ifp_ec;
	unsigned int ifp_ec_max_entries;

	// player for PCM data
	struct media_player *pcm_player;

	struct media_packet *mp; // to pass down to spandsp packet handler
};



int t38_gateway_pair(struct call_media *t38_media, struct call_media *pcm_media);
int t38_input_samples(struct t38_gateway *, struct media_packet *, int16_t amp[], int len);
void t38_encoder_free(struct t38_gateway **te);


INLINE void t38_gateway_put(struct t38_gateway **tp) {
	if (!tp || !*tp)
		return;
	obj_put(*tp);
	*tp = NULL;
}


#endif
#endif
