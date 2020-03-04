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



struct call_media;
struct media_packet;


struct t38_encoder {
	struct call_media *media;
	struct rtp_payload_type dest_pt;
	t38_gateway_state_t *gw;

	uint16_t seqnum;
	GQueue ifp_ec;
	unsigned int ifp_ec_max_entries;

	struct media_packet *mp; // to pass down to spandsp packet handler
};



struct t38_encoder *t38_encoder_new(struct call_media *);
int t38_samples(struct t38_encoder *, struct media_packet *, int16_t amp[], int len);
void t38_encoder_free(struct t38_encoder **te);


#endif
#endif
