#ifndef _T38_H_
#define _T38_H_


struct t38_gateway;

struct t38_options {
	int version;
	int fec_span; // 1 means no FEC
	int min_ec_entries; // currently ignored
	int max_ec_entries;
	int max_ifp;
	int max_datagram;

	int local_tcf:1;
	int fill_bit_removal:1;
	int transcoding_mmr:1;
	int transcoding_jbig:1;

	int no_ecm:1;
	int no_v17:1;
	int no_v27ter:1;
	int no_v29:1;
	int no_v34:1;
	int no_iaf:1;
};



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
#include "codeclib.h"



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

	struct t38_options options;

	// udptl outgoing stuff
	uint16_t seqnum;
	GQueue udptl_ec_out; // seq, seq-1, seq-2, ...
	// udptl incoming stuff
	packet_sequencer_t sequencer;
	GHashTable *udptl_fec;

	// player for PCM data
	struct media_player *pcm_player;
	unsigned long long pts;
};



void t38_init(void);

int t38_gateway_pair(struct call_media *t38_media, struct call_media *pcm_media, const struct t38_options *);
void t38_gateway_start(struct t38_gateway *);
int t38_gateway_input_samples(struct t38_gateway *, int16_t amp[], int len);
int t38_gateway_input_udptl(struct t38_gateway *, const str *);
void t38_gateway_stop(struct t38_gateway *);


INLINE void t38_gateway_put(struct t38_gateway **tp) {
	if (!tp || !*tp)
		return;
	obj_put(*tp);
	*tp = NULL;
}


#else

#include "compat.h"

// stubs
INLINE void t38_init(void) { }
INLINE void t38_gateway_start(struct t38_gateway *tg) { }
INLINE void t38_gateway_stop(struct t38_gateway *tg) { }
INLINE void t38_gateway_put(struct t38_gateway **tp) { }


#endif

#endif
