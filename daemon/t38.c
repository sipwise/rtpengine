#include "t38.h"



#ifdef WITH_TRANSCODING


#include <assert.h>
#include "codec.h"
#include "call.h"
#include "log.h"



static int t38_encoder_handler(t38_core_state_t *s, void *user_data, const uint8_t *buf, int len, int count) {
	struct t38_encoder *te = user_data;

	ilog(LOG_DEBUG, "Generated %i T.38 bytes", len);

	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s.len = len;
	p->s.s = malloc(len);
	memcpy(p->s.s, buf, len);
	p->free_func = free;
	g_queue_push_tail(&te->mp->packets_out, p);

	return 0;
}

struct t38_encoder *t38_encoder_new(struct call_media *media) {
	struct t38_encoder *te = g_slice_alloc0(sizeof(*te));

	te->media = media;

	te->dest_pt.payload_type = -1;
	str_init(&te->dest_pt.encoding, "PCM-S16LE");
	te->dest_pt.encoding_with_params = te->dest_pt.encoding;
	te->dest_pt.clock_rate = 8000;
	te->dest_pt.channels = 1;

	ensure_codec_def(&te->dest_pt, media);
	if (!te->dest_pt.codec_def)
		goto err;

	if (!(te->gw = t38_gateway_init(NULL, t38_encoder_handler, te)))
		goto err;

	return te;

err:
	t38_encoder_free(&te);
	return NULL;
}


int t38_samples(struct t38_encoder *te, struct media_packet *mp, int16_t amp[], int len) {
	if (!te)
		return 0;

	te->mp = mp;
	int left = t38_gateway_rx(te->gw, amp, len);
	assert(left == 0); // XXX

	return 0;
}


void t38_encoder_free(struct t38_encoder **tep) {
	struct t38_encoder *te = *tep;
	if (!te)
		return;
	if (te->gw)
		t38_gateway_free(te->gw);
	g_slice_free1(sizeof(*te), te);
	*tep = NULL;
}



#endif
