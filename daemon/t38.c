#include "t38.h"



#ifdef WITH_TRANSCODING


#include <assert.h>
#include <spandsp/t30.h>
#include "codec.h"
#include "call.h"
#include "log.h"
#include "str.h"



static void __add_ifp_len(GString *s, const void *buf, unsigned int len) {
	if (len < 0x80) {
		g_string_append_c(s, len);
		if (len)
			g_string_append_len(s, buf, len);
		return;
	}

	if (len < 0x4000) {
		uint16_t enc_len = htons(0x8000 | len);
		g_string_append_len(s, (void *) &enc_len, 2);
		g_string_append_len(s, buf, len);
		return;
	}

	// fragmented - we don't support more than 65535 bytes
	unsigned int mult = len >> 14;
	g_string_append_c(s, 0xc0 | mult);
	mult <<= 14;
	// one portion
	g_string_append_len(s, buf, mult);
	// remainder - may be zero length
	__add_ifp_len(s, buf + mult, len - mult);
}

static void __add_ifp(GString *s, const str *buf) {
	assert(buf->len < 0x10000);

	if (buf->len == 0) {
		// add a single zero byte, length 1
		__add_ifp_len(s, "\x00", 1);
		return;
	}

	__add_ifp_len(s, buf->s, buf->len);
}

static int t38_gateway_handler(t38_core_state_t *stat, void *user_data, const uint8_t *b, int len, int count) {
	struct t38_gateway *tg = user_data;

	// cap the max length of packet we can handle
	if (len < 0 || len >= 0x10000) {
		ilog(LOG_ERR, "Received %i bytes from T.38 encoder - discarding", len);
		return -1;
	}

	// XXX honour `count` ?

	ilog(LOG_DEBUG, "Received %i bytes from T.38 encoder", len);

	// build udptl packet: use a conservative guess for required buffer
	GString *s = g_string_sized_new(512);

	// add seqnum
	uint16_t seq = htons(tg->seqnum);
	g_string_append_len(s, (void *) &seq, 2);

	// add primary IFP packet
	str buf = STR_CONST_INIT_LEN((char *) b, len);
	__add_ifp(s, &buf);

	// add error correction packets
	// XXX FEC method

	// redundancy error correction
	g_string_append_c(s, 0);
	// number of entries - must be <0x80
	g_string_append_c(s, tg->ifp_ec.length);

	for (GList *l = tg->ifp_ec.head; l; l = l->next) {
		// add redundancy packet
		str *ec_s = l->data;
		__add_ifp(s, ec_s);
	}

	// done building our packet - add to our error correction buffer
	tg->seqnum++;
	if (tg->ifp_ec_max_entries) {
		while (tg->ifp_ec.length >= tg->ifp_ec_max_entries) {
			str *ec_s = g_queue_pop_tail(&tg->ifp_ec);
			free(ec_s);
		}
		g_queue_push_head(&tg->ifp_ec, str_dup(&buf));
	}

	// add final packet to output queue
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s.len = s->len;
	p->s.s = g_string_free(s, FALSE);
	p->free_func = g_free;
	g_queue_push_tail(&tg->mp->packets_out, p);

	return 0;
}

void __t38_gateway_free(void *p) {
	struct t38_gateway *tg = p;
	ilog(LOG_DEBUG, "Destroying T.38 gateway");
	if (tg->gw)
		t38_gateway_free(tg->gw);
}

int t38_gateway_pair(struct call_media *t38_media, struct call_media *pcm_media) {
	const char *err = NULL;

	if (!t38_media || !pcm_media)
		return -1;

	// do we have one yet?
	if (t38_media->t38_gateway
			&& t38_media->t38_gateway == pcm_media->t38_gateway)
	{
		// XXX check options here?
		return 0;
	}

	// release old structs, if any
	t38_gateway_put(&t38_media->t38_gateway);
	t38_gateway_put(&pcm_media->t38_gateway);

	ilog(LOG_DEBUG, "Creating new T.38 gateway");

	// create and init new
	struct t38_gateway *tg = obj_alloc0("t38_gateway", sizeof(*tg), __t38_gateway_free);

	tg->t38_media = t38_media;
	tg->pcm_media = pcm_media;
	mutex_init(&tg->lock);
	tg->ifp_ec_max_entries = 3;

	tg->dest_pt.payload_type = -1;
	str_init(&tg->dest_pt.encoding, "PCM-S16LE");
	tg->dest_pt.encoding_with_params = tg->dest_pt.encoding;
	tg->dest_pt.clock_rate = 8000;
	tg->dest_pt.channels = 1;

	err = "Failed to init PCM codec";
	ensure_codec_def(&tg->dest_pt, pcm_media);
	if (!tg->dest_pt.codec_def)
 		goto err;

	err = "Failed to create spandsp T.38 gateway";
	if (!(tg->gw = t38_gateway_init(NULL, t38_gateway_handler, tg)))
		goto err;

	// XXX set options
	t38_gateway_set_ecm_capability(tg->gw, TRUE);
	t38_gateway_set_transmit_on_idle(tg->gw, TRUE);
	t38_gateway_set_supported_modems(tg->gw, T30_SUPPORT_V17 | T30_SUPPORT_V27TER | T30_SUPPORT_V29
			| T30_SUPPORT_V34HDX | T30_SUPPORT_IAF);

	t38_media->t38_gateway = tg;
	pcm_media->t38_gateway = obj_get(tg);

	// add SDP options for T38
	// XXX configurable
	g_queue_clear_full(&t38_media->sdp_attributes, free);

	g_queue_push_tail(&t38_media->sdp_attributes, str_sprintf("T38FaxVersion:0"));
	g_queue_push_tail(&t38_media->sdp_attributes, str_sprintf("T38MaxBitRate:14400"));
	g_queue_push_tail(&t38_media->sdp_attributes, str_sprintf("T38FaxRateManagement:transferredTCF"));
	g_queue_push_tail(&t38_media->sdp_attributes, str_sprintf("T38FaxMaxBuffer:262"));
	g_queue_push_tail(&t38_media->sdp_attributes, str_sprintf("T38FaxMaxDatagram:90"));
	g_queue_push_tail(&t38_media->sdp_attributes, str_sprintf("T38FaxUdpEC:t38UDPRedundancy"));

	return 0;
 
err:
	if (err)
		ilog(LOG_ERR, "Failed to create T.38 gateway: %s", err);
	t38_gateway_put(&tg);
	return -1;
}

int t38_input_samples(struct t38_gateway *tg, struct media_packet *mp, int16_t amp[], int len) {
	if (!tg)
		return 0;

	ilog(LOG_DEBUG, "Adding %i samples to T.38 encoder", len);

	mutex_lock(&tg->lock);
 
	tg->mp = mp;
	int left = t38_gateway_rx(tg->gw, amp, len);
	assert(left == 0); // XXX
 
	mutex_unlock(&tg->lock);
 
	return 0;
}
 


#endif
