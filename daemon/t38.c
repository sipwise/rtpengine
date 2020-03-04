#include "t38.h"



#ifdef WITH_TRANSCODING


#include <assert.h>
#include <spandsp/t30.h>
#include "codec.h"
#include "call.h"
#include "log.h"



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

static int t38_encoder_handler(t38_core_state_t *stat, void *user_data, const uint8_t *b, int len, int count) {
	struct t38_encoder *te = user_data;

	// cap the max length of packet we can handle
	if (len < 0 || len >= 0x10000) {
		ilog(LOG_ERR, "Received %i bytes from T.38 encoder - discarding", len);
		return -1;
	}

	ilog(LOG_DEBUG, "Received %i bytes from T.38 encoder", len);

	// build udptl packet: use a conservative guess for required buffer
	GString *s = g_string_sized_new(512);

	// add seqnum
	uint16_t seq = htons(te->seqnum);
	g_string_append_len(s, (void *) &seq, 2);

	// add primary IFP packet
	str buf = STR_CONST_INIT_LEN((char *) b, len);
	__add_ifp(s, &buf);

	// add error correction packets
	// XXX FEC method

	// redundancy error correction
	g_string_append_c(s, 0);
	// number of entries - must be <0x80
	g_string_append_c(s, te->ifp_ec.length);

	for (GList *l = te->ifp_ec.head; l; l = l->next) {
		// add redundancy packet
		str *ec_s = l->data;
		__add_ifp(s, ec_s);
	}

	// done building our packet - add to our error correction buffer
	te->seqnum++;
	if (te->ifp_ec_max_entries) {
		while (te->ifp_ec.length >= te->ifp_ec_max_entries) {
			str *ec_s = g_queue_pop_tail(&te->ifp_ec);
			free(ec_s);
		}
		g_queue_push_head(&te->ifp_ec, str_dup(&buf));
	}

	// add final packet to output queue
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s.len = s->len;
	p->s.s = g_string_free(s, FALSE);
	p->free_func = g_free;
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

	// XXX set options
	t38_gateway_set_ecm_capability(te->gw, TRUE);
	t38_gateway_set_transmit_on_idle(te->gw, TRUE);
	t38_gateway_set_supported_modems(te->gw, T30_SUPPORT_V17 | T30_SUPPORT_V27TER | T30_SUPPORT_V29
			| T30_SUPPORT_V34HDX | T30_SUPPORT_IAF);

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
