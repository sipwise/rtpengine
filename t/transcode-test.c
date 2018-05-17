#include "codec.h"
#include "call.h"
#include "call_interfaces.h"
#include "log.h"
#include "main.h"
#include "ssrc.h"

int _log_facility_rtcp;
int _log_facility_cdr;
struct rtpengine_config rtpe_config;
struct poller *rtpe_poller;

static str *sdup(char *s) {
	str *r = g_slice_alloc(sizeof(*r));
	str_init(r, s);
	return r;
}
static void queue_dump(GString *s, GQueue *q) {
	for (GList *l = q->head; l; l = l->next) {
		if (s->len)
			g_string_append(s, " ");
		struct rtp_payload_type *pt = l->data;
		g_string_append_printf(s, "%i/%s", pt->payload_type, pt->encoding_with_params.s);
		if (pt->format_parameters.len)
			g_string_append_printf(s, "/%s", pt->format_parameters.s);
	}
}

#define start() { \
	printf("running test %s:%i\n", __FILE__, __LINE__); \
	struct call call = {{0,},}; \
	call.ssrc_hash = create_ssrc_hash_call(); \
	struct sdp_ng_flags flags = {0,}; \
	bencode_buffer_init(&call.buffer); \
	struct call_media *media_A = call_media_new(&call); /* originator */ \
	struct call_media *media_B = call_media_new(&call); /* output destination */ \
	GQueue rtp_types = G_QUEUE_INIT; /* parsed from received SDP */ \
	flags.codec_strip = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL); \
	flags.codec_mask = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL)

#define transcode(codec) g_queue_push_tail(&flags.codec_transcode, sdup(#codec))

#define sdp_pt_fmt(num, codec, clockrate, fmt) { \
	struct rtp_payload_type *pt = g_slice_alloc(sizeof(*pt)); \
	*pt = (struct rtp_payload_type) { num, STR_CONST_INIT(#codec "/" #clockrate), STR_CONST_INIT(#codec), \
		clockrate, STR_CONST_INIT(""), 1, STR_CONST_INIT(fmt), 0, 0, NULL }; \
	g_queue_push_tail(&rtp_types, pt); \
	}

#define sdp_pt(num, codec, clockrate) sdp_pt_fmt(num, codec, clockrate, "")

#define offer() \
	codec_rtp_payload_types(media_B, media_A, &rtp_types, \
			flags.codec_strip, &flags.codec_offer, &flags.codec_transcode, \
			flags.codec_mask); \
	codec_handlers_update(media_B, media_A, &flags); \
	g_queue_clear(&rtp_types); \
	memset(&flags, 0, sizeof(flags))

#define answer() \
	codec_rtp_payload_types(media_A, media_B, &rtp_types, \
			flags.codec_strip, &flags.codec_offer, &flags.codec_transcode, \
			flags.codec_mask); \
	codec_handlers_update(media_A, media_B, &flags); \

#define expect(side, dir, codecs) { \
	printf("running test %s:%i\n", __FILE__, __LINE__); \
	GString *s = g_string_new(""); \
	queue_dump(s, &media_ ## side->codecs_prefs_ ## dir); \
	if (strcmp(s->str, codecs) != 0) { \
		printf("test failed: %s:%i\n", __FILE__, __LINE__); \
		printf("expected: %s\n", codecs); \
		printf("received: %s\n", s->str); \
		abort(); \
	} \
	printf("test ok: %s:%i\n", __FILE__, __LINE__); \
	g_string_free(s, TRUE); \
	}

#define packet_seq(side, pt_in, pload, pt_out, pload_exp, rtp_ts, rtp_seq) { \
	printf("running test %s:%i\n", __FILE__, __LINE__); \
	struct codec_handler *h = codec_handler_get(media_ ## side, pt_in); \
	str pl = STR_CONST_INIT(pload); \
	str pl_exp = STR_CONST_INIT(pload_exp); \
	struct media_packet mp = { \
		.media = media_ ## side, \
		.ssrc_in = get_ssrc_ctx(1234, call.ssrc_hash, SSRC_DIR_INPUT), \
		.ssrc_out = get_ssrc_ctx(1234, call.ssrc_hash, SSRC_DIR_OUTPUT), \
	}; \
	int packet_len = sizeof(struct rtp_header) + pl.len; \
	char *packet = malloc(packet_len); \
	struct rtp_header *rtp = (void *) packet; \
	*rtp = (struct rtp_header) { \
		.m_pt = pt_in, \
		.ssrc = 1234, \
		.seq_num = htons(rtp_seq), \
		.timestamp = htonl(rtp_ts), \
	}; \
	mp.rtp = rtp; \
	mp.payload = pl; \
	mp.payload.s = (packet + sizeof(struct rtp_header)); \
	memcpy(mp.payload.s, pl.s, pl.len); \
	mp.raw.s = packet; \
	mp.raw.len = packet_len; \
	h->func(h, &mp); \
	if (pt_out == -1) { \
		if (mp.packets_out.length != 0) { \
			printf("test failed: %s:%i\n", __FILE__, __LINE__); \
			printf("unexpected packet\n"); \
			abort(); \
		} \
	} \
	else { \
		if (mp.packets_out.length != 1) { \
			printf("test failed: %s:%i\n", __FILE__, __LINE__); \
			printf("no packet\n"); \
			abort(); \
		} \
		struct codec_packet *cp = g_queue_pop_head(&mp.packets_out); \
		rtp = (void *) cp->s.s; \
		if (rtp->m_pt != pt_out) { \
			printf("test failed: %s:%i\n", __FILE__, __LINE__); \
			printf("expected: %i\n", pt_out); \
			printf("received: %i\n", rtp->m_pt); \
			abort(); \
		} \
		printf("packet contents: "); \
		for (int i = sizeof(struct rtp_header); i < cp->s.len; i++) { \
			unsigned char cc = cp->s.s[i]; \
			printf("\\x%02x", cc); \
		} \
		printf("\n"); \
		if (str_shift(&cp->s, sizeof(struct rtp_header))) \
			abort(); \
		if (pl_exp.len != cp->s.len) \
			abort(); \
		if (memcmp(pl_exp.s, cp->s.s, pl_exp.len)) \
			abort(); \
	} \
	printf("test ok: %s:%i\n", __FILE__, __LINE__); \
	free(packet); \
}

#define packet(side, pt_in, pload, pt_out, pload_exp) \
	packet_seq(side, pt_in, pload, pt_out, pload_exp, 0, 0)

#define end() } /* free/cleanup should go here */

#define PCMU_payload "\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
#define PCMU_payload_AMR "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7e\xff\x7e\xf6\xf3\xf5\xf5\xf5\xf6\xf7\xf7\xf8\xf9\xf9\xfa\xfb\xfb\xfc\xfc\xfd\xfd\xfe\xfe\xff\xff\x7e\xff\x7d\xff\x7b\xfc\xf6\xf5\xf6\xe3\x6e\x42\x3d\x3d\x3e\x3f\x41\x3f\x3d\x3f\x41\x44\x46\x49\x4b\x4d\x50\x54\x58\x5b\x60\x67\x6f\x74\xec\x6c\x46\x41\x42\x45\x48\x4a\x4d\x4f\x60\xff\xdb\xd2\xce\xc6\xc6\xc5\xc4\xc6\xbf\xbe\xba\xba\xba\xb8\xb6\xb4\xb3\xb2\xb0\xb0\xaf\xaf\xae\xae\xaf\xae\xae\xae\xaf\xb1\xb1\xb2\xb2\xb4\xb6\xb6\xb7\xb7\xb8\xb8\xb8\xb9\xb9\xba\xb8\xb9\xb9\xba\xba\xbb\xbb\xbd\xbc\xbd\xbf\xbf\xc0\xc2\xc5\xc8\xca\xcd\xce\xd0\xdc\xdc\xe5\xe7\xf0\xf8\x7c\x6f\x70\x65\x6e\x62\x60" // after AMR decode
#define PCMA_payload "\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a"
#define AMR_WB_payload "\xf0\x1c\xf3\x06\x08\x10\x77\x32\x23\x20\xd3\x50\x62\x12\xc7\x7c\xe2\xea\x84\x0e\x6e\xf4\x4d\xe4\x7f\xc9\x4c\xcc\x58\x5d\xed\xcc\x5d\x7c\x6c\x14\x7d\xc0" // octet aligned
#define AMR_WB_payload_noe "\xf1\xfc\xc1\x82\x04\x1d\xcc\x88\xc8\x34\xd4\x18\x84\xb1\xdf\x38\xba\xa1\x03\x9b\xbd\x13\x79\x1f\xf2\x53\x33\x16\x17\x7b\x73\x17\x5f\x1b\x05\x1f\x70" // bandwidth efficient

int main() {
	codeclib_init(0);

	// plain
	start();
	sdp_pt(0, PCMU, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000");
	expect(B, send, "");
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, recv, "0/PCMU/8000");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000");
	expect(B, send, "0/PCMU/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
	end();

	// plain with two offered and two answered
	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "0/PCMU/8000 8/PCMA/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
	packet(A, 8, PCMA_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 8, PCMA_payload);
	end();

	// plain with two offered and two answered + always-transcode one way
	start();
	flags.always_transcode = 1;
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "0/PCMU/8000 8/PCMA/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
	packet(A, 8, PCMA_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	end();

	// plain with two offered and two answered + always-transcode both ways
	start();
	flags.always_transcode = 1;
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	flags.always_transcode = 1;
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "0/PCMU/8000 8/PCMA/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
	packet(A, 8, PCMA_payload, 0, PCMU_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	end();

	// add one codec to transcode
	start();
	sdp_pt(0, PCMU, 8000);
	transcode(PCMA);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "0/PCMU/8000");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "0/PCMU/8000 8/PCMA/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	end();

	// add one codec to transcode, don't accept original offered codec
	start();
	sdp_pt(0, PCMU, 8000);
	transcode(PCMA);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "0/PCMU/8000");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "8/PCMA/8000");
	packet(A, 0, PCMU_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	end();

	{
		str codec_name = STR_CONST_INIT("AMR-WB");
		const codec_def_t *def = codec_find(&codec_name, MT_AUDIO);
		assert(def);
		if (def->support_encoding && def->support_decoding) {
			// forward AMR-WB
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR-WB);
			offer();
			expect(A, recv, "");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "0/PCMU/8000 96/AMR-WB/16000/octet-align=1");
			expect(B, send, "");
			sdp_pt_fmt(96, AMR-WB, 16000, "octet-align=1");
			answer();
			expect(A, recv, "0/PCMU/8000");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "0/PCMU/8000 96/AMR-WB/16000/octet-align=1");
			expect(B, send, "96/AMR-WB/16000/octet-align=1");
			packet_seq(A, 0, PCMU_payload, -1, "", 0, 0); // nothing due to resampling buffer
			packet_seq(A, 0, PCMU_payload, 96, AMR_WB_payload, 160, 1);
			packet_seq(B, 96, AMR_WB_payload, -1, "", 0, 0); // nothing due to resampling/decoding buffer
			packet_seq(B, 96, AMR_WB_payload, 0, PCMU_payload_AMR, 320, 1);
			end();

			// reverse AMR-WB (octet aligned)
			start();
			sdp_pt_fmt(96, AMR-WB, 16000, "octet-align=1");
			transcode(PCMU);
			offer();
			expect(A, recv, "");
			expect(A, send, "96/AMR-WB/16000/octet-align=1");
			expect(B, recv, "96/AMR-WB/16000/octet-align=1 0/PCMU/8000");
			expect(B, send, "");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, recv, "96/AMR-WB/16000/octet-align=1");
			expect(A, send, "96/AMR-WB/16000/octet-align=1");
			expect(B, recv, "96/AMR-WB/16000/octet-align=1 0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			packet_seq(B, 0, PCMU_payload, -1, "", 0, 0); // nothing due to resampling buffer
			packet_seq(B, 0, PCMU_payload, 96, AMR_WB_payload, 160, 1);
			packet_seq(A, 96, AMR_WB_payload, -1, "", 0, 0); // nothing due to resampling/decoding buffer
			packet_seq(A, 96, AMR_WB_payload, 0, PCMU_payload_AMR, 320, 1);
			end();

			// reverse AMR-WB (bandwidth efficient)
			start();
			sdp_pt(96, AMR-WB, 16000);
			transcode(PCMU);
			offer();
			expect(A, recv, "");
			expect(A, send, "96/AMR-WB/16000");
			expect(B, recv, "96/AMR-WB/16000 0/PCMU/8000");
			expect(B, send, "");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, recv, "96/AMR-WB/16000");
			expect(A, send, "96/AMR-WB/16000");
			expect(B, recv, "96/AMR-WB/16000 0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			packet_seq(B, 0, PCMU_payload, -1, "", 0, 0); // nothing due to resampling buffer
			packet_seq(B, 0, PCMU_payload, 96, AMR_WB_payload_noe, 160, 1);
			packet_seq(A, 96, AMR_WB_payload_noe, -1, "", 0, 0); // nothing due to resampling/decoding buffer
			packet_seq(A, 96, AMR_WB_payload_noe, 0, PCMU_payload_AMR, 320, 1);
			end();
		}
	}

	return 0;
}
