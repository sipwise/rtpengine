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
	g_queue_clear(&rtp_types)

#define answer() \
	codec_rtp_payload_types(media_A, media_B, &rtp_types, \
			NULL, NULL, NULL, \
			NULL); \
	codec_handlers_update(media_A, media_B, NULL); \

#define expect(side, dir, codecs) { \
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

#define packet_seq(side, pt_in, pload, pt_out, rtp_ts, rtp_seq) { \
	struct codec_handler *h = codec_handler_get(media_ ## side, pt_in); \
	str pl = STR_CONST_INIT(pload); \
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
	h->func(h, media_A, &mp); \
	if (pt_out == -1) { \
		if (mp.packets_out.length == 1) { \
			printf("test failed: %s:%i\n", __FILE__, __LINE__); \
			printf("unexpected packet\n"); \
			abort(); \
		} \
	} \
	else { \
		if (mp.packets_out.length != 1) { \
			printf("test failed: %s:%i\n", __FILE__, __LINE__); \
			printf("no packets\n"); \
			abort(); \
		} \
		struct codec_packet *cp = mp.packets_out.head->data; \
		rtp = (void *) cp->s.s; \
		if (rtp->m_pt != pt_out) { \
			printf("test failed: %s:%i\n", __FILE__, __LINE__); \
			printf("expected: %i\n", pt_out); \
			printf("received: %i\n", rtp->m_pt); \
			abort(); \
		} \
	} \
	printf("test ok: %s:%i\n", __FILE__, __LINE__); \
	free(packet); \
}

#define packet(side, pt_in, pload, pt_out) \
	packet_seq(side, pt_in, pload, pt_out, 0, 0)

#define end() } /* free/cleanup should go here */

#define PCMU_payload "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define AMR_WB_payload "\xf0\x44\xf1\x46\x18\x1d\xd1\x57\x23\x13\x42\xf0\x00\x0c\x50\x33\xdd\xff\x0b\x99\x89\x2c\x68\x52\xf8\xf8\xd9\x59\x16\xd7\x45\xe7\x01\xec\x1f\xfe\x5b\xc6\xf9\x01\xa4\xb5\xe0\x6c\x91\x41\xfe\x52\x2c\xce\x44\xbb\x5a\xdf\x76\x29\xf8\xdb\xca\x18\xd6\x50" // octet aligned
#define AMR_WB_payload_noe "\xf4\x7c\x51\x86\x07\x74\x55\xc8\xc4\xd0\xbc\x00\x03\x14\x0c\xf7\x7f\xc2\xe6\x62\x4b\x1a\x14\xbe\x3e\x36\x56\x45\xb5\xd1\x79\xc0\x7b\x07\xff\x96\xf1\xbe\x40\x69\x2d\x78\x1b\x24\x50\x7f\x94\x8b\x33\x91\x2e\xd6\xb7\xdd\x8a\x7e\x36\xf2\x86\x35\x94" // bandwidth efficient

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
	packet(A, 0, PCMU_payload, 0);
	packet(B, 0, PCMU_payload, 0);
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
	packet(A, 0, PCMU_payload, 0);
	packet(B, 0, PCMU_payload, 0);
	packet(B, 8, PCMU_payload, 0);
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
	packet(A, 0, PCMU_payload, 8);
	packet(B, 8, PCMU_payload, 0);
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
			sdp_pt(96, AMR-WB, 16000);
			answer();
			expect(A, recv, "0/PCMU/8000");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "0/PCMU/8000 96/AMR-WB/16000/octet-align=1");
			expect(B, send, "96/AMR-WB/16000");
			packet_seq(A, 0, PCMU_payload, -1, 0, 0); // nothing due to resampling buffer
			packet_seq(A, 0, PCMU_payload, 96, 160, 1);
			packet_seq(B, 96, AMR_WB_payload, -1, 0, 0); // nothing due to resampling/decoding buffer
			packet_seq(B, 96, AMR_WB_payload, 0, 320, 1);
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
			packet_seq(B, 0, PCMU_payload, -1, 0, 0); // nothing due to resampling buffer
			packet_seq(B, 0, PCMU_payload, 96, 160, 1);
			packet_seq(A, 96, AMR_WB_payload, -1, 0, 0); // nothing due to resampling/decoding buffer
			packet_seq(A, 96, AMR_WB_payload, 0, 320, 1);
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
			packet_seq(B, 0, PCMU_payload, -1, 0, 0); // nothing due to resampling buffer
			packet_seq(B, 0, PCMU_payload, 96, 160, 1);
			packet_seq(A, 96, AMR_WB_payload, -1, 0, 0); // nothing due to resampling/decoding buffer
			packet_seq(A, 96, AMR_WB_payload, 0, 320, 1);
			end();
		}
	}

	return 0;
}
