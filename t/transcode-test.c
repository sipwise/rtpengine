#include "codec.h"
#include "call.h"
#include "call_interfaces.h"
#include "log.h"
#include "main.h"

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
	}
}

#define start() { \
	printf("running test %s:%i\n", __FILE__, __LINE__); \
	struct call call = {{0,},}; \
	struct sdp_ng_flags flags = {0,}; \
	bencode_buffer_init(&call.buffer); \
	struct call_media *media_A = call_media_new(&call); /* originator */ \
	struct call_media *media_B = call_media_new(&call); /* output destination */ \
	GQueue rtp_types = G_QUEUE_INIT; /* parsed from received SDP */ \
	flags.codec_strip = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL); \
	flags.codec_mask = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL)

#define transcode(codec) g_queue_push_tail(&flags.codec_transcode, sdup(#codec))

#define sdp_pt(num, codec, clockrate) { \
	struct rtp_payload_type *pt = g_slice_alloc(sizeof(*pt)); \
	*pt = (struct rtp_payload_type) { num, STR_CONST_INIT(#codec "/" #clockrate), STR_CONST_INIT(#codec), \
		clockrate, STR_CONST_INIT(""), 1, STR_NULL, 0, 0, NULL }; \
	g_queue_push_tail(&rtp_types, pt); \
	}

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

#define end() } /* free/cleanup should go here */

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
	end();

	return 0;
}
