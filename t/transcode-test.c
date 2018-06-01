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

// global variables used by tests
static GHashTable *rtp_ts_ht;
static GHashTable *rtp_seq_ht;
static uint32_t ssrc_A;
static uint32_t ssrc_B;
static struct call call;
static struct sdp_ng_flags flags;
static struct call_media *media_A;
static struct call_media *media_B;
static GQueue rtp_types;

#define start() __start(__FILE__, __LINE__)

static void __start(const char *file, int line) {
	printf("running test %s:%i\n", file, line);
	rtp_ts_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	rtp_seq_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	ssrc_A = 1234;
	ssrc_B = 2345;
	call = (struct call) {{0,},};
	call.ssrc_hash = create_ssrc_hash_call();
	flags = (struct sdp_ng_flags) {0,};
	bencode_buffer_init(&call.buffer);
	media_A = call_media_new(&call); // originator
	media_B = call_media_new(&call); // output destination
	g_queue_init(&rtp_types); // parsed from received SDP
	flags.codec_strip = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
	flags.codec_mask = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
}

#define transcode(codec) g_queue_push_tail(&flags.codec_transcode, sdup(#codec))

#define sdp_pt_fmt(num, codec, clockrate, fmt) \
	__sdp_pt_fmt(num, (str) STR_CONST_INIT(#codec), clockrate, (str) STR_CONST_INIT(#codec "/" #clockrate), \
			(str) STR_CONST_INIT(fmt))

static void __sdp_pt_fmt(int num, str codec, int clockrate, str full_codec, str fmt) {
	struct rtp_payload_type *pt = g_slice_alloc(sizeof(*pt));
	*pt = (struct rtp_payload_type) { num, full_codec, codec,
		clockrate, STR_CONST_INIT(""), 1, fmt, 0, 0, NULL };
	g_queue_push_tail(&rtp_types, pt);
}

#define sdp_pt(num, codec, clockrate) sdp_pt_fmt(num, codec, clockrate, "")

static void offer() {
	printf("offer\n");
	codec_rtp_payload_types(media_B, media_A, &rtp_types, &flags);
	codec_handlers_update(media_B, media_A, &flags);
	g_queue_clear(&rtp_types);
	memset(&flags, 0, sizeof(flags));
}

static void answer() {
	printf("answer\n");
	codec_rtp_payload_types(media_A, media_B, &rtp_types, &flags);
	codec_handlers_update(media_A, media_B, &flags);
}

#define expect(side, dir, codecs) \
	__expect(__FILE__, __LINE__, &media_ ## side->codecs_prefs_ ## dir, codecs)

static void __expect(const char *file, int line, GQueue *dumper, const char *codecs) {
	printf("running test %s:%i\n", file, line);
	GString *s = g_string_new("");
	queue_dump(s, dumper);
	if (strcmp(s->str, codecs) != 0) {
		printf("test failed: %s:%i\n", file, line);
		printf("expected: %s\n", codecs);
		printf("received: %s\n", s->str);
		abort();
	}
	printf("test ok: %s:%i\n", file, line);
	g_string_free(s, TRUE);
}

#define packet_seq_ts(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, ts_exp, fatal) \
	__packet_seq_ts( __FILE__, __LINE__, media_ ## side, pt_in, (str) STR_CONST_INIT(pload), \
			(str) STR_CONST_INIT(pload_exp), ssrc_ ## side, rtp_ts, rtp_seq, pt_out, \
			ts_exp, fatal)

static void __packet_seq_ts(const char *file, int line, struct call_media *media, long long pt_in, str pload,
		str pload_exp, uint32_t ssrc, long long rtp_ts, long long rtp_seq, long long pt_out,
		long long ts_exp, int fatal)
{
	printf("running test %s:%i\n", file, line);
	struct codec_handler *h = codec_handler_get(media, pt_in);
	str pl = pload;
	str pl_exp = pload_exp;
	struct media_packet mp = {
		.media = media,
		.ssrc_in = get_ssrc_ctx(ssrc, call.ssrc_hash, SSRC_DIR_INPUT),
	};
	mp.ssrc_out = get_ssrc_ctx(mp.ssrc_in->ssrc_map_out, call.ssrc_hash, SSRC_DIR_OUTPUT);
	int packet_len = sizeof(struct rtp_header) + pl.len;
	char *packet = malloc(packet_len);
	struct rtp_header *rtp = (void *) packet;
	*rtp = (struct rtp_header) {
		.m_pt = pt_in,
		.ssrc = ssrc,
		.seq_num = htons(rtp_seq),
		.timestamp = htonl(rtp_ts),
	};
	mp.rtp = rtp;
	mp.payload = pl;
	mp.payload.s = (packet + sizeof(struct rtp_header));
	memcpy(mp.payload.s, pl.s, pl.len);
	mp.raw.s = packet;
	mp.raw.len = packet_len;
	h->func(h, &mp);
	if (pt_out == -1) {
		if (mp.packets_out.length != 0) {
			printf("test failed: %s:%i\n", file, line);
			printf("unexpected packet\n");
			abort();
		}
	}
	else {
		if (mp.packets_out.length != 1) {
			printf("test failed: %s:%i\n", file, line);
			printf("no packet\n");
			abort();
		}
		struct codec_packet *cp = g_queue_pop_head(&mp.packets_out);
		rtp = (void *) cp->s.s;
		if (rtp->m_pt != (unsigned char) pt_out) {
			printf("test failed: %s:%i\n", file, line);
			printf("expected: %lli\n", pt_out);
			printf("received: %i\n", rtp->m_pt);
			abort();
		}
		printf("packet contents: ");
		for (int i = sizeof(struct rtp_header); i < cp->s.len; i++) {
			unsigned char cc = cp->s.s[i];
			printf("\\x%02x", cc);
		}
		printf("\n");
		uint32_t ts = ntohl(rtp->timestamp);
		uint16_t seq = ntohs(rtp->seq_num);
		uint32_t ssrc = ntohl(rtp->ssrc);
		uint32_t ssrc_pt = ssrc ^ pt_out;
		ssrc_pt ^= pt_in << 8; /* XXX this is actually wrong and should be removed. it's a workaround for a bug */
		printf("RTP SSRC %x seq %u TS %u PT %u\n", (unsigned int) ssrc,
				(unsigned int) seq, (unsigned int) ts, (unsigned int) rtp->m_pt);
		if (g_hash_table_contains(rtp_ts_ht, GUINT_TO_POINTER(ssrc_pt))) {
			uint32_t old_ts = GPOINTER_TO_UINT(g_hash_table_lookup(rtp_ts_ht,
						GUINT_TO_POINTER(ssrc_pt)));
			uint32_t diff = ts - old_ts;
			printf("RTP TS diff: %u\n", (unsigned int) diff);
			if (ts_exp != -1)
				assert(ts_exp == diff);
		}
		g_hash_table_insert(rtp_ts_ht, GUINT_TO_POINTER(ssrc_pt), GUINT_TO_POINTER(ts));
		if (g_hash_table_contains(rtp_seq_ht, GUINT_TO_POINTER(ssrc_pt))) {
			uint32_t old_seq = GPOINTER_TO_UINT(g_hash_table_lookup(rtp_seq_ht,
						GUINT_TO_POINTER(ssrc_pt)));
			uint16_t diff = seq - old_seq;
			printf("RTP seq diff: %u\n", (unsigned int) diff);
			assert(diff == 1);
		}
		g_hash_table_insert(rtp_seq_ht, GUINT_TO_POINTER(ssrc_pt), GUINT_TO_POINTER(seq));
		if (str_shift(&cp->s, sizeof(struct rtp_header)))
			abort();
		if (pl_exp.len != cp->s.len)
			abort();
		if (fatal && memcmp(pl_exp.s, cp->s.s, pl_exp.len))
			abort();
	}
	printf("test ok: %s:%i\n", file, line);
	free(packet);
}

#define packet(side, pt_in, pload, pt_out, pload_exp) \
	packet_seq(side, pt_in, pload, 0, 0, pt_out, pload_exp)

#define packet_seq(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp) \
	packet_seq_ts(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, -1, 1)

#define packet_seq_nf(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp) \
	packet_seq_ts(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, -1, 0)

static void end() {
	g_hash_table_destroy(rtp_ts_ht);
	g_hash_table_destroy(rtp_seq_ht);
}

#define PCMU_payload "\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
#define PCMA_payload "\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a"
#define G722_payload "\x23\x84\x20\x84\x20\x84\x04\x84\x04\x04\x84\x04\x84\x04\x84\x05\x85\x46\x87\x48\xc8\x48\x88\x48\xc8\x49\x8a\x4b\xcc\x4c\x8c\x4c\xcc\x4c\x8c\x4d\xce\x50\xcf\x51\x90\x50\xcf\x12\xd1\x52\xd2\x54\x91\x52\xd2\x54\x92\x54\xd3\x56\x93\xd6\x94\xd4\x93\xd7\xd5\x55\x94\x55\xd5\x55\xd4\x56\xd5\x17\xd7\x5a\x95\xd7\x97\xd9\xd4\x16\x58\x57\x98\xd5\xd7\x5b\x96\xda\xd6\x1b\x57\x5a\xd6\x1a\x57\x5b\x98\xd6\xd8\x56\x98\xd7\xd9\x5a\x95\xdb\xd6\x1c\x52\x5e\xd7\x5c\x93\xdf\x99\xd5\xd7\x5f\xd9\x14\x56\x7f\x92\xda\xd9\x5c\x92\xdd\xd7\x5d\x92\xff\xd6\x5a\x96\xdc\xd5\x18\x56\x7e\xd2\x5e\x96\xde\x94\xd8\xd8\x58\xd3\x79\x93\xfb\x90\xdc\xd6\x5b\xdd\x58\x96\xff"
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

	// plain with two offered and one answered
	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000");
	expect(A, send, "8/PCMA/8000");
	expect(B, recv, "8/PCMA/8000");
	expect(B, send, "8/PCMA/8000");
	packet(A, 8, PCMA_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 8, PCMA_payload);
	end();

	// plain with two offered and one answered + asymmetric codecs
	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	flags.asymmetric_codecs = 1;
	answer();
	expect(A, recv, "8/PCMA/8000");
	expect(A, send, "0/PCMU/8000 8/PCMA/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "8/PCMA/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
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
	expect(B, recv, "8/PCMA/8000");
	expect(B, send, "8/PCMA/8000");
	packet(A, 0, PCMU_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	end();

	// same as above, but allow asymmetric codecs
	start();
	sdp_pt(0, PCMU, 8000);
	transcode(PCMA);
	offer();
	expect(A, recv, "");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	flags.asymmetric_codecs = 1;
	answer();
	expect(A, recv, "0/PCMU/8000");
	expect(A, send, "0/PCMU/8000");
	expect(B, recv, "0/PCMU/8000 8/PCMA/8000");
	expect(B, send, "8/PCMA/8000");
	packet(A, 0, PCMU_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
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
			expect(B, recv, "96/AMR-WB/16000/octet-align=1");
			expect(B, send, "96/AMR-WB/16000/octet-align=1");
			packet_seq(A, 0, PCMU_payload, 0, 0, -1, ""); // nothing due to resampling buffer
			packet_seq_nf(A, 0, PCMU_payload, 160, 1, 96, AMR_WB_payload);
			packet_seq(B, 96, AMR_WB_payload, 0, 0, -1, ""); // nothing due to resampling/decoding buffer
			packet_seq_nf(B, 96, AMR_WB_payload, 320, 1, 0, PCMU_payload);
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
			expect(B, recv, "0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			packet_seq(B, 0, PCMU_payload, 0, 0, -1, ""); // nothing due to resampling buffer
			packet_seq_nf(B, 0, PCMU_payload, 160, 1, 96, AMR_WB_payload);
			packet_seq(A, 96, AMR_WB_payload, 0, 0, -1, ""); // nothing due to resampling/decoding buffer
			packet_seq_nf(A, 96, AMR_WB_payload, 320, 1, 0, PCMU_payload);
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
			expect(B, recv, "0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			packet_seq(B, 0, PCMU_payload, 0, 0, -1, ""); // nothing due to resampling buffer
			packet_seq_nf(B, 0, PCMU_payload, 160, 1, 96, AMR_WB_payload_noe);
			packet_seq(A, 96, AMR_WB_payload_noe, 0, 0, -1, ""); // nothing due to resampling/decoding buffer
			packet_seq_nf(A, 96, AMR_WB_payload_noe, 320, 1, 0, PCMU_payload);
			end();
		}
	}

	// G.722 <> PCMA
	start();
	sdp_pt(8, PCMA, 8000);
	transcode(G722);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000");
	expect(B, recv, "8/PCMA/8000 9/G722/8000");
	expect(B, send, "");
	sdp_pt(9, G722, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000");
	expect(A, send, "8/PCMA/8000");
	expect(B, recv, "9/G722/8000");
	expect(B, send, "9/G722/8000");
	packet_seq(A, 8, PCMA_payload, 0, 0, -1, ""); // nothing due to resampling
	packet_seq_nf(A, 8, PCMA_payload, 160, 1, 9, G722_payload);
	packet_seq_ts(A, 8, PCMA_payload, 320, 2, 9, G722_payload, 160, 0);
	packet_seq(B, 9, G722_payload, 0, 0, -1, ""); // nothing due to resampling
	packet_seq_nf(B, 9, G722_payload, 160, 1, 8, PCMA_payload);
	packet_seq_ts(B, 9, G722_payload, 320, 2, 8, PCMA_payload, 160, 0);
	end();

	return 0;
}
