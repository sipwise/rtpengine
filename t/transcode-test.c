#include "codec.h"
#include "call.h"
#include "call_interfaces.h"
#include "log.h"
#include "main.h"
#include "ssrc.h"

int _log_facility_rtcp;
int _log_facility_cdr;
int _log_facility_dtmf;
struct rtpengine_config rtpe_config;
struct poller *rtpe_poller;
GString *dtmf_logs;

static str *sdup(char *s) {
	str *r = g_slice_alloc(sizeof(*r));
	char *d = strdup(s);
	str_init(r, d);
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
struct call_monologue ml_A;
struct call_monologue ml_B;
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
	call.tags = g_hash_table_new(g_str_hash, g_str_equal);
	str_init(&call.callid, "test-call");
	flags = (struct sdp_ng_flags) {0,};
	bencode_buffer_init(&call.buffer);
	media_A = call_media_new(&call); // originator
	media_B = call_media_new(&call); // output destination
	ml_A = (struct call_monologue) {0,};
	str_init(&ml_A.tag, "tag_A");
	media_A->monologue = &ml_A;
	media_A->protocol = &transport_protocols[PROTO_RTP_AVP];
	ml_B = (struct call_monologue) {0,};
	str_init(&ml_B.tag, "tag_B");
	media_B->monologue = &ml_B;
	media_B->protocol = &transport_protocols[PROTO_RTP_AVP];
	g_queue_init(&rtp_types); // parsed from received SDP
	flags.codec_strip = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
	flags.codec_mask = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
	flags.codec_set = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
}

#define transcode(codec) g_queue_push_tail(&flags.codec_transcode, sdup(#codec))

#ifdef WITH_AMR_TESTS
static void codec_set(char *c) {
	// from call_ng_flags_str_ht_split
	c = strdup(c);
	str s;
	str_init(&s, c);
	str splitter = s;

	while (1) {
		g_hash_table_replace(flags.codec_set, str_slice_dup(&splitter), str_slice_dup(&s));
		char *c = memrchr(splitter.s, '/', splitter.len);
		if (!c)
			break;
		splitter.len = c - splitter.s;
	}
}
#endif

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

static void offer(void) {
	printf("offer\n");
	codec_rtp_payload_types(media_B, media_A, &rtp_types, &flags);
	codec_handlers_update(media_B, media_A, &flags, NULL);
	g_queue_clear(&rtp_types);
	memset(&flags, 0, sizeof(flags));
}

static void answer(void) {
	printf("answer\n");
	codec_rtp_payload_types(media_A, media_B, &rtp_types, &flags);
	codec_handlers_update(media_A, media_B, &flags, NULL);
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
	printf("test ok: %s:%i\n\n", file, line);
	g_string_free(s, TRUE);
}

#ifdef WITH_AMR_TESTS
#define check_encoder(side, in_pt, out_pt, out_bitrate) \
	__check_encoder(__FILE__, __LINE__, media_ ## side, in_pt, out_pt, out_bitrate)

static void __check_encoder(const char *file, int line, struct call_media *m, int in_pt, int out_pt,
		int out_bitrate)
{
	struct codec_handler *ch = g_hash_table_lookup(m->codec_handlers, GINT_TO_POINTER(in_pt));
	printf("running test %s:%i\n", file, line);
	assert(ch->source_pt.payload_type == in_pt);
	if (ch->dest_pt.payload_type != out_pt || ch->dest_pt.bitrate != out_bitrate) {
		printf("test failed: %s:%i\n", file, line);
		printf("expected: %i/%i\n", out_pt, out_bitrate);
		printf("received: %i/%i\n", ch->dest_pt.payload_type, ch->dest_pt.bitrate);
		abort();
	}
	printf("test ok: %s:%i\n", file, line);
}
#endif

#define packet_seq_ts(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, ts_exp, fatal) \
	__packet_seq_ts( __FILE__, __LINE__, media_ ## side, pt_in, (str) STR_CONST_INIT(pload), \
			(str) STR_CONST_INIT(pload_exp), ssrc_ ## side, rtp_ts, rtp_seq, pt_out, \
			ts_exp, 1, fatal)

#define packet_seq_exp(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, ts_diff_exp) \
	__packet_seq_ts( __FILE__, __LINE__, media_ ## side, pt_in, (str) STR_CONST_INIT(pload), \
			(str) STR_CONST_INIT(pload_exp), ssrc_ ## side, rtp_ts, rtp_seq, pt_out, \
			-1, ts_diff_exp, 1)

static void __packet_seq_ts(const char *file, int line, struct call_media *media, long long pt_in, str pload,
		str pload_exp, uint32_t ssrc, long long rtp_ts, long long rtp_seq, long long pt_out,
		long long ts_exp, int seq_diff_exp, int fatal)
{
	printf("running test %s:%i\n", file, line);
	struct codec_handler *h = codec_handler_get(media, pt_in & 0x7f);
	str pl = pload;
	str pl_exp = pload_exp;

	// from media_packet_rtp()
	struct media_packet mp = {
		.call = &call,
		.media = media,
		.ssrc_in = get_ssrc_ctx(ssrc, call.ssrc_hash, SSRC_DIR_INPUT, NULL),
	};
	// from __stream_ssrc()
	if (!MEDIA_ISSET(media, TRANSCODE))
		mp.ssrc_in->ssrc_map_out = ntohl(ssrc);
	mp.ssrc_out = get_ssrc_ctx(mp.ssrc_in->ssrc_map_out, call.ssrc_hash, SSRC_DIR_OUTPUT, NULL);
	payload_tracker_add(&mp.ssrc_in->tracker, pt_in & 0x7f);

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
	printf("send RTP SSRC %x seq %u TS %u PT %u\n", (unsigned int) ssrc,
			(unsigned int) rtp_seq, (unsigned int) rtp_ts, (unsigned int) pt_in);
	printf("send packet contents: ");
	for (int i = sizeof(struct rtp_header); i < mp.raw.len; i++) {
		unsigned char cc = mp.raw.s[i];
		printf("\\x%02x", cc);
	}
	printf("\n");

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
		printf("recv packet contents: ");
		for (int i = sizeof(struct rtp_header); i < cp->s.len; i++) {
			unsigned char cc = cp->s.s[i];
			printf("\\x%02x", cc);
		}
		printf("\n");
		uint32_t ts = ntohl(rtp->timestamp);
		uint16_t seq = ntohs(rtp->seq_num);
		uint32_t ssrc = ntohl(rtp->ssrc);
		uint32_t ssrc_pt = ssrc;
		printf("recv RTP SSRC %x seq %u TS %u PT %u\n", (unsigned int) ssrc,
				(unsigned int) seq, (unsigned int) ts, (unsigned int) rtp->m_pt);
		if (g_hash_table_contains(rtp_ts_ht, GUINT_TO_POINTER(ssrc_pt))) {
			uint32_t old_ts = GPOINTER_TO_UINT(g_hash_table_lookup(rtp_ts_ht,
						GUINT_TO_POINTER(ssrc_pt)));
			uint32_t diff = ts - old_ts;
			printf("recv RTP TS diff: %u\n", (unsigned int) diff);
			if (ts_exp != -1)
				assert(ts_exp == diff);
		}
		g_hash_table_insert(rtp_ts_ht, GUINT_TO_POINTER(ssrc_pt), GUINT_TO_POINTER(ts));
		if (g_hash_table_contains(rtp_seq_ht, GUINT_TO_POINTER(ssrc_pt))) {
			uint32_t old_seq = GPOINTER_TO_UINT(g_hash_table_lookup(rtp_seq_ht,
						GUINT_TO_POINTER(ssrc_pt)));
			uint16_t diff = seq - old_seq;
			printf("recv RTP seq diff: %u (exp %u)\n", (unsigned int) diff,
					(unsigned int) seq_diff_exp);
			assert(diff == seq_diff_exp);
		}
		g_hash_table_insert(rtp_seq_ht, GUINT_TO_POINTER(ssrc_pt), GUINT_TO_POINTER(seq));
		if (str_shift(&cp->s, sizeof(struct rtp_header)))
			abort();
		if (pl_exp.len != cp->s.len)
			abort();
		if (fatal && memcmp(pl_exp.s, cp->s.s, pl_exp.len))
			abort();
	}
	printf("test ok: %s:%i\n\n", file, line);
	free(packet);
}

#define packet(side, pt_in, pload, pt_out, pload_exp) \
	packet_seq(side, pt_in, pload, 0, 0, pt_out, pload_exp)

#define packet_seq(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp) \
	packet_seq_ts(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, -1, 1)

#define packet_seq_nf(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp) \
	packet_seq_ts(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, -1, 0)

static void end(void) {
	g_hash_table_destroy(rtp_ts_ht);
	g_hash_table_destroy(rtp_seq_ht);
	printf("\n");
}

static void dtmf(const char *s) {
	if (!dtmf_logs) {
		if (strlen(s) != 0)
			abort();
		return;
	}
	if (strlen(s) != dtmf_logs->len) {
		printf("DTMF mismatch: \"%s\" != \"%s\"\n", s, dtmf_logs->str);
		abort();
	}
	if (memcmp(s, dtmf_logs->str, dtmf_logs->len) != 0) {
		printf("DTMF mismatch: \"%s\" != \"%s\"\n", s, dtmf_logs->str);
		abort();
	}
	printf("DTMF log ok; contents: \"%s\"\n", dtmf_logs->str);
	g_string_assign(dtmf_logs, "");
}

#define PCMU_payload "\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00"
#define PCMA_payload "\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a\x2b\x2a"
#define G722_payload "\x23\x84\x20\x84\x20\x84\x04\x84\x04\x04\x84\x04\x84\x04\x84\x05\x85\x46\x87\x48\xc8\x48\x88\x48\xc8\x49\x8a\x4b\xcc\x4c\x8c\x4c\xcc\x4c\x8c\x4d\xce\x50\xcf\x51\x90\x50\xcf\x12\xd1\x52\xd2\x54\x91\x52\xd2\x54\x92\x54\xd3\x56\x93\xd6\x94\xd4\x93\xd7\xd5\x55\x94\x55\xd5\x55\xd4\x56\xd5\x17\xd7\x5a\x95\xd7\x97\xd9\xd4\x16\x58\x57\x98\xd5\xd7\x5b\x96\xda\xd6\x1b\x57\x5a\xd6\x1a\x57\x5b\x98\xd6\xd8\x56\x98\xd7\xd9\x5a\x95\xdb\xd6\x1c\x52\x5e\xd7\x5c\x93\xdf\x99\xd5\xd7\x5f\xd9\x14\x56\x7f\x92\xda\xd9\x5c\x92\xdd\xd7\x5d\x92\xff\xd6\x5a\x96\xdc\xd5\x18\x56\x7e\xd2\x5e\x96\xde\x94\xd8\xd8\x58\xd3\x79\x93\xfb\x90\xdc\xd6\x5b\xdd\x58\x96\xff"
#define AMR_WB_payload "\xf0\x1c\xf3\x06\x08\x10\x77\x32\x23\x20\xd3\x50\x62\x12\xc7\x7c\xe2\xea\x84\x0e\x6e\xf4\x4d\xe4\x7f\xc9\x4c\xcc\x58\x5d\xed\xcc\x5d\x7c\x6c\x14\x7d\xc0" // octet aligned
#define AMR_WB_payload_noe "\xf1\xfc\xc1\x82\x04\x1d\xcc\x88\xc8\x34\xd4\x18\x84\xb1\xdf\x38\xba\xa1\x03\x9b\xbd\x13\x79\x1f\xf2\x53\x33\x16\x17\x7b\x73\x17\x5f\x1b\x05\x1f\x70" // bandwidth efficient

int main(void) {
	codeclib_init(0);
	srandom(time(NULL));
	statistics_init();

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
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
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
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
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
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
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
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
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
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
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
	packet_seq(B, 8, PCMA_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 160, 1, 0, PCMU_payload);
	end();

#ifdef WITH_AMR_TESTS
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

	{
		str codec_name = STR_CONST_INIT("AMR");
		const codec_def_t *def = codec_find(&codec_name, MT_AUDIO);
		assert(def);
		if (def->support_encoding && def->support_decoding) {
			// default bitrate
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR);
			offer();
			expect(A, recv, "");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "0/PCMU/8000 96/AMR/8000/octet-align=1");
			expect(B, send, "");
			sdp_pt_fmt(96, AMR, 8000, "octet-align=1");
			answer();
			expect(A, recv, "0/PCMU/8000");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "96/AMR/8000/octet-align=1");
			expect(B, send, "96/AMR/8000/octet-align=1");
			check_encoder(A, 0, 96, 0); // uses codec default
			check_encoder(B, 96, 0, 0);
			end();

			// default bitrate reverse
			start();
			sdp_pt(96, AMR, 8000);
			transcode(PCMU);
			offer();
			expect(A, recv, "");
			expect(A, send, "96/AMR/8000");
			expect(B, recv, "96/AMR/8000 0/PCMU/8000");
			expect(B, send, "");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, recv, "96/AMR/8000");
			expect(A, send, "96/AMR/8000");
			expect(B, recv, "0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			check_encoder(A, 96, 0, 0);
			check_encoder(B, 0, 96, 0); // uses codec default
			end();

			// specify forward bitrate
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR/8000/1/6700);
			offer();
			expect(A, recv, "");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "0/PCMU/8000 96/AMR/8000/octet-align=1");
			expect(B, send, "");
			sdp_pt_fmt(96, AMR, 8000, "octet-align=1");
			answer();
			expect(A, recv, "0/PCMU/8000");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "96/AMR/8000/octet-align=1");
			expect(B, send, "96/AMR/8000/octet-align=1");
			check_encoder(A, 0, 96, 6700);
			check_encoder(B, 96, 0, 0);
			end();

			// specify non-default forward bitrate
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR/8000/1/7400);
			offer();
			expect(A, recv, "");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "0/PCMU/8000 96/AMR/8000/octet-align=1");
			expect(B, send, "");
			sdp_pt_fmt(96, AMR, 8000, "octet-align=1");
			answer();
			expect(A, recv, "0/PCMU/8000");
			expect(A, send, "0/PCMU/8000");
			expect(B, recv, "96/AMR/8000/octet-align=1");
			expect(B, send, "96/AMR/8000/octet-align=1");
			check_encoder(A, 0, 96, 7400);
			check_encoder(B, 96, 0, 0);
			end();

			// specify reverse bitrate
			start();
			sdp_pt(96, AMR, 8000);
			transcode(PCMU);
			codec_set("AMR/8000/1/6700");
			offer();
			expect(A, recv, "");
			expect(A, send, "96/AMR/8000");
			expect(B, recv, "96/AMR/8000 0/PCMU/8000");
			expect(B, send, "");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, recv, "96/AMR/8000");
			expect(A, send, "96/AMR/8000");
			expect(B, recv, "0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			check_encoder(A, 96, 0, 0);
			check_encoder(B, 0, 96, 6700);
			end();

			// specify non-default reverse bitrate
			start();
			sdp_pt(96, AMR, 8000);
			transcode(PCMU);
			codec_set("AMR/8000/1/7400");
			offer();
			expect(A, recv, "");
			expect(A, send, "96/AMR/8000");
			expect(B, recv, "96/AMR/8000 0/PCMU/8000");
			expect(B, send, "");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, recv, "96/AMR/8000");
			expect(A, send, "96/AMR/8000");
			expect(B, recv, "0/PCMU/8000");
			expect(B, send, "0/PCMU/8000");
			check_encoder(A, 96, 0, 0);
			check_encoder(B, 0, 96, 7400);
			end();
		}
	}
#endif

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

	// A includes unsupported codec by B - no transcoding (GH#562 control case)
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "9/G722/8000 8/PCMA/8000");
	expect(A, send, "9/G722/8000 8/PCMA/8000");
	expect(B, recv, "9/G722/8000 8/PCMA/8000");
	expect(B, send, "9/G722/8000 8/PCMA/8000");
	end();

	// A includes unsupported codec by B - no transcoding (GH#562 control case) + asymmetric codecs
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, send, "");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	flags.asymmetric_codecs = 1;
	answer();
	expect(A, recv, "9/G722/8000 8/PCMA/8000");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, send, "9/G722/8000 8/PCMA/8000");
	end();

	// A includes unsupported codec by B - transcoded codec accepted (GH#562 control case)
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	transcode(PCMU); // standin for G729
	offer();
	expect(A, recv, "");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, send, "");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, send, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	end();

	// A includes unsupported codec by B - transcoded codec rejected (GH#562)
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	transcode(PCMU); // standin for G729
	offer();
	expect(A, recv, "");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, send, "");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, recv, "9/G722/8000 8/PCMA/8000");
	expect(A, send, "9/G722/8000 8/PCMA/8000");
	expect(B, recv, "9/G722/8000 8/PCMA/8000");
	expect(B, send, "9/G722/8000 8/PCMA/8000");
	end();

	// A includes unsupported codec by B - transcoded codec rejected (GH#562) + asymmetric codecs
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	transcode(PCMU); // standin for G729
	offer();
	expect(A, recv, "");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, send, "");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	flags.asymmetric_codecs = 1;
	answer();
	expect(A, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(A, send, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, recv, "97/opus/48000 9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, send, "9/G722/8000 8/PCMA/8000");
	end();

	_log_facility_dtmf = 1; // dummy enabler

	// plain DTMF passthrough w/o transcoding
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "8/PCMA/8000 101/telephone-event/8000");
	packet_seq(A, 8, PCMA_payload, 1000000, 200, 8, PCMA_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x08\x0a\x00\xa0", 1000160, 201, 101 | 0x80, "\x08\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	// XXX check output ts, seq, ssrc
	packet_seq(A, 101, "\x08\x0a\x01\x40", 1000160, 202, 101, "\x08\x0a\x01\x40");
	packet_seq(A, 101, "\x08\x0a\x01\xe0", 1000160, 203, 101, "\x08\x0a\x01\xe0");
	packet_seq(A, 101, "\x08\x0a\x02\x80", 1000160, 204, 101, "\x08\x0a\x02\x80");
	dtmf("");
	// end
	packet_seq(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 8, PCMA_payload, 1000960, 206, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 1001120, 207, 8, PCMA_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, 101 | 0x80, "\x05\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, 101, "\x05\x0a\x01\x40");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, 101, "\x05\x0a\x01\xe0");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80", 0);
	dtmf("");
	// final audio RTP test
	packet_seq(A, 8, PCMA_payload, 1000960, 212, 8, PCMA_payload);
	end();

	// DTMF passthrough w/ transcoding
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	transcode(PCMU);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000 0/PCMU/8000");
	expect(B, send, "");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "101/telephone-event/8000 0/PCMU/8000");
	expect(B, send, "0/PCMU/8000 101/telephone-event/8000");
	packet_seq(A, 8, PCMA_payload, 1000000, 200, 0, PCMU_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x08\x0a\x00\xa0", 1000160, 201, 101 | 0x80, "\x08\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	// XXX check output ts, seq, ssrc
	packet_seq(A, 101, "\x08\x0a\x01\x40", 1000160, 202, 101, "\x08\x0a\x01\x40");
	packet_seq(A, 101, "\x08\x0a\x01\xe0", 1000160, 203, 101, "\x08\x0a\x01\xe0");
	packet_seq(A, 101, "\x08\x0a\x02\x80", 1000160, 204, 101, "\x08\x0a\x02\x80");
	dtmf("");
	// end
	packet_seq(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 8, PCMA_payload, 1000960, 206, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 1001120, 207, 0, PCMU_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, 101 | 0x80, "\x05\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, 101, "\x05\x0a\x01\x40");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, 101, "\x05\x0a\x01\xe0");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80", 0);
	dtmf("");
	// final audio RTP test
	packet_seq(A, 8, PCMA_payload, 1000960, 212, 0, PCMU_payload);
	end();

	// plain DTMF passthrough w/o transcoding w/ implicit primary payload type
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "8/PCMA/8000 101/telephone-event/8000");
	packet_seq(A, 0, PCMU_payload, 1000000, 200, 0, PCMU_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x08\x0a\x00\xa0", 1000160, 201, 101 | 0x80, "\x08\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	// XXX check output ts, seq, ssrc
	packet_seq(A, 101, "\x08\x0a\x01\x40", 1000160, 202, 101, "\x08\x0a\x01\x40");
	packet_seq(A, 101, "\x08\x0a\x01\xe0", 1000160, 203, 101, "\x08\x0a\x01\xe0");
	packet_seq(A, 101, "\x08\x0a\x02\x80", 1000160, 204, 101, "\x08\x0a\x02\x80");
	dtmf("");
	// end
	packet_seq(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 0, PCMU_payload, 1000960, 206, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 1001120, 207, 0, PCMU_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, 101 | 0x80, "\x05\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, 101, "\x05\x0a\x01\x40");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, 101, "\x05\x0a\x01\xe0");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, 101, "\x05\x8a\x02\x80", 0);
	dtmf("");
	// final audio RTP test
	packet_seq(A, 0, PCMU_payload, 1000960, 212, 0, PCMU_payload);
	end();

	// plain DTMF passthrough w/o transcoding - blocking
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "8/PCMA/8000 101/telephone-event/8000");
	packet_seq(A, 8, PCMA_payload, 1000000, 200, 8, PCMA_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x08\x0a\x00\xa0", 1000160, 201, 101 | 0x80, "\x08\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	// XXX check output ts, seq, ssrc
	packet_seq(A, 101, "\x08\x0a\x01\x40", 1000160, 202, 101, "\x08\x0a\x01\x40");
	packet_seq(A, 101, "\x08\x0a\x01\xe0", 1000160, 203, 101, "\x08\x0a\x01\xe0");
	packet_seq(A, 101, "\x08\x0a\x02\x80", 1000160, 204, 101, "\x08\x0a\x02\x80");
	dtmf("");
	// end
	packet_seq(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 8, PCMA_payload, 1000960, 206, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 1001120, 207, 8, PCMA_payload);
	// enable blocking
	call.block_dtmf = 1;
	// start with marker
	packet_seq_exp(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, -1, "", 0);
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, -1, "");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, -1, "");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	dtmf("");
	// final audio RTP test
	packet_seq_exp(A, 8, PCMA_payload, 1000960, 212, 8, PCMA_payload, 5); // DTMF packets appear lost
	packet_seq(A, 8, PCMA_payload, 1001120, 213, 8, PCMA_payload);
	// media blocking
	ml_A.block_media = 1;
	packet_seq_exp(A, 8, PCMA_payload, 1001280, 214, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001440, 215, -1, "", 0);
	ml_A.block_media = 0;
	packet_seq_exp(A, 8, PCMA_payload, 1001600, 216, 8, PCMA_payload, 3); // media packets appear lost
	call.block_media = 1;
	packet_seq_exp(A, 8, PCMA_payload, 1001760, 217, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001920, 218, -1, "", 0);
	call.block_media = 0;
	packet_seq_exp(A, 8, PCMA_payload, 1002080, 219, 8, PCMA_payload, 3); // media packets appear lost
	ml_B.block_media = 1;
	packet_seq(A, 8, PCMA_payload, 1002240, 220, 8, PCMA_payload);
	end();

	// DTMF passthrough w/ transcoding - blocking
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	transcode(PCMU);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000 0/PCMU/8000");
	expect(B, send, "");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "101/telephone-event/8000 0/PCMU/8000");
	expect(B, send, "0/PCMU/8000 101/telephone-event/8000");
	packet_seq(A, 8, PCMA_payload, 1000000, 200, 0, PCMU_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x08\x0a\x00\xa0", 1000160, 201, 101 | 0x80, "\x08\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	// XXX check output ts, seq, ssrc
	packet_seq(A, 101, "\x08\x0a\x01\x40", 1000160, 202, 101, "\x08\x0a\x01\x40");
	packet_seq(A, 101, "\x08\x0a\x01\xe0", 1000160, 203, 101, "\x08\x0a\x01\xe0");
	packet_seq(A, 101, "\x08\x0a\x02\x80", 1000160, 204, 101, "\x08\x0a\x02\x80");
	dtmf("");
	// end
	packet_seq(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 8, PCMA_payload, 1000960, 206, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 1001120, 207, 0, PCMU_payload);
	// enable blocking
	call.block_dtmf = 1;
	// start with marker
	packet_seq_exp(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, -1, "", 0);
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, -1, "");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, -1, "");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	dtmf("");
	// final audio RTP test
	packet_seq_exp(A, 8, PCMA_payload, 1000960, 212, 0, PCMU_payload, 5); // DTMF packets appear lost
	packet_seq(A, 8, PCMA_payload, 1001120, 213, 0, PCMU_payload);
	// media blocking
	ml_A.block_media = 1;
	packet_seq_exp(A, 8, PCMA_payload, 1001280, 214, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001440, 215, -1, "", 0);
	ml_A.block_media = 0;
	packet_seq_exp(A, 8, PCMA_payload, 1001600, 214, 0, PCMU_payload, 1); // cheat with the seq here - 216 would get held by the jitter buffer
	call.block_media = 1;
	packet_seq_exp(A, 8, PCMA_payload, 1001760, 215, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001920, 216, -1, "", 0);
	call.block_media = 0;
	packet_seq_exp(A, 8, PCMA_payload, 1002080, 215, 0, PCMU_payload, 1);
	ml_B.block_media = 1;
	packet_seq_exp(A, 8, PCMA_payload, 1002240, 216, 0, PCMU_payload, 1);
	end();

	// plain DTMF passthrough w/o transcoding w/ implicit primary payload type - blocking
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	offer();
	expect(A, recv, "");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(A, send, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, recv, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, send, "8/PCMA/8000 101/telephone-event/8000");
	packet_seq(A, 0, PCMU_payload, 1000000, 200, 0, PCMU_payload);
	// start with marker
	packet_seq(A, 101 | 0x80, "\x08\x0a\x00\xa0", 1000160, 201, 101 | 0x80, "\x08\x0a\x00\xa0");
	dtmf("");
	// continuous event with increasing length
	// XXX check output ts, seq, ssrc
	packet_seq(A, 101, "\x08\x0a\x01\x40", 1000160, 202, 101, "\x08\x0a\x01\x40");
	packet_seq(A, 101, "\x08\x0a\x01\xe0", 1000160, 203, 101, "\x08\x0a\x01\xe0");
	packet_seq(A, 101, "\x08\x0a\x02\x80", 1000160, 204, 101, "\x08\x0a\x02\x80");
	dtmf("");
	// end
	packet_seq(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 0, PCMU_payload, 1000960, 206, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 1001120, 207, 0, PCMU_payload);
	// enable blocking
	call.block_dtmf = 1;
	// start with marker
	packet_seq_exp(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, -1, "", 0);
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, -1, "");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, -1, "");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	dtmf("");
	// final audio RTP test
	packet_seq_exp(A, 0, PCMU_payload, 1000960, 212, 0, PCMU_payload, 5); // DTMF packets appear lost
	packet_seq(A, 0, PCMU_payload, 1001120, 213, 0, PCMU_payload);
	// media blocking
	ml_A.block_media = 1;
	packet_seq_exp(A, 0, PCMU_payload, 1001280, 214, -1, "", 0);
	packet_seq_exp(A, 0, PCMU_payload, 1001440, 215, -1, "", 0);
	ml_A.block_media = 0;
	packet_seq_exp(A, 0, PCMU_payload, 1001600, 216, 0, PCMU_payload, 3); // media packets appear lost
	call.block_media = 1;
	packet_seq_exp(A, 0, PCMU_payload, 1001760, 217, -1, "", 0);
	packet_seq_exp(A, 0, PCMU_payload, 1001920, 218, -1, "", 0);
	call.block_media = 0;
	packet_seq_exp(A, 0, PCMU_payload, 1002080, 219, 0, PCMU_payload, 3); // media packets appear lost
	ml_B.block_media = 1;
	packet_seq(A, 0, PCMU_payload, 1002240, 220, 0, PCMU_payload);
	end();

	return 0;
}
