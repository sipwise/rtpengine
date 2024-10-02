#include "codec.h"
#include "call.h"
#include "call_interfaces.h"
#include "log.h"
#include "main.h"
#include "ssrc.h"
#include "helpers.h"
#include "bufferpool.h"

int _log_facility_rtcp;
int _log_facility_cdr;
int _log_facility_dtmf;
struct rtpengine_config rtpe_config;
struct rtpengine_config initial_rtpe_config;
struct poller **rtpe_pollers;
struct poller *rtpe_control_poller;
struct poller *uring_poller;
unsigned int num_media_pollers;
unsigned int rtpe_poller_rr_iter;
GString *dtmf_logs;
GQueue rtpe_control_ng = G_QUEUE_INIT;
struct bufferpool *shm_bufferpool;

static str *sdup(char *s) {
	str r = STR(s);
	return str_dup(&r);
}
static void queue_dump(GString *s, rtp_pt_q *q) {
	for (__auto_type l = q->head; l; l = l->next) {
		if (s->len)
			g_string_append(s, " ");
		rtp_payload_type *pt = l->data;
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
static call_t call;
static sdp_ng_flags flags;
static struct call_media *media_A;
static struct call_media *media_B;
struct call_monologue *ml_A;
struct call_monologue *ml_B;
struct stream_params rtp_types_sp;

#define start() __start(__FILE__, __LINE__)

static void __cleanup(void) {
	str_case_ht_destroy_ptr(&flags.codec_except);
	str_case_value_ht_destroy_ptr(&flags.codec_set);
	str_case_ht_destroy_ptr(&flags.sdes_no);
	t_queue_clear_full(&flags.codec_offer, str_free);
	t_queue_clear_full(&flags.codec_transcode, str_free);
	t_queue_clear_full(&flags.codec_strip, str_free);
	t_queue_clear_full(&flags.codec_accept, str_free);
	t_queue_clear_full(&flags.codec_consume, str_free);
	t_queue_clear_full(&flags.codec_mask, str_free);
	t_queue_clear(&call.monologues);

	codec_store_cleanup(&rtp_types_sp.codecs);
	memset(&flags, 0, sizeof(flags));
}
static void __init(void) {
	__cleanup();
	codec_store_init(&rtp_types_sp.codecs, NULL);
	rtp_types_sp.rtp_endpoint.port = 9;
	flags.codec_except = str_case_ht_new();
	flags.codec_set = str_case_value_ht_new();
}
static struct packet_stream *ps_new(call_t *c) {
	struct packet_stream *ps = malloc(sizeof(*ps));
	assert(ps != NULL);
	memset(ps, 0, sizeof(*ps));
	ps->endpoint.port = 12345;
	return ps;
}
static void __start(const char *file, int line) {
	printf("running test %s:%i\n", file, line);
	rtp_ts_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	rtp_seq_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	ssrc_A = 1234;
	ssrc_B = 2345;
	ZERO(call);
	obj_hold(&call);
	call.tags = tags_ht_new();
	call.callid = STR("test-call");
	bencode_buffer_init(&call.buffer);
	call_memory_arena_set(&call);
	ml_A = __monologue_create(&call);
	ml_B = __monologue_create(&call);
	media_A = call_media_new(&call); // originator
	media_B = call_media_new(&call); // output destination
	t_queue_push_tail(&media_A->streams, ps_new(&call));
	t_queue_push_tail(&media_B->streams, ps_new(&call));
	ml_A->tag = STR("tag_A");
	ml_A->label = STR("label_A");
	media_A->monologue = ml_A;
	media_A->protocol = &transport_protocols[PROTO_RTP_AVP];
	ml_B->tag = STR("tag_B");
	ml_B->label = STR("label_B");
	media_B->monologue = ml_B;
	media_B->protocol = &transport_protocols[PROTO_RTP_AVP];
	__init();
}

#define transcode(codec) t_queue_push_tail(&flags.codec_transcode, sdup(#codec))
#define c_accept(codec) t_queue_push_tail(&flags.codec_accept, sdup(#codec))
#define c_consume(codec) t_queue_push_tail(&flags.codec_consume, sdup(#codec))
#define c_mask(codec) t_queue_push_tail(&flags.codec_mask, sdup(#codec))

#ifdef WITH_AMR_TESTS
static void codec_set(char *c) {
	// from call_ng_flags_str_ht_split
	c = strdup(c);
	str s = STR(c);
	str splitter = s;

	while (1) {
		t_hash_table_replace(flags.codec_set, str_dup(&splitter), str_dup(&s));
		char *cp = memrchr(splitter.s, '/', splitter.len);
		if (!cp)
			break;
		splitter.len = cp - splitter.s;
	}
	free(c);
}
#endif

//static void __ht_set(GHashTable *h, char *x) {
//	str *d = sdup(x);
//	g_hash_table_insert(h, d, d);
//}
//#define ht_set(ht, s) __ht_set(flags.ht, #s)

#define sdp_pt_fmt_ch(num, codec, clockrate, channels, fmt) \
	__sdp_pt_fmt(num, (str) STR_CONST(#codec), clockrate, channels, (str) STR_CONST(#codec "/" #clockrate), \
			(str) STR_CONST(#codec "/" #clockrate "/" #channels), (str) STR_CONST(fmt))

#define sdp_pt_fmt(num, codec, clockrate, fmt) sdp_pt_fmt_ch(num, codec, clockrate, 1, fmt)
#define sdp_pt_fmt_s(num, codec, clockrate, fmt) sdp_pt_fmt_ch(num, codec, clockrate, 2, fmt)

static void __sdp_pt_fmt(int num, str codec, int clockrate, int channels, str full_codec, str full_full, str fmt) {
	str *fmtdup = str_dup(&fmt);
	rtp_payload_type pt = (rtp_payload_type) {
		.payload_type = num,
		.encoding_with_params = full_codec,
		.encoding_with_full_params = full_full,
		.encoding = codec,
		.clock_rate = clockrate,
		.encoding_parameters = STR_CONST(""),
		.channels = channels,
		.format_parameters = *fmtdup,
		.codec_opts = STR_NULL,
		.rtcp_fb = G_QUEUE_INIT,
		.ptime = 0,
		.bitrate = 0,
		.codec_def = NULL,
	};
	codec_store_add_raw(&rtp_types_sp.codecs, rtp_payload_type_dup(&pt));
	free(fmtdup);
}

#define sdp_pt(num, codec, clockrate) sdp_pt_fmt(num, codec, clockrate, "")
#define sdp_pt_s(num, codec, clockrate) sdp_pt_fmt_s(num, codec, clockrate, "")

static void offer(void) {
	printf("offer\n");
	flags.opmode = OP_OFFER;

	codecs_offer_answer(media_B, media_A, &rtp_types_sp, &flags);
	__init();
}

static void answer(void) {
	printf("answer\n");
	flags.opmode = OP_ANSWER;

	codecs_offer_answer(media_A, media_B, &rtp_types_sp, &flags);
	__init();
}

#define expect(side, exp_str) \
	__expect(__FILE__, __LINE__, &media_ ## side->codecs.codec_prefs, exp_str)

static void __expect(const char *file, int line, rtp_pt_q *dumper, const char *codecs) {
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
#define check_encoder(side, otherside, in_pt, out_pt, out_bitrate) \
	__check_encoder(__FILE__, __LINE__, media_ ## side, media_ ## otherside, in_pt, out_pt, out_bitrate)

static void __check_encoder(const char *file, int line, struct call_media *m,
		struct call_media *out_m, int in_pt, int out_pt,
		int out_bitrate)
{
	struct codec_handler *ch = codec_handler_lookup(m->codec_handlers, in_pt, out_m);
	printf("running test %s:%i\n", file, line);
	assert(ch);
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
	__packet_seq_ts( __FILE__, __LINE__, media_ ## side, pt_in, (str) STR_CONST(pload), \
			(str) STR_CONST(pload_exp), ssrc_ ## side, rtp_ts, rtp_seq, pt_out, \
			ts_exp, 1, fatal)

#define packet_seq_exp(side, pt_in, pload, rtp_ts, rtp_seq, pt_out, pload_exp, ts_diff_exp) \
	__packet_seq_ts( __FILE__, __LINE__, media_ ## side, pt_in, (str) STR_CONST(pload), \
			(str) STR_CONST(pload_exp), ssrc_ ## side, rtp_ts, rtp_seq, pt_out, \
			-1, ts_diff_exp, 1)

static void __packet_seq_ts(const char *file, int line, struct call_media *media, long long pt_in, str pload,
		str pload_exp, uint32_t ssrc, long long rtp_ts, long long rtp_seq, long long pt_out,
		long long ts_exp, int seq_diff_exp, int fatal)
{
	printf("running test %s:%i\n", file, line);
	struct call_media *other_media;
	if (media == media_A)
		other_media = media_B;
	else if (media == media_B)
		other_media = media_A;
	else
		abort();
	struct codec_handler *h = codec_handler_get(media, pt_in & 0x7f, other_media, NULL);
	str pl = pload;
	str pl_exp = pload_exp;

	// from media_packet_rtp()
	struct interface_stats_block sblock;
	struct local_intf lif = { .stats = &sblock };
	stream_fd sfd = {
		.local_intf = &lif,
	};
	struct media_packet mp = {
		.call = &call,
		.media = media,
		.media_out = other_media,
		.ssrc_in = get_ssrc_ctx(ssrc, media->monologue->ssrc_hash, SSRC_DIR_INPUT, NULL),
		.sfd = &sfd,
	};
	// from __stream_ssrc()
	if (!MEDIA_ISSET(media, TRANSCODING))
		mp.ssrc_in->ssrc_map_out = ntohl(ssrc);
	mp.ssrc_out = get_ssrc_ctx(mp.ssrc_in->ssrc_map_out, other_media->monologue->ssrc_hash, SSRC_DIR_OUTPUT, NULL);
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
	mp.raw = STR_LEN(packet, packet_len);
	printf("send RTP SSRC %x seq %u TS %u PT %u\n", (unsigned int) ssrc,
			(unsigned int) rtp_seq, (unsigned int) rtp_ts, (unsigned int) pt_in);
	printf("send packet contents: ");
	for (int i = sizeof(struct rtp_header); i < mp.raw.len; i++) {
		unsigned char cc = mp.raw.s[i];
		printf("\\x%02x", cc);
	}
	printf("\n");

	h->handler_func(h, &mp);

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
		struct codec_packet *cp = t_queue_pop_head(&mp.packets_out);
		str cp_s = cp->s;
		rtp = (void *) cp_s.s;
		if (rtp->m_pt != (unsigned char) pt_out) {
			printf("test failed: %s:%i\n", file, line);
			printf("expected: %lli\n", pt_out);
			printf("received: %i\n", rtp->m_pt);
			abort();
		}
		printf("recv packet contents: ");
		for (int i = sizeof(struct rtp_header); i < cp_s.len; i++) {
			unsigned char cc = cp_s.s[i];
			printf("\\x%02x", cc);
		}
		printf("\n");
		uint32_t ts = ntohl(rtp->timestamp);
		uint16_t seq = ntohs(rtp->seq_num);
		uint32_t rtp_ssrc = ntohl(rtp->ssrc);
		uint32_t ssrc_pt = rtp_ssrc;
		printf("recv RTP SSRC %x seq %u TS %u PT %u\n", (unsigned int) rtp_ssrc,
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
		if (str_shift(&cp_s, sizeof(struct rtp_header)))
			abort();
		if (pl_exp.len != cp_s.len)
			abort();
		if (fatal && memcmp(pl_exp.s, cp_s.s, pl_exp.len))
			abort();
		codec_packet_free(cp);
	}
	printf("test ok: %s:%i\n\n", file, line);
	free(packet);
	ssrc_ctx_put(&mp.ssrc_in);
	ssrc_ctx_put(&mp.ssrc_out);
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
	t_queue_clear_full(&media_A->streams, (void (*)(struct packet_stream *)) free);
	t_queue_clear_full(&media_B->streams, (void (*)(struct packet_stream *)) free);
	call_media_free(&media_A);
	call_media_free(&media_B);
	bencode_buffer_free(&call.buffer);
	t_hash_table_destroy(call.tags);
	t_queue_clear(&call.medias);
	if (ml_A)
		__monologue_free(ml_A);
	if (ml_B)
		__monologue_free(ml_B);
	__cleanup();
	call_memory_arena_release();
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
#define PCMA_silence "\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5"
#define PCMU_silence "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
#define G722_payload "\x23\x84\x20\x84\x20\x84\x04\x84\x04\x04\x84\x04\x84\x04\x84\x05\x85\x46\x87\x48\xc8\x48\x88\x48\xc8\x49\x8a\x4b\xcc\x4c\x8c\x4c\xcc\x4c\x8c\x4d\xce\x50\xcf\x51\x90\x50\xcf\x12\xd1\x52\xd2\x54\x91\x52\xd2\x54\x92\x54\xd3\x56\x93\xd6\x94\xd4\x93\xd7\xd5\x55\x94\x55\xd5\x55\xd4\x56\xd5\x17\xd7\x5a\x95\xd7\x97\xd9\xd4\x16\x58\x57\x98\xd5\xd7\x5b\x96\xda\xd6\x1b\x57\x5a\xd6\x1a\x57\x5b\x98\xd6\xd8\x56\x98\xd7\xd9\x5a\x95\xdb\xd6\x1c\x52\x5e\xd7\x5c\x93\xdf\x99\xd5\xd7\x5f\xd9\x14\x56\x7f\x92\xda\xd9\x5c\x92\xdd\xd7\x5d\x92\xff\xd6\x5a\x96\xdc\xd5\x18\x56\x7e\xd2\x5e\x96\xde\x94\xd8\xd8\x58\xd3\x79\x93\xfb\x90\xdc\xd6\x5b\xdd\x58\x96\xff"
#define AMR_WB_payload "\xf0\x1c\xf3\x06\x08\x10\x77\x32\x23\x20\xd3\x50\x62\x12\xc7\x7c\xe2\xea\x84\x0e\x6e\xf4\x4d\xe4\x7f\xc9\x4c\xcc\x58\x5d\xed\xcc\x5d\x7c\x6c\x14\x7d\xc0" // octet aligned
#define AMR_WB_payload_noe "\xf1\xfc\xc1\x82\x04\x1d\xcc\x88\xc8\x34\xd4\x18\x84\xb1\xdf\x38\xba\xa1\x03\x9b\xbd\x13\x79\x1f\xf2\x53\x33\x16\x17\x7b\x73\x17\x5f\x1b\x05\x1f\x70" // bandwidth efficient

int main(void) {
	rtpe_common_config_ptr = &rtpe_config.common;
	bufferpool_init();
	media_bufferpool = bufferpool_new(g_malloc, g_free, 4096);
	shm_bufferpool = bufferpool_new(g_malloc, g_free, 4096);

	unsigned long random_seed = 0;

	codeclib_init(0);
	RAND_seed(&random_seed, sizeof(random_seed));
	statistics_init();
	codecs_init();

	// plain
	start();
	sdp_pt(0, PCMU, 8000);
	offer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000");
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet(B, 0, PCMU_payload, 0, PCMU_payload);
	end();

	// plain with two offered and two answered
	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "0/PCMU/8000 8/PCMA/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
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
	expect(A, "0/PCMU/8000 8/PCMA/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "8/PCMA/8000");
	expect(B, "8/PCMA/8000");
	packet(A, 8, PCMA_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 8, PCMA_payload);
	end();

	// plain with two offered and two answered + always-transcode one way
	start();
	c_accept(all);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
	end();

	// plain with two offered and two answered + always-transcode both ways
	start();
	c_accept(all);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	c_accept(all);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
	end();

	// add one codec to transcode
	start();
	sdp_pt(0, PCMU, 8000);
	transcode(PCMA);
	offer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	packet(A, 0, PCMU_payload, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 0, PCMU_payload);
	end();

	// add one codec to transcode, don't accept original offered codec
	start();
	sdp_pt(0, PCMU, 8000);
	transcode(PCMA);
	offer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "8/PCMA/8000");
	packet(A, 0, PCMU_payload, 8, PCMA_payload);
	packet(B, 8, PCMA_payload, 0, PCMU_payload);
	end();

#ifdef WITH_AMR_TESTS
	{
		str codec_name = STR_CONST("AMR-WB");
		codec_def_t *def = codec_find(&codec_name, MT_AUDIO);
		assert(def);
		if (def->support_encoding && def->support_decoding) {
			// forward AMR-WB
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR-WB);
			offer();
			expect(A, "0/PCMU/8000");
			expect(B, "0/PCMU/8000 96/AMR-WB/16000/octet-align=1;mode-change-capability=2");
			sdp_pt_fmt(96, AMR-WB, 16000, "octet-align=1");
			answer();
			expect(A, "0/PCMU/8000");
			expect(B, "96/AMR-WB/16000/octet-align=1");
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
			expect(A, "96/AMR-WB/16000/octet-align=1");
			expect(B, "96/AMR-WB/16000/octet-align=1 0/PCMU/8000");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, "96/AMR-WB/16000/octet-align=1");
			expect(B, "0/PCMU/8000");
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
			expect(A, "96/AMR-WB/16000");
			expect(B, "96/AMR-WB/16000 0/PCMU/8000");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, "96/AMR-WB/16000");
			expect(B, "0/PCMU/8000");
			packet_seq(B, 0, PCMU_payload, 0, 0, -1, ""); // nothing due to resampling buffer
			packet_seq_nf(B, 0, PCMU_payload, 160, 1, 96, AMR_WB_payload_noe);
			packet_seq(A, 96, AMR_WB_payload_noe, 0, 0, -1, ""); // nothing due to resampling/decoding buffer
			packet_seq_nf(A, 96, AMR_WB_payload_noe, 320, 1, 0, PCMU_payload);
			end();
		}
	}

	{
		str codec_name = STR_CONST("AMR");
		codec_def_t *def = codec_find(&codec_name, MT_AUDIO);
		assert(def);
		if (def->support_encoding && def->support_decoding) {
			// default bitrate
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR);
			offer();
			expect(A, "0/PCMU/8000");
			expect(B, "0/PCMU/8000 96/AMR/8000/octet-align=1;mode-change-capability=2");
			sdp_pt_fmt(96, AMR, 8000, "octet-align=1");
			answer();
			expect(A, "0/PCMU/8000");
			expect(B, "96/AMR/8000/octet-align=1");
			check_encoder(A, B, 0, 96, 0); // uses codec default
			check_encoder(B, A, 96, 0, 0);
			end();

			// default bitrate reverse
			start();
			sdp_pt(96, AMR, 8000);
			transcode(PCMU);
			offer();
			expect(A, "96/AMR/8000");
			expect(B, "96/AMR/8000 0/PCMU/8000");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, "96/AMR/8000");
			expect(B, "0/PCMU/8000");
			check_encoder(A, B, 96, 0, 0);
			check_encoder(B, A, 0, 96, 0); // uses codec default
			end();

			// specify forward bitrate
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR/8000/1/6700);
			offer();
			expect(A, "0/PCMU/8000");
			expect(B, "0/PCMU/8000 96/AMR/8000/octet-align=1;mode-change-capability=2");
			sdp_pt_fmt(96, AMR, 8000, "octet-align=1");
			answer();
			expect(A, "0/PCMU/8000");
			expect(B, "96/AMR/8000/octet-align=1");
			check_encoder(A, B, 0, 96, 6700);
			check_encoder(B, A, 96, 0, 0);
			end();

			// specify non-default forward bitrate
			start();
			sdp_pt(0, PCMU, 8000);
			transcode(AMR/8000/1/7400);
			offer();
			expect(A, "0/PCMU/8000");
			expect(B, "0/PCMU/8000 96/AMR/8000/octet-align=1;mode-change-capability=2");
			sdp_pt_fmt(96, AMR, 8000, "octet-align=1");
			answer();
			expect(A, "0/PCMU/8000");
			expect(B, "96/AMR/8000/octet-align=1");
			check_encoder(A, B, 0, 96, 7400);
			check_encoder(B, A, 96, 0, 0);
			end();

			// specify reverse bitrate
			start();
			sdp_pt(96, AMR, 8000);
			transcode(PCMU);
			codec_set("AMR/8000/1/6700");
			offer();
			expect(A, "96/AMR/8000");
			expect(B, "96/AMR/8000 0/PCMU/8000");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, "96/AMR/8000");
			expect(B, "0/PCMU/8000");
			check_encoder(A, B, 96, 0, 0);
			check_encoder(B, A, 0, 96, 6700);
			end();

			// specify non-default reverse bitrate
			start();
			sdp_pt(96, AMR, 8000);
			transcode(PCMU);
			codec_set("AMR/8000/1/7400");
			offer();
			expect(A, "96/AMR/8000");
			expect(B, "96/AMR/8000 0/PCMU/8000");
			sdp_pt(0, PCMU, 8000);
			answer();
			expect(A, "96/AMR/8000");
			expect(B, "0/PCMU/8000");
			check_encoder(A, B, 96, 0, 0);
			check_encoder(B, A, 0, 96, 7400);
			end();
		}
	}
#endif

	// G.722 <> PCMA
	start();
	sdp_pt(8, PCMA, 8000);
	transcode(G722);
	offer();
	expect(A, "8/PCMA/8000");
	expect(B, "8/PCMA/8000 9/G722/8000");
	sdp_pt(9, G722, 8000);
	answer();
	expect(A, "8/PCMA/8000");
	expect(B, "9/G722/8000");
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
	expect(A, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "9/G722/8000 8/PCMA/8000");
	expect(B, "9/G722/8000 8/PCMA/8000");
	end();

	// A includes unsupported codec by B - transcoded codec accepted (GH#562 control case)
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	transcode(PCMU); // standin for G729
	offer();
	expect(A, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, "97/opus/48000 9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, "9/G722/8000 8/PCMA/8000 97/opus/48000");
	expect(B, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	end();

	// A includes unsupported codec by B - transcoded codec rejected (GH#562)
	start();
	sdp_pt(97, opus, 48000);
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	transcode(PCMU); // standin for G729
	offer();
	expect(A, "97/opus/48000 9/G722/8000 8/PCMA/8000");
	expect(B, "97/opus/48000 9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "9/G722/8000 8/PCMA/8000");
	expect(B, "9/G722/8000 8/PCMA/8000");
	end();

	_log_facility_dtmf = 1; // dummy enabler

	// plain DTMF passthrough w/o transcoding
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	offer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
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
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 0/PCMU/8000 101/telephone-event/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "0/PCMU/8000 101/telephone-event/8000");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
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
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
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
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 8, PCMA_payload, 1000960, 206, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 1001120, 207, 8, PCMA_payload);
	// enable blocking
	call.block_dtmf = BLOCK_DTMF_DROP;
	// start with marker
	packet_seq_exp(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, -1, "", 0);
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, -1, "");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, -1, "");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	dtmf("");
	// final audio RTP test
	packet_seq_exp(A, 8, PCMA_payload, 1000960, 212, 8, PCMA_payload, 5); // DTMF packets appear lost
	packet_seq(A, 8, PCMA_payload, 1001120, 213, 8, PCMA_payload);
	// media blocking
	ML_SET(ml_A, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1001280, 214, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001440, 215, -1, "", 0);
	ML_CLEAR(ml_A, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1001600, 216, 8, PCMA_payload, 3); // media packets appear lost
	CALL_SET(&call, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1001760, 217, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001920, 218, -1, "", 0);
	CALL_CLEAR(&call, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1002080, 219, 8, PCMA_payload, 3); // media packets appear lost
	ML_SET(ml_B, BLOCK_MEDIA);
	packet_seq(A, 8, PCMA_payload, 1002240, 220, 8, PCMA_payload);
	end();

	// DTMF passthrough w/ transcoding - blocking
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	transcode(PCMU);
	offer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 0/PCMU/8000 101/telephone-event/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "0/PCMU/8000 101/telephone-event/8000");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 8, PCMA_payload, 1000960, 206, 0, PCMU_payload);
	packet_seq(A, 8, PCMA_payload, 1001120, 207, 0, PCMU_payload);
	// enable blocking
	call.block_dtmf = BLOCK_DTMF_DROP;
	// start with marker
	packet_seq_exp(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, -1, "", 0);
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, -1, "");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, -1, "");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	dtmf("");
	// final audio RTP test
	packet_seq_exp(A, 8, PCMA_payload, 1000960, 212, 0, PCMU_payload, 5); // DTMF packets appear lost
	packet_seq(A, 8, PCMA_payload, 1001120, 213, 0, PCMU_payload);
	// media blocking
	ML_SET(ml_A, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1001280, 214, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001440, 215, -1, "", 0);
	ML_CLEAR(ml_A, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1001600, 214, 0, PCMU_payload, 1); // cheat with the seq here - 216 would get held by the jitter buffer
	CALL_SET(&call, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1001760, 215, -1, "", 0);
	packet_seq_exp(A, 8, PCMA_payload, 1001920, 216, -1, "", 0);
	CALL_CLEAR(&call, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1002080, 215, 0, PCMU_payload, 1);
	ML_SET(ml_B, BLOCK_MEDIA);
	packet_seq_exp(A, 8, PCMA_payload, 1002240, 216, 0, PCMU_payload, 1);
	end();

	// plain DTMF passthrough w/o transcoding w/ implicit primary payload type - blocking
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	offer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
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
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":8,\"duration\":100,\"volume\":10}");
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	packet_seq_exp(A, 101, "\x08\x8a\x03\x20", 1000160, 205, 101, "\x08\x8a\x03\x20", 0);
	dtmf("");
	// send some more audio
	packet_seq(A, 0, PCMU_payload, 1000960, 206, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 1001120, 207, 0, PCMU_payload);
	// enable blocking
	call.block_dtmf = BLOCK_DTMF_DROP;
	// start with marker
	packet_seq_exp(A, 101 | 0x80, "\x05\x0a\x00\xa0", 1001280, 208, -1, "", 0);
	dtmf("");
	// continuous event with increasing length
	packet_seq(A, 101, "\x05\x0a\x01\x40", 1001280, 209, -1, "");
	packet_seq(A, 101, "\x05\x0a\x01\xe0", 1001280, 210, -1, "");
	dtmf("");
	// end
	packet_seq(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "");
	dtmf("{\"callid\":\"test-call\",\"source_tag\":\"tag_A\",\"source_label\":\"label_A\",\"tags\":[],\"type\":\"DTMF\",\"timestamp\":0,\"source_ip\":\"\",\"event\":5,\"duration\":80,\"volume\":10}");
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	packet_seq_exp(A, 101, "\x05\x8a\x02\x80", 1001280, 211, -1, "", 0);
	dtmf("");
	// final audio RTP test
	packet_seq_exp(A, 0, PCMU_payload, 1000960, 212, 0, PCMU_payload, 5); // DTMF packets appear lost
	packet_seq(A, 0, PCMU_payload, 1001120, 213, 0, PCMU_payload);
	// media blocking
	ML_SET(ml_A, BLOCK_MEDIA);
	packet_seq_exp(A, 0, PCMU_payload, 1001280, 214, -1, "", 0);
	packet_seq_exp(A, 0, PCMU_payload, 1001440, 215, -1, "", 0);
	ML_CLEAR(ml_A, BLOCK_MEDIA);
	packet_seq_exp(A, 0, PCMU_payload, 1001600, 216, 0, PCMU_payload, 3); // media packets appear lost
	CALL_SET(&call, BLOCK_MEDIA);
	packet_seq_exp(A, 0, PCMU_payload, 1001760, 217, -1, "", 0);
	packet_seq_exp(A, 0, PCMU_payload, 1001920, 218, -1, "", 0);
	CALL_CLEAR(&call, BLOCK_MEDIA);
	packet_seq_exp(A, 0, PCMU_payload, 1002080, 219, 0, PCMU_payload, 3); // media packets appear lost
	ML_SET(ml_B, BLOCK_MEDIA);
	packet_seq(A, 0, PCMU_payload, 1002240, 220, 0, PCMU_payload);
	end();

	// codec-mask/accept/consume tests
	// control - plain in/out
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-mask only
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_mask(PCMU);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "104/SILK/16000 9/G722/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-mask + transcode + reject transcoded codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_mask(PCMU);
	transcode(GSM);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 8/PCMA/8000 3/GSM/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-mask + transcode + accept transcoded codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_mask(PCMU);
	transcode(GSM);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 8/PCMA/8000 3/GSM/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(3, GSM, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "8/PCMA/8000 9/G722/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 3/GSM/8000 101/telephone-event/8000");
	// G.722 > PCMA
	packet_seq(A, 9, G722_payload, 0, 0, -1, ""); // nothing due to resampling
	packet_seq_nf(A, 9, G722_payload, 160, 1, 8, PCMA_payload);
	packet_seq_ts(A, 9, G722_payload, 320, 2, 8, PCMA_payload, 160, 0);
	// asymmetric codec
	packet(B, 8, PCMA_payload, 8, PCMA_payload); // nothing due to resampling
	end();
	// codec-consume only
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_consume(PCMU);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "0/PCMU/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-consume + transcode + reject transcoded codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_consume(PCMU);
	transcode(GSM);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 8/PCMA/8000 3/GSM/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "0/PCMU/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-consume + transcode + accept transcoded codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_consume(PCMU);
	transcode(GSM);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 8/PCMA/8000 3/GSM/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(3, GSM, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "0/PCMU/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 3/GSM/8000 101/telephone-event/8000");
	end();
	// codec-accept only
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_accept(PCMU);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "0/PCMU/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-accept + transcode + reject transcoded codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_accept(PCMU);
	transcode(GSM);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 0/PCMU/8000 8/PCMA/8000 3/GSM/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "0/PCMU/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// codec-accept + transcode + accept transcoded codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_accept(PCMU);
	transcode(GSM);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 0/PCMU/8000 8/PCMA/8000 3/GSM/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(3, GSM, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "0/PCMU/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 3/GSM/8000 101/telephone-event/8000");
	end();
	// codec-accept first codec
	start();
	sdp_pt(104, SILK, 16000);
	sdp_pt(9, G722, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	sdp_pt(13, CN, 8000);
	sdp_pt(118, CN, 16000);
	c_accept(G722);
	offer();
	expect(A, "104/SILK/16000 9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000 118/CN/16000");
	expect(B, "9/G722/8000 0/PCMU/8000 8/PCMA/8000 101/telephone-event/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "9/G722/8000 101/telephone-event/8000");
	expect(B, "8/PCMA/8000 101/telephone-event/8000");
	end();
	// gh 664 codec masking a/t
	start();
	sdp_pt(120, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	c_mask(opus);
	c_mask(G722);
	c_mask(G7221);
	c_accept(all);
	offer();
	expect(B, "8/PCMA/8000 0/PCMU/8000 101/telephone-event/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "120/opus/48000");
	end();
	// gh 664 codec masking accept=all
	start();
	sdp_pt(120, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	c_mask(opus);
	c_mask(G722);
	c_mask(G7221);
	c_accept(all);
	offer();
	expect(B, "8/PCMA/8000 0/PCMU/8000 101/telephone-event/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	answer();
	expect(A, "120/opus/48000");
	end();

	// CN transcoding
	rtpe_config.silence_detect_int = 10 << 16;
	rtpe_config.cn_payload = STR_LEN("\x40", 1);
	// CN transcoding - forward
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	transcode(CN);
	offer();
	expect(B, "8/PCMA/8000 0/PCMU/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(13, CN, 8000);
	answer();
	expect(A, "8/PCMA/8000 0/PCMU/8000");
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 13, "\x20", 320, 2, 8, "\xf5\x5c\x4b\xc2\xde\xf4\x5e\xd4\x47\x70\x5d\x77\x45\x51\xc5\xcd\xd7\x77\x5a\xf5\xcf\x4a\x4c\x40\xc3\x47\x74\x49\x59\xc4\x76\x57\x71\x57\x40\xc5\xf4\x5a\x47\xd6\xc4\xf6\xc7\xf3\x40\x58\x74\x54\x4b\xd7\x5c\xc7\x41\x49\xf5\x5b\x53\xd9\x70\x44\xcd\xc4\xce\xcb\xc7\x58\xcd\x45\xc6\x71\xf5\x70\x43\xca\x43\xd5\x52\x5c\x75\x74\xc6\xc3\x4f\xda\x56\xc3\x46\xf5\x49\xdf\x56\x4f\x71\x5b\x52\xc6\x4e\xd0\x43\xc2\xcd\xd5\xdf\x40\x43\x4a\xf7\xf6\xd9\xdf\xde\x45\xc9\xd9\xc2\xf0\xc1\x4a\x40\x52\xd1\x5b\xd0\x54\xc9\x5e\xde\xd5\x74\x5c\x5d\x59\x71\xc1\xc1\x71\xd2\xcb\x50\x50\x54\x53\x75\xdc\x4b\xcf\xc2\xd7\x4a\xcc\x58\xc7\xdb\xd8\x48\x4a\xd6\x58\xf0\x46");
	packet_seq(A, 8, PCMA_silence, 320, 2, 13, "\x40");
	end();
	// CN transcoding - reverse 1
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(13, CN, 8000);
	c_consume(CN);
	offer();
	expect(B, "8/PCMA/8000 0/PCMU/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, "8/PCMA/8000 0/PCMU/8000 13/CN/8000");
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(A, 13, "\x20", 320, 2, 8, "\xf5\x5c\x4b\xc2\xde\xf4\x5e\xd4\x47\x70\x5d\x77\x45\x51\xc5\xcd\xd7\x77\x5a\xf5\xcf\x4a\x4c\x40\xc3\x47\x74\x49\x59\xc4\x76\x57\x71\x57\x40\xc5\xf4\x5a\x47\xd6\xc4\xf6\xc7\xf3\x40\x58\x74\x54\x4b\xd7\x5c\xc7\x41\x49\xf5\x5b\x53\xd9\x70\x44\xcd\xc4\xce\xcb\xc7\x58\xcd\x45\xc6\x71\xf5\x70\x43\xca\x43\xd5\x52\x5c\x75\x74\xc6\xc3\x4f\xda\x56\xc3\x46\xf5\x49\xdf\x56\x4f\x71\x5b\x52\xc6\x4e\xd0\x43\xc2\xcd\xd5\xdf\x40\x43\x4a\xf7\xf6\xd9\xdf\xde\x45\xc9\xd9\xc2\xf0\xc1\x4a\x40\x52\xd1\x5b\xd0\x54\xc9\x5e\xde\xd5\x74\x5c\x5d\x59\x71\xc1\xc1\x71\xd2\xcb\x50\x50\x54\x53\x75\xdc\x4b\xcf\xc2\xd7\x4a\xcc\x58\xc7\xdb\xd8\x48\x4a\xd6\x58\xf0\x46");
	packet_seq(B, 8, PCMA_silence, 320, 2, 13, "\x40");
	end();
	// CN transcoding - reverse 2
	start();
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(13, CN, 8000);
	c_accept(CN);
	offer();
	expect(B, "8/PCMA/8000 0/PCMU/8000 13/CN/8000");
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, "8/PCMA/8000 0/PCMU/8000 13/CN/8000");
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(A, 13, "\x20", 320, 2, 8, "\xf5\x5c\x4b\xc2\xde\xf4\x5e\xd4\x47\x70\x5d\x77\x45\x51\xc5\xcd\xd7\x77\x5a\xf5\xcf\x4a\x4c\x40\xc3\x47\x74\x49\x59\xc4\x76\x57\x71\x57\x40\xc5\xf4\x5a\x47\xd6\xc4\xf6\xc7\xf3\x40\x58\x74\x54\x4b\xd7\x5c\xc7\x41\x49\xf5\x5b\x53\xd9\x70\x44\xcd\xc4\xce\xcb\xc7\x58\xcd\x45\xc6\x71\xf5\x70\x43\xca\x43\xd5\x52\x5c\x75\x74\xc6\xc3\x4f\xda\x56\xc3\x46\xf5\x49\xdf\x56\x4f\x71\x5b\x52\xc6\x4e\xd0\x43\xc2\xcd\xd5\xdf\x40\x43\x4a\xf7\xf6\xd9\xdf\xde\x45\xc9\xd9\xc2\xf0\xc1\x4a\x40\x52\xd1\x5b\xd0\x54\xc9\x5e\xde\xd5\x74\x5c\x5d\x59\x71\xc1\xc1\x71\xd2\xcb\x50\x50\x54\x53\x75\xdc\x4b\xcf\xc2\xd7\x4a\xcc\x58\xc7\xdb\xd8\x48\x4a\xd6\x58\xf0\x46");
	packet_seq(B, 8, PCMA_silence, 320, 2, 13, "\x40");
	end();
	// DTMF PT TC
	start();
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(101, telephone-event, 8000);
	c_mask(all);
	transcode(opus/48000/1);
	transcode(PCMA);
	transcode(telephone-event);
	offer();
	expect(B, "96/opus/48000/useinbandfec=1 8/PCMA/8000 97/telephone-event/48000/0-15 101/telephone-event/8000");
	sdp_pt(96, opus, 48000);
	sdp_pt(97, telephone-event, 48000);
	flags.single_codec = 1;
	answer();
	expect(A, "9/G722/8000 101/telephone-event/8000");
	packet_seq(A, 101, "\x05\x07\x01\x40", 4000, 10, 97, "\x05\x07\x07\x80");
	packet_seq(B, 97, "\x05\x07\x07\x80", 4000, 10, 101, "\x05\x07\x01\x40");
	end();
	// DTMF PT TC w eq PT
	start();
	sdp_pt(96, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(102, telephone-event, 48000);
	sdp_pt(101, telephone-event, 8000);
	c_mask(all);
	transcode(opus);
	transcode(PCMA);
	transcode(PCMU);
	transcode(telephone-event);
	offer();
	expect(B, "96/opus/48000 8/PCMA/8000 0/PCMU/8000 101/telephone-event/8000 102/telephone-event/48000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(101, telephone-event, 8000);
	flags.single_codec = 1;
	answer();
	expect(A, "96/opus/48000 102/telephone-event/48000");
	packet_seq(A, 102, "\x05\x07\x01\x40", 4000, 10, 101, "\x05\x07\x00\x35");
	packet_seq(B, 101, "\x05\x07\x07\x80", 4000, 10, 102, "\x05\x07\x2d\x00");
	end();

	//reusing_codecs test
	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, PCMA, 8000);
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/PCMA/8000");
	sdp_pt(7, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, PCMA, 8000);
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/PCMA/8000");
	sdp_pt(7, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(B, "0/PCMU/8000 8/PCMA/8000");
	end();

	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, G722, 8000);
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, G722, 8000);
	answer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	offer();
	expect(A, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	expect(B, "9/G722/8000 8/PCMA/8000 0/PCMU/8000");
	end();

	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, G722, 8000);
	flags.reuse_codec = 1;
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, G722, 8000);
	flags.reuse_codec = 1;
	answer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	flags.reuse_codec = 1;
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	flags.reuse_codec = 1;
	answer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	end();

	start();
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, G722, 8000);
	flags.reuse_codec = 1;
	flags.single_codec = 1;
	offer();
	expect(A, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(0, PCMU, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(9, G722, 8000);
	flags.reuse_codec = 1;
	flags.single_codec = 1;
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	flags.reuse_codec = 1;
	flags.single_codec = 1;
	offer();
	expect(A, "0/PCMU/8000 9/G722/8000 8/PCMA/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	sdp_pt(9, G722, 8000);
	sdp_pt(8, PCMA, 8000);
	sdp_pt(0, PCMU, 8000);
	flags.reuse_codec = 1;
	flags.single_codec = 1;
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000 8/PCMA/8000 9/G722/8000");
	end();

	// media silencing PCMA
	start();
	sdp_pt(8, PCMA, 8000);
	offer();
	expect(A, "8/PCMA/8000");
	expect(B, "8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "8/PCMA/8000");
	expect(B, "8/PCMA/8000");
	packet_seq(A, 8, PCMA_payload, 0, 0, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 0, 0, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 160, 1, 8, PCMA_payload);
	CALL_SET(&call, SILENCE_MEDIA);
	packet_seq(A, 8, PCMA_payload, 320, 2, 8, PCMA_silence);
	packet_seq(B, 8, PCMA_payload, 320, 2, 8, PCMA_silence);
	packet_seq(A, 8, PCMA_payload, 480, 3, 8, PCMA_silence);
	packet_seq(B, 8, PCMA_payload, 480, 3, 8, PCMA_silence);
	CALL_CLEAR(&call, SILENCE_MEDIA);
	packet_seq(A, 8, PCMA_payload, 640, 4, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 640, 4, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 800, 5, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 800, 5, 8, PCMA_payload);
	ML_SET(ml_A, SILENCE_MEDIA);
	packet_seq(A, 8, PCMA_payload, 960, 6, 8, PCMA_silence);
	packet_seq(B, 8, PCMA_payload, 960, 6, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 1120, 7, 8, PCMA_silence);
	packet_seq(B, 8, PCMA_payload, 1120, 7, 8, PCMA_payload);
	ML_CLEAR(ml_A, SILENCE_MEDIA);
	packet_seq(A, 8, PCMA_payload, 1280, 8, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 1280, 8, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 1440, 9, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 1440, 9, 8, PCMA_payload);
	ML_SET(ml_B, SILENCE_MEDIA);
	packet_seq(A, 8, PCMA_payload, 1600, 10, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 1600, 10, 8, PCMA_silence);
	packet_seq(A, 8, PCMA_payload, 1760, 11, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 1760, 11, 8, PCMA_silence);
	ML_CLEAR(ml_B, SILENCE_MEDIA);
	packet_seq(A, 8, PCMA_payload, 1920, 12, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 1920, 12, 8, PCMA_payload);
	packet_seq(A, 8, PCMA_payload, 2080, 13, 8, PCMA_payload);
	packet_seq(B, 8, PCMA_payload, 2080, 13, 8, PCMA_payload);
	end();

	// media silencing PCMU
	start();
	sdp_pt(0, PCMU, 8000);
	offer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000");
	sdp_pt(0, PCMU, 8000);
	answer();
	expect(A, "0/PCMU/8000");
	expect(B, "0/PCMU/8000");
	packet_seq(A, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 0, 0, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 160, 1, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 160, 1, 0, PCMU_payload);
	CALL_SET(&call, SILENCE_MEDIA);
	packet_seq(A, 0, PCMU_payload, 320, 2, 0, PCMU_silence);
	packet_seq(B, 0, PCMU_payload, 320, 2, 0, PCMU_silence);
	packet_seq(A, 0, PCMU_payload, 480, 3, 0, PCMU_silence);
	packet_seq(B, 0, PCMU_payload, 480, 3, 0, PCMU_silence);
	CALL_CLEAR(&call, SILENCE_MEDIA);
	packet_seq(A, 0, PCMU_payload, 640, 4, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 640, 4, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 800, 5, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 800, 5, 0, PCMU_payload);
	ML_SET(ml_A, SILENCE_MEDIA);
	packet_seq(A, 0, PCMU_payload, 960, 6, 0, PCMU_silence);
	packet_seq(B, 0, PCMU_payload, 960, 6, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 1120, 7, 0, PCMU_silence);
	packet_seq(B, 0, PCMU_payload, 1120, 7, 0, PCMU_payload);
	ML_CLEAR(ml_A, SILENCE_MEDIA);
	packet_seq(A, 0, PCMU_payload, 1280, 8, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 1280, 8, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 1440, 9, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 1440, 9, 0, PCMU_payload);
	ML_SET(ml_B, SILENCE_MEDIA);
	packet_seq(A, 0, PCMU_payload, 1600, 10, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 1600, 10, 0, PCMU_silence);
	packet_seq(A, 0, PCMU_payload, 1760, 11, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 1760, 11, 0, PCMU_silence);
	ML_CLEAR(ml_B, SILENCE_MEDIA);
	packet_seq(A, 0, PCMU_payload, 1920, 12, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 1920, 12, 0, PCMU_payload);
	packet_seq(A, 0, PCMU_payload, 2080, 13, 0, PCMU_payload);
	packet_seq(B, 0, PCMU_payload, 2080, 13, 0, PCMU_payload);
	end();

	start();
	sdp_pt_s(96, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	c_accept(opus/48000/2);
	offer();
	expect(A, "96/opus/48000/2 8/PCMA/8000");
	expect(B, "96/opus/48000/2 8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "96/opus/48000/2");
	expect(B, "8/PCMA/8000");
	end();

	start();
	sdp_pt(96, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	c_accept(opus/48000);
	offer();
	expect(A, "96/opus/48000 8/PCMA/8000");
	expect(B, "96/opus/48000 8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "96/opus/48000");
	expect(B, "8/PCMA/8000");
	end();

	start();
	sdp_pt(96, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	c_accept(opus);
	offer();
	expect(A, "96/opus/48000 8/PCMA/8000");
	expect(B, "96/opus/48000 8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "96/opus/48000");
	expect(B, "8/PCMA/8000");
	end();

	start();
	sdp_pt_s(96, opus, 48000);
	sdp_pt(8, PCMA, 8000);
	c_accept(opus);
	offer();
	expect(A, "96/opus/48000/2 8/PCMA/8000");
	expect(B, "96/opus/48000/2 8/PCMA/8000");
	sdp_pt(8, PCMA, 8000);
	answer();
	expect(A, "96/opus/48000/2");
	expect(B, "8/PCMA/8000");
	end();

	statistics_free();
	bufferpool_destroy(media_bufferpool);
	bufferpool_destroy(shm_bufferpool);
	bufferpool_cleanup();

	return 0;
}

int get_local_log_level(unsigned int u) {
	return 7;
}
