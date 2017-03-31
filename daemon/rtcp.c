#include "rtcp.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <glib.h>

#include "compat.h"
#include "str.h"
#include "call.h"
#include "log.h"
#include "rtp.h"
#include "crypto.h"
#include "rtcp_xr.h"
#include "homer.h"
#include "media_socket.h"
#include "rtcplib.h"
#include "ssrc.h"



/* This toggles between two different and incompatible interpretations of
 * RFC 3711, namely sections 4.3.2 and 4.3.1.
 * See http://www.ietf.org/mail-archive/web/avt/current/msg06124.html
 * The default (define not set) is to be compatible with libsrtp, but
 * incompatible with a strict interpretation of the RFC.
 *
 * In Errata ID: 3712 the libsrtp behaviour (labels in the same place)
 * is now considered canonical.
 *
 * https://www.rfc-editor.org/errata_search.php?rfc=3711
 * https://github.com/cisco/libsrtp/issues/150
 */
#ifdef SRTCP_KEY_DERIVATION_RFC_COMPLIANCE
#define SRTCP_R_LENGTH 4
#else
#define SRTCP_R_LENGTH 6
#endif

#define RTCP_PT_SR	200	/* sender report */
#define RTCP_PT_RR	201	/* receiver report */
#define RTCP_PT_SDES	202	/* source description */
#define RTCP_PT_BYE	203	/* bye */
#define RTCP_PT_APP	204	/* application specific */
#define RTCP_PT_RTPFB	205	/* transport layer feedback message (RTP/AVPF) */
#define RTCP_PT_PSFB	206	/* payload-specific feedback message (RTP/AVPF) */
#define RTCP_PT_XR   207

#define SDES_TYPE_END	0
#define SDES_TYPE_CNAME	1
#define SDES_TYPE_NAME	2
#define SDES_TYPE_EMAIL	3
#define SDES_TYPE_PHONE	4
#define SDES_TYPE_LOC	5
#define SDES_TYPE_TOOL	6
#define SDES_TYPE_NOTE	7
#define SDES_TYPE_PRIV	8



struct report_block {
	u_int32_t ssrc;
	unsigned char fraction_lost;
	unsigned char number_lost[3];
	u_int32_t high_seq_received;
	u_int32_t jitter;
	u_int32_t lsr;
	u_int32_t dlsr;
} __attribute__ ((packed));

struct sender_report_packet {
	struct rtcp_packet rtcp;
	u_int32_t ntp_msw;
	u_int32_t ntp_lsw;
	u_int32_t timestamp;
	u_int32_t packet_count;
	u_int32_t octet_count;
	struct report_block reports[0];
} __attribute__ ((packed));

struct receiver_report_packet {
	struct rtcp_packet rtcp;
	struct report_block reports[0];
} __attribute__ ((packed));

struct sdes_item {
	unsigned char type;
	unsigned char length;
	unsigned char data[0];
} __attribute__ ((packed));

struct sdes_chunk {
	u_int32_t ssrc;
	struct sdes_item items[0];
} __attribute__ ((packed));

struct source_description_packet {
	struct rtcp_header header;
	struct sdes_chunk chunks[0];
} __attribute__ ((packed));

struct bye_packet {
	struct rtcp_header header;
	u_int32_t ssrcs[0];
} __attribute__ ((packed));

struct app_packet {
	struct rtcp_packet rtcp;
	unsigned char name[4];
	unsigned char data[0];
} __attribute__ ((packed));

struct fb_packet {
	struct rtcp_packet rtcp;
	u_int32_t media_ssrc;
	unsigned char information[0];
} __attribute__ ((packed));

struct rtcp_chain_element {
	int type;
	unsigned int len;
	union {
		void *buf;
		struct rtcp_packet *rtcp_packet;
		struct sender_report_packet *sr;
		struct receiver_report_packet *rr;
		struct source_description_packet *sdes;
		struct bye_packet *bye;
		struct app_packet *app;
	} u;
};

// log handlers
// struct defs
// context to hold state variables
struct rtcp_process_ctx {
	// input
	struct call *call;
	const struct timeval *received;

	// handler vars
	union {
		struct ssrc_receiver_report rr;
		struct ssrc_sender_report sr;
	} scratch;
	u_int32_t scratch_common_ssrc;

	GString *log;
	GString *json;
};
// all available methods
struct rtcp_handler {
	void (*init)(struct rtcp_process_ctx *);
	void (*start)(struct rtcp_process_ctx *, struct call *);
	void (*common)(struct rtcp_process_ctx *, const struct rtcp_packet *);
	void (*sr)(struct rtcp_process_ctx *, const struct sender_report_packet *);
	void (*rr_list_start)(struct rtcp_process_ctx *, const struct rtcp_packet *);
	void (*rr)(struct rtcp_process_ctx *, const struct report_block *);
	void (*rr_list_end)(struct rtcp_process_ctx *);
	void (*xr)(struct rtcp_process_ctx *, const struct rtcp_packet *, str *);
	void (*sdes_list_start)(struct rtcp_process_ctx *, const struct source_description_packet *);
	void (*sdes_item)(struct rtcp_process_ctx *, const struct sdes_chunk *, const struct sdes_item *,
			const char *);
	void (*sdes_list_end)(struct rtcp_process_ctx *);
	void (*finish)(struct rtcp_process_ctx *, struct call *, const endpoint_t *, const endpoint_t *,
			const struct timeval *);
	void (*destroy)(struct rtcp_process_ctx *);
};
// collection of all handler types
struct rtcp_handlers {
	const struct rtcp_handler
		*scratch,
		*mos,
		*logging,
		*homer;
};

// log handler function prototypes
static void dummy_handler();

// scratch area (prepare/parse packet)
static void scratch_common(struct rtcp_process_ctx *, const struct rtcp_packet *);
static void scratch_sr(struct rtcp_process_ctx *, const struct sender_report_packet *);
static void scratch_rr(struct rtcp_process_ctx *, const struct report_block *);

// MOS calculation / stats
static void mos_sr(struct rtcp_process_ctx *, const struct sender_report_packet *);
static void mos_rr(struct rtcp_process_ctx *, const struct report_block *);

// homer functions
static void homer_init(struct rtcp_process_ctx *);
static void homer_sr(struct rtcp_process_ctx *, const struct sender_report_packet *);
static void homer_rr_list_start(struct rtcp_process_ctx *, const struct rtcp_packet *);
static void homer_rr(struct rtcp_process_ctx *, const struct report_block *);
static void homer_rr_list_end(struct rtcp_process_ctx *);
static void homer_sdes_list_start(struct rtcp_process_ctx *, const struct source_description_packet *);
static void homer_sdes_item(struct rtcp_process_ctx *, const struct sdes_chunk *, const struct sdes_item *,
		const char *);
static void homer_sdes_list_end(struct rtcp_process_ctx *);
static void homer_finish(struct rtcp_process_ctx *, struct call *, const endpoint_t *, const endpoint_t *,
		const struct timeval *);

// syslog functions
static void logging_init(struct rtcp_process_ctx *);
static void logging_start(struct rtcp_process_ctx *, struct call *);
static void logging_common(struct rtcp_process_ctx *, const struct rtcp_packet *);
static void logging_sdes_list_start(struct rtcp_process_ctx *, const struct source_description_packet *);
static void logging_sr(struct rtcp_process_ctx *, const struct sender_report_packet *);
static void logging_rr(struct rtcp_process_ctx *, const struct report_block *);
static void logging_xr(struct rtcp_process_ctx *, const struct rtcp_packet *, str *);
static void logging_finish(struct rtcp_process_ctx *, struct call *, const endpoint_t *, const endpoint_t *,
		const struct timeval *);
static void logging_destroy(struct rtcp_process_ctx *);

// structs for each handler type
static struct rtcp_handler dummy_handlers;
static struct rtcp_handler scratch_handlers = {
	.common = scratch_common,
	.rr = scratch_rr,
	.sr = scratch_sr,
};
static struct rtcp_handler mos_handlers = {
	.rr = mos_rr,
	.sr = mos_sr,
};
static struct rtcp_handler log_handlers = {
	.init = logging_init,
	.start = logging_start,
	.common = logging_common,
	.sdes_list_start = logging_sdes_list_start,
	.sr = logging_sr,
	.rr = logging_rr,
	.xr = logging_xr,
	.finish = logging_finish,
	.destroy = logging_destroy,
};
static struct rtcp_handler homer_handlers = {
	.init = homer_init,
	.sr = homer_sr,
	.rr_list_start = homer_rr_list_start,
	.rr = homer_rr,
	.rr_list_end = homer_rr_list_end,
	.sdes_list_start = homer_sdes_list_start,
	.sdes_item = homer_sdes_item,
	.sdes_list_end = homer_sdes_list_end,
	.finish = homer_finish,
};

// main var to hold references
static struct rtcp_handlers rtcp_handlers = {
	.scratch = &scratch_handlers,
	.mos = &mos_handlers,
	// remainder is variable
};

// list of all handlers
static struct rtcp_handler *all_handlers[] = {
	&dummy_handlers,
	&scratch_handlers,
	&mos_handlers,
	&log_handlers,
	&homer_handlers,
};

// macro to call all function handlers in one go
#define CAH(func, ...) do { \
		rtcp_handlers.scratch->func(log_ctx, ##__VA_ARGS__); \
		rtcp_handlers.mos->func(log_ctx, ##__VA_ARGS__); \
		rtcp_handlers.logging->func(log_ctx, ##__VA_ARGS__); \
		rtcp_handlers.homer->func(log_ctx, ##__VA_ARGS__); \
	} while (0)





typedef int (*rtcp_handler_func)(struct rtcp_chain_element *, struct rtcp_process_ctx *);

static int rtcp_sr(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_rr(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_sdes(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_xr(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_generic(struct rtcp_chain_element *, struct rtcp_process_ctx *);





static const rtcp_handler_func handler_funcs[] = {
	[RTCP_PT_SR]	= rtcp_sr,
	[RTCP_PT_RR]	= rtcp_rr,
	[RTCP_PT_SDES]	= rtcp_sdes,
	[RTCP_PT_BYE]	= rtcp_generic,
	[RTCP_PT_APP]	= rtcp_generic,
	[RTCP_PT_RTPFB]	= rtcp_generic,
	[RTCP_PT_PSFB]	= rtcp_generic,
	[RTCP_PT_XR]	= rtcp_xr,
};
static const int min_packet_sizes[] = {
	[RTCP_PT_SR]	= sizeof(struct sender_report_packet),
	[RTCP_PT_RR]	= sizeof(struct receiver_report_packet),
	[RTCP_PT_SDES]	= sizeof(struct source_description_packet),
	[RTCP_PT_BYE]	= sizeof(struct bye_packet),
	[RTCP_PT_APP]	= sizeof(struct app_packet),
	[RTCP_PT_RTPFB]	= sizeof(struct fb_packet),
	[RTCP_PT_PSFB]	= sizeof(struct fb_packet),
};






static struct rtcp_header *rtcp_length_check(str *s, size_t min_len, unsigned int *len_p) {
	struct rtcp_header *h;

	if (s->len < min_len)
		return NULL;

	h = (void *) s->s;
	*len_p = (ntohs(h->length) + 1) << 2;

	if (*len_p > s->len)
		return NULL;

	return h;
}

static struct rtcp_chain_element *rtcp_new_element(struct rtcp_header *p, unsigned int len) {
	struct rtcp_chain_element *el;

	el = g_slice_alloc(sizeof(*el));
	el->type = p->pt;
	el->len = len;
	el->u.buf = p;

	return el;
}

static int rtcp_generic(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	return 0;
}

static int rtcp_Xr(struct rtcp_chain_element *el) {
	if (el->len < el->u.rtcp_packet->header.count * sizeof(struct report_block))
		return -1;
	return 0;
}

static void rtcp_rr_list(const struct rtcp_packet *common, struct report_block *blocks,
		struct rtcp_process_ctx *log_ctx)
{
	CAH(rr_list_start, common);
	for (unsigned int i = 0; i < common->header.count; i++) {
		struct report_block *block = &blocks[i];
		CAH(rr, block);
	}
	CAH(rr_list_end);
}


static int rtcp_sr(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	if (rtcp_Xr(el))
		return -1;
	CAH(common, &el->u.sr->rtcp);
	CAH(sr, el->u.sr);
	rtcp_rr_list(&el->u.sr->rtcp, el->u.sr->reports, log_ctx);
	return 0;
}

static int rtcp_rr(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	if (rtcp_Xr(el))
		return -1;
	CAH(common, &el->u.rr->rtcp);
	rtcp_rr_list(&el->u.rr->rtcp, el->u.rr->reports, log_ctx);
	return 0;
}

static int rtcp_sdes(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	str comp_s;

	CAH(sdes_list_start, el->u.sdes);

	str_init_len(&comp_s, (void *) el->u.sdes->chunks, el->len - sizeof(el->u.sdes->header));
	int i = 0;
	while (1) {
		struct sdes_chunk *sdes_chunk = (struct sdes_chunk *) comp_s.s;
		if (str_shift(&comp_s, sizeof(*sdes_chunk)))
			break;
		while (comp_s.len) {
			struct sdes_item *sdes_item = (struct sdes_item *) comp_s.s;
			// check for zero type first
			if (str_shift(&comp_s, 1))
				break;
			if (!sdes_item->type)
				break;
			if (str_shift(&comp_s, sizeof(*sdes_item) - 1))
				break;
			if (comp_s.len < sdes_item->length)
				break;
			CAH(sdes_item, sdes_chunk, sdes_item, comp_s.s);
			str_shift(&comp_s, sdes_item->length);
		}

		// remove padding to next chunk
		while (comp_s.len % 4 != 0)
			str_shift(&comp_s, 1);

		// more chunks? set chunk header
		i++;
		if (i >= el->u.sdes->header.count)
			break;
	}

	CAH(sdes_list_end);

	return 0;
}

static int rtcp_xr(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	CAH(common, el->u.rtcp_packet);
	str comp_s;
	str_init_len(&comp_s, el->u.buf + sizeof(*el->u.rtcp_packet), el->len - sizeof(*el->u.rtcp_packet));
	CAH(xr, el->u.rtcp_packet, &comp_s);
	return 0;
}



static void rtcp_ce_free(void *p) {
	g_slice_free1(sizeof(struct rtcp_chain_element), p);
}
static void rtcp_list_free(GQueue *q) {
	g_queue_clear_full(q, rtcp_ce_free);
}



static int __rtcp_parse(GQueue *q, const str *_s, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv)
{
	struct rtcp_header *hdr;
	struct rtcp_chain_element *el;
	rtcp_handler_func func;
	str s = *_s;
	struct call *c = sfd->call;
	struct rtcp_process_ctx log_ctx_s,
				*log_ctx;
	unsigned int len;
	int ret;
	int min_packet_size;

	ZERO(log_ctx_s);
	log_ctx_s.call = c;
	log_ctx_s.received = tv;

	log_ctx = &log_ctx_s;

	CAH(init);
	CAH(start, c);

	while (1) {
		if (!(hdr = rtcp_length_check(&s, sizeof(*hdr), &len)))
			break;

		if (hdr->version != 2) {
			ilog(LOG_WARN, "Unknown RTCP version %u", hdr->version);
			goto error;
		}

		min_packet_size = 0;
		if (hdr->pt < G_N_ELEMENTS(min_packet_sizes))
			min_packet_size = min_packet_sizes[hdr->pt];
		if (len < min_packet_size) {
			ilog(LOG_WARN, "Invalid RTCP packet type %u (short: %u < %i)",
					hdr->pt, len, min_packet_size);
			goto error;
		}

		el = rtcp_new_element(hdr, len);

		if (hdr->pt >= G_N_ELEMENTS(handler_funcs)) {
			ilog(LOG_INFO, "Ignoring unknown RTCP packet type %u", hdr->pt);
			goto next;
		}
		func = handler_funcs[hdr->pt];
		if (!func) {
			ilog(LOG_INFO, "Ignoring unknown RTCP packet type %u", hdr->pt);
			goto next;
		}

		ilog(LOG_DEBUG, "Calling handler for RTCP packet type %u", hdr->pt);
		ret = func(el, log_ctx);
		if (ret) {
			ilog(LOG_WARN, "Failed to handle or parse RTCP packet type %u", hdr->pt);
			rtcp_ce_free(el);
			goto error;
		}

next:
		g_queue_push_tail(q, el);

		if (str_shift(&s, el->len))
			abort();
	}

	CAH(finish, c, src, &sfd->socket.local, tv);
	CAH(destroy);

	return 0;

error:
	CAH(finish, c, src, &sfd->socket.local, tv);
	CAH(destroy);
	rtcp_list_free(q);
	return -1;
}

void rtcp_parse(const str *s, struct stream_fd *sfd, const endpoint_t *src, const struct timeval *tv) {
	GQueue rtcp_list = G_QUEUE_INIT;
	if (__rtcp_parse(&rtcp_list, s, sfd, src, tv))
		return;
	rtcp_list_free(&rtcp_list);
}

int rtcp_avpf2avp(str *s, struct stream_fd *sfd, const endpoint_t *src, const struct timeval *tv) {
	GQueue rtcp_list = G_QUEUE_INIT;
	GList *l;
	struct rtcp_chain_element *el;
	void *start;
	unsigned int removed, left;

	if (__rtcp_parse(&rtcp_list, s, sfd, src, tv))
		return 0;

	left = s->len;
	removed = 0;
	for (l = rtcp_list.head; l; l = l->next) {
		el = l->data;
		left -= el->len;

		switch (el->type) {
			case RTCP_PT_RTPFB:
			case RTCP_PT_PSFB:
				start = el->u.buf;
				memmove(start - removed, start + el->len - removed, left);
				removed += el->len;
				break;

			default:
				break;
		}
	}

	rtcp_list_free(&rtcp_list);

	s->len -= removed;
	if (!s->len)
		return -1;

	return 0;
}


INLINE int check_session_keys(struct crypto_context *c) {
	str s;
	const char *err;

	if (c->have_session_key)
		return 0;
	err = "SRTCP output wanted, but no crypto suite was negotiated";
	if (!c->params.crypto_suite)
		goto error;

	err = "Failed to generate SRTCP session keys";
	str_init_len_assert(&s, c->session_key, c->params.crypto_suite->session_key_len);
	if (crypto_gen_session_key(c, &s, 0x03, SRTCP_R_LENGTH))
		goto error;
	str_init_len_assert(&s, c->session_auth_key, c->params.crypto_suite->srtcp_auth_key_len);
	if (crypto_gen_session_key(c, &s, 0x04, SRTCP_R_LENGTH))
		goto error;
	str_init_len_assert(&s, c->session_salt, c->params.crypto_suite->session_salt_len);
	if (crypto_gen_session_key(c, &s, 0x05, SRTCP_R_LENGTH))
		goto error;

	c->have_session_key = 1;
	crypto_init_session_key(c);

	return 0;

error:
	ilog(LOG_ERROR | LOG_FLAG_LIMIT, "%s", err);
	return -1;
}

static int rtcp_payload(struct rtcp_packet **out, str *p, const str *s) {
	struct rtcp_packet *rtcp;
	const char *err;

	err = "short packet (header)";
	if (s->len < sizeof(*rtcp))
		goto error;

	rtcp = (void *) s->s;

	err = "invalid header version";
	if (rtcp->header.version != 2) /* version 2 */
		goto error;
	err = "invalid packet type";
	if (rtcp->header.pt != RTCP_PT_SR
			&& rtcp->header.pt != RTCP_PT_RR)
		goto error;

	*p = *s;
	str_shift(p, sizeof(*rtcp));
	*out = rtcp;

	return 0;
error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Error parsing RTCP header: %s", err);
	return -1;
}

/* rfc 3711 section 3.4 */
int rtcp_avp2savp(str *s, struct crypto_context *c) {
	struct rtcp_packet *rtcp;
	u_int32_t *idx;
	str to_auth, payload;

	if (rtcp_payload(&rtcp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	if (!c->params.session_params.unencrypted_srtcp && crypto_encrypt_rtcp(c, rtcp, &payload, c->last_index))
		return -1;

	idx = (void *) s->s + s->len;
	*idx = htonl((c->params.session_params.unencrypted_srtcp ? 0ULL : 0x80000000ULL) | c->last_index++);
	s->len += sizeof(*idx);

	to_auth = *s;

	rtp_append_mki(s, c);

	c->params.crypto_suite->hash_rtcp(c, s->s + s->len, &to_auth);
	s->len += c->params.crypto_suite->srtcp_auth_tag;

	return 1;
}


/* rfc 3711 section 3.4 */
int rtcp_savp2avp(str *s, struct crypto_context *c) {
	struct rtcp_packet *rtcp;
	str payload, to_auth, to_decrypt, auth_tag;
	u_int32_t idx, *idx_p;
	char hmac[20];
	const char *err;

	if (rtcp_payload(&rtcp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	if (srtp_payloads(&to_auth, &to_decrypt, &auth_tag, NULL,
			c->params.crypto_suite->srtcp_auth_tag, c->params.mki_len,
			s, &payload))
		return -1;

	err = "short packet";
	if (to_decrypt.len < sizeof(idx))
		goto error;
	to_decrypt.len -= sizeof(idx);
	idx_p = (void *) to_decrypt.s + to_decrypt.len;
	idx = ntohl(*idx_p);

	assert(sizeof(hmac) >= auth_tag.len);
	c->params.crypto_suite->hash_rtcp(c, hmac, &to_auth);
	err = "authentication failed";
	if (str_memcmp(&auth_tag, hmac))
		goto error;

	if ((idx & 0x80000000ULL)) {
		if (crypto_decrypt_rtcp(c, rtcp, &to_decrypt, idx & 0x7fffffffULL))
			return -1;
	}

	*s = to_auth;
	s->len -= sizeof(idx);

	return 0;

error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Discarded invalid SRTCP packet: %s", err);
	return -1;
}


static void str_sanitize(GString *s) {
	while (s->len > 0 && (s->str[s->len - 1] == ' ' || s->str[s->len - 1] == ','))
		g_string_truncate(s, s->len - 1);
}


static void dummy_handler() {
	return;
}



static void scratch_common(struct rtcp_process_ctx *ctx, const struct rtcp_packet *common) {
	ctx->scratch_common_ssrc = htonl(common->ssrc);
}
static void scratch_rr(struct rtcp_process_ctx *ctx, const struct report_block *rr) {
	ctx->scratch.rr = (struct ssrc_receiver_report) {
		.from = ctx->scratch_common_ssrc,
		.ssrc = htonl(rr->ssrc),
		.high_seq_received = ntohl(rr->high_seq_received),
		.fraction_lost = rr->fraction_lost,
		.jitter = ntohl(rr->jitter),
		.lsr = ntohl(rr->lsr),
		.dlsr = ntohl(rr->dlsr),
	};
	ctx->scratch.rr.packets_lost = (rr->number_lost[0] << 16) | (rr->number_lost[1] << 8) | rr->number_lost[2];
}
static void scratch_sr(struct rtcp_process_ctx *ctx, const struct sender_report_packet *sr) {
	ctx->scratch.sr = (struct ssrc_sender_report) {
		.ssrc = ctx->scratch_common_ssrc,
		.ntp_msw = ntohl(sr->ntp_msw),
		.ntp_lsw = ntohl(sr->ntp_lsw),
		.octet_count = ntohl(sr->octet_count),
		.timestamp = ntohl(sr->timestamp),
		.packet_count = ntohl(sr->packet_count),
	};
	ctx->scratch.sr.ntp_ts = ntp_ts_to_double(ctx->scratch.sr.ntp_msw, ctx->scratch.sr.ntp_lsw);
}



static void homer_init(struct rtcp_process_ctx *ctx) {
	ctx->json = g_string_new("{ ");
}
static void homer_sr(struct rtcp_process_ctx *ctx, const struct sender_report_packet *sr) {
	g_string_append_printf(ctx->json, "\"sender_information\":{\"ntp_timestamp_sec\":%u,"
	"\"ntp_timestamp_usec\":%u,\"octets\":%u,\"rtp_timestamp\":%u, \"packets\":%u},",
		ctx->scratch.sr.ntp_msw,
		ctx->scratch.sr.ntp_lsw,
		ctx->scratch.sr.octet_count,
		ctx->scratch.sr.timestamp,
		ctx->scratch.sr.packet_count);
}
static void homer_rr_list_start(struct rtcp_process_ctx *ctx, const struct rtcp_packet *common) {
	g_string_append_printf(ctx->json, "\"ssrc\":%u,\"type\":%u,\"report_count\":%u,\"report_blocks\":[",
		ctx->scratch_common_ssrc,
		common->header.pt,
		common->header.count);
}
static void homer_rr(struct rtcp_process_ctx *ctx, const struct report_block *rr) {
	g_string_append_printf(ctx->json, "{\"source_ssrc\":%u,"
	    "\"highest_seq_no\":%u,\"fraction_lost\":%u,\"ia_jitter\":%u,"
	    "\"packets_lost\":%u,\"lsr\":%u,\"dlsr\":%u},",
		ctx->scratch.rr.ssrc,
		ctx->scratch.rr.high_seq_received,
		ctx->scratch.rr.fraction_lost,
		ctx->scratch.rr.jitter,
		ctx->scratch.rr.packets_lost,
		ctx->scratch.rr.lsr,
		ctx->scratch.rr.dlsr);
}
static void homer_rr_list_end(struct rtcp_process_ctx *ctx) {
	str_sanitize(ctx->json);
	g_string_append_printf(ctx->json, "],");
}
static void homer_sdes_list_start(struct rtcp_process_ctx *ctx, const struct source_description_packet *sdes) {
	g_string_append_printf(ctx->json, "\"sdes_report_count\":%u,\"sdes_information\": [ ",
		sdes->header.count);
}
static void homer_sdes_item(struct rtcp_process_ctx *ctx, const struct sdes_chunk *chunk,
		const struct sdes_item *item, const char *data)
{
	int i;

	g_string_append_printf(ctx->json, "{\"sdes_chunk_ssrc\":%u,\"type\":%u,\"text\":\"",
		htonl(chunk->ssrc),
		item->type);

	for (i = 0; i < item->length; i++) {
		switch (data[i]) {
			case '"':
				g_string_append(ctx->json, "\\\"");
				break;
			case '\\':
				g_string_append(ctx->json, "\\\\");
				break;
			case '\b':
				g_string_append(ctx->json, "\\b");
				break;
			case '\f':
				g_string_append(ctx->json, "\\f");
				break;
			case '\n':
				g_string_append(ctx->json, "\\n");
				break;
			case '\r':
				g_string_append(ctx->json, "\\r");
				break;
			case '\t':
				g_string_append(ctx->json, "\\t");
				break;
			default:
				g_string_append_c(ctx->json, data[i]);
				break;
		}
	}

	g_string_append(ctx->json, "\"},");
}
static void homer_sdes_list_end(struct rtcp_process_ctx *ctx) {
	str_sanitize(ctx->json);
	g_string_append_printf(ctx->json, "],");
}
static void homer_finish(struct rtcp_process_ctx *ctx, struct call *c, const endpoint_t *src,
		const endpoint_t *dst, const struct timeval *tv)
{
	str_sanitize(ctx->json);
	g_string_append(ctx->json, " }");
	homer_send(ctx->json, &c->callid, src, dst, tv);
	ctx->json = NULL;
}

static void logging_init(struct rtcp_process_ctx *ctx) {
	ctx->log = g_string_new(NULL);
}
static void logging_start(struct rtcp_process_ctx *ctx, struct call *c) {
	g_string_append_printf(ctx->log, "["STR_FORMAT"] ", STR_FMT(&c->callid));
}
static void logging_common(struct rtcp_process_ctx *ctx, const struct rtcp_packet *common) {
	g_string_append_printf(ctx->log,"version=%u, padding=%u, count=%u, payloadtype=%u, length=%u, ssrc=%u, ",
		common->header.version,
		common->header.p,
		common->header.count,
		common->header.pt,
		ntohs(common->header.length),
		ctx->scratch_common_ssrc);
}
static void logging_sdes_list_start(struct rtcp_process_ctx *ctx, const struct source_description_packet *sdes) {
	g_string_append_printf(ctx->log,"version=%u, padding=%u, count=%u, payloadtype=%u, length=%u, ",
		sdes->header.version,
		sdes->header.p,
		sdes->header.count,
		sdes->header.pt,
		ntohs(sdes->header.length));
}
static void logging_sr(struct rtcp_process_ctx *ctx, const struct sender_report_packet *sr) {
	g_string_append_printf(ctx->log,"ntp_sec=%u, ntp_fractions=%u, rtp_ts=%u, sender_packets=%u, " \
			"sender_bytes=%u, ",
		ctx->scratch.sr.ntp_msw,
		ctx->scratch.sr.ntp_lsw,
		ctx->scratch.sr.timestamp,
		ctx->scratch.sr.packet_count,
		ctx->scratch.sr.octet_count);
}
static void logging_rr(struct rtcp_process_ctx *ctx, const struct report_block *rr) {
	    g_string_append_printf(ctx->log,"ssrc=%u, fraction_lost=%u, packet_loss=%u, last_seq=%u, jitter=%u, last_sr=%u, delay_since_last_sr=%u, ",
			ctx->scratch.rr.ssrc,
			rr->fraction_lost,
			ctx->scratch.rr.packets_lost,
			ctx->scratch.rr.high_seq_received,
			ctx->scratch.rr.jitter,
			ctx->scratch.rr.lsr,
			ctx->scratch.rr.dlsr);
}
static void logging_xr(struct rtcp_process_ctx *ctx, const struct rtcp_packet *common, str *comp_s) {
	pjmedia_rtcp_xr_rx_rtcp_xr(ctx->log, common, comp_s);
}
static void logging_finish(struct rtcp_process_ctx *ctx, struct call *c, const endpoint_t *src,
		const endpoint_t *dst, const struct timeval *tv)
{
	str_sanitize(ctx->log);
	rtcplog(ctx->log->str);
}
static void logging_destroy(struct rtcp_process_ctx *ctx) {
	g_string_free(ctx->log, TRUE);
}




static void mos_sr(struct rtcp_process_ctx *ctx, const struct sender_report_packet *sr) {
	ssrc_sender_report(ctx->call, &ctx->scratch.sr, ctx->received);
}
static void mos_rr(struct rtcp_process_ctx *ctx, const struct report_block *rr) {
	ssrc_receiver_report(ctx->call, &ctx->scratch.rr, ctx->received);
}




void rtcp_init() {
	rtcp_handlers.logging = _log_facility_rtcp ? &log_handlers : &dummy_handlers;
	rtcp_handlers.homer = has_homer() ? &homer_handlers : &dummy_handlers;

	// walk through list of handlers and fill missing entries to dummy handler
	void *dummy = dummy_handler;
	for (int i = 0; i < G_N_ELEMENTS(all_handlers); i++) {
		struct rtcp_handler *lh = all_handlers[i];
		for (int j = 0; j < (sizeof(*lh) / sizeof(void *)); j++) {
			void **ptr = (void *) lh;
			ptr += j;
			if (*ptr == NULL)
				*ptr = dummy;
		}
	}
}
