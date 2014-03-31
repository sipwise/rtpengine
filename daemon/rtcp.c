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



/* This toggles between two different and incompatible interpretations of
 * RFC 3711, namely sections 4.3.2 and 4.3.1.
 * See http://www.ietf.org/mail-archive/web/avt/current/msg06124.html
 * The default (define not set) is to be compatible with libsrtp, but
 * incompatible with a strict interpretation of the RFC.
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





typedef struct rtcp_chain_element *(*rtcp_handler_func)(str *);

static struct rtcp_chain_element *rtcp_sr(str *s);
static struct rtcp_chain_element *rtcp_rr(str *s);
static struct rtcp_chain_element *rtcp_sdes(str *s);
static struct rtcp_chain_element *rtcp_bye(str *s);
static struct rtcp_chain_element *rtcp_app(str *s);
static struct rtcp_chain_element *rtcp_rtpfb(str *s);
static struct rtcp_chain_element *rtcp_psfb(str *s);





static const rtcp_handler_func handler_funcs[] = {
	[RTCP_PT_SR]	= rtcp_sr,
	[RTCP_PT_RR]	= rtcp_rr,
	[RTCP_PT_SDES]	= rtcp_sdes,
	[RTCP_PT_BYE]	= rtcp_bye,
	[RTCP_PT_APP]	= rtcp_app,
	[RTCP_PT_RTPFB]	= rtcp_rtpfb,
	[RTCP_PT_PSFB]	= rtcp_psfb,
};






static void *rtcp_length_check(str *s, size_t min_len, unsigned int *len_p) {
	struct rtcp_header *h;

	if (s->len < min_len)
		return NULL;

	h = (void *) s->s;
	*len_p = (ntohs(h->length) + 1) << 2;

	if (*len_p > s->len)
		return NULL;

	return h;
}

static struct rtcp_chain_element *rtcp_new_element(void *p, unsigned int len, int type) {
	struct rtcp_chain_element *el;

	el = g_slice_alloc(sizeof(*el));
	el->type = type;
	el->len = len;
	el->u.buf = p;

	return el;
}

static struct rtcp_chain_element *rtcp_generic(str *s, int type) {
	struct rtcp_header *p;
	unsigned int len;

	if (!(p = rtcp_length_check(s, sizeof(*p), &len)))
		return NULL;

	return rtcp_new_element(p, len, type);
}

static struct rtcp_chain_element *rtcp_Xr(str *s, int type, size_t struct_len) {
	struct rtcp_packet *p;
	unsigned int len;

	if (!(p = rtcp_length_check(s, struct_len, &len)))
		return NULL;

	if (len < (p->header.v_p_x & 0x1f) * sizeof(struct report_block))
		return NULL;

	return rtcp_new_element(p, len, type);
}

static struct rtcp_chain_element *rtcp_sr(str *s) {
	return rtcp_Xr(s, RTCP_PT_SR, sizeof(struct sender_report_packet));
}

static struct rtcp_chain_element *rtcp_rr(str *s) {
	return rtcp_Xr(s, RTCP_PT_RR, sizeof(struct receiver_report_packet));
}

static struct rtcp_chain_element *rtcp_sdes(str *s) {
	struct source_description_packet *p;
	unsigned int len;

	if (!(p = rtcp_length_check(s, sizeof(*p), &len)))
		return NULL;

	/* sdes items ... */

	return rtcp_new_element(p, len, RTCP_PT_SDES);
}

static struct rtcp_chain_element *rtcp_bye(str *s) {
	return rtcp_generic(s, RTCP_PT_BYE);
}

static struct rtcp_chain_element *rtcp_app(str *s) {
	return rtcp_generic(s, RTCP_PT_APP);
}

static struct rtcp_chain_element *rtcp_rtpfb(str *s) {
	return rtcp_generic(s, RTCP_PT_RTPFB);
}

static struct rtcp_chain_element *rtcp_psfb(str *s) {
	return rtcp_generic(s, RTCP_PT_PSFB);
}

static void rtcp_list_free(GQueue *q) {
	struct rtcp_chain_element *el;

	while ((el = g_queue_pop_head(q)))
		g_slice_free1(sizeof(*el), el);
}

static int rtcp_parse(GQueue *q, str *_s) {
	struct rtcp_packet *hdr;
	struct rtcp_chain_element *el;
	rtcp_handler_func func;
	str s = *_s;

	while (1) {
		if (s.len < sizeof(*hdr))
			break;

		hdr = (void *) s.s;

		if ((hdr->header.v_p_x & 0xc0) != 0x80) /* version 2 */
			goto error;

		if (hdr->header.pt >= G_N_ELEMENTS(handler_funcs))
			goto error;
		func = handler_funcs[hdr->header.pt];
		if (!func)
			goto error;

		el = func(&s);
		if (!el)
			goto error;

		g_queue_push_tail(q, el);

		if (str_shift(&s, el->len))
			abort();
	}

	return 0;

error:
	rtcp_list_free(q);
	return -1;
}

int rtcp_avpf2avp(str *s) {
	GQueue rtcp_list = G_QUEUE_INIT;
	GList *l;
	struct rtcp_chain_element *el;
	void *start;
	unsigned int removed, left;

	if (rtcp_parse(&rtcp_list, s))
		return 0;

	left = s->len;
	removed = 0;
	for (l = rtcp_list.head; l; l = l->next) {
		el = l->data;
		left -= el->len;

		switch (el->type) {
			case RTCP_PT_SR:
			case RTCP_PT_RR:
			case RTCP_PT_SDES:
			case RTCP_PT_BYE:
			case RTCP_PT_APP:
				break;

			case RTCP_PT_RTPFB:
			case RTCP_PT_PSFB:
				start = el->u.buf;
				memmove(start - removed, start + el->len - removed, left);
				removed += el->len;
				break;

			default:
				abort();
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
	ilog(LOG_ERROR, "%s", err);
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
	if ((rtcp->header.v_p_x & 0xc0) != 0x80) /* version 2 */
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
	ilog(LOG_WARNING, "Error parsing RTCP header: %s", err);
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

	if (crypto_encrypt_rtcp(c, rtcp, &payload, c->last_index))
		return -1;

	idx = (void *) s->s + s->len;
	*idx = htonl(0x80000000ULL | c->last_index++);
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
	ilog(LOG_WARNING, "Discarded invalid SRTCP packet: %s", err);
	return -1;
}


/* RFC 5761 section 4 */
int rtcp_demux_is_rtcp(const str *s) {
	struct rtcp_packet *rtcp;

	if (s->len < sizeof(*rtcp))
		return 0;

	rtcp = (void *) s->s;

	if (rtcp->header.pt < 194)
		return 0;
	if (rtcp->header.pt > 223)
		return 0;
	return 1;
}
