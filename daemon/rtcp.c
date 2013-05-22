#include "rtcp.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "str.h"
#include "call.h"
#include "log.h"




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



struct rtcp_header {
	unsigned char v_p_x;
	unsigned char pt;
	u_int16_t length;
} __attribute__ ((packed));

struct rtcp_packet {
	struct rtcp_header header;
	u_int32_t ssrc;
} __attribute__ ((packed));

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

static void rtcp_list_free_cb(void *d) {
	g_slice_free1(sizeof(struct rtcp_chain_element), d);
}
static void rtcp_list_free(GQueue *q) {
	g_queue_free_full(q, rtcp_list_free_cb);
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

		if (hdr->header.pt >= ARRAYSIZE(handler_funcs))
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

	s->len -= removed;
	if (!s->len)
		return -1;

	return 0;
}
