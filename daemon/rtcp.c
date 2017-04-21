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

/* RTCP XR block types */
#define BT_LOSS_RLE	    1
#define BT_DUP_RLE	    2
#define BT_RCPT_TIMES	    3
#define BT_RR_TIME	    4
#define BT_DLRR		    5
#define BT_STATS	    6
#define BT_VOIP_METRICS	    7


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

struct xr_report_block {
    u_int8_t		 bt;		/**< Block type.		*/
    u_int8_t		 specific;	/**< Block specific data.	*/
    u_int16_t		 length;	/**< Block length.		*/
} __attribute__ ((packed));

struct xr_packet {
	struct rtcp_packet rtcp;
	struct xr_report_block report_blocks[0];
} __attribute__ ((packed));

struct xr_rb_rr_time {
    struct xr_report_block header;
    u_int32_t		 ntp_msw;	/**< NTP time, seconds part.	*/
    u_int32_t		 ntp_lsw;	/**< NTP time, fractions part.	*/
} __attribute__ ((packed));

struct xr_rb_dlrr_item {
    u_int32_t		 ssrc;		/**< receiver SSRC		*/
    u_int32_t		 lrr;		/**< last receiver report	*/
    u_int32_t		 dlrr;		/**< delay since last receiver
					     report			*/
} __attribute__ ((packed));

struct xr_rb_dlrr {
    struct xr_report_block header;
    struct xr_rb_dlrr_item item;	/**< Block contents,
					     variable length list	*/
} __attribute__ ((packed));

struct xr_rb_stats {
    struct xr_report_block header;
    u_int32_t		 ssrc;		/**< Receiver SSRC		     */
    u_int16_t		 begin_seq;	/**< Begin RTP sequence reported     */
    u_int16_t		 end_seq;	/**< End RTP sequence reported       */
    u_int32_t		 lost;		/**< Number of packet lost in this
					     interval  */
    u_int32_t		 dup;		/**< Number of duplicated packet in
					     this interval */
    u_int32_t		 jitter_min;	/**< Minimum jitter in this interval */
    u_int32_t		 jitter_max;	/**< Maximum jitter in this interval */
    u_int32_t		 jitter_mean;	/**< Average jitter in this interval */
    u_int32_t		 jitter_dev;	/**< Jitter deviation in this
					     interval */
    u_int32_t		 toh_min:8;	/**< Minimum ToH in this interval    */
    u_int32_t		 toh_max:8;	/**< Maximum ToH in this interval    */
    u_int32_t		 toh_mean:8;	/**< Average ToH in this interval    */
    u_int32_t		 toh_dev:8;	/**< ToH deviation in this interval  */
} __attribute__ ((packed));

struct xr_rb_voip_metrics {
    struct xr_report_block header;
    u_int32_t		 ssrc;		/**< Receiver SSRC		*/
    u_int8_t		 loss_rate;	/**< Packet loss rate		*/
    u_int8_t		 discard_rate;	/**< Packet discarded rate	*/
    u_int8_t		 burst_den;	/**< Burst density		*/
    u_int8_t		 gap_den;	/**< Gap density		*/
    u_int16_t		 burst_dur;	/**< Burst duration		*/
    u_int16_t		 gap_dur;	/**< Gap duration		*/
    u_int16_t		 rnd_trip_delay;/**< Round trip delay		*/
    u_int16_t		 end_sys_delay; /**< End system delay		*/
    u_int8_t		 signal_lvl;	/**< Signal level		*/
    u_int8_t		 noise_lvl;	/**< Noise level		*/
    u_int8_t		 rerl;		/**< Residual Echo Return Loss	*/
    u_int8_t		 gmin;		/**< The gap threshold		*/
    u_int8_t		 r_factor;	/**< Voice quality metric carried
					     over this RTP session	*/
    u_int8_t		 ext_r_factor;  /**< Voice quality metric carried
					     outside of this RTP session*/
    u_int8_t		 mos_lq;	/**< Mean Opinion Score for
					     Listening Quality          */
    u_int8_t		 mos_cq;	/**< Mean Opinion Score for
					     Conversation Quality       */
    u_int8_t		 rx_config;	/**< Receiver configuration	*/
    u_int8_t		 reserved2;	/**< Not used			*/
    u_int16_t		 jb_nom;	/**< Current delay by jitter
					     buffer			*/
    u_int16_t		 jb_max;	/**< Maximum delay by jitter
					     buffer			*/
    u_int16_t		 jb_abs_max;	/**< Maximum possible delay by
					     jitter buffer		*/
}  __attribute__ ((packed));

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
		struct xr_packet *xr;
	} u;
};

// log handlers
// struct defs
// context to hold state variables
struct rtcp_process_ctx {
	// input
	struct call *call;
	struct call_media *media;
	const struct timeval *received;

	// handler vars
	union {
		struct ssrc_receiver_report rr;
		struct ssrc_sender_report sr;
		struct ssrc_xr_voip_metrics xr_vm;
		struct ssrc_xr_rr_time xr_rr;
		struct ssrc_xr_dlrr xr_dlrr;
	} scratch;
	u_int32_t scratch_common_ssrc;

	// RTCP syslog output
	GString *log;
	int log_init_len;

	// Homer stats
	GString *json;
	int json_init_len;
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
	//void (*xr)(struct rtcp_process_ctx *, const struct rtcp_packet *, str *);
	void (*sdes_list_start)(struct rtcp_process_ctx *, const struct source_description_packet *);
	void (*sdes_item)(struct rtcp_process_ctx *, const struct sdes_chunk *, const struct sdes_item *,
			const char *);
	void (*sdes_list_end)(struct rtcp_process_ctx *);
	void (*xr_rb)(struct rtcp_process_ctx *, const struct xr_report_block *);
	void (*xr_dlrr)(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
	void (*xr_stats)(struct rtcp_process_ctx *, const struct xr_rb_stats *);
	void (*xr_rr_time)(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
	void (*xr_voip_metrics)(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);
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
static void scratch_xr_rr_time(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
static void scratch_xr_dlrr(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
static void scratch_xr_voip_metrics(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);

// MOS calculation / stats
static void mos_sr(struct rtcp_process_ctx *, const struct sender_report_packet *);
static void mos_rr(struct rtcp_process_ctx *, const struct report_block *);
static void mos_xr_rr_time(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
static void mos_xr_dlrr(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
static void mos_xr_voip_metrics(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);

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
static void logging_xr_rb(struct rtcp_process_ctx *, const struct xr_report_block *);
static void logging_xr_rr_time(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
static void logging_xr_dlrr(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
static void logging_xr_stats(struct rtcp_process_ctx *, const struct xr_rb_stats *);
static void logging_xr_voip_metrics(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);
static void logging_finish(struct rtcp_process_ctx *, struct call *, const endpoint_t *, const endpoint_t *,
		const struct timeval *);
static void logging_destroy(struct rtcp_process_ctx *);

// structs for each handler type
static struct rtcp_handler dummy_handlers;
static struct rtcp_handler scratch_handlers = {
	.common = scratch_common,
	.rr = scratch_rr,
	.sr = scratch_sr,
	.xr_rr_time = scratch_xr_rr_time,
	.xr_dlrr = scratch_xr_dlrr,
	.xr_voip_metrics = scratch_xr_voip_metrics,
};
static struct rtcp_handler mos_handlers = {
	.rr = mos_rr,
	.sr = mos_sr,
	.xr_rr_time = mos_xr_rr_time,
	.xr_dlrr = mos_xr_dlrr,
	.xr_voip_metrics = mos_xr_voip_metrics,
};
static struct rtcp_handler log_handlers = {
	.init = logging_init,
	.start = logging_start,
	.common = logging_common,
	.sdes_list_start = logging_sdes_list_start,
	.sr = logging_sr,
	.rr = logging_rr,
	.xr_rb = logging_xr_rb,
	.xr_rr_time = logging_xr_rr_time,
	.xr_dlrr = logging_xr_dlrr,
	.xr_stats = logging_xr_stats,
	.xr_voip_metrics = logging_xr_voip_metrics,
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
typedef void (*xr_handler_func)(void *, struct rtcp_process_ctx *);

static int rtcp_sr(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_rr(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_sdes(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_xr(struct rtcp_chain_element *, struct rtcp_process_ctx *);
static int rtcp_generic(struct rtcp_chain_element *, struct rtcp_process_ctx *);

static void xr_rr_time(struct xr_rb_rr_time *, struct rtcp_process_ctx *);
static void xr_dlrr(struct xr_rb_dlrr *, struct rtcp_process_ctx *);
static void xr_stats(struct xr_rb_stats *, struct rtcp_process_ctx *);
static void xr_voip_metrics(struct xr_rb_voip_metrics *, struct rtcp_process_ctx *);





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

static const xr_handler_func xr_handler_funcs[] = {
	[BT_RR_TIME]		= (void *) xr_rr_time,
	[BT_DLRR]		= (void *) xr_dlrr,
	[BT_STATS]		= (void *) xr_stats,
	[BT_VOIP_METRICS]	= (void *) xr_voip_metrics,
};
static const int min_xr_packet_sizes[] = {
	[BT_RR_TIME]		= sizeof(struct xr_rb_rr_time),
	[BT_DLRR]		= sizeof(struct xr_rb_dlrr),
	[BT_STATS]		= sizeof(struct xr_rb_stats),
	[BT_VOIP_METRICS]	= sizeof(struct xr_rb_voip_metrics),
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



static void xr_rr_time(struct xr_rb_rr_time *rb, struct rtcp_process_ctx *log_ctx) {
	CAH(xr_rb, &rb->header);
	CAH(xr_rr_time, rb);
}
static void xr_dlrr(struct xr_rb_dlrr *rb, struct rtcp_process_ctx *log_ctx) {
	// XXX support multiple report blocks
	CAH(xr_rb, &rb->header);
	CAH(xr_dlrr, rb);
}
static void xr_stats(struct xr_rb_stats *rb, struct rtcp_process_ctx *log_ctx) {
	CAH(xr_rb, &rb->header);
	CAH(xr_stats, rb);
}
static void xr_voip_metrics(struct xr_rb_voip_metrics *rb, struct rtcp_process_ctx *log_ctx) {
	CAH(xr_rb, &rb->header);
	CAH(xr_voip_metrics, rb);
}

static int rtcp_xr(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	CAH(common, el->u.rtcp_packet);
	str comp_s;
	str_init_len(&comp_s, el->u.buf + sizeof(el->u.xr->rtcp), el->len - sizeof(el->u.xr->rtcp));
	while (1) {
		struct xr_report_block *rb = (void *) comp_s.s;
		if (comp_s.len < sizeof(*rb))
			break;
		unsigned int len = (ntohs(rb->length) + 1) << 2;
		if (str_shift(&comp_s, len))
			break;
		if (rb->bt >= G_N_ELEMENTS(xr_handler_funcs))
			goto next;
		xr_handler_func hf = xr_handler_funcs[rb->bt];
		if (!hf)
			goto next;
		if (rb->bt < G_N_ELEMENTS(min_xr_packet_sizes) && len < min_xr_packet_sizes[rb->bt]) {
			ilog(LOG_WARN, "Short RTCP XR block (type %u, %u < %i)", rb->bt, len,
					min_xr_packet_sizes[rb->bt]);
			goto next;
		}
		hf(rb, log_ctx);

next:
		;

	}
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
	struct call_media *m = sfd->stream->media;
	struct rtcp_process_ctx log_ctx_s,
				*log_ctx;
	unsigned int len;
	int ret;
	int min_packet_size;

	ZERO(log_ctx_s);
	log_ctx_s.call = c;
	log_ctx_s.media = m;
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

int rtcp_payload(struct rtcp_packet **out, str *p, const str *s) {
	struct rtcp_packet *rtcp;
	const char *err;

	err = "short packet (header)";
	if (s->len < sizeof(*rtcp))
		goto error;

	rtcp = (void *) s->s;

	err = "invalid header version";
	if (rtcp->header.version != 2)
		goto error;
	err = "invalid packet type";
	if (rtcp->header.pt != RTCP_PT_SR
			&& rtcp->header.pt != RTCP_PT_RR)
		goto error;

	if (!p)
		goto done;

	*p = *s;
	str_shift(p, sizeof(*rtcp));

done:
	*out = rtcp;
	return 0;
error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Error parsing RTCP header: %s", err);
	return -1;
}

/* rfc 3711 section 3.4 */
int rtcp_avp2savp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtcp_packet *rtcp;
	u_int32_t *idx;
	str to_auth, payload;

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
	if (rtcp_payload(&rtcp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	if (!c->params.session_params.unencrypted_srtcp && crypto_encrypt_rtcp(c, rtcp, &payload,
				ssrc_ctx->srtcp_index))
		return -1;

	idx = (void *) s->s + s->len;
	*idx = htonl((c->params.session_params.unencrypted_srtcp ? 0ULL : 0x80000000ULL) |
			ssrc_ctx->srtcp_index++);
	s->len += sizeof(*idx);

	to_auth = *s;

	rtp_append_mki(s, c);

	c->params.crypto_suite->hash_rtcp(c, s->s + s->len, &to_auth);
	s->len += c->params.crypto_suite->srtcp_auth_tag;

	return 1;
}


/* rfc 3711 section 3.4 */
int rtcp_savp2avp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtcp_packet *rtcp;
	str payload, to_auth, to_decrypt, auth_tag;
	u_int32_t idx, *idx_p;
	char hmac[20];
	const char *err;

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
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
}
static void scratch_xr_rr_time(struct rtcp_process_ctx *ctx, const struct xr_rb_rr_time *rr) {
	ctx->scratch.xr_rr = (struct ssrc_xr_rr_time) {
		.ssrc = ctx->scratch_common_ssrc,
		.ntp_msw = ntohl(rr->ntp_msw),
		.ntp_lsw = ntohl(rr->ntp_lsw),
	};
}
static void scratch_xr_dlrr(struct rtcp_process_ctx *ctx, const struct xr_rb_dlrr *dlrr) {
	ctx->scratch.xr_dlrr = (struct ssrc_xr_dlrr) {
		.from = ctx->scratch_common_ssrc,
		.ssrc = htonl(dlrr->item.ssrc),
		.lrr = ntohl(dlrr->item.lrr),
		.dlrr = ntohl(dlrr->item.dlrr),
	};
}
static void scratch_xr_voip_metrics(struct rtcp_process_ctx *ctx, const struct xr_rb_voip_metrics *vm) {
	ctx->scratch.xr_vm = (struct ssrc_xr_voip_metrics) {
		.from = ctx->scratch_common_ssrc,
		.ssrc = ntohl(vm->ssrc),
		.loss_rate = vm->loss_rate,
		.discard_rate = vm->discard_rate,
		.burst_den = vm->burst_den,
		.gap_den = vm->gap_den,
		.burst_dur = ntohs(vm->burst_dur),
		.gap_dur = ntohs(vm->gap_dur),
		.rnd_trip_delay = ntohs(vm->rnd_trip_delay),
		.end_sys_delay = ntohs(vm->end_sys_delay),
		.signal_lvl = vm->signal_lvl,
		.noise_lvl = vm->noise_lvl,
		.rerl = vm->rerl,
		.gmin = vm->gmin,
		.r_factor = vm->r_factor,
		.ext_r_factor = vm->ext_r_factor,
		.mos_lq = vm->mos_lq,
		.mos_cq = vm->mos_cq,
		.rx_config = vm->rx_config,
		.jb_nom = ntohs(vm->jb_nom),
		.jb_max = ntohs(vm->jb_max),
		.jb_abs_max = ntohs(vm->jb_abs_max),

	};
}



static void homer_init(struct rtcp_process_ctx *ctx) {
	ctx->json = g_string_new("{ ");
	ctx->json_init_len = ctx->json->len;
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
	if (ctx->json->len > ctx->json_init_len + 2)
		homer_send(ctx->json, &c->callid, src, dst, tv);
	else
		g_string_free(ctx->json, TRUE);
	ctx->json = NULL;
}

static void logging_init(struct rtcp_process_ctx *ctx) {
	ctx->log = g_string_new(NULL);
}
static void logging_start(struct rtcp_process_ctx *ctx, struct call *c) {
	g_string_append_printf(ctx->log, "["STR_FORMAT"] ", STR_FMT(&c->callid));
	ctx->log_init_len = ctx->log->len;
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
//static void logging_xr(struct rtcp_process_ctx *ctx, const struct rtcp_packet *common, str *comp_s) {
	//pjmedia_rtcp_xr_rx_rtcp_xr(ctx->log, common, comp_s);
//}
static void logging_xr_rb(struct rtcp_process_ctx *ctx, const struct xr_report_block *rb_header) {
	g_string_append_printf(ctx->log, "rb_header_blocktype=%u, rb_header_blockspecdata=%u, " \
			"rb_header_blocklength=%u, ",
			rb_header->bt,
			rb_header->specific,
			ntohs(rb_header->length));
}
static void logging_xr_rr_time(struct rtcp_process_ctx *ctx, const struct xr_rb_rr_time *rb_rr_time) {
	g_string_append_printf(ctx->log, "rb_rr_time_ntp_sec=%u, rb_rr_time_ntp_frac=%u, ",
			ntohl(ctx->scratch.xr_rr.ntp_msw),
			ntohl(ctx->scratch.xr_rr.ntp_lsw));
}
static void logging_xr_dlrr(struct rtcp_process_ctx *ctx, const struct xr_rb_dlrr *rb_dlrr) {
	g_string_append_printf(ctx->log, "rb_dlrr_ssrc=%u, rb_dlrr_lrr=%u, rb_dlrr_dlrr=%u, ",
			ntohl(ctx->scratch.xr_dlrr.ssrc),
			ntohl(ctx->scratch.xr_dlrr.lrr),
			ntohl(ctx->scratch.xr_dlrr.dlrr));
}
static void logging_xr_stats(struct rtcp_process_ctx *ctx, const struct xr_rb_stats *rb_stats) {
	g_string_append_printf(ctx->log, "rb_stats_ssrc=%u, rb_stats_begin_seq=%u, rb_stats_end_seq=%u, rb_stats_lost_packets=%u, rb_stats_duplicate_packets=%u,"
			"rb_stats_jitter_min=%u, rb_stats_jitter_max=%u, rb_stats_jitter_mean=%u, rb_stats_jitter_deviation=%u,"
			"rb_stats_toh_min=%u, rb_stats_toh_max=%u, rb_stats_toh_mean=%u, rb_stats_toh_deviation=%u, ",
			ntohl(rb_stats->ssrc),
			ntohs(rb_stats->begin_seq),
			ntohl(rb_stats->end_seq),
			ntohl(rb_stats->lost),
			ntohl(rb_stats->dup),
			ntohl(rb_stats->jitter_min),
			ntohl(rb_stats->jitter_max),
			ntohl(rb_stats->jitter_mean),
			ntohl(rb_stats->jitter_dev),
			ntohl(rb_stats->toh_min),
			ntohl(rb_stats->toh_max),
			ntohl(rb_stats->toh_mean),
			ntohl(rb_stats->toh_dev));
}
static void logging_xr_voip_metrics(struct rtcp_process_ctx *ctx, const struct xr_rb_voip_metrics *rb_voip_mtc) {
	g_string_append_printf(ctx->log, "rb_voip_mtc_ssrc=%u, rb_voip_mtc_loss_rate=%u, " \
			"rb_voip_mtc_discard_rate=%u, rb_voip_mtc_burst_den=%u, "
			"rb_voip_mtc_gap_den=%u, rb_voip_mtc_burst_dur=%u, rb_voip_mtc_gap_dur=%u, " \
			"rb_voip_mtc_rnd_trip_delay=%u, "
			"rb_voip_mtc_end_sys_delay=%u, rb_voip_mtc_signal_lvl=%u, rb_voip_mtc_noise_lvl=%u, " \
			"rb_voip_mtc_rerl=%u, "
			"rb_voip_mtc_gmin=%u, rb_voip_mtc_r_factor=%u, rb_voip_mtc_ext_r_factor=%u, " \
			"rb_voip_mtc_mos_lq=%u, "
			"rb_voip_mtc_mos_cq=%u, rb_voip_mtc_rx_config=%u, rb_voip_mtc_jb_nom=%u, " \
			"rb_voip_mtc_jb_max=%u, "
			"rb_voip_mtc_jb_abs_max=%u, ",
			ctx->scratch.xr_vm.ssrc,
			ctx->scratch.xr_vm.loss_rate,
			ctx->scratch.xr_vm.discard_rate,
			ctx->scratch.xr_vm.burst_den,
			ctx->scratch.xr_vm.gap_den,
			ctx->scratch.xr_vm.burst_dur,
			ctx->scratch.xr_vm.gap_dur,
			ctx->scratch.xr_vm.rnd_trip_delay,
			ctx->scratch.xr_vm.end_sys_delay,
			ctx->scratch.xr_vm.signal_lvl,
			ctx->scratch.xr_vm.noise_lvl,
			ctx->scratch.xr_vm.rerl,
			ctx->scratch.xr_vm.gmin,
			ctx->scratch.xr_vm.r_factor,
			ctx->scratch.xr_vm.ext_r_factor,
			ctx->scratch.xr_vm.mos_lq,
			ctx->scratch.xr_vm.mos_cq,
			ctx->scratch.xr_vm.rx_config,
			ctx->scratch.xr_vm.jb_nom,
			ctx->scratch.xr_vm.jb_max,
			ctx->scratch.xr_vm.jb_abs_max);
}
static void logging_finish(struct rtcp_process_ctx *ctx, struct call *c, const endpoint_t *src,
		const endpoint_t *dst, const struct timeval *tv)
{
	str_sanitize(ctx->log);
	if (ctx->log->len > ctx->log_init_len)
		rtcplog(ctx->log->str);
}
static void logging_destroy(struct rtcp_process_ctx *ctx) {
	g_string_free(ctx->log, TRUE);
}




static void mos_sr(struct rtcp_process_ctx *ctx, const struct sender_report_packet *sr) {
	ssrc_sender_report(ctx->media, &ctx->scratch.sr, ctx->received);
}
static void mos_rr(struct rtcp_process_ctx *ctx, const struct report_block *rr) {
	ssrc_receiver_report(ctx->media, &ctx->scratch.rr, ctx->received);
}
static void mos_xr_rr_time(struct rtcp_process_ctx *ctx, const struct xr_rb_rr_time *rr) {
	ssrc_receiver_rr_time(ctx->media, &ctx->scratch.xr_rr, ctx->received);
}
static void mos_xr_dlrr(struct rtcp_process_ctx *ctx, const struct xr_rb_dlrr *dlrr) {
	ssrc_receiver_dlrr(ctx->media, &ctx->scratch.xr_dlrr, ctx->received);
}
static void mos_xr_voip_metrics(struct rtcp_process_ctx *ctx, const struct xr_rb_voip_metrics *rb_voip_mtc) {
	ssrc_voip_metrics(ctx->media, &ctx->scratch.xr_vm, ctx->received);
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
