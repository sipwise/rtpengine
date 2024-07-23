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
#include "sdp.h"
#include "log_funcs.h"

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
	uint32_t ssrc;
	unsigned char fraction_lost;
	unsigned char number_lost[3];
	uint32_t high_seq_received;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t dlsr;
} __attribute__ ((packed));

struct sender_report_packet {
	struct rtcp_packet rtcp;
	uint32_t ntp_msw;
	uint32_t ntp_lsw;
	uint32_t timestamp;
	uint32_t packet_count;
	uint32_t octet_count;
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
	uint32_t ssrc;
	struct sdes_item items[0];
} __attribute__ ((packed));

struct source_description_packet {
	struct rtcp_header header;
	struct sdes_chunk chunks[0];
} __attribute__ ((packed));

struct bye_packet {
	struct rtcp_header header;
	uint32_t ssrcs[0];
} __attribute__ ((packed));

struct app_packet {
	struct rtcp_packet rtcp;
	unsigned char name[4];
	unsigned char data[0];
} __attribute__ ((packed));

struct fb_packet {
	struct rtcp_packet rtcp;
	uint32_t media_ssrc;
	unsigned char information[0];
} __attribute__ ((packed));

struct xr_report_block {
    uint8_t		 bt;		/**< Block type.		*/
    uint8_t		 specific;	/**< Block specific data.	*/
    uint16_t		 length;	/**< Block length.		*/
} __attribute__ ((packed));

struct xr_packet {
	struct rtcp_packet rtcp;
	struct xr_report_block report_blocks[0];
} __attribute__ ((packed));

struct xr_rb_rr_time {
    struct xr_report_block header;
    uint32_t		 ntp_msw;	/**< NTP time, seconds part.	*/
    uint32_t		 ntp_lsw;	/**< NTP time, fractions part.	*/
} __attribute__ ((packed));

struct xr_rb_dlrr_item {
    uint32_t		 ssrc;		/**< receiver SSRC		*/
    uint32_t		 lrr;		/**< last receiver report	*/
    uint32_t		 dlrr;		/**< delay since last receiver
					     report			*/
} __attribute__ ((packed));

struct xr_rb_dlrr {
    struct xr_report_block header;
    struct xr_rb_dlrr_item item;	/**< Block contents,
					     variable length list	*/
} __attribute__ ((packed));

struct xr_rb_stats {
    struct xr_report_block header;
    uint32_t		 ssrc;		/**< Receiver SSRC		     */
    uint16_t		 begin_seq;	/**< Begin RTP sequence reported     */
    uint16_t		 end_seq;	/**< End RTP sequence reported       */
    uint32_t		 lost;		/**< Number of packet lost in this
					     interval  */
    uint32_t		 dup;		/**< Number of duplicated packet in
					     this interval */
    uint32_t		 jitter_min;	/**< Minimum jitter in this interval */
    uint32_t		 jitter_max;	/**< Maximum jitter in this interval */
    uint32_t		 jitter_mean;	/**< Average jitter in this interval */
    uint32_t		 jitter_dev;	/**< Jitter deviation in this
					     interval */
    uint32_t		 toh_min:8;	/**< Minimum ToH in this interval    */
    uint32_t		 toh_max:8;	/**< Maximum ToH in this interval    */
    uint32_t		 toh_mean:8;	/**< Average ToH in this interval    */
    uint32_t		 toh_dev:8;	/**< ToH deviation in this interval  */
} __attribute__ ((packed));

struct xr_rb_voip_metrics {
    struct xr_report_block header;
    uint32_t		 ssrc;		/**< Receiver SSRC		*/
    uint8_t		 loss_rate;	/**< Packet loss rate		*/
    uint8_t		 discard_rate;	/**< Packet discarded rate	*/
    uint8_t		 burst_den;	/**< Burst density		*/
    uint8_t		 gap_den;	/**< Gap density		*/
    uint16_t		 burst_dur;	/**< Burst duration		*/
    uint16_t		 gap_dur;	/**< Gap duration		*/
    uint16_t		 rnd_trip_delay;/**< Round trip delay		*/
    uint16_t		 end_sys_delay; /**< End system delay		*/
    uint8_t		 signal_lvl;	/**< Signal level		*/
    uint8_t		 noise_lvl;	/**< Noise level		*/
    uint8_t		 rerl;		/**< Residual Echo Return Loss	*/
    uint8_t		 gmin;		/**< The gap threshold		*/
    uint8_t		 r_factor;	/**< Voice quality metric carried
					     over this RTP session	*/
    uint8_t		 ext_r_factor;  /**< Voice quality metric carried
					     outside of this RTP session*/
    uint8_t		 mos_lq;	/**< Mean Opinion Score for
					     Listening Quality          */
    uint8_t		 mos_cq;	/**< Mean Opinion Score for
					     Conversation Quality       */
    uint8_t		 rx_config;	/**< Receiver configuration	*/
    uint8_t		 reserved2;	/**< Not used			*/
    uint16_t		 jb_nom;	/**< Current delay by jitter
					     buffer			*/
    uint16_t		 jb_max;	/**< Maximum delay by jitter
					     buffer			*/
    uint16_t		 jb_abs_max;	/**< Maximum possible delay by
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
	};
};

// log handlers
// struct defs
// context to hold state variables
struct rtcp_process_ctx {
	// input
	struct media_packet *mp;

	// handler vars
	union {
		struct ssrc_receiver_report rr;
		struct ssrc_sender_report sr;
		struct ssrc_xr_voip_metrics xr_vm;
		struct ssrc_xr_rr_time xr_rr;
		struct ssrc_xr_dlrr xr_dlrr;
	} scratch;
	uint32_t scratch_common_ssrc;

	// RTCP syslog output
	GString *log;
	int log_init_len;

	// Homer stats
	GString *json;
	int json_init_len;

	// verdict
	unsigned int discard:1;
};
// all available methods
struct rtcp_handler {
	void (*init)(struct rtcp_process_ctx *);
	void (*start)(struct rtcp_process_ctx *, call_t *);
	void (*common)(struct rtcp_process_ctx *, struct rtcp_packet *);
	void (*sr)(struct rtcp_process_ctx *, struct sender_report_packet *);
	void (*rr_list_start)(struct rtcp_process_ctx *, const struct rtcp_packet *);
	void (*rr)(struct rtcp_process_ctx *, struct report_block *);
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
	void (*finish)(struct rtcp_process_ctx *, call_t *, const endpoint_t *, const endpoint_t *,
			const struct timeval *);
	void (*destroy)(struct rtcp_process_ctx *);
};
// collection of all handler types
struct rtcp_handlers {
	const struct rtcp_handler
		*scratch,
		*mos,
		*transcode,
		*logging,
		*homer;
};

// log handler function prototypes

// scratch area (prepare/parse packet)
static void scratch_common(struct rtcp_process_ctx *, struct rtcp_packet *);
static void scratch_sr(struct rtcp_process_ctx *, struct sender_report_packet *);
static void scratch_rr(struct rtcp_process_ctx *, struct report_block *);
static void scratch_xr_rr_time(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
static void scratch_xr_dlrr(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
static void scratch_xr_voip_metrics(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);

// MOS calculation / stats
static void mos_sr(struct rtcp_process_ctx *, struct sender_report_packet *);
static void mos_rr(struct rtcp_process_ctx *, struct report_block *);
static void mos_xr_rr_time(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
static void mos_xr_dlrr(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
static void mos_xr_voip_metrics(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);

// RTCP translation for transcoding
static void transcode_common(struct rtcp_process_ctx *, struct rtcp_packet *);
static void transcode_rr(struct rtcp_process_ctx *, struct report_block *);
static void transcode_sr(struct rtcp_process_ctx *, struct sender_report_packet *);

// wrappers to enable dynamic transcoding
static void transcode_common_wrap(struct rtcp_process_ctx *, struct rtcp_packet *);
static void transcode_rr_wrap(struct rtcp_process_ctx *, struct report_block *);
static void transcode_sr_wrap(struct rtcp_process_ctx *, struct sender_report_packet *);

// RTCP sinks for local RTCP generation
static void sink_common(struct rtcp_process_ctx *, struct rtcp_packet *);

// homer functions
static void homer_init(struct rtcp_process_ctx *);
static void homer_sr(struct rtcp_process_ctx *, struct sender_report_packet *);
static void homer_rr_list_start(struct rtcp_process_ctx *, const struct rtcp_packet *);
static void homer_rr(struct rtcp_process_ctx *, struct report_block *);
static void homer_rr_list_end(struct rtcp_process_ctx *);
static void homer_sdes_list_start(struct rtcp_process_ctx *, const struct source_description_packet *);
static void homer_sdes_item(struct rtcp_process_ctx *, const struct sdes_chunk *, const struct sdes_item *,
		const char *);
static void homer_sdes_list_end(struct rtcp_process_ctx *);
static void homer_finish(struct rtcp_process_ctx *, call_t *, const endpoint_t *, const endpoint_t *,
		const struct timeval *);

// syslog functions
static void logging_init(struct rtcp_process_ctx *);
static void logging_start(struct rtcp_process_ctx *, call_t *);
static void logging_common(struct rtcp_process_ctx *, struct rtcp_packet *);
static void logging_sdes_list_start(struct rtcp_process_ctx *, const struct source_description_packet *);
static void logging_sr(struct rtcp_process_ctx *, struct sender_report_packet *);
static void logging_rr(struct rtcp_process_ctx *, struct report_block *);
static void logging_xr_rb(struct rtcp_process_ctx *, const struct xr_report_block *);
static void logging_xr_rr_time(struct rtcp_process_ctx *, const struct xr_rb_rr_time *);
static void logging_xr_dlrr(struct rtcp_process_ctx *, const struct xr_rb_dlrr *);
static void logging_xr_stats(struct rtcp_process_ctx *, const struct xr_rb_stats *);
static void logging_xr_voip_metrics(struct rtcp_process_ctx *, const struct xr_rb_voip_metrics *);
static void logging_finish(struct rtcp_process_ctx *, call_t *, const endpoint_t *, const endpoint_t *,
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
static struct rtcp_handler transcode_handlers = {
	.common = transcode_common,
	.rr = transcode_rr,
	.sr = transcode_sr,
};
static struct rtcp_handler sink_handlers = {
	.common = sink_common,
};
static struct rtcp_handler transcode_handlers_wrap = {
	.common = transcode_common_wrap,
	.rr = transcode_rr_wrap,
	.sr = transcode_sr_wrap,
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
	.transcode = &transcode_handlers_wrap,
	// remainder is variable
};

// macro to call one handler
#define CH(func, type, ...) do { \
		if (rtcp_handlers.type->func) \
			rtcp_handlers.type->func(log_ctx, ##__VA_ARGS__); \
	} while (0)
// macro to call all function handlers in one go
// order is important
#define CAH(func, ...) do { \
		CH(func, scratch, ##__VA_ARGS__); /* first parse out the values into scratch area */ \
		CH(func, mos, ##__VA_ARGS__); /* process for MOS calculation */ \
		CH(func, logging, ##__VA_ARGS__); /* log packets to syslog */ \
		CH(func, homer, ##__VA_ARGS__); /* send contents to homer */ \
		CH(func, transcode, ##__VA_ARGS__); /* translate for transcoding */ \
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
	[RTCP_PT_XR]	= sizeof(struct xr_packet),
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




struct rtcp_handler *rtcp_transcode_handler = &transcode_handlers;
struct rtcp_handler *rtcp_sink_handler = &sink_handlers;






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
	el->buf = p;

	return el;
}

static int rtcp_generic(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	return 0;
}

static int rtcp_Xr(struct rtcp_chain_element *el) {
	if (el->len < el->rtcp_packet->header.count * sizeof(struct report_block))
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
	CAH(common, &el->sr->rtcp);
	CAH(sr, el->sr);
	rtcp_rr_list(&el->sr->rtcp, el->sr->reports, log_ctx);
	return 0;
}

static int rtcp_rr(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	if (rtcp_Xr(el))
		return -1;
	CAH(common, &el->rr->rtcp);
	rtcp_rr_list(&el->rr->rtcp, el->rr->reports, log_ctx);
	return 0;
}

static int rtcp_sdes(struct rtcp_chain_element *el, struct rtcp_process_ctx *log_ctx) {
	CAH(sdes_list_start, el->sdes);

	str comp_s = STR_LEN(el->sdes->chunks, el->len - sizeof(el->sdes->header));
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
		if (i >= el->sdes->header.count)
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
	CAH(common, el->rtcp_packet);
	str comp_s = STR_LEN(el->buf + sizeof(el->xr->rtcp), el->len - sizeof(el->xr->rtcp));
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
			ilogs(rtcp, LOG_WARN, "Short RTCP XR block (type %u, %u < %i)", rb->bt, len,
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
void rtcp_list_free(GQueue *q) {
	g_queue_clear_full(q, rtcp_ce_free);
}



// returns: 0 = ok, forward, -1 = error, drop, 1 = ok, but discard (no forward)
int rtcp_parse(GQueue *q, struct media_packet *mp) {
	struct rtcp_header *hdr;
	struct rtcp_chain_element *el;
	rtcp_handler_func func;
	str s = mp->raw;
	call_t *c = mp->call;
	struct rtcp_process_ctx log_ctx_s,
				*log_ctx;
	unsigned int len;
	int ret;
	int min_packet_size;

	ZERO(log_ctx_s);
	log_ctx_s.mp = mp;

	log_ctx = &log_ctx_s;

	CAH(init);
	CAH(start, c);

	while (1) {
		if (!(hdr = rtcp_length_check(&s, sizeof(*hdr), &len)))
			break;

		if (hdr->version != 2) {
			ilogs(rtcp, LOG_DEBUG, "Unknown RTCP version %u", hdr->version);
			goto error;
		}

		min_packet_size = 0;
		if (hdr->pt < G_N_ELEMENTS(min_packet_sizes))
			min_packet_size = min_packet_sizes[hdr->pt];
		if (len < min_packet_size) {
			ilogs(rtcp, LOG_WARN, "Invalid RTCP packet type %u (short: %u < %i)",
					hdr->pt, len, min_packet_size);
			goto error;
		}

		el = rtcp_new_element(hdr, len);

		if (hdr->pt >= G_N_ELEMENTS(handler_funcs)) {
			ilogs(rtcp, LOG_INFO, "Ignoring unknown RTCP packet type %u", hdr->pt);
			goto next;
		}
		func = handler_funcs[hdr->pt];
		if (!func) {
			ilogs(rtcp, LOG_INFO, "Ignoring unknown RTCP packet type %u", hdr->pt);
			goto next;
		}

		ilogs(rtcp, LOG_DEBUG, "Calling handler for RTCP packet type %u", hdr->pt);
		ret = func(el, log_ctx);
		if (ret) {
			ilogs(rtcp, LOG_WARN, "Failed to handle or parse RTCP packet type %u", hdr->pt);
			rtcp_ce_free(el);
			goto error;
		}

next:
		g_queue_push_tail(q, el);

		if (str_shift(&s, el->len))
			abort();
	}

	CAH(finish, c, &mp->fsin, &mp->sfd->socket.local, &mp->tv);
	CAH(destroy);

	return log_ctx->discard ? 1 : 0;

error:
	CAH(finish, c, &mp->fsin, &mp->sfd->socket.local, &mp->tv);
	CAH(destroy);
	rtcp_list_free(q);
	return -1;
}

int rtcp_avpf2avp_filter(struct media_packet *mp, GQueue *rtcp_list) {
	GList *l;
	struct rtcp_chain_element *el;
	void *start;
	unsigned int removed, left;

	left = mp->raw.len;
	removed = 0;
	for (l = rtcp_list->head; l; l = l->next) {
		el = l->data;
		left -= el->len;

		switch (el->type) {
			case RTCP_PT_RTPFB:
			case RTCP_PT_PSFB:
				start = el->buf;
				memmove(start - removed, start + el->len - removed, left);
				removed += el->len;
				break;

			default:
				break;
		}
	}

	mp->raw.len -= removed;
	if (!mp->raw.len)
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
	s = STR_LEN_ASSERT(c->session_key, c->params.crypto_suite->session_key_len);
	if (crypto_gen_session_key(c, &s, 0x03, SRTCP_R_LENGTH))
		goto error;
	s = STR_LEN_ASSERT(c->session_auth_key, c->params.crypto_suite->srtcp_auth_key_len);
	if (crypto_gen_session_key(c, &s, 0x04, SRTCP_R_LENGTH))
		goto error;
	s = STR_LEN_ASSERT(c->session_salt, c->params.crypto_suite->session_salt_len);
	if (crypto_gen_session_key(c, &s, 0x05, SRTCP_R_LENGTH))
		goto error;

	c->have_session_key = 1;
	crypto_init_session_key(c);

	return 0;

error:
	ilogs(rtcp, LOG_ERROR | LOG_FLAG_LIMIT, "%s", err);
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
	switch (rtcp->header.pt) {
		case RTCP_PT_SR:
		case RTCP_PT_RR:
		// RFC 5506
		case RTCP_PT_SDES:
		case RTCP_PT_BYE:
		case RTCP_PT_APP:
		// RFC 4585 + 5506
		case RTCP_PT_PSFB:
		case RTCP_PT_RTPFB:
		// RFC 3611 + 5506
		case RTCP_PT_XR:
			goto ok;
	}
	goto error;

ok:
	if (!p)
		goto done;

	*p = *s;
	str_shift(p, sizeof(*rtcp));

done:
	*out = rtcp;
	return 0;
error:
	ilogs(rtcp, LOG_DEBUG | LOG_FLAG_LIMIT, "Error parsing RTCP header: %s", err);
	return -1;
}

/* rfc 3711 section 3.4 */
int rtcp_avp2savp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtcp_packet *rtcp;
	unsigned int i;
	uint32_t *idx;
	str to_auth, payload;

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
	if (rtcp_payload(&rtcp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	i = atomic_get_na(&ssrc_ctx->stats->rtcp_seq);
	crypto_debug_init(1);
	crypto_debug_printf("RTCP SSRC %" PRIx32 ", idx %u, plain pl: ",
			rtcp->ssrc, i);
	crypto_debug_dump(&payload);

	int prev_len = payload.len;
	if (!c->params.session_params.unencrypted_srtcp && crypto_encrypt_rtcp(c, rtcp, &payload, i))
		return -1;
	s->len += payload.len - prev_len;

	crypto_debug_printf(", enc pl: ");
	crypto_debug_dump(&payload);

	idx = (void *) s->s + s->len;
	*idx = htonl((c->params.session_params.unencrypted_srtcp ? 0ULL : 0x80000000ULL) | i);
	s->len += sizeof(*idx);
	atomic_inc_na(&ssrc_ctx->stats->rtcp_seq);

	to_auth = *s;

	rtp_append_mki(s, c);

	if (c->params.crypto_suite->srtcp_auth_tag) {
		c->params.crypto_suite->hash_rtcp(c, s->s + s->len, &to_auth);
		crypto_debug_printf(", auth: ");
		crypto_debug_dump_raw(s->s + s->len, c->params.crypto_suite->srtcp_auth_tag);
		s->len += c->params.crypto_suite->srtcp_auth_tag;
	}

	crypto_debug_finish();

	return 1;
}


/* rfc 3711 section 3.4 */
int rtcp_savp2avp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtcp_packet *rtcp;
	str payload, to_auth, to_decrypt, auth_tag;
	uint32_t idx;
	char hmac[20];
	const char *err;

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
	if (rtcp_payload(&rtcp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	crypto_debug_init(1);

	if (srtp_payloads(&to_auth, &to_decrypt, &auth_tag, NULL,
			c->params.crypto_suite->srtcp_auth_tag, c->params.mki_len,
			s, &payload))
		return -1;

	crypto_debug_printf("RTCP SSRC %" PRIx32 ", enc pl: ",
			rtcp->ssrc);
	crypto_debug_dump(&to_decrypt);

	err = "short packet";
	if (to_decrypt.len < sizeof(idx))
		goto error;
	to_decrypt.len -= sizeof(idx);
	memcpy(&idx, to_decrypt.s + to_decrypt.len, sizeof(idx));
	idx = ntohl(idx);

	crypto_debug_printf(", idx %" PRIu32, idx);

	if (!auth_tag.len)
		goto decrypt;

	// authenticate
	assert(sizeof(hmac) >= auth_tag.len);
	c->params.crypto_suite->hash_rtcp(c, hmac, &to_auth);

	crypto_debug_printf(", rcv hmac: ");
	crypto_debug_dump(&auth_tag);
	crypto_debug_printf(", calc hmac: ");
	crypto_debug_dump_raw(hmac, auth_tag.len);

	err = "authentication failed";
	if (str_memcmp(&auth_tag, hmac))
		goto error;

decrypt:;
	int prev_len = to_decrypt.len;
	if ((idx & 0x80000000ULL)) {
		if (crypto_decrypt_rtcp(c, rtcp, &to_decrypt, idx & 0x7fffffffULL))
			return -1;

		crypto_debug_printf(", dec pl: ");
		crypto_debug_dump(&to_decrypt);
	}

	*s = to_auth;
	s->len -= sizeof(idx);
	s->len -= prev_len - to_decrypt.len;

	crypto_debug_finish();

	return 0;

error:
	ilogs(rtcp, LOG_WARNING | LOG_FLAG_LIMIT, "Discarded invalid SRTCP packet: %s", err);
	return -1;
}


static void str_sanitize(GString *s) {
	while (s->len > 0 && (s->str[s->len - 1] == ' ' || s->str[s->len - 1] == ','))
		g_string_truncate(s, s->len - 1);
}



static void scratch_common(struct rtcp_process_ctx *ctx, struct rtcp_packet *common) {
	ctx->scratch_common_ssrc = htonl(common->ssrc);
}
static void scratch_rr(struct rtcp_process_ctx *ctx, struct report_block *rr) {
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
static void scratch_sr(struct rtcp_process_ctx *ctx, struct sender_report_packet *sr) {
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
static void homer_sr(struct rtcp_process_ctx *ctx, struct sender_report_packet *sr) {
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
static void homer_rr(struct rtcp_process_ctx *ctx, struct report_block *rr) {
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
				if (data[i] < ' ' || data[i] > 126)
					g_string_append_c(ctx->json, '_');
				else
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
static void homer_finish(struct rtcp_process_ctx *ctx, call_t *c, const endpoint_t *src,
		const endpoint_t *dst, const struct timeval *tv)
{
	str_sanitize(ctx->json);
	g_string_append(ctx->json, " }");
	if (ctx->json->len > ctx->json_init_len + 2)
		homer_send(ctx->json, &c->callid, src, dst, tv, PROTO_RTCP_JSON);
	else
		g_string_free(ctx->json, TRUE);
	ctx->json = NULL;
}

static void logging_init(struct rtcp_process_ctx *ctx) {
	ctx->log = g_string_new(NULL);
}
static void logging_start(struct rtcp_process_ctx *ctx, call_t *c) {
	g_string_append_printf(ctx->log, "["STR_FORMAT"] ", STR_FMT(&c->callid));
	ctx->log_init_len = ctx->log->len;
}
static void logging_common(struct rtcp_process_ctx *ctx, struct rtcp_packet *common) {
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
static void logging_sr(struct rtcp_process_ctx *ctx, struct sender_report_packet *sr) {
	g_string_append_printf(ctx->log,"ntp_sec=%u, ntp_fractions=%u, rtp_ts=%u, sender_packets=%u, " \
			"sender_bytes=%u, ",
		ctx->scratch.sr.ntp_msw,
		ctx->scratch.sr.ntp_lsw,
		ctx->scratch.sr.timestamp,
		ctx->scratch.sr.packet_count,
		ctx->scratch.sr.octet_count);
}
static void logging_rr(struct rtcp_process_ctx *ctx, struct report_block *rr) {
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
static void logging_finish(struct rtcp_process_ctx *ctx, call_t *c, const endpoint_t *src,
		const endpoint_t *dst, const struct timeval *tv)
{
	str_sanitize(ctx->log);
	if (ctx->log->len > ctx->log_init_len)
		rtcplog(ctx->log->str);
}
static void logging_destroy(struct rtcp_process_ctx *ctx) {
	g_string_free(ctx->log, TRUE);
}




static void mos_sr(struct rtcp_process_ctx *ctx, struct sender_report_packet *sr) {
	ssrc_sender_report(ctx->mp->media, &ctx->scratch.sr, &ctx->mp->tv);
}
static void mos_rr(struct rtcp_process_ctx *ctx, struct report_block *rr) {
	ssrc_receiver_report(ctx->mp->media, ctx->mp->sfd, &ctx->scratch.rr, &ctx->mp->tv);
}
static void mos_xr_rr_time(struct rtcp_process_ctx *ctx, const struct xr_rb_rr_time *rr) {
	ssrc_receiver_rr_time(ctx->mp->media, &ctx->scratch.xr_rr, &ctx->mp->tv);
}
static void mos_xr_dlrr(struct rtcp_process_ctx *ctx, const struct xr_rb_dlrr *dlrr) {
	ssrc_receiver_dlrr(ctx->mp->media, &ctx->scratch.xr_dlrr, &ctx->mp->tv);
}
static void mos_xr_voip_metrics(struct rtcp_process_ctx *ctx, const struct xr_rb_voip_metrics *rb_voip_mtc) {
	ssrc_voip_metrics(ctx->mp->media, &ctx->scratch.xr_vm, &ctx->mp->tv);
}




static void transcode_common(struct rtcp_process_ctx *ctx, struct rtcp_packet *common) {
	if (!ctx->mp->ssrc_in)
		return;
	if (ctx->scratch_common_ssrc != ctx->mp->ssrc_in->parent->h.ssrc)
		return;
	// forward SSRC mapping
	common->ssrc = htonl(ctx->mp->ssrc_in->ssrc_map_out);
	ilogs(rtcp, LOG_DEBUG, "Substituting RTCP header SSRC from %s%x%s to %x",
		FMT_M(ctx->scratch_common_ssrc), ctx->mp->ssrc_in->ssrc_map_out);
}
static void transcode_rr(struct rtcp_process_ctx *ctx, struct report_block *rr) {
	if (!ctx->mp->ssrc_in)
		return;
	if (ctx->scratch.rr.from != ctx->mp->ssrc_in->parent->h.ssrc)
		return;
	if (!ctx->mp->media)
		return;

	// reverse SSRC mapping
	struct ssrc_ctx *map_ctx = get_ssrc_ctx(ctx->scratch.rr.ssrc, ctx->mp->media->monologue->ssrc_hash,
			SSRC_DIR_OUTPUT, ctx->mp->media->monologue);
	rr->ssrc = htonl(map_ctx->ssrc_map_out);

	if (!ctx->mp->media_out)
		return;

	// for reception stats
	struct ssrc_ctx *input_ctx = get_ssrc_ctx(map_ctx->ssrc_map_out,
			ctx->mp->media_out->monologue->ssrc_hash,
			SSRC_DIR_INPUT, NULL);
	if (!input_ctx)
		return;

	// substitute our own values
	
	unsigned int packets = atomic64_get(&input_ctx->stats->packets);

	// we might not be keeping track of stats for this SSRC (handler_func_passthrough_ssrc).
	// just leave the values in place.
	if (!packets)
		goto out;

	unsigned int lost = input_ctx->parent->packets_lost;
	unsigned int dupes = input_ctx->parent->duplicates;
	unsigned int tot_lost = lost - dupes; // can be negative/rollover

	ilogs(rtcp, LOG_DEBUG, "Substituting RTCP RR SSRC from %s%x%s to %x: %u packets, %u lost, %u duplicates",
		FMT_M(ctx->scratch.rr.ssrc), map_ctx->ssrc_map_out,
		packets, lost, dupes);

	if (G_UNLIKELY(tot_lost > 0xffffff))
		memset(rr->number_lost, 0xff, sizeof(rr->number_lost));
	else {
		rr->number_lost[0] = (tot_lost & 0xff0000) >> 16;
		rr->number_lost[1] = (tot_lost & 0x00ff00) >>  8;
		rr->number_lost[2] = (tot_lost & 0x0000ff) >>  0;
	}

	unsigned int exp_packets = packets + lost;

	if (dupes > lost || exp_packets == 0) // negative
		rr->fraction_lost = 0;
	else
		rr->fraction_lost = tot_lost * 256 / (packets + lost);

	rr->high_seq_received = htonl(atomic_get_na(&input_ctx->stats->ext_seq));
	// XXX jitter, last SR

out:
	if (input_ctx)
		obj_put(&input_ctx->parent->h);
	obj_put(&map_ctx->parent->h);
}
static void transcode_sr(struct rtcp_process_ctx *ctx, struct sender_report_packet *sr) {
	if (!ctx->mp->ssrc_in)
		return;
	if (ctx->scratch.sr.ssrc != ctx->mp->ssrc_in->parent->h.ssrc)
		return;
	if (!ctx->mp->ssrc_out)
		return;
	unsigned int packets = atomic64_get(&ctx->mp->ssrc_out->stats->packets);

	// we might not be keeping track of stats for this SSRC (handler_func_passthrough_ssrc).
	// just leave the values in place.
	if (!packets)
		return;

	// substitute our own values
	sr->octet_count = htonl(atomic64_get(&ctx->mp->ssrc_out->stats->bytes));
	sr->packet_count = htonl(packets);
	sr->timestamp = htonl(atomic_get_na(&ctx->mp->ssrc_out->stats->timestamp));
	// XXX NTP timestamp
}



static void transcode_common_wrap(struct rtcp_process_ctx *ctx, struct rtcp_packet *common) {
	if (!ctx->mp->media->rtcp_handler)
		return;
	if (ctx->mp->media->rtcp_handler->common)
		ctx->mp->media->rtcp_handler->common(ctx, common);
}
static void transcode_rr_wrap(struct rtcp_process_ctx *ctx, struct report_block *rr) {
	if (!ctx->mp->media->rtcp_handler)
		return;
	if (ctx->mp->media->rtcp_handler->rr)
		ctx->mp->media->rtcp_handler->rr(ctx, rr);
}
static void transcode_sr_wrap(struct rtcp_process_ctx *ctx, struct sender_report_packet *sr) {
	if (!ctx->mp->media->rtcp_handler)
		return;
	if (ctx->mp->media->rtcp_handler->sr)
		ctx->mp->media->rtcp_handler->sr(ctx, sr);
}




void rtcp_init(void) {
	rtcp_handlers.logging = _log_facility_rtcp ? &log_handlers : &dummy_handlers;
	rtcp_handlers.homer = has_homer() && !rtpe_config.homer_rtcp_off ? &homer_handlers : &dummy_handlers;
}



static GString *rtcp_sender_report(struct ssrc_sender_report *ssr,
		uint32_t ssrc, uint32_t ssrc_out, uint32_t ts, uint32_t packets, uint32_t octets, GQueue *rrs,
		GQueue *srrs)
{
	GString *ret = g_string_sized_new(128);
	g_string_set_size(ret, sizeof(struct sender_report_packet));
	struct sender_report_packet *sr = (void *) ret->str;

	*sr = (struct sender_report_packet) {
		.rtcp.header.version = 2,
		.rtcp.header.pt = RTCP_PT_SR,
		.rtcp.ssrc = htonl(ssrc),
		.ntp_msw = htonl(rtpe_now.tv_sec + 2208988800),
		.ntp_lsw = htonl((4294967295ULL * rtpe_now.tv_usec) / 1000000ULL),
		.timestamp = htonl(ts), // XXX calculate from rtpe_now instead
		.packet_count = htonl(packets),
		.octet_count = htonl(octets),
	};
	if (ssr) {
		*ssr = (struct ssrc_sender_report) {
			.ssrc = ssrc_out,
			.ntp_msw = rtpe_now.tv_sec + 2208988800,
			.ntp_lsw = (4294967295ULL * rtpe_now.tv_usec) / 1000000ULL,
			.timestamp = ts, // XXX calculate from rtpe_now instead
			.packet_count = packets,
			.octet_count = octets,
		};
	}

	// receiver reports
	int i = 0, n = 0;
	while (rrs->length) {
		struct ssrc_ctx *s = g_queue_pop_head(rrs);
		if (i < 30) {
			g_string_set_size(ret, ret->len + sizeof(struct report_block));
			struct report_block *rr = (void *) ret->str + ret->len - sizeof(struct report_block);

			// XXX unify with transcode_rr

			// last received SR?
			struct ssrc_entry_call *se = s->parent;
			long long tv_diff = 0;
			uint32_t ntp_middle_bits = 0;
			mutex_lock(&se->h.lock);
			if (se->sender_reports.length) {
				struct ssrc_time_item *si = se->sender_reports.tail->data;
				tv_diff = timeval_diff(&rtpe_now, &si->received);
				ntp_middle_bits = si->ntp_middle_bits;
			}
			uint32_t jitter = se->jitter;
			mutex_unlock(&se->h.lock);

			uint64_t lost = se->packets_lost;
			uint64_t tot = atomic64_get(&s->stats->packets);

			*rr = (struct report_block) {
				.ssrc = htonl(s->parent->h.ssrc),
				.fraction_lost = lost * 256 / (tot + lost),
				.number_lost[0] = (lost >> 16) & 0xff,
				.number_lost[1] = (lost >> 8) & 0xff,
				.number_lost[2] = lost & 0xff,
				.high_seq_received = htonl(atomic_get_na(&s->stats->ext_seq)),
				.lsr = htonl(ntp_middle_bits),
				.dlsr = htonl(tv_diff * 65536 / 1000000),
				.jitter = htonl(jitter >> 4),
			};

			if (srrs) {
				struct ssrc_receiver_report *srr = g_slice_alloc(sizeof(*srr));
				*srr = (struct ssrc_receiver_report) {
					.from = ssrc_out,
					.ssrc = s->parent->h.ssrc,
					.fraction_lost = lost * 256 / (tot + lost),
					.packets_lost = lost,
					.high_seq_received = atomic_get_na(&s->stats->ext_seq),
					.lsr = ntp_middle_bits,
					.dlsr = tv_diff * 65536 / 1000000,
					.jitter = jitter >> 4,
				};
				g_queue_push_tail(srrs, srr);
			}

			n++;
		}
		ssrc_ctx_put(&s);
		i++;
	}

	sr = (void *) ret->str; // reacquire ptr after g_string_set_size
	sr->rtcp.header.count = n;
	sr->rtcp.header.length = htons((ret->len >> 2) - 1);

	// sdes
	assert(rtpe_instance_id.len == 12);

	struct {
		struct source_description_packet sdes;
		struct sdes_chunk chunk;
		struct sdes_item cname;
		char str[12];
		char nul;
		char pad;
	} __attribute__ ((packed)) *sdes;

	assert(sizeof(*sdes) == 24);

	g_string_set_size(ret, ret->len + sizeof(*sdes));
	sdes = (void *) ret->str + ret->len - sizeof(*sdes);

	*sdes = (__typeof(*sdes)) {
		.sdes.header.version = 2,
		.sdes.header.pt = RTCP_PT_SDES,
		.sdes.header.count = 1,
		.sdes.header.length = htons((sizeof(*sdes) >> 2) - 1),
		.chunk.ssrc = htonl(ssrc),
		.cname.type = SDES_TYPE_CNAME,
		.cname.length = rtpe_instance_id.len,
		.nul = 0,
		.pad = 0,
	};
	memcpy(sdes->str, rtpe_instance_id.s, rtpe_instance_id.len);

	return ret;
}

void rtcp_receiver_reports(GQueue *out, struct ssrc_hash *hash, struct call_monologue *ml) {
	rwlock_lock_r(&hash->lock);
	for (GList *l = hash->q.head; l; l = l->next) {
		struct ssrc_entry_call *e = l->data;
		struct ssrc_ctx *i = &e->input_ctx;
		if (i->ref != ml)
			continue;
		if (!atomic64_get_na(&i->stats->packets))
			continue;

		ssrc_ctx_hold(i);
		g_queue_push_tail(out, i);
	}
	rwlock_unlock_r(&hash->lock);
}


// call must be locked in R
void rtcp_send_report(struct call_media *media, struct ssrc_ctx *ssrc_out) {
	// figure out where to send it
	struct packet_stream *ps = media->streams.head->data;
	// crypto context is held separately
	struct packet_stream *rtcp_ps = media->streams.head->next ? media->streams.head->next->data : ps;

	if (MEDIA_ISSET(media, RTCP_MUX))
		;
	else {
		if (PS_ISSET(rtcp_ps, RTCP))
			ps = rtcp_ps;
		else
			rtcp_ps = ps;
	}

	if (!ps->selected_sfd || !rtcp_ps->selected_sfd)
		return;
	if (ps->selected_sfd->socket.fd == -1 || ps->endpoint.address.family == NULL)
		return;

	log_info_stream_fd(ps->selected_sfd);

	GQueue rrs = G_QUEUE_INIT;
	rtcp_receiver_reports(&rrs, media->monologue->ssrc_hash, ps->media->monologue);

	ilogs(rtcp, LOG_DEBUG, "Generating and sending RTCP SR for %x and up to %i source(s)",
			ssrc_out->parent->h.ssrc, rrs.length);

	struct ssrc_sender_report ssr;
	GQueue srrs = G_QUEUE_INIT;

	GString *sr = rtcp_sender_report(&ssr, ssrc_out->parent->h.ssrc,
			ssrc_out->ssrc_map_out ? : ssrc_out->parent->h.ssrc,
			atomic_get_na(&ssrc_out->stats->timestamp),
			atomic64_get_na(&ssrc_out->stats->packets),
			atomic64_get(&ssrc_out->stats->bytes),
			&rrs, &srrs);

	// handle crypto

	str rtcp_packet = STR_GS(sr);

	const struct streamhandler *crypt_handler = determine_handler(&transport_protocols[PROTO_RTP_AVP],
			media, true);

	if (crypt_handler && crypt_handler->out->rtcp_crypt) {
		g_string_set_size(sr, sr->len + RTP_BUFFER_TAIL_ROOM);
		rtcp_packet = STR_LEN(sr->str, sr->len - RTP_BUFFER_TAIL_ROOM);
		crypt_handler->out->rtcp_crypt(&rtcp_packet, ps, ssrc_out);
	}

	socket_sendto(&ps->selected_sfd->socket, rtcp_packet.s, rtcp_packet.len, &ps->endpoint);
	g_string_free(sr, TRUE);

	sink_handler_q *sinks = ps->rtp_sinks.length ? &ps->rtp_sinks : &ps->rtcp_sinks;
	for (__auto_type l = sinks->head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		struct packet_stream *sink = sh->sink;
		struct call_media *other_media = sink->media;

		ssrc_sender_report(other_media, &ssr, &rtpe_now);
		for (GList *k = srrs.head; k; k = k->next) {
			struct ssrc_receiver_report *srr = k->data;
			ssrc_receiver_report(other_media, sink->selected_sfd, srr, &rtpe_now);
		}
	}
	while (srrs.length) {
		struct ssrc_receiver_report *srr = g_queue_pop_head(&srrs);
		g_slice_free1(sizeof(*srr), srr);
	}
}



static void sink_common(struct rtcp_process_ctx *ctx, struct rtcp_packet *common) {
	ctx->discard = 1;
}
