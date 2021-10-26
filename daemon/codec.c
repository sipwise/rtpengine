#include "codec.h"
#include <glib.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include "call.h"
#include "log.h"
#include "rtplib.h"
#include "codeclib.h"
#include "ssrc.h"
#include "rtcp.h"
#include "call_interfaces.h"
#include "dtmf.h"
#include "dtmflib.h"
#include "t38.h"
#include "media_player.h"
#include "timerthread.h"
#include "log_funcs.h"
#include "mqtt.h"




struct codec_timer {
	struct timerthread_obj tt_obj;
	struct timeval next;
	void (*func)(struct codec_timer *);
};
struct mqtt_timer {
	struct codec_timer ct;
	struct mqtt_timer **self;
	struct call *call;
	struct call_media *media;
};


static codec_handler_func handler_func_passthrough;
static struct timerthread codec_timers_thread;

static void rtp_payload_type_copy(struct rtp_payload_type *dst, const struct rtp_payload_type *src);
static void codec_store_add_raw_order(struct codec_store *cs, struct rtp_payload_type *pt);
static void __rtp_payload_type_add_name(GHashTable *, struct rtp_payload_type *pt);
static void codec_calc_lost(struct ssrc_ctx *ssrc, uint16_t seq);


static struct codec_handler codec_handler_stub = {
	.source_pt.payload_type = -1,
	.dest_pt.payload_type = -1,
	.func = handler_func_passthrough,
	.kernelize = 1,
	.passthrough = 1,
};



static void __ht_queue_del(GHashTable *ht, const void *key, const void *val) {
	GQueue *q = g_hash_table_lookup(ht, key);
	if (!q)
		return;
	g_queue_remove_all(q, val);
}

static GList *__codec_store_delete_link(GList *link, struct codec_store *cs) {
	struct rtp_payload_type *pt = link->data;

	g_hash_table_remove(cs->codecs, GINT_TO_POINTER(pt->payload_type));
	__ht_queue_del(cs->codec_names, &pt->encoding, GINT_TO_POINTER(pt->payload_type));
	__ht_queue_del(cs->codec_names, &pt->encoding_with_params, GINT_TO_POINTER(pt->payload_type));
	__ht_queue_del(cs->codec_names, &pt->encoding_with_full_params, GINT_TO_POINTER(pt->payload_type));

	GList *next = link->next;
	if (cs->supp_link == link)
		cs->supp_link = next;
	g_queue_delete_link(&cs->codec_prefs, link);
	payload_type_free(pt);
	return next;
}
#ifdef WITH_TRANSCODING


#include <spandsp/telephony.h>
#include <spandsp/super_tone_rx.h>
#include <spandsp/logging.h>
#include <spandsp/dtmf.h>
#include "resample.h"
#include "dtmf_rx_fillin.h"



struct codec_ssrc_handler;
struct transcode_packet;

struct dtx_buffer {
	struct codec_timer ct;
	mutex_t lock;
	struct codec_ssrc_handler *csh;
	int ptime; // ms per packet
	int tspp; // timestamp increment per packet
	unsigned int clockrate;
	struct call *call;
	GQueue packets;
	struct media_packet last_mp;
	unsigned long head_ts;
	uint32_t ssrc;
	time_t start;
};
struct dtx_packet {
	struct transcode_packet *packet;
	struct media_packet mp;
	struct codec_ssrc_handler *decoder_handler; // holds reference
	struct codec_ssrc_handler *input_handler; // holds reference
	int (*func)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
			struct transcode_packet *packet, struct media_packet *mp);
};

struct silence_event {
	uint64_t start;
	uint64_t end;
};

struct codec_ssrc_handler {
	struct ssrc_entry h; // must be first
	struct codec_handler *handler;
	decoder_t *decoder;
	encoder_t *encoder;
	format_t encoder_format;
	int bitrate;
	int ptime;
	int bytes_per_packet;
	unsigned long first_ts; // for output TS scaling
	unsigned long last_ts; // to detect input lag and handle lost packets
	struct timeval first_send;
	unsigned long first_send_ts;
	long output_skew;
	GString *sample_buffer;
	struct dtx_buffer *dtx_buffer;

	// DTMF DSP stuff
	dtmf_rx_state_t *dtmf_dsp;
	resample_t dtmf_resampler;
	format_t dtmf_format;
	uint64_t dtmf_ts, last_dtmf_event_ts;
	GQueue dtmf_events;
	struct dtmf_event dtmf_event;

	// silence detection
	GQueue silence_events;

	// DTMF audio suppression
	unsigned long dtmf_start_ts;
	// DTMF send delay
	unsigned long dtmf_first_duration;

	uint64_t skip_pts;

	unsigned int rtp_mark:1;
};
struct transcode_packet {
	seq_packet_t p; // must be first
	unsigned long ts;
	str *payload;
	struct codec_handler *handler;
	unsigned int marker:1,
	             bypass_seq:1;
	int (*func)(struct codec_ssrc_handler *, struct codec_ssrc_handler *, struct transcode_packet *,
			struct media_packet *);
	int (*dup_func)(struct codec_ssrc_handler *, struct codec_ssrc_handler *, struct transcode_packet *,
			struct media_packet *);
	struct rtp_header rtp;
};
struct codec_tracker {
	GHashTable *touched; // 8000, 16000, etc, for each audio codec that was touched (added, removed, etc)
	int all_touched;
};


struct rtcp_timer {
	struct codec_timer ct;
	struct call *call;
	struct call_media *media;
};



static codec_handler_func handler_func_passthrough_ssrc;
static codec_handler_func handler_func_transcode;
static codec_handler_func handler_func_playback;
static codec_handler_func handler_func_inject_dtmf;
static codec_handler_func handler_func_dtmf;
static codec_handler_func handler_func_t38;

static struct ssrc_entry *__ssrc_handler_transcode_new(void *p);
static struct ssrc_entry *__ssrc_handler_new(void *p);
static void __ssrc_handler_stop(void *p, void *dummy);
static void __free_ssrc_handler(void *);
INLINE struct codec_handler *codec_handler_lookup(GHashTable *ht, int pt, struct call_media *sink);

static void __transcode_packet_free(struct transcode_packet *);

static int packet_decode(struct codec_ssrc_handler *, struct codec_ssrc_handler *,
		struct transcode_packet *, struct media_packet *);
static int packet_encoded_rtp(encoder_t *enc, void *u1, void *u2);
static int packet_decoded_fifo(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);
static int packet_decoded_direct(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);

static void codec_touched(struct codec_store *cs, struct rtp_payload_type *pt);

static int __buffer_dtx(struct dtx_buffer *dtxb, struct codec_ssrc_handler *ch,
		struct codec_ssrc_handler *input_handler,
		struct transcode_packet *packet, struct media_packet *mp,
		int (*func)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
			struct transcode_packet *packet,
			struct media_packet *mp));
static void __dtx_shutdown(struct dtx_buffer *dtxb);
static struct codec_handler *__input_handler(struct codec_handler *h, struct media_packet *mp);


static struct codec_handler codec_handler_stub_ssrc = {
	.source_pt.payload_type = -1,
	.dest_pt.payload_type = -1,
	.func = handler_func_passthrough_ssrc,
	.kernelize = 1,
	.passthrough = 1,
};



static void __handler_shutdown(struct codec_handler *handler) {
	ssrc_hash_foreach(handler->ssrc_hash, __ssrc_handler_stop, NULL);
	free_ssrc_hash(&handler->ssrc_hash);

	if (handler->ssrc_handler)
		obj_put(&handler->ssrc_handler->h);
	handler->ssrc_handler = NULL;
	handler->kernelize = 0;
	handler->transcoder = 0;
	handler->output_handler = handler; // reset to default
	handler->dtmf_payload_type = -1;
	handler->cn_payload_type = -1;
	handler->pcm_dtmf_detect = 0;
	handler->passthrough = 0;

	codec_handler_free(&handler->dtmf_injector);

	if (handler->stats_entry) {
		g_atomic_int_add(&handler->stats_entry->num_transcoders, -1);
		handler->stats_entry = NULL;
		g_free(handler->stats_chain);
	}
}

static void __codec_handler_free(void *pp) {
	struct codec_handler *h = pp;
	__handler_shutdown(h);
	payload_type_clear(&h->source_pt);
	payload_type_clear(&h->dest_pt);
	g_slice_free1(sizeof(*h), h);
}
void codec_handler_free(struct codec_handler **handler) {
	if (!handler || !*handler)
		return;
	__codec_handler_free(*handler);
	*handler = NULL;
}

static struct codec_handler *__handler_new(const struct rtp_payload_type *pt, struct call_media *media,
		struct call_media *sink)
{
	struct codec_handler *handler = g_slice_alloc0(sizeof(*handler));
	handler->source_pt.payload_type = -1;
	if (pt)
		rtp_payload_type_copy(&handler->source_pt, pt);
	handler->dest_pt.payload_type = -1;
	handler->output_handler = handler; // default
	handler->dtmf_payload_type = -1;
	handler->cn_payload_type = -1;
	handler->packet_encoded = packet_encoded_rtp;
	handler->packet_decoded = packet_decoded_fifo;
	handler->media = media;
	handler->sink = sink;
	return handler;
}

static void __make_passthrough(struct codec_handler *handler, int dtmf_pt, int cn_pt) {
	__handler_shutdown(handler);
	ilogs(codec, LOG_DEBUG, "Using passthrough handler for " STR_FORMAT " with DTMF %i, CN %i",
			STR_FMT(&handler->source_pt.encoding_with_params), dtmf_pt, cn_pt);
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;
	else {
		handler->func = handler_func_passthrough;
		handler->kernelize = 1;
	}
	rtp_payload_type_copy(&handler->dest_pt, &handler->source_pt);
	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, handler);
	handler->dtmf_payload_type = dtmf_pt;
	handler->cn_payload_type = cn_pt;
	handler->passthrough = 1;
}
static void __make_passthrough_ssrc(struct codec_handler *handler) {
	int dtmf_pt = handler->dtmf_payload_type;
	int cn_pt = handler->cn_payload_type;

	__handler_shutdown(handler);
	ilogs(codec, LOG_DEBUG, "Using passthrough handler with new SSRC for " STR_FORMAT,
			STR_FMT(&handler->source_pt.encoding_with_params));
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;
	else {
		handler->func = handler_func_passthrough_ssrc;
		handler->kernelize = 1;
	}
	rtp_payload_type_copy(&handler->dest_pt, &handler->source_pt);
	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, handler);
	handler->dtmf_payload_type = dtmf_pt;
	handler->cn_payload_type = cn_pt;
	handler->passthrough = 1;
}

static void __reset_sequencer(void *p, void *dummy) {
	struct ssrc_entry_call *s = p;
	s->sequencer.seq = -1;
}
static void __make_transcoder(struct codec_handler *handler, struct rtp_payload_type *dest,
		GHashTable *output_transcoders, int dtmf_payload_type, int pcm_dtmf_detect,
		int cn_payload_type)
{
	assert(handler->source_pt.codec_def != NULL);

	assert(dest->codec_def != NULL);

	// don't reset handler if it already matches what we want
	if (!handler->transcoder)
		goto reset;
	if (rtp_payload_type_cmp(dest, &handler->dest_pt))
		goto reset;
	if (handler->func != handler_func_transcode)
		goto reset;
	if (handler->cn_payload_type != cn_payload_type)
		goto reset;
	if (handler->dtmf_payload_type != dtmf_payload_type)
		goto reset;

	ilogs(codec, LOG_DEBUG, "Leaving transcode context for " STR_FORMAT " (%i) -> " STR_FORMAT " (%i) intact",
			STR_FMT(&handler->source_pt.encoding_with_params),
			handler->source_pt.payload_type,
			STR_FMT(&dest->encoding_with_params),
			dest->payload_type);

	goto check_output;

reset:
	__handler_shutdown(handler);

	rtp_payload_type_copy(&handler->dest_pt, dest);
	handler->func = handler_func_transcode;
	handler->transcoder = 1;
	handler->dtmf_payload_type = dtmf_payload_type;
	handler->cn_payload_type = cn_payload_type;
	handler->pcm_dtmf_detect = pcm_dtmf_detect ? 1 : 0;

	// DTMF transcoder/scaler?
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;

	ilogs(codec, LOG_DEBUG, "Created transcode context for " STR_FORMAT " (%i) -> " STR_FORMAT
		" (%i) with DTMF output %i and CN output %i",
			STR_FMT(&handler->source_pt.encoding_with_params),
			handler->source_pt.payload_type,
			STR_FMT(&dest->encoding_with_params),
			dest->payload_type,
			dtmf_payload_type, cn_payload_type);

	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_transcode_new, handler);

	// stats entry
	handler->stats_chain = g_strdup_printf(STR_FORMAT " -> " STR_FORMAT,
				STR_FMT(&handler->source_pt.encoding_with_params),
				STR_FMT(&dest->encoding_with_params));

	mutex_lock(&rtpe_codec_stats_lock);
	struct codec_stats *stats_entry =
		g_hash_table_lookup(rtpe_codec_stats, handler->stats_chain);
	if (!stats_entry) {
		stats_entry = g_slice_alloc0(sizeof(*stats_entry));
		stats_entry->chain = strdup(handler->stats_chain);
		g_hash_table_insert(rtpe_codec_stats, stats_entry->chain, stats_entry);
		stats_entry->chain_brief = g_strdup_printf(STR_FORMAT "_" STR_FORMAT,
				STR_FMT(&handler->source_pt.encoding_with_params),
				STR_FMT(&dest->encoding_with_params));
	}
	handler->stats_entry = stats_entry;
	mutex_unlock(&rtpe_codec_stats_lock);

	g_atomic_int_inc(&stats_entry->num_transcoders);

	ssrc_hash_foreach(handler->media->monologue->ssrc_hash, __reset_sequencer, NULL);

check_output:;
	// check if we have multiple decoders transcoding to the same output PT
	struct codec_handler *output_handler = NULL;
	if (output_transcoders)
		output_handler = g_hash_table_lookup(output_transcoders,
				GINT_TO_POINTER(dest->payload_type));
	if (output_handler) {
		ilogs(codec, LOG_DEBUG, "Using existing encoder context");
		handler->output_handler = output_handler;
	}
	else {
		if (output_transcoders)
			g_hash_table_insert(output_transcoders, GINT_TO_POINTER(dest->payload_type), handler);
		handler->output_handler = handler; // make sure we don't have a stale pointer
	}
}

struct codec_handler *codec_handler_make_playback(const struct rtp_payload_type *src_pt,
		const struct rtp_payload_type *dst_pt, unsigned long last_ts, struct call_media *media)
{
	struct codec_handler *handler = __handler_new(src_pt, media, NULL);
	rtp_payload_type_copy(&handler->dest_pt, dst_pt);
	handler->func = handler_func_playback;
	handler->ssrc_handler = (void *) __ssrc_handler_transcode_new(handler);
	handler->ssrc_handler->first_ts = last_ts;
	while (handler->ssrc_handler->first_ts == 0)
		handler->ssrc_handler->first_ts = ssl_random();
	handler->ssrc_handler->rtp_mark = 1;

	ilogs(codec, LOG_DEBUG, "Created media playback context for " STR_FORMAT " -> " STR_FORMAT "",
			STR_FMT(&src_pt->encoding_with_params),
			STR_FMT(&dst_pt->encoding_with_params));

	return handler;
}

static void ensure_codec_def_type(struct rtp_payload_type *pt, enum media_type type) {
	if (pt->codec_def)
		return;

	pt->codec_def = codec_find(&pt->encoding, type);
	if (!pt->codec_def)
		return;
	if (!pt->codec_def->support_encoding || !pt->codec_def->support_decoding)
		pt->codec_def = NULL;
}
void ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media) {
	if (!media)
		return;
	ensure_codec_def_type(pt, media->type_id);
}

// only called from codec_handlers_update()
static void __make_passthrough_gsl(struct codec_handler *handler, GSList **handlers,
		struct rtp_payload_type *dtmf_pt, struct rtp_payload_type *cn_pt)
{
	__make_passthrough(handler, dtmf_pt ? dtmf_pt->payload_type : -1,
			cn_pt ? cn_pt->payload_type : -1);
	if (MEDIA_ISSET(handler->media, ECHO))
		__make_passthrough_ssrc(handler);
	*handlers = g_slist_prepend(*handlers, handler);
}


static void __track_supp_codec(GHashTable *supplemental_sinks, struct rtp_payload_type *pt) {
	if (!pt->codec_def || !pt->codec_def->supplemental)
		return;

	GHashTable *supp_sinks = g_hash_table_lookup(supplemental_sinks, pt->codec_def->rtpname);
	if (!supp_sinks)
		return;
	if (!g_hash_table_lookup(supp_sinks, GUINT_TO_POINTER(pt->clock_rate)))
		g_hash_table_insert(supp_sinks, GUINT_TO_POINTER(pt->clock_rate), pt);
}

static void __check_codec_list(GHashTable **supplemental_sinks, struct rtp_payload_type **pref_dest_codec,
		struct call_media *sink, GQueue *sink_list)
{
	// first initialise and populate the list of supp sinks
	GHashTable *ss = *supplemental_sinks = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);
	for (GList *l = codec_supplemental_codecs->head; l; l = l->next) {
		codec_def_t *def = l->data;
		g_hash_table_replace(ss, (void *) def->rtpname,
				g_hash_table_new(g_direct_hash, g_direct_equal));
	}

	struct rtp_payload_type *pdc = NULL;
	struct rtp_payload_type *first_tc_codec = NULL;

	for (GList *l = sink->codecs.codec_prefs.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		ensure_codec_def(pt, sink);
		if (!pt->codec_def) // not supported, next
			continue;

		// fix up ptime
		if (pt->ptime <= 0)
			pt->ptime = pt->codec_def->default_ptime;
		if (sink->ptime > 0)
			pt->ptime = sink->ptime;

		if (!pdc && !pt->codec_def->supplemental)
			pdc = pt;
		if (pt->accepted) {
			// codec is explicitly marked as accepted
			if (!first_tc_codec && !pt->codec_def->supplemental)
				first_tc_codec = pt;
		}

		__track_supp_codec(ss, pt);
	}

	if (first_tc_codec)
		pdc = first_tc_codec;
	if (pdc && pref_dest_codec) {
		*pref_dest_codec = pdc;
		ilogs(codec, LOG_DEBUG, "Default sink codec is " STR_FORMAT,
				STR_FMT(&(*pref_dest_codec)->encoding_with_params));
	}
}

static struct rtp_payload_type *__supp_payload_type(GHashTable *supplemental_sinks, int clockrate,
		const char *codec)
{
	GHashTable *supp_sinks = g_hash_table_lookup(supplemental_sinks, codec);
	if (!supp_sinks)
		return NULL;
	if (!g_hash_table_size(supp_sinks))
		return NULL;

	// find the codec entry with a matching clock rate
	struct rtp_payload_type *pt = g_hash_table_lookup(supp_sinks,
			GUINT_TO_POINTER(clockrate));
	return pt;
}

static int __unused_pt_number(struct call_media *media, struct call_media *other_media,
		struct codec_store *extra_cs,
		struct rtp_payload_type *pt)
{
	int num = pt ? pt->payload_type : -1;
	struct rtp_payload_type *pt_match;

	if (num < 0)
		num = 96; // default first dynamic payload type number
	while (1) {
		if ((pt_match = g_hash_table_lookup(media->codecs.codecs, GINT_TO_POINTER(num))))
			goto next;
		if (other_media) {
			if ((pt_match = g_hash_table_lookup(other_media->codecs.codecs,
							GINT_TO_POINTER(num))))
				goto next;
		}
		if (extra_cs) {
			if ((pt_match = g_hash_table_lookup(extra_cs->codecs,
							GINT_TO_POINTER(num))))
				goto next;
		}
		// OK
		break;

next:
		// is this actually the same?
		if (pt && !rtp_payload_type_cmp_nf(pt, pt_match))
			break;
		num++;
		if (num < 96) // if an RFC type was taken already
			num = 96;
		else if (num >= 128)
			return -1;
	}
	return num;
}

static void __check_dtmf_injector(struct call_media *receiver, struct call_media *sink,
		struct codec_handler *parent,
		GHashTable *output_transcoders)
{
	if (!sink->monologue->inject_dtmf)
		return;
	if (parent->dtmf_payload_type != -1)
		return;
	if (parent->dtmf_injector)
		return;
	if (parent->source_pt.codec_def->supplemental)
		return;

	// synthesise input rtp payload type
	struct rtp_payload_type src_pt = {
		.payload_type = -1,
		.clock_rate = parent->source_pt.clock_rate,
		.channels = parent->source_pt.channels,
	};
	str_init(&src_pt.encoding, "DTMF injector");
	str_init(&src_pt.encoding_with_params, "DTMF injector");
	str_init(&src_pt.encoding_with_full_params, "DTMF injector");
	static const str tp_event = STR_CONST_INIT("telephone-event");
	src_pt.codec_def = codec_find(&tp_event, MT_AUDIO);
	if (!src_pt.codec_def) {
		ilogs(codec, LOG_ERR, "RTP payload type 'telephone-event' is not defined");
		return;
	}

	parent->dtmf_injector = __handler_new(&src_pt, receiver, sink);
	__make_transcoder(parent->dtmf_injector, &parent->dest_pt, output_transcoders, -1, 0, -1);
	parent->dtmf_injector->func = handler_func_inject_dtmf;
}




static struct codec_handler *__get_pt_handler(struct call_media *receiver, struct rtp_payload_type *pt,
		struct call_media *sink)
{
	ensure_codec_def(pt, receiver);
	struct codec_handler *handler;
	handler = codec_handler_lookup(receiver->codec_handlers, pt->payload_type, sink);
	if (handler) {
		// make sure existing handler matches this PT
		if (rtp_payload_type_cmp(pt, &handler->source_pt)) {
			ilogs(codec, LOG_DEBUG, "Resetting codec handler for PT %i", pt->payload_type);
			g_hash_table_remove(receiver->codec_handlers, handler);
			__handler_shutdown(handler);
			handler = NULL;
			g_atomic_pointer_set(&receiver->codec_handler_cache, NULL);
		}
	}
	if (!handler) {
		ilogs(codec, LOG_DEBUG, "Creating codec handler for " STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				pt->payload_type);
		handler = __handler_new(pt, receiver, sink);
		g_hash_table_insert(receiver->codec_handlers, handler, handler);
		g_queue_push_tail(&receiver->codec_handlers_store, handler);
	}

	// figure out our ptime
	if (pt->ptime <= 0 && pt->codec_def)
		pt->ptime = pt->codec_def->default_ptime;
	if (receiver->ptime > 0)
		pt->ptime = receiver->ptime;

	return handler;
}




static void __check_t38_decoder(struct call_media *t38_media) {
	if (t38_media->t38_handler)
		return;
	ilogs(codec, LOG_DEBUG, "Creating T.38 packet handler");
	t38_media->t38_handler = __handler_new(NULL, t38_media, NULL);
	t38_media->t38_handler->func = handler_func_t38;
}

static int packet_encoded_t38(encoder_t *enc, void *u1, void *u2) {
	struct media_packet *mp = u2;

	if (!mp->media)
		return 0;

	return t38_gateway_input_samples(mp->media->t38_gateway,
			(int16_t *) enc->avpkt->data, enc->avpkt->size / 2);
}

static void __generator_stop(struct call_media *media) {
	if (media->t38_gateway) {
		t38_gateway_stop(media->t38_gateway);
		t38_gateway_put(&media->t38_gateway);
	}
}

static void __t38_options_from_flags(struct t38_options *t_opts, const struct sdp_ng_flags *flags) {
#define t38_opt(name) t_opts->name = flags ? flags->t38_ ## name : 0
	t38_opt(no_ecm);
	t38_opt(no_v17);
	t38_opt(no_v27ter);
	t38_opt(no_v29);
	t38_opt(no_v34);
	t38_opt(no_iaf);
}

static void __check_t38_gateway(struct call_media *pcm_media, struct call_media *t38_media,
		const struct stream_params *sp, const struct sdp_ng_flags *flags)
{
	struct t38_options t_opts = {0,};

	if (sp)
		t_opts = sp->t38_options;
	else {
		// create our own options
		if (flags && flags->t38_fec)
			t_opts.fec_span = 3;
		t_opts.max_ec_entries = 3;
	}
	__t38_options_from_flags(&t_opts, flags);

	MEDIA_SET(pcm_media, TRANSCODE);
	MEDIA_SET(pcm_media, GENERATOR);
	MEDIA_SET(t38_media, TRANSCODE);
	MEDIA_SET(t38_media, GENERATOR);

	if (t38_gateway_pair(t38_media, pcm_media, &t_opts))
		return;

	// need a packet handler on the T.38 side
	__check_t38_decoder(t38_media);


	// for each codec type supported by the pcm_media, we create a codec handler that
	// links to the T.38 encoder
	for (GList *l = pcm_media->codecs.codec_prefs.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		struct codec_handler *handler = __get_pt_handler(pcm_media, pt, t38_media);
		if (!pt->codec_def) {
			// should not happen
			ilogs(codec, LOG_WARN, "Unsupported codec " STR_FORMAT " for T.38 transcoding",
					STR_FMT(&pt->encoding_with_params));
			continue;
		}

		ilogs(codec, LOG_DEBUG, "Creating T.38 encoder for " STR_FORMAT, STR_FMT(&pt->encoding_with_params));

		__make_transcoder(handler, &pcm_media->t38_gateway->pcm_pt, NULL, -1, 0, -1);

		handler->packet_decoded = packet_decoded_direct;
		handler->packet_encoded = packet_encoded_t38;
	}
}

// call must be locked in W
static int codec_handler_udptl_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags)
{
	// anything to do?
	if (proto_is(sink->protocol, PROTO_UDPTL))
		return 0;

	if (sink->type_id == MT_AUDIO && proto_is_rtp(sink->protocol) && receiver->type_id == MT_IMAGE) {
		if (!str_cmp(&receiver->format_str, "t38")) {
			__check_t38_gateway(sink, receiver, NULL, flags);
			return 1;
		}
	}
	ilogs(codec, LOG_WARN, "Unsupported non-RTP protocol: " STR_FORMAT "/" STR_FORMAT
			" -> " STR_FORMAT "/" STR_FORMAT,
			STR_FMT(&receiver->type), STR_FMT(&receiver->format_str),
			STR_FMT(&sink->type), STR_FMT(&sink->format_str));
	return 0;
}

// call must be locked in W
// for transcoding RTP types to non-RTP
static int codec_handler_non_rtp_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, const struct stream_params *sp)
{
	if (proto_is(sink->protocol, PROTO_UDPTL) && !str_cmp(&sink->format_str, "t38")) {
		__check_t38_gateway(receiver, sink, sp, flags);
		return 1;
	}
	ilogs(codec, LOG_WARN, "Unsupported non-RTP protocol: " STR_FORMAT "/" STR_FORMAT
			" -> " STR_FORMAT "/" STR_FORMAT,
			STR_FMT(&receiver->type), STR_FMT(&receiver->format_str),
			STR_FMT(&sink->type), STR_FMT(&sink->format_str));
	return 0;
}


static void __rtcp_timer_free(void *p) {
	struct rtcp_timer *rt = p;
	if (rt->call)
		obj_put(rt->call);
}
static void __rtcp_timer_run(struct codec_timer *);
// master lock held in W
static void __codec_rtcp_timer_schedule(struct call_media *media) {
	struct rtcp_timer *rt = media->rtcp_timer;
	if (!rt) {
		media->rtcp_timer = rt = obj_alloc0("rtcp_timer", sizeof(*rt), __rtcp_timer_free);
		rt->ct.tt_obj.tt = &codec_timers_thread;
		rt->call = obj_get(media->call);
		rt->media = media;
		rt->ct.next = rtpe_now;
		rt->ct.func = __rtcp_timer_run;
	}

	timeval_add_usec(&rt->ct.next, 5000000 + (ssl_random() % 2000000));
	timerthread_obj_schedule_abs(&rt->ct.tt_obj, &rt->ct.next);
}
// no lock held
static void __rtcp_timer_run(struct codec_timer *ct) {
	struct rtcp_timer *rt = (void *) ct;

	// check scheduling
	rwlock_lock_w(&rt->call->master_lock);
	struct call_media *media = rt->media;

	log_info_call(rt->call);

	if (media->rtcp_timer != rt || !proto_is_rtp(media->protocol) || !MEDIA_ISSET(media, RTCP_GEN)) {
		if (media->rtcp_timer == rt)
			rtcp_timer_stop(&media->rtcp_timer);
		rwlock_unlock_w(&rt->call->master_lock);
		goto out;
	}
	timeval_add_usec(&ct->next, 5000000 + (ssl_random() % 2000000));
	__codec_rtcp_timer_schedule(media);

	// switch locks to be more graceful
	rwlock_unlock_w(&rt->call->master_lock);

	rwlock_lock_r(&rt->call->master_lock);

	// copy out references to SSRCs for lock-free handling
	struct ssrc_ctx *ssrc_out[RTPE_NUM_SSRC_TRACKING] = {NULL,};
	if (media->streams.head) {
		struct packet_stream *ps = media->streams.head->data;
		mutex_lock(&ps->out_lock);
		for (unsigned int u = 0; u < RTPE_NUM_SSRC_TRACKING; u++) {
			if (!ps->ssrc_out[u]) // end of list
				break;
			ssrc_out[u] = ps->ssrc_out[u];
			ssrc_ctx_hold(ssrc_out[u]);
		}
		mutex_unlock(&ps->out_lock);
	}

	for (unsigned int u = 0; u < RTPE_NUM_SSRC_TRACKING; u++) {
		if (!ssrc_out[u]) // end of list
			break;
		rtcp_send_report(media, ssrc_out[u]);
	}

	rwlock_unlock_r(&rt->call->master_lock);

	for (unsigned int u = 0; u < RTPE_NUM_SSRC_TRACKING; u++) {
		if (!ssrc_out[u]) // end of list
			break;
		ssrc_ctx_put(&ssrc_out[u]);
	}

out:
	log_info_clear();
}
// master lock held in W
static void __codec_rtcp_timer(struct call_media *receiver) {
	if (receiver->rtcp_timer) // already scheduled
		return;
	__codec_rtcp_timer_schedule(receiver);
	// XXX unify with media player into a generic RTCP player
}

static unsigned int __codec_handler_hash(const void *p) {
	const struct codec_handler *h = p;
	return h->source_pt.payload_type ^ GPOINTER_TO_UINT(h->sink);
}
static int __codec_handler_eq(const void *a, const void *b) {
	const struct codec_handler *h = a, *j = b;
	return h->source_pt.payload_type == j->source_pt.payload_type
		&& h->sink == j->sink;
}
INLINE struct codec_handler __codec_handler_lookup_struct(int pt, struct call_media *sink) {
	struct codec_handler lookup = {
		.source_pt = {
			.payload_type = pt,
		},
		.sink = sink,
	};
	return lookup;
}
INLINE struct codec_handler *codec_handler_lookup(GHashTable *ht, int pt, struct call_media *sink) {
	struct codec_handler lookup = __codec_handler_lookup_struct(pt, sink);
	return g_hash_table_lookup(ht, &lookup);
}

// call must be locked in W
void codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, const struct stream_params *sp)
{
	ilogs(codec, LOG_DEBUG, "Setting up codec handlers for " STR_FORMAT_M " #%u -> " STR_FORMAT_M " #%u",
			STR_FMT_M(&receiver->monologue->tag), receiver->index,
			STR_FMT_M(&sink->monologue->tag), sink->index);

	MEDIA_CLEAR(receiver, GENERATOR);
	MEDIA_CLEAR(sink, GENERATOR);

	// non-RTP protocol?
	if (proto_is(receiver->protocol, PROTO_UDPTL)) {
		if (codec_handler_udptl_update(receiver, sink, flags))
			return;
	}
	// everything else is unsupported: pass through
	if (proto_is_not_rtp(receiver->protocol)) {
		__generator_stop(receiver);
		__generator_stop(sink);
		return;
	}

	if (!receiver->codec_handlers)
		receiver->codec_handlers = g_hash_table_new(__codec_handler_hash, __codec_handler_eq);

	// should we transcode to a non-RTP protocol?
	if (proto_is_not_rtp(sink->protocol)) {
		if (codec_handler_non_rtp_update(receiver, sink, flags, sp))
			return;
	}

	// we're doing some kind of media passthrough - shut down local generators
	__generator_stop(receiver);
	__generator_stop(sink);

	MEDIA_CLEAR(receiver, TRANSCODE);
	receiver->rtcp_handler = NULL;
	GSList *passthrough_handlers = NULL;

	// first gather info about what we can send
	AUTO_CLEANUP_NULL(GHashTable *supplemental_sinks, __g_hash_table_destroy);
	struct rtp_payload_type *pref_dest_codec = NULL;
	__check_codec_list(&supplemental_sinks, &pref_dest_codec, sink, &sink->codecs.codec_prefs);

	// then do the same with what we can receive
	AUTO_CLEANUP_NULL(GHashTable *supplemental_recvs, __g_hash_table_destroy);
	__check_codec_list(&supplemental_recvs, NULL, receiver, &receiver->codecs.codec_prefs);

	// if multiple input codecs transcode to the same output codec, we want to make sure
	// that all the decoders output their media to the same encoder. we use the destination
	// payload type to keep track of this.
	AUTO_CLEANUP(GHashTable *output_transcoders, __g_hash_table_destroy)
		= g_hash_table_new(g_direct_hash, g_direct_equal);


	for (GList *l = receiver->codecs.codec_prefs.head; l; ) {
		struct rtp_payload_type *pt = l->data;
		struct rtp_payload_type *sink_pt = NULL;

		ilogs(codec, LOG_DEBUG, "Checking receiver codec " STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_full_params), pt->payload_type);

		struct codec_handler *handler = __get_pt_handler(receiver, pt, sink);

		// check our own support for this codec
		if (!pt->codec_def) {
			// not supported
			ilogs(codec, LOG_DEBUG, "No codec support for " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			__make_passthrough_gsl(handler, &passthrough_handlers, NULL, NULL);
			goto next;
		}

		// fill matching supp codecs
		struct rtp_payload_type *recv_dtmf_pt = __supp_payload_type(supplemental_recvs, pt->clock_rate,
				"telephone-event");
		struct rtp_payload_type *recv_cn_pt = __supp_payload_type(supplemental_recvs, pt->clock_rate,
				"CN");
		int pcm_dtmf_detect = 0;

		// find the matching sink codec

		if (!sink_pt) {
			// can we send the same codec that we want to receive?
			sink_pt = g_hash_table_lookup(sink->codecs.codecs,
					GINT_TO_POINTER(pt->payload_type));
			// is it actually the same?
			if (sink_pt && rtp_payload_type_cmp(pt, sink_pt))
				sink_pt = NULL;
		}

		if (!sink_pt) {
			// no matching/identical output codec. maybe we have the same output codec,
			// but with a different payload type or a different format?
			GQueue *dest_codecs = g_hash_table_lookup(sink->codecs.codec_names, &pt->encoding);
			if (dest_codecs) {
				// the sink supports this codec - check offered formats
				for (GList *k = dest_codecs->head; k; k = k->next) {
					unsigned int dest_ptype = GPOINTER_TO_UINT(k->data);
					sink_pt = g_hash_table_lookup(sink->codecs.codecs,
							GINT_TO_POINTER(dest_ptype));
					if (!sink_pt)
						continue;
					if (sink_pt->clock_rate != pt->clock_rate ||
							sink_pt->channels != pt->channels) {
						sink_pt = NULL;
						continue;
					}
					break;
				}
			}
		}

		if (sink_pt && !pt->codec_def->supplemental) {
			// we have a matching output codec. do we actually want to use it, or
			// do we want to transcode to something else?
			// ignore the preference here - for now, all `for_transcoding` codecs
			// take preference
			if (pref_dest_codec && pref_dest_codec->for_transcoding)
				sink_pt = pref_dest_codec;
		}

		// still no output? pick the preferred sink codec
		if (!sink_pt)
			sink_pt = pref_dest_codec;

		if (!sink_pt) {
			ilogs(codec, LOG_DEBUG, "No suitable output codec for " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			__make_passthrough_gsl(handler, &passthrough_handlers, recv_dtmf_pt, recv_cn_pt);
			goto next;
		}

		// sink_pt has been determined here now.

		ilogs(codec, LOG_DEBUG, "Sink codec is " STR_FORMAT " (%i)",
				STR_FMT(&sink_pt->encoding_with_full_params), sink_pt->payload_type);

		// we have found a usable output codec. gather matching output supp codecs
		struct rtp_payload_type *sink_dtmf_pt = __supp_payload_type(supplemental_sinks,
				sink_pt->clock_rate, "telephone-event");
		struct rtp_payload_type *sink_cn_pt = __supp_payload_type(supplemental_sinks,
				sink_pt->clock_rate, "CN");

		// XXX synthesise missing supp codecs according to codec tracker XXX needed?

		if (!flags) {
			// second pass going through the offerer codecs during an answer:
			// if an answer rejected a supplemental codec that isn't marked for transcoding,
			// reject it on the sink side as well
			if (sink_dtmf_pt && !recv_dtmf_pt && !sink_dtmf_pt->for_transcoding)
				sink_dtmf_pt = NULL;
			if (sink_cn_pt && !recv_cn_pt && !sink_cn_pt->for_transcoding)
				sink_cn_pt = NULL;
		}
		else {
			if (flags->inject_dtmf) 
				sink->monologue->inject_dtmf = 1;
		}

		// do we need DTMF detection?
		if (!pt->codec_def->supplemental && !recv_dtmf_pt && sink_dtmf_pt
				&& sink_dtmf_pt->for_transcoding)
		{
			pcm_dtmf_detect = 1;
			ilogs(codec, LOG_DEBUG, "Enabling PCM DTMF detection from " STR_FORMAT
					" to " STR_FORMAT
					"/" STR_FORMAT,
					STR_FMT(&pt->encoding_with_params),
					STR_FMT(&sink_pt->encoding_with_params),
					STR_FMT(&sink_dtmf_pt->encoding_with_params));
		}

		// we can now decide whether we can do passthrough, or transcode

		// different codecs?
		// XXX needs more intelligent fmtp matching
		if (rtp_payload_type_cmp_nf(pt, sink_pt))
			goto transcode;

		// different ptime?
		if (sink_pt->ptime && pt->ptime && sink_pt->ptime != pt->ptime) {
			if (MEDIA_ISSET(sink, PTIME_OVERRIDE) || MEDIA_ISSET(receiver, PTIME_OVERRIDE)) {
				ilogs(codec, LOG_DEBUG, "Mismatched ptime between source and sink (%i <> %i), "
						"enabling transcoding",
					sink_pt->ptime, pt->ptime);
				goto transcode;
			}
			ilogs(codec, LOG_DEBUG, "Mismatched ptime between source and sink (%i <> %i), "
					"but no override requested",
				sink_pt->ptime, pt->ptime);
		}

		if (sink->monologue->inject_dtmf) {
			// we have a matching output codec, but we were told that we might
			// want to inject DTMF, so we must still go through our transcoding
			// engine, despite input and output codecs being the same.
			goto transcode;
		}

		// compare supplemental codecs
		// DTMF
		if (pcm_dtmf_detect)
			goto transcode;
		if (recv_dtmf_pt && recv_dtmf_pt->for_transcoding && !sink_dtmf_pt) {
			ilogs(codec, LOG_DEBUG, "Transcoding DTMF events to PCM from " STR_FORMAT
					" to " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params),
					STR_FMT(&sink_pt->encoding_with_params));
			goto transcode;
		}
		// CN
		if (!recv_cn_pt && sink_cn_pt && sink_cn_pt->for_transcoding) {
			ilogs(codec, LOG_DEBUG, "Enabling CN silence detection from " STR_FORMAT
					" to " STR_FORMAT
					"/" STR_FORMAT,
					STR_FMT(&pt->encoding_with_params),
					STR_FMT(&sink_pt->encoding_with_params),
					STR_FMT(&sink_cn_pt->encoding_with_params));
			goto transcode;
		}
		if (recv_cn_pt && recv_cn_pt->for_transcoding && !sink_cn_pt) {
			ilogs(codec, LOG_DEBUG, "Transcoding CN packets to PCM from " STR_FORMAT
					" to " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params),
					STR_FMT(&sink_pt->encoding_with_params));
			goto transcode;
		}

		// everything matches - we can do passthrough
		ilogs(codec, LOG_DEBUG, "Sink supports codec " STR_FORMAT " for passthrough",
				STR_FMT(&pt->encoding_with_params));
		__make_passthrough_gsl(handler, &passthrough_handlers, sink_dtmf_pt, sink_cn_pt);
		goto next;

transcode:;
		// look up the reverse side of this payload type, which is the decoder to our
		// encoder. if any codec options such as bitrate were set during an offer,
		// they're in the decoder PT. copy them to the encoder PT.
		struct rtp_payload_type *reverse_pt = g_hash_table_lookup(sink->codecs.codecs,
				GINT_TO_POINTER(sink_pt->payload_type));
		if (reverse_pt) {
			if (!sink_pt->bitrate)
				sink_pt->bitrate = reverse_pt->bitrate;
			if (!sink_pt->codec_opts.len) {
				str_free_dup(&sink_pt->codec_opts);
				str_init_dup_str(&sink_pt->codec_opts, &reverse_pt->codec_opts);
			}
		}
		MEDIA_SET(receiver, TRANSCODE);
		__make_transcoder(handler, sink_pt, output_transcoders,
				sink_dtmf_pt ? sink_dtmf_pt->payload_type : -1,
				pcm_dtmf_detect, sink_cn_pt ? sink_cn_pt->payload_type : -1);
		__check_dtmf_injector(receiver, sink, handler, output_transcoders);

next:
		l = l->next;
	}

	if (MEDIA_ISSET(receiver, TRANSCODE)) {
		// we have to translate RTCP packets
		receiver->rtcp_handler = rtcp_transcode_handler;

		for (GList *l = receiver->codecs.codec_prefs.head; l; ) {
			struct rtp_payload_type *pt = l->data;

			if (pt->codec_def) {
				// supported
				l = l->next;
				continue;
			}

			ilogs(codec, LOG_DEBUG, "Stripping unsupported codec " STR_FORMAT
					" due to active transcoding",
					STR_FMT(&pt->encoding));
			codec_touched(&receiver->codecs, pt);
			l = __codec_store_delete_link(l, &receiver->codecs);
		}


		// at least some payload types will be transcoded, which will result in SSRC
		// change. for payload types which we don't actually transcode, we still
		// must substitute the SSRC
		while (passthrough_handlers) {
			struct codec_handler *handler = passthrough_handlers->data;
			__make_passthrough_ssrc(handler);
			passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);

		}
	}
	while (passthrough_handlers)
		passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);

	if (MEDIA_ISSET(receiver, RTCP_GEN)) {
		receiver->rtcp_handler = rtcp_sink_handler;
		__codec_rtcp_timer(receiver);
	}
	if (MEDIA_ISSET(sink, RTCP_GEN)) {
		sink->rtcp_handler = rtcp_sink_handler;
		__codec_rtcp_timer(sink);
	}
}


static struct codec_handler *codec_handler_get_rtp(struct call_media *m, int payload_type,
		struct call_media *sink)
{
	struct codec_handler *h;

	if (payload_type < 0)
		return NULL;

	struct codec_handler lookup = __codec_handler_lookup_struct(payload_type, sink);
	h = g_atomic_pointer_get(&m->codec_handler_cache);
	if (G_LIKELY(G_LIKELY(h) && G_LIKELY(__codec_handler_eq(&lookup, h))))
		return h;

	if (G_UNLIKELY(!m->codec_handlers))
		return NULL;
	h = g_hash_table_lookup(m->codec_handlers, &lookup);
	if (!h)
		return NULL;

	g_atomic_pointer_set(&m->codec_handler_cache, h);

	return h;
}
static struct codec_handler *codec_handler_get_udptl(struct call_media *m) {
	if (m->t38_handler)
		return m->t38_handler;
	return NULL;
}

#endif

static void __mqtt_timer_free(void *p) {
	struct mqtt_timer *mqt = p;
	if (mqt->call)
		obj_put(mqt->call);
}
static void __codec_mqtt_timer_schedule(struct mqtt_timer *mqt);
static void __mqtt_timer_run(struct codec_timer *ct) {
	struct mqtt_timer *mqt = (struct mqtt_timer *) ct;
	struct call *call = mqt->call;

	if (call)
		rwlock_lock_w(&call->master_lock);

	if (!*mqt->self) {
		if (call)
			rwlock_unlock_w(&call->master_lock);
		goto out;
	}

	__codec_mqtt_timer_schedule(mqt);

	if (call)
		rwlock_unlock_w(&call->master_lock);

	mqtt_timer_run(call, mqt->media);

out:
	log_info_clear();
}
static void __codec_mqtt_timer_schedule(struct mqtt_timer *mqt) {
	timeval_add_usec(&mqt->ct.next, rtpe_config.mqtt_publish_interval * 1000);
	timerthread_obj_schedule_abs(&mqt->ct.tt_obj, &mqt->ct.next);
}
// master lock held in W
void mqtt_timer_start(struct mqtt_timer **mqtp, struct call *call, struct call_media *media) {
	if (*mqtp) // already scheduled
		return;

	struct mqtt_timer *mqt = *mqtp = obj_alloc0("mqtt_timer", sizeof(*mqt), __mqtt_timer_free);
	mqt->ct.tt_obj.tt = &codec_timers_thread;
	mqt->call = call ? obj_get(call) : NULL;
	mqt->self = mqtp;
	mqt->media = media;
	mqt->ct.next = rtpe_now;
	mqt->ct.func = __mqtt_timer_run;

	__codec_mqtt_timer_schedule(mqt);
}


// master lock held in W
static void codec_timer_stop(struct codec_timer **ctp) {
	if (!ctp || !*ctp)
		return;
	obj_put(&(*ctp)->tt_obj);
	*ctp = NULL;
}
// master lock held in W
void rtcp_timer_stop(struct rtcp_timer **rtp) {
	codec_timer_stop((struct codec_timer **) rtp);
}
void mqtt_timer_stop(struct mqtt_timer **mqtp) {
	codec_timer_stop((struct codec_timer **) mqtp);
}




// call must be locked in R
struct codec_handler *codec_handler_get(struct call_media *m, int payload_type, struct call_media *sink) {
#ifdef WITH_TRANSCODING
	struct codec_handler *ret = NULL;

	if (!m->protocol)
		goto out;

	if (m->protocol->rtp)
		ret = codec_handler_get_rtp(m, payload_type, sink);
	else if (m->protocol->index == PROTO_UDPTL)
		ret = codec_handler_get_udptl(m);

out:
	if (ret)
		return ret;
	if (MEDIA_ISSET(m, TRANSCODE))
		return &codec_handler_stub_ssrc;
#endif
	return &codec_handler_stub;
}

void codec_handlers_free(struct call_media *m) {
	if (m->codec_handlers)
		g_hash_table_destroy(m->codec_handlers);
	m->codec_handlers = NULL;
	m->codec_handler_cache = NULL;
#ifdef WITH_TRANSCODING
	g_queue_clear_full(&m->codec_handlers_store, __codec_handler_free);
#endif
}


void codec_add_raw_packet(struct media_packet *mp, unsigned int clockrate) {
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s = mp->raw;
	p->free_func = NULL;
	p->clockrate = clockrate;
	if (mp->rtp && mp->ssrc_out) {
		ssrc_ctx_hold(mp->ssrc_out);
		p->ssrc_out = mp->ssrc_out;
		p->rtp = mp->rtp;
	}
	g_queue_push_tail(&mp->packets_out, p);
}
static bool handler_silence_block(struct codec_handler *h, struct media_packet *mp) {
	if (mp->call->block_media || mp->media->monologue->block_media)
		return false;
	if (mp->call->silence_media || mp->media->monologue->silence_media) {
		if (h->source_pt.codec_def && h->source_pt.codec_def->silence_pattern.len) {
			if (h->source_pt.codec_def->silence_pattern.len == 1)
				memset(mp->payload.s, h->source_pt.codec_def->silence_pattern.s[0],
						mp->payload.len);
			else {
				for (size_t pos = 0; pos < mp->payload.len;
						pos += h->source_pt.codec_def->silence_pattern.len)
					memcpy(&mp->payload.s[pos], h->source_pt.codec_def->silence_pattern.s,
							h->source_pt.codec_def->silence_pattern.len);
			}
		}
	}
	return true;
}
static int handler_func_passthrough(struct codec_handler *h, struct media_packet *mp) {
	if (!handler_silence_block(h, mp))
		return 0;

	if (mp->rtp) {
		codec_calc_jitter(mp->ssrc_in, ntohl(mp->rtp->timestamp), h->source_pt.clock_rate, &mp->tv);
		codec_calc_lost(mp->ssrc_in, ntohs(mp->rtp->seq_num));
	}
	codec_add_raw_packet(mp, h->source_pt.clock_rate);
	return 0;
}

#ifdef WITH_TRANSCODING
static void __ssrc_lock_both(struct media_packet *mp) {
	struct ssrc_ctx *ssrc_in = mp->ssrc_in;
	struct ssrc_entry_call *ssrc_in_p = ssrc_in->parent;
	struct ssrc_ctx *ssrc_out = mp->ssrc_out;
	struct ssrc_entry_call *ssrc_out_p = ssrc_out->parent;

	// we need a nested lock here - both input and output SSRC needs to be locked.
	// we don't know the lock order, so try both, and keep trying until we succeed.
	while (1) {
		mutex_lock(&ssrc_in_p->h.lock);
		if (ssrc_in_p == ssrc_out_p)
			break;
		if (!mutex_trylock(&ssrc_out_p->h.lock))
			break;
		mutex_unlock(&ssrc_in_p->h.lock);

		mutex_lock(&ssrc_out_p->h.lock);
		if (!mutex_trylock(&ssrc_in_p->h.lock))
			break;
		mutex_unlock(&ssrc_out_p->h.lock);
	}
}
static void __ssrc_unlock_both(struct media_packet *mp) {
	struct ssrc_ctx *ssrc_in = mp->ssrc_in;
	struct ssrc_entry_call *ssrc_in_p = ssrc_in->parent;
	struct ssrc_ctx *ssrc_out = mp->ssrc_out;
	struct ssrc_entry_call *ssrc_out_p = ssrc_out->parent;

	mutex_unlock(&ssrc_in_p->h.lock);
	if (ssrc_in_p != ssrc_out_p)
		mutex_unlock(&ssrc_out_p->h.lock);
}

static int __handler_func_sequencer(struct media_packet *mp, struct transcode_packet *packet)
{
	struct codec_handler *h = packet->handler;

	if (G_UNLIKELY(!h->ssrc_hash)) {
		if (!packet->func || !h->input_handler->ssrc_hash) {
			h->func(h, mp);
			__transcode_packet_free(packet);
			return 0;
		}
	}

	struct ssrc_ctx *ssrc_in = mp->ssrc_in;
	struct ssrc_entry_call *ssrc_in_p = ssrc_in->parent;
	struct ssrc_ctx *ssrc_out = mp->ssrc_out;
	struct ssrc_entry_call *ssrc_out_p = ssrc_out->parent;

	struct codec_ssrc_handler *ch = get_ssrc(ssrc_in_p->h.ssrc, h->ssrc_hash);
	if (G_UNLIKELY(!ch)) {
		__transcode_packet_free(packet);
		return 0;
	}

	packet->p.seq = ntohs(mp->rtp->seq_num);
	packet->payload = str_dup(&mp->payload);
	uint32_t packet_ts = ntohl(mp->rtp->timestamp);
	packet->ts = packet_ts;
	packet->marker = (mp->rtp->m_pt & 0x80) ? 1 : 0;

	atomic64_inc(&ssrc_in->packets);
	atomic64_add(&ssrc_in->octets, mp->payload.len);

	if (packet->bypass_seq) {
		// bypass sequencer
		__ssrc_lock_both(mp);
		int ret = packet->func(ch, ch, packet, mp);
		if (ret != 1)
			__transcode_packet_free(packet);
		__ssrc_unlock_both(mp);
		goto out_ch;
	}

	struct codec_ssrc_handler *input_ch = get_ssrc(ssrc_in_p->h.ssrc, h->input_handler->ssrc_hash);
	if (G_UNLIKELY(!input_ch)) {
		__transcode_packet_free(packet);
		goto out_ch;
	}

	__ssrc_lock_both(mp);

	packet_sequencer_init(&ssrc_in_p->sequencer, (GDestroyNotify) __transcode_packet_free);

	uint16_t seq_ori = ssrc_in_p->sequencer.seq;
	int seq_ret = packet_sequencer_insert(&ssrc_in_p->sequencer, &packet->p);
	if (seq_ret < 0) {
		// dupe
		if (packet->dup_func)
			packet->dup_func(ch, input_ch, packet, mp);
		else
			ilogs(transcoding, LOG_DEBUG, "Ignoring duplicate RTP packet");
		__transcode_packet_free(packet);
		ssrc_in_p->duplicates++;
		goto out;
	}

	// got a new packet, run decoder

	while (1) {
		int func_ret = 0;

		packet = packet_sequencer_next_packet(&ssrc_in_p->sequencer);
		if (G_UNLIKELY(!packet)) {
			if (!ch || !ch->encoder_format.clockrate || !ch->handler
					|| !ch->handler->dest_pt.codec_def)
				break;

			uint32_t ts_diff = packet_ts - ch->last_ts;
			unsigned long long ts_diff_us =
				(unsigned long long) ts_diff * 1000000 / ch->encoder_format.clockrate
				* ch->handler->dest_pt.codec_def->clockrate_mult;
			if (ts_diff_us >= 60000)  { // arbitrary value
				packet = packet_sequencer_force_next_packet(&ssrc_in_p->sequencer);
				if (!packet)
					break;
				ilogs(transcoding, LOG_DEBUG, "Timestamp difference too large (%llu ms) after lost packet, "
						"forcing next packet", ts_diff_us / 1000);
			}
			else
				break;
		}

		// new packet might have different handlers
		h = packet->handler;
		if (ch)
			obj_put(&ch->h);
		if (input_ch)
			obj_put(&input_ch->h);
		input_ch = NULL;
		ch = get_ssrc(ssrc_in_p->h.ssrc, h->ssrc_hash);
		if (G_UNLIKELY(!ch))
			goto next;
		input_ch = get_ssrc(ssrc_in_p->h.ssrc, h->input_handler->ssrc_hash);
		if (G_UNLIKELY(!input_ch)) {
			obj_put(&ch->h);
			ch = NULL;
			goto next;
		}

		ssrc_in_p->packets_lost = ssrc_in_p->sequencer.lost_count;
		atomic64_set(&ssrc_in->last_seq, ssrc_in_p->sequencer.ext_seq);

		ilogs(transcoding, LOG_DEBUG, "Processing RTP packet: seq %u, TS %lu",
				packet->p.seq, packet->ts);

		if (seq_ret == 1) {
			// seq reset - update output seq. we keep our output seq clean
			ssrc_out_p->seq_diff -= packet->p.seq - seq_ori;
			seq_ret = 0;
		}

		// we might be working with a different packet now
		mp->rtp = &packet->rtp;

		func_ret = packet->func(ch, input_ch, packet, mp);
		if (func_ret < 0)
			ilogs(transcoding, LOG_WARN | LOG_FLAG_LIMIT, "Decoder error while processing RTP packet");
next:
		if (func_ret != 1)
			__transcode_packet_free(packet);
	}

out:
	__ssrc_unlock_both(mp);
	if (input_ch)
		obj_put(&input_ch->h);
out_ch:
	if (ch)
		obj_put(&ch->h);

	return 0;
}

static void __output_rtp(struct media_packet *mp, struct codec_ssrc_handler *ch,
		struct codec_handler *handler, // normally == ch->handler except for DTMF
		char *buf, // malloc'd, room for rtp_header + filled-in payload
		unsigned int payload_len,
		unsigned long payload_ts,
		int marker, int seq, int seq_inc, int payload_type,
		unsigned long ts_delay)
{
	struct rtp_header *rh = (void *) buf;
	struct ssrc_ctx *ssrc_out = mp->ssrc_out;
	struct ssrc_entry_call *ssrc_out_p = ssrc_out->parent;
	// reconstruct RTP header
	unsigned long ts = payload_ts;
	ZERO(*rh);
	rh->v_p_x_cc = 0x80;
	if (payload_type == -1)
		payload_type = handler->dest_pt.payload_type;
	rh->m_pt = payload_type | (marker ? 0x80 : 0);
	if (seq != -1)
		rh->seq_num = htons(seq);
	else
		rh->seq_num = htons(ntohs(mp->rtp->seq_num) + (ssrc_out_p->seq_diff += seq_inc));
	rh->timestamp = htonl(ts);
	rh->ssrc = htonl(ssrc_out_p->h.ssrc);

	// add to output queue
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s.s = buf;
	p->s.len = payload_len + sizeof(struct rtp_header);
	payload_tracker_add(&ssrc_out->tracker, handler->dest_pt.payload_type);
	p->free_func = free;
	p->ttq_entry.source = handler;
	p->rtp = rh;
	p->ts = ts;
	p->clockrate = handler->dest_pt.clock_rate;
	ssrc_ctx_hold(ssrc_out);
	p->ssrc_out = ssrc_out;

	// this packet is dynamically allocated, so we're able to schedule it.
	// determine scheduled time to send
	if (ch->first_send.tv_sec && ch->encoder_format.clockrate) {
		// scale first_send from first_send_ts to ts
		p->ttq_entry.when = ch->first_send;
		uint32_t ts_diff = (uint32_t) ts - (uint32_t) ch->first_send_ts; // allow for wrap-around
		ts_diff += ts_delay;
		long long ts_diff_us =
			(unsigned long long) ts_diff * 1000000 / ch->encoder_format.clockrate
			* ch->handler->dest_pt.codec_def->clockrate_mult;
		timeval_add_usec(&p->ttq_entry.when, ts_diff_us);

		// how far in the future is this?
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);
		if (ts_diff_us > 1000000 || ts_diff_us < -1000000) // more than one second, can't be right
			ch->first_send.tv_sec = 0; // fix it up below
	}
	if (!ch->first_send.tv_sec) {
		p->ttq_entry.when = ch->first_send = rtpe_now;
		ch->first_send_ts = ts;
	}

	long long ts_diff_us
		= timeval_diff(&p->ttq_entry.when, &rtpe_now);

	ch->output_skew = ch->output_skew * 15 / 16 + ts_diff_us / 16;
	if (ch->output_skew > 50000 && ts_diff_us > 10000) { // arbitrary value, 50 ms, 10 ms shift
		ilogs(transcoding, LOG_DEBUG, "Steady clock skew of %li.%01li ms detected, shifting send timer back by 10 ms",
			ch->output_skew / 1000,
			(ch->output_skew % 1000) / 100);
		timeval_add_usec(&p->ttq_entry.when, -10000);
		ch->output_skew -= 10000;
		ch->first_send_ts += ch->encoder_format.clockrate / 100;
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);
	}
	else if (ts_diff_us < 0) {
		ts_diff_us *= -1;
		ilogs(transcoding, LOG_DEBUG, "Negative clock skew of %lli.%01lli ms detected, shifting send timer forward",
			ts_diff_us / 1000,
			(ts_diff_us % 1000) / 100);
		timeval_add_usec(&p->ttq_entry.when, ts_diff_us);
		ch->output_skew += ts_diff_us;
		ch->first_send_ts -= (long long) ch->encoder_format.clockrate * ts_diff_us / 1000000;
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now); // should be 0 now
	}

	ilogs(transcoding, LOG_DEBUG, "Scheduling to send RTP packet (seq %u TS %lu) in %s%lli.%01lli ms (at %lu.%06lu)",
			ntohs(rh->seq_num),
			ts,
			ts_diff_us < 0 ? "-" : "",
			llabs(ts_diff_us / 1000),
			llabs((ts_diff_us % 1000) / 100),
			(long unsigned) p->ttq_entry.when.tv_sec,
			(long unsigned) p->ttq_entry.when.tv_usec);

	g_queue_push_tail(&mp->packets_out, p);
}

// returns new reference
static struct codec_ssrc_handler *__output_ssrc_handler(struct codec_ssrc_handler *ch, struct media_packet *mp) {
	struct codec_handler *handler = ch->handler;
	if (handler->output_handler == handler) {
		obj_get(&ch->h);
		return ch;
	}

	// our encoder is in a different codec handler
	ilogs(transcoding, LOG_DEBUG, "Switching context from decoder to encoder");
	handler = handler->output_handler;
	struct codec_ssrc_handler *new_ch = get_ssrc(mp->ssrc_in->parent->h.ssrc, handler->ssrc_hash);
	if (G_UNLIKELY(!new_ch)) {
		ilogs(transcoding, LOG_ERR | LOG_FLAG_LIMIT,
				"Switched from input to output codec context, but no codec handler present");
		obj_get(&ch->h);
		return ch;
	}

	return new_ch;
}

// forwards DTMF input to DTMF output, plus rescaling duration
static int packet_dtmf_fwd(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		struct media_packet *mp)
{
	int payload_type = -1; // take from handler's output config
	unsigned long ts_delay = 0;

	struct codec_ssrc_handler *output_ch = NULL;

	// this is actually a DTMF -> PCM handler
	// grab our underlying PCM transcoder
	output_ch = __output_ssrc_handler(input_ch, mp);
	if (G_UNLIKELY(!output_ch->encoder))
		goto skip;

	// init some vars
	ch->first_ts = output_ch->first_ts;
	ch->first_send_ts = output_ch->first_send_ts;
	ch->output_skew = output_ch->output_skew;
	ch->first_send = output_ch->first_send;


	// the correct output TS is the encoder's FIFO PTS at the start of the DTMF
	// event. however, we must shift the FIFO PTS forward as the DTMF event goes on
	// as the DTMF event replaces the audio samples. therefore we must remember
	// the TS at the start of the event and the last seen event duration.
	if (ch->dtmf_ts != packet->ts) {
		// this is a new event
		ch->dtmf_ts = packet->ts; // start TS
		ch->last_dtmf_event_ts = 0; // last DTMF event duration
	}

	unsigned long ts = output_ch->encoder->next_pts / output_ch->encoder->def->clockrate_mult;
	// roll back TS to start of event
	ts -= ch->last_dtmf_event_ts;
	// adjust to output RTP TS
	unsigned long packet_ts = ts + output_ch->first_ts;

	ilogs(transcoding, LOG_DEBUG, "Scaling DTMF packet timestamp and duration: TS %lu -> %lu "
			"(%u -> %u)",
			packet->ts, packet_ts,
			ch->handler->source_pt.clock_rate, ch->handler->dest_pt.clock_rate);
	packet->ts = packet_ts;

	if (packet->payload->len >= sizeof(struct telephone_event_payload)) {
		struct telephone_event_payload *dtmf = (void *) packet->payload->s;
		unsigned int duration = av_rescale(ntohs(dtmf->duration),
				ch->handler->dest_pt.clock_rate, ch->handler->source_pt.clock_rate);
		dtmf->duration = htons(duration);

		// we can't directly use the RTP TS to schedule the send, as we have to adjust it
		// by the duration
		if (ch->dtmf_first_duration == 0 || duration < ch->dtmf_first_duration)
			ch->dtmf_first_duration = duration;
		ts_delay = duration - ch->dtmf_first_duration;

		// shift forward our output RTP TS
		output_ch->encoder->next_pts = (ts + duration) * output_ch->encoder->def->clockrate_mult;
		output_ch->encoder->packet_pts += (duration - ch->last_dtmf_event_ts) * output_ch->encoder->def->clockrate_mult;
		ch->last_dtmf_event_ts = duration;
	}
	payload_type = ch->handler->dtmf_payload_type;

skip:
	if (output_ch)
		obj_put(&output_ch->h);

	char *buf = malloc(packet->payload->len + sizeof(struct rtp_header) + RTP_BUFFER_TAIL_ROOM);
	memcpy(buf + sizeof(struct rtp_header), packet->payload->s, packet->payload->len);
	if (packet->bypass_seq) // inject original seq
		__output_rtp(mp, ch, packet->handler ? : ch->handler, buf, packet->payload->len, packet->ts,
				packet->marker, packet->p.seq, -1, payload_type, ts_delay);
	else // use our own sequencing
		__output_rtp(mp, ch, packet->handler ? : ch->handler, buf, packet->payload->len, packet->ts,
				packet->marker, -1, 0, payload_type, ts_delay);

	return 0;
}

// returns the codec handler for the primary payload type - mostly determined by guessing
static struct codec_handler *__input_handler(struct codec_handler *h, struct media_packet *mp) {
	if (!mp->ssrc_in)
		return h;

	for (int i = 0; i < mp->ssrc_in->tracker.most_len; i++) {
		int prim_pt = mp->ssrc_in->tracker.most[i];
		if (prim_pt == 255)
			continue;

		struct codec_handler *sequencer_h = codec_handler_get(mp->media, prim_pt, mp->media_out);
		if (sequencer_h == h)
			continue;
		if (sequencer_h->source_pt.codec_def && sequencer_h->source_pt.codec_def->supplemental)
			continue;
		ilogs(transcoding, LOG_DEBUG, "Primary RTP payload type for handling %s is %i",
				h->source_pt.codec_def->rtpname,
				prim_pt);
		return sequencer_h;
	}
	return h;
}

static int packet_dtmf(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	{
		LOCK(&mp->media->dtmf_lock);

		if (mp->media->dtmf_ts != packet->ts) { // ignore already processed events
			int ret = dtmf_event_packet(mp, packet->payload, ch->encoder_format.clockrate);
			if (G_UNLIKELY(ret == -1)) // error
				return -1;
			if (ret == 1) {
				// END event
				mp->media->dtmf_ts = packet->ts;
				input_ch->dtmf_start_ts = 0;
			}
			else
				input_ch->dtmf_start_ts = packet->ts ? packet->ts : 1;
		}
	}

	int ret = 0;

	if (!mp->call->block_dtmf && !mp->media->monologue->block_dtmf) {
		if (__buffer_dtx(input_ch->dtx_buffer, ch, input_ch, packet, mp, packet_dtmf_fwd))
			ret = 1; // consumed
		else
			packet_dtmf_fwd(ch, input_ch, packet, mp);
	}

	return ret;
}
static int packet_dtmf_dup(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		struct media_packet *mp)
{
	if (!mp->call->block_dtmf && !mp->media->monologue->block_dtmf)
		packet_dtmf_fwd(ch, input_ch, packet, mp);
	return 0;
}

static int __handler_func_supplemental(struct codec_handler *h, struct media_packet *mp,
		int (*func)(struct codec_ssrc_handler *, struct codec_ssrc_handler *,
			struct transcode_packet *, struct media_packet *),
		int (*dup_func)(struct codec_ssrc_handler *, struct codec_ssrc_handler *,
			struct transcode_packet *, struct media_packet *))
{
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);

	assert((mp->rtp->m_pt & 0x7f) == h->source_pt.payload_type);

	// create new packet and insert it into sequencer queue

	ilogs(transcoding, LOG_DEBUG, "Received %s supplemental RTP packet: SSRC %" PRIx32
				", PT %u, seq %u, TS %u, len %zu",
			h->source_pt.codec_def->rtpname,
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

	// determine the primary audio codec used by this SSRC, as the sequence numbers
	// and timing info is shared with it. we'll need to use the same sequencer

	struct codec_handler *sequencer_h = __input_handler(h, mp);

	h->input_handler = sequencer_h;
	h->output_handler = sequencer_h;

	struct transcode_packet *packet = g_slice_alloc0(sizeof(*packet));
	packet->func = func;
	packet->dup_func = dup_func;
	packet->handler = h;
	packet->rtp = *mp->rtp;

	if (sequencer_h->passthrough || sequencer_h->kernelize) {
		// bypass sequencer, directly pass it to forwarding function
		packet->bypass_seq = 1;
	}

	return __handler_func_sequencer(mp, packet);
}
static int handler_func_dtmf(struct codec_handler *h, struct media_packet *mp) {
	// DTMF input - can we do DTMF output?
	if (h->dtmf_payload_type == -1)
		return handler_func_transcode(h, mp);

	return __handler_func_supplemental(h, mp, packet_dtmf, packet_dtmf_dup);
}

static int handler_func_t38(struct codec_handler *h, struct media_packet *mp) {
	if (!mp->media)
		return 0;

	return t38_gateway_input_udptl(mp->media->t38_gateway, &mp->raw);
}
#endif



void codec_packet_free(void *pp) {
	struct codec_packet *p = pp;
	if (p->free_func)
		p->free_func(p->s.s);
	ssrc_ctx_put(&p->ssrc_out);
	g_slice_free1(sizeof(*p), p);
}



struct rtp_payload_type *codec_make_payload_type(const str *codec_str, enum media_type type) {

	str codec_fmt = *codec_str;
	str codec, parms, chans, opts, extra_opts, fmt_params, codec_opts;
	if (str_token_sep(&codec, &codec_fmt, '/'))
		return NULL;
	str_token_sep(&parms, &codec_fmt, '/');
	str_token_sep(&chans, &codec_fmt, '/');
	str_token_sep(&opts, &codec_fmt, '/');
	str_token_sep(&extra_opts, &codec_fmt, '/');
	str_token_sep(&fmt_params, &codec_fmt, '/');
	str_token_sep(&codec_opts, &codec_fmt, '/');

	int clockrate = str_to_i(&parms, 0);
	int channels = str_to_i(&chans, 0);
	int bitrate = str_to_i(&opts, 0);
	int ptime = str_to_i(&extra_opts, 0);

	if (clockrate && !channels)
		channels = 1;

	struct rtp_payload_type *pt = g_slice_alloc0(sizeof(*pt));

	pt->payload_type = -1;
	pt->encoding = codec;
	pt->clock_rate = clockrate;
	pt->channels = channels;
	pt->bitrate = bitrate;
	pt->ptime = ptime;
	pt->format_parameters = fmt_params;
	pt->codec_opts = codec_opts;

	codec_init_payload_type(pt, type);

	return pt;
}

void codec_init_payload_type(struct rtp_payload_type *pt, enum media_type type) {
#ifdef WITH_TRANSCODING
	ensure_codec_def_type(pt, type);
	const codec_def_t *def = pt->codec_def;

	if (def) {
		if (!pt->clock_rate)
			pt->clock_rate = def->default_clockrate;
		if (!pt->channels)
			pt->channels = def->default_channels;
		if (pt->ptime <= 0)
			pt->ptime = def->default_ptime;
		if (!pt->format_parameters.s && def->default_fmtp)
			str_init(&pt->format_parameters, (char *) def->default_fmtp);

		if (def->init)
			def->init(pt);

		if (pt->payload_type == -1 && def->rfc_payload_type >= 0) {
			const struct rtp_payload_type *rfc_pt = rtp_get_rfc_payload_type(def->rfc_payload_type);
			// only use the RFC payload type if all parameters match
			if (rfc_pt
					&& (pt->clock_rate == 0 || pt->clock_rate == rfc_pt->clock_rate)
					&& (pt->channels == 0 || pt->channels == rfc_pt->channels))
			{
				pt->payload_type = rfc_pt->payload_type;
				if (!pt->clock_rate)
					pt->clock_rate = rfc_pt->clock_rate;
				if (!pt->channels)
					pt->channels = rfc_pt->channels;
			}
		}
	}
#endif

	// init params strings
	char full_encoding[64];
	char full_full_encoding[64];
	char params[32] = "";

	snprintf(full_full_encoding, sizeof(full_full_encoding), STR_FORMAT "/%u/%i", STR_FMT(&pt->encoding),
			pt->clock_rate,
			pt->channels);

	if (pt->channels > 1) {
		strcpy(full_encoding, full_full_encoding);
		snprintf(params, sizeof(params), "%i", pt->channels);
	}
	else
		snprintf(full_encoding, sizeof(full_encoding), STR_FORMAT "/%u", STR_FMT(&pt->encoding),
				pt->clock_rate);

	// allocate strings
	str_init_dup_str(&pt->encoding, &pt->encoding);
	str_init_dup(&pt->encoding_with_params, full_encoding);
	str_init_dup(&pt->encoding_with_full_params, full_full_encoding);
	str_init_dup(&pt->encoding_parameters, params);
	str_init_dup_str(&pt->format_parameters, &pt->format_parameters);
	str_init_dup_str(&pt->codec_opts, &pt->codec_opts);

	// allocate everything from the rtcp-fb list
	for (GList *l = pt->rtcp_fb.head; l; l = l->next) {
		str *fb = l->data;
		l->data = str_dup(fb);
	}
}



#ifdef WITH_TRANSCODING


static int handler_func_passthrough_ssrc(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);
	if (!handler_silence_block(h, mp))
		return 0;

	if (mp->rtp) {
		codec_calc_jitter(mp->ssrc_in, ntohl(mp->rtp->timestamp), h->source_pt.clock_rate, &mp->tv);
		codec_calc_lost(mp->ssrc_in, ntohs(mp->rtp->seq_num));
	}

	// substitute out SSRC etc
	mp->rtp->ssrc = htonl(mp->ssrc_in->ssrc_map_out);
	mp->rtp->seq_num = htons(ntohs(mp->rtp->seq_num) + mp->ssrc_out->parent->seq_diff);

	// keep track of other stats here?

	codec_add_raw_packet(mp, h->source_pt.clock_rate);
	return 0;
}


static void __transcode_packet_free(struct transcode_packet *p) {
	free(p->payload);
	g_slice_free1(sizeof(*p), p);
}

static struct ssrc_entry *__ssrc_handler_new(void *p) {
	// XXX combine with __ssrc_handler_transcode_new
	struct codec_handler *h = p;
	struct codec_ssrc_handler *ch = obj_alloc0("codec_ssrc_handler", sizeof(*ch), __free_ssrc_handler);
	ch->handler = h;
	return &ch->h;
}

static void __dtmf_dsp_callback(void *ptr, int code, int level, int delay) {
	struct codec_ssrc_handler *ch = ptr;
	uint64_t ts = ch->last_dtmf_event_ts + delay;
	ch->last_dtmf_event_ts = ts;
	ts = av_rescale(ts, ch->encoder_format.clockrate, ch->dtmf_format.clockrate);
	codec_add_dtmf_event(ch, code, level, ts);
}

void codec_add_dtmf_event(struct codec_ssrc_handler *ch, int code, int level, uint64_t ts) {
	struct dtmf_event *ev = g_slice_alloc(sizeof(*ev));
	*ev = (struct dtmf_event) { .code = code, .volume = level, .ts = ts };
	ilogs(transcoding, LOG_DEBUG, "DTMF event state change: code %i, volume %i, TS %lu",
			ev->code, ev->volume, (unsigned long) ts);
	g_queue_push_tail(&ch->dtmf_events, ev);
}

uint64_t codec_last_dtmf_event(struct codec_ssrc_handler *ch) {
	struct dtmf_event *ev = g_queue_peek_tail(&ch->dtmf_events);
	if (!ev)
		return 0;
	return ev->ts;
}

uint64_t codec_encoder_pts(struct codec_ssrc_handler *ch) {
	if (!ch || !ch->encoder)
		return 0;
	return ch->encoder->fifo_pts;
}

void codec_decoder_skip_pts(struct codec_ssrc_handler *ch, uint64_t pts) {
	ilogs(transcoding, LOG_DEBUG, "Skipping next %" PRIu64 " samples", pts);
	ch->skip_pts += pts;
}

uint64_t codec_decoder_unskip_pts(struct codec_ssrc_handler *ch) {
	uint64_t prev = ch->skip_pts;
	ilogs(transcoding, LOG_DEBUG, "Un-skipping next %" PRIu64 " samples", prev);
	ch->skip_pts = 0;
	return prev;
}

static int codec_decoder_event(enum codec_event event, void *ptr, void *data) {
	struct call_media *media = data;
	if (!media)
		return 0;

	switch (event) {
		case CE_AMR_CMR_RECV:
			// ignore locking and races for this
			media->u.amr.cmr.cmr_in = GPOINTER_TO_UINT(ptr);
			media->u.amr.cmr.cmr_in_ts = rtpe_now;
			break;
		case CE_AMR_SEND_CMR:
			// ignore locking and races for this
			media->u.amr.cmr.cmr_out = GPOINTER_TO_UINT(ptr);
			media->u.amr.cmr.cmr_out_ts = rtpe_now;
		default:
			break;
	}
	return 0;
}

// consumes `packet` if buffered (returns 1)
static int __buffer_dtx(struct dtx_buffer *dtxb, struct codec_ssrc_handler *decoder_handler,
		struct codec_ssrc_handler *input_handler,
		struct transcode_packet *packet, struct media_packet *mp,
		int (*func)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
			struct transcode_packet *packet,
			struct media_packet *mp))
{
	if (!dtxb || !mp->sfd || !mp->ssrc_in || !mp->ssrc_out)
		return 0;

	unsigned long ts = packet->ts;

	// allocate packet object
	struct dtx_packet *dtxp = g_slice_alloc0(sizeof(*dtxp));
	dtxp->packet = packet;
	dtxp->func = func;
	if (decoder_handler)
		dtxp->decoder_handler = obj_get(&decoder_handler->h);
	if (input_handler)
		dtxp->input_handler = obj_get(&input_handler->h);
	media_packet_copy(&dtxp->mp, mp);

	// add to processing queue

	mutex_lock(&dtxb->lock);

	dtxb->start = rtpe_now.tv_sec;
	g_queue_push_tail(&dtxb->packets, dtxp);
	ilogs(dtx, LOG_DEBUG, "Adding packet (TS %lu) to DTX buffer; now %i packets in DTX queue",
			ts, dtxb->packets.length);

	// schedule timer if not running yet
	if (!dtxb->ct.next.tv_sec) {
		if (!dtxb->ssrc)
			dtxb->ssrc = mp->ssrc_in->parent->h.ssrc;
		dtxb->ct.next = mp->tv;
		timeval_add_usec(&dtxb->ct.next, rtpe_config.dtx_delay * 1000);
		timerthread_obj_schedule_abs(&dtxb->ct.tt_obj, &dtxb->ct.next);
	}

	// packet now consumed
	packet = NULL;

	mutex_unlock(&dtxb->lock);

	return 1;
}

static void dtx_packet_free(struct dtx_packet *dtxp) {
	if (dtxp->packet)
		__transcode_packet_free(dtxp->packet);
	media_packet_release(&dtxp->mp);
	if (dtxp->decoder_handler)
		obj_put(&dtxp->decoder_handler->h);
	if (dtxp->input_handler)
		obj_put(&dtxp->input_handler->h);
	g_slice_free1(sizeof(*dtxp), dtxp);
}
static void dtx_buffer_stop(struct dtx_buffer **dtxbp) {
	codec_timer_stop((struct codec_timer **) dtxbp);
}
static bool __dtx_drift_shift(struct dtx_buffer *dtxb, struct dtx_packet *dtxp, unsigned long ts,
		long tv_diff, long ts_diff,
		struct codec_ssrc_handler *ch)
{
	bool discard = false;

	if (tv_diff < rtpe_config.dtx_delay * 1000) {
		// timer underflow
		ilogs(dtx, LOG_DEBUG, "Packet reception time has caught up with DTX timer "
				"(%li ms < %i ms), "
				"pushing DTX timer forward my %i ms",
				tv_diff / 1000, rtpe_config.dtx_delay, rtpe_config.dtx_shift);
		timeval_add_usec(&dtxb->ct.next, rtpe_config.dtx_shift * 1000);
	}
	else if (ts_diff < dtxb->tspp) {
		// TS underflow
		// special case: DTMF timestamps are static
		if (ts_diff == 0 && ch->handler->source_pt.codec_def->dtmf) {
			;
		}
		else {
			ilogs(dtx, LOG_DEBUG, "Packet timestamps have caught up with DTX timer "
					"(TS %lu, diff %li), "
					"pushing DTX timer forward by %i ms and discarding packet",
					ts, ts_diff, rtpe_config.dtx_shift);
			timeval_add_usec(&dtxb->ct.next, rtpe_config.dtx_shift * 1000);
			discard = true;
		}
	}
	else if (dtxb->packets.length >= rtpe_config.dtx_buffer) {
		// inspect TS is most recent packet
		struct dtx_packet *dtxp_last = g_queue_peek_tail(&dtxb->packets);
		ts_diff = dtxp_last->packet->ts - ts;
		long long ts_diff_us = (long long) ts_diff * 1000000 / dtxb->clockrate;
		if (ts_diff_us >= rtpe_config.dtx_lag * 1000) {
			// overflow
			ilogs(dtx, LOG_DEBUG, "DTX timer queue overflowing (%i packets in queue, "
					"%lli ms delay), speeding up DTX timer by %i ms",
					dtxb->packets.length, ts_diff_us / 1000, rtpe_config.dtx_shift);
			timeval_add_usec(&dtxb->ct.next, rtpe_config.dtx_shift * -1000);
		}
	}

	return discard;
}
static bool __dtx_drift_drop(struct dtx_buffer *dtxb, struct dtx_packet *dtxp, unsigned long ts,
		long tv_diff, long ts_diff,
		struct codec_ssrc_handler *ch)
{
	bool discard = false;

	if (ts_diff < dtxb->tspp) {
		// TS underflow
		// special case: DTMF timestamps are static
		if (ts_diff == 0 && ch->handler->source_pt.codec_def->dtmf) {
			;
		}
		else {
			ilogs(dtx, LOG_DEBUG, "Packet timestamps have caught up with DTX timer "
					"(TS %lu, diff %li), "
					"adjusting input TS clock back by one frame (%i)",
					ts, ts_diff, dtxb->tspp);
			dtxb->head_ts -= dtxb->tspp;
		}
	}
	else if (dtxb->packets.length >= rtpe_config.dtx_buffer) {
		// inspect TS is most recent packet
		struct dtx_packet *dtxp_last = g_queue_peek_tail(&dtxb->packets);
		ts_diff = dtxp_last->packet->ts - ts;
		long long ts_diff_us = (long long) ts_diff * 1000000 / dtxb->clockrate;
		if (ts_diff_us >= rtpe_config.dtx_lag * 1000) {
			// overflow
			ilogs(dtx, LOG_DEBUG, "DTX timer queue overflowing (%i packets in queue, "
					"%lli ms delay), discarding packet",
					dtxb->packets.length, ts_diff_us / 1000);
			discard = true;
		}
	}

	return discard;
}
static bool __dtx_handle_drift(struct dtx_buffer *dtxb, struct dtx_packet *dtxp, unsigned long ts,
		long tv_diff, long ts_diff,
		struct codec_ssrc_handler *ch)
{
	if (!dtxp)
		return false;
	if (rtpe_config.dtx_shift)
		return __dtx_drift_shift(dtxb, dtxp, ts, tv_diff, ts_diff, ch);
	return __dtx_drift_drop(dtxb, dtxp, ts, tv_diff, ts_diff, ch);
}
static void __dtx_send_later(struct codec_timer *ct) {
	struct dtx_buffer *dtxb = (void *) ct;
	struct media_packet mp_copy = {0,};
	int ret = 0;
	unsigned long ts;
	int p_left = 0;
	long tv_diff = -1, ts_diff = 0;

	mutex_lock(&dtxb->lock);

	if (dtxb->call)
		log_info_call(dtxb->call);

	// vars assigned in the loop
	struct dtx_packet *dtxp;
	struct call *call;
	struct codec_ssrc_handler *ch;
	struct packet_stream *ps;
	struct codec_ssrc_handler *input_ch;

	while (true) {
		// do we have a packet?
		dtxp = g_queue_peek_head(&dtxb->packets);
		if (dtxp) {
			// inspect head packet and check TS, see if it's ready to be decoded
			ts = dtxp->packet->ts;
			ts_diff = ts - dtxb->head_ts;
			long long ts_diff_us = (long long) ts_diff * 1000000 / dtxb->clockrate;

			if (!dtxb->head_ts)
				; // first packet
			else if (ts_diff < 0)
				ilogs(dtx, LOG_DEBUG, "DTX timestamp reset (from %lu to %lu)", dtxb->head_ts, ts);
			else if (ts_diff_us > MAX(20 * rtpe_config.dtx_delay, 200000))
				ilogs(dtx, LOG_DEBUG, "DTX timestamp reset (from %lu to %lu = %lli ms)",
						dtxb->head_ts, ts, ts_diff_us);
			else if (ts_diff >= dtxb->tspp * 2) {
				ilogs(dtx, LOG_DEBUG, "First packet in DTX buffer not ready yet (packet TS %lu, "
						"DTX TS %lu, diff %li)",
						ts, dtxb->head_ts, ts_diff);
				dtxp = NULL;
			}

			// go or no go?
			if (dtxp)
				g_queue_pop_head(&dtxb->packets);
		}

		p_left = dtxb->packets.length;

		if (dtxp) {
			// save the `mp` for possible future DTX
			media_packet_release(&dtxb->last_mp);
			media_packet_copy(&dtxb->last_mp, &dtxp->mp);
			media_packet_copy(&mp_copy, &dtxp->mp);
			if (dtxb->head_ts)
				ts_diff = dtxp->packet->ts - dtxb->head_ts;
			else
				ts_diff = dtxb->tspp; // first packet
			ts = dtxb->head_ts = dtxp->packet->ts;
			tv_diff = timeval_diff(&rtpe_now, &mp_copy.tv);
		}
		else {
			// no packet ready to decode: DTX
			media_packet_copy(&mp_copy, &dtxb->last_mp);
			// shift forward TS
			dtxb->head_ts += dtxb->tspp;
			ts = dtxb->head_ts;
		}
		ps = mp_copy.stream;
		log_info_stream_fd(mp_copy.sfd);

		// copy out other fields so we can unlock
		ch = (dtxp && dtxp->decoder_handler) ? obj_get(&dtxp->decoder_handler->h)
			: NULL;
		if (!ch && dtxb->csh)
			ch = obj_get(&dtxb->csh->h);
		input_ch = (dtxp && dtxp->input_handler) ? obj_get(&dtxp->input_handler->h) : NULL;
		call = dtxb->call ? obj_get(dtxb->call) : NULL;

		if (!call || !ch || !ps || !ps->ssrc_in[0]
				|| dtxb->ssrc != ps->ssrc_in[0]->parent->h.ssrc
				|| dtxb->ct.next.tv_sec == 0) {
			// shut down or SSRC change
			ilogs(dtx, LOG_DEBUG, "DTX buffer for %lx has been shut down", (unsigned long) dtxb->ssrc);
			dtxb->ct.next.tv_sec = 0;
			dtxb->head_ts = 0;
			mutex_unlock(&dtxb->lock);
			goto out; // shut down
		}

		if (!dtxp) // we need to do DTX
			break;

		bool discard = __dtx_handle_drift(dtxb, dtxp, ts, tv_diff, ts_diff, ch);

		if (!discard)
			break;

		// release and try again
		mutex_unlock(&dtxb->lock);

		if (call && mp_copy.ssrc_out) {
			// packet consumed - track seq
			rwlock_lock_r(&call->master_lock);
			__ssrc_lock_both(&mp_copy);
			mp_copy.ssrc_out->parent->seq_diff--;
			__ssrc_unlock_both(&mp_copy);
			rwlock_unlock_r(&call->master_lock);
		}
		if (call)
			obj_put(call);
		if (ch)
			obj_put(&ch->h);
		if (input_ch)
			obj_put(&input_ch->h);
		if (dtxp)
			dtx_packet_free(dtxp);
		media_packet_release(&mp_copy);

		call = NULL;
		ch = NULL;
		input_ch = NULL;
		dtxp = NULL;
		ps = NULL;

		mutex_lock(&dtxb->lock);
	}

	int ptime = dtxb->ptime;

	mutex_unlock(&dtxb->lock);

	rwlock_lock_r(&call->master_lock);
	__ssrc_lock_both(&mp_copy);

	if (dtxp) {
		ilogs(dtx, LOG_DEBUG, "Decoding DTX-buffered RTP packet (TS %lu) now; "
				"%i packets left in queue", ts, p_left);

		mp_copy.ptime = -1;
		ret = dtxp->func(ch, input_ch, dtxp->packet, &mp_copy);
		if (!ret) {
			if (mp_copy.ptime > 0)
				ptime = mp_copy.ptime;
		}
		else
			ilogs(dtx, LOG_WARN | LOG_FLAG_LIMIT,
					"Decoder error while processing buffered RTP packet");
	}
	else {
		unsigned int diff = rtpe_now.tv_sec - dtxb->start;

		if (rtpe_config.max_dtx <= 0 || diff < rtpe_config.max_dtx) {
			ilogs(dtx, LOG_DEBUG, "RTP media for TS %lu missing, triggering DTX", ts);

			// synthetic packet
			mp_copy.rtp->seq_num = htons(ntohs(mp_copy.rtp->seq_num) + 1);

			ret = decoder_dtx(ch->decoder, ts, ptime,
					ch->handler->packet_decoded, ch, &mp_copy);
			if (ret)
				ilogs(dtx, LOG_WARN | LOG_FLAG_LIMIT,
						"Decoder error handling DTX/lost packet");
		}
		else {
			ilogs(dtx, LOG_DEBUG, "Stopping DTX at TS %lu", ts);

			mutex_lock(&dtxb->lock);
			__dtx_shutdown(dtxb);
			mutex_unlock(&dtxb->lock);
		}
	}

	mutex_lock(&dtxb->lock);

	if (ptime != dtxb->ptime) {
		dtxb->ptime = ptime;
		dtxb->tspp = ptime * dtxb->clockrate / 1000;
	}

	// schedule next run
	timeval_add_usec(&dtxb->ct.next, dtxb->ptime * 1000);
	timerthread_obj_schedule_abs(&dtxb->ct.tt_obj, &dtxb->ct.next);

	mutex_unlock(&dtxb->lock);

	__ssrc_unlock_both(&mp_copy);

	if (mp_copy.packets_out.length && ret == 0) {
		struct sink_handler *sh = &mp_copy.sink;
		struct packet_stream *sink = sh->sink;

		if (!sink)
			media_socket_dequeue(&mp_copy, NULL); // just free
		else {
			if (sh->handler && media_packet_encrypt(sh->handler->out->rtp_crypt, sink, &mp_copy))
				ilogs(dtx, LOG_ERR | LOG_FLAG_LIMIT, "Error encrypting buffered RTP media");

			mutex_lock(&sink->out_lock);
			if (media_socket_dequeue(&mp_copy, sink))
				ilogs(dtx, LOG_ERR | LOG_FLAG_LIMIT,
						"Error sending buffered media to RTP sink");
			mutex_unlock(&sink->out_lock);
		}
	}

	rwlock_unlock_r(&call->master_lock);

out:
	if (call)
		obj_put(call);
	if (ch)
		obj_put(&ch->h);
	if (input_ch)
		obj_put(&input_ch->h);
	if (dtxp)
		dtx_packet_free(dtxp);
	media_packet_release(&mp_copy);
	log_info_clear();
}
static void __dtx_shutdown(struct dtx_buffer *dtxb) {
	if (dtxb->csh)
		obj_put(&dtxb->csh->h);
	dtxb->csh = NULL;
	if (dtxb->call)
		obj_put(dtxb->call);
	dtxb->call = NULL;
	g_queue_clear_full(&dtxb->packets, (GDestroyNotify) dtx_packet_free);
}
static void __dtx_free(void *p) {
	struct dtx_buffer *dtxb = p;
	__dtx_shutdown(dtxb);
	media_packet_release(&dtxb->last_mp);
	mutex_destroy(&dtxb->lock);
}
static void __dtx_setup(struct codec_ssrc_handler *ch) {
	if (!decoder_has_dtx(ch->decoder) || ch->dtx_buffer)
		return;

	if (!rtpe_config.dtx_delay)
		return;

	struct dtx_buffer *dtx =
		ch->dtx_buffer = obj_alloc0("dtx_buffer", sizeof(*dtx), __dtx_free);
	dtx->ct.tt_obj.tt = &codec_timers_thread;
	dtx->ct.func = __dtx_send_later;
	dtx->csh = obj_get(&ch->h);
	dtx->call = obj_get(ch->handler->media->call);
	mutex_init(&dtx->lock);
	dtx->ptime = ch->ptime;
	if (dtx->ptime <= 0)
		dtx->ptime = ch->handler->source_pt.codec_def->default_ptime;
	if (dtx->ptime <= 0)
		dtx->ptime = 20;
	ilogs(dtx, LOG_DEBUG, "Using DTX ptime %i based on handler=%i codec=%i", dtx->ptime,
			ch->ptime, ch->handler->source_pt.codec_def->default_ptime);
	dtx->clockrate = ch->handler->source_pt.clock_rate;
	dtx->tspp = dtx->ptime * dtx->clockrate / 1000;
}
static void __ssrc_handler_stop(void *p, void *dummy) {
	struct codec_ssrc_handler *ch = p;
	if (ch->dtx_buffer) {
		mutex_lock(&ch->dtx_buffer->lock);
		__dtx_shutdown(ch->dtx_buffer);
		mutex_unlock(&ch->dtx_buffer->lock);

		dtx_buffer_stop(&ch->dtx_buffer);
	}
}
void codec_handlers_stop(GQueue *q) {
	for (GList *l = q->head; l; l = l->next) {
		struct codec_handler *h = l->data;
		ssrc_hash_foreach(h->ssrc_hash, __ssrc_handler_stop, NULL);
	}
}




static void silence_event_free(void *p) {
	g_slice_free1(sizeof(struct silence_event), p);
}

#define __silence_detect_type(type) \
static void __silence_detect_ ## type(struct codec_ssrc_handler *ch, AVFrame *frame, type thres) { \
	type *s = (void *) frame->data[0]; \
	struct silence_event *last = g_queue_peek_tail(&ch->silence_events); \
 \
	if (last && last->end) /* last event finished? */ \
		last = NULL; \
 \
	for (unsigned int i = 0; i < frame->nb_samples; i++) { \
		if (s[i] <= thres && s[1] >= -thres) { \
			/* silence */ \
			if (!last) { \
				/* new event */ \
				last = g_slice_alloc0(sizeof(*last)); \
				last->start = frame->pts + i; \
				g_queue_push_tail(&ch->silence_events, last); \
			} \
		} \
		else { \
			/* not silence */ \
			if (last && !last->end) { \
				/* close off event */ \
				last->end = frame->pts + i; \
				last = NULL; \
			} \
		} \
	} \
}

__silence_detect_type(double)
__silence_detect_type(float)
__silence_detect_type(int32_t)
__silence_detect_type(int16_t)

static void __silence_detect(struct codec_ssrc_handler *ch, AVFrame *frame) {
	if (!rtpe_config.silence_detect_int)
		return;
	if (ch->handler->cn_payload_type < 0)
		return;
	switch (frame->format) {
		case AV_SAMPLE_FMT_DBL:
			__silence_detect_double(ch, frame, rtpe_config.silence_detect_double);
			break;
		case AV_SAMPLE_FMT_FLT:
			__silence_detect_float(ch, frame, rtpe_config.silence_detect_double);
			break;
		case AV_SAMPLE_FMT_S32:
			__silence_detect_int32_t(ch, frame, rtpe_config.silence_detect_int);
			break;
		case AV_SAMPLE_FMT_S16:
			__silence_detect_int16_t(ch, frame, rtpe_config.silence_detect_int >> 16);
			break;
		default:
			ilogs(transcoding, LOG_WARN | LOG_FLAG_LIMIT, "Unsupported sample format %i for silence detection",
					frame->format);
	}
}
static int is_silence_event(str *inout, GQueue *events, uint64_t pts, uint64_t duration) {
	uint64_t end = pts + duration;

	while (events->length) {
		struct silence_event *first = g_queue_peek_head(events);
		if (first->start > pts) // future event
			return 0;
		if (!first->end) // ongoing event
			goto silence;
		if (first->end > end) // event finished with end in the future
			goto silence;
		// event has ended: remove it
		g_queue_pop_head(events);
		// does the event fill the entire span?
		if (first->end == end) {
			silence_event_free(first);
			goto silence;
		}
		// keep going, there might be more
		silence_event_free(first);
	}
	return 0;

silence:
	// replace with CN payload
	inout->len = rtpe_config.cn_payload.len;
	memcpy(inout->s, rtpe_config.cn_payload.s, inout->len);
	return 1;
}




static struct ssrc_entry *__ssrc_handler_transcode_new(void *p) {
	struct codec_handler *h = p;

	ilogs(codec, LOG_DEBUG, "Creating SSRC transcoder from %s/%u/%i to "
			"%s/%u/%i",
			h->source_pt.codec_def->rtpname, h->source_pt.clock_rate,
			h->source_pt.channels,
			h->dest_pt.codec_def->rtpname, h->dest_pt.clock_rate,
			h->dest_pt.channels);

	struct codec_ssrc_handler *ch = obj_alloc0("codec_ssrc_handler", sizeof(*ch), __free_ssrc_handler);
	ch->handler = h;
	ch->ptime = h->dest_pt.ptime;
	ch->sample_buffer = g_string_new("");
	ch->bitrate = h->dest_pt.bitrate ? : h->dest_pt.codec_def->default_bitrate;

	format_t enc_format = {
		.clockrate = h->dest_pt.clock_rate * h->dest_pt.codec_def->clockrate_mult,
		.channels = h->dest_pt.channels,
		.format = -1,
	};
	ch->encoder = encoder_new();
	if (!ch->encoder)
		goto err;
	if (encoder_config_fmtp(ch->encoder, h->dest_pt.codec_def,
				ch->bitrate,
				ch->ptime,
				&enc_format, &ch->encoder_format, &h->dest_pt.format_parameters,
				&h->dest_pt.codec_opts))
		goto err;

	if (h->pcm_dtmf_detect) {
		ilogs(codec, LOG_DEBUG, "Inserting DTMF DSP for output payload type %i", h->dtmf_payload_type);
		ch->dtmf_format = (format_t) { .clockrate = 8000, .channels = 1, .format = AV_SAMPLE_FMT_S16 };
		ch->dtmf_dsp = dtmf_rx_init(NULL, NULL, NULL);
		if (!ch->dtmf_dsp)
			ilogs(codec, LOG_ERR, "Failed to allocate DTMF RX context");
		else
			dtmf_rx_set_realtime_callback(ch->dtmf_dsp, __dtmf_dsp_callback, ch);
	}

	ch->decoder = decoder_new_fmtp(h->source_pt.codec_def, h->source_pt.clock_rate, h->source_pt.channels,
			h->source_pt.ptime,
			&ch->encoder_format, &h->source_pt.format_parameters, &h->source_pt.codec_opts);
	if (!ch->decoder)
		goto err;
	if (rtpe_config.dtx_cn_params.len) {
		if (ch->decoder->def->amr) {
			if (rtpe_config.amr_cn_dtx)
				decoder_set_cn_dtx(ch->decoder, &rtpe_config.dtx_cn_params);
		}
		else
			decoder_set_cn_dtx(ch->decoder, &rtpe_config.dtx_cn_params);
	}

	ch->decoder->event_data = h->media;
	ch->decoder->event_func = codec_decoder_event;

	ch->bytes_per_packet = (ch->encoder->samples_per_packet ? : ch->encoder->samples_per_frame)
		* h->dest_pt.codec_def->bits_per_sample / 8;

	__dtx_setup(ch);

	ilogs(codec, LOG_DEBUG, "Encoder created with clockrate %i, %i channels, using sample format %i "
			"(ptime %i for %i samples per frame and %i samples (%i bytes) per packet, bitrate %i)",
			ch->encoder_format.clockrate, ch->encoder_format.channels, ch->encoder_format.format,
			ch->ptime, ch->encoder->samples_per_frame, ch->encoder->samples_per_packet,
			ch->bytes_per_packet, ch->bitrate);

	return &ch->h;

err:
	obj_put(&ch->h);
	return NULL;
}
static int __encoder_flush(encoder_t *enc, void *u1, void *u2) {
	int *going = u1;
	*going = 1;
	return 0;
}
static void __free_ssrc_handler(void *chp) {
	struct codec_ssrc_handler *ch = chp;
	if (ch->decoder)
		decoder_close(ch->decoder);
	if (ch->encoder) {
		// flush out queue to avoid ffmpeg warnings
		int going;
		do {
			going = 0;
			encoder_input_data(ch->encoder, NULL, __encoder_flush, &going, NULL);
		} while (going);
		encoder_free(ch->encoder);
	}
	if (ch->sample_buffer)
		g_string_free(ch->sample_buffer, TRUE);
	if (ch->dtmf_dsp)
		dtmf_rx_free(ch->dtmf_dsp);
	resample_shutdown(&ch->dtmf_resampler);
	g_queue_clear_full(&ch->dtmf_events, dtmf_event_free);
	g_queue_clear_full(&ch->silence_events, silence_event_free);
	dtx_buffer_stop(&ch->dtx_buffer);
}

static int packet_encoded_rtp(encoder_t *enc, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilogs(transcoding, LOG_DEBUG, "RTP media successfully encoded: TS %llu, len %i",
			(unsigned long long) enc->avpkt->pts, enc->avpkt->size);

	// run this through our packetizer
	AVPacket *in_pkt = enc->avpkt;

	while (1) {
		// figure out how big of a buffer we need
		unsigned int payload_len = MAX(MAX(enc->avpkt->size, ch->bytes_per_packet),
				sizeof(struct telephone_event_payload));
		unsigned int pkt_len = sizeof(struct rtp_header) + payload_len + RTP_BUFFER_TAIL_ROOM;
		// prepare our buffers
		char *buf = malloc(pkt_len);
		char *payload = buf + sizeof(struct rtp_header);
		// tell our packetizer how much we want
		str inout;
		str_init_len(&inout, payload, payload_len);
		// and request a packet
		if (in_pkt)
			ilogs(transcoding, LOG_DEBUG, "Adding %i bytes to packetizer", in_pkt->size);
		int ret = enc->def->packetizer(in_pkt,
				ch->sample_buffer, &inout, enc);

		if (G_UNLIKELY(ret == -1 || enc->avpkt->pts == AV_NOPTS_VALUE)) {
			// nothing
			free(buf);
			break;
		}

		ilogs(transcoding, LOG_DEBUG, "Received packet of %zu bytes from packetizer", inout.len);

		// check special payloads

		unsigned int repeats = 0;
		int payload_type = -1;
		int dtmf_pt = ch->handler->dtmf_payload_type;
		int is_dtmf = 0;

		if (dtmf_pt != -1)
			is_dtmf = dtmf_event_payload(&inout, (uint64_t *) &enc->avpkt->pts, enc->avpkt->duration,
					&ch->dtmf_event, &ch->dtmf_events);
		if (is_dtmf) {
			payload_type = dtmf_pt;
			if (is_dtmf == 1)
				ch->rtp_mark = 1; // DTMF start event
			else if (is_dtmf == 3)
				repeats = 2; // DTMF end event
		}
		else {
			if (is_silence_event(&inout, &ch->silence_events, enc->avpkt->pts, enc->avpkt->duration))
				payload_type = ch->handler->cn_payload_type;
		}

		// ready to send

		do {
			char *send_buf = buf;
			if (repeats > 0) {
				// need to duplicate the payload as __output_rtp consumes it
				send_buf = malloc(pkt_len);
				memcpy(send_buf, buf, pkt_len);
			}
			__output_rtp(mp, ch, ch->handler, send_buf, inout.len, ch->first_ts
					+ enc->avpkt->pts / enc->def->clockrate_mult,
					ch->rtp_mark ? 1 : 0, -1, 0,
					payload_type, 0);
			mp->ssrc_out->parent->seq_diff++;
			ch->rtp_mark = 0;
		} while (repeats--);

		if (ret == 0) {
			// no more to go
			break;
		}

		// loop around and get more
		in_pkt = NULL;
	}

	return 0;
}

static void __dtmf_detect(struct codec_ssrc_handler *ch, AVFrame *frame) {
	if (!ch->dtmf_dsp)
		return;
	if (ch->handler->dtmf_payload_type == -1 || !ch->handler->pcm_dtmf_detect) {
		ch->dtmf_event.code = 0;
		return;
	}

	AVFrame *dsp_frame = resample_frame(&ch->dtmf_resampler, frame, &ch->dtmf_format);
	if (!dsp_frame) {
		ilogs(transcoding, LOG_ERR | LOG_FLAG_LIMIT, "Failed to resample audio for DTMF DSP");
		return;
	}

	ilogs(transcoding, LOG_DEBUG, "DTMF detect, TS %lu -> %lu, %u -> %u samples",
			(unsigned long) frame->pts,
			(unsigned long) dsp_frame->pts,
			frame->nb_samples,
			dsp_frame->nb_samples);

	if (dsp_frame->pts > ch->dtmf_ts)
		dtmf_rx_fillin(ch->dtmf_dsp, dsp_frame->pts - ch->dtmf_ts);
	else if (dsp_frame->pts < ch->dtmf_ts)
		ilogs(transcoding, LOG_ERR | LOG_FLAG_LIMIT, "DTMF TS seems to run backwards (%lu < %lu)",
				(unsigned long) dsp_frame->pts,
				(unsigned long) ch->dtmf_ts);

	int num_samples = dsp_frame->nb_samples;
	int16_t *samples = (void *) dsp_frame->extended_data[0];
	while (num_samples > 0) {
		int ret = dtmf_rx(ch->dtmf_dsp, samples, num_samples);
		if (ret < 0 || ret >= num_samples) {
			ilogs(transcoding, LOG_ERR | LOG_FLAG_LIMIT, "DTMF DSP returned error %i", ret);
			break;
		}
		samples += num_samples - ret;
		num_samples = ret;
	}
	ch->dtmf_ts = dsp_frame->pts + dsp_frame->nb_samples;
	av_frame_free(&dsp_frame);
}

static int packet_decoded_common(decoder_t *decoder, AVFrame *frame, void *u1, void *u2,
		int (*input_func)(encoder_t *enc, AVFrame *frame,
			int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2))
{
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilogs(transcoding, LOG_DEBUG, "RTP media successfully decoded: TS %llu, samples %u",
			(unsigned long long) frame->pts, frame->nb_samples);

	// switch from input codec context to output context if necessary
	struct codec_ssrc_handler *new_ch = __output_ssrc_handler(ch, mp);
	if (new_ch != ch) {
		// copy some essential parameters
		if (!new_ch->first_ts)
			new_ch->first_ts = ch->first_ts;

		ch = new_ch;
	}

	struct codec_handler *h = ch->handler;
	if (h->stats_entry) {
		int idx = rtpe_now.tv_sec & 1;
		atomic64_add(&h->stats_entry->pcm_samples[idx], frame->nb_samples);
		atomic64_add(&h->stats_entry->pcm_samples[2], frame->nb_samples);
	}

	if (ch->skip_pts) {
		if (frame->nb_samples <= 0)
			;
		else if (frame->nb_samples < ch->skip_pts)
			ch->skip_pts -= frame->nb_samples;
		else
			ch->skip_pts = 0;
		ilogs(transcoding, LOG_DEBUG, "Discarding %i samples", frame->nb_samples);
		goto discard;
	}

	if (G_UNLIKELY(!ch->encoder)) {
		ilogs(transcoding, LOG_INFO | LOG_FLAG_LIMIT,
				"Discarding decoded %i PCM samples due to lack of output encoder",
				frame->nb_samples);
		goto discard;
	}

	__dtmf_detect(ch, frame);
	__silence_detect(ch, frame);

	// locking deliberately ignored
	if (mp->media_out)
		ch->encoder->codec_options.amr.cmr = mp->media_out->u.amr.cmr;

	input_func(ch->encoder, frame, h->packet_encoded, ch, mp);

discard:
	av_frame_free(&frame);
	obj_put(&new_ch->h);

	return 0;
}

static int packet_decoded_fifo(decoder_t *decoder, AVFrame *frame, void *u1, void *u2) {
	return packet_decoded_common(decoder, frame, u1, u2, encoder_input_fifo);
}
static int packet_decoded_direct(decoder_t *decoder, AVFrame *frame, void *u1, void *u2) {
	return packet_decoded_common(decoder, frame, u1, u2, encoder_input_data);
}

static int __rtp_decode(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	int ret = decoder_input_data_ptime(ch->decoder, packet->payload, packet->ts, &mp->ptime,
			ch->handler->packet_decoded,
			ch, mp);
	mp->ssrc_out->parent->seq_diff--;
	return ret;
}
static int packet_decode(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	int ret = 0;

	if (!ch->first_ts)
		ch->first_ts = packet->ts;
	ch->last_ts = packet->ts;

	if (input_ch->dtmf_start_ts && !rtpe_config.dtmf_no_suppress) {
		if ((packet->ts > input_ch->dtmf_start_ts && packet->ts - input_ch->dtmf_start_ts > 80000) ||
				(packet->ts < input_ch->dtmf_start_ts && input_ch->dtmf_start_ts - packet->ts > 80000)) {
			ilogs(transcoding, LOG_DEBUG, "Resetting decoder DTMF state due to TS discrepancy");
			input_ch->dtmf_start_ts = 0;
		}
		else {
			ilogs(transcoding, LOG_DEBUG, "Decoder is in DTMF state, discaring codec packet");
			if (mp->ssrc_out)
				mp->ssrc_out->parent->seq_diff--;
			goto out;
		}
	}

	if (__buffer_dtx(input_ch->dtx_buffer, ch, input_ch, packet, mp, __rtp_decode))
		ret = 1; // consumed
	else {
		ilogs(transcoding, LOG_DEBUG, "Decoding RTP packet now");
		ret = __rtp_decode(ch, input_ch, packet, mp);
		ret = ret ? -1 : 0;
	}

out:
	return ret;
}

#endif


void codec_update_all_handlers(struct call_monologue *ml) {
	for (GList *l = ml->subscribers.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		struct call_monologue *sink = cs->monologue;

		// iterate both simultaneously
		GList *source_media_it = ml->medias.head;
		GList *sink_media_it = sink->medias.head;
		while (source_media_it && sink_media_it) {
			struct call_media *source_media = source_media_it->data;
			struct call_media *sink_media = sink_media_it->data;
			codec_handlers_update(source_media, sink_media, NULL, NULL);
			source_media_it = source_media_it->next;
			sink_media_it = sink_media_it->next;
		}
	}

	dialogue_unkernelize(ml);
}


void codec_calc_jitter(struct ssrc_ctx *ssrc, unsigned long ts, unsigned int clockrate,
		const struct timeval *tv)
{
	if (!ssrc || !clockrate)
		return;
	struct ssrc_entry_call *sec = ssrc->parent;

	// RFC 3550 A.8
	uint32_t transit = (((timeval_us(tv) / 1000) * clockrate) / 1000) - ts;
	mutex_lock(&sec->h.lock);
	int32_t d = 0;
	if (sec->transit)
		d = transit - sec->transit;
	sec->transit = transit;
	if (d < 0)
		d = -d;
	sec->jitter += d - ((sec->jitter + 8) >> 4);
	mutex_unlock(&sec->h.lock);
}
static void codec_calc_lost(struct ssrc_ctx *ssrc, uint16_t seq) {
	struct ssrc_entry_call *s = ssrc->parent;

	LOCK(&s->h.lock);

	// XXX shared code from kernel module

	uint32_t last_seq = s->last_seq_tracked;
	uint32_t new_seq = last_seq;

	// old seq or seq reset?
	uint16_t old_seq_trunc = last_seq & 0xffff;
	uint16_t seq_diff = seq - old_seq_trunc;
	if (seq_diff == 0 || seq_diff >= 0xfeff) // old/dup seq - ignore
		;
	else if (seq_diff > 0x100) {
		// reset seq and loss tracker
		new_seq = seq;
		s->last_seq_tracked = seq;
		s->lost_bits = -1;
	}
	else {
		// seq wrap?
		new_seq = (last_seq & 0xffff0000) | seq;
		while (new_seq < last_seq) {
			new_seq += 0x10000;
			if ((new_seq & 0xffff0000) == 0) // ext seq wrapped
				break;
		}
		seq_diff = new_seq - last_seq;
		s->last_seq_tracked = new_seq;

		// shift loss tracker bit field and count losses
		if (seq_diff >= (sizeof(s->lost_bits) * 8)) {
			// complete loss
			s->packets_lost += sizeof(s->lost_bits) * 8;
			s->lost_bits = -1;
		}
		else {
			while (seq_diff) {
				// shift out one bit and see if we lost it
				if ((s->lost_bits & 0x80000000) == 0)
					s->packets_lost++;
				s->lost_bits <<= 1;
				seq_diff--;
			}
		}
	}

	// track this frame as being seen
	seq_diff = (new_seq & 0xffff) - seq;
	if (seq_diff < (sizeof(s->lost_bits) * 8))
		s->lost_bits |= (1 << seq_diff);
}


#ifdef WITH_TRANSCODING


static int handler_func_transcode(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);
	if (!handler_silence_block(h, mp))
		return 0;

	// use main codec handler for supp codecs
	if (h->source_pt.codec_def->supplemental) {
		h->input_handler = __input_handler(h, mp);
		h->output_handler = h->input_handler;
	}
	else
		h->input_handler = h;

	// create new packet and insert it into sequencer queue

	ilogs(transcoding, LOG_DEBUG, "Received RTP packet: SSRC %" PRIx32 ", PT %u, seq %u, TS %u, len %zu",
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

	codec_calc_jitter(mp->ssrc_in, ntohl(mp->rtp->timestamp), h->input_handler->source_pt.clock_rate,
			&mp->tv);

	if (h->stats_entry) {
		unsigned int idx = rtpe_now.tv_sec & 1;
		int last_tv_sec = g_atomic_int_get(&h->stats_entry->last_tv_sec[idx]);
		if (last_tv_sec != (int) rtpe_now.tv_sec) {
			if (g_atomic_int_compare_and_exchange(&h->stats_entry->last_tv_sec[idx],
						last_tv_sec, rtpe_now.tv_sec))
			{
				// new second - zero out stats. slight race condition here
				atomic64_set(&h->stats_entry->packets_input[idx], 0);
				atomic64_set(&h->stats_entry->bytes_input[idx], 0);
				atomic64_set(&h->stats_entry->pcm_samples[idx], 0);
			}
		}
		atomic64_inc(&h->stats_entry->packets_input[idx]);
		atomic64_add(&h->stats_entry->bytes_input[idx], mp->payload.len);
		atomic64_inc(&h->stats_entry->packets_input[2]);
		atomic64_add(&h->stats_entry->bytes_input[2], mp->payload.len);
	}

	struct transcode_packet *packet = g_slice_alloc0(sizeof(*packet));
	packet->func = packet_decode;
	packet->rtp = *mp->rtp;
	packet->handler = h;

	if (h->source_pt.codec_def->dtmf && h->dest_pt.codec_def->dtmf) {
		// DTMF scaler
		packet->func = packet_dtmf;
		packet->dup_func = packet_dtmf_dup;
	}

	int ret = __handler_func_sequencer(mp, packet);

	return ret;
}

static int handler_func_playback(struct codec_handler *h, struct media_packet *mp) {
	decoder_input_data(h->ssrc_handler->decoder, &mp->payload, mp->rtp->timestamp,
			h->packet_decoded, h->ssrc_handler, mp);
	return 0;
}

static int handler_func_inject_dtmf(struct codec_handler *h, struct media_packet *mp) {
	h->input_handler = __input_handler(h, mp);
	h->output_handler = h->input_handler;

	struct codec_ssrc_handler *ch = get_ssrc(mp->ssrc_in->parent->h.ssrc, h->ssrc_hash);
	if (!ch)
		return 0;
	decoder_input_data(ch->decoder, &mp->payload, mp->rtp->timestamp,
			h->packet_decoded, ch, mp);
	obj_put(&ch->h);
	return 0;
}






// special return value `(void *) 0x1` to signal type mismatch
static struct rtp_payload_type *codec_make_payload_type_sup(const str *codec_str, struct call_media *media) {
	struct rtp_payload_type *ret = codec_make_payload_type(codec_str, media->type_id);
	if (!ret)
		return NULL;

	if (!ret->codec_def || (media->type_id && ret->codec_def->media_type != media->type_id)) {
		payload_type_free(ret);
		return (void *) 0x1;
	}
	// we must support both encoding and decoding
	if (!ret->codec_def->support_decoding)
		goto err;
	if (!ret->codec_def->support_encoding)
		goto err;
	if (ret->codec_def->default_channels <= 0 || ret->codec_def->default_clockrate < 0)
		goto err;

	return ret;


err:
	payload_type_free(ret);
	return NULL;

}


static struct rtp_payload_type *codec_add_payload_type(const str *codec, struct call_media *media,
		struct call_media *other_media, struct codec_store *extra_cs)
{
	struct rtp_payload_type *pt = codec_make_payload_type_sup(codec, media);
	if (!pt) {
		ilogs(codec, LOG_WARN, "Codec '" STR_FORMAT "' requested for transcoding is not supported",
				STR_FMT(codec));
		return NULL;
	}
	if (pt == (void *) 0x1)
		return NULL;

	pt->payload_type = __unused_pt_number(media, other_media, extra_cs, pt);
	if (pt->payload_type < 0) {
		ilogs(codec, LOG_WARN, "Ran out of RTP payload type numbers while adding codec '"
				STR_FORMAT "' for transcoding",
			STR_FMT(&pt->encoding_with_params));
		payload_type_free(pt);
		return NULL;
	}

	return pt;
}


#endif





void payload_type_clear(struct rtp_payload_type *p) {
	g_queue_clear_full(&p->rtcp_fb, free);
	str_free_dup(&p->encoding);
	str_free_dup(&p->encoding_parameters);
	str_free_dup(&p->encoding_with_params);
	str_free_dup(&p->encoding_with_full_params);
	str_free_dup(&p->format_parameters);
	str_free_dup(&p->codec_opts);
	ZERO(*p);
	p->payload_type = -1;
}
void payload_type_free(struct rtp_payload_type *p) {
	payload_type_clear(p);
	g_slice_free1(sizeof(*p), p);
}


// dst must be pre-initialised (zeroed)
static void rtp_payload_type_copy(struct rtp_payload_type *dst, const struct rtp_payload_type *src) {
	payload_type_clear(dst);

	*dst = *src;

	// make shallow copy of lists
	g_queue_init(&dst->rtcp_fb);
	g_queue_append(&dst->rtcp_fb, &src->rtcp_fb);

	// duplicate contents
	codec_init_payload_type(dst, MT_UNKNOWN);
}

struct rtp_payload_type *rtp_payload_type_dup(const struct rtp_payload_type *pt) {
	struct rtp_payload_type *pt_copy = g_slice_alloc0(sizeof(*pt));
	rtp_payload_type_copy(pt_copy, pt);
	return pt_copy;
}
static void __rtp_payload_type_add_name(GHashTable *ht, struct rtp_payload_type *pt) {
	GQueue *q = g_hash_table_lookup_queue_new(ht, str_dup(&pt->encoding), free);
	g_queue_push_tail(q, GINT_TO_POINTER(pt->payload_type));
	q = g_hash_table_lookup_queue_new(ht, str_dup(&pt->encoding_with_params), free);
	g_queue_push_tail(q, GINT_TO_POINTER(pt->payload_type));
	q = g_hash_table_lookup_queue_new(ht, str_dup(&pt->encoding_with_full_params), free);
	g_queue_push_tail(q, GINT_TO_POINTER(pt->payload_type));
}
#ifdef WITH_TRANSCODING
static void __insert_codec_tracker(GHashTable *all_clockrates, GHashTable *all_supp_codecs,
		struct codec_tracker *sct, GList *link)
{
	struct rtp_payload_type *pt = link->data;

	if (!pt->codec_def || !pt->codec_def->supplemental)
		g_hash_table_replace(all_clockrates, GUINT_TO_POINTER(pt->clock_rate),
				GUINT_TO_POINTER(GPOINTER_TO_UINT(
						g_hash_table_lookup(all_clockrates,
							GUINT_TO_POINTER(pt->clock_rate))) + 1));
	else {
		GHashTable *clockrates = g_hash_table_lookup(all_supp_codecs, &pt->encoding);
		if (!clockrates) {
			clockrates = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
					(GDestroyNotify) g_queue_free);
			g_hash_table_replace(all_supp_codecs, str_dup(&pt->encoding), clockrates);
		}
		GQueue *entries = g_hash_table_lookup_queue_new(clockrates, GUINT_TO_POINTER(pt->clock_rate),
				NULL);
		g_queue_push_tail(entries, link);
	}
}
#endif
static int __codec_options_set1(struct call *call, struct rtp_payload_type *pt, const str *enc,
		GHashTable *codec_set)
{
	str *pt_str = g_hash_table_lookup(codec_set, enc);
	if (!pt_str)
		return 0;
	struct rtp_payload_type *pt_parsed = codec_make_payload_type(pt_str, MT_UNKNOWN);
	if (!pt_parsed)
		return 0;
	// match parameters
	if (pt->clock_rate != pt_parsed->clock_rate || pt->channels != pt_parsed->channels) {
		payload_type_free(pt_parsed);
		return 0;
	}
	// match - apply options
	if (!pt->bitrate)
		pt->bitrate = pt_parsed->bitrate;
	if (!pt->codec_opts.len && pt_parsed->codec_opts.len) {
		str_free_dup(&pt->codec_opts);
		pt->codec_opts = pt_parsed->codec_opts;
		pt_parsed->codec_opts = STR_NULL;
	}
	payload_type_free(pt_parsed);
	return 1;
}
static void __codec_options_set(struct call *call, struct rtp_payload_type *pt, GHashTable *codec_set) {
	if (!call)
		return;
	if (!codec_set)
		return;
	if (__codec_options_set1(call, pt, &pt->encoding_with_full_params, codec_set))
		return;
	if (__codec_options_set1(call, pt, &pt->encoding_with_params, codec_set))
		return;
	if (__codec_options_set1(call, pt, &pt->encoding, codec_set))
		return;
}
static void codec_tracker_destroy(struct codec_tracker **sct) {
#ifdef WITH_TRANSCODING
	if (!*sct)
		return;
	g_hash_table_destroy((*sct)->touched);
	g_slice_free1(sizeof(**sct), *sct);
	*sct = NULL;
#endif
}
static struct codec_tracker *codec_tracker_init(void) {
#ifdef WITH_TRANSCODING
	struct codec_tracker *ret = g_slice_alloc0(sizeof(*ret));
	ret->touched = g_hash_table_new(g_direct_hash, g_direct_equal);
	return ret;
#else
	return NULL;
#endif
}
static void codec_touched(struct codec_store *cs, struct rtp_payload_type *pt) {
#ifdef WITH_TRANSCODING
	if (pt->codec_def && pt->codec_def->supplemental) {
		cs->tracker->all_touched = 1;
		return;
	}
	g_hash_table_replace(cs->tracker->touched, GUINT_TO_POINTER(pt->clock_rate), (void *) 0x1);
#endif
}
static int is_codec_touched(struct codec_store *cs, struct rtp_payload_type *pt) {
#ifdef WITH_TRANSCODING
	if (!cs || !cs->tracker || !cs->tracker->touched)
		return 0;
	if (cs->tracker->all_touched)
		return 1;
	return g_hash_table_lookup(cs->tracker->touched, GINT_TO_POINTER(pt->clock_rate)) ? 1 : 0;
#else
	return 0;
#endif
}
#ifdef WITH_TRANSCODING
static int ptr_cmp(const void *a, const void *b) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}
void codec_tracker_update(struct codec_store *cs) {
	if (!cs)
		return;
	struct codec_tracker *sct = cs->tracker;
	if (!sct)
		return;

	ilogs(codec, LOG_DEBUG, "Updating supplemental codecs for " STR_FORMAT " #%u",
			STR_FMT(&cs->media->monologue->tag),
			cs->media->index);

	// build our tables
	GHashTable *all_clockrates = g_hash_table_new(g_direct_hash, g_direct_equal);
	GHashTable *all_supp_codecs = g_hash_table_new_full(str_case_hash, str_case_equal, free,
			(GDestroyNotify) g_hash_table_destroy);
	for (GList *l = cs->codec_prefs.head; l; l = l->next)
		__insert_codec_tracker(all_clockrates, all_supp_codecs, sct, l);

	// get all supported audio clock rates
	GList *clockrates = g_hash_table_get_keys(all_clockrates);
	// and to ensure consistent results
	clockrates = g_list_sort(clockrates, ptr_cmp);

	// for each supplemental codec supported ...
	GList *supp_codecs = g_hash_table_get_keys(all_supp_codecs);

	for (GList *l = supp_codecs; l; l = l->next) {
		// ... compare the list of clock rates against the clock rates supported by the audio codecs
		str *supp_codec = l->data;
		GHashTable *supp_clockrates = g_hash_table_lookup(all_supp_codecs, supp_codec);

		// iterate audio clock rates and check against supp clockrates
		for (GList *k = clockrates; k; k = k->next) {
			unsigned int clockrate = GPOINTER_TO_UINT(k->data);

			// has it been removed?
			if (!g_hash_table_lookup(all_clockrates, GUINT_TO_POINTER(clockrate)))
				continue;

			// is this already supported?
			if (g_hash_table_lookup(supp_clockrates, GUINT_TO_POINTER(clockrate))) {
				// good, remember this
				g_hash_table_remove(supp_clockrates, GUINT_TO_POINTER(clockrate));
				continue;
			}

			// ignore if we haven't touched anything with that clock rate
			if (!sct->all_touched && !g_hash_table_lookup(sct->touched, GUINT_TO_POINTER(clockrate)))
				continue;

			ilogs(codec, LOG_DEBUG, "Adding supplemental codec " STR_FORMAT " for clock rate %u", STR_FMT(supp_codec), clockrate);

			char *pt_s = g_strdup_printf(STR_FORMAT "/%u", STR_FMT(supp_codec), clockrate);
			str pt_str;
			str_init(&pt_str, pt_s);

			struct rtp_payload_type *pt = codec_add_payload_type(&pt_str, cs->media, NULL, NULL);
			if (!pt)
				continue;
			pt->for_transcoding = 1;

			codec_store_add_raw_order(cs, pt);
			g_free(pt_s);
		}

		// finally check which clock rates are left over and remove those
		GList *to_remove = g_hash_table_get_keys(supp_clockrates);
		while (to_remove) {
			unsigned int clockrate = GPOINTER_TO_UINT(to_remove->data);
			to_remove = g_list_delete_link(to_remove, to_remove);

			// ignore if we haven't touched anything with that clock rate
			if (!sct->all_touched && !g_hash_table_lookup(sct->touched, GUINT_TO_POINTER(clockrate)))
				continue;

			GQueue *entries = g_hash_table_lookup(supp_clockrates, GUINT_TO_POINTER(clockrate));
			for (GList *j = entries->head; j; j = j->next) {
				GList *link = j->data;
				struct rtp_payload_type *pt = link->data;

				ilogs(codec, LOG_DEBUG, "Eliminating supplemental codec " STR_FORMAT " (%i) with "
						"stray clock rate %u",
						STR_FMT(&pt->encoding_with_params), pt->payload_type, clockrate);
				__codec_store_delete_link(link, cs);
			}
		}
	}

	g_list_free(supp_codecs);
	g_list_free(clockrates);
	g_hash_table_destroy(all_clockrates);
	g_hash_table_destroy(all_supp_codecs);
}
#endif

void codec_store_cleanup(struct codec_store *cs) {
	if (cs->codecs)
		g_hash_table_destroy(cs->codecs);
	if (cs->codec_names)
		g_hash_table_destroy(cs->codec_names);
	g_queue_clear_full(&cs->codec_prefs, (GDestroyNotify) payload_type_free);
	cs->supp_link = NULL;
	codec_tracker_destroy(&cs->tracker);
	ZERO(*cs);
}

void codec_store_init(struct codec_store *cs, struct call_media *media) {
	if (!media)
		media = cs->media;

	codec_store_cleanup(cs);

	cs->codecs = g_hash_table_new(g_direct_hash, g_direct_equal);
	cs->codec_names = g_hash_table_new_full(str_case_hash, str_case_equal, free,
			(void (*)(void*)) g_queue_free);
	cs->media = media;
	cs->tracker = codec_tracker_init();
}

static void codec_store_move(struct codec_store *dst, struct codec_store *src) {
	*dst = *src;
	ZERO(*src);
	codec_store_init(src, dst->media);
}

static void codec_store_add_raw_link(struct codec_store *cs, struct rtp_payload_type *pt, GList *link) {
	// cs->media may be NULL
	ensure_codec_def(pt, cs->media);
	if (cs->media && cs->media->ptime > 0)
		pt->ptime = cs->media->ptime;

	ilogs(internals, LOG_DEBUG, "Adding codec '" STR_FORMAT "'/'" STR_FORMAT "'/'" STR_FORMAT "' at pos %p",
			STR_FMT(&pt->encoding),
			STR_FMT(&pt->encoding_with_params),
			STR_FMT(&pt->encoding_with_full_params), link);
	g_hash_table_insert(cs->codecs, GINT_TO_POINTER(pt->payload_type), pt);
	__rtp_payload_type_add_name(cs->codec_names, pt);
	if (!link)
		g_queue_push_tail(&cs->codec_prefs, pt);
	else
		g_queue_insert_before(&cs->codec_prefs, link, pt);
	pt->prefs_link = cs->codec_prefs.tail;
	if (!cs->supp_link && pt->codec_def && pt->codec_def->supplemental)
		cs->supp_link = pt->prefs_link;
}

// appends to the end, but before supplemental codecs
static void codec_store_add_raw_order(struct codec_store *cs, struct rtp_payload_type *pt) {
	codec_store_add_raw_link(cs, pt, cs->supp_link);
}
// appends to the end
void codec_store_add_raw(struct codec_store *cs, struct rtp_payload_type *pt) {
	codec_store_add_raw_link(cs, pt, NULL);
}

static void codec_store_add_link(struct codec_store *cs, struct rtp_payload_type *pt, GList *link) {
	if (!cs->media)
		return;

	ensure_codec_def(pt, cs->media);
	if (proto_is_not_rtp(cs->media->protocol))
		return;

	struct rtp_payload_type *copy = rtp_payload_type_dup(pt);
	codec_store_add_raw_link(cs, copy, link);
}

// appends to the end, but before supplemental codecs
static void codec_store_add_order(struct codec_store *cs, struct rtp_payload_type *pt) {
	codec_store_add_link(cs, pt, cs->supp_link);
}
// always add to end
static void codec_store_add_end(struct codec_store *cs, struct rtp_payload_type *pt) {
	codec_store_add_link(cs, pt, NULL);
}

void codec_store_populate_reuse(struct codec_store *dst, struct codec_store *src, GHashTable *codec_set) {
	// start fresh
	struct call_media *media = dst->media;
	struct call *call = media ? media->call : NULL;

	for (GList *l = src->codec_prefs.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		struct rtp_payload_type *orig_pt = g_hash_table_lookup(dst->codecs,
				GINT_TO_POINTER(pt->payload_type));
		ilogs(codec, LOG_DEBUG, "Adding codec " STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				pt->payload_type);
				
		if (!orig_pt) {
			__codec_options_set(call, pt, codec_set);
			codec_store_add_end(dst, pt);
		}
	}
	if(dst->codec_prefs.head){
		for (GList *l = dst->codec_prefs.head; l;) {
			struct rtp_payload_type *pt = l->data;
			struct rtp_payload_type *orig_pt = g_hash_table_lookup(src->codecs,
					GINT_TO_POINTER(pt->payload_type));
			if(!orig_pt){
				l = __codec_store_delete_link(l, dst);
			}else{
				l = l->next;
			}
		}
	}
}

void codec_store_populate(struct codec_store *dst, struct codec_store *src, GHashTable *codec_set) {
	// start fresh
	struct codec_store orig_dst;
	codec_store_move(&orig_dst, dst);

	struct call_media *media = dst->media;
	struct call *call = media ? media->call : NULL;

	for (GList *l = src->codec_prefs.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		struct rtp_payload_type *orig_pt = g_hash_table_lookup(orig_dst.codecs,
				GINT_TO_POINTER(pt->payload_type));
		ilogs(codec, LOG_DEBUG, "Adding codec " STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				pt->payload_type);
		if (orig_pt) {
			// carry over existing options
			pt->ptime = orig_pt->ptime;
			pt->for_transcoding = orig_pt->for_transcoding;
			pt->accepted = orig_pt->accepted;
			pt->bitrate = orig_pt->bitrate;
			str_free_dup(&pt->codec_opts);
			pt->codec_opts = orig_pt->codec_opts;
			orig_pt->codec_opts = STR_NULL;
		}
		__codec_options_set(call, pt, codec_set);
		codec_store_add_end(dst, pt);
	}

	codec_store_cleanup(&orig_dst);
}

void codec_store_strip(struct codec_store *cs, GQueue *strip, GHashTable *except) {
	for (GList *l = strip->head; l; l = l->next) {
		str *codec = l->data;
		if (!str_cmp(codec, "all") || !str_cmp(codec, "full")) {
			if (!str_cmp(codec, "all"))
				cs->strip_all = 1;
			else
				cs->strip_full = 1;

			// strip all except ...
			GList *link = cs->codec_prefs.head;
			while (link) {
				GList *next = link->next;
				struct rtp_payload_type *pt = link->data;
				if (except && g_hash_table_lookup(except, &pt->encoding))
					;
				else if (except && g_hash_table_lookup(except, &pt->encoding_with_params))
					;
				else if (except && g_hash_table_lookup(except, &pt->encoding_with_full_params))
					;
				else {
					ilogs(codec, LOG_DEBUG, "Stripping codec " STR_FORMAT
							" (%i) due to strip=all or strip=full",
							STR_FMT(&pt->encoding_with_params),
							pt->payload_type);
					codec_touched(cs, pt);
					next = __codec_store_delete_link(link, cs);
				}
				link = next;
			}
			continue;
		}
		// strip just this one
		GQueue *pts = g_hash_table_lookup(cs->codec_names, codec);
		if (!pts || !pts->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" not present for stripping",
					STR_FMT(codec));
			continue;
		}
		while (pts->length) {
			int pt_num = GPOINTER_TO_INT(pts->head->data);
			struct rtp_payload_type *pt = g_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num));
			if (pt) {
				ilogs(codec, LOG_DEBUG, "Stripping codec " STR_FORMAT " (%i)",
						STR_FMT(&pt->encoding_with_params), pt_num);
				codec_touched(cs, pt);
				__codec_store_delete_link(pt->prefs_link, cs);
				// this removes pts->head
			}
			else {
				ilogs(codec, LOG_DEBUG, "PT %i missing for stripping " STR_FORMAT, pt_num,
						STR_FMT(codec));
				break; // should not happen - don't continue
			}
		}
	}
}

void codec_store_offer(struct codec_store *cs, GQueue *offer, struct codec_store *orig) {
	// restore stripped codecs in order: codecs must be present in `orig` but not present
	// in `cs`
	for (GList *l = offer->head; l; l = l->next) {
		str *codec = l->data;
		GQueue *pts = g_hash_table_lookup(cs->codec_names, codec);
		if (pts && pts->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" already present (%i)",
					STR_FMT(codec), GPOINTER_TO_INT(pts->head->data));
			continue;
		}
		GQueue *orig_list = g_hash_table_lookup(orig->codec_names, codec);
		if (!orig_list || !orig_list->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" not present for offering",
					STR_FMT(codec));
			continue;
		}
		for (GList *l = orig_list->head; l; l = l->next) {
			int pt_num = GPOINTER_TO_INT(l->data);
			struct rtp_payload_type *orig_pt = g_hash_table_lookup(orig->codecs,
					GINT_TO_POINTER(pt_num));
			if (!orig_pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for offering " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			if (g_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num))) {
				ilogs(codec, LOG_DEBUG, "PT %i (" STR_FORMAT ") already preset", pt_num,
						STR_FMT(codec));
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Re-adding stripped codec " STR_FORMAT " (%i)",
					STR_FMT(&orig_pt->encoding_with_params), orig_pt->payload_type);
			codec_touched(cs, orig_pt);
			codec_store_add_order(cs, orig_pt);
		}
	}
}

void codec_store_accept(struct codec_store *cs, GQueue *accept, struct codec_store *orig) {
	// mark codecs as `for transcoding`
	for (GList *l = accept->head; l; l = l->next) {
		str *codec = l->data;
		GQueue *pts;
		int pts_is_full_list = 0; // bit of a hack
		if (!str_cmp(codec, "all") || !str_cmp(codec, "full")) {
			pts = &cs->codec_prefs;
			pts_is_full_list = 1;
		}
		else
			pts = g_hash_table_lookup(cs->codec_names, codec);
		if (!pts || !pts->length) {
			pts_is_full_list = 0;
			pts = NULL;
			// special case: strip=all, consume=X
			if (orig)
				pts = g_hash_table_lookup(orig->codec_names, codec);
			if (pts && pts->length) {
				// re-add from orig, then mark as accepted below
				// XXX duplicate code
				for (GList *k = pts->head; k; k = k->next) {
					int pt_num = GPOINTER_TO_INT(k->data);
					struct rtp_payload_type *orig_pt = g_hash_table_lookup(orig->codecs,
							GINT_TO_POINTER(pt_num));
					if (!orig_pt) {
						ilogs(codec, LOG_DEBUG, "PT %i missing for accepting " STR_FORMAT,
								pt_num,
								STR_FMT(codec));
						continue;
					}
					if (g_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num))) {
						ilogs(codec, LOG_DEBUG, "PT %i (" STR_FORMAT ") already preset",
								pt_num,
								STR_FMT(codec));
						continue;
					}
					ilogs(codec, LOG_DEBUG, "Re-adding stripped codec " STR_FORMAT " (%i)",
							STR_FMT(&orig_pt->encoding_with_params), orig_pt->payload_type);
					codec_touched(cs, orig_pt);
					codec_store_add_order(cs, orig_pt);
				}
				pts = g_hash_table_lookup(cs->codec_names, codec);
				if (!pts)
					continue;
				// drop down below
			}
			else {
				ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
						" not present for accepting",
						STR_FMT(codec));
				continue;
			}
		}
		for (GList *k = pts->head; k; k = k->next) {
			int pt_num;
			if (!pts_is_full_list)
				pt_num = GPOINTER_TO_INT(k->data);
			else {
				struct rtp_payload_type *fpt = k->data;
				pt_num = fpt->payload_type;
			}
			struct rtp_payload_type *pt = g_hash_table_lookup(cs->codecs,
					GINT_TO_POINTER(pt_num));
			if (!pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for accepting " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Accepting codec " STR_FORMAT " (%i)",
					STR_FMT(&pt->encoding_with_params), pt->payload_type);
			pt->for_transcoding = 1;
			pt->accepted = 1;
			codec_touched(cs, pt);
		}
	}
}

int codec_store_accept_one(struct codec_store *cs, GQueue *accept, bool accept_any) {
	// local codec-accept routine: accept first supported codec, or first from "accept" list
	// if given

	struct rtp_payload_type *accept_pt = NULL;

	for (GList *l = accept ? accept->head : NULL; l; l = l->next) {
		// iterate through list and look for the first supported codec
		str *codec = l->data;
		if (!str_cmp(codec, "any")) {
			accept_any = true;
			continue;
		}
		GQueue *pts = g_hash_table_lookup(cs->codec_names, codec);
		if (!pts)
			continue;
		for (GList *k = pts->head; k; k = k->next) {
			int pt_num = GPOINTER_TO_INT(k->data);
			struct rtp_payload_type *pt = g_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num));
			if (!pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for accepting " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			accept_pt = pt;
			break;
		}
		if (accept_pt)
			break;
	}

	if (!accept_pt) {
		// none found yet - pick the first one
		for (GList *l = cs->codec_prefs.head; l; l = l->next) {
			struct rtp_payload_type *pt = l->data;
			if (!accept_any) {
				ensure_codec_def(pt, cs->media);
				if (!pt->codec_def)
					continue;
			}
			accept_pt = pt;
			break;
		}
	}

	if (!accept_pt) {
		ilogs(codec, LOG_WARN, "No acceptable codecs found from publisher");
		return -1;
	}

	// delete all codecs except the accepted one
	GList *link = cs->codec_prefs.head;
	while (link) {
		struct rtp_payload_type *pt = link->data;
		if (pt == accept_pt) {
			link = link->next;
			continue;
		}
		link = __codec_store_delete_link(link, cs);
	}

	return 0;
}

void codec_store_track(struct codec_store *cs, GQueue *q) {
#ifdef WITH_TRANSCODING
	// just track all codecs from the list as "touched"
	for (GList *l = q->head; l; l = l->next) {
		str *codec = l->data;
		if (!str_cmp(codec, "all") || !str_cmp(codec, "full")) {
			cs->tracker->all_touched = 1;
			continue;
		}
		GQueue *pts = g_hash_table_lookup(cs->codec_names, codec);
		if (!pts)
			continue;
		for (GList *k = pts->head; k; k = k->next) {
			int pt_num = GPOINTER_TO_INT(k->data);
			struct rtp_payload_type *pt = g_hash_table_lookup(cs->codecs,
					GINT_TO_POINTER(pt_num));
			codec_touched(cs, pt);
		}
	}
#endif
}

void codec_store_transcode(struct codec_store *cs, GQueue *offer, struct codec_store *orig) {
#ifdef WITH_TRANSCODING
	// special case of codec_store_offer(): synthesise codecs that were not already present
	for (GList *l = offer->head; l; l = l->next) {
		str *codec = l->data;
		GQueue *pts = g_hash_table_lookup(cs->codec_names, codec);
		if (pts && pts->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" already present (%i)",
					STR_FMT(codec), GPOINTER_TO_INT(pts->head->data));
			continue;
		}
		GQueue *orig_list = g_hash_table_lookup(orig->codec_names, codec);
		if (!orig_list || !orig_list->length || cs->strip_full) {
			ilogs(codec, LOG_DEBUG, "Adding codec " STR_FORMAT
					" for transcoding",
					STR_FMT(codec));
			// create new payload type
			struct rtp_payload_type *pt = codec_add_payload_type(codec, cs->media, NULL, orig);
			if (!pt)
				continue;
			pt->for_transcoding = 1;

			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT " added for transcoding with payload "
					"type %i",
					STR_FMT(&pt->encoding_with_params), pt->payload_type);
			codec_touched(cs, pt);
			codec_store_add_raw_order(cs, pt);
			continue;
		}
		// XXX duplicate code
		for (GList *l = orig_list->head; l; l = l->next) {
			int pt_num = GPOINTER_TO_INT(l->data);
			struct rtp_payload_type *orig_pt = g_hash_table_lookup(orig->codecs,
					GINT_TO_POINTER(pt_num));
			if (!orig_pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for offering " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			if (g_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num))) {
				ilogs(codec, LOG_DEBUG, "PT %i (" STR_FORMAT ") already preset", pt_num,
						STR_FMT(codec));
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Re-adding stripped codec " STR_FORMAT " (%i)",
					STR_FMT(&orig_pt->encoding_with_params), orig_pt->payload_type);
			codec_touched(cs, orig_pt);
			codec_store_add_order(cs, orig_pt);
		}
	}
#endif
}

void codec_store_answer(struct codec_store *dst, struct codec_store *src, struct sdp_ng_flags *flags) {
	// retain existing setup for supplemental codecs, but start fresh otherwise
	struct codec_store orig_dst;
	codec_store_move(&orig_dst, dst);

	struct call_media *src_media = src->media;
	struct call_media *dst_media = dst->media;
	if (!dst_media || !src_media)
		goto out;

#ifdef WITH_TRANSCODING
	// synthetic answer for T.38:
	if (dst_media->type_id == MT_AUDIO && src_media->type_id == MT_IMAGE && dst->codec_prefs.length == 0) {
		if (dst_media->t38_gateway && dst_media->t38_gateway->pcm_player
				&& dst_media->t38_gateway->pcm_player->handler) {
			codec_store_add_order(dst, &dst_media->t38_gateway->pcm_player->handler->dest_pt);
			goto out;
		}
	}
#endif

	unsigned int num_codecs = 0;
	//int codec_order = 0; // to track whether we've added supplemental codecs based on their media codecs
	GQueue supp_codecs = G_QUEUE_INIT; // postpone actually adding them until the end

	// populate dst via output PTs from src's codec handlers
	for (GList *l = src->codec_prefs.head; l; l = l->next) {
		int add_codec = 1;
		if (flags && flags->single_codec && num_codecs >= 1)
			add_codec = 0;

		struct rtp_payload_type *pt = l->data;
		struct codec_handler *h = codec_handler_get(src_media, pt->payload_type, dst_media);
		if (!h || h->dest_pt.payload_type == -1) {
			// passthrough or missing
			if (pt->for_transcoding)
				ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
						" (%i) is being transcoded",
						STR_FMT(&pt->encoding_with_params),
						pt->payload_type);
			else {
				if (add_codec) {
					ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
							" (%i) is passthrough",
							STR_FMT(&pt->encoding_with_params),
							pt->payload_type);
					codec_store_add_end(dst, pt);
					num_codecs++;
				}
				else
					ilogs(codec, LOG_DEBUG, "Skipping passthrough codec " STR_FORMAT
							" (%i) due to single-codec flag",
							STR_FMT(&pt->encoding_with_params),
							pt->payload_type);
			}
			continue;
		}

		// supp codecs are handled in-line with their main media codecs
		int is_supp = 0;
		if (pt->codec_def && pt->codec_def->supplemental) {
			is_supp = 1;
			if (pt->for_transcoding)
				continue;
			if (is_codec_touched(dst, pt))
				continue;
			if (is_codec_touched(src, pt))
				continue;
			if (is_codec_touched(&orig_dst, pt))
				continue;
			// except those that were not touched - we pass those through regardless
		}

		if (!add_codec && !is_supp) {
			ilogs(codec, LOG_DEBUG, "Skipping reverse codec for " STR_FORMAT
					" (%i) = " STR_FORMAT " (%i) due to single-codec flag",
					STR_FMT(&pt->encoding_with_params),
					pt->payload_type,
					STR_FMT(&h->dest_pt.encoding_with_params),
					h->dest_pt.payload_type);
			continue;
		}
		ilogs(codec, LOG_DEBUG, "Reverse codec for " STR_FORMAT
				" (%i) is " STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				pt->payload_type,
				STR_FMT(&h->dest_pt.encoding_with_params),
				h->dest_pt.payload_type);
		if (!g_hash_table_lookup(dst->codecs, GINT_TO_POINTER(h->dest_pt.payload_type))) {
			if (h->passthrough)
				codec_store_add_end(dst, pt);
			else
				codec_store_add_end(dst, &h->dest_pt);
			num_codecs++;
		}

		// handle associated supplemental codecs
		if (h->cn_payload_type != -1) {
			pt = g_hash_table_lookup(orig_dst.codecs, GINT_TO_POINTER(h->cn_payload_type));
			if (!pt)
				ilogs(codec, LOG_DEBUG, "CN payload type %i is missing", h->cn_payload_type);
			else
				g_queue_push_tail(&supp_codecs, rtp_payload_type_dup(pt));
		}
		if (h->dtmf_payload_type != -1) {
			pt = g_hash_table_lookup(orig_dst.codecs, GINT_TO_POINTER(h->dtmf_payload_type));
			if (!pt)
				ilogs(codec, LOG_DEBUG, "DTMF payload type %i is missing", h->dtmf_payload_type);
			else
				g_queue_push_tail(&supp_codecs, rtp_payload_type_dup(pt));
		}
	}

	while (supp_codecs.length) {
		struct rtp_payload_type *pt = g_queue_pop_head(&supp_codecs);
		if (g_hash_table_lookup(dst->codecs, GINT_TO_POINTER(pt->payload_type))) {
			ilogs(codec, LOG_DEBUG, STR_FORMAT " payload type %i already present, skip",
					STR_FMT(&pt->encoding_with_full_params), pt->payload_type);
			payload_type_free(pt);
			continue;
		}
		ilogs(codec, LOG_DEBUG, "Adding " STR_FORMAT " payload type %i",
				STR_FMT(&pt->encoding_with_params), pt->payload_type);
		codec_store_add_raw(dst, pt);
	}

out:
	codec_store_cleanup(&orig_dst);
}

// offer codecs for non-RTP transcoding scenarios
void codec_store_synthesise(struct codec_store *dst, struct codec_store *opposite) {
	if (!dst->media || !opposite->media)
		return;
	if (dst->media->type_id == MT_AUDIO && opposite->media->type_id == MT_IMAGE) {
		// audio <> T.38 transcoder
		if (!dst->codec_prefs.length) {
			// no codecs given: add defaults
			static const str PCMU_str = STR_CONST_INIT("PCMU");
			static const str PCMA_str = STR_CONST_INIT("PCMA");
			codec_store_add_raw_order(dst, codec_make_payload_type(&PCMU_str, MT_AUDIO));
			codec_store_add_raw_order(dst, codec_make_payload_type(&PCMA_str, MT_AUDIO));

			ilogs(codec, LOG_DEBUG, "Using default codecs PCMU and PCMA for T.38 gateway");
		}
		else {
			// we already have a list of codecs - make sure they're all supported by us
			for (GList *l = dst->codec_prefs.head; l;) {
				struct rtp_payload_type *pt = l->data;
				if (pt->codec_def) {
					l = l->next;
					continue;
				}
				ilogs(codec, LOG_DEBUG, "Eliminating unsupported codec " STR_FORMAT
						" for T.38 transcoding",
						STR_FMT(&pt->encoding_with_params));
				codec_touched(dst, pt);
				l = __codec_store_delete_link(l, dst);
			}
		}
	}
}

// check all codecs listed in the source are also be present in the answer (dst)
bool codec_store_is_full_answer(const struct codec_store *src, const struct codec_store *dst) {
	for (GList *l = src->codec_prefs.head; l; l = l->next) {
		const struct rtp_payload_type *src_pt = l->data;
		const struct rtp_payload_type *dst_pt = g_hash_table_lookup(dst->codecs,
				GINT_TO_POINTER(src_pt->payload_type));
		if (!dst_pt || rtp_payload_type_cmp(src_pt, dst_pt)) {
			ilogs(codec, LOG_DEBUG, "Source codec " STR_FORMAT " is not present in the answer",
					STR_FMT(&src_pt->encoding_with_params));
			return false;
		}
	}
	return true;
}

static void codec_timers_run(void *p) {
	struct codec_timer *ct = p;
	ct->func(ct);
}

void codecs_init(void) {
	timerthread_init(&codec_timers_thread, codec_timers_run);
}
void codecs_cleanup(void) {
	timerthread_free(&codec_timers_thread);
}
void codec_timers_loop(void *p) {
	timerthread_run(&codec_timers_thread);
}
