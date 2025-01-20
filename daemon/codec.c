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
#include "audio_player.h"
#ifdef WITH_TRANSCODING
#include "fix_frame_channel_layout.h"
#endif
#include "bufferpool.h"

struct codec_timer {
	struct timerthread_obj tt_obj;
	struct timeval next;
	void (*timer_func)(struct codec_timer *);
};
struct mqtt_timer {
	struct codec_timer ct;
	struct mqtt_timer **self;
	call_t *call;
	struct call_media *media;
};
struct timer_callback {
	struct codec_timer ct;
	void (*timer_callback_func)(call_t *, codec_timer_callback_arg_t);
	call_t *call;
	codec_timer_callback_arg_t arg;
};

typedef void (*raw_input_func_t)(struct media_packet *mp, unsigned int);

static void __buffer_delay_raw(struct delay_buffer *dbuf, struct codec_handler *handler,
		raw_input_func_t input_func, struct media_packet *mp, unsigned int clockrate);


static codec_handler_func handler_func_passthrough;
static struct timerthread codec_timers_thread;

static void rtp_payload_type_copy(rtp_payload_type *dst, const rtp_payload_type *src);
static void codec_store_add_raw_order(struct codec_store *cs, rtp_payload_type *pt);
static rtp_payload_type *codec_store_find_compatible(struct codec_store *cs,
		const rtp_payload_type *pt);
static void __rtp_payload_type_add_name(codec_names_ht, rtp_payload_type *pt);
static void codec_calc_lost(struct ssrc_ctx *ssrc, uint16_t seq);
static void __codec_options_set(call_t *call, rtp_payload_type *pt, str_case_value_ht codec_set);


static struct codec_handler codec_handler_stub = {
	.source_pt.payload_type = -1,
	.dest_pt.payload_type = -1,
	.handler_func = handler_func_passthrough,
	.kernelize = 1,
	.passthrough = 1,
};



static void __ht_queue_del(codec_names_ht ht, const str *key, int pt) {
	GQueue *q = t_hash_table_lookup(ht, key);
	if (!q)
		return;
	g_queue_remove_all(q, GINT_TO_POINTER(pt));
}

static rtp_pt_list *__codec_store_delete_link(rtp_pt_list *link, struct codec_store *cs) {
	rtp_payload_type *pt = link->data;

	t_hash_table_remove(cs->codecs, GINT_TO_POINTER(pt->payload_type));
	__ht_queue_del(cs->codec_names, &pt->encoding, pt->payload_type);
	__ht_queue_del(cs->codec_names, &pt->encoding_with_params, pt->payload_type);
	__ht_queue_del(cs->codec_names, &pt->encoding_with_full_params, pt->payload_type);

	__auto_type next = link->next;
	if (cs->supp_link == link)
		cs->supp_link = next;
	t_queue_delete_link(&cs->codec_prefs, link);
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
struct dtx_packet;

TYPED_GQUEUE(dtx_packet, struct dtx_packet)


typedef enum {
	TCC_ERR = -1,
	TCC_OK = 0, // not consumed, must be freed
	TCC_CONSUMED = 1, // ok, don't free
} tc_code;

struct dtx_buffer {
	struct codec_timer ct;
	mutex_t lock;
	struct codec_ssrc_handler *csh;
	int ptime; // ms per packet
	int tspp; // timestamp increment per packet
	unsigned int clockrate;
	call_t *call;
	dtx_packet_q packets;
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
	tc_code (*dtx_func)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
			struct transcode_packet *packet, struct media_packet *mp);
};

typedef int (*encoder_input_func_t)(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2);
typedef int (*packet_input_func_t)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		unsigned long ts_delay,
		int payload_type,
		struct media_packet *mp);


struct delay_frame;
TYPED_GQUEUE(delay_frame, struct delay_frame)

struct delay_buffer {
	struct codec_timer ct;
	call_t *call;
	struct codec_handler *handler;
	mutex_t lock;
	unsigned int delay;
	delay_frame_q frames; // in reverse order: newest packet first, oldest last
};
struct delay_frame {
	AVFrame *frame;
	struct media_packet mp;
	struct transcode_packet *packet;
	unsigned long ts_delay;
	int payload_type;
	unsigned int clockrate;
	uint32_t ts;
	encoder_input_func_t encoder_func;
	raw_input_func_t raw_func;
	packet_input_func_t packet_func;
	struct codec_handler *handler;
	struct codec_ssrc_handler *ch;
	struct codec_ssrc_handler *input_ch;
	int seq_adj;
};

struct silence_event {
	uint64_t start;
	uint64_t end;
};
TYPED_GQUEUE(silence_event, struct silence_event)

struct transcode_job {
	struct media_packet mp;
	struct codec_ssrc_handler *ch;
	struct codec_ssrc_handler *input_ch;
	struct transcode_packet *packet;
	bool done; // needed for in-order processing
};
TYPED_GQUEUE(transcode_job, struct transcode_job);

struct codec_ssrc_handler {
	struct ssrc_entry h; // must be first
	struct codec_handler *handler;
	decoder_t *decoder;
	encoder_t *encoder;
	codec_cc_t *chain;
	format_t encoder_format;
	int bitrate;
	int ptime;
	int bytes_per_packet;
	struct codec_scheduler csch;
	GString *sample_buffer;
	struct dtx_buffer *dtx_buffer;
	transcode_job_q async_jobs;

	// DTMF DSP stuff
	dtmf_rx_state_t *dtmf_dsp;
	resample_t dtmf_resampler;
	format_t dtmf_format;
	uint64_t dtmf_ts, last_dtmf_event_ts;
	dtmf_event_q dtmf_events;
	struct dtmf_event dtmf_event; // for replacing PCM with DTMF event
	struct dtmf_event dtmf_state; // state tracker for DTMF actions

	// silence detection
	silence_event_q silence_events;

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
	tc_code (*packet_func)(struct codec_ssrc_handler *, struct codec_ssrc_handler *, struct transcode_packet *,
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
	call_t *call;
	struct call_media *media;
};



static mutex_t transcode_lock = MUTEX_STATIC_INIT;
static cond_t transcode_cond = COND_STATIC_INIT;
static transcode_job_q transcode_jobs = TYPED_GQUEUE_INIT;

static tc_code (*__rtp_decode)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp);
static void transcode_job_free(struct transcode_job *j);
static void packet_encoded_tx(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		str *inout, char *buf, unsigned int pkt_len, const struct fraction *cr_fact);
static void packet_encoded_tx_seq_own(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		str *inout, char *buf, unsigned int pkt_len, const struct fraction *cr_fact);



static codec_handler_func handler_func_passthrough_ssrc;
static codec_handler_func handler_func_transcode;
static codec_handler_func handler_func_playback;
static codec_handler_func handler_func_inject_dtmf;
static codec_handler_func handler_func_dtmf;
static codec_handler_func handler_func_t38;

static struct ssrc_entry *__ssrc_handler_transcode_new(void *p);
static struct ssrc_entry *__ssrc_handler_decode_new(void *p);
static struct ssrc_entry *__ssrc_handler_new(void *p);
static void __ssrc_handler_stop(void *p, void *dummy);
static void __free_ssrc_handler(struct codec_ssrc_handler *);

static void __transcode_packet_free(struct transcode_packet *);

static tc_code packet_decode(struct codec_ssrc_handler *, struct codec_ssrc_handler *,
		struct transcode_packet *, struct media_packet *);
static int packet_encoded_rtp(encoder_t *enc, void *u1, void *u2);
static int packet_decoded_fifo(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);
static int packet_decoded_direct(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);
static int packet_decoded_audio_player(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);

static void codec_touched(struct codec_store *cs, rtp_payload_type *pt);

static bool __buffer_dtx(struct dtx_buffer *dtxb, struct codec_ssrc_handler *ch,
		struct codec_ssrc_handler *input_handler,
		struct transcode_packet *packet, struct media_packet *mp,
		tc_code (*dtx_func)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
			struct transcode_packet *packet,
			struct media_packet *mp));
static void __dtx_shutdown(struct dtx_buffer *dtxb);
static struct codec_handler *__input_handler(struct codec_handler *h, struct media_packet *mp);

static void __delay_frame_process(struct delay_buffer *, struct delay_frame *dframe);
static void __dtx_restart(struct codec_handler *h);
static void __delay_buffer_setup(struct delay_buffer **dbufp,
		struct codec_handler *h, call_t *call, unsigned int delay);
static void __delay_buffer_shutdown(struct delay_buffer *dbuf, bool);
static void delay_buffer_stop(struct delay_buffer **pcmbp);
static tc_code __buffer_delay_packet(struct delay_buffer *dbuf,
		struct codec_ssrc_handler *ch,
		struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		unsigned long ts_delay,
		int payload_type,
		packet_input_func_t packet_func, struct media_packet *mp, unsigned int clockrate);
static void __buffer_delay_seq(struct delay_buffer *dbuf, struct media_packet *mp, int seq_adj);


static struct codec_handler codec_handler_stub_ssrc = {
	.source_pt.payload_type = -1,
	.dest_pt.payload_type = -1,
	.handler_func = handler_func_passthrough_ssrc,
	.kernelize = 1,
	.passthrough = 1,
};



static void __handler_shutdown(struct codec_handler *handler) {
	ssrc_hash_foreach(handler->ssrc_hash, __ssrc_handler_stop, (void *) true);
	free_ssrc_hash(&handler->ssrc_hash);
	if (handler->delay_buffer) {
		__delay_buffer_shutdown(handler->delay_buffer, true);
		delay_buffer_stop(&handler->delay_buffer);
	}

	if (handler->ssrc_handler)
		obj_put(&handler->ssrc_handler->h);
	handler->ssrc_handler = NULL;
	handler->kernelize = 0;
	handler->transcoder = 0;
	handler->output_handler = handler; // reset to default
	handler->packet_decoded = packet_decoded_fifo;
	handler->dtmf_payload_type = -1;
	handler->real_dtmf_payload_type = -1;
	handler->cn_payload_type = -1;
	handler->pcm_dtmf_detect = 0;
	handler->passthrough = 0;
	handler->payload_len = 0;

	codec_handler_free(&handler->dtmf_injector);

	if (handler->stats_entry) {
		g_atomic_int_add(&handler->stats_entry->num_transcoders, -1);
		handler->stats_entry = NULL;
		g_free(handler->stats_chain);
	}
}

static void __codec_handler_free(struct codec_handler *h) {
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

static struct codec_handler *__handler_new(const rtp_payload_type *pt, struct call_media *media,
		struct call_media *sink)
{
	struct codec_handler *handler = g_slice_alloc0(sizeof(*handler));
	handler->source_pt.payload_type = -1;
	if (pt)
		rtp_payload_type_copy(&handler->source_pt, pt);
	handler->dest_pt.payload_type = -1;
	handler->output_handler = handler; // default
	handler->dtmf_payload_type = -1;
	handler->real_dtmf_payload_type = -1;
	handler->cn_payload_type = -1;
	handler->packet_encoded = packet_encoded_rtp;
	handler->packet_decoded = packet_decoded_fifo;
	handler->media = media;
	handler->sink = sink;
	return handler;
}

static void __make_passthrough(struct codec_handler *handler, int dtmf_pt, int cn_pt) {
	__handler_shutdown(handler);
	ilogs(codec, LOG_DEBUG, "Using passthrough handler for " STR_FORMAT "/"
		STR_FORMAT " (%i) with DTMF %i, CN %i",
			STR_FMT(&handler->source_pt.encoding_with_params),
			STR_FMT0(&handler->source_pt.format_parameters),
			handler->source_pt.payload_type,
			dtmf_pt, cn_pt);
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->handler_func = handler_func_dtmf;
	else {
		handler->handler_func = handler_func_passthrough;
		handler->kernelize = 1;
	}
	rtp_payload_type_copy(&handler->dest_pt, &handler->source_pt);
	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, handler);
	handler->dtmf_payload_type = dtmf_pt;
	handler->cn_payload_type = cn_pt;
	handler->passthrough = 1;

#ifdef WITH_TRANSCODING
	if (handler->media->buffer_delay) {
		__delay_buffer_setup(&handler->delay_buffer, handler, handler->media->call,
				handler->media->buffer_delay);
		handler->kernelize = 0;
	}
#endif
}

// converts existing passthrough handler to SSRC passthrough
static void __convert_passthrough_ssrc(struct codec_handler *handler) {
	ilogs(codec, LOG_DEBUG, "Using passthrough handler with new SSRC for " STR_FORMAT "/" STR_FORMAT,
			STR_FMT(&handler->source_pt.encoding_with_params),
			STR_FMT0(&handler->source_pt.format_parameters));

	if (handler->handler_func == handler_func_passthrough)
		handler->handler_func = handler_func_passthrough_ssrc;

}

static void __reset_sequencer(void *p, void *dummy) {
	struct ssrc_entry_call *s = p;
	if (s->sequencers)
		g_hash_table_destroy(s->sequencers);
	s->sequencers = NULL;
}
static bool __make_transcoder_full(struct codec_handler *handler, rtp_payload_type *dest,
		GHashTable *output_transcoders, int dtmf_payload_type, bool pcm_dtmf_detect,
		int cn_payload_type, int (*packet_decoded)(decoder_t *, AVFrame *, void *, void *),
		struct ssrc_entry *(*ssrc_handler_new_func)(void *p))
{
	if (!handler->source_pt.codec_def)
		return false;
	if (!dest->codec_def)
		return false;

	// don't reset handler if it already matches what we want
	if (!handler->transcoder)
		goto reset;
	if (!rtp_payload_type_eq_exact(dest, &handler->dest_pt))
		goto reset;
	if (handler->handler_func != handler_func_transcode)
		goto reset;
	if (handler->packet_decoded != packet_decoded)
		goto reset;
	if (handler->cn_payload_type != cn_payload_type)
		goto reset;
	if (handler->dtmf_payload_type != dtmf_payload_type)
		goto reset;
	if ((pcm_dtmf_detect ? 1 : 0) != handler->pcm_dtmf_detect)
		goto reset;

	ilogs(codec, LOG_DEBUG, "Leaving transcode context for " STR_FORMAT "/" STR_FORMAT
		" (%i) -> " STR_FORMAT "/" STR_FORMAT " (%i) intact",
			STR_FMT(&handler->source_pt.encoding_with_params),
			STR_FMT0(&handler->source_pt.format_parameters),
			handler->source_pt.payload_type,
			STR_FMT(&dest->encoding_with_params),
			STR_FMT0(&dest->format_parameters),
			dest->payload_type);

	goto no_handler_reset;

reset:
	__handler_shutdown(handler);

	rtp_payload_type_copy(&handler->dest_pt, dest);
	if (dest->codec_def->format_answer)
		dest->codec_def->format_answer(&handler->dest_pt, &handler->source_pt);
	handler->handler_func = handler_func_transcode;
	handler->packet_decoded = packet_decoded;
	handler->transcoder = 1;
	handler->dtmf_payload_type = dtmf_payload_type;
	handler->cn_payload_type = cn_payload_type;
	handler->pcm_dtmf_detect = pcm_dtmf_detect ? 1 : 0;

	// DTMF transcoder/scaler?
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->handler_func = handler_func_dtmf;

	ilogs(codec, LOG_DEBUG, "Created transcode context for " STR_FORMAT "/" STR_FORMAT " (%i) -> " STR_FORMAT
		"/" STR_FORMAT " (%i) with DTMF output %i and CN output %i",
			STR_FMT(&handler->source_pt.encoding_with_params),
			STR_FMT0(&handler->source_pt.format_parameters),
			handler->source_pt.payload_type,
			STR_FMT(&dest->encoding_with_params),
			STR_FMT0(&dest->format_parameters),
			dest->payload_type,
			dtmf_payload_type, cn_payload_type);

	handler->ssrc_hash = create_ssrc_hash_full(ssrc_handler_new_func, handler);

	// stats entry
	handler->stats_chain = g_strdup_printf(STR_FORMAT " -> " STR_FORMAT,
				STR_FMT(&handler->source_pt.encoding_with_params),
				STR_FMT(&dest->encoding_with_params));

	mutex_lock(&rtpe_codec_stats_lock);
	struct codec_stats *stats_entry =
		t_hash_table_lookup(rtpe_codec_stats, handler->stats_chain);
	if (!stats_entry) {
		stats_entry = g_slice_alloc0(sizeof(*stats_entry));
		stats_entry->chain = strdup(handler->stats_chain);
		t_hash_table_insert(rtpe_codec_stats, stats_entry->chain, stats_entry);
		stats_entry->chain_brief = g_strdup_printf(STR_FORMAT "_" STR_FORMAT,
				STR_FMT(&handler->source_pt.encoding_with_params),
				STR_FMT(&dest->encoding_with_params));
	}
	handler->stats_entry = stats_entry;
	mutex_unlock(&rtpe_codec_stats_lock);

	g_atomic_int_inc(&stats_entry->num_transcoders);

	ssrc_hash_foreach(handler->media->monologue->ssrc_hash, __reset_sequencer, NULL);

no_handler_reset:
	__delay_buffer_setup(&handler->delay_buffer, handler, handler->media->call, handler->media->buffer_delay);
	__dtx_restart(handler);
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

	return true;
}
static void __make_transcoder(struct codec_handler *handler, rtp_payload_type *dest,
		GHashTable *output_transcoders, int dtmf_payload_type, bool pcm_dtmf_detect,
		int cn_payload_type)
{
	__make_transcoder_full(handler, dest, output_transcoders, dtmf_payload_type, pcm_dtmf_detect,
			cn_payload_type, packet_decoded_fifo, __ssrc_handler_transcode_new);
}
static bool __make_audio_player_decoder(struct codec_handler *handler, rtp_payload_type *dest,
		bool pcm_dtmf_detect)
{
	return __make_transcoder_full(handler, dest, NULL, -1, pcm_dtmf_detect, -1, packet_decoded_audio_player,
			__ssrc_handler_decode_new);
}

// used for generic playback (audio_player, t38_gateway)
struct codec_handler *codec_handler_make_playback(const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, unsigned long last_ts, struct call_media *media,
		uint32_t ssrc, str_case_value_ht codec_set)
{
	struct codec_handler *handler = __handler_new(src_pt, media, NULL);
	rtp_payload_type_copy(&handler->dest_pt, dst_pt);
	__codec_options_set(media ? media->call : NULL, &handler->dest_pt, codec_set);
	handler->handler_func = handler_func_playback;
	handler->ssrc_handler = (void *) __ssrc_handler_transcode_new(handler);
	if (!handler->ssrc_handler) {
		codec_handler_free(&handler);
		return NULL;
	}
	handler->ssrc_handler->csch.first_ts = last_ts;
	handler->ssrc_handler->h.ssrc = ssrc;
	while (handler->ssrc_handler->csch.first_ts == 0)
		handler->ssrc_handler->csch.first_ts = ssl_random();
	handler->ssrc_handler->rtp_mark = 1;

	ilogs(codec, LOG_DEBUG, "Created media playback context for " STR_FORMAT "/" STR_FORMAT
		" -> " STR_FORMAT "/" STR_FORMAT "",
			STR_FMT(&src_pt->encoding_with_params),
			STR_FMT0(&src_pt->format_parameters),
			STR_FMT(&dst_pt->encoding_with_params),
			STR_FMT0(&dst_pt->format_parameters));

	return handler;
}
// used for "play media" player
struct codec_handler *codec_handler_make_media_player(const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, unsigned long last_ts, struct call_media *media,
		uint32_t ssrc, str_case_value_ht codec_set)
{
	struct codec_handler *h = codec_handler_make_playback(src_pt, dst_pt, last_ts, media, ssrc, codec_set);
	if (!h)
		return NULL;
	if (audio_player_is_active(media)) {
		h->packet_decoded = packet_decoded_audio_player;
		if (!audio_player_pt_match(media, dst_pt))
			ilogs(codec, LOG_WARN, "Codec mismatch between audio player and media player (wanted: "
				STR_FORMAT "/" STR_FORMAT ")",
					STR_FMT(&dst_pt->encoding_with_params),
					STR_FMT0(&dst_pt->format_parameters));
	}
	return h;
}
struct codec_handler *codec_handler_make_dummy(const rtp_payload_type *dst_pt, struct call_media *media,
		str_case_value_ht codec_set)
{
	struct codec_handler *handler = __handler_new(NULL, media, NULL);
	rtp_payload_type_copy(&handler->dest_pt, dst_pt);
	__codec_options_set(media->call, &handler->dest_pt, codec_set);
	return handler;
}


// does not init/parse a=fmtp
static void ensure_codec_def_type(rtp_payload_type *pt, enum media_type type) {
	if (pt->codec_def)
		return;

	pt->codec_def = codec_find(&pt->encoding, type);
	if (!pt->codec_def)
		return;
	if (!pt->codec_def->support_encoding || !pt->codec_def->support_decoding)
		pt->codec_def = NULL;
}
// does init/parse a=fmtp
void ensure_codec_def(rtp_payload_type *pt, struct call_media *media) {
	if (!media)
		return;
	ensure_codec_def_type(pt, media->type_id);
	if (pt->codec_def)
		codec_parse_fmtp(pt->codec_def, &pt->format, &pt->format_parameters, NULL);
}

// only called from codec_handlers_update()
static void __make_passthrough_gsl(struct codec_handler *handler, GSList **handlers,
		rtp_payload_type *dtmf_pt, rtp_payload_type *cn_pt,
		bool use_ssrc_passthrough)
{
	__make_passthrough(handler, dtmf_pt ? dtmf_pt->payload_type : -1,
			cn_pt ? cn_pt->payload_type : -1);
	if (use_ssrc_passthrough)
		__convert_passthrough_ssrc(handler);
	*handlers = g_slist_prepend(*handlers, handler);
}


static void __track_supp_codec(GHashTable *supplemental_sinks, rtp_payload_type *pt) {
	if (!pt->codec_def || !pt->codec_def->supplemental)
		return;

	GHashTable *supp_sinks = g_hash_table_lookup(supplemental_sinks, pt->codec_def->rtpname);
	if (!supp_sinks)
		return;
	if (!g_hash_table_lookup(supp_sinks, GUINT_TO_POINTER(pt->clock_rate)))
		g_hash_table_insert(supp_sinks, GUINT_TO_POINTER(pt->clock_rate), pt);
}

static void __check_codec_list(GHashTable **supplemental_sinks, rtp_payload_type **pref_dest_codec,
		struct call_media *sink, rtp_pt_q *sink_list)
{
	// first initialise and populate the list of supp sinks
	GHashTable *ss = *supplemental_sinks = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);
	for (GList *l = codec_supplemental_codecs->head; l; l = l->next) {
		codec_def_t *def = l->data;
		g_hash_table_replace(ss, (void *) def->rtpname,
				g_hash_table_new(g_direct_hash, g_direct_equal));
	}

	rtp_payload_type *pdc = NULL;
	rtp_payload_type *first_tc_codec = NULL;

	for (__auto_type l = sink->codecs.codec_prefs.head; l; l = l->next) {
		rtp_payload_type *pt = l->data;
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
		ilogs(codec, LOG_DEBUG, "Default sink codec is " STR_FORMAT "/" STR_FORMAT " (%i)",
				STR_FMT(&(*pref_dest_codec)->encoding_with_params),
				STR_FMT0(&(*pref_dest_codec)->format_parameters),
				(*pref_dest_codec)->payload_type);
	}
}

static rtp_payload_type *__supp_payload_type(GHashTable *supplemental_sinks, int clockrate,
		const char *codec)
{
	GHashTable *supp_sinks = g_hash_table_lookup(supplemental_sinks, codec);
	if (!supp_sinks)
		return NULL;
	if (!g_hash_table_size(supp_sinks))
		return NULL;

	// find the codec entry with a matching clock rate
	rtp_payload_type *pt = g_hash_table_lookup(supp_sinks,
			GUINT_TO_POINTER(clockrate));
	return pt;
}

static int __unused_pt_number(struct call_media *media, struct call_media *other_media,
		struct codec_store *extra_cs,
		rtp_payload_type *pt)
{
	int num = pt ? pt->payload_type : -1;
	rtp_payload_type *pt_match;

	if (num < 0)
		num = 96; // default first dynamic payload type number
	while (1) {
		if ((pt_match = t_hash_table_lookup(media->codecs.codecs, GINT_TO_POINTER(num))))
			goto next;
		if (other_media) {
			if ((pt_match = t_hash_table_lookup(other_media->codecs.codecs,
							GINT_TO_POINTER(num))))
				goto next;
		}
		if (extra_cs) {
			if ((pt_match = t_hash_table_lookup(extra_cs->codecs,
							GINT_TO_POINTER(num))))
				goto next;
		}
		// OK
		break;

next:
		// is this actually the same?
		if (pt && rtp_payload_type_eq_nf(pt, pt_match))
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
	if (!ML_ISSET(sink->monologue, INJECT_DTMF))
		return;
	if (parent->dtmf_payload_type != -1)
		return;
	if (parent->dtmf_injector)
		return;
	if (parent->source_pt.codec_def->supplemental)
		return;

	// synthesise input rtp payload type
	rtp_payload_type src_pt = {
		.payload_type = -1,
		.clock_rate = parent->source_pt.clock_rate,
		.channels = parent->source_pt.channels,
	};
	src_pt.encoding = STR("DTMF injector");
	src_pt.encoding_with_params = STR("DTMF injector");
	src_pt.encoding_with_full_params = STR("DTMF injector");
	static const str tp_event = STR_CONST("telephone-event");
	src_pt.codec_def = codec_find(&tp_event, MT_AUDIO);
	if (!src_pt.codec_def) {
		ilogs(codec, LOG_ERR, "RTP payload type 'telephone-event' is not defined");
		return;
	}

	parent->dtmf_injector = __handler_new(&src_pt, receiver, sink);
	__make_transcoder(parent->dtmf_injector, &parent->dest_pt, output_transcoders, -1, 0, -1);
	parent->dtmf_injector->handler_func = handler_func_inject_dtmf;
}




static struct codec_handler *__get_pt_handler(struct call_media *receiver, rtp_payload_type *pt,
		struct call_media *sink)
{
	ensure_codec_def(pt, receiver);
	struct codec_handler *handler;
	handler = codec_handler_lookup(receiver->codec_handlers, pt->payload_type, sink);
	if (handler) {
		// make sure existing handler matches this PT
		if (!rtp_payload_type_eq_exact(pt, &handler->source_pt)) {
			ilogs(codec, LOG_DEBUG, "Resetting codec handler for PT %i", pt->payload_type);
			t_hash_table_remove(receiver->codec_handlers, handler);
			__handler_shutdown(handler);
			handler = NULL;
			g_atomic_pointer_set(&receiver->codec_handler_cache, NULL);
		}
	}
	if (!handler) {
		ilogs(codec, LOG_DEBUG, "Creating codec handler for " STR_FORMAT "/" STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters),
				pt->payload_type);
		handler = __handler_new(pt, receiver, sink);
		t_hash_table_insert(receiver->codec_handlers, handler, handler);
		t_queue_push_tail(&receiver->codec_handlers_store, handler);
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
	t38_media->t38_handler->handler_func = handler_func_t38;
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
static void __generator_stop_all(struct call_media *media) {
	__generator_stop(media);
	audio_player_stop(media);
}

static void __t38_options_from_flags(struct t38_options *t_opts, const sdp_ng_flags *flags) {
#define t38_opt(name) t_opts->name = flags ? flags->t38_ ## name : 0
	t38_opt(no_ecm);
	t38_opt(no_v17);
	t38_opt(no_v27ter);
	t38_opt(no_v29);
	t38_opt(no_v34);
	t38_opt(no_iaf);
}

static void __check_t38_gateway(struct call_media *pcm_media, struct call_media *t38_media,
		const struct stream_params *sp, const sdp_ng_flags *flags)
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

	MEDIA_SET(pcm_media, GENERATOR);
	MEDIA_SET(t38_media, GENERATOR);

	if (t38_gateway_pair(t38_media, pcm_media, &t_opts))
		return;

	// need a packet handler on the T.38 side
	__check_t38_decoder(t38_media);


	// for each codec type supported by the pcm_media, we create a codec handler that
	// links to the T.38 encoder
	for (__auto_type l = pcm_media->codecs.codec_prefs.head; l; l = l->next) {
		rtp_payload_type *pt = l->data;
		struct codec_handler *handler = __get_pt_handler(pcm_media, pt, t38_media);
		if (!pt->codec_def) {
			// should not happen
			ilogs(codec, LOG_WARN, "Unsupported codec " STR_FORMAT "/" STR_FORMAT
				" for T.38 transcoding",
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters));
			continue;
		}

		ilogs(codec, LOG_DEBUG, "Creating T.38 encoder for " STR_FORMAT "/" STR_FORMAT,
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters));

		__make_transcoder(handler, &pcm_media->t38_gateway->pcm_pt, NULL, -1, false, -1);

		handler->packet_decoded = packet_decoded_direct;
		handler->packet_encoded = packet_encoded_t38;
	}
}

// call must be locked in W
static int codec_handler_udptl_update(struct call_media *receiver, struct call_media *sink,
		const sdp_ng_flags *flags)
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
		const sdp_ng_flags *flags, const struct stream_params *sp)
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


static void __rtcp_timer_free(struct rtcp_timer *rt) {
	if (rt->call)
		obj_put(rt->call);
}
static void __rtcp_timer_run(struct codec_timer *);
// master lock held in W
static void __codec_rtcp_timer_schedule(struct call_media *media) {
	struct rtcp_timer *rt = media->rtcp_timer;
	if (!rt) {
		media->rtcp_timer = rt = obj_alloc0(struct rtcp_timer, __rtcp_timer_free);
		rt->ct.tt_obj.tt = &codec_timers_thread;
		rt->call = obj_get(media->call);
		rt->media = media;
		rt->ct.next = rtpe_now;
		rt->ct.timer_func = __rtcp_timer_run;
	}

	timeval_add_usec(&rt->ct.next, rtpe_config.rtcp_interval * 1000 + (ssl_random() % 1000000));
	timerthread_obj_schedule_abs(&rt->ct.tt_obj, &rt->ct.next);
}
// no lock held
static void __rtcp_timer_run(struct codec_timer *ct) {
	struct rtcp_timer *rt = (void *) ct;

	// check scheduling
	rwlock_lock_w(&rt->call->master_lock);
	struct call_media *media = rt->media;

	log_info_media(media);

	if (media->rtcp_timer != rt || !proto_is_rtp(media->protocol) || !MEDIA_ISSET(media, RTCP_GEN)) {
		if (media->rtcp_timer == rt)
			rtcp_timer_stop(&media->rtcp_timer);
		rwlock_unlock_w(&rt->call->master_lock);
		goto out;
	}
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
		// coverity[use : FALSE]
		rtcp_send_report(media, ssrc_out[u]);
	}

	rwlock_unlock_r(&rt->call->master_lock);

	for (unsigned int u = 0; u < RTPE_NUM_SSRC_TRACKING; u++) {
		if (!ssrc_out[u]) // end of list
			break;
		ssrc_ctx_put(&ssrc_out[u]);
	}

out:
	log_info_pop();
}
// master lock held in W
static void __codec_rtcp_timer(struct call_media *receiver) {
	if (receiver->rtcp_timer) // already scheduled
		return;
	__codec_rtcp_timer_schedule(receiver);
	// XXX unify with media player into a generic RTCP player
}

static unsigned int __codec_handler_hash(const struct codec_handler *h) {
	return h->source_pt.payload_type ^ GPOINTER_TO_UINT(h->sink);
}
static int __codec_handler_eq(const struct codec_handler *h, const struct codec_handler *j) {
	return h->source_pt.payload_type == j->source_pt.payload_type
		&& h->sink == j->sink;
}

TYPED_GHASHTABLE_IMPL(codec_handlers_ht, __codec_handler_hash, __codec_handler_eq, NULL, NULL)

/**
 * receiver - media / sink - other_media
 * call must be locked in W
 */
void __codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		struct chu_args a)
{
	struct call_monologue *monologue = receiver->monologue;
	struct call_monologue *other_monologue = sink->monologue;

	if (!monologue || !other_monologue)
		return;

	/* required for updating the transcoding attrs of subscriber */
	struct media_subscription * ms = call_get_media_subscription(receiver->media_subscribers_ht, sink);

	ilogs(codec, LOG_DEBUG, "Setting up codec handlers for " STR_FORMAT_M " #%u -> " STR_FORMAT_M " #%u",
			STR_FMT_M(&monologue->tag), receiver->index,
			STR_FMT_M(&other_monologue->tag), sink->index);

	if (a.reset_transcoding && ms)
		ms->attrs.transcoding = 0;

	MEDIA_CLEAR(receiver, GENERATOR);
	MEDIA_CLEAR(sink, GENERATOR);

	if (!t_hash_table_is_set(receiver->codec_handlers))
		receiver->codec_handlers = codec_handlers_ht_new();
	if (!t_hash_table_is_set(sink->codec_handlers))
		sink->codec_handlers = codec_handlers_ht_new();

	// non-RTP protocol?
	if (proto_is(receiver->protocol, PROTO_UDPTL)) {
		if (codec_handler_udptl_update(receiver, sink, a.flags)) {
			if (a.reset_transcoding && ms)
				ms->attrs.transcoding = 1;
			return;
		}
	}
	// everything else is unsupported: pass through
	if (proto_is_not_rtp(receiver->protocol)) {
		__generator_stop_all(receiver);
		__generator_stop_all(sink);
		codec_handlers_stop(&receiver->codec_handlers_store, sink);
		return;
	}

	// should we transcode to a non-RTP protocol?
	if (proto_is_not_rtp(sink->protocol)) {
		if (codec_handler_non_rtp_update(receiver, sink, a.flags, a.sp)) {
			if (a.reset_transcoding && ms)
				ms->attrs.transcoding = 1;
			return;
		}
	}

	// we're doing some kind of media passthrough - shut down local generators
	__generator_stop(receiver);
	__generator_stop(sink);
	codec_handlers_stop(&receiver->codec_handlers_store, sink);

	bool is_transcoding = false;
	receiver->rtcp_handler = NULL;
	receiver->dtmf_count = 0;
	GSList *passthrough_handlers = NULL;

	// default choice of audio player usage is based on whether it was in use previously,
	// overridden by signalling flags, overridden by global option
	bool use_audio_player = !!MEDIA_ISSET(sink, AUDIO_PLAYER);
	bool implicit_audio_player = false;

	if (a.flags && a.flags->audio_player == AP_FORCE)
		use_audio_player = true;
	else if (a.flags && a.flags->audio_player == AP_OFF)
		use_audio_player = false;
	else if (rtpe_config.use_audio_player == UAP_ALWAYS)
		use_audio_player = true;
	else if (rtpe_config.use_audio_player == UAP_PLAY_MEDIA) {
		// check for implicitly enabled player
		if ((a.flags && a.flags->opmode == OP_PLAY_MEDIA) || (media_player_is_active(other_monologue))) {
			use_audio_player = true;
			implicit_audio_player = true;
		}
	}

	// first gather info about what we can send
	g_autoptr(GHashTable) supplemental_sinks = NULL;
	rtp_payload_type *pref_dest_codec = NULL;
	__check_codec_list(&supplemental_sinks, &pref_dest_codec, sink, &sink->codecs.codec_prefs);

	// then do the same with what we can receive
	g_autoptr(GHashTable) supplemental_recvs = NULL;
	__check_codec_list(&supplemental_recvs, NULL, receiver, &receiver->codecs.codec_prefs);

	// if multiple input codecs transcode to the same output codec, we want to make sure
	// that all the decoders output their media to the same encoder. we use the destination
	// payload type to keep track of this.
	g_autoptr(GHashTable) output_transcoders = g_hash_table_new(g_direct_hash, g_direct_equal);

	enum block_dtmf_mode dtmf_block_mode = dtmf_get_block_mode(NULL, monologue);
	bool do_pcm_dtmf_blocking = is_pcm_dtmf_block_mode(dtmf_block_mode);
	bool do_dtmf_blocking = is_dtmf_replace_mode(dtmf_block_mode);

	if (monologue->dtmf_delay) // received DTMF must be replaced by silence initially, therefore:
		do_pcm_dtmf_blocking = true;

	bool do_dtmf_detect = false;
	if (monologue->num_dtmf_triggers)
		do_dtmf_detect = true;

	if (a.flags && a.flags->inject_dtmf)
		ML_SET(other_monologue, INJECT_DTMF);

	bool use_ssrc_passthrough = MEDIA_ISSET(receiver, ECHO) || ML_ISSET(other_monologue, INJECT_DTMF);

	// do we have to force everything through the transcoding engine even if codecs match?
	bool force_transcoding = do_pcm_dtmf_blocking || do_dtmf_blocking || use_audio_player;

	for (__auto_type l = receiver->codecs.codec_prefs.head; l; ) {
		rtp_payload_type *pt = l->data;
		rtp_payload_type *sink_pt = NULL;

		ilogs(codec, LOG_DEBUG, "Checking receiver codec " STR_FORMAT "/" STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_full_params),
				STR_FMT0(&pt->format_parameters),
				pt->payload_type);

		struct codec_handler *handler = __get_pt_handler(receiver, pt, sink);

		// check our own support for this codec
		if (!pt->codec_def) {
			// not supported
			ilogs(codec, LOG_DEBUG, "No codec support for " STR_FORMAT "/" STR_FORMAT,
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters));
			__make_passthrough_gsl(handler, &passthrough_handlers, NULL, NULL, use_ssrc_passthrough);
			goto next;
		}

		// fill matching supp codecs
		rtp_payload_type *recv_dtmf_pt = __supp_payload_type(supplemental_recvs, pt->clock_rate,
				"telephone-event");
		rtp_payload_type *recv_cn_pt = __supp_payload_type(supplemental_recvs, pt->clock_rate,
				"CN");
		bool pcm_dtmf_detect = false;

		// find the matching sink codec

		if (!sink_pt) {
			// can we send the same codec that we want to receive?
			sink_pt = t_hash_table_lookup(sink->codecs.codecs,
					GINT_TO_POINTER(pt->payload_type));
			// is it actually the same?
			if (sink_pt && !rtp_payload_type_eq_compat(pt, sink_pt))
				sink_pt = NULL;
		}

		if (!sink_pt) {
			// no matching/identical output codec. maybe we have the same output codec,
			// but with a different payload type or a different format?
			if (!a.allow_asymmetric)
				sink_pt = codec_store_find_compatible(&sink->codecs, pt);
			else
				sink_pt = pt;
		}

		if (sink_pt && !pt->codec_def->supplemental) {
			// we have a matching output codec. do we actually want to use it, or
			// do we want to transcode to something else?
			// ignore the preference here - for now, all `for_transcoding` codecs
			// take preference
			if (pref_dest_codec && pref_dest_codec->for_transcoding)
				sink_pt = pref_dest_codec;
		}

		// ignore DTMF sink if we're blocking DTMF in PCM replacement mode
		if (do_pcm_dtmf_blocking && sink_pt && sink_pt->codec_def && sink_pt->codec_def->dtmf)
			sink_pt = NULL;

		// still no output? pick the preferred sink codec
		if (!sink_pt)
			sink_pt = pref_dest_codec;

		if (!sink_pt) {
			ilogs(codec, LOG_DEBUG, "No suitable output codec for " STR_FORMAT "/" STR_FORMAT,
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters));
			__make_passthrough_gsl(handler, &passthrough_handlers, recv_dtmf_pt, recv_cn_pt,
					use_ssrc_passthrough);
			goto next;
		}

		// sink_pt has been determined here now.

		ilogs(codec, LOG_DEBUG, "Sink codec for " STR_FORMAT "/" STR_FORMAT
			" is " STR_FORMAT "/" STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters),
				STR_FMT(&sink_pt->encoding_with_full_params),
				STR_FMT0(&sink_pt->format_parameters),
				sink_pt->payload_type);

sink_pt_fixed:;
		// we have found a usable output codec. gather matching output supp codecs
		rtp_payload_type *sink_dtmf_pt = NULL;
		rtp_payload_type *sink_cn_pt = NULL;
		if (!a.allow_asymmetric) {
			sink_dtmf_pt = __supp_payload_type(supplemental_sinks,
					sink_pt->clock_rate, "telephone-event");
			sink_cn_pt = __supp_payload_type(supplemental_sinks,
					sink_pt->clock_rate, "CN");
		}
		else {
			sink_dtmf_pt = recv_dtmf_pt;
			sink_cn_pt = recv_cn_pt;
		}
		rtp_payload_type *real_sink_dtmf_pt = NULL; // for DTMF delay

		// XXX synthesise missing supp codecs according to codec tracker XXX needed?

		if (!a.flags) {
			// second pass going through the offerer codecs during an answer:
			// if an answer rejected a supplemental codec that isn't marked for transcoding,
			// reject it on the sink side as well
			if (sink_dtmf_pt && !recv_dtmf_pt && !sink_dtmf_pt->for_transcoding)
				sink_dtmf_pt = NULL;
			if (sink_cn_pt && !recv_cn_pt && !sink_cn_pt->for_transcoding)
				sink_cn_pt = NULL;
		}

		// do we need DTMF detection?
		if (!pt->codec_def->supplemental && !recv_dtmf_pt && sink_dtmf_pt
				&& sink_dtmf_pt->for_transcoding)
			pcm_dtmf_detect = true;

		if (ML_ISSET(monologue, DETECT_DTMF))
			pcm_dtmf_detect = true;

		// special mode for DTMF blocking
		if (do_pcm_dtmf_blocking) {
			real_sink_dtmf_pt = sink_dtmf_pt; // remember for DTMF delay
			sink_dtmf_pt = NULL; // always transcode DTMF to PCM

			// enable DSP if we expect DTMF to be carried as PCM
			if (!recv_dtmf_pt)
				pcm_dtmf_detect = true;
		}
		else if (do_dtmf_blocking && !pcm_dtmf_detect) {
			// we only need the DSP if there's no DTMF payload present, as otherwise
			// we expect DTMF event packets
			if (!recv_dtmf_pt)
				pcm_dtmf_detect = true;
		}

		// same logic if we need to detect DTMF
		if (do_dtmf_detect && !pcm_dtmf_detect) {
			if (!recv_dtmf_pt)
				pcm_dtmf_detect = true;
		}

		if (pcm_dtmf_detect) {
			if (sink_dtmf_pt)
				ilogs(codec, LOG_DEBUG, "Enabling PCM DTMF detection from " STR_FORMAT
					"/" STR_FORMAT " to " STR_FORMAT
					"/" STR_FORMAT "/" STR_FORMAT "/" STR_FORMAT,
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						STR_FMT(&sink_pt->encoding_with_params),
						STR_FMT0(&sink_pt->format_parameters),
						STR_FMT(&sink_dtmf_pt->encoding_with_params),
						STR_FMT0(&sink_dtmf_pt->format_parameters));
			else
				ilogs(codec, LOG_DEBUG, "Enabling PCM DTMF detection from " STR_FORMAT
					"/" STR_FORMAT " to " STR_FORMAT "/" STR_FORMAT,
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						STR_FMT(&sink_pt->encoding_with_params),
						STR_FMT0(&sink_pt->format_parameters));
		}

		// we can now decide whether we can do passthrough, or transcode

		// different codecs? this will only be true for non-supplemental codecs
		if (!a.allow_asymmetric && pt->payload_type != sink_pt->payload_type)
			goto transcode;
		if (!rtp_payload_type_fmt_eq_nf(pt, sink_pt))
			goto transcode;

		// supplemental codecs are always matched up. we want them as passthrough if
		// possible. skip checks that are only applicable for real codecs
		if (!pt->codec_def->supplemental) {
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

			if (force_transcoding)
				goto transcode;

			// compare supplemental codecs
			// DTMF
			if (pcm_dtmf_detect)
				goto transcode;
			if (recv_dtmf_pt && (recv_dtmf_pt->for_transcoding || do_pcm_dtmf_blocking) && !sink_dtmf_pt) {
				ilogs(codec, LOG_DEBUG, "Transcoding DTMF events to PCM from " STR_FORMAT
					"/" STR_FORMAT " to " STR_FORMAT "/" STR_FORMAT,
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						STR_FMT(&sink_pt->encoding_with_params),
						STR_FMT0(&sink_pt->format_parameters));
				goto transcode;
			}
			// CN
			if (!recv_cn_pt && sink_cn_pt && sink_cn_pt->for_transcoding) {
				ilogs(codec, LOG_DEBUG, "Enabling CN silence detection from " STR_FORMAT
					"/" STR_FORMAT " to " STR_FORMAT
					"/" STR_FORMAT "/" STR_FORMAT "/" STR_FORMAT,
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						STR_FMT(&sink_pt->encoding_with_params),
						STR_FMT0(&sink_pt->format_parameters),
						STR_FMT(&sink_cn_pt->encoding_with_params),
						STR_FMT0(&sink_cn_pt->format_parameters));
				goto transcode;
			}
			if (recv_cn_pt && recv_cn_pt->for_transcoding && !sink_cn_pt) {
				ilogs(codec, LOG_DEBUG, "Transcoding CN packets to PCM from " STR_FORMAT
					"/" STR_FORMAT " to " STR_FORMAT "/" STR_FORMAT,
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						STR_FMT(&sink_pt->encoding_with_params),
						STR_FMT0(&sink_pt->format_parameters));
				goto transcode;
			}
		}

		// force transcoding if we want DTMF injection and there's no DTMF PT
		if (!sink_dtmf_pt && ML_ISSET(other_monologue, INJECT_DTMF))
			goto transcode;

		// everything matches - we can do passthrough
		ilogs(codec, LOG_DEBUG, "Sink supports codec " STR_FORMAT "/" STR_FORMAT
			" (%i) for passthrough (to %i)",
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters),
				pt->payload_type,
				sink_pt->payload_type);
		__make_passthrough_gsl(handler, &passthrough_handlers, sink_dtmf_pt, sink_cn_pt,
				use_ssrc_passthrough);
		goto next;

transcode:
		// enable audio player if not explicitly disabled
		if (rtpe_config.use_audio_player == UAP_TRANSCODING && (!a.flags || a.flags->audio_player != AP_OFF))
			use_audio_player = true;
		else if (a.flags && a.flags->audio_player == AP_TRANSCODING)
			use_audio_player = true;

		if (use_audio_player) {
			// when using the audio player, everything must decode to the same
			// format that is appropriate for the audio player
			if (sink_pt != pref_dest_codec && pref_dest_codec) {
				ilogs(codec, LOG_DEBUG, "Switching sink codec for " STR_FORMAT "/" STR_FORMAT
					" to " STR_FORMAT "/" STR_FORMAT " (%i) due to usage of audio player",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						STR_FMT(&pref_dest_codec->encoding_with_full_params),
						STR_FMT0(&pref_dest_codec->format_parameters),
						pref_dest_codec->payload_type);
				sink_pt = pref_dest_codec;
				force_transcoding = true;
				goto sink_pt_fixed;
			}
		}
		// look up the reverse side of this payload type, which is the decoder to our
		// encoder. if any codec options such as bitrate were set during an offer,
		// they're in the decoder PT. copy them to the encoder PT.
		rtp_payload_type *reverse_pt = t_hash_table_lookup(sink->codecs.codecs,
				GINT_TO_POINTER(sink_pt->payload_type));
		if (reverse_pt) {
			if (!sink_pt->bitrate)
				sink_pt->bitrate = reverse_pt->bitrate;
			if (!sink_pt->codec_opts.len)
				sink_pt->codec_opts = call_str_cpy(&reverse_pt->codec_opts);
		}
		is_transcoding = true;
		if (!use_audio_player)
			__make_transcoder(handler, sink_pt, output_transcoders,
					sink_dtmf_pt ? sink_dtmf_pt->payload_type : -1,
					pcm_dtmf_detect, sink_cn_pt ? sink_cn_pt->payload_type : -1);
		else
			__make_audio_player_decoder(handler, sink_pt, pcm_dtmf_detect);
		// for DTMF delay: we pretend that there is no output DTMF payload type (sink_dtmf_pt == NULL)
		// so that DTMF is converted to audio (so it can be replaced with silence). we still want
		// to output DTMF event packets when we can though, so we need to remember the DTMF payload
		// type here.
		handler->real_dtmf_payload_type = real_sink_dtmf_pt ? real_sink_dtmf_pt->payload_type : -1;
		__check_dtmf_injector(receiver, sink, handler, output_transcoders);

next:
		l = l->next;
	}

	if (!use_audio_player) {
		MEDIA_CLEAR(sink, AUDIO_PLAYER);
		audio_player_stop(sink);
	}
	else if (!implicit_audio_player)
		MEDIA_SET(sink, AUDIO_PLAYER);

	if (is_transcoding) {
		if (a.reset_transcoding && ms)
			ms->attrs.transcoding = 1;

		for (__auto_type l = receiver->codecs.codec_prefs.head; l; ) {
			rtp_payload_type *pt = l->data;

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

		if (!use_audio_player) {
			// we have to translate RTCP packets
			receiver->rtcp_handler = rtcp_transcode_handler;

			// at least some payload types will be transcoded, which will result in SSRC
			// change. for payload types which we don't actually transcode, we still
			// must substitute the SSRC
			while (passthrough_handlers) {
				struct codec_handler *handler = passthrough_handlers->data;
				__convert_passthrough_ssrc(handler);
				passthrough_handlers = g_slist_delete_link(passthrough_handlers,
						passthrough_handlers);
			}
		}
		else {
			receiver->rtcp_handler = rtcp_sink_handler;
			MEDIA_CLEAR(receiver, RTCP_GEN);

			// change all passthrough handlers also to transcoders
			while (passthrough_handlers) {
				struct codec_handler *handler = passthrough_handlers->data;
				if (!__make_audio_player_decoder(handler, pref_dest_codec, false))
					__convert_passthrough_ssrc(handler);
				passthrough_handlers = g_slist_delete_link(passthrough_handlers,
						passthrough_handlers);

			}

			audio_player_setup(sink, pref_dest_codec, rtpe_config.audio_buffer_length,
					rtpe_config.audio_buffer_delay,
					a.flags ? a.flags->codec_set : str_case_value_ht_null());
			if (a.flags && (a.flags->early_media || a.flags->opmode == OP_ANSWER))
				audio_player_activate(sink);
		}
	}

	g_slist_free(passthrough_handlers);

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
	if (G_LIKELY(h) && G_LIKELY(__codec_handler_eq(&lookup, h)))
		return h;

	if (G_UNLIKELY(!t_hash_table_is_set(m->codec_handlers)))
		return NULL;
	h = t_hash_table_lookup(m->codec_handlers, &lookup);
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

static void __mqtt_timer_free(struct mqtt_timer *mqt) {
	if (mqt->call)
		obj_put(mqt->call);
}
static void __codec_mqtt_timer_schedule(struct mqtt_timer *mqt);
INLINE bool __mqtt_timer_common_call(struct mqtt_timer *mqt) {
	call_t *call = mqt->call;

	rwlock_lock_w(&call->master_lock);

	if (!*mqt->self) {
		rwlock_unlock_w(&call->master_lock);
		return false;
	}

	log_info_call(call);

	__codec_mqtt_timer_schedule(mqt);

	rwlock_unlock_w(&call->master_lock);

	return true;
}
static void __mqtt_timer_run_media(struct codec_timer *ct) {
	struct mqtt_timer *mqt = (struct mqtt_timer *) ct;
	if (!__mqtt_timer_common_call(mqt))
		return;
	mqtt_timer_run_media(mqt->call, mqt->media);
	log_info_pop();
}
static void __mqtt_timer_run_call(struct codec_timer *ct) {
	struct mqtt_timer *mqt = (struct mqtt_timer *) ct;
	if (!__mqtt_timer_common_call(mqt))
		return;
	mqtt_timer_run_call(mqt->call);
	log_info_pop();
}
static void __mqtt_timer_run_global(struct codec_timer *ct) {
	struct mqtt_timer *mqt = (struct mqtt_timer *) ct;
	if (!*mqt->self)
		return;
	__codec_mqtt_timer_schedule(mqt);
	mqtt_timer_run_global();
}
static void __mqtt_timer_run_summary(struct codec_timer *ct) {
	struct mqtt_timer *mqt = (struct mqtt_timer *) ct;
	if (!*mqt->self)
		return;
	__codec_mqtt_timer_schedule(mqt);
	mqtt_timer_run_summary();
}
static void __codec_mqtt_timer_schedule(struct mqtt_timer *mqt) {
	timeval_add_usec(&mqt->ct.next, rtpe_config.mqtt_publish_interval * 1000);
	timerthread_obj_schedule_abs(&mqt->ct.tt_obj, &mqt->ct.next);
}
// master lock held in W
void mqtt_timer_start(struct mqtt_timer **mqtp, call_t *call, struct call_media *media) {
	if (*mqtp) // already scheduled
		return;

	__auto_type mqt = *mqtp = obj_alloc0(struct mqtt_timer, __mqtt_timer_free);
	mqt->ct.tt_obj.tt = &codec_timers_thread;
	mqt->call = call ? obj_get(call) : NULL;
	mqt->self = mqtp;
	mqt->media = media;
	mqt->ct.next = rtpe_now;

	if (media)
		mqt->ct.timer_func = __mqtt_timer_run_media;
	else if (call)
		mqt->ct.timer_func = __mqtt_timer_run_call;
	else {
		// global or summary
		mqt->ct.timer_func = mqtt_publish_scope() == MPS_GLOBAL
			? __mqtt_timer_run_global : __mqtt_timer_run_summary;
	}

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
struct codec_handler *codec_handler_get(struct call_media *m, int payload_type, struct call_media *sink,
		struct sink_handler *sh)
{
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
	if (sh && sh->attrs.transcoding)
		return &codec_handler_stub_ssrc;
#endif
	return &codec_handler_stub;
}

void codec_handlers_free(struct call_media *m) {
	codec_handlers_ht_destroy_ptr(&m->codec_handlers);
	m->codec_handler_cache = NULL;
#ifdef WITH_TRANSCODING
	t_queue_clear_full(&m->codec_handlers_store, __codec_handler_free);
#endif
}


static void codec_add_raw_packet_common(struct media_packet *mp, unsigned int clockrate,
		struct codec_packet *p)
{
	p->clockrate = clockrate;
	if (mp->rtp && mp->ssrc_out) {
		ssrc_ctx_hold(mp->ssrc_out);
		p->ssrc_out = mp->ssrc_out;
		if (!p->rtp)
			p->rtp = mp->rtp;
	}
	t_queue_push_tail(&mp->packets_out, p);
}
void codec_add_raw_packet(struct media_packet *mp, unsigned int clockrate) {
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s = mp->raw;
	p->free_func = NULL;
	codec_add_raw_packet_common(mp, clockrate, p);
}
#ifdef WITH_TRANSCODING
static void codec_add_raw_packet_dup(struct media_packet *mp, unsigned int clockrate) {
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	// don't just duplicate the string. need to ensure enough room
	// if encryption is enabled on this stream
	p->s.s = bufferpool_alloc(media_bufferpool, mp->raw.len + RTP_BUFFER_TAIL_ROOM);
	memcpy(p->s.s, mp->raw.s, mp->raw.len);
	p->s.len = mp->raw.len;
	p->free_func = bufferpool_unref;
	p->rtp = (struct rtp_header *) p->s.s;
	codec_add_raw_packet_common(mp, clockrate, p);
}
#endif
static bool handler_silence_block(struct codec_handler *h, struct media_packet *mp) {
	if (CALL_ISSET(mp->call, BLOCK_MEDIA) || ML_ISSET(mp->media->monologue, BLOCK_MEDIA) || mp->sink.attrs.block_media || MEDIA_ISSET(mp->media_out, BLOCK_EGRESS))
		return false;
	if (CALL_ISSET(mp->call, SILENCE_MEDIA) || ML_ISSET(mp->media->monologue, SILENCE_MEDIA) || mp->sink.attrs.silence_media) {
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

	uint32_t ts = 0;
	if (mp->rtp) {
		ts = ntohl(mp->rtp->timestamp);
		codec_calc_jitter(mp->ssrc_in, ts, h->source_pt.clock_rate, &mp->tv);
		codec_calc_lost(mp->ssrc_in, ntohs(mp->rtp->seq_num));

		if (ML_ISSET(mp->media->monologue, BLOCK_SHORT) && h->source_pt.codec_def
				&& h->source_pt.codec_def->fixed_sizes)
		{
			if (!h->payload_len)
				h->payload_len = mp->payload.len;
			else if (mp->payload.len < h->payload_len)
				return 0;
		}
	}

	ML_CLEAR(mp->media->monologue, DTMF_INJECTION_ACTIVE);

	__buffer_delay_raw(h->delay_buffer, h, codec_add_raw_packet, mp, h->source_pt.clock_rate);

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

static void __seq_free(void *p) {
	packet_sequencer_t *seq = p;
	packet_sequencer_destroy(seq);
	g_slice_free1(sizeof(*seq), seq);
}

static int __handler_func_sequencer(struct media_packet *mp, struct transcode_packet *packet)
{
	struct codec_handler *h = packet->handler;

	if (G_UNLIKELY(!h->ssrc_hash)) {
		if (!packet->packet_func || !h->input_handler->ssrc_hash) {
			h->handler_func(h, mp);
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

	// save RTP pointer - we clobber it below XXX this shouldn't be necessary to do
	struct rtp_header *orig_rtp = mp->rtp;

	packet->p.seq = ntohs(mp->rtp->seq_num);
	packet->payload = str_dup(&mp->payload);
	uint32_t packet_ts = ntohl(mp->rtp->timestamp);
	packet->ts = packet_ts;
	packet->marker = (mp->rtp->m_pt & 0x80) ? 1 : 0;

	atomic64_inc_na(&ssrc_in->stats->packets);
	atomic64_add_na(&ssrc_in->stats->bytes, mp->payload.len);
	atomic64_inc_na(&mp->sfd->local_intf->stats->in.packets);
	atomic64_add_na(&mp->sfd->local_intf->stats->in.bytes, mp->payload.len);

	struct codec_ssrc_handler *input_ch = get_ssrc(ssrc_in_p->h.ssrc, h->input_handler->ssrc_hash);

	if (packet->bypass_seq) {
		// bypass sequencer
		__ssrc_lock_both(mp);
		tc_code code = packet->packet_func(ch, input_ch ?: ch, packet, mp);
		if (code != TCC_CONSUMED)
			__transcode_packet_free(packet);
		goto out;
	}

	if (G_UNLIKELY(!input_ch)) {
		__transcode_packet_free(packet);
		goto out_ch;
	}

	__ssrc_lock_both(mp);

	// get sequencer appropriate for our output
	if (!ssrc_in_p->sequencers)
		ssrc_in_p->sequencers = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, __seq_free);
	packet_sequencer_t *seq = g_hash_table_lookup(ssrc_in_p->sequencers, mp->media_out);
	if (!seq) {
		seq = g_slice_alloc0(sizeof(*seq));
		packet_sequencer_init(seq, (GDestroyNotify) __transcode_packet_free);
		g_hash_table_insert(ssrc_in_p->sequencers, mp->media_out, seq);
	}

	uint16_t seq_ori = (seq->seq < 0) ? 0 : seq->seq;
	int seq_ret = packet_sequencer_insert(seq, &packet->p);
	if (seq_ret < 0) {
		// dupe
		int func_ret = 0;
		if (packet->dup_func)
			func_ret = packet->dup_func(ch, input_ch, packet, mp);
		else
			ilogs(transcoding, LOG_DEBUG, "Ignoring duplicate RTP packet");
		if (func_ret != 1)
			__transcode_packet_free(packet);
		ssrc_in_p->duplicates++;
		atomic64_inc_na(&mp->sfd->local_intf->stats->s.duplicates);
		RTPE_STATS_INC(rtp_duplicates);
		goto out;
	}

	if (seq_ret == 1)
		RTPE_STATS_INC(rtp_seq_resets);
	else if (seq_ret == 2)
		RTPE_STATS_INC(rtp_reordered);

	// got a new packet, run decoder

	while (1) {
		tc_code func_ret = TCC_OK;

		packet = packet_sequencer_next_packet(seq);
		if (G_UNLIKELY(!packet)) {
			if (!ch || !h->dest_pt.clock_rate || !ch->handler
					|| !h->dest_pt.codec_def)
				break;

			uint32_t ts_diff = packet_ts - ch->csch.last_ts;

			// if packet TS is larger than last tracked TS, we can force the next packet if packets were lost and the TS
			// difference is too large. if packet TS is the same or lower (can happen for supplement codecs) we can wait
			// for the next packet
			if (ts_diff == 0 || ts_diff >= 0x80000000)
				break;

			unsigned long long ts_diff_us =
				(unsigned long long) ts_diff * 1000000 / h->dest_pt.clock_rate;
			if (ts_diff_us >= 60000)  { // arbitrary value
				packet = packet_sequencer_force_next_packet(seq);
				if (!packet)
					break;
				ilogs(transcoding, LOG_DEBUG, "Timestamp difference too large (%llu ms) after lost packet, "
						"forcing next packet", ts_diff_us / 1000);
				RTPE_STATS_INC(rtp_skips);
			}
			else
				break;
		}

		if (ch) {
			uint32_t ts_diff = ch->csch.last_ts - packet->ts;
			if (ts_diff < 0x80000000) { // ch->last_ts >= packet->ts
				// multiple consecutive packets with same TS: this could be a compound packet, e.g. a large video frame, or
				// it could be a supplemental audio codec with static timestamps, in which case we adjust the TS forward
				// by one frame length. This is needed so that the next real audio packet (with real TS) is not mistakenly
				// seen as overdue
				if (h->source_pt.codec_def && h->source_pt.codec_def->supplemental)
					ch->csch.last_ts += h->source_pt.clock_rate * (ch->ptime ?: 20) / 1000;
			}
			else
				ch->csch.last_ts = packet->ts;

			if (input_ch)
				input_ch->csch.last_ts = ch->csch.last_ts;
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

		ssrc_in_p->packets_lost = seq->lost_count;
		atomic_set_na(&ssrc_in->stats->ext_seq, seq->ext_seq);

		ilogs(transcoding, LOG_DEBUG, "Processing RTP packet: seq %u, TS %lu",
				packet->p.seq, packet->ts);

		if (seq_ret == 1) {
			// seq reset - update output seq. we keep our output seq clean
			ssrc_out_p->seq_diff -= packet->p.seq - seq_ori;
			seq_ret = 0;
		}

		// we might be working with a different packet now
		mp->rtp = &packet->rtp;

		func_ret = packet->packet_func(ch, input_ch, packet, mp);
		if (func_ret == TCC_ERR)
			ilogs(transcoding, LOG_WARN | LOG_FLAG_LIMIT, "Decoder error while processing RTP packet");
next:
		if (func_ret != TCC_CONSUMED)
			__transcode_packet_free(packet);
	}

out:
	__ssrc_unlock_both(mp);
	if (input_ch)
		obj_put(&input_ch->h);
out_ch:
	if (ch)
		obj_put(&ch->h);

	mp->rtp = orig_rtp;

	return 0;
}

void codec_output_rtp(struct media_packet *mp, struct codec_scheduler *csch,
		struct codec_handler *handler,
		char *buf, // bufferpool_alloc'd, room for rtp_header + filled-in payload
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
	p->free_func = bufferpool_unref;
	p->ttq_entry.source = handler;
	p->rtp = rh;
	p->ts = ts;
	p->clockrate = handler->dest_pt.clock_rate;
	ssrc_ctx_hold(ssrc_out);
	p->ssrc_out = ssrc_out;

	long long ts_diff_us = 0;

	// ignore scheduling if a sequence number was supplied. in that case we're just doing
	// passthrough forwarding (or are handling some other prepared RTP stream) and want
	// to send the packet out immediately.
	if (seq != -1) {
		p->ttq_entry.when = rtpe_now;
		goto send;
	}

	// this packet is dynamically allocated, so we're able to schedule it.
	// determine scheduled time to send
	if (csch->first_send.tv_sec && handler->dest_pt.clock_rate) {
		// scale first_send from first_send_ts to ts
		p->ttq_entry.when = csch->first_send;
		uint32_t ts_diff = (uint32_t) ts - (uint32_t) csch->first_send_ts; // allow for wrap-around
		ts_diff += ts_delay;
		ts_diff_us = (unsigned long long) ts_diff * 1000000 / handler->dest_pt.clock_rate;
		timeval_add_usec(&p->ttq_entry.when, ts_diff_us);

		// how far in the future is this?
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);
		if (ts_diff_us > 1000000 || ts_diff_us < -1000000) // more than one second, can't be right
			csch->first_send.tv_sec = 0; // fix it up below
	}
	if (!csch->first_send.tv_sec || !p->ttq_entry.when.tv_sec) {
		p->ttq_entry.when = csch->first_send = rtpe_now;
		csch->first_send_ts = ts;
	}

	ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);

	csch->output_skew = csch->output_skew * 15 / 16 + ts_diff_us / 16;
	if (csch->output_skew > 50000 && ts_diff_us > 10000) { // arbitrary value, 50 ms, 10 ms shift
		ilogs(transcoding, LOG_DEBUG, "Steady clock skew of %li.%01li ms detected, shifting send timer back by 10 ms",
			csch->output_skew / 1000,
			(csch->output_skew % 1000) / 100);
		timeval_add_usec(&p->ttq_entry.when, -10000);
		csch->output_skew -= 10000;
		csch->first_send_ts += handler->dest_pt.clock_rate / 100;
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now);
	}
	else if (ts_diff_us < 0) {
		ts_diff_us *= -1;
		ilogs(transcoding, LOG_DEBUG, "Negative clock skew of %lli.%01lli ms detected, shifting send timer forward",
			ts_diff_us / 1000,
			(ts_diff_us % 1000) / 100);
		timeval_add_usec(&p->ttq_entry.when, ts_diff_us);
		csch->output_skew += ts_diff_us;
		csch->first_send_ts -= (long long) handler->dest_pt.clock_rate * ts_diff_us / 1000000;
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now); // should be 0 now
	}

send:
	ilogs(transcoding, LOG_DEBUG, "Scheduling to send RTP packet (seq %u TS %lu) in %s%lli.%01lli ms (at %lu.%06lu)",
			ntohs(rh->seq_num),
			ts,
			ts_diff_us < 0 ? "-" : "",
			llabs(ts_diff_us / 1000),
			llabs((ts_diff_us % 1000) / 100),
			(long unsigned) p->ttq_entry.when.tv_sec,
			(long unsigned) p->ttq_entry.when.tv_usec);

	t_queue_push_tail(&mp->packets_out, p);
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

static int codec_add_dtmf_packet(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		unsigned long ts_delay,
		int payload_type,
		struct media_packet *mp)
{
	struct codec_handler *h = ch->handler;
	struct codec_ssrc_handler *output_ch = NULL;

	// grab our underlying PCM transcoder
	output_ch = __output_ssrc_handler(input_ch, mp);
	if (G_UNLIKELY(!output_ch->encoder))
		goto skip;

	ch->csch = output_ch->csch;

	// the correct output TS is the encoder's FIFO PTS at the start of the DTMF
	// event. however, we must shift the FIFO PTS forward as the DTMF event goes on
	// as the DTMF event replaces the audio samples. therefore we must remember
	// the TS at the start of the event and the last seen event duration.
	if (ch->dtmf_ts != packet->ts) {
		// this is a new event
		ch->dtmf_ts = packet->ts; // start TS
		ch->last_dtmf_event_ts = 0; // last DTMF event duration
	}

	unsigned long ts = fraction_divl(output_ch->encoder->next_pts, &output_ch->encoder->clockrate_fact);
	// roll back TS to start of event
	ts -= ch->last_dtmf_event_ts;
	// adjust to output RTP TS
	unsigned long packet_ts = ts + output_ch->csch.first_ts;

	ilogs(transcoding, LOG_DEBUG, "Scaling DTMF packet timestamp and duration: TS %lu -> %lu "
			"(%u -> %u)",
			packet->ts, packet_ts,
			h->source_pt.clock_rate, h->dest_pt.clock_rate);
	packet->ts = packet_ts;

	if (packet->payload->len >= sizeof(struct telephone_event_payload)) {
		struct telephone_event_payload *dtmf = (void *) packet->payload->s;
		unsigned int duration = av_rescale(ntohs(dtmf->duration),
				h->dest_pt.clock_rate, h->source_pt.clock_rate);
		dtmf->duration = htons(duration);

		// we can't directly use the RTP TS to schedule the send, as we have to adjust it
		// by the duration
		if (ch->dtmf_first_duration == 0 || duration < ch->dtmf_first_duration)
			ch->dtmf_first_duration = duration;
		ts_delay = duration - ch->dtmf_first_duration;

		// shift forward our output RTP TS
		output_ch->encoder->next_pts = fraction_multl(ts + duration, &output_ch->encoder->clockrate_fact);
		output_ch->encoder->packet_pts += fraction_multl(duration - ch->last_dtmf_event_ts, &output_ch->encoder->clockrate_fact);
		ch->last_dtmf_event_ts = duration;
	}
	payload_type = h->dtmf_payload_type;
	if (payload_type == -1)
		payload_type = h->real_dtmf_payload_type;

skip:
	obj_put(&output_ch->h);
	char *buf = bufferpool_alloc(media_bufferpool,
			packet->payload->len + sizeof(struct rtp_header) + RTP_BUFFER_TAIL_ROOM);
	memcpy(buf + sizeof(struct rtp_header), packet->payload->s, packet->payload->len);
	if (packet->bypass_seq) // inject original seq
		codec_output_rtp(mp, &ch->csch, packet->handler ? : h, buf, packet->payload->len, packet->ts,
				packet->marker, packet->p.seq, -1, payload_type, ts_delay);
	else // use our own sequencing
		codec_output_rtp(mp, &ch->csch, packet->handler ? : h, buf, packet->payload->len, packet->ts,
				packet->marker, -1, 0, payload_type, ts_delay);
	mp->ssrc_out->parent->seq_diff++;

	return 0;
}

// forwards DTMF input to DTMF output, plus rescaling duration
static tc_code packet_dtmf_fwd(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		struct media_packet *mp)
{
	int payload_type = -1; // take from handler's output config
	unsigned long ts_delay = 0;
	struct codec_handler *h = ch->handler;
	struct codec_handler *input_h = input_ch->handler;

	tc_code ret = __buffer_delay_packet(input_h->delay_buffer, ch, input_ch, packet, ts_delay, payload_type,
			codec_add_dtmf_packet, mp, h->source_pt.clock_rate);
	__buffer_delay_seq(input_h->delay_buffer, mp, -1);
	return ret;
}

// returns the codec handler for the primary payload type - mostly determined by guessing
static struct codec_handler *__input_handler(struct codec_handler *h, struct media_packet *mp) {
	if (!mp->ssrc_in)
		return h;

	for (int i = 0; i < mp->ssrc_in->tracker.most_len; i++) {
		int prim_pt = mp->ssrc_in->tracker.most[i];
		if (prim_pt == 255)
			continue;

		struct codec_handler *sequencer_h = codec_handler_get(mp->media, prim_pt, mp->media_out, NULL);
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

// returns: -1 = error, 0 = processed ok, 1 = duplicate, already processed
static int packet_dtmf_event(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	LOCK(&mp->media->dtmf_lock);

	if (mp->media->dtmf_ts == packet->ts)
		return 1; // ignore already processed events

	int ret = dtmf_event_packet(mp, packet->payload, ch->handler->source_pt.clock_rate, packet->ts);
	if (G_UNLIKELY(ret == -1)) // error
		return -1;
	if (ret == 1) {
		// END event
		mp->media->dtmf_ts = packet->ts;
		input_ch->dtmf_start_ts = 0;
	}
	else
		input_ch->dtmf_start_ts = packet->ts ? packet->ts : 1;

	return 0;
}

static tc_code packet_dtmf(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	int dtmf_event_processed = packet_dtmf_event(ch, input_ch, packet, mp);
	if (dtmf_event_processed == -1)
		return TCC_ERR;


	enum block_dtmf_mode block_dtmf = dtmf_get_block_mode(mp->call, mp->media->monologue);

	bool do_blocking = block_dtmf == BLOCK_DTMF_DROP;

	if (packet->payload->len >= sizeof(struct telephone_event_payload)) {
		struct telephone_event_payload *dtmf = (void *) packet->payload->s;
		struct codec_handler *h = input_ch->handler;
		// fudge up TS and duration values
		uint64_t duration = (uint64_t) h->source_pt.clock_rate * h->source_pt.ptime / 1000;
		uint64_t ts = packet->ts + ntohs(dtmf->duration) - duration;

		// remember this as last "encoder" TS
		atomic_set_na(&mp->ssrc_in->stats->timestamp, ts);

		// provide an uninitialised buffer as potential output storage for DTMF
		char buf[sizeof(struct telephone_event_payload)];
		str ev_pl = STR_LEN(buf, sizeof(buf));

		int is_dtmf = dtmf_event_payload(&ev_pl, &ts, duration,
				&input_ch->dtmf_event, &input_ch->dtmf_events);
		if (is_dtmf) {
			// generate appropriate transcode_packets
			unsigned int copies = 1;
			if (dtmf_event_processed == 1) // discard duplicate end packets
				copies = 0;
			else if (is_dtmf == 3) // end event
				copies = 3;

			// fix up RTP header
			struct rtp_header r;
			r = *mp->rtp;
			r.m_pt = h->dtmf_payload_type;
			r.timestamp = htonl(ts);

			for (; copies > 0; copies--) {
				struct transcode_packet *dup = g_slice_alloc(sizeof(*dup));
				*dup = *packet;
				dup->payload = str_dup(&ev_pl);
				dup->rtp = r;
				dup->bypass_seq = 0;
				dup->ts = ts;
				if (is_dtmf == 1)
					dup->marker = 1;

				tc_code ret = TCC_OK;

				if (__buffer_dtx(input_ch->dtx_buffer, ch, input_ch, dup, mp, packet_dtmf_fwd))
					ret = TCC_CONSUMED;
				else
					ret = packet_dtmf_fwd(ch, input_ch, dup, mp);
				mp->ssrc_out->parent->seq_diff++;

				if (ret != TCC_CONSUMED)
					__transcode_packet_free(dup);
			}
			mp->ssrc_out->parent->seq_diff--;

			// discard the received event
			do_blocking = true;


		}
		else if (!input_ch->dtmf_events.length)
			ML_CLEAR(mp->media->monologue, DTMF_INJECTION_ACTIVE);

	}

	tc_code ret = TCC_OK;

	if (do_blocking)
		{ }
	else {
		// pass through
		if (__buffer_dtx(input_ch->dtx_buffer, ch, input_ch, packet, mp, packet_dtmf_fwd))
			ret = TCC_CONSUMED;
		else
			ret = packet_dtmf_fwd(ch, input_ch, packet, mp);
	}

	return ret;
}
static tc_code packet_dtmf_dup(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		struct media_packet *mp)
{
	enum block_dtmf_mode block_dtmf = dtmf_get_block_mode(mp->call, mp->media->monologue);

	tc_code ret = TCC_OK;

	if (block_dtmf == BLOCK_DTMF_DROP)
		{ }
	else // pass through
		ret = packet_dtmf_fwd(ch, input_ch, packet, mp);
	return ret;
}

static int __handler_func_supplemental(struct codec_handler *h, struct media_packet *mp,
		tc_code (*packet_func)(struct codec_ssrc_handler *, struct codec_ssrc_handler *,
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
	packet->packet_func = packet_func;
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
	if (p->plain_free_func && p->plain.s)
		p->plain_free_func(p->plain.s);
	ssrc_ctx_put(&p->ssrc_out);
	g_slice_free1(sizeof(*p), p);
}
bool codec_packet_copy(struct codec_packet *p) {
	char *buf = bufferpool_alloc(media_bufferpool, p->s.len + RTP_BUFFER_TAIL_ROOM);
	memcpy(buf, p->s.s, p->s.len);
	p->s.s = buf;
	p->free_func = bufferpool_unref;
	return true;
}
struct codec_packet *codec_packet_dup(struct codec_packet *p) {
	struct codec_packet *dup = g_slice_alloc0(sizeof(*p));
	*dup = *p;
	codec_packet_copy(dup);
	if (dup->ssrc_out)
		ssrc_ctx_hold(dup->ssrc_out);
	if (dup->rtp)
		dup->rtp = (void *) dup->s.s;
	return dup;
}



rtp_payload_type *codec_make_payload_type(const str *codec_str, enum media_type type) {

	str codec_fmt = *codec_str;
	str codec, parms, chans, opts, extra_opts, fmt_params, codec_opts;
	if (!str_token_sep(&codec, &codec_fmt, '/'))
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

	rtp_payload_type *pt = g_slice_alloc0(sizeof(*pt));

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

void codec_init_payload_type(rtp_payload_type *pt, enum media_type type) {
#ifdef WITH_TRANSCODING
	ensure_codec_def_type(pt, type);
	codec_def_t *def = pt->codec_def;

	if (def) {
		if (!pt->clock_rate)
			pt->clock_rate = def->default_clockrate;
		if (!pt->channels)
			pt->channels = def->default_channels;
		if (pt->ptime <= 0)
			pt->ptime = def->default_ptime;
		if (!pt->format_parameters.s && def->default_fmtp)
			pt->format_parameters = STR(def->default_fmtp);

		codec_parse_fmtp(def, &pt->format, &pt->format_parameters, NULL);

		if (def->init)
			def->init(pt);

		if (pt->payload_type == -1 && def->rfc_payload_type >= 0) {
			const rtp_payload_type *rfc_pt = rtp_get_rfc_payload_type(def->rfc_payload_type);
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
	pt->encoding = call_str_cpy(&pt->encoding);
	pt->encoding_with_params = call_str_cpy_c(full_encoding);
	pt->encoding_with_full_params = call_str_cpy_c(full_full_encoding);
	pt->encoding_parameters = call_str_cpy_c(params);
	pt->format_parameters = call_str_cpy(&pt->format_parameters);
	pt->codec_opts = call_str_cpy(&pt->codec_opts);

	// allocate everything from the rtcp-fb list
	for (GList *l = pt->rtcp_fb.head; l; l = l->next) {
		str *fb = l->data;
		l->data = call_str_dup(fb);
	}
}



#ifdef WITH_TRANSCODING


static int handler_func_passthrough_ssrc(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);
	if (!handler_silence_block(h, mp))
		return 0;

	uint32_t ts = ntohl(mp->rtp->timestamp);
	codec_calc_jitter(mp->ssrc_in, ts, h->source_pt.clock_rate, &mp->tv);
	codec_calc_lost(mp->ssrc_in, ntohs(mp->rtp->seq_num));

	// save original payload in case DTMF mangles it
	str orig_raw = mp->raw;

	// provide an uninitialised buffer as potential output storage for DTMF
	char buf[sizeof(*mp->rtp) + sizeof(struct telephone_event_payload) + RTP_BUFFER_TAIL_ROOM];

	// default function to return packets
	void (*add_packet_fn)(struct media_packet *mp, unsigned int clockrate) = codec_add_raw_packet;

	unsigned int duplicates = 0;

	// check for DTMF injection
	if (h->dtmf_payload_type != -1) {
		struct codec_ssrc_handler *ch = get_ssrc(mp->ssrc_in->parent->h.ssrc, h->ssrc_hash);
		if (ch) {
			uint64_t ts64 = ntohl(mp->rtp->timestamp);

			str ev_pl = { .s = buf + sizeof(*mp->rtp) };

			int is_dtmf = dtmf_event_payload(&ev_pl, &ts64,
					(uint64_t) h->source_pt.clock_rate * h->source_pt.ptime / 1000,
					&ch->dtmf_event, &ch->dtmf_events);
			if (is_dtmf) {
				// fix up RTP header
				struct rtp_header *r = (void *) buf;
				*r = *mp->rtp;
				r->m_pt = h->dtmf_payload_type;
				r->timestamp = htonl(ts64);
				if (is_dtmf == 1)
					r->m_pt |= 0x80;
				else if (is_dtmf == 3) // end event
					duplicates = 2;
				mp->rtp = r;
				mp->raw.s = buf;
				mp->raw.len = ev_pl.len + sizeof(*mp->rtp);

				add_packet_fn = codec_add_raw_packet_dup;
			}
			else if (!ch->dtmf_events.length)
				ML_CLEAR(mp->media->monologue, DTMF_INJECTION_ACTIVE);

			obj_put(&ch->h);
		}
	}

	// substitute out SSRC etc
	mp->rtp->ssrc = htonl(mp->ssrc_out->parent->h.ssrc);

	// to track our seq
	unsigned short seq = ntohs(mp->rtp->seq_num);

	while (true) {
		mp->rtp->seq_num = htons(seq + mp->ssrc_out->parent->seq_diff);

		// keep track of other stats here?

		__buffer_delay_raw(h->delay_buffer, h, add_packet_fn, mp, h->source_pt.clock_rate);

		if (duplicates == 0)
			break;
		duplicates--;
		mp->ssrc_out->parent->seq_diff++;
	}

	// restore original in case it was mangled
	mp->raw = orig_raw;

	return 0;
}


static void __transcode_packet_free(struct transcode_packet *p) {
	free(p->payload);
	g_slice_free1(sizeof(*p), p);
}

static struct ssrc_entry *__ssrc_handler_new(void *p) {
	// XXX combine with __ssrc_handler_transcode_new
	struct codec_handler *h = p;
	__auto_type ch = obj_alloc0(struct codec_ssrc_handler, __free_ssrc_handler);
	ch->handler = h;
	ch->ptime = h->source_pt.ptime;
	if (!ch->ptime)
		ch->ptime = 20;
	return &ch->h;
}

static void __dtmf_dsp_callback(void *ptr, int code, int level, int delay) {
	struct codec_ssrc_handler *ch = ptr;
	uint64_t ts = ch->last_dtmf_event_ts + delay;
	ch->last_dtmf_event_ts = ts;
	ts = av_rescale(ts, ch->encoder_format.clockrate, ch->dtmf_format.clockrate);
	codec_add_dtmf_event(ch, code, level, ts, false);
}

void codec_add_dtmf_event(struct codec_ssrc_handler *ch, int code, int level, uint64_t ts, bool injected) {
	struct dtmf_event new_ev = { .code = code, .volume = level, .ts = ts };
	ilogs(transcoding, LOG_DEBUG, "DTMF event state change: code %i, volume %i, TS %lu",
			new_ev.code, new_ev.volume, (unsigned long) ts);
	dtmf_dsp_event(&new_ev, &ch->dtmf_state, ch->handler->media, ch->handler->source_pt.clock_rate,
			ts + ch->csch.first_ts, injected);

	// add to queue if we're doing PCM -> DTMF event conversion
	// this does not capture events when doing DTMF delay (dtmf_payload_type == -1)
	// unless this is an injected event, in which case we check the real payload type
	if (ch->handler->dtmf_payload_type != -1 || (injected && ch->handler->real_dtmf_payload_type != -1)) {
		struct dtmf_event *ev = g_slice_alloc(sizeof(*ev));
		*ev = new_ev;
		t_queue_push_tail(&ch->dtmf_events, ev);
	}
}

uint64_t codec_last_dtmf_event(struct codec_ssrc_handler *ch) {
	struct dtmf_event *ev = t_queue_peek_tail(&ch->dtmf_events);
	if (!ev)
		ev = &ch->dtmf_state;
	return ev->ts;
}

uint64_t codec_encoder_pts(struct codec_ssrc_handler *ch, struct ssrc_ctx *ssrc_in) {
	if (!ch || !ch->encoder) {
		if (!ssrc_in)
			return 0;
		uint64_t cur = atomic_get_na(&ssrc_in->stats->timestamp);
		// return the TS of the next expected packet
		if (ch)
			cur += (uint64_t) ch->ptime * ch->handler->source_pt.clock_rate / 1000;
		return cur;
	}
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
			media->encoder_callback.amr.cmr_in = GPOINTER_TO_UINT(ptr);
			media->encoder_callback.amr.cmr_in_ts = rtpe_now;
			break;
		case CE_AMR_SEND_CMR:
			// ignore locking and races for this
			media->encoder_callback.amr.cmr_out = GPOINTER_TO_UINT(ptr);
			media->encoder_callback.amr.cmr_out_ts = rtpe_now;
			break;
		case CE_EVS_CMR_RECV:
			// ignore locking and races for this
			media->encoder_callback.evs.cmr_in = GPOINTER_TO_UINT(ptr);
			media->encoder_callback.evs.cmr_in_ts = rtpe_now;
			break;
		default:
			break;
	}
	return 0;
}

// must be locked
static void __delay_buffer_schedule(struct delay_buffer *dbuf) {
	if (dbuf->ct.next.tv_sec) // already scheduled?
		return;

	struct delay_frame *dframe = t_queue_peek_tail(&dbuf->frames);
	if (!dframe)
		return;

	struct timeval to_run = dframe->mp.tv;
	timeval_add_usec(&to_run, dbuf->delay * 1000);
	dbuf->ct.next = to_run;
	timerthread_obj_schedule_abs(&dbuf->ct.tt_obj, &dbuf->ct.next);
}

static bool __buffer_delay_do_direct(struct delay_buffer *dbuf) {
	if (!dbuf)
		return true;
	LOCK(&dbuf->lock);
	if (dbuf->delay == 0 && dbuf->frames.length == 0)
		return true;
	return false;
}

static int delay_frame_cmp(const struct delay_frame *a, const struct delay_frame *b, void *ptr) {
	return -1 * timeval_cmp(&a->mp.tv, &b->mp.tv);
}

INLINE struct codec_ssrc_handler *ssrc_handler_get(struct codec_ssrc_handler *ch) {
	return (struct codec_ssrc_handler *) obj_get(&ch->h);
}

// consumes frame
// `frame` can be NULL (discarded/lost packet)
static void __buffer_delay_frame(struct delay_buffer *dbuf, struct codec_ssrc_handler *ch,
		encoder_input_func_t input_func, AVFrame *frame, struct media_packet *mp, uint32_t ts)
{
	if (__buffer_delay_do_direct(dbuf)) {
		// input now
		if (frame) {
			input_func(ch->encoder, frame, ch->handler->packet_encoded, ch, mp);
			av_frame_free(&frame);
		}
		return;
	}

	struct delay_frame *dframe = g_slice_alloc0(sizeof(*dframe));
	dframe->frame = frame;
	dframe->encoder_func = input_func;
	dframe->ts = ts;
	dframe->ch = ssrc_handler_get(ch);
	dframe->handler = ch->handler;
	media_packet_copy(&dframe->mp, mp);

	LOCK(&dbuf->lock);
	t_queue_insert_sorted(&dbuf->frames, dframe, delay_frame_cmp, NULL);

	__delay_buffer_schedule(dbuf);

}

static void __buffer_delay_raw(struct delay_buffer *dbuf, struct codec_handler *handler,
		raw_input_func_t input_func, struct media_packet *mp, unsigned int clockrate)
{
	if (__buffer_delay_do_direct(dbuf)) {
		// direct passthrough
		input_func(mp, clockrate);
		return;
	}

	struct delay_frame *dframe = g_slice_alloc0(sizeof(*dframe));
	dframe->raw_func = input_func;
	dframe->clockrate = clockrate;
	dframe->handler = handler;
	media_packet_copy(&dframe->mp, mp);

	// also copy packet payload
	dframe->mp.raw = mp->raw;
	dframe->mp.raw.s = g_malloc(mp->raw.len + RTP_BUFFER_TAIL_ROOM);
	memcpy(dframe->mp.raw.s, mp->raw.s, mp->raw.len);

	LOCK(&dbuf->lock);
	t_queue_insert_sorted(&dbuf->frames, dframe, delay_frame_cmp, NULL);

	__delay_buffer_schedule(dbuf);
}

static tc_code __buffer_delay_packet(struct delay_buffer *dbuf,
		struct codec_ssrc_handler *ch,
		struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet,
		unsigned long ts_delay,
		int payload_type,
		packet_input_func_t packet_func, struct media_packet *mp, unsigned int clockrate)
{
	if (__buffer_delay_do_direct(dbuf)) {
		// direct passthrough
		packet_func(ch, input_ch, packet, ts_delay, payload_type, mp);
		return TCC_OK;
	}

	struct delay_frame *dframe = g_slice_alloc0(sizeof(*dframe));
	dframe->packet_func = packet_func;
	dframe->clockrate = clockrate;
	dframe->ch = ch ? ssrc_handler_get(ch) : NULL;
	dframe->input_ch = input_ch ? ssrc_handler_get(input_ch) : NULL;
	dframe->ts_delay = ts_delay;
	dframe->payload_type = payload_type;
	dframe->packet = packet;
	dframe->ts = packet->ts;
	dframe->handler = ch ? ch->handler : NULL;
	media_packet_copy(&dframe->mp, mp);

	LOCK(&dbuf->lock);
	t_queue_insert_sorted(&dbuf->frames, dframe, delay_frame_cmp, NULL);

	__delay_buffer_schedule(dbuf);

	return TCC_CONSUMED;
}

static void __buffer_delay_seq(struct delay_buffer *dbuf, struct media_packet *mp, int seq_adj) {
	if (!mp->ssrc_out)
		return;

	if (__buffer_delay_do_direct(dbuf)) {
		mp->ssrc_out->parent->seq_diff += seq_adj;
		return;
	}

	LOCK(&dbuf->lock);

	// peg the adjustment to the most recent frame if any
	struct delay_frame *dframe = t_queue_peek_head(&dbuf->frames);
	if (!dframe) {
		mp->ssrc_out->parent->seq_diff += seq_adj;
		return;
	}

	dframe->seq_adj += seq_adj;
}

// consumes `packet` if buffered (returns true)
// `packet` can be NULL (discarded packet for seq tracking)
static bool __buffer_dtx(struct dtx_buffer *dtxb, struct codec_ssrc_handler *decoder_handler,
		struct codec_ssrc_handler *input_handler,
		struct transcode_packet *packet, struct media_packet *mp,
		tc_code (*dtx_func)(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
			struct transcode_packet *packet,
			struct media_packet *mp))
{
	if (!dtxb || !mp->sfd || !mp->ssrc_in || !mp->ssrc_out)
		return false;

	unsigned long ts = packet ? packet->ts : 0;

	// allocate packet object
	struct dtx_packet *dtxp = g_slice_alloc0(sizeof(*dtxp));
	dtxp->packet = packet;
	dtxp->dtx_func = dtx_func;
	if (decoder_handler)
		dtxp->decoder_handler = ssrc_handler_get(decoder_handler);
	if (input_handler)
		dtxp->input_handler = ssrc_handler_get(input_handler);
	media_packet_copy(&dtxp->mp, mp);

	// add to processing queue

	mutex_lock(&dtxb->lock);

	dtxb->start = rtpe_now.tv_sec;
	t_queue_push_tail(&dtxb->packets, dtxp);
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

	// packet now consumed if there was one
	bool ret = packet ? true : false;
	packet = NULL;

	mutex_unlock(&dtxb->lock);

	return ret;
}

static void send_buffered(struct media_packet *mp, unsigned int log_sys) {
	struct sink_handler *sh = &mp->sink;
	struct packet_stream *sink = sh->sink;

	if (!sink)
		media_socket_dequeue(mp, NULL); // just free
	else {
		if (sh->handler && media_packet_encrypt(sh->handler->out->rtp_crypt, sink, mp))
			ilogsn(log_sys, LOG_ERR | LOG_FLAG_LIMIT, "Error encrypting buffered RTP media");

		mutex_lock(&sink->out_lock);
		if (media_socket_dequeue(mp, sink))
			ilogsn(log_sys, LOG_ERR | LOG_FLAG_LIMIT,
					"Error sending buffered media to RTP sink");
		mutex_unlock(&sink->out_lock);
	}
}

static void delay_frame_free(struct delay_frame *dframe) {
	av_frame_free(&dframe->frame);
	g_free(dframe->mp.raw.s);
	media_packet_release(&dframe->mp);
	if (dframe->ch)
		obj_put(&dframe->ch->h);
	if (dframe->input_ch)
		obj_put(&dframe->input_ch->h);
	if (dframe->packet)
		__transcode_packet_free(dframe->packet);
	g_slice_free1(sizeof(*dframe), dframe);
}
static void delay_frame_send(struct delay_frame *dframe) {
	send_buffered(&dframe->mp, log_level_index_transcoding);
}
static void delay_frame_flush(struct delay_buffer *dbuf, struct delay_frame *dframe) {
	// call is locked in W here
	__delay_frame_process(dbuf, dframe);
	delay_frame_send(dframe);
	delay_frame_free(dframe);
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
static void delay_buffer_stop(struct delay_buffer **pcmbp) {
	codec_timer_stop((struct codec_timer **) pcmbp);
}
static void dtx_buffer_stop(struct dtx_buffer **dtxbp) {
	codec_timer_stop((struct codec_timer **) dtxbp);
}


static void delay_frame_manipulate(struct delay_frame *dframe) {
	struct call_media *media = dframe->mp.media;
	if (!media)
		return;

	AVFrame *frame = dframe->frame;

	struct call_monologue *ml = media->monologue;
	enum block_dtmf_mode mode = dtmf_get_block_mode(dframe->mp.call, ml);

	if (mode == BLOCK_DTMF_OFF && media->monologue->dtmf_delay == 0)
		return;

	mutex_lock(&media->dtmf_lock);
	struct dtmf_event *dtmf_recv = is_in_dtmf_event(&media->dtmf_recv, dframe->ts, frame->sample_rate,
			media->buffer_delay, media->buffer_delay);
	struct dtmf_event *dtmf_send = is_in_dtmf_event(&media->dtmf_send, dframe->ts, frame->sample_rate,
			0, 0);
	mutex_unlock(&media->dtmf_lock);

	if (mode == BLOCK_DTMF_OFF) {
		if (!dtmf_send) {
			mode = BLOCK_DTMF_SILENCE;

			if (dframe->ch->handler->real_dtmf_payload_type != -1) {
				// add end event to queue
				if (dframe->ch->dtmf_event.code) {
					struct dtmf_event *ev = g_slice_alloc0(sizeof(*ev));
					uint64_t ts = dframe->ch->encoder ? dframe->ch->encoder->next_pts
						: dframe->ts;
					*ev = (struct dtmf_event) { .code = 0, .volume = 0, .ts = ts };
					t_queue_push_tail(&dframe->ch->dtmf_events, ev);
				}
			}

			if (!dtmf_recv)
				return;
		}
		else
			mode = dtmf_send->block_dtmf;
	}
	else if (!dtmf_recv)
		return;

	// XXX this should be used for DTMF injection instead of a separate codec handler

	switch (mode) {
		case BLOCK_DTMF_OFF:
			// DTMF delay mode: play original DTMF
			// `dtmf_send` is valid ONLY HERE
			if (dframe->ch->handler->real_dtmf_payload_type != -1) {
				// add event to handler queue so the packet can be translated
				// to DTMF event packet.
				memset(frame->extended_data[0], 0, frame->linesize[0]);
				// XXX quite some redundant operations here: first the incoming
				// DTMF event is decoded to audio, which is then later (maybe) replaced
				// by silence. when the delayed DTMF is reproduced, the frame samples
				// are first filled with silence, and then replaced
				// by the DTMF event packet in packet_encoded_rtp().
				if (dframe->ch->dtmf_event.code != dtmf_send->code) {
					// XXX this should be switched to proper state tracking instead
					// of using start/stop events
					struct dtmf_event *ev = g_slice_alloc0(sizeof(*ev));
					uint64_t ts = dframe->ch->encoder ? dframe->ch->encoder->next_pts
						: dframe->ts;
					*ev = (struct dtmf_event) { .code = dtmf_send->code,
						.volume = -1 * dtmf_send->volume,
						.ts = ts };
					t_queue_push_tail(&dframe->ch->dtmf_events, ev);
				}
			}
			else {
				// fill with DTMF PCM
				frame_fill_dtmf_samples(frame->format, frame->extended_data[0], dframe->ts,
						frame->nb_samples, dtmf_code_from_char(dtmf_send->code),
						dtmf_send->volume, frame->sample_rate,
						GET_CHANNELS(frame));
			}
			break;
		case BLOCK_DTMF_SILENCE:
			memset(frame->extended_data[0], 0, frame->linesize[0]);
			break;
		case BLOCK_DTMF_TONE:;
			unsigned int freq = 0;
			if (ml->tone_freqs && ml->tone_freqs->len)
				freq = g_array_index(ml->tone_freqs, unsigned int,
						dtmf_recv->index % ml->tone_freqs->len);
			frame_fill_tone_samples(frame->format, frame->extended_data[0], dframe->ts,
					frame->nb_samples, freq ?: 400,
					ml->tone_vol ? : 10, frame->sample_rate, GET_CHANNELS(frame));
			break;
		case BLOCK_DTMF_ZERO:
		case BLOCK_DTMF_DTMF:
			// if we have DTMF output, use silence, otherwise use a DTMF zero
			if (dframe->ch->handler->dtmf_payload_type != -1)
				memset(frame->extended_data[0], 0, frame->linesize[0]);
			else
				frame_fill_dtmf_samples(frame->format, frame->extended_data[0],
						dframe->ts,
						frame->nb_samples, dtmf_code_from_char(ml->dtmf_digit),
						ml->tone_vol ? : 10, frame->sample_rate,
						GET_CHANNELS(frame));
			break;
		case BLOCK_DTMF_RANDOM:
			frame_fill_dtmf_samples(frame->format, frame->extended_data[0], dframe->ts,
					frame->nb_samples, dtmf_recv->rand_code - '0',
					10, frame->sample_rate,
					GET_CHANNELS(frame));
			break;
		default:
			break;
	}
}
static void delay_packet_manipulate(struct delay_frame *dframe) {
	struct call_media *media = dframe->mp.media;
	if (!media)
		return;
	if (!dframe->handler)
		return;

	struct media_packet *mp = &dframe->mp;

	if (is_in_dtmf_event(&media->dtmf_recv, dframe->ts, dframe->clockrate, media->buffer_delay,
				media->buffer_delay))
	{
		// is this a DTMF event packet?
		if (!dframe->handler->source_pt.codec_def || !dframe->handler->source_pt.codec_def->dtmf)
			return;

		struct call_monologue *ml = media->monologue;
		enum block_dtmf_mode mode = dtmf_get_block_mode(dframe->mp.call, ml);

		// this can be a "raw" or "packet" - get the appropriate payload
		str *payload = &mp->raw;
		if (dframe->packet)
			payload = dframe->packet->payload;

		struct telephone_event_payload *dtmf = (void *) payload->s;
		if (payload->len < sizeof(*dtmf))
			return;

		switch (mode) {
			case BLOCK_DTMF_ZERO:
			case BLOCK_DTMF_DTMF:
				dtmf->event = dtmf_code_from_char(ml->dtmf_digit);
				break;
			default:
				break;
		}
	}
}
static void __delay_frame_process(struct delay_buffer *dbuf, struct delay_frame *dframe) {
	struct codec_ssrc_handler *csh = dframe->ch;

	if (csh && csh->handler && csh->encoder && dframe->encoder_func) {
		delay_frame_manipulate(dframe);
		dframe->encoder_func(csh->encoder, dframe->frame, csh->handler->packet_encoded,
				csh, &dframe->mp);
	}
	else if (dframe->raw_func) {
		delay_packet_manipulate(dframe);
		dframe->raw_func(&dframe->mp, dframe->clockrate);
	}
	else if (dframe->packet_func && dframe->packet) {
		delay_packet_manipulate(dframe);
		dframe->packet_func(csh, dframe->input_ch, dframe->packet, dframe->ts_delay,
				dframe->payload_type, &dframe->mp);
	}

	if (dframe->seq_adj)
		dframe->mp.ssrc_out->parent->seq_diff += dframe->seq_adj;
}
static void __delay_send_later(struct codec_timer *ct) {
	struct delay_buffer *dbuf = (void *) ct;

	call_t *call = NULL;
	struct delay_frame *dframe = NULL;

	{
		// short-term lock - copy out references to all relevant objects
		LOCK(&dbuf->lock);

		call = dbuf->call;
		if (call)
			obj_get(call);

		dframe = t_queue_pop_tail(&dbuf->frames);
	}

	if (!call) // do nothing
		goto out;

	// we can now do a top-down lock
	rwlock_lock_r(&call->master_lock);
	log_info_call(call);

	if (!dframe)
		goto out;

	__ssrc_lock_both(&dframe->mp);

	__delay_frame_process(dbuf, dframe);

	__ssrc_unlock_both(&dframe->mp);

	delay_frame_send(dframe);

	{
		// schedule next run
		LOCK(&dbuf->lock);
		dbuf->ct.next.tv_sec = 0;
		__delay_buffer_schedule(dbuf);
	}

out:
	// release all references
	if (call) {
		rwlock_unlock_r(&call->master_lock);
		obj_put(call);
		log_info_pop();
	}
	if (dframe)
		delay_frame_free(dframe);
}


static bool __dtx_drift_shift(struct dtx_buffer *dtxb, unsigned long ts,
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
		struct dtx_packet *dtxp_last = t_queue_peek_tail(&dtxb->packets);
		ts_diff = dtxp_last->packet ? dtxp_last->packet->ts - ts : 0;
		long long ts_diff_us = (long long) ts_diff * 1000000 / dtxb->clockrate;
		if (ts_diff_us >= (long long) rtpe_config.dtx_lag * 1000) {
			// overflow
			ilogs(dtx, LOG_DEBUG, "DTX timer queue overflowing (%i packets in queue, "
					"%lli ms delay), speeding up DTX timer by %i ms",
					dtxb->packets.length, ts_diff_us / 1000, rtpe_config.dtx_shift);
			timeval_add_usec(&dtxb->ct.next, rtpe_config.dtx_shift * -1000);
		}
	}

	return discard;
}
static bool __dtx_drift_drop(struct dtx_buffer *dtxb, unsigned long ts,
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
		struct dtx_packet *dtxp_last = t_queue_peek_tail(&dtxb->packets);
		ts_diff = dtxp_last->packet ? dtxp_last->packet->ts - ts : 0;
		long long ts_diff_us = (long long) ts_diff * 1000000 / dtxb->clockrate;
		if (ts_diff_us >= (long long) rtpe_config.dtx_lag * 1000) {
			// overflow
			ilogs(dtx, LOG_DEBUG, "DTX timer queue overflowing (%i packets in queue, "
					"%lli ms delay), discarding packet",
					dtxb->packets.length, ts_diff_us / 1000);
			discard = true;
		}
	}

	return discard;
}
static bool __dtx_handle_drift(struct dtx_buffer *dtxb, unsigned long ts,
		long tv_diff, long ts_diff,
		struct codec_ssrc_handler *ch)
{
	if (rtpe_config.dtx_shift)
		return __dtx_drift_shift(dtxb, ts, tv_diff, ts_diff, ch);
	return __dtx_drift_drop(dtxb, ts, tv_diff, ts_diff, ch);
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
	call_t *call;
	struct codec_ssrc_handler *ch;
	struct packet_stream *ps;
	struct codec_ssrc_handler *input_ch;

	while (true) {
		// do we have a packet?
		dtxp = t_queue_peek_head(&dtxb->packets);
		if (dtxp) {
			// inspect head packet and check TS, see if it's ready to be decoded
			ts = dtxp->packet ? dtxp->packet->ts : dtxb->head_ts;
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
				t_queue_pop_head(&dtxb->packets);
		}

		p_left = dtxb->packets.length;

		if (dtxp) {
			// save the `mp` for possible future DTX
			media_packet_release(&dtxb->last_mp);
			media_packet_copy(&dtxb->last_mp, &dtxp->mp);
			media_packet_copy(&mp_copy, &dtxp->mp);
			if (dtxb->head_ts)
				ts_diff = dtxp->packet ? dtxp->packet->ts - dtxb->head_ts : 0;
			else
				ts_diff = dtxb->tspp; // first packet
			if (dtxp->packet)
				ts = dtxb->head_ts = dtxp->packet->ts;
			else
				ts = dtxb->head_ts;
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
		ch = (dtxp && dtxp->decoder_handler) ? ssrc_handler_get(dtxp->decoder_handler)
			: NULL;
		if (!ch && dtxb->csh)
			ch = ssrc_handler_get(dtxb->csh);
		input_ch = (dtxp && dtxp->input_handler) ? ssrc_handler_get(dtxp->input_handler) : NULL;
		call = dtxb->call ? obj_get(dtxb->call) : NULL;

		// check but DTX buffer shutdown conditions
		bool shutdown = false;
		if (!call)
			shutdown = true;
		else if (!ch)
			shutdown = true;
		else if (!ps)
			shutdown = true;
		else if (!ps->ssrc_in[0])
			shutdown = true;
		else if (dtxb->ssrc != ps->ssrc_in[0]->parent->h.ssrc)
			shutdown = true;
		else if (dtxb->ct.next.tv_sec == 0)
			shutdown = true;
		else {
			shutdown = true; // default if no most used PTs are known

			for (int i = 0; i < ps->ssrc_in[0]->tracker.most_len; i++) {
				unsigned char most_pt = ps->ssrc_in[0]->tracker.most[i];
				shutdown = false;
				// we are good if the most used PT is
				// either us
				if (ch->handler->source_pt.payload_type == most_pt)
					break;
				// or our input PT (which is the audio PT if we are supplemental)
				if (ch->handler->input_handler && ch->handler->input_handler->source_pt.payload_type == most_pt)
					break;

				// looks like codec change, but...
				shutdown = true;

				// another possibility is that the most used PT is actually a supplemental type. check this,
				// and if true move on to the next most used PT.
				rtp_payload_type *pt = t_hash_table_lookup(ps->media->codecs.codecs,
						GUINT_TO_POINTER(most_pt));
				if (pt && pt->codec_def && pt->codec_def->supplemental)
					continue;

				// all other cases: codec change
				break;
			}
		}

		if (shutdown) {
			ilogs(dtx, LOG_DEBUG, "DTX buffer for %lx has been shut down", (unsigned long) dtxb->ssrc);
			dtxb->ct.next.tv_sec = 0;
			dtxb->head_ts = 0;
			mutex_unlock(&dtxb->lock);
			goto out; // shut down
		}

		if (!dtxp) // we need to do DTX
			break;

		bool discard = __dtx_handle_drift(dtxb, ts, tv_diff, ts_diff, ch);

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
	time_t dtxb_start = dtxb->start;

	mutex_unlock(&dtxb->lock);

	rwlock_lock_r(&call->master_lock);
	__ssrc_lock_both(&mp_copy);

	if (dtxp) {
		ilogs(dtx, LOG_DEBUG, "Decoding DTX-buffered RTP packet (TS %lu) now; "
				"%i packets left in queue", ts, p_left);

		mp_copy.ptime = -1;
		tc_code tcc = dtxp->dtx_func(ch, input_ch, dtxp->packet, &mp_copy);
		if (tcc >= TCC_OK) {
			if (mp_copy.ptime > 0)
				ptime = mp_copy.ptime;
			if (tcc == TCC_CONSUMED)
				dtxp->packet = NULL;
		}
		else
			ilogs(dtx, LOG_WARN | LOG_FLAG_LIMIT,
					"Decoder error while processing buffered RTP packet");
	}
	else {
		int diff = rtpe_now.tv_sec - dtxb_start;

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

	if (mp_copy.packets_out.length && ret == 0)
		send_buffered(&mp_copy, log_level_index_dtx);

	rwlock_unlock_r(&call->master_lock);

out:
	if (call) {
		obj_put(call);
		log_info_pop();
	}
	if (ch)
		obj_put(&ch->h);
	if (input_ch)
		obj_put(&input_ch->h);
	if (dtxp)
		dtx_packet_free(dtxp);
	media_packet_release(&mp_copy);
}
static void __dtx_shutdown(struct dtx_buffer *dtxb) {
	if (dtxb->csh)
		obj_put(&dtxb->csh->h);
	dtxb->csh = NULL;
	obj_release(dtxb->call);
	t_queue_clear_full(&dtxb->packets, dtx_packet_free);
}
static void __delay_buffer_shutdown(struct delay_buffer *dbuf, bool flush) {
	if (flush) {
		while (dbuf->frames.length) {
			struct delay_frame *dframe = t_queue_pop_tail(&dbuf->frames);
			delay_frame_flush(dbuf, dframe);
		}
	}
	else
		t_queue_clear_full(&dbuf->frames, delay_frame_free);
	obj_release(dbuf->call);
}
static void __dtx_free(struct dtx_buffer *dtxb) {
	__dtx_shutdown(dtxb);
	media_packet_release(&dtxb->last_mp);
	mutex_destroy(&dtxb->lock);
}
static void __delay_buffer_free(struct delay_buffer *dbuf) {
	__delay_buffer_shutdown(dbuf, false);
	mutex_destroy(&dbuf->lock);
}
static void __dtx_setup(struct codec_ssrc_handler *ch) {
	if (!ch->decoder)
		return;
	if (!decoder_has_dtx(ch->decoder))
		return;

	if (!rtpe_config.dtx_delay)
		return;

	struct dtx_buffer *dtx = ch->dtx_buffer;
	if (!dtx) {
		dtx = ch->dtx_buffer = obj_alloc0(struct dtx_buffer, __dtx_free);
		dtx->ct.tt_obj.tt = &codec_timers_thread;
		dtx->ct.timer_func = __dtx_send_later;
		mutex_init(&dtx->lock);
	}

	if (!dtx->csh)
		dtx->csh = ssrc_handler_get(ch);
	if (!dtx->call)
		dtx->call = obj_get(ch->handler->media->call);
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
static void __dtx_buffer_restart(void *p, void *arg) {
	struct codec_ssrc_handler *ch = p;
	__dtx_setup(ch);
}
static void __dtx_restart(struct codec_handler *h) {
	ssrc_hash_foreach(h->ssrc_hash, __dtx_buffer_restart, NULL);
}
static void __delay_buffer_setup(struct delay_buffer **dbufp,
		struct codec_handler *h, call_t *call, unsigned int delay)
{
	if (!dbufp)
		return;

	struct delay_buffer *dbuf = *dbufp;

	if (!dbuf) {
		if (!delay)
			return;
		dbuf = obj_alloc0(struct delay_buffer, __delay_buffer_free);
		dbuf->ct.tt_obj.tt = &codec_timers_thread;
		dbuf->ct.timer_func = __delay_send_later;
		dbuf->handler = h;
		mutex_init(&dbuf->lock);
	}

	if (!dbuf->call)
		dbuf->call = obj_get(call);
	dbuf->delay = delay;

	*dbufp = dbuf;
}
static void __ssrc_handler_stop(void *p, void *arg) {
	struct codec_ssrc_handler *ch = p;
	if (ch->dtx_buffer) {
		mutex_lock(&ch->dtx_buffer->lock);
		__dtx_shutdown(ch->dtx_buffer);
		mutex_unlock(&ch->dtx_buffer->lock);

		dtx_buffer_stop(&ch->dtx_buffer);
	}
	codec_cc_stop(ch->chain);
}
void codec_handlers_stop(codec_handlers_q *q, struct call_media *sink) {
	for (__auto_type l = q->head; l; l = l->next) {
		struct codec_handler *h = l->data;

		if (sink && h->sink != sink)
			continue;

		if (h->delay_buffer) {
			mutex_lock(&h->delay_buffer->lock);
			__delay_buffer_shutdown(h->delay_buffer, true);
			mutex_unlock(&h->delay_buffer->lock);

			delay_buffer_stop(&h->delay_buffer);
		}
		ssrc_hash_foreach(h->ssrc_hash, __ssrc_handler_stop, (void *) true);
	}
}




static void silence_event_free(struct silence_event *p) {
	g_slice_free1(sizeof(*p), p);
}

#define __silence_detect_type(type) \
static void __silence_detect_ ## type(struct codec_ssrc_handler *ch, AVFrame *frame, type thres) { \
	type *s = (void *) frame->data[0]; \
	struct silence_event *last = t_queue_peek_tail(&ch->silence_events); \
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
				t_queue_push_tail(&ch->silence_events, last); \
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
static int is_silence_event(str *inout, silence_event_q *events, uint64_t pts, uint64_t duration) {
	uint64_t end = pts + duration;

	while (events->length) {
		struct silence_event *first = t_queue_peek_head(events);
		if (first->start > pts) // future event
			return 0;
		if (!first->end) // ongoing event
			goto silence;
		if (first->end > end) // event finished with end in the future
			goto silence;
		// event has ended: remove it
		t_queue_pop_head(events);
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



static void *async_chain_start(void *x, void *y, void *z) {
	struct codec_ssrc_handler *ch = x;
	struct codec_ssrc_handler *input_ch = y;
	struct media_packet *mp = z;

	struct transcode_job *j = g_new0(__typeof(*j), 1);
	//printf("call %p inc refs %p %p job %p\n", mp->call, ch, input_ch, j);
	media_packet_copy(&j->mp, mp);
	j->ch = ssrc_handler_get(ch);
	j->input_ch = ssrc_handler_get(input_ch);

	return j;
}
static void async_chain_finish(AVPacket *pkt, void *async_cb_obj) {
	struct transcode_job *j = async_cb_obj;
	struct call *call = j->mp.call;

	gettimeofday(&rtpe_now, NULL);

	if (pkt) {
		rwlock_lock_r(&call->master_lock);
		__ssrc_lock_both(&j->mp);

		static const struct fraction chain_fact = {1,1};
		packet_encoded_packetize(pkt, j->ch, &j->mp, packetizer_passthrough, NULL, &chain_fact,
				packet_encoded_tx_seq_own);

		__ssrc_unlock_both(&j->mp);
		send_buffered(&j->mp, log_level_index_transcoding);
		rwlock_unlock_r(&call->master_lock);
	}

	transcode_job_free(j);
}

static bool __ssrc_handler_decode_common(struct codec_ssrc_handler *ch, struct codec_handler *h,
		const format_t *enc_format)
{
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
			enc_format, &h->source_pt.format,
			&h->source_pt.format_parameters, &h->source_pt.codec_opts);
	if (!ch->decoder)
		return false;
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

	__dtx_setup(ch);

	return true;
}
static struct ssrc_entry *__ssrc_handler_transcode_new(void *p) {
	struct codec_handler *h = p;

	if (!h->source_pt.codec_def || !h->dest_pt.codec_def)
		return NULL;

	ilogs(codec, LOG_DEBUG, "Creating SSRC transcoder from %s/%u/%i to "
			"%s/%u/%i",
			h->source_pt.codec_def->rtpname, h->source_pt.clock_rate,
			h->source_pt.channels,
			h->dest_pt.codec_def->rtpname, h->dest_pt.clock_rate,
			h->dest_pt.channels);

	__auto_type ch = obj_alloc0(struct codec_ssrc_handler, __free_ssrc_handler);
	ch->handler = h;
	ch->ptime = h->dest_pt.ptime;
	ch->sample_buffer = g_string_new("");
	ch->bitrate = h->dest_pt.bitrate ? : h->dest_pt.codec_def->default_bitrate;

	format_t dec_format = {
		.clockrate = h->source_pt.clock_rate,
		.channels = h->source_pt.channels,
		.format = -1,
	};
	format_t enc_format = {
		.clockrate = h->dest_pt.clock_rate,
		.channels = h->dest_pt.channels,
		.format = -1,
	};

	// see if there's a complete codec chain usable for this
	if (!h->pcm_dtmf_detect)
		ch->chain = codec_cc_new(h->source_pt.codec_def, &dec_format,
				h->dest_pt.codec_def, &enc_format,
				ch->bitrate, ch->ptime, async_chain_start, async_chain_finish);

	if (ch->chain) {
		ilogs(codec, LOG_DEBUG, "Using codec chain to transcode from " STR_FORMAT "/" STR_FORMAT
			" to " STR_FORMAT "/" STR_FORMAT,
				STR_FMT(&h->source_pt.encoding_with_params),
				STR_FMT0(&h->source_pt.format_parameters),
				STR_FMT(&h->dest_pt.encoding_with_params),
				STR_FMT0(&h->dest_pt.format_parameters));

		return &ch->h;
	}

	ch->encoder = encoder_new();
	if (!ch->encoder)
		goto err;
	if (encoder_config_fmtp(ch->encoder, h->dest_pt.codec_def,
				ch->bitrate,
				ch->ptime, &dec_format,
				&enc_format, &ch->encoder_format, &h->dest_pt.format,
				&h->dest_pt.format_parameters,
				&h->dest_pt.codec_opts))
		goto err;

	if (!__ssrc_handler_decode_common(ch, h, &ch->encoder_format))
		goto err;

	ch->bytes_per_packet = (ch->encoder->samples_per_packet ? : ch->encoder->samples_per_frame)
		* h->dest_pt.codec_def->bits_per_sample / 8;

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
static struct ssrc_entry *__ssrc_handler_decode_new(void *p) {
	struct codec_handler *h = p;

	ilogs(codec, LOG_DEBUG, "Creating SSRC decoder for %s/%u/%i",
			h->source_pt.codec_def->rtpname, h->source_pt.clock_rate,
			h->source_pt.channels);

	__auto_type ch = obj_alloc0(struct codec_ssrc_handler, __free_ssrc_handler);
	ch->handler = h;
	ch->ptime = h->dest_pt.ptime;

	format_t dest_format = {
		.clockrate = h->dest_pt.clock_rate,
		.channels = h->dest_pt.channels,
		.format = AV_SAMPLE_FMT_S16,
	};

	if (!__ssrc_handler_decode_common(ch, h, &dest_format))
		goto err;

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
static void __free_ssrc_handler(struct codec_ssrc_handler *ch) {
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
	codec_cc_free(&ch->chain);
	if (ch->sample_buffer)
		g_string_free(ch->sample_buffer, TRUE);
	if (ch->dtmf_dsp)
		dtmf_rx_free(ch->dtmf_dsp);
	resample_shutdown(&ch->dtmf_resampler);
	t_queue_clear_full(&ch->dtmf_events, dtmf_event_free);
	t_queue_clear_full(&ch->silence_events, silence_event_free);
	t_queue_clear(&ch->async_jobs);
	dtx_buffer_stop(&ch->dtx_buffer);
}


void packet_encoded_packetize(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		packetizer_f pkt_f, void *pkt_f_data, const struct fraction *cr_fact,
		void (*tx_f)(AVPacket *, struct codec_ssrc_handler *, struct media_packet *, str *,
			char *, unsigned int, const struct fraction *cr_fact))
{
	// run this through our packetizer
	AVPacket *in_pkt = pkt;

	while (true) {
		// figure out how big of a buffer we need
		unsigned int payload_len = MAX(MAX(pkt->size, ch->bytes_per_packet),
				sizeof(struct telephone_event_payload));
		unsigned int pkt_len = sizeof(struct rtp_header) + payload_len + RTP_BUFFER_TAIL_ROOM;
		// prepare our buffers
		char *buf = bufferpool_alloc(media_bufferpool, pkt_len);
		char *payload = buf + sizeof(struct rtp_header);
		// tell our packetizer how much we want
		str inout = STR_LEN(payload, payload_len);
		// and request a packet
		if (in_pkt)
			ilogs(transcoding, LOG_DEBUG, "Adding %i bytes to packetizer", in_pkt->size);
		int ret = pkt_f(in_pkt,
				ch->sample_buffer, &inout, pkt_f_data);

		if (G_UNLIKELY(ret == -1 || pkt->pts == AV_NOPTS_VALUE)) {
			// nothing
			bufferpool_unref(buf);
			break;
		}

		ilogs(transcoding, LOG_DEBUG, "Received packet of %zu bytes from packetizer", inout.len);

		tx_f(pkt, ch, mp, &inout, buf, pkt_len, cr_fact);

		if (ret == 0) {
			// no more to go
			break;
		}

		// loop around and get more
		in_pkt = NULL;
	}
}

static int packet_encoded_rtp(encoder_t *enc, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilogs(transcoding, LOG_DEBUG, "RTP media successfully encoded: TS %llu, len %i",
			(unsigned long long) enc->avpkt->pts, enc->avpkt->size);

	packet_encoded_packetize(enc->avpkt, ch, mp, enc->def->packetizer, enc, &enc->clockrate_fact,
			packet_encoded_tx);

	return 0;
}

static void __codec_output_rtp_seq_passthrough(struct media_packet *mp, struct codec_scheduler *csch,
		struct codec_handler *handler,
		char *buf, // bufferpool_alloc'd, room for rtp_header + filled-in payload
		unsigned int payload_len,
		unsigned long payload_ts,
		int marker, int payload_type,
		unsigned long ts_delay)
{
	codec_output_rtp(mp, csch, handler, buf, payload_len, payload_ts, marker, -1, 0, payload_type, ts_delay);
}

static void __codec_output_rtp_seq_own(struct media_packet *mp, struct codec_scheduler *csch,
		struct codec_handler *handler,
		char *buf, // bufferpool_alloc'd, room for rtp_header + filled-in payload
		unsigned int payload_len,
		unsigned long payload_ts,
		int marker, int payload_type,
		unsigned long ts_delay)
{
	// XXX this bypasses the send timer
	codec_output_rtp(mp, csch, handler, buf, payload_len, payload_ts, marker, mp->ssrc_out->seq_out++,
			0, payload_type, ts_delay);
}

static void __packet_encoded_tx(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		str *inout, char *buf, unsigned int pkt_len, const struct fraction *cr_fact,
		__typeof(__codec_output_rtp_seq_passthrough) func)
{
	// check special payloads

	unsigned int repeats = 0;
	unsigned long ts_delay = 0;
	int payload_type = -1;
	int dtmf_pt = ch->handler->dtmf_payload_type;
	if (dtmf_pt == -1)
		dtmf_pt = ch->handler->real_dtmf_payload_type;
	int is_dtmf = 0;

	if (dtmf_pt != -1)
		is_dtmf = dtmf_event_payload(inout, (uint64_t *) &pkt->pts, pkt->duration,
				&ch->dtmf_event, &ch->dtmf_events);
	if (is_dtmf) {
		payload_type = dtmf_pt;
		if (is_dtmf == 1)
			ch->rtp_mark = 1; // DTMF start event
		else if (is_dtmf == 3)
			repeats = 2; // DTMF end event
		// we need to pass a ts_delay to codec_output_rtp to ensure the calculated time
		// to send the packet is offset by the event duration of the DTMF packets
		// but we need to reduce it by one packet duration so that the delay is offset
		// from the first event packet
		struct telephone_event_payload *ev_pt = (void *) inout->s;
		ts_delay = ntohs(ev_pt->duration) - (ch->handler->dest_pt.ptime * ch->handler->dest_pt.clock_rate / 1000);
	}
	else {
		if (is_silence_event(inout, &ch->silence_events, pkt->pts, pkt->duration))
			payload_type = ch->handler->cn_payload_type;
	}

	// ready to send

	do {
		char *send_buf = buf;
		if (repeats > 0) {
			// need to duplicate the payload as codec_output_rtp consumes it
			send_buf = bufferpool_alloc(media_bufferpool, pkt_len);
			memcpy(send_buf, buf, pkt_len);
		}
		func(mp, &ch->csch, ch->handler, send_buf, inout->len, ch->csch.first_ts
				+ fraction_divl(pkt->pts, cr_fact),
				ch->rtp_mark ? 1 : 0,
				payload_type, ts_delay);
		mp->ssrc_out->parent->seq_diff++;
		ch->rtp_mark = 0;
	} while (repeats--);
}

static void packet_encoded_tx(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		str *inout, char *buf, unsigned int pkt_len, const struct fraction *cr_fact)
{
	__packet_encoded_tx(pkt, ch, mp, inout, buf, pkt_len, cr_fact, __codec_output_rtp_seq_passthrough);
}
static void packet_encoded_tx_seq_own(AVPacket *pkt, struct codec_ssrc_handler *ch, struct media_packet *mp,
		str *inout, char *buf, unsigned int pkt_len, const struct fraction *cr_fact)
{
	__packet_encoded_tx(pkt, ch, mp, inout, buf, pkt_len, cr_fact, __codec_output_rtp_seq_own);
}



static void __dtmf_detect(struct codec_ssrc_handler *ch, AVFrame *frame) {
	if (!ch->dtmf_dsp)
		return;
	if (!ch->handler->pcm_dtmf_detect) {
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
	if (dsp_frame != frame)
		av_frame_free(&dsp_frame);
}

static int packet_decoded_common(decoder_t *decoder, AVFrame *frame, void *u1, void *u2,
		encoder_input_func_t input_func)
{
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilogs(transcoding, LOG_DEBUG, "RTP media successfully decoded: TS %llu, samples %u",
			(unsigned long long) frame->pts, frame->nb_samples);

	// switch from input codec context to output context if necessary
	struct codec_ssrc_handler *new_ch = __output_ssrc_handler(ch, mp);
	if (new_ch != ch) {
		// copy some essential parameters
		if (!new_ch->csch.first_ts)
			new_ch->csch.first_ts = ch->csch.first_ts;

		if (decoder->def->supplemental) {
			// supp codecs return bogus timestamps. Adjust the frame's TS to be in
			// line with the primary decoder
			frame->pts -= new_ch->csch.first_ts;
		}

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
		ch->encoder->callback = mp->media_out->encoder_callback;

	uint32_t ts = frame->pts + ch->csch.first_ts;
	__buffer_delay_frame(h->input_handler ? h->input_handler->delay_buffer : h->delay_buffer,
			ch, input_func, frame, mp, ts);
	frame = NULL; // consumed

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
static int packet_decoded_audio_player(decoder_t *decoder, AVFrame *frame, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilogs(transcoding, LOG_DEBUG, "RTP media decoded for audio player: TS %llu, samples %u",
			(unsigned long long) frame->pts, frame->nb_samples);

	struct call_media *m = mp->media_out;
	if (!m || !m->audio_player) {
		// discard XXX log?
		return 0;
	}

	audio_player_add_frame(m->audio_player, ch->h.ssrc, frame);
	// XXX error checking/reporting

	return 0;
}

static tc_code __rtp_decode_direct(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	tc_code code = TCC_OK;
	if (packet) {
#ifdef HAVE_CODEC_CHAIN
		if (ch->chain) {
#else
		if (false) {
#endif
			static const struct fraction chain_fact = {1,1};
			AVPacket *pkt = codec_cc_input_data(ch->chain, packet->payload, packet->ts,
					/* x, y, z: */ ch, input_ch, mp);
			if (pkt) {
				packet_encoded_packetize(pkt, ch, mp, packetizer_passthrough, NULL, &chain_fact,
						packet_encoded_tx);
				av_packet_unref(pkt);
			}
		}
		else {
			int ret = decoder_input_data_ptime(ch->decoder, packet->payload, packet->ts, &mp->ptime,
					ch->handler->packet_decoded,
					ch, mp);
			code = ret == 0 ? TCC_OK : TCC_ERR;
		}
	}
	__buffer_delay_seq(input_ch->handler->delay_buffer, mp, -1);
	return code;
}
static tc_code __rtp_decode_async(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	struct transcode_job *j = g_new(__typeof(*j), 1);
	media_packet_copy(&j->mp, mp);
	j->ch = ssrc_handler_get(ch);
	j->input_ch = ssrc_handler_get(input_ch);
	j->packet = packet;
	j->done = false;

	// append-only here, with the SSRC handler locked
	t_queue_push_tail(&ch->async_jobs, j);

	// if this is the first job for this SSRC handler, notify async worker
	if (ch->async_jobs.length == 1) {
		LOCK(&transcode_lock);
		t_queue_push_tail(&transcode_jobs, j);
		cond_signal(&transcode_cond);
	}

	return TCC_CONSUMED;
}

static tc_code packet_decode(struct codec_ssrc_handler *ch, struct codec_ssrc_handler *input_ch,
		struct transcode_packet *packet, struct media_packet *mp)
{
	tc_code ret = TCC_OK;

	if (!ch->csch.first_ts)
		ch->csch.first_ts = packet->ts;

	if (ch->decoder && ch->decoder->def->dtmf) {
		if (packet_dtmf_event(ch, input_ch, packet, mp) == -1)
			goto out;
	}
	else {
		if (input_ch->dtmf_start_ts && !rtpe_config.dtmf_no_suppress) {
			if ((packet->ts > input_ch->dtmf_start_ts && packet->ts - input_ch->dtmf_start_ts > 80000) ||
					(packet->ts < input_ch->dtmf_start_ts && input_ch->dtmf_start_ts - packet->ts > 80000)) {
				ilogs(transcoding, LOG_DEBUG, "Resetting decoder DTMF state due to TS discrepancy");
				input_ch->dtmf_start_ts = 0;
			}
			else
				packet = NULL;
		}
	}

	if (__buffer_dtx(input_ch->dtx_buffer, ch, input_ch, packet, mp, __rtp_decode))
		ret = TCC_CONSUMED;
	else {
		ilogs(transcoding, LOG_DEBUG, "Decoding RTP packet now");
		ret = __rtp_decode(ch, input_ch, packet, mp);
	}

out:
	return ret;
}

#else

// dummy/stub
static void __buffer_delay_raw(struct delay_buffer *dbuf, struct codec_handler *handler,
		raw_input_func_t input_func, struct media_packet *mp, unsigned int clockrate)
{
	input_func(mp, clockrate);
}

#endif


void codec_update_all_handlers(struct call_monologue *ml) {
	for (int i = 0; i < ml->medias->len; i++)
	{
		struct call_media * source_media = ml->medias->pdata[i];
		if (!source_media)
			continue;

		for (__auto_type sub = source_media->media_subscribers.head; sub; sub = sub->next)
		{
			struct media_subscription * ms = sub->data;
			struct call_media * sink_media = ms->media;

			if (!sink_media)
				continue;

			codec_handlers_update(source_media, sink_media);
		}
	}

	dialogue_unconfirm(ml, "updating codec handlers");
}
void codec_update_all_source_handlers(struct call_monologue *ml, const sdp_ng_flags *flags) {

	for (int i = 0; i < ml->medias->len; i++)
	{
		struct call_media * sink_media = ml->medias->pdata[i];
		if (!sink_media)
			continue;

		for (__auto_type sub = sink_media->media_subscriptions.head; sub; sub = sub->next)
		{
			struct media_subscription * ms = sub->data;
			struct call_media * source_media = ms->media;

			if (!source_media)
				continue;

			codec_handlers_update(source_media, sink_media, .flags = flags);
		}
	}

	dialogue_unconfirm(ml, "updating codec source handlers");
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
	// ignore implausibly large values
	if (d < 100000)
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
	packet->packet_func = packet_decode;
	packet->rtp = *mp->rtp;
	packet->handler = h;

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

#endif





static rtp_payload_type *codec_make_payload_type_sup(const str *codec_str, struct call_media *media) {
	rtp_payload_type *ret = codec_make_payload_type(codec_str, media ? media->type_id : MT_UNKNOWN);
	if (!ret)
		goto err2;

#ifndef WITH_TRANSCODING

	return ret;

#else

	// check for type mismatch and don't warn if it is
	if (!ret->codec_def || (media && media->type_id && ret->codec_def->media_type != media->type_id)) {
		payload_type_free(ret);
		return NULL;
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

#endif

err2:
	ilogs(codec, LOG_WARN, "Codec '" STR_FORMAT "' requested for transcoding is not supported",
			STR_FMT(codec_str));
	return NULL;

}


#ifdef WITH_TRANSCODING

static rtp_payload_type *codec_add_payload_type_pt(rtp_payload_type *pt, struct call_media *media,
		struct call_media *other_media, struct codec_store *extra_cs)
{
	if (!pt)
		return NULL;
	pt->payload_type = __unused_pt_number(media, other_media, extra_cs, pt);
	if (pt->payload_type < 0) {
		ilogs(codec, LOG_WARN, "Ran out of RTP payload type numbers while adding codec '"
				STR_FORMAT "/" STR_FORMAT "' for transcoding",
			STR_FMT(&pt->encoding_with_params),
			STR_FMT0(&pt->format_parameters));
		payload_type_free(pt);
		return NULL;
	}

	return pt;
}
static rtp_payload_type *codec_add_payload_type(const str *codec, struct call_media *media,
		struct call_media *other_media, struct codec_store *extra_cs)
{
	rtp_payload_type *pt = codec_make_payload_type_sup(codec, media);
	return codec_add_payload_type_pt(pt, media, other_media, extra_cs);
}



#endif





void payload_type_clear(rtp_payload_type *p) {
	g_queue_clear(&p->rtcp_fb);
	ZERO(*p);
	p->payload_type = -1;
}
void payload_type_free(rtp_payload_type *p) {
	payload_type_clear(p);
	g_slice_free1(sizeof(*p), p);
}
void payload_type_destroy(rtp_payload_type **p) {
	if (*p)
		payload_type_free(*p);
	*p = NULL;
}


// dst must be pre-initialised (zeroed)
static void rtp_payload_type_copy(rtp_payload_type *dst, const rtp_payload_type *src) {
	payload_type_clear(dst);

	*dst = *src;

	// make shallow copy of lists
	g_queue_init(&dst->rtcp_fb);
	g_queue_append(&dst->rtcp_fb, &src->rtcp_fb);

	// duplicate contents
	codec_init_payload_type(dst, MT_UNKNOWN);
}

rtp_payload_type *rtp_payload_type_dup(const rtp_payload_type *pt) {
	rtp_payload_type *pt_copy = g_slice_alloc0(sizeof(*pt));
	rtp_payload_type_copy(pt_copy, pt);
	return pt_copy;
}
static void __rtp_payload_type_add_name(codec_names_ht ht, rtp_payload_type *pt) {
	GQueue *q = codec_names_ht_lookup_insert(ht, str_dup(&pt->encoding));
	g_queue_push_tail(q, GINT_TO_POINTER(pt->payload_type));
	q = codec_names_ht_lookup_insert(ht, str_dup(&pt->encoding_with_params));
	g_queue_push_tail(q, GINT_TO_POINTER(pt->payload_type));
	q = codec_names_ht_lookup_insert(ht, str_dup(&pt->encoding_with_full_params));
	g_queue_push_tail(q, GINT_TO_POINTER(pt->payload_type));
}
#ifdef WITH_TRANSCODING
static void __insert_codec_tracker(GHashTable *all_clockrates, GHashTable *all_supp_codecs,
		struct codec_tracker *sct, rtp_pt_list *link)
{
	rtp_payload_type *pt = link->data;

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
static int __codec_options_set1(call_t *call, rtp_payload_type *pt, const str *enc,
		str_case_value_ht codec_set)
{
	str *pt_str = t_hash_table_lookup(codec_set, enc);
	if (!pt_str)
		return 0;
	rtp_payload_type *pt_parsed = codec_make_payload_type(pt_str, MT_UNKNOWN);
	if (!pt_parsed)
		return 0;
	// match parameters
	if (pt->clock_rate != pt_parsed->clock_rate || pt->channels != pt_parsed->channels) {
		payload_type_free(pt_parsed);
		return 0;
	}
	// match - apply options
	if (pt_parsed->bitrate)
		pt->bitrate = pt_parsed->bitrate;
	if (!pt->codec_opts.len && pt_parsed->codec_opts.len) {
		str_free_dup(&pt->codec_opts);
		pt->codec_opts = pt_parsed->codec_opts;
		pt_parsed->codec_opts = STR_NULL;
	}
	payload_type_free(pt_parsed);
	return 1;
}
static void __codec_options_set(call_t *call, rtp_payload_type *pt, str_case_value_ht codec_set) {
	if (!call)
		return;
	if (!t_hash_table_is_set(codec_set))
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
static void codec_tracker_move(struct codec_tracker **dst, struct codec_tracker **src) {
#ifdef WITH_TRANSCODING
	codec_tracker_destroy(dst);
	*dst = *src;
	*src = NULL;
#endif
}
static void codec_touched_real(struct codec_store *cs, rtp_payload_type *pt) {
#ifdef WITH_TRANSCODING
	if (pt->codec_def && pt->codec_def->supplemental)
		return;
	g_hash_table_replace(cs->tracker->touched, GUINT_TO_POINTER(pt->clock_rate), (void *) 0x1);
#endif
}
static void codec_touched(struct codec_store *cs, rtp_payload_type *pt) {
#ifdef WITH_TRANSCODING
	if (pt->codec_def && pt->codec_def->supplemental) {
		cs->tracker->all_touched = 1;
		return;
	}
	g_hash_table_replace(cs->tracker->touched, GUINT_TO_POINTER(pt->clock_rate), (void *) 0x1);
#endif
}
static bool is_codec_touched_rate(struct codec_tracker *tracker, unsigned int clock_rate) {
#ifdef WITH_TRANSCODING
	if (!tracker || !tracker->touched)
		return false;
	if (tracker->all_touched)
		return true;
	return g_hash_table_lookup(tracker->touched, GUINT_TO_POINTER(clock_rate)) ? true : false;
#else
	return false;
#endif
}
static bool is_codec_touched(struct codec_store *cs, rtp_payload_type *pt) {
	if (!cs)
		return false;
	return is_codec_touched_rate(cs->tracker, pt->clock_rate);
}
#ifdef WITH_TRANSCODING
static int ptr_cmp(const void *a, const void *b) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}
void codec_tracker_update(struct codec_store *cs, struct codec_store *orig_cs) {
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
	GHashTable *all_supp_codecs = g_hash_table_new_full((GHashFunc) str_case_hash,
			(GEqualFunc) str_case_equal, free,
			(GDestroyNotify) g_hash_table_destroy);
	for (__auto_type l = cs->codec_prefs.head; l; l = l->next)
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
			if (!is_codec_touched_rate(sct, clockrate))
				continue;

			g_autoptr(char) pt_s
				= g_strdup_printf(STR_FORMAT "/%u", STR_FMT(supp_codec), clockrate);
			str pt_str = STR(pt_s);

			// see if we have a matching PT from before
			rtp_payload_type *pt = NULL;
			if (orig_cs) {
				GQueue *ptq = t_hash_table_lookup(orig_cs->codec_names, &pt_str);
				if (ptq) {
					for (GList *n = ptq->head; n; n = n->next) {
						pt = t_hash_table_lookup(orig_cs->codecs, n->data);
						if (!pt)
							continue;
						pt = rtp_payload_type_dup(pt);
						break;
					}
				}
			}

			if (!pt)
				pt = codec_add_payload_type(&pt_str, cs->media, NULL, NULL);
			if (!pt)
				continue;

			ilogs(codec, LOG_DEBUG, "Adding supplemental codec " STR_FORMAT " for clock rate %u (%i)",
					STR_FMT(supp_codec), clockrate, pt->payload_type);

			pt->for_transcoding = 1;

			codec_store_add_raw_order(cs, pt);
		}

		// finally check which clock rates are left over and remove those
		GList *to_remove = g_hash_table_get_keys(supp_clockrates);
		while (to_remove) {
			unsigned int clockrate = GPOINTER_TO_UINT(to_remove->data);
			to_remove = g_list_delete_link(to_remove, to_remove);

			// ignore if we haven't touched anything with that clock rate
			if (!is_codec_touched_rate(sct, clockrate))
				continue;

			GQueue *entries = g_hash_table_lookup(supp_clockrates, GUINT_TO_POINTER(clockrate));
			for (GList *j = entries->head; j; j = j->next) {
				rtp_pt_list *link = j->data;
				rtp_payload_type *pt = link->data;

				ilogs(codec, LOG_DEBUG, "Eliminating supplemental codec " STR_FORMAT "/" STR_FORMAT " (%i) with "
						"stray clock rate %u",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						pt->payload_type, clockrate);
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
	if (t_hash_table_is_set(cs->codecs))
		t_hash_table_destroy(cs->codecs);
	if (t_hash_table_is_set(cs->codec_names))
		t_hash_table_destroy(cs->codec_names);
	t_queue_clear_full(&cs->codec_prefs, payload_type_free);
	cs->supp_link = NULL;
	codec_tracker_destroy(&cs->tracker);
	ZERO(*cs);
}

void codec_store_init(struct codec_store *cs, struct call_media *media) {
	if (!media)
		media = cs->media;

	codec_store_cleanup(cs);

	cs->codecs = codecs_ht_new();
	cs->codec_names = codec_names_ht_new();
	cs->media = media;
	cs->tracker = codec_tracker_init();
}

static void codec_store_move(struct codec_store *dst, struct codec_store *src) {
	*dst = *src;
	ZERO(*src);
	codec_store_init(src, dst->media);
}

// `out_compat` must be initialised already, or NULL
// either `codec` or `pt_parsed` must be given (or both)
static void codec_store_find_matching_codecs(rtp_pt_q *out_compat, rtp_payload_type **out_exact,
		struct codec_store *cs, const str *codec,
		rtp_payload_type *pt_parsed)
{
	g_autoptr(rtp_payload_type) pt_store = NULL;
	rtp_payload_type *pt = NULL;

	if (pt_parsed)
		pt = pt_parsed;
	else {
		// parse out the codec params if any are given, otherwise just go with the name
		if (str_chr(codec, '/'))
			pt = pt_store = codec_make_payload_type_sup(codec, cs->media);
	}

	GQueue *pts = t_hash_table_lookup(cs->codec_names, codec);
	if (pt) {
		if (!pts)
			pts = t_hash_table_lookup(cs->codec_names, &pt->encoding_with_params);
		if (!pts)
			pts = t_hash_table_lookup(cs->codec_names, &pt->encoding);
	}
	if (!pts)
		return; // no matches
	// see if given format parameters match
	for (GList *k = pts->head; k; k = k->next) {
		rtp_payload_type *pt2 = t_hash_table_lookup(cs->codecs, k->data);
		if (!pt2)
			continue;
		ensure_codec_def(pt2, cs->media);
		int match;
		if (pt)
			match = rtp_payload_type_fmt_cmp(pt, pt2);
		else
			match = (str_cmp_str(codec, &pt2->encoding) == 0) ? 0 : -1;
		if (match == 0) {
			if (out_exact && !*out_exact)
				*out_exact = pt2;
			if (out_compat)
				t_queue_push_head(out_compat, pt2);
		}
		else if (out_compat && match == 1)
			t_queue_push_tail(out_compat, pt2);
	}
}

__attribute__((nonnull(1, 2)))
static void codec_store_add_raw_link(struct codec_store *cs, rtp_payload_type *pt, rtp_pt_list *link) {
	// cs->media may be NULL
	ensure_codec_def(pt, cs->media);
	if (cs->media && cs->media->ptime > 0)
		pt->ptime = cs->media->ptime;

	ilogs(internals, LOG_DEBUG, "Adding codec '" STR_FORMAT "'/'" STR_FORMAT "'/'" STR_FORMAT "'/'" STR_FORMAT "' at pos %p",
			STR_FMT(&pt->encoding),
			STR_FMT(&pt->encoding_with_params),
			STR_FMT0(&pt->format_parameters),
			STR_FMT(&pt->encoding_with_full_params), link);
	t_hash_table_insert(cs->codecs, GINT_TO_POINTER(pt->payload_type), pt);
	__rtp_payload_type_add_name(cs->codec_names, pt);
	if (!link) {
		t_queue_push_tail(&cs->codec_prefs, pt);
		pt->prefs_link = cs->codec_prefs.tail;
	}
	else {
		t_queue_insert_before(&cs->codec_prefs, link, pt);
		pt->prefs_link = link->prev;
	}
	if (!cs->supp_link && pt->codec_def && pt->codec_def->supplemental)
		cs->supp_link = pt->prefs_link;
}

// appends to the end, but before supplemental codecs
__attribute__((nonnull(1, 2)))
static void codec_store_add_raw_order(struct codec_store *cs, rtp_payload_type *pt) {
	codec_store_add_raw_link(cs, pt, cs->supp_link);
}
// appends to the end
__attribute__((nonnull(1, 2)))
void codec_store_add_raw(struct codec_store *cs, rtp_payload_type *pt) {
	codec_store_add_raw_link(cs, pt, NULL);
}

__attribute__((nonnull(1, 2)))
static rtp_payload_type *codec_store_add_link(struct codec_store *cs,
		rtp_payload_type *pt, rtp_pt_list *link)
{
	if (!cs->media)
		return NULL;

	ensure_codec_def(pt, cs->media);
	if (proto_is_not_rtp(cs->media->protocol))
		return NULL;

	rtp_payload_type *copy = rtp_payload_type_dup(pt);
	codec_store_add_raw_link(cs, copy, link);
	return copy;
}

// appends to the end, but before supplemental codecs
__attribute__((nonnull(1, 2)))
static rtp_payload_type *codec_store_add_order(struct codec_store *cs, rtp_payload_type *pt) {
	return codec_store_add_link(cs, pt, cs->supp_link);
}
// always add to end
__attribute__((nonnull(1, 2)))
static void codec_store_add_end(struct codec_store *cs, rtp_payload_type *pt) {
	codec_store_add_link(cs, pt, NULL);
}

static rtp_payload_type *codec_store_find_compatible_q(struct codec_store *cs, GQueue *q,
		const rtp_payload_type *pt)
{
	if (!q)
		return NULL;
	for (GList *l = q->head; l; l = l->next) {
		rtp_payload_type *ret = t_hash_table_lookup(cs->codecs, l->data);
		if (rtp_payload_type_fmt_eq_compat(ret, pt))
			return ret;
	}
	return NULL;
}
static rtp_payload_type *codec_store_find_compatible(struct codec_store *cs,
		const rtp_payload_type *pt)
{
	rtp_payload_type *ret;
	ret = codec_store_find_compatible_q(cs,
			t_hash_table_lookup(cs->codec_names, &pt->encoding_with_full_params),
			pt);
	if (ret)
		return ret;
	ret = codec_store_find_compatible_q(cs,
			t_hash_table_lookup(cs->codec_names, &pt->encoding_with_params),
			pt);
	if (ret)
		return ret;
	ret = codec_store_find_compatible_q(cs,
			t_hash_table_lookup(cs->codec_names, &pt->encoding),
			pt);
	if (ret)
		return ret;
	return NULL;
}

void __codec_store_populate_reuse(struct codec_store *dst, struct codec_store *src, struct codec_store_args a) {
	struct call_media *media = dst->media;
	call_t *call = media ? media->call : NULL;

	for (__auto_type l = src->codec_prefs.head; l; l = l->next) {
		rtp_payload_type *pt = l->data;
		rtp_payload_type *orig_pt = t_hash_table_lookup(dst->codecs,
				GINT_TO_POINTER(pt->payload_type));

		pt->reverse_payload_type = pt->payload_type;

		if (orig_pt)
			ilogs(codec, LOG_DEBUG, "Retaining codec " STR_FORMAT "/" STR_FORMAT " (%i)",
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters),
					pt->payload_type);
		else {
			if (!a.answer_only) {
				ilogs(codec, LOG_DEBUG, "Adding codec " STR_FORMAT "/" STR_FORMAT
					" (%i) to end of list",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						pt->payload_type);
				__codec_options_set(call, pt, a.codec_set);
				codec_store_add_end(dst, pt);
			}
			else
				ilogs(codec, LOG_DEBUG, "Not adding stray answer codec "
					STR_FORMAT "/" STR_FORMAT " (%i)",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						pt->payload_type);
		}
	}
	for (__auto_type l = dst->codec_prefs.head; l;) {
		rtp_payload_type *pt = l->data;
		rtp_payload_type *orig_pt = t_hash_table_lookup(src->codecs,
				GINT_TO_POINTER(pt->payload_type));
		if(!orig_pt){
			if (a.merge_cs)
				codec_store_add_raw_link(src, rtp_payload_type_dup(pt),
						src->codec_prefs.head);
			l = __codec_store_delete_link(l, dst);
		}else{
			l = l->next;
		}
	}
}

void codec_store_check_empty(struct codec_store *dst, struct codec_store *src, sdp_ng_flags *flags) {
	if (dst->codec_prefs.length)
		return;

	if (flags->allow_no_codec_media)
		return;

	ilog(LOG_WARN, "Usage error: List of codecs empty. Restoring original list of codecs. "
			"Results may be unexpected.");

	codec_store_populate(dst, src);
}

static void codec_store_merge(struct codec_store *dst, struct codec_store *src) {
	while (src->codec_prefs.length) {
		rtp_payload_type *pt = t_queue_pop_tail(&src->codec_prefs);

		// src codecs take preference over existing entries in dst: if there's
		// a collision in payload types, remove the existing entry in dst,
		// then replace with the entry from src
		rtp_payload_type *old_pt = t_hash_table_lookup(dst->codecs,
				GINT_TO_POINTER(pt->payload_type));
		if (old_pt)
			__codec_store_delete_link(old_pt->prefs_link, dst);

		codec_store_add_raw_link(dst, pt, dst->codec_prefs.head);
	}

	codec_store_cleanup(src);
}

void __codec_store_populate(struct codec_store *dst, struct codec_store *src, struct codec_store_args a) {
	// start fresh
	struct codec_store orig_dst;
	codec_store_move(&orig_dst, dst);

	struct call_media *media = dst->media;
	call_t *call = media ? media->call : NULL;

	for (__auto_type l = src->codec_prefs.head; l; l = l->next) {
		rtp_payload_type *pt = l->data;
		rtp_payload_type *orig_pt = t_hash_table_lookup(orig_dst.codecs,
				GINT_TO_POINTER(pt->payload_type));
		if (orig_pt && !rtp_payload_type_eq_compat(orig_pt, pt))
			orig_pt = NULL;
		if (a.answer_only && !orig_pt) {
			if (a.allow_asymmetric)
				orig_pt = codec_store_find_compatible(&orig_dst, pt);
			if (!orig_pt) {
				ilogs(codec, LOG_DEBUG, "Not adding stray answer codec "
					STR_FORMAT "/" STR_FORMAT " (%i)",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						pt->payload_type);
				continue;
			}
			if (orig_pt->codec_def && orig_pt->codec_def->supplemental)
				orig_pt = NULL;
		}
		ilogs(codec, LOG_DEBUG, "Adding codec " STR_FORMAT "/" STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters),
				pt->payload_type);

		pt->reverse_payload_type = pt->payload_type;

		if (orig_pt) {
			// carry over existing options
			pt->payload_type = orig_pt->payload_type;
			pt->ptime = orig_pt->ptime;
			pt->for_transcoding = orig_pt->for_transcoding;
			pt->accepted = orig_pt->accepted;
			pt->bitrate = orig_pt->bitrate;
			str_free_dup(&pt->codec_opts);
			pt->codec_opts = orig_pt->codec_opts;
			orig_pt->codec_opts = STR_NULL;
			if (pt->for_transcoding)
				codec_touched(dst, pt);
		}
		__codec_options_set(call, pt, a.codec_set);
		codec_store_add_end(dst, pt);
	}

	if (a.merge_cs)
		codec_store_merge(a.merge_cs, &orig_dst);
	else
		codec_store_cleanup(&orig_dst);
}

void codec_store_copy(struct codec_store *dst, struct codec_store *src) {
	codec_store_init(dst, src->media);

	for (__auto_type l = src->codec_prefs.head; l; l = l->next) {
		rtp_payload_type *pt = l->data;
		codec_store_add_end(dst, pt);
		if (l == src->supp_link)
			dst->supp_link = dst->codec_prefs.tail;
	}

	dst->strip_full = src->strip_full;
	dst->strip_all = src->strip_all;

#ifdef WITH_TRANSCODING
	dst->tracker->all_touched = src->tracker->all_touched;

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, src->tracker->touched);
	void *key;
	while (g_hash_table_iter_next(&iter, &key, NULL))
		g_hash_table_insert(dst->tracker->touched, key, (void *) 0x1);
#endif
}

void codec_store_strip(struct codec_store *cs, str_q *strip, str_case_ht except) {
	for (__auto_type l = strip->head; l; l = l->next) {
		str *codec = l->data;
		if (!str_cmp(codec, "all") || !str_cmp(codec, "full")) {
			if (!str_cmp(codec, "all"))
				cs->strip_all = 1;
			else
				cs->strip_full = 1;

			// strip all except ...
			__auto_type link = cs->codec_prefs.head;
			while (link) {
				__auto_type next = link->next;
				rtp_payload_type *pt = link->data;
				if (t_hash_table_is_set(except) && t_hash_table_lookup(except, &pt->encoding))
					;
				else if (t_hash_table_is_set(except) && t_hash_table_lookup(except, &pt->encoding_with_params))
					;
				else if (t_hash_table_is_set(except) && t_hash_table_lookup(except, &pt->encoding_with_full_params))
					;
				else {
					ilogs(codec, LOG_DEBUG, "Stripping codec " STR_FORMAT
						"/" STR_FORMAT " (%i) due to strip=all or strip=full",
							STR_FMT(&pt->encoding_with_params),
							STR_FMT0(&pt->format_parameters),
							pt->payload_type);
					codec_touched_real(cs, pt);
					next = __codec_store_delete_link(link, cs);
				}
				link = next;
			}
			continue;
		}
		// strip just this one
		GQueue *pts = t_hash_table_lookup(cs->codec_names, codec);
		if (!pts || !pts->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" not present for stripping",
					STR_FMT(codec));
			continue;
		}
		while (pts->length) {
			int pt_num = GPOINTER_TO_INT(pts->head->data);
			rtp_payload_type *pt = t_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num));
			if (pt) {
				ilogs(codec, LOG_DEBUG, "Stripping codec " STR_FORMAT "/" STR_FORMAT " (%i)",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						pt_num);
				codec_touched_real(cs, pt);
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

void codec_store_offer(struct codec_store *cs, str_q *offer, struct codec_store *orig) {
	// restore stripped codecs in order: codecs must be present in `orig` but not present
	// in `cs`
	for (__auto_type l = offer->head; l; l = l->next) {
		str *codec = l->data;
		GQueue *pts = t_hash_table_lookup(cs->codec_names, codec);
		if (pts && pts->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" already present (%i)",
					STR_FMT(codec), GPOINTER_TO_INT(pts->head->data));
			continue;
		}
		GQueue *orig_list = t_hash_table_lookup(orig->codec_names, codec);
		if (!orig_list || !orig_list->length) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" not present for offering",
					STR_FMT(codec));
			continue;
		}
		for (GList *k = orig_list->head; k; k = k->next) {
			int pt_num = GPOINTER_TO_INT(k->data);
			rtp_payload_type *orig_pt = t_hash_table_lookup(orig->codecs,
					GINT_TO_POINTER(pt_num));
			if (!orig_pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for offering " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			if (t_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num))) {
				ilogs(codec, LOG_DEBUG, "PT %i (" STR_FORMAT ") already preset", pt_num,
						STR_FMT(codec));
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Re-adding stripped codec " STR_FORMAT "/" STR_FORMAT " (%i)",
					STR_FMT(&orig_pt->encoding_with_params),
					STR_FMT0(&orig_pt->format_parameters),
					orig_pt->payload_type);
			codec_touched(cs, orig_pt);
			codec_store_add_order(cs, orig_pt);
		}
	}
}

void codec_store_accept(struct codec_store *cs, str_q *accept, struct codec_store *orig) {
	// mark codecs as `for transcoding`
	for (__auto_type l = accept->head; l; l = l->next) {
		str *codec = l->data;
		g_auto(rtp_pt_q) pts_matched = TYPED_GQUEUE_INIT;

		rtp_pt_q *pts = &pts_matched;
		if (!str_cmp(codec, "all") || !str_cmp(codec, "full"))
			pts = &cs->codec_prefs;
		else
			codec_store_find_matching_codecs(&pts_matched, NULL, cs, codec, NULL);

		if (!pts->length) {
			pts = &pts_matched;
			// special case: strip=all, consume=X
			if (orig)
				codec_store_find_matching_codecs(&pts_matched, NULL, orig, codec, NULL);
			if (!pts->length) {
				ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
						" not present for accepting",
						STR_FMT(codec));
				continue;
			}
			// re-add from orig, then mark as accepted below
			rtp_pt_q pt_readded = TYPED_GQUEUE_INIT;
			// XXX duplicate code
			for (__auto_type k = pts->head; k; k = k->next) {
				rtp_payload_type *orig_pt = k->data;
				if (t_hash_table_lookup(cs->codecs, GINT_TO_POINTER(orig_pt->payload_type))) {
					ilogs(codec, LOG_DEBUG, "PT %i (" STR_FORMAT ") already preset",
							orig_pt->payload_type,
							STR_FMT(codec));
					continue;
				}
				ilogs(codec, LOG_DEBUG, "Re-adding stripped codec " STR_FORMAT "/" STR_FORMAT
					" (%i)",
						STR_FMT(&orig_pt->encoding_with_params),
						STR_FMT0(&orig_pt->format_parameters),
						orig_pt->payload_type);
				codec_touched(cs, orig_pt);
				rtp_payload_type *added = codec_store_add_order(cs, orig_pt);
				if (added)
					t_queue_push_tail(&pt_readded, added);
			}
			t_queue_clear(&pts_matched);
			pts_matched = pt_readded;
			if (!pts_matched.length)
				continue;
		}
		for (__auto_type k = pts->head; k; k = k->next) {
			rtp_payload_type *fpt = k->data;
			int pt_num = fpt->payload_type;
			rtp_payload_type *pt = t_hash_table_lookup(cs->codecs,
					GINT_TO_POINTER(pt_num));
			if (!pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for accepting " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Accepting codec " STR_FORMAT "/" STR_FORMAT " (%i)",
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters),
					pt->payload_type);
			pt->for_transcoding = 1;
			pt->accepted = 1;
			codec_touched(cs, pt);
		}
	}
}

int codec_store_accept_one(struct codec_store *cs, str_q *accept, bool accept_any) {
	// local codec-accept routine: accept first supported codec, or first from "accept" list
	// if given

	rtp_payload_type *accept_pt = NULL;

	for (__auto_type l = accept->head; l; l = l->next) {
		// iterate through list and look for the first supported codec
		str *codec = l->data;
		if (!str_cmp(codec, "any")) {
			accept_any = true;
			continue;
		}
		GQueue *pts = t_hash_table_lookup(cs->codec_names, codec);
		if (!pts)
			continue;
		for (GList *k = pts->head; k; k = k->next) {
			int pt_num = GPOINTER_TO_INT(k->data);
			rtp_payload_type *pt = t_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num));
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
		for (__auto_type l = cs->codec_prefs.head; l; l = l->next) {
			rtp_payload_type *pt = l->data;
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
	__auto_type link = cs->codec_prefs.head;
	while (link) {
		rtp_payload_type *pt = link->data;
		if (pt == accept_pt) {
			link = link->next;
			continue;
		}
		link = __codec_store_delete_link(link, cs);
	}

	return 0;
}

void codec_store_track(struct codec_store *cs, str_q *q) {
#ifdef WITH_TRANSCODING
	// just track all codecs from the list as "touched"
	for (__auto_type l = q->head; l; l = l->next) {
		str *codec = l->data;
		if (!str_cmp(codec, "all") || !str_cmp(codec, "full")) {
			cs->tracker->all_touched = 1;
			continue;
		}
		GQueue *pts = t_hash_table_lookup(cs->codec_names, codec);
		if (!pts)
			continue;
		for (GList *k = pts->head; k; k = k->next) {
			int pt_num = GPOINTER_TO_INT(k->data);
			rtp_payload_type *pt = t_hash_table_lookup(cs->codecs,
					GINT_TO_POINTER(pt_num));
			codec_touched(cs, pt);
		}
	}
#endif
}

void codec_store_transcode(struct codec_store *cs, str_q *offer, struct codec_store *orig) {
#ifdef WITH_TRANSCODING
	// special case of codec_store_offer(): synthesise codecs that were not already present
	for (__auto_type l = offer->head; l; l = l->next) {
		str *codec = l->data;
		// parse out given codec string
		g_autoptr(rtp_payload_type) pt
			= codec_make_payload_type_sup(codec, cs->media);

		// find matching existing PT if one exists
		rtp_payload_type *pt_match = NULL;
		codec_store_find_matching_codecs(NULL, &pt_match, cs, codec, pt);
		if (pt_match) {
			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
					" already present (%i)",
					STR_FMT(codec), pt_match->payload_type);
			continue;
		}
		GQueue *orig_list = t_hash_table_lookup(orig->codec_names, codec);
		if (!orig_list || !orig_list->length || cs->strip_full) {
			ilogs(codec, LOG_DEBUG, "Adding codec " STR_FORMAT
					" for transcoding",
					STR_FMT(codec));
			// create new payload type
			pt = codec_add_payload_type_pt(pt, cs->media, NULL, orig);
			if (!pt)
				continue;
			pt->for_transcoding = 1;

			ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT "/" STR_FORMAT " added for transcoding with payload "
					"type %i",
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters),
					pt->payload_type);
			codec_touched(cs, pt);
			codec_store_add_raw_order(cs, pt);
			pt = NULL;
			continue;
		}
		// XXX duplicate code
		for (GList *k = orig_list->head; k; k = k->next) {
			int pt_num = GPOINTER_TO_INT(k->data);
			rtp_payload_type *orig_pt = t_hash_table_lookup(orig->codecs,
					GINT_TO_POINTER(pt_num));
			if (!orig_pt) {
				ilogs(codec, LOG_DEBUG, "PT %i missing for offering " STR_FORMAT, pt_num,
						STR_FMT(codec));
				continue;
			}
			if (t_hash_table_lookup(cs->codecs, GINT_TO_POINTER(pt_num))) {
				ilogs(codec, LOG_DEBUG, "PT %i (" STR_FORMAT ") already preset", pt_num,
						STR_FMT(codec));
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Re-adding stripped codec " STR_FORMAT "/" STR_FORMAT " (%i)",
					STR_FMT(&orig_pt->encoding_with_params),
					STR_FMT0(&orig_pt->format_parameters),
					orig_pt->payload_type);
			codec_touched(cs, orig_pt);
			codec_store_add_order(cs, orig_pt);
		}
	}
#endif
}

void __codec_store_answer(struct codec_store *dst, struct codec_store *src, sdp_ng_flags *flags,
		struct codec_store_args a)
{
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
				&& dst_media->t38_gateway->pcm_player->coder.handler) {
			codec_store_add_order(dst, &dst_media->t38_gateway->pcm_player->coder.handler->dest_pt);
			goto out;
		}
	}
#endif

	unsigned int num_codecs = 0;
	//int codec_order = 0; // to track whether we've added supplemental codecs based on their media codecs
	GQueue supp_codecs = G_QUEUE_INIT; // postpone actually adding them until the end

	// populate dst via output PTs from src's codec handlers
	for (__auto_type l = src->codec_prefs.head; l; l = l->next) {
		bool add_codec = true;
		if (flags->single_codec && num_codecs >= 1)
			add_codec = false;

		rtp_payload_type *pt = l->data;
		struct codec_handler *h = codec_handler_get(src_media, pt->payload_type, dst_media, NULL);

		bool is_supp = false;
		if (pt->codec_def && pt->codec_def->supplemental)
			is_supp = true;

		if (!h || h->dest_pt.payload_type == -1) {
			// passthrough or missing
			if (pt->for_transcoding)
				ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
						"/" STR_FORMAT " (%i) is being transcoded",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters),
						pt->payload_type);
			else {
				if (add_codec) {
					ilogs(codec, LOG_DEBUG, "Codec " STR_FORMAT
							"/" STR_FORMAT " (%i) is passthrough",
							STR_FMT(&pt->encoding_with_params),
							STR_FMT0(&pt->format_parameters),
							pt->payload_type);
					if (!is_supp)
						num_codecs++;
					codec_store_add_end(dst, pt);
				}
				else
					ilogs(codec, LOG_DEBUG, "Skipping passthrough codec " STR_FORMAT
							"/" STR_FORMAT " (%i) due to single-codec flag",
							STR_FMT(&pt->encoding_with_params),
							STR_FMT0(&pt->format_parameters),
							pt->payload_type);
			}
			continue;
		}

		// supp codecs are handled in-line with their main media codecs
		if (is_supp) {
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
					"/" STR_FORMAT " (%i) = " STR_FORMAT "/" STR_FORMAT " (%i) due to single-codec flag",
					STR_FMT(&pt->encoding_with_params),
					STR_FMT0(&pt->format_parameters),
					pt->payload_type,
					STR_FMT(&h->dest_pt.encoding_with_params),
					STR_FMT0(&h->dest_pt.format_parameters),
					h->dest_pt.payload_type);
			continue;
		}
		ilogs(codec, LOG_DEBUG, "Reverse codec for " STR_FORMAT
				"/" STR_FORMAT " (%i) is " STR_FORMAT "/" STR_FORMAT " (%i)",
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters),
				pt->payload_type,
				STR_FMT(&h->dest_pt.encoding_with_params),
				STR_FMT0(&h->dest_pt.format_parameters),
				h->dest_pt.payload_type);
		if (!t_hash_table_lookup(dst->codecs, GINT_TO_POINTER(h->dest_pt.payload_type))) {
			if (h->passthrough) {
				rtp_payload_type copy = *pt;
				copy.payload_type = pt->reverse_payload_type;
				codec_store_add_end(dst, &copy);
			}
			else
				codec_store_add_end(dst, &h->dest_pt);
			if (!is_supp)
				num_codecs++;
		}

		// handle associated supplemental codecs
		if (h->cn_payload_type != -1) {
			pt = t_hash_table_lookup(orig_dst.codecs, GINT_TO_POINTER(h->cn_payload_type));
			if (a.allow_asymmetric) {
				struct rtp_payload_type *src_pt
					= t_hash_table_lookup(src->codecs, GINT_TO_POINTER(h->cn_payload_type));
				if (src_pt && (!pt || !rtp_payload_type_eq_compat(src_pt, pt)))
					pt = src_pt;
			}
			if (!pt)
				ilogs(codec, LOG_DEBUG, "CN payload type %i is missing", h->cn_payload_type);
			else
				g_queue_push_tail(&supp_codecs, rtp_payload_type_dup(pt));
		}
		int dtmf_payload_type = h->dtmf_payload_type;
		if (dtmf_payload_type == -1)
			dtmf_payload_type = h->real_dtmf_payload_type;
		if (dtmf_payload_type != -1) {
			pt = t_hash_table_lookup(orig_dst.codecs, GINT_TO_POINTER(dtmf_payload_type));
			if (a.allow_asymmetric) {
				struct rtp_payload_type *src_pt
					= t_hash_table_lookup(src->codecs, GINT_TO_POINTER(dtmf_payload_type));
				if (src_pt && (!pt || !rtp_payload_type_eq_compat(src_pt, pt)))
					pt = src_pt;
			}
			if (!pt)
				ilogs(codec, LOG_DEBUG, "DTMF payload type %i is missing", dtmf_payload_type);
			else
				g_queue_push_tail(&supp_codecs, rtp_payload_type_dup(pt));
		}
	}

	while (supp_codecs.length) {
		rtp_payload_type *pt = g_queue_pop_head(&supp_codecs);
		if (t_hash_table_lookup(dst->codecs, GINT_TO_POINTER(pt->payload_type))) {
			ilogs(codec, LOG_DEBUG, STR_FORMAT " payload type %i already present, skip",
					STR_FMT(&pt->encoding_with_full_params), pt->payload_type);
			payload_type_free(pt);
			continue;
		}
		ilogs(codec, LOG_DEBUG, "Adding " STR_FORMAT "/" STR_FORMAT " payload type %i",
				STR_FMT(&pt->encoding_with_params),
				STR_FMT0(&pt->format_parameters),
				pt->payload_type);
		codec_store_add_raw(dst, pt);
	}

out:
	codec_tracker_move(&dst->tracker, &orig_dst.tracker);
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
			static const str PCMU_str = STR_CONST("PCMU");
			static const str PCMA_str = STR_CONST("PCMA");
			codec_store_add_raw_order(dst, codec_make_payload_type(&PCMU_str, MT_AUDIO));
			codec_store_add_raw_order(dst, codec_make_payload_type(&PCMA_str, MT_AUDIO));

			ilogs(codec, LOG_DEBUG, "Using default codecs PCMU and PCMA for T.38 gateway");
		}
		else {
			// we already have a list of codecs - make sure they're all supported by us
			for (__auto_type l = dst->codec_prefs.head; l;) {
				rtp_payload_type *pt = l->data;
				if (pt->codec_def) {
					l = l->next;
					continue;
				}
				ilogs(codec, LOG_DEBUG, "Eliminating unsupported codec " STR_FORMAT
						"/" STR_FORMAT " for T.38 transcoding",
						STR_FMT(&pt->encoding_with_params),
						STR_FMT0(&pt->format_parameters));
				codec_touched(dst, pt);
				l = __codec_store_delete_link(l, dst);
			}
		}
	}
}

// check all codecs listed in the source are also be present in the answer (dst)
bool codec_store_is_full_answer(const struct codec_store *src, const struct codec_store *dst) {
	for (auto_iter(l, src->codec_prefs.head); l; l = l->next) {
		const rtp_payload_type *src_pt = l->data;
		const rtp_payload_type *dst_pt = t_hash_table_lookup(dst->codecs,
				GINT_TO_POINTER(src_pt->payload_type));
		if (!dst_pt || !rtp_payload_type_eq_compat(src_pt, dst_pt)) {
			ilogs(codec, LOG_DEBUG, "Source codec " STR_FORMAT "/" STR_FORMAT
				" is not present in the answer",
					STR_FMT(&src_pt->encoding_with_params),
					STR_FMT0(&src_pt->format_parameters));
			return false;
		}
	}
	return true;
}



static void __codec_timer_callback_free(struct timer_callback *cb) {
	if (cb->call)
		obj_put(cb->call);
}
static void __codec_timer_callback_fire(struct codec_timer *ct) {
	struct timer_callback *cb = (void *) ct;
	log_info_call(cb->call);
	cb->timer_callback_func(cb->call, cb->arg);
	codec_timer_stop(&ct);
	log_info_pop();
}
void codec_timer_callback(call_t *c, void (*func)(call_t *, codec_timer_callback_arg_t),
		codec_timer_callback_arg_t a, uint64_t delay)
{
	__auto_type cb = obj_alloc0(struct timer_callback, __codec_timer_callback_free);
	cb->ct.tt_obj.tt = &codec_timers_thread;
	cb->call = obj_get(c);
	cb->timer_callback_func = func;
	cb->arg = a;
	cb->ct.timer_func = __codec_timer_callback_fire;
	cb->ct.next = rtpe_now;
	timeval_add_usec(&cb->ct.next, delay);
	timerthread_obj_schedule_abs(&cb->ct.tt_obj, &cb->ct.next);
}

static void codec_timers_run(void *p) {
	struct codec_timer *ct = p;
	ct->timer_func(ct);
}

#ifdef WITH_TRANSCODING
static void transcode_job_free(struct transcode_job *j) {
	media_packet_release(&j->mp);
	obj_put(&j->ch->h);
	obj_put(&j->input_ch->h);
	if (j->packet)
		__transcode_packet_free(j->packet);
	g_free(j);
}

static void transcode_job_do(struct transcode_job *ref_j) {
	struct call *call = ref_j->mp.call;

	rwlock_lock_r(&call->master_lock);
	__ssrc_lock_both(&ref_j->mp);

	// the first job in the queue must be the one that was given to async worker
	transcode_job_list *list = ref_j->ch->async_jobs.head;
	// given: // assert(list->data == ref_j);

	do {
		// nothing can remove entries while we're running. prepare to run job
		__ssrc_unlock_both(&ref_j->mp);

		struct transcode_job *j = list->data;

		__ssrc_lock_both(&j->mp);

		tc_code ret = __rtp_decode_direct(j->ch, j->input_ch, j->packet, &j->mp);
		if (ret == TCC_CONSUMED)
			j->packet = NULL;

		// unlock and send
		__ssrc_unlock_both(&j->mp);
		send_buffered(&j->mp, log_level_index_transcoding);

		// reacquire primary lock and see if we're done. new jobs might have been
		// added in the meantime.
		__ssrc_lock_both(&ref_j->mp);
		list = list->next;
	}
	while (list);

	// we've reached the end of the list while holding the SSRC handler lock.
	// we will run no more jobs here. we take over the list for cleanup and
	// then release the lock, guaranteeing that anything added afterwards will
	// run later and will result in a new job given to the async worker threads.
	transcode_job_q q = ref_j->ch->async_jobs;
	t_queue_init(&ref_j->ch->async_jobs);
	__ssrc_unlock_both(&ref_j->mp);

	while ((ref_j = t_queue_pop_head(&q)))
		transcode_job_free(ref_j);

	rwlock_unlock_r(&call->master_lock);
}

static void codec_worker(void *d) {
	struct thread_waker waker = { .lock = &transcode_lock, .cond = &transcode_cond };
	thread_waker_add(&waker);

	mutex_lock(&transcode_lock);

	while (!rtpe_shutdown) {
		// wait once, but then loop in case of shutdown
		if (transcode_jobs.length == 0)
			cond_wait(&transcode_cond, &transcode_lock);
		if (transcode_jobs.length == 0)
			continue;

		struct transcode_job *j = t_queue_pop_head(&transcode_jobs);

		mutex_unlock(&transcode_lock);

		gettimeofday(&rtpe_now, NULL);
		transcode_job_do(j);

		mutex_lock(&transcode_lock);
	}

	mutex_unlock(&transcode_lock);
	thread_waker_del(&waker);
}
#endif

void codecs_init(void) {
	timerthread_init(&codec_timers_thread, rtpe_config.media_num_threads, codec_timers_run);

#ifdef WITH_TRANSCODING
	if (rtpe_config.codec_num_threads) {
		for (unsigned int i = 0; i < rtpe_config.codec_num_threads; i++)
			thread_create_detach(codec_worker, NULL, "transcode");

		__rtp_decode = __rtp_decode_async;
	}
	else
		__rtp_decode = __rtp_decode_direct;
#endif
}
void codecs_cleanup(void) {
	timerthread_free(&codec_timers_thread);
}
void codec_timers_launch(void) {
	timerthread_launch(&codec_timers_thread, rtpe_config.scheduling, rtpe_config.priority, "codec timer");
}
