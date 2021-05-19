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




static codec_handler_func handler_func_passthrough;

static struct rtp_payload_type *__rtp_payload_type_copy(const struct rtp_payload_type *pt);
static void __rtp_payload_type_dup(struct call *call, struct rtp_payload_type *pt);
static void __rtp_payload_type_add_name(GHashTable *, struct rtp_payload_type *pt);


static struct codec_handler codec_handler_stub = {
	.source_pt.payload_type = -1,
	.func = handler_func_passthrough,
	.kernelize = 1,
};



static GList *__delete_x_codec(GList *link, GHashTable *codecs, GHashTable *codec_names, GQueue *codecs_prefs) {
	struct rtp_payload_type *pt = link->data;

	g_hash_table_remove(codecs, GINT_TO_POINTER(pt->payload_type));
	g_hash_table_remove(codec_names, &pt->encoding);
	g_hash_table_remove(codec_names, &pt->encoding_with_params);
	g_hash_table_remove(codec_names, &pt->encoding_with_full_params);

	GList *next = link->next;
	g_queue_delete_link(codecs_prefs, link);
	payload_type_free(pt);
	return next;
}
static GList *__delete_receiver_codec(struct call_media *receiver, GList *link) {
	return __delete_x_codec(link, receiver->codecs_recv, receiver->codec_names_recv,
			&receiver->codecs_prefs_recv);
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
	struct timerthread_queue ttq;
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
	struct timerthread_queue_entry ttq_entry;
	time_t start;
};
struct dtx_packet {
	struct transcode_packet *packet;
	struct media_packet mp;
	struct codec_ssrc_handler *decoder_handler; // holds reference
	int (*func)(struct codec_ssrc_handler *ch, struct transcode_packet *packet, struct media_packet *mp);
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
	unsigned long ts_in; // for DTMF dupe detection
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
	             ignore_seq:1;
	int (*func)(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *);
	int (*dup_func)(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *);
	struct rtp_header rtp;
};
struct codec_tracker {
	GHashTable *clockrates; // 8000, 16000, etc, for each real audio codec that is present
	GHashTable *touched; // 8000, 16000, etc, for each audio codec that was touched (added, removed, etc)
	int all_touched;
	GHashTable *supp_codecs; // telephone-event etc => hash table of clock rates
};

struct rtcp_timer_queue {
	struct timerthread_queue ttq;
};
struct rtcp_timer {
	struct timerthread_queue_entry ttq_entry;
	struct call *call;
	struct call_media *media;
};



static struct timerthread codec_timers_thread;
static struct rtcp_timer_queue *rtcp_timer_queue;


static codec_handler_func handler_func_passthrough_ssrc;
static codec_handler_func handler_func_transcode;
static codec_handler_func handler_func_playback;
static codec_handler_func handler_func_inject_dtmf;
static codec_handler_func handler_func_supplemental;
static codec_handler_func handler_func_dtmf;
static codec_handler_func handler_func_t38;

static struct ssrc_entry *__ssrc_handler_transcode_new(void *p);
static struct ssrc_entry *__ssrc_handler_new(void *p);
static void __ssrc_handler_stop(void *p);
static void __free_ssrc_handler(void *);

static void __transcode_packet_free(struct transcode_packet *);

static int packet_decode(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *);
static int packet_encoded_rtp(encoder_t *enc, void *u1, void *u2);
static int packet_decoded_fifo(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);
static int packet_decoded_direct(decoder_t *decoder, AVFrame *frame, void *u1, void *u2);

static void codec_touched(struct rtp_payload_type *pt, struct call_media *media);

static int __buffer_dtx(struct dtx_buffer *dtxb, struct codec_ssrc_handler *ch,
		struct transcode_packet *packet, struct media_packet *mp,
		int (*func)(struct codec_ssrc_handler *ch, struct transcode_packet *packet,
			struct media_packet *mp));
static void __dtx_shutdown(struct dtx_buffer *dtxb);
static struct codec_handler *__decoder_handler(struct codec_handler *h, struct media_packet *mp);


static struct codec_handler codec_handler_stub_ssrc = {
	.source_pt.payload_type = -1,
	.func = handler_func_passthrough_ssrc,
	.kernelize = 1,
};



static void __handler_shutdown(struct codec_handler *handler) {
	if (handler->ssrc_hash) {
		ssrc_hash_foreach(handler->ssrc_hash, __ssrc_handler_stop);
		free_ssrc_hash(&handler->ssrc_hash);
	}
	if (handler->ssrc_handler)
		obj_put(&handler->ssrc_handler->h);
	handler->ssrc_handler = NULL;
	handler->kernelize = 0;
	handler->transcoder = 0;
	handler->dtmf_scaler = 0;
	handler->output_handler = handler; // reset to default
	handler->dtmf_payload_type = -1;
	handler->cn_payload_type = -1;
	handler->pcm_dtmf_detect = 0;

	if (handler->stats_entry) {
		g_atomic_int_add(&handler->stats_entry->num_transcoders, -1);
		handler->stats_entry = NULL;
		g_free(handler->stats_chain);
	}
}

static void __codec_handler_free(void *pp) {
	struct codec_handler *h = pp;
	__handler_shutdown(h);
	g_slice_free1(sizeof(*h), h);
}
void codec_handler_free(struct codec_handler **handler) {
	if (!handler || !*handler)
		return;
	__codec_handler_free(*handler);
	*handler = NULL;
}

static struct codec_handler *__handler_new(const struct rtp_payload_type *pt, struct call_media *media) {
	struct codec_handler *handler = g_slice_alloc0(sizeof(*handler));
	if (pt)
		handler->source_pt = *pt;
	handler->output_handler = handler; // default
	handler->dtmf_payload_type = -1;
	handler->cn_payload_type = -1;
	handler->packet_encoded = packet_encoded_rtp;
	handler->packet_decoded = packet_decoded_fifo;
	handler->media = media;
	return handler;
}

static void __make_passthrough(struct codec_handler *handler) {
	__handler_shutdown(handler);
	ilogs(codec, LOG_DEBUG, "Using passthrough handler for " STR_FORMAT,
			STR_FMT(&handler->source_pt.encoding_with_params));
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;
	else if (handler->source_pt.codec_def && handler->source_pt.codec_def->supplemental)
		handler->func = handler_func_supplemental;
	else {
		handler->func = handler_func_passthrough;
		handler->kernelize = 1;
	}
	handler->dest_pt = handler->source_pt;
	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, handler);
}
static void __make_passthrough_ssrc(struct codec_handler *handler) {
	__handler_shutdown(handler);
	ilogs(codec, LOG_DEBUG, "Using passthrough handler with new SSRC for " STR_FORMAT,
			STR_FMT(&handler->source_pt.encoding_with_params));
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;
	else if (handler->source_pt.codec_def && handler->source_pt.codec_def->supplemental)
		handler->func = handler_func_supplemental;
	else {
		handler->func = handler_func_passthrough_ssrc;
		handler->kernelize = 1;
	}
	handler->dest_pt = handler->source_pt;
	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, handler);
}

static void __make_transcoder(struct codec_handler *handler, struct rtp_payload_type *dest,
		GHashTable *output_transcoders, int dtmf_payload_type, int pcm_dtmf_detect)
{
	assert(handler->source_pt.codec_def != NULL);
	assert(dest->codec_def != NULL);

	// if we're just repacketising:
	if (dtmf_payload_type == -1 && dest->codec_def && dest->codec_def->dtmf)
		dtmf_payload_type = dest->payload_type;

	// don't reset handler if it already matches what we want
	if (!handler->transcoder)
		goto reset;
	if (rtp_payload_type_cmp(dest, &handler->dest_pt))
		goto reset;
	if (handler->func != handler_func_transcode)
		goto reset;

	ilogs(codec, LOG_DEBUG, "Leaving transcode context for " STR_FORMAT " -> " STR_FORMAT " intact",
			STR_FMT(&handler->source_pt.encoding_with_params),
			STR_FMT(&dest->encoding_with_params));

	goto check_output;

reset:
	__handler_shutdown(handler);

	handler->dest_pt = *dest;
	handler->func = handler_func_transcode;
	handler->transcoder = 1;
	if (dtmf_payload_type != -1)
		handler->dtmf_payload_type = dtmf_payload_type;
	handler->pcm_dtmf_detect = pcm_dtmf_detect ? 1 : 0;

	// is this DTMF to DTMF?
	if (dtmf_payload_type != -1 && handler->source_pt.codec_def->dtmf) {
		ilogs(codec, LOG_DEBUG, "Created DTMF transcode context for " STR_FORMAT " -> PT %i",
				STR_FMT(&handler->source_pt.encoding_with_params),
				dtmf_payload_type);
		handler->dtmf_scaler = 1;
	}
	else
		ilogs(codec, LOG_DEBUG, "Created transcode context for " STR_FORMAT " -> " STR_FORMAT
			" with DTMF output %i",
				STR_FMT(&handler->source_pt.encoding_with_params),
				STR_FMT(&dest->encoding_with_params), dtmf_payload_type);

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
	struct codec_handler *handler = __handler_new(src_pt, media);
	handler->dest_pt = *dst_pt;
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

void ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media) {
	if (pt->codec_def)
		return;

	pt->codec_def = codec_find(&pt->encoding, media->type_id);
	if (!pt->codec_def)
		return;
	if (!pt->codec_def->support_encoding || !pt->codec_def->support_decoding)
		pt->codec_def = NULL;
}

static GList *__delete_send_codec(struct call_media *sender, GList *link) {
	return __delete_x_codec(link, sender->codecs_send, sender->codec_names_send,
			&sender->codecs_prefs_send);
}

// only called from codec_handlers_update()
static void __make_passthrough_gsl(struct codec_handler *handler, GSList **handlers) {
	__make_passthrough(handler);
	*handlers = g_slist_prepend(*handlers, handler);
}

// only called from codec_handlers_update()
static void __dtmf_dsp_shutdown(struct call_media *sink, int payload_type) {
	if (!sink->codec_handlers)
		return;

	for (GList *l = sink->codec_handlers_store.head; l; l = l->next) {
		struct codec_handler *handler = l->data;
		if (!handler->transcoder)
			continue;
		if (handler->dtmf_payload_type != payload_type)
			continue;
		if (handler->dtmf_scaler)
			continue;

		ilogs(codec, LOG_DEBUG, "Shutting down DTMF DSP for '" STR_FORMAT "' -> %i (not needed)",
				STR_FMT(&handler->source_pt.encoding_with_params),
				payload_type);
		handler->dtmf_payload_type = -1;
	}
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

static struct rtp_payload_type *__check_dest_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, GHashTable *supplemental_sinks, int *sink_transcoding)
{
	struct rtp_payload_type *pref_dest_codec = NULL;
	struct rtp_payload_type *first_tc_codec = NULL;

	for (GList *l = sink->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		ensure_codec_def(pt, sink);
		if (!pt->codec_def) // not supported, next
			continue;

		// fix up ptime
		if (!pt->ptime)
			pt->ptime = pt->codec_def->default_ptime;
		if (sink->ptime)
			pt->ptime = sink->ptime;

		if (!pref_dest_codec && !pt->codec_def->supplemental)
			pref_dest_codec = pt;


		// also check if this is a transcoding codec: if we can send a codec to the sink,
		// but can't receive it on the receiver side, then it's transcoding. this is to check
		// whether transcoding on the sink side is actually needed. if transcoding has been
		// previously enabled on the sink, but no transcoding codecs are actually present,
		// we can disable the transcoding engine.
		struct rtp_payload_type *recv_pt = g_hash_table_lookup(receiver->codecs_send,
				GINT_TO_POINTER(pt->payload_type));
		if (recv_pt && rtp_payload_type_cmp(pt, recv_pt))
			recv_pt = NULL;
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX old flag is %i", *sink_transcoding);
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX checking dest codec " STR_FORMAT " is %i",
				//STR_FMT(&pt->encoding_with_params),
				//pt->for_transcoding);
		//if (recv_pt)
			//ilog(LOG_DEBUG, "XXXXXXXXXXXX checking dest codec reverse " STR_FORMAT " is %i",
					//STR_FMT(&recv_pt->encoding_with_params),
					//recv_pt->for_transcoding);
		if (MEDIA_ISSET(sink, TRANSCODE)) {
			if (!recv_pt) {
				// can the sink receive codec but the receiver can't send it?
				*sink_transcoding |= 0x3;
			}
		}
		if (pt->for_transcoding) {
			// codec is explicitly marked for transcoding. enable transcoding engine
			MEDIA_SET(receiver, TRANSCODE);
			*sink_transcoding |= 0x3;
			if (!first_tc_codec && !pt->codec_def->supplemental)
				first_tc_codec = pt;
			if (pt->codec_def->supplemental)
				*sink_transcoding |= 0x4;
		}
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX new flag is %i", *sink_transcoding);

		__track_supp_codec(supplemental_sinks, pt);
	}

	if (first_tc_codec)
		pref_dest_codec = first_tc_codec;
	if (pref_dest_codec)
		ilogs(codec, LOG_DEBUG, "Default sink codec is " STR_FORMAT,
				STR_FMT(&pref_dest_codec->encoding_with_params));

	return pref_dest_codec;
}

static void __check_send_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, GHashTable *supplemental_sinks, int *sink_transcoding)
{
	if (!MEDIA_ISSET(sink, TRANSCODE))
		return;

	for (GList *l = sink->codecs_prefs_recv.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		struct rtp_payload_type *recv_pt = g_hash_table_lookup(receiver->codecs_send,
				GINT_TO_POINTER(pt->payload_type));
		int tc_flag = 0;
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX old flag is %i", *sink_transcoding);
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX checking send codec " STR_FORMAT " is %i",
				//STR_FMT(&pt->encoding_with_params),
				//pt->for_transcoding);
		//if (recv_pt)
			//ilog(LOG_DEBUG, "XXXXXXXXXXXX checking send codec reverse " STR_FORMAT " is %i",
					//STR_FMT(&recv_pt->encoding_with_params),
					//recv_pt->for_transcoding);
		if (!recv_pt || rtp_payload_type_cmp(pt, recv_pt))
			tc_flag |= 0x3;
		if (flags && flags->inject_dtmf)
			tc_flag |= 0x1;
		if (pt->for_transcoding)
			tc_flag |= 0x3;
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX set flag is %i", *sink_transcoding);
		if (tc_flag) {
			// can the sink receive codec but the receiver can't send it?
			*sink_transcoding |= tc_flag;
			continue;
		}

		// even if the receiver can receive the same codec that the sink can
		// send, we might still have it configured as a transcoder due to
		// force accepted codec in the offer
		struct codec_handler *ch_recv =
			g_hash_table_lookup(sink->codec_handlers, GINT_TO_POINTER(recv_pt->payload_type));
		if (!ch_recv)
			continue;
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX handler transcoder %i", ch_recv->transcoder);
		if (ch_recv->transcoder)
			*sink_transcoding |= 0x3;
	}
}

static int __supp_payload_type(GHashTable *supplemental_sinks, struct rtp_payload_type *pref_dest_codec,
		const char *codec)
{
	GHashTable *supp_sinks = g_hash_table_lookup(supplemental_sinks, codec);
	if (!supp_sinks)
		return -1;
	if (!g_hash_table_size(supp_sinks) || !pref_dest_codec)
		return -1;

	// find the codec entry with a matching clock rate
	struct rtp_payload_type *pt = g_hash_table_lookup(supp_sinks,
			GUINT_TO_POINTER(pref_dest_codec->clock_rate));
	if (!pt)
		return -1;
	return pt->payload_type;
}

static int __dtmf_payload_type(GHashTable *supplemental_sinks, struct rtp_payload_type *pref_dest_codec) {
	GHashTable *dtmf_sinks = g_hash_table_lookup(supplemental_sinks, "telephone-event");
	if (!dtmf_sinks)
		return -1;
	if (!g_hash_table_size(dtmf_sinks) || !pref_dest_codec)
		return -1;

	int dtmf_payload_type = __supp_payload_type(supplemental_sinks, pref_dest_codec, "telephone-event");

	if (dtmf_payload_type == -1)
		ilogs(codec, LOG_INFO, "Not transcoding PCM DTMF tones to telephone-event packets as "
				"no payload type with a matching clock rate for '" STR_FORMAT
				"' was found", STR_FMT(&pref_dest_codec->encoding_with_params));
	else
		ilogs(codec, LOG_DEBUG, "Output DTMF payload type is %i", dtmf_payload_type);

	return dtmf_payload_type;
}

static int __unused_pt_number(struct call_media *media, struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	int num = pt ? pt->payload_type : -1;
	struct rtp_payload_type *pt_match;

	if (num < 0)
		num = 96; // default first dynamic payload type number
	while (1) {
		if ((pt_match = g_hash_table_lookup(media->codecs_recv, GINT_TO_POINTER(num))))
			goto next;
		if ((pt_match = g_hash_table_lookup(media->codecs_send, GINT_TO_POINTER(num))))
			goto next;
		if (other_media) {
			if ((pt_match = g_hash_table_lookup(other_media->codecs_recv, GINT_TO_POINTER(num))))
				goto next;
			if ((pt_match = g_hash_table_lookup(other_media->codecs_send, GINT_TO_POINTER(num))))
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

static void __single_codec(struct call_media *media, const struct sdp_ng_flags *flags) {
	if (!flags || flags->opmode != OP_ANSWER || !flags->single_codec)
		return;
	int have_codec = 0;
	for (GList *l = media->codecs_prefs_recv.head; l;) {
		struct rtp_payload_type *pt = l->data;
		ensure_codec_def(pt, media);
		if (pt->codec_def && pt->codec_def->supplemental) {
			// leave these alone
			l = l->next;
			continue;
		}
		if (!have_codec) {
			have_codec = 1;
			l = l->next;
			continue;
		}
		ilogs(codec, LOG_DEBUG, "Removing codec '" STR_FORMAT "' due to 'single codec' flag",
				STR_FMT(&pt->encoding_with_params));
		codec_touched(pt, media);
		l = __delete_receiver_codec(media, l);
	}
}

static int __check_receiver_codecs(struct call_media *receiver, struct call_media *sink) {
	int ret = 0;
	// if some codecs were explicitly marked for transcoding, then we accept only those.
	// otherwise we accept all that we can.
	for (GList *l = receiver->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		ensure_codec_def(pt, receiver);
		if (!pt->codec_def)
			continue;
		//ilog(LOG_DEBUG, "XXXXXXXXXXXX checking recv send " STR_FORMAT " %i %i", STR_FMT(&pt->encoding_with_params), pt->for_transcoding, pt->codec_def->supplemental);
		struct rtp_payload_type *sink_pt = g_hash_table_lookup(sink->codecs_recv,
				GINT_TO_POINTER(pt->payload_type));
		if (sink_pt && !rtp_payload_type_cmp(pt, sink_pt))
			continue;
		if (pt->for_transcoding) {
			if (pt->codec_def->supplemental)
				ret |= 0x2 | 0x4;
			else
				ret |= 0x1 | 0x2;
		}
	}
	return ret;
}

static void __accept_pt(struct call_media *receiver, struct call_media *sink, int payload_type,
		int fallback_type, int accept_only_tc, GList **insert_pos)
{
	struct rtp_payload_type *pt = g_hash_table_lookup(receiver->codecs_send, GINT_TO_POINTER(payload_type));

	// fallback PT in case the codec handler is a dummy or a passthrough
	// or some other internal problem
	if (!pt && fallback_type != -1)
		pt = g_hash_table_lookup(receiver->codecs_send, GINT_TO_POINTER(fallback_type));
	if (!pt)
		return;

	ensure_codec_def(pt, receiver);
	if (!pt->codec_def)
		return;
	if (accept_only_tc && !pt->for_transcoding)
		return;
	//ilog(LOG_DEBUG, "XXXXXXXXXXX accept codec " STR_FORMAT " flag %i", STR_FMT(&pt->encoding_with_params), pt->for_transcoding);
	struct rtp_payload_type *existing_pt
		= g_hash_table_lookup(receiver->codecs_recv, GINT_TO_POINTER(pt->payload_type));
	if (existing_pt && !rtp_payload_type_cmp_nf(existing_pt, pt)) {
		// already present.
		// to keep the order intact, we seek the list for the position
		// of this codec entry. all newly added codecs must come after
		// this entry.
		if (!*insert_pos)
			*insert_pos = receiver->codecs_prefs_recv.head;
		while (*insert_pos) {
			if (!(*insert_pos)->next)
				break; // end of list - we insert everything after
			struct rtp_payload_type *test_pt = (*insert_pos)->data;
			if (test_pt->payload_type == pt->payload_type)
				break;
			*insert_pos = (*insert_pos)->next;
		}
		return;
	}

	if (existing_pt) {
		// PT collision. We must renumber one of the entries. `pt` is taken
		// from the send list, so the PT should remain the same. Renumber
		// the existing entry.
		int new_pt = __unused_pt_number(receiver, sink, existing_pt);
		if (new_pt < 0) {
			ilogs(codec, LOG_WARN, "Ran out of RTP payload type numbers while accepting '"
					STR_FORMAT "' due to '" STR_FORMAT "'",
					STR_FMT(&pt->encoding_with_params),
					STR_FMT(&existing_pt->encoding_with_params));
			return;
		}
		ilogs(codec, LOG_DEBUG, "Renumbering '" STR_FORMAT "' from PT %i to %i due to '" STR_FORMAT "'",
					STR_FMT(&existing_pt->encoding_with_params),
					existing_pt->payload_type,
					new_pt,
					STR_FMT(&pt->encoding_with_params));
		g_hash_table_steal(receiver->codecs_recv, GINT_TO_POINTER(existing_pt->payload_type));
		existing_pt->payload_type = new_pt;
		g_hash_table_insert(receiver->codecs_recv, GINT_TO_POINTER(existing_pt->payload_type),
				existing_pt);
	}

	//ilog(LOG_DEBUG, "XXXXXXXXXXXXX offered codec %i", pt->for_transcoding);
	ilogs(codec, LOG_DEBUG, "Accepting offered codec " STR_FORMAT " due to transcoding",
			STR_FMT(&pt->encoding_with_params));
	MEDIA_SET(receiver, TRANSCODE);

	// we need a new pt entry
	pt = __rtp_payload_type_copy(pt);
	pt->for_transcoding = 1;
	codec_touched(pt, receiver);
	// this somewhat duplicates __rtp_payload_type_add_recv
	g_hash_table_insert(receiver->codecs_recv, GINT_TO_POINTER(pt->payload_type), pt);
	__rtp_payload_type_add_name(receiver->codec_names_recv, pt);

	// keep supplemental codecs last
	ensure_codec_def(pt, receiver);
	if (!pt->codec_def || !pt->codec_def->supplemental) {
		while (*insert_pos) {
			struct rtp_payload_type *ipt = (*insert_pos)->data;
			ensure_codec_def(ipt, receiver);
			if (!ipt->codec_def || !ipt->codec_def->supplemental)
				break;
			*insert_pos = (*insert_pos)->prev;
		}
	}
	else {
		if (!*insert_pos)
			*insert_pos = receiver->codecs_prefs_recv.tail;
	}

	if (!*insert_pos) {
		g_queue_push_head(&receiver->codecs_prefs_recv, pt);
		*insert_pos = receiver->codecs_prefs_recv.head;
	}
	else {
		g_queue_insert_after(&receiver->codecs_prefs_recv, *insert_pos, pt);
		*insert_pos = (*insert_pos)->next;
	}
}
static void __reorder_transcode_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, int accept_only_tc)
{
	// if the other side is transcoding, we need to accept codecs that were
	// originally offered (recv->send) if we support them, even if the
	// response (sink->send) doesn't include them
	GList *insert_pos = NULL;
	for (GList *l = sink->codecs_prefs_recv.head; l; l = l->next) {
		// take the PT that we can receive on the sink side and get the appropriate
		// output PT on the receiver side to ensure codec symmetry.
		struct rtp_payload_type *sink_pt = l->data;
		// determine output PT from the codec handler
		struct codec_handler *ch = codec_handler_get(sink, sink_pt->payload_type);
		if (ch && ch->source_pt.payload_type != -1 && ch->dest_pt.payload_type != -1) {
			__accept_pt(receiver, sink, ch->dest_pt.payload_type, sink_pt->payload_type,
					accept_only_tc, &insert_pos);
			if (ch->dtmf_payload_type != -1)
				__accept_pt(receiver, sink, ch->dtmf_payload_type, -1,
						accept_only_tc, &insert_pos);
			if (ch->cn_payload_type != -1)
				__accept_pt(receiver, sink, ch->cn_payload_type, -1,
						accept_only_tc, &insert_pos);
		}
		else
			__accept_pt(receiver, sink, sink_pt->payload_type, -1, accept_only_tc, &insert_pos);
	}

	__single_codec(receiver, flags);
}
static void __accept_transcode_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, int accept_only_tc)
{
	// if the other side is transcoding, we need to accept codecs that were
	// originally offered (recv->send) if we support them, even if the
	// response (sink->send) doesn't include them
	GList *insert_pos = NULL;
	for (GList *l = receiver->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		__accept_pt(receiver, sink, pt->payload_type, -1, accept_only_tc, &insert_pos);
	}

	__single_codec(receiver, flags);
}

static void __eliminate_rejected_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags)
{
	if (flags && flags->asymmetric_codecs)
		return;

	// in the other case (not transcoding), we can eliminate rejected codecs from our
	// `send` list if the receiver cannot receive it.
	for (GList *l = receiver->codecs_prefs_send.head; l;) {
		struct rtp_payload_type *pt = l->data;
		if (g_hash_table_lookup(receiver->codec_names_recv, &pt->encoding)) {
			l = l->next;
			continue;
		}
		ilogs(codec, LOG_DEBUG, "Eliminating asymmetric outbound codec " STR_FORMAT,
				STR_FMT(&pt->encoding_with_params));
		l = __delete_send_codec(receiver, l);
	}
}

// transfers ownership of payload type objects from a queue to a hash table.
// duplicates are removed.
static GHashTable *__payload_type_queue_hash(GQueue *prefs, GQueue *order) {
	GHashTable *ret = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			(GDestroyNotify) payload_type_free);
	g_queue_init(order);
	for (GList *l = prefs->head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		if (g_hash_table_lookup(ret, GINT_TO_POINTER(pt->payload_type))) {
			ilogs(codec, LOG_DEBUG, "Removing duplicate RTP payload type %i", pt->payload_type);
			payload_type_free(pt);
			continue;
		}
		g_hash_table_insert(ret, GINT_TO_POINTER(pt->payload_type), pt);
		g_queue_push_tail(order, GINT_TO_POINTER(pt->payload_type));
	}

	// ownership has been transferred
	g_queue_clear(prefs);

	return ret;
}

static void __symmetric_codecs(struct call_media *receiver, struct call_media *sink,
		int *sink_transcoding)
{
	//ilog(LOG_DEBUG, "XXXXXXXXXXXXXXX symm codec flags %i %i", MEDIA_ISSET(sink, TRANSCODE), *sink_transcoding);
	if (!MEDIA_ISSET(sink, TRANSCODE))
		return;
	if (!*sink_transcoding)
		return;

	// sink still looks like it's transcoding. reconstruct our answer to the receiver
	// (receiver->prefs_recv) based on the codecs accepted by the sink (sink->prefs_send).

	GQueue prefs_recv_order, prefs_send_order;
	GHashTable *prefs_recv = __payload_type_queue_hash(&receiver->codecs_prefs_recv, &prefs_recv_order);
	GHashTable *prefs_send = __payload_type_queue_hash(&receiver->codecs_prefs_send, &prefs_send_order);

	// ownership of the objects has been transferred. clear out old structures.
	g_hash_table_remove_all(receiver->codecs_recv);
	g_hash_table_remove_all(receiver->codec_names_recv);
	g_hash_table_remove_all(receiver->codecs_send);
	g_hash_table_remove_all(receiver->codec_names_send);

	// reconstruct list based on other side's preference.
	int transcoding = 0;

	// keep track of our reconstruction order. there might be some codecs that have been force accepted
	// that aren't present in sink->codecs_prefs_send. we must add them our output (receiver->send/recv)
	// in order.
	GList *prefix_pt_pos = prefs_send_order.head;

	for (GList *l = sink->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		//ilog(LOG_DEBUG, "XXXXXXXXXXXXXXXX symm codec check " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
		// do we have a matching output?
		struct rtp_payload_type *out_pt = g_hash_table_lookup(prefs_recv,
				GINT_TO_POINTER(pt->payload_type));
		struct rtp_payload_type *send_pt;
		if (!out_pt || !(send_pt = g_hash_table_lookup(prefs_send, GINT_TO_POINTER(pt->payload_type)))) {
			// we must transcode after all.
			ilogs(codec, LOG_DEBUG, "RTP payload type %i is not symmetric and must be transcoded",
					pt->payload_type);
			transcoding = 1;
			continue;
		}

		// seek forward in our prefix list and check any PTs to see if they're force accepted
		while (prefix_pt_pos) {
			void *ptype = prefix_pt_pos->data;
			struct rtp_payload_type *prefix_pt = g_hash_table_lookup(prefs_send, ptype);
			prefix_pt_pos = prefix_pt_pos->next;
			if (!prefix_pt)
				continue; // bug?
			if (prefix_pt == send_pt)
				break; // caught up
			//ilog(LOG_DEBUG, "XXXXXXXXXXXXXXXX prefix codec check " STR_FORMAT " %i", STR_FMT(&prefix_pt->encoding_with_params), prefix_pt->for_transcoding);
			if (!prefix_pt->for_transcoding)
				continue; // not interesting

			// add it to the list
			ilogs(codec, LOG_DEBUG, "Adding force-accepted RTP payload type %i", prefix_pt->payload_type);
			g_hash_table_steal(prefs_send, ptype);
			__rtp_payload_type_add_send(receiver, prefix_pt);
			// and our receive leg
			struct rtp_payload_type *in_pt = g_hash_table_lookup(prefs_recv, ptype);
			if (in_pt) {
				g_hash_table_steal(prefs_recv, ptype);
				__rtp_payload_type_add_recv(receiver, in_pt, 1);
			}
			transcoding = 1;
		}

		// add it to the list
		ilogs(codec, LOG_DEBUG, "Adding symmetric RTP payload type %i", pt->payload_type);
		g_hash_table_steal(prefs_recv, GINT_TO_POINTER(pt->payload_type));
		__rtp_payload_type_add_recv(receiver, out_pt, 1);
		// and our send leg
		out_pt = g_hash_table_lookup(prefs_send, GINT_TO_POINTER(pt->payload_type));
		if (out_pt) {
			g_hash_table_steal(prefs_send, GINT_TO_POINTER(pt->payload_type));
			__rtp_payload_type_add_send(receiver, out_pt);
		}
	}

	if (!transcoding)
		*sink_transcoding = 0;
	else {
		// append any leftover codecs
		while (prefs_recv_order.length) {
			void *ptype = g_queue_pop_head(&prefs_recv_order);
			struct rtp_payload_type *out_pt = g_hash_table_lookup(prefs_recv, ptype);
			if (!out_pt)
				continue;
			//ilog(LOG_DEBUG, "XXXXXXXXXXXXXXXX appending recv codec " STR_FORMAT, STR_FMT(&out_pt->encoding_with_params));
			g_hash_table_steal(prefs_recv, ptype);
			__rtp_payload_type_add_recv(receiver, out_pt, 1);
		}
		while (prefs_send_order.length) {
			void *ptype = g_queue_pop_head(&prefs_send_order);
			struct rtp_payload_type *out_pt = g_hash_table_lookup(prefs_send, ptype);
			if (!out_pt)
				continue;
			//ilog(LOG_DEBUG, "XXXXXXXXXXXXXXXX appending send codec " STR_FORMAT, STR_FMT(&out_pt->encoding_with_params));
			g_hash_table_steal(prefs_send, ptype);
			__rtp_payload_type_add_send(receiver, out_pt);
		}
	}

	g_hash_table_destroy(prefs_recv);
	g_queue_clear(&prefs_recv_order);
	g_hash_table_destroy(prefs_send);
	g_queue_clear(&prefs_send_order);
}

static void __check_dtmf_injector(const struct sdp_ng_flags *flags, struct call_media *receiver,
		struct rtp_payload_type *pref_dest_codec, GHashTable *output_transcoders,
		int dtmf_payload_type)
{
	if (!flags || !flags->inject_dtmf)
		return;
	if (receiver->dtmf_injector) {
		// is this still valid?
		if (!rtp_payload_type_cmp(pref_dest_codec, &receiver->dtmf_injector->dest_pt))
			return;

		receiver->dtmf_injector = NULL;
	}

	// synthesise input rtp payload type
	struct rtp_payload_type src_pt = {
		.payload_type = -1,
		.clock_rate = pref_dest_codec->clock_rate,
		.channels = pref_dest_codec->channels,
	};
	str_init(&src_pt.encoding, "DTMF injector");
	str_init(&src_pt.encoding_with_params, "DTMF injector");
	str_init(&src_pt.encoding_with_full_params, "DTMF injector");
	const str tp_event = STR_CONST_INIT("telephone-event");
	src_pt.codec_def = codec_find(&tp_event, MT_AUDIO);
	if (!src_pt.codec_def) {
		ilogs(codec, LOG_ERR, "RTP payload type 'telephone-event' is not defined");
		return;
	}

	//receiver->dtmf_injector = codec_handler_make_playback(&src_pt, pref_dest_codec, 0);
	//receiver->dtmf_injector->dtmf_payload_type = dtmf_payload_type;
	receiver->dtmf_injector = __handler_new(&src_pt, receiver);
	__make_transcoder(receiver->dtmf_injector, pref_dest_codec, output_transcoders, dtmf_payload_type, 0);
	receiver->dtmf_injector->func = handler_func_inject_dtmf;
	g_queue_push_tail(&receiver->codec_handlers_store, receiver->dtmf_injector);
}




static struct codec_handler *__get_pt_handler(struct call_media *receiver, struct rtp_payload_type *pt) {
	ensure_codec_def(pt, receiver);
	struct codec_handler *handler;
	handler = g_hash_table_lookup(receiver->codec_handlers, GINT_TO_POINTER(pt->payload_type));
	if (handler) {
		// make sure existing handler matches this PT
		if (rtp_payload_type_cmp(pt, &handler->source_pt)) {
			ilogs(codec, LOG_DEBUG, "Resetting codec handler for PT %u", pt->payload_type);
			__handler_shutdown(handler);
			handler = NULL;
			g_atomic_pointer_set(&receiver->codec_handler_cache, NULL);
			g_hash_table_remove(receiver->codec_handlers, GINT_TO_POINTER(pt->payload_type));
		}
	}
	if (!handler) {
		ilogs(codec, LOG_DEBUG, "Creating codec handler for " STR_FORMAT,
				STR_FMT(&pt->encoding_with_params));
		handler = __handler_new(pt, receiver);
		g_hash_table_insert(receiver->codec_handlers,
				GINT_TO_POINTER(handler->source_pt.payload_type),
				handler);
		g_queue_push_tail(&receiver->codec_handlers_store, handler);
	}

	// figure out our ptime
	if (!pt->ptime && pt->codec_def)
		pt->ptime = pt->codec_def->default_ptime;
	if (receiver->ptime)
		pt->ptime = receiver->ptime;

	return handler;
}




static void __check_t38_decoder(struct call_media *t38_media) {
	if (t38_media->t38_handler)
		return;
	ilogs(codec, LOG_DEBUG, "Creating T.38 packet handler");
	t38_media->t38_handler = __handler_new(NULL, t38_media);
	t38_media->t38_handler->func = handler_func_t38;
}

static int packet_encoded_t38(encoder_t *enc, void *u1, void *u2) {
	struct media_packet *mp = u2;

	if (!mp->media)
		return 0;

	return t38_gateway_input_samples(mp->media->t38_gateway,
			(int16_t *) enc->avpkt.data, enc->avpkt.size / 2);
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
	for (GList *l = pcm_media->codecs_prefs_recv.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		struct codec_handler *handler = __get_pt_handler(pcm_media, pt);
		if (!pt->codec_def) {
			// should not happen
			ilogs(codec, LOG_WARN, "Unsupported codec " STR_FORMAT " for T.38 transcoding",
					STR_FMT(&pt->encoding_with_params));
			continue;
		}

		ilogs(codec, LOG_DEBUG, "Creating T.38 encoder for " STR_FORMAT, STR_FMT(&pt->encoding_with_params));

		__make_transcoder(handler, &pcm_media->t38_gateway->pcm_pt, NULL, -1, 0);

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
	g_slice_free1(sizeof(*rt), rt);
}
// master lock held in W
static void __codec_rtcp_timer_schedule(struct call_media *media) {
	struct rtcp_timer *rt = g_slice_alloc0(sizeof(*rt));
	rt->ttq_entry.when = media->rtcp_timer;
	rt->call = obj_get(media->call);
	rt->media = media;

	timerthread_queue_push(&rtcp_timer_queue->ttq, &rt->ttq_entry);
}
// no lock held
static void __rtcp_timer_run(struct timerthread_queue *q, void *p) {
	struct rtcp_timer *rt = p;

	// check scheduling
	rwlock_lock_w(&rt->call->master_lock);
	struct call_media *media = rt->media;
	struct timeval rtcp_timer = media->rtcp_timer;

	log_info_call(rt->call);

	if (!rtcp_timer.tv_sec || timeval_diff(&rtpe_now, &rtcp_timer) < 0 || !proto_is_rtp(media->protocol)
			|| !MEDIA_ISSET(media, RTCP_GEN))
	{
		media->rtcp_timer.tv_sec = 0;
		rwlock_unlock_w(&rt->call->master_lock);
		__rtcp_timer_free(rt);
		goto out;
	}
	timeval_add_usec(&rtcp_timer, 5000000 + (ssl_random() % 2000000));
	media->rtcp_timer = rtcp_timer;
	__codec_rtcp_timer_schedule(media);

	// switch locks to be more graceful
	rwlock_unlock_w(&rt->call->master_lock);

	rwlock_lock_r(&rt->call->master_lock);

	struct ssrc_ctx *ssrc_out = NULL;
	if (media->streams.head) {
		struct packet_stream *ps = media->streams.head->data;
		mutex_lock(&ps->out_lock);
		ssrc_out = ps->ssrc_out;
		if (ssrc_out)
			obj_hold(&ssrc_out->parent->h);
		mutex_unlock(&ps->out_lock);
	}

	if (ssrc_out)
		rtcp_send_report(media, ssrc_out);

	rwlock_unlock_r(&rt->call->master_lock);

	if (ssrc_out)
		obj_put(&ssrc_out->parent->h);

	__rtcp_timer_free(rt);

out:
	log_info_clear();
}
// master lock held in W
static void __codec_rtcp_timer(struct call_media *receiver) {
	if (receiver->rtcp_timer.tv_sec) // already scheduled
		return;

	receiver->rtcp_timer = rtpe_now;
	timeval_add_usec(&receiver->rtcp_timer, 5000000 + (ssl_random() % 2000000));
	__codec_rtcp_timer_schedule(receiver);
	// XXX unify with media player into a generic RTCP player
}


// returns: 0 = supp codec not present; 1 = sink has codec but receiver does not, 2 = both have codec
int __supp_codec_match(struct call_media *receiver, struct call_media *sink, int pt,
		struct rtp_payload_type **sink_pt, struct rtp_payload_type **recv_pt)
{
	if (pt == -1)
		return 0;
	//ilog(LOG_DEBUG, "XXXXXXXXX checking supp PT match %i", pt);

	struct rtp_payload_type *sink_pt_stor = NULL;
	struct rtp_payload_type *recv_pt_stor = NULL;
	if (!sink_pt)
		sink_pt = &sink_pt_stor;
	if (!recv_pt)
		recv_pt = &recv_pt_stor;

	// find a matching output payload type
	*sink_pt = g_hash_table_lookup(sink->codecs_send, GINT_TO_POINTER(pt));
	if (!*sink_pt)
		return 0;
	//ilog(LOG_DEBUG, "XXXXXXXXX sink has supp PT %i", pt);
	// XXX should go by codec name/params, not payload type number
	*recv_pt = g_hash_table_lookup(receiver->codecs_recv, GINT_TO_POINTER(pt));
	if (!*recv_pt)
		return 1;
	//ilog(LOG_DEBUG, "XXXXXXXXX recv has supp PT %i", pt);
	if (rtp_payload_type_cmp(*sink_pt, *recv_pt))
		return 1;
	//ilog(LOG_DEBUG, "XXXXXXXXX recv has matching supp PT %i", pt);
	return 2;
}

// call must be locked in W
void codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, const struct stream_params *sp)
{
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
		receiver->codec_handlers = g_hash_table_new(g_direct_hash, g_direct_equal);

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

	// we go through the list of codecs that the receiver supports and compare it
	// with the list of codecs supported by the sink. if the receiver supports
	// a codec that the sink doesn't support, we must transcode.
	//
	// if we transcode, we transcode to the highest-preference supported codec
	// that the sink specified. determine this first.
	struct rtp_payload_type *pref_dest_codec = NULL;

	// 0x1 = any transcoder present, 0x2 = non pseudo transcoder present,
	// 0x4 = supplemental codec for transcoding
	int sink_transcoding = 0;

	// keep track of supplemental payload types. we hash them by clock rate
	// in case there's several of them. the clock rates of the destination
	// codec and the supplemental codec must match.
	GHashTable *supplemental_sinks = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);
	for (GList *l = codec_supplemental_codecs->head; l; l = l->next) {
		codec_def_t *def = l->data;
		g_hash_table_replace(supplemental_sinks, (void *) def->rtpname,
				g_hash_table_new(g_direct_hash, g_direct_equal));
	}

	pref_dest_codec = __check_dest_codecs(receiver, sink, flags, supplemental_sinks, &sink_transcoding);

	// similarly, if the sink can receive a codec that the receiver can't send, it's also transcoding
	__check_send_codecs(receiver, sink, flags, supplemental_sinks, &sink_transcoding);

	// 0x1 = accept only codecs marked for transcoding, 0x2 = some codecs marked for transcoding
	// present, 0x4 = supplemental codec for transcoding
	int receiver_transcoding = __check_receiver_codecs(receiver, sink);

	if (flags && flags->opmode == OP_ANSWER && flags->symmetric_codecs)
		__symmetric_codecs(receiver, sink, &sink_transcoding);

	int dtmf_payload_type = __dtmf_payload_type(supplemental_sinks, pref_dest_codec);
	int cn_payload_type = __supp_payload_type(supplemental_sinks, pref_dest_codec, "CN");

	g_hash_table_destroy(supplemental_sinks);
	supplemental_sinks = NULL;

	struct rtp_payload_type *dtmf_pt = NULL;
	struct rtp_payload_type *reverse_dtmf_pt = NULL;
	int dtmf_pt_match = __supp_codec_match(receiver, sink, dtmf_payload_type, &dtmf_pt, &reverse_dtmf_pt);
	int cn_pt_match = __supp_codec_match(receiver, sink, cn_payload_type, NULL, NULL);

	// stop transcoding if we've determined that we don't need it
	if (MEDIA_ISSET(sink, TRANSCODE) && !sink_transcoding && !(receiver_transcoding & 0x2)) {
		ilogs(codec, LOG_DEBUG, "Disabling transcoding engine (not needed)");
		MEDIA_CLEAR(sink, TRANSCODE);
	}

	if (MEDIA_ISSET(sink, TRANSCODE) && (sink_transcoding & 0x2)) {
		if (flags && flags->opmode == OP_ANSWER &&
				(rtpe_config.reorder_codecs || flags->reorder_codecs))
			__reorder_transcode_codecs(receiver, sink, flags, (receiver_transcoding & 0x1));
		else
			__accept_transcode_codecs(receiver, sink, flags, (receiver_transcoding & 0x1));
	}
	else
		__eliminate_rejected_codecs(receiver, sink, flags);

	// if multiple input codecs transcode to the same output codec, we want to make sure
	// that all the decoders output their media to the same encoder. we use the destination
	// payload type to keep track of this.
	GHashTable *output_transcoders = g_hash_table_new(g_direct_hash, g_direct_equal);

	int transcode_supplemental = 0; // is one of our source codecs a supplemental one?
	if ((sink_transcoding & 0x4))
		transcode_supplemental = 1;

	// do we need to detect PCM DTMF tones?
	int pcm_dtmf_detect = 0;
	if ((MEDIA_ISSET(sink, TRANSCODE) || (sink_transcoding & 0x2))
			&& dtmf_payload_type != -1
			&& dtmf_pt && (!reverse_dtmf_pt || reverse_dtmf_pt->for_transcoding ||
				!g_hash_table_lookup(receiver->codecs_send, GINT_TO_POINTER(dtmf_payload_type))))
		pcm_dtmf_detect = 1;


	for (GList *l = receiver->codecs_prefs_recv.head; l; ) {
		struct rtp_payload_type *pt = l->data;

		ilogs(internals, LOG_DEBUG, "checking recv codec " STR_FORMAT,
				STR_FMT(&pt->encoding));

		if (MEDIA_ISSET(sink, TRANSCODE) && flags && flags->opmode == OP_ANSWER) {
			// if the other side is transcoding, we may come across a receiver entry
			// (recv->recv) that wasn't originally offered (recv->send). we must eliminate
			// those, unless we added them ourselves for transcoding.
			struct rtp_payload_type *recv_pt =
				g_hash_table_lookup(receiver->codecs_send, GINT_TO_POINTER(pt->payload_type));
			if (!recv_pt && !pt->for_transcoding) {
				ilogs(codec, LOG_DEBUG, "Eliminating transcoded codec " STR_FORMAT,
						STR_FMT(&pt->encoding_with_params));

				codec_touched(pt, receiver);
				l = __delete_receiver_codec(receiver, l);
				continue;
			}
		}

		struct codec_handler *handler = __get_pt_handler(receiver, pt);

		// check our own support for this codec
		if (!pt->codec_def) {
			// not supported
			__make_passthrough_gsl(handler, &passthrough_handlers);
			goto next;
		}

		// if the sink's codec preferences are unknown (empty), or there are
		// no supported codecs to transcode to, then we have nothing
		// to do. most likely this is an initial offer without a received answer.
		// we default to forwarding without transcoding.
		if (!pref_dest_codec) {
			ilogs(codec, LOG_DEBUG, "No known/supported sink codec for " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			__make_passthrough_gsl(handler, &passthrough_handlers);
			goto next;
		}

		ilogs(internals, LOG_DEBUG, "pref dest codec " STR_FORMAT " is %i, CN match %i DTMF match %i "
				"sink TC %i/%i recv TC %i TC supp %i DTMF DSP %i",
				STR_FMT(&pref_dest_codec->encoding_with_params),
				pref_dest_codec->for_transcoding,
				cn_pt_match, dtmf_pt_match,
				MEDIA_ISSET(sink, TRANSCODE), sink_transcoding,
				receiver_transcoding,
				transcode_supplemental, pcm_dtmf_detect);

		struct rtp_payload_type *dest_pt; // transcode to this

		GQueue *dest_codecs = NULL;
		if (pref_dest_codec->for_transcoding) {
			// with force accepted codec, we still accept DTMF payloads if possible
			if (pt->codec_def && pt->codec_def->supplemental)
				dest_codecs = g_hash_table_lookup(sink->codec_names_send, &pt->encoding);
		}
		else {
			// we ignore output codec matches if we must transcode supp codecs
			if ((dtmf_pt_match == 1 || cn_pt_match == 1) && MEDIA_ISSET(sink, TRANSCODE))
				;
			else if ((receiver_transcoding & 0x4))
				;
			else if (pcm_dtmf_detect)
				;
			else
				dest_codecs = g_hash_table_lookup(sink->codec_names_send, &pt->encoding);
		}
		if (dest_codecs) {
			// the sink supports this codec - check offered formats
			dest_pt = NULL;
			for (GList *k = dest_codecs->head; k; k = k->next) {
				unsigned int dest_ptype = GPOINTER_TO_UINT(k->data);
				dest_pt = g_hash_table_lookup(sink->codecs_send, GINT_TO_POINTER(dest_ptype));
				if (!dest_pt)
					continue;
				if (dest_pt->clock_rate != pt->clock_rate ||
						dest_pt->channels != pt->channels) {
					dest_pt = NULL;
					continue;
				}
				break;
			}

			if (!dest_pt)
				goto unsupported;

			// in case of ptime mismatch, we transcode, but between the same codecs
			if (dest_pt->ptime && pt->ptime
					&& dest_pt->ptime != pt->ptime)
			{
				ilogs(codec, LOG_DEBUG, "Mismatched ptime between source and sink (%i <> %i), "
						"enabling transcoding",
					dest_pt->ptime, pt->ptime);
				goto transcode;
			}

			if (flags && flags->inject_dtmf) {
				// we have a matching output codec, but we were told that we might
				// want to inject DTMF, so we must still go through our transcoding
				// engine, despite input and output codecs being the same.
				goto transcode;
			}

			// XXX needs more intelligent fmtp matching
			if (rtp_payload_type_cmp_nf(pt, dest_pt))
				goto transcode;

			// do we need silence detection?
			if (cn_pt_match == 2 && MEDIA_ISSET(sink, TRANSCODE))
				goto transcode;

			// XXX check format parameters as well
			ilogs(codec, LOG_DEBUG, "Sink supports codec " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
			__make_passthrough_gsl(handler, &passthrough_handlers);
			if (pt->codec_def && pt->codec_def->dtmf)
				__dtmf_dsp_shutdown(sink, pt->payload_type);
			goto next;
		}

unsupported:
		// the sink does not support this codec -> transcode
		ilogs(codec, LOG_DEBUG, "Sink does not support codec " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
		dest_pt = pref_dest_codec;
		if (pt->codec_def->supplemental)
			transcode_supplemental = 1;
transcode:;
		// look up the reverse side of this payload type, which is the decoder to our
		// encoder. if any codec options such as bitrate were set during an offer,
		// they're in the decoder // PT. copy them to the encoder PT.
		struct rtp_payload_type *reverse_pt = g_hash_table_lookup(sink->codecs_recv,
				GINT_TO_POINTER(dest_pt->payload_type));
		if (reverse_pt) {
			if (!dest_pt->bitrate)
				dest_pt->bitrate = reverse_pt->bitrate;
			if (!dest_pt->codec_opts.len)
				call_str_cpy(sink->call, &dest_pt->codec_opts, &reverse_pt->codec_opts);
		}
		MEDIA_SET(receiver, TRANSCODE);
		__make_transcoder(handler, dest_pt, output_transcoders, dtmf_payload_type, pcm_dtmf_detect);
		handler->cn_payload_type = cn_payload_type;

next:
		l = l->next;
	}

	// if we've determined that we transcode, we must remove all unsupported codecs from
	// the list, as we must expect to potentially receive media in that codec, which we
	// then could not transcode.
	if (MEDIA_ISSET(receiver, TRANSCODE)) {
		ilogs(codec, LOG_INFO, "Enabling transcoding engine");

		for (GList *l = receiver->codecs_prefs_recv.head; l; ) {
			struct rtp_payload_type *pt = l->data;

			ilogs(internals, LOG_DEBUG, "checking recv codec " STR_FORMAT,
					STR_FMT(&pt->encoding));

			if (pt->codec_def) {
				// supported
				l = l->next;
				continue;
			}

			ilogs(codec, LOG_DEBUG, "Stripping unsupported codec " STR_FORMAT " due to active transcoding",
					STR_FMT(&pt->encoding));
			codec_touched(pt, receiver);
			l = __delete_receiver_codec(receiver, l);
		}

		// we have to translate RTCP packets
		receiver->rtcp_handler = rtcp_transcode_handler;

		__check_dtmf_injector(flags, receiver, pref_dest_codec, output_transcoders, dtmf_payload_type);

		// at least some payload types will be transcoded, which will result in SSRC
		// change. for payload types which we don't actually transcode, we still
		// must substitute the SSRC
		while (passthrough_handlers) {
			struct codec_handler *handler = passthrough_handlers->data;
			// if the sink does not support DTMF but we can receive it, we must transcode
			// DTMF event packets to PCM. this requires all codecs to be transcoded to the
			// sink's preferred destination codec.
			//ilog(LOG_DEBUG, "XXXXXXXXXXXXX tc supp %i DTMF PT %i DTMF PT match %i PCM detect %i",
					//transcode_supplemental, dtmf_payload_type, dtmf_pt_match, pcm_dtmf_detect);
			//ilog(LOG_DEBUG, "XXXXXXXXXXXXX tc supp %i CN PT %i CN PT match %i",
					//transcode_supplemental, cn_payload_type, cn_pt_match);
			//ilog(LOG_DEBUG, "XXXXXXXXXXXXX %p %p %p",
					//pref_dest_codec, handler->source_pt.codec_def, pref_dest_codec->codec_def);
			if (!transcode_supplemental && !pcm_dtmf_detect)
				__make_passthrough_ssrc(handler);
			else if (dtmf_pt_match == 2)
				__make_passthrough_ssrc(handler);
			else if (!pref_dest_codec
					|| !handler->source_pt.codec_def || !pref_dest_codec->codec_def)
				__make_passthrough_ssrc(handler);
			else {
				__make_transcoder(handler, pref_dest_codec, output_transcoders,
						dtmf_payload_type, pcm_dtmf_detect);
				handler->cn_payload_type = cn_payload_type;
			}
			passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);

		}
	}
	while (passthrough_handlers) {
		passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);
	}

	g_hash_table_destroy(output_transcoders);

	if (MEDIA_ISSET(receiver, RTCP_GEN)) {
		receiver->rtcp_handler = rtcp_sink_handler;
		__codec_rtcp_timer(receiver);
	}
	if (MEDIA_ISSET(sink, RTCP_GEN)) {
		sink->rtcp_handler = rtcp_sink_handler;
		__codec_rtcp_timer(sink);
	}
}


static struct codec_handler *codec_handler_get_rtp(struct call_media *m, int payload_type) {
	struct codec_handler *h;

	if (payload_type < 0)
		return NULL;

	h = g_atomic_pointer_get(&m->codec_handler_cache);
	if (G_LIKELY(G_LIKELY(h) && G_LIKELY(h->source_pt.payload_type == payload_type)))
		return h;

	if (G_UNLIKELY(!m->codec_handlers))
		return NULL;
	h = g_hash_table_lookup(m->codec_handlers, GINT_TO_POINTER(payload_type));
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


// call must be locked in R
struct codec_handler *codec_handler_get(struct call_media *m, int payload_type) {
#ifdef WITH_TRANSCODING
	struct codec_handler *ret = NULL;

	if (!m->protocol)
		goto out;

	if (m->protocol->rtp)
		ret = codec_handler_get_rtp(m, payload_type);
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
	m->dtmf_injector = NULL;
#endif
}


void codec_add_raw_packet(struct media_packet *mp) {
	struct codec_packet *p = g_slice_alloc0(sizeof(*p));
	p->s = mp->raw;
	p->free_func = NULL;
	if (mp->rtp && mp->ssrc_out) {
		ssrc_ctx_hold(mp->ssrc_out);
		p->ssrc_out = mp->ssrc_out;
		p->rtp = mp->rtp;
	}
	g_queue_push_tail(&mp->packets_out, p);
}
static int handler_func_passthrough(struct codec_handler *h, struct media_packet *mp) {
	if (mp->call->block_media || mp->media->monologue->block_media)
		return 0;

	codec_add_raw_packet(mp);
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
		if (!packet->func || !packet->handler->ssrc_hash) {
			h->func(h, mp);
			return 0;
		}
	}

	struct ssrc_ctx *ssrc_in = mp->ssrc_in;
	struct ssrc_entry_call *ssrc_in_p = ssrc_in->parent;
	struct ssrc_ctx *ssrc_out = mp->ssrc_out;
	struct ssrc_entry_call *ssrc_out_p = ssrc_out->parent;

	struct codec_ssrc_handler *ch = get_ssrc(ssrc_in_p->h.ssrc, h->ssrc_hash);
	if (G_UNLIKELY(!ch))
		return 0;

	atomic64_inc(&ssrc_in->packets);
	atomic64_add(&ssrc_in->octets, mp->payload.len);

	packet->p.seq = ntohs(mp->rtp->seq_num);
	packet->payload = str_dup(&mp->payload);
	uint32_t packet_ts = ntohl(mp->rtp->timestamp);
	packet->ts = packet_ts;
	packet->marker = (mp->rtp->m_pt & 0x80) ? 1 : 0;

	// how should we retrieve packets from the sequencer?
	void *(*seq_next_packet)(packet_sequencer_t *) = packet_sequencer_next_packet;
	if (packet->ignore_seq)
		seq_next_packet = packet_sequencer_force_next_packet;

	__ssrc_lock_both(mp);

	packet_sequencer_init(&ssrc_in_p->sequencer, (GDestroyNotify) __transcode_packet_free);

	uint16_t seq_ori = ssrc_in_p->sequencer.seq;
	int seq_ret = packet_sequencer_insert(&ssrc_in_p->sequencer, &packet->p);
	if (seq_ret < 0) {
		// dupe
		if (packet->dup_func)
			packet->dup_func(ch, packet, mp);
		else
			ilogs(transcoding, LOG_DEBUG, "Ignoring duplicate RTP packet");
		__transcode_packet_free(packet);
		atomic64_inc(&ssrc_in->duplicates);
		goto out;
	}

	// got a new packet, run decoder

	while (1) {
		int func_ret = 0;

		packet = seq_next_packet(&ssrc_in_p->sequencer);
		if (G_UNLIKELY(!packet)) {
			if (!ch->encoder_format.clockrate || !ch->handler || !ch->handler->dest_pt.codec_def)
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

		h = packet->handler;
		obj_put(&ch->h);
		ch = get_ssrc(ssrc_in_p->h.ssrc, h->ssrc_hash);
		if (G_UNLIKELY(!ch))
			goto next;

		atomic64_set(&ssrc_in->packets_lost, ssrc_in_p->sequencer.lost_count);
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

		func_ret = packet->func(ch, packet, mp);
		if (func_ret < 0)
			ilogs(transcoding, LOG_WARN | LOG_FLAG_LIMIT, "Decoder error while processing RTP packet");
next:
		if (func_ret != 1)
			__transcode_packet_free(packet);
	}

out:
	__ssrc_unlock_both(mp);
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

static int packet_dtmf_fwd(struct codec_ssrc_handler *ch, struct transcode_packet *packet,
		struct media_packet *mp)
{
	int payload_type = -1; // take from handler's output config
	unsigned long ts_delay = 0;

	if (ch->handler->dtmf_scaler) {
		struct codec_ssrc_handler *output_ch = NULL;
		struct codec_ssrc_handler *decoder_ch = NULL;

		// this is actually a DTMF -> PCM handler
		// grab our underlying PCM transcoder
		struct codec_handler *decoder_handler = __decoder_handler(ch->handler, mp);
		decoder_ch = get_ssrc(mp->ssrc_in->parent->h.ssrc,
				decoder_handler->ssrc_hash);
		output_ch = __output_ssrc_handler(decoder_ch, mp);
		if (G_UNLIKELY(!ch->encoder || !output_ch->encoder))
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
		obj_put(&decoder_ch->h);
	}

	char *buf = malloc(packet->payload->len + sizeof(struct rtp_header) + RTP_BUFFER_TAIL_ROOM);
	memcpy(buf + sizeof(struct rtp_header), packet->payload->s, packet->payload->len);
	if (packet->ignore_seq) // inject original seq
		__output_rtp(mp, ch, packet->handler ? : ch->handler, buf, packet->payload->len, packet->ts,
				packet->marker, packet->p.seq, -1, payload_type, ts_delay);
	else // use our own sequencing
		__output_rtp(mp, ch, packet->handler ? : ch->handler, buf, packet->payload->len, packet->ts,
				packet->marker, -1, 0, payload_type, ts_delay);

	return 0;
}

// returns the codec handler for the primary payload type - mostly determined by guessing
static struct codec_handler *__decoder_handler(struct codec_handler *h, struct media_packet *mp) {
	if (!mp->ssrc_in)
		return h;

	for (int i = 0; i < mp->ssrc_in->tracker.most_len; i++) {
		int prim_pt = mp->ssrc_in->tracker.most[i];
		if (prim_pt == 255)
			continue;

		struct codec_handler *sequencer_h = codec_handler_get(mp->media, prim_pt);
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

static int packet_dtmf(struct codec_ssrc_handler *ch, struct transcode_packet *packet, struct media_packet *mp)
{
	struct codec_ssrc_handler *decoder_ch = NULL;

	if (mp->ssrc_in) {
		// find our decoder handler for the appropriate DTX buffer
		struct codec_handler *handler = ch->handler;
		struct codec_handler *decoder_handler = __decoder_handler(handler, mp);
		decoder_ch = get_ssrc(mp->ssrc_in->parent->h.ssrc,
				decoder_handler->ssrc_hash);
	}

	if (ch->ts_in != packet->ts) { // ignore already processed events
		int ret = dtmf_event(mp, packet->payload, ch->encoder_format.clockrate);
		if (G_UNLIKELY(ret == -1)) // error
			return -1;
		if (ret == 1) {
			// END event
			ch->ts_in = packet->ts;
			if (decoder_ch)
				decoder_ch->dtmf_start_ts = 0;
		}
		else {
			if (decoder_ch)
				decoder_ch->dtmf_start_ts = packet->ts ? packet->ts : 1;
		}
	}

	int ret = 0;

	if (!mp->call->block_dtmf && !mp->media->monologue->block_dtmf) {
		if (decoder_ch && __buffer_dtx(decoder_ch->dtx_buffer, ch, packet, mp, packet_dtmf_fwd))
			ret = 1; // consumed
		else
			packet_dtmf_fwd(ch, packet, mp);
	}

	if (decoder_ch)
		obj_put(&decoder_ch->h);

	return ret;
}
static int packet_dtmf_dup(struct codec_ssrc_handler *ch, struct transcode_packet *packet,
		struct media_packet *mp)
{
	if (!mp->call->block_dtmf && !mp->media->monologue->block_dtmf)
		packet_dtmf_fwd(ch, packet, mp);
	return 0;
}

static int __handler_func_supplemental(struct codec_handler *h, struct media_packet *mp,
		int (*func)(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *),
		int (*dup_func)(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *))
{
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);

	assert((mp->rtp->m_pt & 0x7f) == h->source_pt.payload_type);

	// create new packet and insert it into sequencer queue

	ilogs(transcoding, LOG_DEBUG, "Received %s RTP packet: SSRC %" PRIx32 ", PT %u, seq %u, TS %u, len %zu",
			h->source_pt.codec_def->rtpname,
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

	// determine the primary audio codec used by this SSRC, as the sequence numbers
	// and timing info is shared with it. we'll need to use the same sequencer

	struct codec_handler *sequencer_h = __decoder_handler(h, mp);

	// XXX ? h->output_handler = sequencer_h->output_handler; // XXX locking?

	struct transcode_packet *packet = g_slice_alloc0(sizeof(*packet));
	packet->func = func;
	packet->dup_func = dup_func;
	packet->handler = h;
	packet->rtp = *mp->rtp;

	if (sequencer_h->kernelize) {
		// this sequencer doesn't actually keep track of RTP seq properly. instruct
		// the sequencer not to wait for the next in-seq packet but always return
		// them immediately
		packet->ignore_seq = 1;
	}

	return __handler_func_sequencer(mp, packet);
}
static int handler_func_supplemental(struct codec_handler *h, struct media_packet *mp) {
	return __handler_func_supplemental(h, mp, packet_decode, NULL);
}
static int handler_func_dtmf(struct codec_handler *h, struct media_packet *mp) {
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



struct rtp_payload_type *codec_make_payload_type(const str *codec_str, struct call_media *media) {
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

	struct rtp_payload_type *ret = g_slice_alloc0(sizeof(*ret));
	ret->payload_type = -1;
	ret->encoding = codec;
	ret->clock_rate = clockrate;
	ret->channels = channels;
	ret->bitrate = bitrate;
	ret->ptime = ptime;
	ret->format_parameters = fmt_params;
	ret->codec_opts = codec_opts;

	const codec_def_t *def = codec_find(&ret->encoding, 0);
	ret->codec_def = def;

	codec_init_payload_type(ret, media);

	return ret;
}

void codec_init_payload_type(struct rtp_payload_type *ret, struct call_media *media) {
#ifdef WITH_TRANSCODING
	const codec_def_t *def = ret->codec_def;

	if (def) {
		if (!ret->clock_rate)
			ret->clock_rate = def->default_clockrate;
		if (!ret->channels)
			ret->channels = def->default_channels;
		if (!ret->ptime)
			ret->ptime = def->default_ptime;
		if ((!ret->format_parameters.s || !ret->format_parameters.s[0]) && def->default_fmtp)
			str_init(&ret->format_parameters, (char *) def->default_fmtp);

		if (def->init)
			def->init(ret);

		if (def->rfc_payload_type >= 0) {
			const struct rtp_payload_type *rfc_pt = rtp_get_rfc_payload_type(def->rfc_payload_type);
			// only use the RFC payload type if all parameters match
			if (rfc_pt
					&& (ret->clock_rate == 0 || ret->clock_rate == rfc_pt->clock_rate)
					&& (ret->channels == 0 || ret->channels == rfc_pt->channels))
			{
				ret->payload_type = rfc_pt->payload_type;
				if (!ret->clock_rate)
					ret->clock_rate = rfc_pt->clock_rate;
				if (!ret->channels)
					ret->channels = rfc_pt->channels;
			}
		}
	}
#endif

	// init params strings
	char full_encoding[64];
	char full_full_encoding[64];
	char params[32] = "";

	snprintf(full_full_encoding, sizeof(full_full_encoding), STR_FORMAT "/%u/%i", STR_FMT(&ret->encoding),
			ret->clock_rate,
			ret->channels);

	if (ret->channels > 1) {
		strcpy(full_encoding, full_full_encoding);
		snprintf(params, sizeof(params), "%i", ret->channels);
	}
	else
		snprintf(full_encoding, sizeof(full_encoding), STR_FORMAT "/%u", STR_FMT(&ret->encoding),
				ret->clock_rate);

	str_init(&ret->encoding_with_params, full_encoding);
	str_init(&ret->encoding_with_full_params, full_full_encoding);
	str_init(&ret->encoding_parameters, params);

	if (media)
		__rtp_payload_type_dup(media->call, ret);
}



#ifdef WITH_TRANSCODING


static int handler_func_passthrough_ssrc(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);
	if (mp->call->block_media || mp->media->monologue->block_media)
		return 0;

	// substitute out SSRC etc
	mp->rtp->ssrc = htonl(mp->ssrc_in->ssrc_map_out);
	//mp->rtp->timestamp = htonl(ntohl(mp->rtp->timestamp));
	mp->rtp->seq_num = htons(ntohs(mp->rtp->seq_num) + mp->ssrc_out->parent->seq_diff);

	// keep track of other stats here?

	codec_add_raw_packet(mp);
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
		struct transcode_packet *packet, struct media_packet *mp,
		int (*func)(struct codec_ssrc_handler *ch, struct transcode_packet *packet,
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
	media_packet_copy(&dtxp->mp, mp);

	// add to processing queue

	mutex_lock(&dtxb->lock);

	dtxb->start = rtpe_now.tv_sec;
	g_queue_push_tail(&dtxb->packets, dtxp);
	ilogs(dtx, LOG_DEBUG, "Adding packet (TS %lu) to DTX buffer; now %i packets in DTX queue",
			ts, dtxb->packets.length);

	// schedule timer if not running yet
	if (!dtxb->ttq_entry.when.tv_sec) {
		if (!dtxb->ssrc)
			dtxb->ssrc = mp->ssrc_in->parent->h.ssrc;
		dtxb->ttq_entry.when = mp->tv;
		timeval_add_usec(&dtxb->ttq_entry.when, rtpe_config.dtx_delay * 1000);
		timerthread_queue_push(&dtxb->ttq, &dtxb->ttq_entry);
	}

	mutex_unlock(&dtxb->lock);

	return 1;
}

static void dtx_packet_free(struct dtx_packet *dtxp) {
	if (dtxp->packet)
		__transcode_packet_free(dtxp->packet);
	media_packet_release(&dtxp->mp);
	if (dtxp->decoder_handler)
		obj_put(&dtxp->decoder_handler->h);
	g_slice_free1(sizeof(*dtxp), dtxp);
}
static void __dtx_send_later(struct timerthread_queue *ttq, void *p) {
	struct dtx_buffer *dtxb = (void *) ttq;
	struct media_packet mp_copy = {0,};
	int ret = 0, discard = 0;
	unsigned long ts;
	int p_left = 0;
	long tv_diff = -1, ts_diff = 0;

	mutex_lock(&dtxb->lock);

	// do we have a packet?
	struct dtx_packet *dtxp = g_queue_peek_head(&dtxb->packets);
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
		else if (ts_diff > dtxb->tspp) {
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
		ts_diff = dtxp->packet->ts - dtxb->head_ts;
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
	struct packet_stream *ps = mp_copy.stream;
	log_info_stream_fd(mp_copy.sfd);

	// copy out other fields so we can unlock
	struct codec_ssrc_handler *ch = (dtxp && dtxp->decoder_handler) ? obj_get(&dtxp->decoder_handler->h)
		: NULL;
	if (!ch && dtxb->csh)
		ch = obj_get(&dtxb->csh->h);
	struct call *call = dtxb->call ? obj_get(dtxb->call) : NULL;

	if (!call || !ch || !ps || !ps->ssrc_in
			|| dtxb->ssrc != ps->ssrc_in->parent->h.ssrc
			|| dtxb->ttq_entry.when.tv_sec == 0) {
		// shut down or SSRC change
		ilogs(dtx, LOG_DEBUG, "DTX buffer for %lx has been shut down", (unsigned long) dtxb->ssrc);
		dtxb->ttq_entry.when.tv_sec = 0;
		dtxb->head_ts = 0;
		mutex_unlock(&dtxb->lock);
		goto out; // shut down
	}

	// schedule next run
	timeval_add_usec(&dtxb->ttq_entry.when, dtxb->ptime * 1000);

	// handle timer drifts
	if (dtxp && tv_diff < rtpe_config.dtx_delay * 1000) {
		// timer underflow
		ilogs(dtx, LOG_DEBUG, "Packet reception time has caught up with DTX timer "
				"(%li ms < %i ms), "
				"pushing DTX timer forward my %i ms",
				tv_diff / 1000, rtpe_config.dtx_delay, rtpe_config.dtx_shift);
		timeval_add_usec(&dtxb->ttq_entry.when, rtpe_config.dtx_shift * 1000);
	}
	else if (dtxp && ts_diff < dtxb->tspp) {
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
			timeval_add_usec(&dtxb->ttq_entry.when, rtpe_config.dtx_shift * 1000);
			discard = 1;
		}
	}
	else if (dtxp && dtxb->packets.length >= rtpe_config.dtx_buffer) {
		// inspect TS is most recent packet
		struct dtx_packet *dtxp_last = g_queue_peek_tail(&dtxb->packets);
		ts_diff = dtxp_last->packet->ts - ts;
		long long ts_diff_us = (long long) ts_diff * 1000000 / dtxb->clockrate;
		if (ts_diff_us >= rtpe_config.dtx_lag * 1000) {
			// overflow
			ilogs(dtx, LOG_DEBUG, "DTX timer queue overflowing (%i packets in queue, "
					"%lli ms delay), speeding up DTX timer by %i ms",
					dtxb->packets.length, ts_diff_us / 1000, rtpe_config.dtx_shift);
			timeval_add_usec(&dtxb->ttq_entry.when, rtpe_config.dtx_shift * -1000);
		}
	}

	timerthread_queue_push(&dtxb->ttq, &dtxb->ttq_entry);

	mutex_unlock(&dtxb->lock);

	rwlock_lock_r(&call->master_lock);
	__ssrc_lock_both(&mp_copy);

	if (dtxp) {
		if (!discard) {
			ilogs(dtx, LOG_DEBUG, "Decoding DTX-buffered RTP packet (TS %lu) now; "
					"%i packets left in queue", ts, p_left);

			ret = dtxp->func(ch, dtxp->packet, &mp_copy);
			if (ret)
				ilogs(dtx, LOG_WARN | LOG_FLAG_LIMIT,
						"Decoder error while processing buffered RTP packet");
		}
	}
	else {
		unsigned int diff = rtpe_now.tv_sec - dtxb->start;

		if (rtpe_config.max_dtx <= 0 || diff < rtpe_config.max_dtx) {
			ilogs(dtx, LOG_DEBUG, "RTP media for TS %lu missing, triggering DTX", ts);

			// synthetic packet
			mp_copy.rtp->seq_num += htons(1);

			ret = decoder_lost_packet(ch->decoder, ts,
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

	__ssrc_unlock_both(&mp_copy);

	if (mp_copy.packets_out.length && ret == 0) {
		struct packet_stream *sink = ps->rtp_sink;

		if (!sink)
			media_socket_dequeue(&mp_copy, NULL); // just free
		else {
			if (ps->handler && media_packet_encrypt(ps->handler->out->rtp_crypt, sink, &mp_copy))
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
	if (!ch->handler->source_pt.codec_def->packet_lost || ch->dtx_buffer)
		return;

	if (!rtpe_config.dtx_delay)
		return;

	struct dtx_buffer *dtx =
		ch->dtx_buffer = timerthread_queue_new("dtx_buffer", sizeof(*ch->dtx_buffer),
				&codec_timers_thread, NULL, __dtx_send_later, __dtx_free, NULL);
	dtx->csh = obj_get(&ch->h);
	dtx->call = obj_get(ch->handler->media->call);
	mutex_init(&dtx->lock);
	dtx->ptime = ch->ptime;
	if (!dtx->ptime)
		dtx->ptime = 20; // XXX should be replaced with length of actual decoded packet
	dtx->tspp = dtx->ptime * ch->handler->source_pt.clock_rate / 1000; // XXX ditto
	dtx->clockrate = ch->handler->source_pt.clock_rate;
}
static void __ssrc_handler_stop(void *p) {
	struct codec_ssrc_handler *ch = p;
	if (ch->dtx_buffer) {
		mutex_lock(&ch->dtx_buffer->lock);
		__dtx_shutdown(ch->dtx_buffer);
		mutex_unlock(&ch->dtx_buffer->lock);

		obj_put(&ch->dtx_buffer->ttq.tt_obj);
		ch->dtx_buffer = NULL;
	}
}
void codec_handlers_stop(GQueue *q) {
	for (GList *l = q->head; l; l = l->next) {
		struct codec_handler *h = l->data;
		if (h->ssrc_hash)
			ssrc_hash_foreach(h->ssrc_hash, __ssrc_handler_stop);
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
		/* ilog(LOG_DEBUG, "XXXXXXXXXXXX checking %u %i vs %i", i, (int) s[i], (int) thres); */ \
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
	//ilog(LOG_DEBUG, "XXXXXXXXXXXXXXXXXXXX silence detect %i %i", rtpe_config.silence_detect_int, ch->handler->cn_payload_type);
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

	if (h->dtmf_scaler)
		ilogs(codec, LOG_DEBUG, "Creating SSRC DTMF transcoder from %s/%u/%i to "
				"PT %i",
				h->source_pt.codec_def->rtpname, h->source_pt.clock_rate,
				h->source_pt.channels,
				h->dtmf_payload_type);
	else
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
	if (ch->dtx_buffer)
		obj_put(&ch->dtx_buffer->ttq.tt_obj);
}

static int packet_encoded_rtp(encoder_t *enc, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;
	//unsigned int seq_off = (mp->iter_out > mp->iter_in) ? 1 : 0;

	ilogs(transcoding, LOG_DEBUG, "RTP media successfully encoded: TS %llu, len %i",
			(unsigned long long) enc->avpkt.pts, enc->avpkt.size);

	// run this through our packetizer
	AVPacket *in_pkt = &enc->avpkt;

	while (1) {
		// figure out how big of a buffer we need
		unsigned int payload_len = MAX(MAX(enc->avpkt.size, ch->bytes_per_packet),
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

		if (G_UNLIKELY(ret == -1 || enc->avpkt.pts == AV_NOPTS_VALUE)) {
			// nothing
			free(buf);
			break;
		}

		ilogs(transcoding, LOG_DEBUG, "Received packet of %zu bytes from packetizer", inout.len);

		// check special payloads

		unsigned int repeats = 0;
		int payload_type = -1;

		int is_dtmf = dtmf_event_payload(&inout, (uint64_t *) &enc->avpkt.pts, enc->avpkt.duration,
				&ch->dtmf_event, &ch->dtmf_events);
		if (is_dtmf) {
			payload_type = ch->handler->dtmf_payload_type;
			if (is_dtmf == 1)
				ch->rtp_mark = 1; // DTMF start event
			else if (is_dtmf == 3)
				repeats = 2; // DTMF end event
		}
		else {
			if (is_silence_event(&inout, &ch->silence_events, enc->avpkt.pts, enc->avpkt.duration))
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
					+ enc->avpkt.pts / enc->def->clockrate_mult,
					ch->rtp_mark ? 1 : 0, -1, 0,
					payload_type, 0);
			mp->ssrc_out->parent->seq_diff++;
			//mp->iter_out++;
			ch->rtp_mark = 0;
		} while (repeats--);

		if (ret == 0) {
			// no more to go
			break;
		}

		// loop around and get more
		in_pkt = NULL;
		//seq_off = 1; // next packet needs last seq + 1 XXX set unkernelize if used
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

static int __rtp_decode(struct codec_ssrc_handler *ch, struct transcode_packet *packet, struct media_packet *mp)
{
	int ret = decoder_input_data(ch->decoder, packet->payload, packet->ts, ch->handler->packet_decoded,
			ch, mp);
	mp->ssrc_out->parent->seq_diff--;
	return ret;
}
static int packet_decode(struct codec_ssrc_handler *ch, struct transcode_packet *packet, struct media_packet *mp)
{
	int ret = 0;

	struct codec_ssrc_handler *decoder_ch = ch;

	if (ch->handler && ch->handler->source_pt.codec_def && ch->handler->source_pt.codec_def->supplemental) {
		struct codec_handler *decoder_handler = __decoder_handler(ch->handler, mp);
		decoder_ch = get_ssrc(mp->ssrc_in->parent->h.ssrc,
				decoder_handler->ssrc_hash);
	}

	if (!ch->first_ts)
		ch->first_ts = packet->ts;
	ch->last_ts = packet->ts;

	if (decoder_ch->dtmf_start_ts && !rtpe_config.dtmf_no_suppress) {
		if ((packet->ts > decoder_ch->dtmf_start_ts && packet->ts - decoder_ch->dtmf_start_ts > 80000) ||
				(packet->ts < decoder_ch->dtmf_start_ts && decoder_ch->dtmf_start_ts - packet->ts > 80000)) {
			ilogs(transcoding, LOG_DEBUG, "Resetting decoder DTMF state due to TS discrepancy");
			decoder_ch->dtmf_start_ts = 0;
		}
		else {
			ilogs(transcoding, LOG_DEBUG, "Decoder is in DTMF state, discaring codec packet");
			if (mp->ssrc_out)
				mp->ssrc_out->parent->seq_diff--;
			goto out;
		}
	}

	if (__buffer_dtx(ch->dtx_buffer, ch, packet, mp, __rtp_decode))
		ret = 1; // consumed
	else {
		ilogs(transcoding, LOG_DEBUG, "Decoding RTP packet now");
		ret = __rtp_decode(ch, packet, mp);
		ret = ret ? -1 : 0;
	}

out:
	if (decoder_ch != ch)
		obj_put(&decoder_ch->h);
	return ret;
}


static void codec_calc_jitter(struct media_packet *mp, unsigned int clockrate) {
	if (!mp->ssrc_in)
		return;
	struct ssrc_entry_call *sec = mp->ssrc_in->parent;

	// RFC 3550 A.8
	uint32_t transit = (((timeval_us(&mp->tv) / 1000) * clockrate) / 1000)
		- ntohl(mp->rtp->timestamp);
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


static int handler_func_transcode(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);
	if (mp->call->block_media || mp->media->monologue->block_media)
		return 0;

	// create new packet and insert it into sequencer queue

	ilogs(transcoding, LOG_DEBUG, "Received RTP packet: SSRC %" PRIx32 ", PT %u, seq %u, TS %u, len %zu",
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

	codec_calc_jitter(mp, h->source_pt.clock_rate);

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

	if (h->dtmf_scaler) {
		packet->func = packet_dtmf;
		packet->dup_func = packet_dtmf_dup;
	}

	int ret = __handler_func_sequencer(mp, packet);

	//ilog(LOG_DEBUG, "tc iters: in %u out %u", mp->iter_in, mp->iter_out);

	return ret;
}

static int handler_func_playback(struct codec_handler *h, struct media_packet *mp) {
	decoder_input_data(h->ssrc_handler->decoder, &mp->payload, mp->rtp->timestamp,
			h->packet_decoded, h->ssrc_handler, mp);
	return 0;
}

static int handler_func_inject_dtmf(struct codec_handler *h, struct media_packet *mp) {
	struct codec_ssrc_handler *ch = get_ssrc(mp->ssrc_in->parent->h.ssrc, h->ssrc_hash);
	decoder_input_data(ch->decoder, &mp->payload, mp->rtp->timestamp,
			h->packet_decoded, ch, mp);
	obj_put(&ch->h);
	return 0;
}






// special return value `(void *) 0x1` to signal type mismatch
static struct rtp_payload_type *codec_make_payload_type_sup(const str *codec_str, struct call_media *media) {
	struct rtp_payload_type *ret = codec_make_payload_type(codec_str, media);
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
		struct call_media *other_media)
{
	struct rtp_payload_type *pt = codec_make_payload_type_sup(codec, media);
	if (!pt) {
		ilogs(codec, LOG_WARN, "Codec '" STR_FORMAT "' requested for transcoding is not supported",
				STR_FMT(codec));
		return NULL;
	}
	if (pt == (void *) 0x1)
		return NULL;

	pt->payload_type = __unused_pt_number(media, other_media, pt);
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





static void __rtp_payload_type_dup(struct call *call, struct rtp_payload_type *pt) {
	/* we must duplicate the contents */
	call_str_cpy(call, &pt->encoding_with_params, &pt->encoding_with_params);
	// special handling of this one as it's not done by the SDP parser
	if (pt->encoding_with_full_params.len)
		call_str_cpy(call, &pt->encoding_with_full_params, &pt->encoding_with_full_params);
	else {
		char buf[64];
		snprintf(buf, sizeof(buf), STR_FORMAT "/%i/%i", STR_FMT(&pt->encoding),
				pt->clock_rate, pt->channels);
		str s;
		str_init(&s, buf);
		call_str_cpy(call, &pt->encoding_with_full_params, &s);
	}
	call_str_cpy(call, &pt->encoding, &pt->encoding);
	call_str_cpy(call, &pt->encoding_parameters, &pt->encoding_parameters);
	call_str_cpy(call, &pt->format_parameters, &pt->format_parameters);
	call_str_cpy(call, &pt->codec_opts, &pt->codec_opts);
	for (GList *l = pt->rtcp_fb.head; l; l = l->next) {
		str *fb = l->data;
		call_str_cpy(call, fb, fb);
	}
}
static struct rtp_payload_type *__rtp_payload_type_copy(const struct rtp_payload_type *pt) {
	struct rtp_payload_type *pt_copy = g_slice_alloc(sizeof(*pt));
	*pt_copy = *pt;
	g_queue_init(&pt_copy->rtcp_fb);
	for (GList *l = pt->rtcp_fb.head; l; l = l->next)
		g_queue_push_tail(&pt_copy->rtcp_fb, l->data);
	return pt_copy;
}
static void __rtp_payload_type_add_name(GHashTable *ht, struct rtp_payload_type *pt)
{
	GQueue *q = g_hash_table_lookup_queue_new(ht, str_dup(&pt->encoding), free);
	g_queue_push_tail(q, GUINT_TO_POINTER(pt->payload_type));
	q = g_hash_table_lookup_queue_new(ht, str_dup(&pt->encoding_with_params), free);
	g_queue_push_tail(q, GUINT_TO_POINTER(pt->payload_type));
	q = g_hash_table_lookup_queue_new(ht, str_dup(&pt->encoding_with_full_params), free);
	g_queue_push_tail(q, GUINT_TO_POINTER(pt->payload_type));
}
#ifdef WITH_TRANSCODING
static void __insert_codec_tracker(struct call_media *media, GList *link) {
	struct rtp_payload_type *pt = link->data;
	struct codec_tracker *sct = media->codec_tracker;

	ensure_codec_def(pt, media);

	if (!pt->codec_def || !pt->codec_def->supplemental)
		g_hash_table_replace(sct->clockrates, GUINT_TO_POINTER(pt->clock_rate),
				GUINT_TO_POINTER(GPOINTER_TO_UINT(
						g_hash_table_lookup(sct->clockrates,
							GUINT_TO_POINTER(pt->clock_rate))) + 1));
	else {
		GHashTable *clockrates = g_hash_table_lookup(sct->supp_codecs, &pt->encoding);
		if (!clockrates) {
			clockrates = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
					(GDestroyNotify) g_queue_free);
			g_hash_table_replace(sct->supp_codecs, str_dup(&pt->encoding), clockrates);
		}
		GQueue *entries = g_hash_table_lookup_queue_new(clockrates, GUINT_TO_POINTER(pt->clock_rate),
				NULL);
		g_queue_push_tail(entries, link);
	}
}
#endif
static void __queue_insert_supp(GQueue *q, struct rtp_payload_type *pt, int supp_check) {
	// do we care at all?
	if (!supp_check) {
		g_queue_push_tail(q, pt);
		return;
	}

	// all new supp codecs go last
	if (pt->codec_def && pt->codec_def->supplemental) {
		g_queue_push_tail(q, pt);
		return;
	}

	// find the cut-off point between non-supp and supp codecs
	GList *insert_pos = NULL; // last non-supp codec
	for (GList *l = q->tail; l; l = l->prev) {
		struct rtp_payload_type *ptt = l->data;
		if (!ptt->codec_def || !ptt->codec_def->supplemental) {
			insert_pos = l;
			break;
		}
	}
	// do we have any non-supp codecs?
	if (!insert_pos)
		g_queue_push_head(q, pt);
	else
		g_queue_insert_after(q, insert_pos, pt);
}
// consumes 'pt'
void __rtp_payload_type_add_recv(struct call_media *media, struct rtp_payload_type *pt, int supp_check) {
	if (!pt)
		return;
#ifdef WITH_TRANSCODING
	ensure_codec_def(pt, media);
#endif
	if (proto_is_not_rtp(media->protocol)) {
		payload_type_free(pt);
		return;
	}
	// update ptime in case it was overridden
	if (media->ptime > 0)
		pt->ptime = media->ptime;
	g_hash_table_insert(media->codecs_recv, GINT_TO_POINTER(pt->payload_type), pt);
	__rtp_payload_type_add_name(media->codec_names_recv, pt);
	__queue_insert_supp(&media->codecs_prefs_recv, pt, supp_check);
}
// consumes 'pt'
void __rtp_payload_type_add_send(struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	if (!pt)
		return;
	if (proto_is_not_rtp(other_media->protocol)) {
		payload_type_free(pt);
		return;
	}
	// update ptime in case it was overridden
	if (other_media->ptime > 0)
		pt->ptime = other_media->ptime;
	g_hash_table_insert(other_media->codecs_send, GINT_TO_POINTER(pt->payload_type), pt);
	__rtp_payload_type_add_name(other_media->codec_names_send, pt);
	g_queue_push_tail(&other_media->codecs_prefs_send, pt);
}
// duplicates 'pt'
void __rtp_payload_type_add_send_dup(struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	if (proto_is_not_rtp(other_media->protocol))
		return;
	pt = __rtp_payload_type_copy(pt);
	__rtp_payload_type_add_send(other_media, pt);
}
// consumes 'pt'
static void __rtp_payload_type_add(struct call_media *media, struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	__rtp_payload_type_add_send_dup(other_media, pt);
	__rtp_payload_type_add_recv(media, pt, 0);
}

static void __payload_queue_free(void *qq) {
	GQueue *q = qq;
	g_queue_free_full(q, (GDestroyNotify) payload_type_free);
}
static int __revert_codec_strip(GHashTable *stripped, GHashTable *masked, const str *codec,
		struct call_media *media, struct call_media *other_media)
{
	int ret = 0;

	GQueue *q = g_hash_table_lookup(stripped, codec);
	if (q) {
		ilogs(codec, LOG_DEBUG, "Restoring codec '" STR_FORMAT "' from stripped codecs (%u payload types)",
				STR_FMT(codec), q->length);
		while (q->length) {
			struct rtp_payload_type *pt = g_queue_pop_head(q);
			__rtp_payload_type_add(media, other_media, pt);
		}
		g_hash_table_remove(stripped, codec);
		ret = 1;
	}

	q = g_hash_table_lookup(masked, codec);
	if (q) {
		ilogs(codec, LOG_DEBUG, "Restoring codec '" STR_FORMAT "' from masked codecs (%u payload types)",
				STR_FMT(codec), q->length);
		while (q->length) {
			struct rtp_payload_type *pt = g_queue_pop_head(q);
			__rtp_payload_type_add_recv(media, pt, 1);
		}
		g_hash_table_remove(masked, codec);
		ret = 1;
	}

	return ret;
}
static int __codec_options_set1(struct call *call, struct rtp_payload_type *pt, const str *enc,
		GHashTable *codec_set)
{
	str *pt_str = g_hash_table_lookup(codec_set, enc);
	if (!pt_str)
		return 0;
	struct rtp_payload_type *pt_parsed = codec_make_payload_type(pt_str, NULL);
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
	if (!pt->codec_opts.len && pt_parsed->codec_opts.len)
		call_str_cpy(call, &pt->codec_opts, &pt_parsed->codec_opts);
	payload_type_free(pt_parsed);
	return 1;
}
static void __codec_options_set(struct call *call, struct rtp_payload_type *pt, GHashTable *codec_set) {
	if (!codec_set)
		return;
	if (__codec_options_set1(call, pt, &pt->encoding_with_full_params, codec_set))
		return;
	if (__codec_options_set1(call, pt, &pt->encoding_with_params, codec_set))
		return;
	if (__codec_options_set1(call, pt, &pt->encoding, codec_set))
		return;
}
#ifdef WITH_TRANSCODING
static void codec_tracker_destroy(struct codec_tracker **sct) {
	if (!*sct)
		return;
	g_hash_table_destroy((*sct)->clockrates);
	g_hash_table_destroy((*sct)->touched);
	g_hash_table_destroy((*sct)->supp_codecs);
	g_slice_free1(sizeof(**sct), *sct);
	*sct = NULL;
}
void codec_tracker_init(struct call_media *m) {
	codec_tracker_destroy(&m->codec_tracker);
	m->codec_tracker = g_slice_alloc0(sizeof(*m->codec_tracker));
	m->codec_tracker->clockrates = g_hash_table_new(g_direct_hash, g_direct_equal);
	m->codec_tracker->touched = g_hash_table_new(g_direct_hash, g_direct_equal);
	m->codec_tracker->supp_codecs = g_hash_table_new_full(str_case_hash, str_case_equal, free,
			(GDestroyNotify) g_hash_table_destroy);
}
static void codec_touched(struct rtp_payload_type *pt, struct call_media *media) {
	if (!media->codec_tracker)
		return;
	ensure_codec_def(pt, media);
	if (pt->codec_def && pt->codec_def->supplemental) {
		media->codec_tracker->all_touched = 1;
		return;
	}
	g_hash_table_replace(media->codec_tracker->touched, GUINT_TO_POINTER(pt->clock_rate), (void *) 0x1);
}
static int ptr_cmp(const void *a, const void *b) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}
void codec_tracker_finish(struct call_media *media, struct call_media *other_media) {
	struct codec_tracker *sct = media->codec_tracker;
	if (!sct)
		return;

	// build our tables
	for (GList *l = media->codecs_prefs_recv.head; l; l = l->next)
		__insert_codec_tracker(media, l);

	// get all supported audio clock rates
	GList *clockrates = g_hash_table_get_keys(sct->clockrates);
	// and to ensure consistent results
	clockrates = g_list_sort(clockrates, ptr_cmp);

	// for each supplemental codec supported ...
	GList *supp_codecs = g_hash_table_get_keys(sct->supp_codecs);

	for (GList *l = supp_codecs; l; l = l->next) {
		// ... compare the list of clock rates against the clock rates supported by the audio codecs
		str *supp_codec = l->data;
		GHashTable *supp_clockrates = g_hash_table_lookup(sct->supp_codecs, supp_codec);

		// iterate audio clock rates and check against supp clockrates
		for (GList *k = clockrates; k; k = k->next) {
			unsigned int clockrate = GPOINTER_TO_UINT(k->data);

			// has it been removed?
			if (!g_hash_table_lookup(sct->clockrates, GUINT_TO_POINTER(clockrate)))
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

			struct rtp_payload_type *pt = codec_add_payload_type(&pt_str, media, NULL);
			if (!pt)
				continue;
			pt->for_transcoding = 1;

			// there should be an existing entry with a different clock rate
			GQueue *existing_pts = g_hash_table_lookup(media->codec_names_recv, &pt->encoding);
			struct rtp_payload_type *existing_pt = NULL;
			if (existing_pts && existing_pts->length) {
				int pt_num = GPOINTER_TO_UINT(existing_pts->head->data);
				existing_pt = g_hash_table_lookup(media->codecs_recv, GINT_TO_POINTER(pt_num));
			}
			struct codec_handler *existing_handler = existing_pt ? codec_handler_get(media, existing_pt->payload_type) : NULL;

			if (existing_pt && existing_handler && existing_handler->dest_pt.codec_def) {
				// since this happens after we ran through the codec matchup, we must create the appropriate handler here
				struct codec_handler *handler = __get_pt_handler(media, pt);
				// duplicate the codec handler of the existing PT
				__make_transcoder(handler, &existing_handler->dest_pt, NULL, existing_handler->dtmf_payload_type, 0);
			}

			__rtp_payload_type_add_recv(media, pt, 1);
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

				// now we have to check the codec handlers on the opposite side to see
				// if any of them were using this as output
				struct rtp_payload_type *prim_dtmf = NULL;
				struct rtp_payload_type *prim_cn = NULL;
				for (GList *o = other_media->codecs_prefs_recv.head; o; o = o->next) {
					struct rtp_payload_type *opt = o->data;
					struct codec_handler *ch = codec_handler_get(other_media,
							opt->payload_type);
					if (!ch)
						continue;

					// check DTMF
					if (!prim_dtmf && ch->dtmf_payload_type != -1)
						prim_dtmf = g_hash_table_lookup(other_media->codecs_recv,
								GINT_TO_POINTER(ch->dtmf_payload_type));
					if (prim_dtmf) {
						if (ch->dest_pt.payload_type == pt->payload_type) {
							ilogs(codec, LOG_DEBUG, "Adjusting output DTMF PT for "
									"opposite codec handler for "
									STR_FORMAT " (%i) to %i",
									STR_FMT(&opt->encoding_with_params),
									opt->payload_type,
									prim_dtmf->payload_type);
							__make_transcoder(ch, prim_dtmf, NULL,
									prim_dtmf->payload_type,
									ch->pcm_dtmf_detect);
						}
						else if (ch->dtmf_payload_type == pt->payload_type) {
							ilogs(codec, LOG_DEBUG, "Adjusting output DTMF PT for "
									"opposite codec handler for "
									STR_FORMAT " (%i) to %i",
									STR_FMT(&opt->encoding_with_params),
									opt->payload_type,
									prim_dtmf->payload_type);
							__make_transcoder(ch, &ch->dest_pt, NULL,
									prim_dtmf->payload_type,
									ch->pcm_dtmf_detect);
						}
					}

					// check CN
					if (!prim_cn && ch->cn_payload_type != -1)
						prim_cn = g_hash_table_lookup(other_media->codecs_recv,
								GINT_TO_POINTER(ch->cn_payload_type));
					if (prim_cn) {
						if (ch->dest_pt.payload_type == pt->payload_type) {
							ilogs(codec, LOG_DEBUG, "Adjusting output CN PT for "
									"opposite codec handler for "
									STR_FORMAT " (%i) to %i",
									STR_FMT(&opt->encoding_with_params),
									opt->payload_type,
									prim_cn->payload_type);
							ch->cn_payload_type = prim_cn->payload_type;
						}
						else if (ch->cn_payload_type == pt->payload_type) {
							ilogs(codec, LOG_DEBUG, "Adjusting output CN PT for "
									"opposite codec handler for "
									STR_FORMAT " (%i) to %i",
									STR_FMT(&opt->encoding_with_params),
									opt->payload_type,
									prim_cn->payload_type);
							ch->cn_payload_type = prim_cn->payload_type;
						}
					}
				}

				__delete_receiver_codec(media, link);
			}
		}
	}

	g_list_free(supp_codecs);
	g_list_free(clockrates);
	codec_tracker_destroy(&media->codec_tracker);
}
#endif
int __codec_ht_except(int all_flag, GHashTable *yes_ht, GHashTable *no_ht, struct rtp_payload_type *pt) {
	int do_this = 0;
	if (all_flag)
		do_this = 1;
	if (yes_ht) {
		if (g_hash_table_lookup(yes_ht, &pt->encoding))
			do_this = 1;
		else if (g_hash_table_lookup(yes_ht, &pt->encoding_with_params))
			do_this = 1;
		else if (g_hash_table_lookup(yes_ht, &pt->encoding_with_full_params))
			do_this = 1;
	}
	if (no_ht && all_flag) {
		if (g_hash_table_lookup(no_ht, &pt->encoding))
			do_this = 0;
		else if (g_hash_table_lookup(no_ht, &pt->encoding_with_params))
			do_this = 0;
		else if (g_hash_table_lookup(no_ht, &pt->encoding_with_full_params))
			do_this = 0;
	}
	return do_this;
}
void __ht_merge(GHashTable **dst, GHashTable *src) {
	if (!src)
		return;
	if (!*dst)
		*dst = g_hash_table_new_full(str_case_hash, str_case_equal, free, NULL);
	GHashTableIter iter;
	g_hash_table_iter_init(&iter, src);
	void *key;
	while (g_hash_table_iter_next(&iter, &key, NULL)) {
		str *dup = str_dup(key);
		g_hash_table_replace(*dst, dup, dup);
	}
}
void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, struct sdp_ng_flags *flags)
{
	if (!flags)
		return;

	// 'media' = receiver of this offer/answer; 'other_media' = sender of this offer/answer
	struct call *call = media->call;
	struct rtp_payload_type *pt;
	static const str str_all = STR_CONST_INIT("all");
	static const str str_full = STR_CONST_INIT("full");
	GHashTable *stripped = g_hash_table_new_full(str_case_hash, str_case_equal, free, __payload_queue_free);
	GHashTable *masked = g_hash_table_new_full(str_case_hash, str_case_equal, free, __payload_queue_free);
	int strip_all = 0, mask_all = 0, consume_all = 0, accept_all = 0;

	// start fresh
	if (!proto_is_rtp(other_media->protocol) && proto_is_rtp(media->protocol) && flags->opmode == OP_OFFER) {
		// leave them alone if incoming proto is not RTP but outgoing is,
		// as this is needed for T.38 decoding during a re-invite.
		// this special case is only needed in an offer as in the answer
		// we can go by media->codecs_prefs_send.
		;
	}
	else {
		// receiving part for 'media'
		g_queue_clear_full(&media->codecs_prefs_recv, (GDestroyNotify) payload_type_free);
		g_hash_table_remove_all(media->codecs_recv);
		g_hash_table_remove_all(media->codec_names_recv);
	}
	// and sending part for 'other_media'
	g_queue_clear_full(&other_media->codecs_prefs_send, (GDestroyNotify) payload_type_free);
	g_hash_table_remove_all(other_media->codecs_send);
	g_hash_table_remove_all(other_media->codec_names_send);

	if (flags->codec_strip && g_hash_table_lookup(flags->codec_strip, &str_all))
		strip_all = 1;
	else if (flags->codec_strip && g_hash_table_lookup(flags->codec_strip, &str_full))
		strip_all = 2;
	if (flags->codec_mask && g_hash_table_lookup(flags->codec_mask, &str_all))
		mask_all = 1;
	else if (flags->codec_mask && g_hash_table_lookup(flags->codec_mask, &str_full))
		mask_all = 2;
	if (flags->codec_consume && g_hash_table_lookup(flags->codec_consume, &str_all))
		consume_all = 1;
	else if (flags->codec_consume && g_hash_table_lookup(flags->codec_consume, &str_full))
		consume_all = 2;
	if (flags->codec_accept && g_hash_table_lookup(flags->codec_accept, &str_all))
		accept_all = 1;

	__ht_merge(&flags->codec_except, flags->codec_consume);
	__ht_merge(&flags->codec_except, flags->codec_accept);
	__ht_merge(&flags->codec_except, flags->codec_strip);
	__ht_merge(&flags->codec_except, flags->codec_mask);

	/* we steal the entire list to avoid duplicate allocs */
	while ((pt = g_queue_pop_head(types))) {
		__rtp_payload_type_dup(call, pt); // this takes care of string allocation

		// codec stripping
		if (__codec_ht_except(strip_all, flags->codec_strip, flags->codec_except, pt)) {
			ilogs(codec, LOG_DEBUG, "Stripping codec '" STR_FORMAT "'",
					STR_FMT(&pt->encoding_with_params));
#ifdef WITH_TRANSCODING
			codec_touched(pt, media);
#endif
			GQueue *q = g_hash_table_lookup_queue_new(stripped, str_dup(&pt->encoding), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			q = g_hash_table_lookup_queue_new(stripped, str_dup(&pt->encoding_with_full_params), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			q = g_hash_table_lookup_queue_new(stripped, str_dup(&pt->encoding_with_params), free);
			g_queue_push_tail(q, pt);
			continue;
		}

		__codec_options_set(call, pt, flags->codec_set);

		// codec masking
		if (__codec_ht_except(mask_all, flags->codec_mask, flags->codec_except, pt)) {
			ilogs(codec, LOG_DEBUG, "Masking codec '" STR_FORMAT "'",
					STR_FMT(&pt->encoding_with_params));
#ifdef WITH_TRANSCODING
			codec_touched(pt, media);
#endif
			// special case for handling of the legacy always-transcode flag (= accept-all)
			// in combination with codec-mask
			if (accept_all)
				pt->for_transcoding = 1;

			GQueue *q = g_hash_table_lookup_queue_new(masked, str_dup(&pt->encoding), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			q = g_hash_table_lookup_queue_new(masked, str_dup(&pt->encoding_with_full_params), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			q = g_hash_table_lookup_queue_new(masked, str_dup(&pt->encoding_with_params), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			__rtp_payload_type_add_send(other_media, pt);
		}
		else if (__codec_ht_except(consume_all, flags->codec_consume, flags->codec_except, pt)) {
			ilogs(codec, LOG_DEBUG, "Consuming codec '" STR_FORMAT "'",
					STR_FMT(&pt->encoding_with_params));
#ifdef WITH_TRANSCODING
			codec_touched(pt, media);
#endif
			pt->for_transcoding = 1;
			GQueue *q = g_hash_table_lookup_queue_new(masked, str_dup(&pt->encoding), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			q = g_hash_table_lookup_queue_new(masked, str_dup(&pt->encoding_with_full_params), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			q = g_hash_table_lookup_queue_new(masked, str_dup(&pt->encoding_with_params), free);
			g_queue_push_tail(q, __rtp_payload_type_copy(pt));
			__rtp_payload_type_add_send(other_media, pt);
		}
		else if (__codec_ht_except(accept_all, flags->codec_accept, NULL, pt)) {
			ilogs(codec, LOG_DEBUG, "Accepting codec '" STR_FORMAT "'",
					STR_FMT(&pt->encoding_with_params));
#ifdef WITH_TRANSCODING
			codec_touched(pt, media);
#endif
			pt->for_transcoding = 1;
			__rtp_payload_type_add(media, other_media, pt);
		}
		else
			__rtp_payload_type_add(media, other_media, pt);
	}

	// now restore codecs that have been removed, but should be offered
	for (GList *l = flags->codec_offer.head; l; l = l->next) {
		str *codec = l->data;
		__revert_codec_strip(stripped, masked, codec, media, other_media);
	}

	if (!flags->asymmetric_codecs) {
		// eliminate rejected codecs from the reverse direction. a rejected codec is missing
		// from the `send` list. also remove it from the `receive` list.
		for (GList *l = other_media->codecs_prefs_recv.head; l;) {
			pt = l->data;
			if (g_hash_table_lookup(other_media->codec_names_send, &pt->encoding)) {
				l = l->next;
				continue;
			}
			ilogs(codec, LOG_DEBUG, "Eliminating asymmetric inbound codec " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			l = __delete_receiver_codec(other_media, l);
		}
	}

#ifdef WITH_TRANSCODING
	__single_codec(media, flags);
#endif

#ifdef WITH_TRANSCODING
	// add transcode codecs
	for (GList *l = flags->codec_transcode.head; l; l = l->next) {
		str *codec = l->data;
		// if we wish to 'transcode' to a codec that was offered originally
		// and removed by a strip=all option,
		// simply restore it from the original list and handle it the same way
		// as 'offer'
		if ((strip_all == 1 || mask_all == 1)
				&& __revert_codec_strip(stripped, masked, codec, media, other_media))
			continue;
		// also check if maybe the codec was never stripped
		if (g_hash_table_lookup(media->codec_names_recv, codec)) {
			ilogs(codec, LOG_DEBUG, "Codec '" STR_FORMAT "' requested for transcoding is already present",
					STR_FMT(codec));
			continue;
		}

		// create new payload type
		pt = codec_add_payload_type(codec, media, other_media);
		if (!pt)
			continue;
		pt->for_transcoding = 1;
		codec_touched(pt, media);

		ilogs(codec, LOG_DEBUG, "Codec '" STR_FORMAT "' added for transcoding with payload type %u",
				STR_FMT(&pt->encoding_with_params), pt->payload_type);
		__rtp_payload_type_add_recv(media, pt, 1);
	}

	if (media->type_id == MT_AUDIO && other_media->type_id == MT_IMAGE) {
		if (media->codecs_prefs_recv.length == 0) {
			// find some codecs to put into our outgoing SDP body

			if (media->codecs_prefs_send.length && media->t38_gateway
					&& flags->opmode == OP_ANSWER)
			{
				// audio -> T.38 transcoder, answer:
				// we answer with the codec that we're sending audio with, taken from
				// our PCM player
				if (media->t38_gateway && media->t38_gateway->pcm_player
						&& media->t38_gateway->pcm_player->handler)
					__rtp_payload_type_add_recv(media,
							__rtp_payload_type_copy(&media->t38_gateway->pcm_player->handler->dest_pt), 1);
			}
			else if (flags->opmode == OP_OFFER) {
				// T.38 -> audio transcoder, initial offer, and no codecs have been given.
				// Default to PCMA and PCMU
				// XXX can we improve the codec lookup/synthesis?
				static const str PCMU_str = STR_CONST_INIT("PCMU");
				static const str PCMA_str = STR_CONST_INIT("PCMA");
				pt = codec_add_payload_type(&PCMU_str, media, NULL);
				assert(pt != NULL);
				__rtp_payload_type_add_recv(media, pt, 1);
				pt = codec_add_payload_type(&PCMA_str, media, NULL);
				assert(pt != NULL);
				__rtp_payload_type_add_recv(media, pt, 1);

				ilogs(codec, LOG_DEBUG, "Using default codecs PCMU and PCMA for T.38 gateway");
			}
		}
		else if (flags->opmode == OP_OFFER) {
			// re-invite - we remember some codecs from before, or perhaps they
			// were added manually through the transcoding options. make sure
			// they're all supported by us

			for (GList *l = media->codecs_prefs_recv.head; l;) {
				pt = l->data;
				ensure_codec_def(pt, media);
				if (pt->codec_def) {
					l = l->next;
					continue;
				}
				ilogs(codec, LOG_DEBUG, "Eliminating unsupported codec " STR_FORMAT,
						STR_FMT(&pt->encoding_with_params));
				codec_touched(pt, media);
				l = __delete_receiver_codec(media, l);
			}
		}
	}
#endif

	g_hash_table_destroy(stripped);
	g_hash_table_destroy(masked);
}

void codecs_init(void) {
#ifdef WITH_TRANSCODING
	// XXX not real queue timer - unify to simple timerthread
	timerthread_init(&codec_timers_thread, timerthread_queue_run);
	rtcp_timer_queue = timerthread_queue_new("rtcp_timer_queue", sizeof(*rtcp_timer_queue),
			&codec_timers_thread, NULL, __rtcp_timer_run, NULL, __rtcp_timer_free);
#endif
}
void codecs_cleanup(void) {
#ifdef WITH_TRANSCODING
	obj_put(&rtcp_timer_queue->ttq.tt_obj);
	timerthread_free(&codec_timers_thread);
#endif
}
void codec_timers_loop(void *p) {
#ifdef WITH_TRANSCODING
	//ilog(LOG_DEBUG, "codec_timers_loop");
	timerthread_run(&codec_timers_thread);
#endif
}
