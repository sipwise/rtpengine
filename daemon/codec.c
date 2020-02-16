#include "codec.h"
#include <glib.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <spandsp/telephony.h>
#include <spandsp/super_tone_rx.h>
#include <spandsp/logging.h>
#include <spandsp/dtmf.h>
#include "call.h"
#include "log.h"
#include "rtplib.h"
#include "codeclib.h"
#include "ssrc.h"
#include "rtcp.h"
#include "call_interfaces.h"
#include "dtmf.h"
#include "dtmflib.h"




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

	g_hash_table_remove(codecs, &pt->payload_type);
	g_hash_table_remove(codec_names, &pt->encoding);
	g_hash_table_remove(codec_names, &pt->encoding_with_params);

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


#include "resample.h"
#include "dtmf_rx_fillin.h"



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
	unsigned long ts_in; // for DTMF dupe detection
	struct timeval first_send;
	unsigned long first_send_ts;
	GString *sample_buffer;

	// DTMF DSP stuff
	dtmf_rx_state_t *dtmf_dsp;
	resample_t dtmf_resampler;
	format_t dtmf_format;
	uint64_t dtmf_ts, last_dtmf_event_ts;
	GQueue dtmf_events;
	struct dtmf_event dtmf_event;

	uint64_t skip_pts;

	int rtp_mark:1;
};
struct transcode_packet {
	seq_packet_t p; // must be first
	unsigned long ts;
	str *payload;
	struct codec_handler *handler;
	int marker:1,
	    ignore_seq:1;
	int (*func)(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *);
	int (*dup_func)(struct codec_ssrc_handler *, struct transcode_packet *, struct media_packet *);
	struct rtp_header rtp;
};


static codec_handler_func handler_func_passthrough_ssrc;
static codec_handler_func handler_func_transcode;
static codec_handler_func handler_func_playback;
static codec_handler_func handler_func_inject_dtmf;
static codec_handler_func handler_func_dtmf;

static struct ssrc_entry *__ssrc_handler_transcode_new(void *p);
static struct ssrc_entry *__ssrc_handler_new(void *p);
static void __free_ssrc_handler(void *);

static void __transcode_packet_free(struct transcode_packet *);


static struct codec_handler codec_handler_stub_ssrc = {
	.source_pt.payload_type = -1,
	.func = handler_func_passthrough_ssrc,
	.kernelize = 1,
};



static void __handler_shutdown(struct codec_handler *handler) {
	free_ssrc_hash(&handler->ssrc_hash);
	if (handler->ssrc_handler)
		obj_put(&handler->ssrc_handler->h);
	handler->ssrc_handler = NULL;
	handler->kernelize = 0;
	handler->transcoder = 0;
	handler->dtmf_scaler = 0;
	handler->output_handler = handler; // reset to default
	handler->dtmf_payload_type = -1;
	handler->pcm_dtmf_detect = 0;
}

static void __codec_handler_free(void *pp) {
	struct codec_handler *h = pp;
	__handler_shutdown(h);
	g_slice_free1(sizeof(*h), h);
}
void codec_handler_free(struct codec_handler *handler) {
	__codec_handler_free(handler);
}

static struct codec_handler *__handler_new(struct rtp_payload_type *pt) {
	struct codec_handler *handler = g_slice_alloc0(sizeof(*handler));
	handler->source_pt = *pt;
	handler->output_handler = handler; // default
	handler->dtmf_payload_type = -1;
	return handler;
}

static void __make_passthrough(struct codec_handler *handler) {
	__handler_shutdown(handler);
	ilog(LOG_DEBUG, "Using passthrough handler for " STR_FORMAT,
			STR_FMT(&handler->source_pt.encoding_with_params));
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;
	else {
		handler->func = handler_func_passthrough;
		handler->kernelize = 1;
	}
	handler->dest_pt = handler->source_pt;
	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, handler);
}
static void __make_passthrough_ssrc(struct codec_handler *handler) {
	__handler_shutdown(handler);
	ilog(LOG_DEBUG, "Using passthrough handler with new SSRC for " STR_FORMAT,
			STR_FMT(&handler->source_pt.encoding_with_params));
	if (handler->source_pt.codec_def && handler->source_pt.codec_def->dtmf)
		handler->func = handler_func_dtmf;
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

	ilog(LOG_DEBUG, "Leaving transcode context for " STR_FORMAT " -> " STR_FORMAT " intact",
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
		ilog(LOG_DEBUG, "Created DTMF transcode context for " STR_FORMAT " -> PT %i",
				STR_FMT(&handler->source_pt.encoding_with_params),
				dtmf_payload_type);
		handler->dtmf_scaler = 1;
	}
	else
		ilog(LOG_DEBUG, "Created transcode context for " STR_FORMAT " -> " STR_FORMAT
			" with DTMF output %i",
				STR_FMT(&handler->source_pt.encoding_with_params),
				STR_FMT(&dest->encoding_with_params), dtmf_payload_type);

	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_transcode_new, handler);

check_output:;
	// check if we have multiple decoders transcoding to the same output PT
	struct codec_handler *output_handler = g_hash_table_lookup(output_transcoders,
			GINT_TO_POINTER(dest->payload_type));
	if (output_handler) {
		ilog(LOG_DEBUG, "Using existing encoder context");
		handler->output_handler = output_handler;
	}
	else {
		g_hash_table_insert(output_transcoders, GINT_TO_POINTER(dest->payload_type), handler);
		handler->output_handler = handler; // make sure we don't have a stale pointer
	}
}

struct codec_handler *codec_handler_make_playback(struct rtp_payload_type *src_pt,
		struct rtp_payload_type *dst_pt, unsigned long last_ts)
{
	struct codec_handler *handler = __handler_new(src_pt);
	handler->dest_pt = *dst_pt;
	handler->func = handler_func_playback;
	handler->ssrc_handler = (void *) __ssrc_handler_transcode_new(handler);
	handler->ssrc_handler->first_ts = last_ts;
	while (handler->ssrc_handler->first_ts == 0)
		handler->ssrc_handler->first_ts = random();
	handler->ssrc_handler->rtp_mark = 1;

	ilog(LOG_DEBUG, "Created media playback context for " STR_FORMAT " -> " STR_FORMAT "",
			STR_FMT(&src_pt->encoding_with_params),
			STR_FMT(&dst_pt->encoding_with_params));

	return handler;
}

static void __ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media) {
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

		ilog(LOG_DEBUG, "Shutting down DTMF DSP for '" STR_FORMAT "' -> %i (not needed)",
				STR_FMT(&handler->source_pt.encoding_with_params),
				payload_type);
		handler->dtmf_payload_type = -1;
	}
}


static struct rtp_payload_type *__check_dest_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, GHashTable *dtmf_sinks, int *sink_transcoding)
{
	struct rtp_payload_type *pref_dest_codec = NULL;

	for (GList *l = sink->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		__ensure_codec_def(pt, sink);
		if (!pt->codec_def) // not supported, next
			continue;

		// fix up ptime
		if (!pt->ptime)
			pt->ptime = pt->codec_def->default_ptime;
		if (sink->ptime)
			pt->ptime = sink->ptime;

		if (!pref_dest_codec && !pt->codec_def->supplemental) {
			ilog(LOG_DEBUG, "Default sink codec is " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
			pref_dest_codec = pt;
		}

		// also check if this is a transcoding codec: if we can send a codec to the sink,
		// but can't receive it on the receiver side, then it's transcoding. this is to check
		// whether transcoding on the sink side is actually needed. if transcoding has been
		// previously enabled on the sink, but no transcoding codecs are actually present,
		// we can disable the transcoding engine.
		if (MEDIA_ISSET(sink, TRANSCODE)) {
			struct rtp_payload_type *recv_pt = g_hash_table_lookup(receiver->codecs_send,
					&pt->payload_type);
			if (!recv_pt || rtp_payload_type_cmp(pt, recv_pt)) {
				*sink_transcoding = 1;
				// can the sink receive RFC DTMF but the receiver can't send it?
				if (pt->codec_def && pt->codec_def->dtmf) {
					if (!g_hash_table_lookup(dtmf_sinks, GUINT_TO_POINTER(pt->clock_rate)))
						g_hash_table_insert(dtmf_sinks, GUINT_TO_POINTER(pt->clock_rate),
								pt);
				}
			}
		}
		else if (flags && (flags->always_transcode || flags->inject_dtmf)) {
			// with always-transcode, we must keep track of potential output DTMF payload
			// types as well
			if (pt->codec_def && pt->codec_def->dtmf) {
				if (!g_hash_table_lookup(dtmf_sinks, GUINT_TO_POINTER(pt->clock_rate)))
					g_hash_table_insert(dtmf_sinks, GUINT_TO_POINTER(pt->clock_rate),
							pt);
			}
		}
	}

	return pref_dest_codec;
}

static void __check_send_codecs(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags, GHashTable *dtmf_sinks, int *sink_transcoding)
{
	if (!MEDIA_ISSET(sink, TRANSCODE))
		return;

	for (GList *l = sink->codecs_prefs_recv.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		struct rtp_payload_type *recv_pt = g_hash_table_lookup(receiver->codecs_send,
				&pt->payload_type);
		if (!recv_pt || rtp_payload_type_cmp(pt, recv_pt) || (flags && flags->inject_dtmf)) {
			*sink_transcoding = 1;
			// can the sink receive RFC DTMF but the receiver can't send it?
			if (pt->codec_def && pt->codec_def->dtmf) {
				if (!g_hash_table_lookup(dtmf_sinks, GUINT_TO_POINTER(pt->clock_rate)))
					g_hash_table_insert(dtmf_sinks, GUINT_TO_POINTER(pt->clock_rate),
							pt);
			}
			continue;
		}

		// even if the receiver can receive the same codec that the sink can
		// send, we might still have it configured as a transcoder due to
		// always-transcode in the offer
		// XXX codec_handlers can be converted to g_direct_hash table
		struct codec_handler *ch_recv =
			g_hash_table_lookup(sink->codec_handlers, &recv_pt->payload_type);
		if (!ch_recv)
			continue;
		if (ch_recv->transcoder) {
			*sink_transcoding = 1;
			break;
		}
	}
}

static int __dtmf_payload_type(GHashTable *dtmf_sinks, struct rtp_payload_type *pref_dest_codec) {
	if (!g_hash_table_size(dtmf_sinks) || !pref_dest_codec)
		return -1;

	int dtmf_payload_type = -1;

	// find the telephone-event codec entry with a matching clock rate
	struct rtp_payload_type *pt = g_hash_table_lookup(dtmf_sinks,
			GUINT_TO_POINTER(pref_dest_codec->clock_rate));
	if (!pt)
		ilog(LOG_INFO, "Not transcoding PCM DTMF tones to telephone-event packets as "
				"no payload type with a matching clock rate for '" STR_FORMAT
				"' was found", STR_FMT(&pref_dest_codec->encoding_with_params));
	else {
		dtmf_payload_type = pt->payload_type;
		ilog(LOG_DEBUG, "Output DTMF payload type is %i", dtmf_payload_type);
	}

	return dtmf_payload_type;
}

static void __accept_transcode_codecs(struct call_media *receiver, struct call_media *sink) {
	// if the other side is transcoding, we need to accept codecs that were
	// originally offered (recv->send) if we support them, even if the
	// response (sink->send) doesn't include them
	GList *insert_pos = NULL;
	for (GList *l = receiver->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		__ensure_codec_def(pt, receiver);
		if (!pt->codec_def)
			continue;
		if (g_hash_table_lookup(receiver->codecs_recv, &pt->payload_type)) {
			// already present.
			// to keep the order intact, we seek the list for the position
			// of this codec entry. all newly added codecs must come after
			// this entry.
			if (!insert_pos)
				insert_pos = receiver->codecs_prefs_recv.head;
			while (insert_pos) {
				if (!insert_pos->next)
					break; // end of list - we insert everything after
				struct rtp_payload_type *test_pt = insert_pos->data;
				if (test_pt->payload_type == pt->payload_type)
					break;
				insert_pos = insert_pos->next;
			}
			continue;
		}

		ilog(LOG_DEBUG, "Accepting offered codec " STR_FORMAT " due to transcoding",
				STR_FMT(&pt->encoding_with_params));
		MEDIA_SET(receiver, TRANSCODE);

		// we need a new pt entry
		pt = __rtp_payload_type_copy(pt);
		// this somewhat duplicates __rtp_payload_type_add_recv
		g_hash_table_insert(receiver->codecs_recv, &pt->payload_type, pt);
		__rtp_payload_type_add_name(receiver->codec_names_recv, pt);
		if (!insert_pos) {
			g_queue_push_head(&receiver->codecs_prefs_recv, pt);
			insert_pos = receiver->codecs_prefs_recv.head;
		}
		else {
			g_queue_insert_after(&receiver->codecs_prefs_recv, insert_pos, pt);
			insert_pos = insert_pos->next;
		}
	}
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
		ilog(LOG_DEBUG, "Eliminating asymmetric outbound codec " STR_FORMAT,
				STR_FMT(&pt->encoding_with_params));
		l = __delete_send_codec(receiver, l);
	}
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
	const str tp_event = STR_CONST_INIT("telephone-event");
	src_pt.codec_def = codec_find(&tp_event, MT_AUDIO);
	if (!src_pt.codec_def) {
		ilog(LOG_ERR, "RTP payload type 'telephone-event' is not defined");
		return;
	}

	//receiver->dtmf_injector = codec_handler_make_playback(&src_pt, pref_dest_codec, 0);
	//receiver->dtmf_injector->dtmf_payload_type = dtmf_payload_type;
	receiver->dtmf_injector = __handler_new(&src_pt);
	__make_transcoder(receiver->dtmf_injector, pref_dest_codec, output_transcoders, dtmf_payload_type, 0);
	receiver->dtmf_injector->func = handler_func_inject_dtmf;
	g_queue_push_tail(&receiver->codec_handlers_store, receiver->dtmf_injector);
}

// call must be locked in W
void codec_handlers_update(struct call_media *receiver, struct call_media *sink,
		const struct sdp_ng_flags *flags)
{
	if (!receiver->codec_handlers)
		receiver->codec_handlers = g_hash_table_new(g_int_hash, g_int_equal);

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
	int sink_transcoding = 0;
	// keep track of telephone-event payload types. we hash them by clock rate
	// in case there's several of them. the clock rates of the destination
	// codec and the telephone-event codec must match.
	GHashTable *dtmf_sinks = g_hash_table_new(g_direct_hash, g_direct_equal);

	pref_dest_codec = __check_dest_codecs(receiver, sink, flags, dtmf_sinks, &sink_transcoding);

	// similarly, if the sink can receive a codec that the receiver can't send, it's also transcoding
	__check_send_codecs(receiver, sink, flags, dtmf_sinks, &sink_transcoding);

	ilog(LOG_DEBUG, "%i DTMF sink entries", g_hash_table_size(dtmf_sinks));
	int dtmf_payload_type = __dtmf_payload_type(dtmf_sinks, pref_dest_codec);

	g_hash_table_destroy(dtmf_sinks);

	// stop transcoding if we've determined that we don't need it
	if (MEDIA_ISSET(sink, TRANSCODE) && !sink_transcoding) {
		ilog(LOG_DEBUG, "Disabling transcoding engine (not needed)");
		MEDIA_CLEAR(sink, TRANSCODE);
	}

	if (MEDIA_ISSET(sink, TRANSCODE))
		__accept_transcode_codecs(receiver, sink);
	else
		__eliminate_rejected_codecs(receiver, sink, flags);

	// if multiple input codecs transcode to the same output codec, we want to make sure
	// that all the decoders output their media to the same encoder. we use the destination
	// payload type to keep track of this.
	GHashTable *output_transcoders = g_hash_table_new(g_direct_hash, g_direct_equal);

	int transcode_dtmf = 0; // is one of our destination codecs DTMF?

	// do we need to detect PCM DTMF tones?
	int pcm_dtmf_detect = 0;
	if ((MEDIA_ISSET(sink, TRANSCODE) || (flags && flags->always_transcode))
			&& dtmf_payload_type != -1
			&& !g_hash_table_lookup(receiver->codecs_send, &dtmf_payload_type))
		pcm_dtmf_detect = 1;


	for (GList *l = receiver->codecs_prefs_recv.head; l; ) {
		struct rtp_payload_type *pt = l->data;

		if (MEDIA_ISSET(sink, TRANSCODE)) {
			// if the other side is transcoding, we may come across a receiver entry
			// (recv->recv) that wasn't originally offered (recv->send). we must eliminate
			// those
			if (!g_hash_table_lookup(receiver->codecs_send, &pt->payload_type)) {
				ilog(LOG_DEBUG, "Eliminating transcoded codec " STR_FORMAT,
						STR_FMT(&pt->encoding_with_params));

				l = __delete_receiver_codec(receiver, l);
				continue;
			}
		}

		// first, make sure we have a codec_handler struct for this
		__ensure_codec_def(pt, receiver);
		struct codec_handler *handler;
		handler = g_hash_table_lookup(receiver->codec_handlers, &pt->payload_type);
		if (handler) {
			// make sure existing handler matches this PT
			if (rtp_payload_type_cmp(pt, &handler->source_pt)) {
				ilog(LOG_DEBUG, "Resetting codec handler for PT %u", pt->payload_type);
				handler = NULL;
				g_atomic_pointer_set(&receiver->codec_handler_cache, NULL);
				g_hash_table_remove(receiver->codec_handlers, &pt->payload_type);
			}
		}
		if (!handler) {
			ilog(LOG_DEBUG, "Creating codec handler for " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			handler = __handler_new(pt);
			g_hash_table_insert(receiver->codec_handlers, &handler->source_pt.payload_type,
					handler);
			g_queue_push_tail(&receiver->codec_handlers_store, handler);
		}

		// check our own support for this codec
		if (!pt->codec_def) {
			// not supported
			__make_passthrough_gsl(handler, &passthrough_handlers);
			goto next;
		}

		// figure out our ptime
		if (!pt->ptime)
			pt->ptime = pt->codec_def->default_ptime;
		if (receiver->ptime)
			pt->ptime = receiver->ptime;

		// if the sink's codec preferences are unknown (empty), or there are
		// no supported codecs to transcode to, then we have nothing
		// to do. most likely this is an initial offer without a received answer.
		// we default to forwarding without transcoding.
		if (!pref_dest_codec) {
			ilog(LOG_DEBUG, "No known/supported sink codec for " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			__make_passthrough_gsl(handler, &passthrough_handlers);
			goto next;
		}

		struct rtp_payload_type *dest_pt; // transcode to this

		GQueue *dest_codecs = NULL;
		if (!flags || !flags->always_transcode) {
			// we ignore output codec matches if we must transcode DTMF
			if (dtmf_payload_type != -1)
				;
			else if (flags && flags->inject_dtmf)
				;
			else
				dest_codecs = g_hash_table_lookup(sink->codec_names_send, &pt->encoding);
		}
		else if (flags->always_transcode) {
			// with always-transcode, we still accept DTMF payloads if possible
			if (pt->codec_def && pt->codec_def->supplemental)
				dest_codecs = g_hash_table_lookup(sink->codec_names_send, &pt->encoding);
		}
		if (dest_codecs) {
			// the sink supports this codec - check offered formats
			dest_pt = NULL;
			for (GList *k = dest_codecs->head; k; k = k->next) {
				unsigned int dest_ptype = GPOINTER_TO_UINT(k->data);
				dest_pt = g_hash_table_lookup(sink->codecs_send, &dest_ptype);
				if (!dest_pt)
					continue;
				// XXX match up format parameters
				break;
			}

			if (!dest_pt)
				goto unsupported;

			// in case of ptime mismatch, we transcode, but between the same codecs
			if (dest_pt->ptime && pt->ptime
					&& dest_pt->ptime != pt->ptime)
			{
				ilog(LOG_DEBUG, "Mismatched ptime between source and sink (%i <> %i), "
						"enabling transcoding",
					dest_pt->ptime, pt->ptime);
				goto transcode;
			}

			// XXX check format parameters as well
			ilog(LOG_DEBUG, "Sink supports codec " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
			__make_passthrough_gsl(handler, &passthrough_handlers);
			if (pt->codec_def && pt->codec_def->dtmf)
				__dtmf_dsp_shutdown(sink, pt->payload_type);
			goto next;
		}

unsupported:
		// the sink does not support this codec -> transcode
		ilog(LOG_DEBUG, "Sink does not support codec " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
		dest_pt = pref_dest_codec;
		if (pt->codec_def->dtmf)
			transcode_dtmf = 1;
transcode:;
		// look up the reverse side of this payload type, which is the decoder to our
		// encoder. if any codec options such as bitrate were set during an offer,
		// they're in the decoder // PT. copy them to the encoder PT.
		struct rtp_payload_type *reverse_pt = g_hash_table_lookup(sink->codecs_recv,
				&dest_pt->payload_type);
		if (reverse_pt) {
			if (!dest_pt->bitrate)
				dest_pt->bitrate = reverse_pt->bitrate;
		}
		MEDIA_SET(receiver, TRANSCODE);
		__make_transcoder(handler, dest_pt, output_transcoders, dtmf_payload_type, pcm_dtmf_detect);

next:
		l = l->next;
	}

	// if we've determined that we transcode, we must remove all unsupported codecs from
	// the list, as we must expect to potentially receive media in that codec, which we
	// then could not transcode.
	if (MEDIA_ISSET(receiver, TRANSCODE)) {
		ilog(LOG_INFO, "Enabling transcoding engine");

		for (GList *l = receiver->codecs_prefs_recv.head; l; ) {
			struct rtp_payload_type *pt = l->data;

			if (pt->codec_def) {
				// supported
				l = l->next;
				continue;
			}

			ilog(LOG_DEBUG, "Stripping unsupported codec " STR_FORMAT " due to active transcoding",
					STR_FMT(&pt->encoding));
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
			if ((!transcode_dtmf && dtmf_payload_type == -1) || !pref_dest_codec
					|| !handler->source_pt.codec_def || !pref_dest_codec->codec_def)
				__make_passthrough_ssrc(handler);
			else
				__make_transcoder(handler, pref_dest_codec, output_transcoders,
						dtmf_payload_type, pcm_dtmf_detect);
			passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);

		}
	}
	while (passthrough_handlers) {
		passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);
	}

	g_hash_table_destroy(output_transcoders);
}



#endif


// call must be locked in R
struct codec_handler *codec_handler_get(struct call_media *m, int payload_type) {
#ifdef WITH_TRANSCODING
	struct codec_handler *h;

	if (payload_type < 0)
		goto out;

	h = g_atomic_pointer_get(&m->codec_handler_cache);
	if (G_LIKELY(G_LIKELY(h) && G_LIKELY(h->source_pt.payload_type == payload_type)))
		return h;

	if (G_UNLIKELY(!m->codec_handlers))
		goto out;
	h = g_hash_table_lookup(m->codec_handlers, &payload_type);
	if (!h)
		goto out;

	g_atomic_pointer_set(&m->codec_handler_cache, h);

	return h;

out:
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
	if (mp->rtp && mp->ssrc_out)
		payload_tracker_add(&mp->ssrc_out->tracker, mp->rtp->m_pt & 0x7f);
	g_queue_push_tail(&mp->packets_out, p);
}
static int handler_func_passthrough(struct codec_handler *h, struct media_packet *mp) {
	if (mp->call->block_media || mp->media->monologue->block_media)
		return 0;

	codec_add_raw_packet(mp);
	return 0;
}

#ifdef WITH_TRANSCODING
static int __handler_func_sequencer(struct media_packet *mp, struct transcode_packet *packet)
{
	struct codec_handler *h = packet->handler;

	if (G_UNLIKELY(!h->ssrc_hash)) {
		if (!packet->func || !packet->handler || !packet->handler->ssrc_hash) {
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
	packet->ts = ntohl(mp->rtp->timestamp);
	packet->marker = (mp->rtp->m_pt & 0x80) ? 1 : 0;

	// how should we retrieve packets from the sequencer?
	void *(*seq_next_packet)(packet_sequencer_t *) = packet_sequencer_next_packet;
	if (packet->ignore_seq)
		seq_next_packet = packet_sequencer_force_next_packet;

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

	packet_sequencer_init(&ssrc_in_p->sequencer, (GDestroyNotify) __transcode_packet_free);

	u_int16_t seq_ori = ssrc_in_p->sequencer.seq;
	int seq_ret = packet_sequencer_insert(&ssrc_in_p->sequencer, &packet->p);
	if (seq_ret < 0) {
		// dupe
		if (packet->dup_func)
			packet->dup_func(ch, packet, mp);
		else
			ilog(LOG_DEBUG, "Ignoring duplicate RTP packet");
		__transcode_packet_free(packet);
		atomic64_inc(&ssrc_in->duplicates);
		goto out;
	}

	// got a new packet, run decoder

	while (1) {
		packet = seq_next_packet(&ssrc_in_p->sequencer);
		if (G_UNLIKELY(!packet))
			break;

		h = packet->handler;
		obj_put(&ch->h);
		ch = get_ssrc(ssrc_in_p->h.ssrc, h->ssrc_hash);
		if (G_UNLIKELY(!ch))
			goto next;

		atomic64_set(&ssrc_in->packets_lost, ssrc_in_p->sequencer.lost_count);
		atomic64_set(&ssrc_in->last_seq, ssrc_in_p->sequencer.ext_seq);

		ilog(LOG_DEBUG, "Decoding RTP packet: seq %u, TS %lu",
				packet->p.seq, packet->ts);

		if (seq_ret == 1) {
			// seq reset - update output seq. we keep our output seq clean
			ssrc_out_p->seq_diff -= packet->p.seq - seq_ori;
			seq_ret = 0;
		}

		// we might be working with a different packet now
		mp->rtp = &packet->rtp;

		if (packet->func(ch, packet, mp))
			ilog(LOG_WARN, "Decoder error while processing RTP packet");
next:
		__transcode_packet_free(packet);
	}

out:
	mutex_unlock(&ssrc_in_p->h.lock);
	if (ssrc_in_p != ssrc_out_p)
		mutex_unlock(&ssrc_out_p->h.lock);
	obj_put(&ch->h);

	return 0;
}

static void __output_rtp(struct media_packet *mp, struct codec_ssrc_handler *ch,
		struct codec_handler *handler, // normally == ch->handler except for DTMF
		char *buf, // malloc'd, room for rtp_header + filled-in payload
		unsigned int payload_len,
		unsigned long payload_ts,
		int marker, int seq, int seq_inc, int payload_type)
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

	// this packet is dynamically allocated, so we're able to schedule it.
	// determine scheduled time to send
	if (ch->first_send.tv_sec && ch->encoder_format.clockrate) {
		// scale first_send from first_send_ts to ts
		p->ttq_entry.when = ch->first_send;
		uint32_t ts_diff = (uint32_t) ts - (uint32_t) ch->first_send_ts; // allow for wrap-around
		unsigned long long ts_diff_us =
			(unsigned long long) ts_diff * 1000000 / ch->encoder_format.clockrate
			* ch->handler->dest_pt.codec_def->clockrate_mult;
		timeval_add_usec(&p->ttq_entry.when, ts_diff_us);

		// how far in the future is this?
		ts_diff_us = timeval_diff(&p->ttq_entry.when, &rtpe_now); // negative wrap-around to positive OK

		if (ts_diff_us > 1000000) // more than one second, can't be right
			ch->first_send.tv_sec = 0; // fix it up below
	}
	if (!ch->first_send.tv_sec) {
		p->ttq_entry.when = ch->first_send = rtpe_now;
		ch->first_send_ts = ts;
	}
	ilog(LOG_DEBUG, "Scheduling to send RTP packet (seq %u TS %lu) at %lu.%06lu",
			ntohs(rh->seq_num),
			ts,
			(long unsigned) p->ttq_entry.when.tv_sec,
			(long unsigned) p->ttq_entry.when.tv_usec);

	g_queue_push_tail(&mp->packets_out, p);

	atomic64_inc(&ssrc_out->packets);
	atomic64_add(&ssrc_out->octets, payload_len);
	atomic64_set(&ssrc_out->last_ts, ts);
}

// returns new reference
static struct codec_ssrc_handler *__output_ssrc_handler(struct codec_ssrc_handler *ch, struct media_packet *mp) {
	struct codec_handler *handler = ch->handler;
	if (handler->output_handler == handler) {
		obj_get(&ch->h);
		return ch;
	}

	// our encoder is in a different codec handler
	ilog(LOG_DEBUG, "Switching context from decoder to encoder");
	handler = handler->output_handler;
	struct codec_ssrc_handler *new_ch = get_ssrc(mp->ssrc_in->parent->h.ssrc, handler->ssrc_hash);
	if (G_UNLIKELY(!new_ch)) {
		ilog(LOG_ERR, "Switched from input to output codec context, but no codec handler present");
		obj_get(&ch->h);
		return ch;
	}

	return new_ch;
}

static void packet_dtmf_fwd(struct codec_ssrc_handler *ch, struct transcode_packet *packet,
		struct media_packet *mp, int seq_inc)
{
	int payload_type = -1; // take from handler's output config

	if (ch->handler->dtmf_scaler) {
		// this is actually a DTMF -> PCM handler
		// grab our underlying PCM transcoder
		struct codec_ssrc_handler *output_ch = __output_ssrc_handler(ch, mp);
		if (G_UNLIKELY(!ch->encoder))
			goto skip;

		// init some vars
		if (!ch->first_ts)
			ch->first_ts = output_ch->first_ts;

		// the correct output TS is the encoder's FIFO PTS at the start of the DTMF
		// event. however, we must shift the FIFO PTS forward as the DTMF event goes on
		// as the DTMF event replaces the audio samples. therefore we must remember
		// the TS at the start of the event and the last seen event duration.
		if (ch->dtmf_ts != packet->ts) {
			// this is a new event
			ch->dtmf_ts = packet->ts; // start TS
			ch->last_dtmf_event_ts = 0; // last shifted FIFO PTS
		}

		unsigned long ts = output_ch->encoder->fifo_pts;
		// roll back TS to start of event
		ts -= ch->last_dtmf_event_ts;
		// adjust to output RTP TS
		unsigned long packet_ts = ts + output_ch->first_ts;

		ilog(LOG_DEBUG, "Scaling DTMF packet timestamp and duration: TS %lu -> %lu "
				"(%u -> %u)",
				packet->ts, packet_ts,
				ch->handler->source_pt.clock_rate, ch->handler->dest_pt.clock_rate);
		packet->ts = packet_ts;

		if (packet->payload->len >= sizeof(struct telephone_event_payload)) {
			struct telephone_event_payload *dtmf = (void *) packet->payload->s;
			unsigned int duration = av_rescale(ntohs(dtmf->duration),
					ch->handler->dest_pt.clock_rate, ch->handler->source_pt.clock_rate);
			dtmf->duration = htons(duration);

			// shift forward our output RTP TS
			output_ch->encoder->fifo_pts = ts + duration;
			ch->last_dtmf_event_ts = duration;
		}
		payload_type = ch->handler->dtmf_payload_type;
		obj_put(&output_ch->h);
	}

skip:;
	char *buf = malloc(packet->payload->len + sizeof(struct rtp_header) + RTP_BUFFER_TAIL_ROOM);
	memcpy(buf + sizeof(struct rtp_header), packet->payload->s, packet->payload->len);
	if (packet->ignore_seq) // inject original seq
		__output_rtp(mp, ch, packet->handler ? : ch->handler, buf, packet->payload->len, packet->ts,
				packet->marker, packet->p.seq, -1, payload_type);
	else // use our own sequencing
		__output_rtp(mp, ch, packet->handler ? : ch->handler, buf, packet->payload->len, packet->ts,
				packet->marker, -1, seq_inc, payload_type);
}
static int packet_dtmf(struct codec_ssrc_handler *ch, struct transcode_packet *packet, struct media_packet *mp)
{
	if (ch->ts_in != packet->ts) { // ignore already processed events
		int ret = dtmf_event(mp, packet->payload, ch->encoder_format.clockrate);
		if (G_UNLIKELY(ret == -1)) // error
			return -1;
		if (ret == 1) {
			// END event
			ch->ts_in = packet->ts;
		}
	}

	if (!mp->call->block_dtmf && !mp->media->monologue->block_dtmf)
		packet_dtmf_fwd(ch, packet, mp, 0);
	return 0;
}
static int packet_dtmf_dup(struct codec_ssrc_handler *ch, struct transcode_packet *packet,
		struct media_packet *mp)
{
	if (!mp->call->block_dtmf && !mp->media->monologue->block_dtmf)
		packet_dtmf_fwd(ch, packet, mp, 0);
	return 0;
}

static int handler_func_dtmf(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);

	assert((mp->rtp->m_pt & 0x7f) == h->source_pt.payload_type);

	// create new packet and insert it into sequencer queue

	ilog(LOG_DEBUG, "Received DTMF RTP packet: SSRC %" PRIx32 ", PT %u, seq %u, TS %u, len %i",
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

	// determine the primary audio codec used by this SSRC, as the sequence numbers
	// and timing info is shared with it. we'll need to use the same sequencer

	struct codec_handler *sequencer_h = h; // handler that contains the appropriate sequencer
	if (mp->ssrc_in) {
		for (int i = 0; i < mp->ssrc_in->tracker.most_len; i++) {
			int prim_pt = mp->ssrc_in->tracker.most[i];
			if (prim_pt == 255)
				continue;

			sequencer_h = codec_handler_get(mp->media, prim_pt);
			if (sequencer_h == h)
				continue;
			ilog(LOG_DEBUG, "Primary RTP payload type for handling DTMF event is %i", prim_pt);
			break;
		}
	}

	struct transcode_packet *packet = g_slice_alloc0(sizeof(*packet));
	packet->func = packet_dtmf;
	packet->dup_func = packet_dtmf_dup;
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
#endif



void codec_packet_free(void *pp) {
	struct codec_packet *p = pp;
	if (p->free_func)
		p->free_func(p->s.s);
	g_slice_free1(sizeof(*p), p);
}

str *codec_print_payload_type(const struct rtp_payload_type* pt) {
	return str_sprintf(
		"%s/" /* encoding */
		"%u/" /* clock_rate */
		"%i/" /* channels */
		"%i/" /* bitrate (opts) */
		"%i/" /* ptime (extra_opts) */
		"%s/" /* format_parameters(fmt_params) */
			/* the last part must end with '/', otherwise codec_make_payload_type won't read it*/
		,pt->encoding.s, pt->clock_rate, pt->channels, pt->bitrate, pt->ptime, pt->format_parameters.s);
}

struct rtp_payload_type *codec_make_payload_type(const str *codec_str, struct call_media *media) {
	str codec_fmt = *codec_str;
	str codec, parms, chans, opts, extra_opts, fmt_params;
	if (str_token_sep(&codec, &codec_fmt, '/'))
		return NULL;
	str_token_sep(&parms, &codec_fmt, '/');
	str_token_sep(&chans, &codec_fmt, '/');
	str_token_sep(&opts, &codec_fmt, '/');
	str_token_sep(&extra_opts, &codec_fmt, '/');
	str_token_sep(&fmt_params, &codec_fmt, '/');

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
	char params[32] = "";

	if (ret->channels > 1) {
		snprintf(full_encoding, sizeof(full_encoding), STR_FORMAT "/%u/%i", STR_FMT(&ret->encoding),
				ret->clock_rate,
				ret->channels);
		snprintf(params, sizeof(params), "%i", ret->channels);
	}
	else
		snprintf(full_encoding, sizeof(full_encoding), STR_FORMAT "/%u", STR_FMT(&ret->encoding),
				ret->clock_rate);

	str_init(&ret->encoding_with_params, full_encoding);
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
	ilog(LOG_DEBUG, "DTMF event state change: code %i, volume %i, TS %lu",
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
	ilog(LOG_DEBUG, "Skipping next %" PRIu64 " samples", pts);
	ch->skip_pts += pts;
}

uint64_t codec_decoder_unskip_pts(struct codec_ssrc_handler *ch) {
	uint64_t prev = ch->skip_pts;
	ilog(LOG_DEBUG, "Un-skipping next %" PRIu64 " samples", prev);
	ch->skip_pts = 0;
	return prev;
}

static struct ssrc_entry *__ssrc_handler_transcode_new(void *p) {
	struct codec_handler *h = p;

	if (h->dtmf_scaler)
		ilog(LOG_DEBUG, "Creating SSRC DTMF transcoder from %s/%u/%i to "
				"PT %i",
				h->source_pt.codec_def->rtpname, h->source_pt.clock_rate,
				h->source_pt.channels,
				h->dtmf_payload_type);
	else
		ilog(LOG_DEBUG, "Creating SSRC transcoder from %s/%u/%i to "
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
				&enc_format, &ch->encoder_format, &h->dest_pt.format_parameters))
		goto err;

	if (h->pcm_dtmf_detect) {
		ilog(LOG_DEBUG, "Inserting DTMF DSP for output payload type %i", h->dtmf_payload_type);
		ch->dtmf_format = (format_t) { .clockrate = 8000, .channels = 1, .format = AV_SAMPLE_FMT_S16 };
		ch->dtmf_dsp = dtmf_rx_init(NULL, NULL, NULL);
		if (!ch->dtmf_dsp)
			ilog(LOG_ERR, "Failed to allocate DTMF RX context");
		else
			dtmf_rx_set_realtime_callback(ch->dtmf_dsp, __dtmf_dsp_callback, ch);
	}

	ch->decoder = decoder_new_fmtp(h->source_pt.codec_def, h->source_pt.clock_rate, h->source_pt.channels,
			h->source_pt.ptime,
			&ch->encoder_format, &h->source_pt.format_parameters);
	if (!ch->decoder)
		goto err;

	ch->bytes_per_packet = (ch->encoder->samples_per_packet ? : ch->encoder->samples_per_frame)
		* h->dest_pt.codec_def->bits_per_sample / 8;

	ilog(LOG_DEBUG, "Encoder created with clockrate %i, %i channels, using sample format %i "
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
	ilog(LOG_DEBUG, "__free_ssrc_handler");
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
}

static int __packet_encoded(encoder_t *enc, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;
	//unsigned int seq_off = (mp->iter_out > mp->iter_in) ? 1 : 0;

	ilog(LOG_DEBUG, "RTP media successfully encoded: TS %llu, len %i",
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
			ilog(LOG_DEBUG, "Adding %i bytes to packetizer", in_pkt->size);
		int ret = ch->handler->dest_pt.codec_def->packetizer(in_pkt,
				ch->sample_buffer, &inout, enc);

		if (G_UNLIKELY(ret == -1 || enc->avpkt.pts == AV_NOPTS_VALUE)) {
			// nothing
			free(buf);
			break;
		}

		ilog(LOG_DEBUG, "Received packet of %i bytes from packetizer", inout.len);

		unsigned int repeats = 0;
		int is_dtmf = dtmf_event_payload(&inout, (uint64_t *) &enc->avpkt.pts, enc->avpkt.duration,
				&ch->dtmf_event, &ch->dtmf_events);
		if (is_dtmf == 1)
			ch->rtp_mark = 1; // DTMF start event
		else if (is_dtmf == 3)
			repeats = 2; // DTMF end event

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
					is_dtmf ? ch->handler->dtmf_payload_type : -1);
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
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Failed to resample audio for DTMF DSP");
		return;
	}

	ilog(LOG_DEBUG, "DTMF detect, TS %lu -> %lu, %u -> %u samples",
			(unsigned long) frame->pts,
			(unsigned long) dsp_frame->pts,
			frame->nb_samples,
			dsp_frame->nb_samples);

	if (dsp_frame->pts > ch->dtmf_ts)
		dtmf_rx_fillin(ch->dtmf_dsp, dsp_frame->pts - ch->dtmf_ts);
	else if (dsp_frame->pts < ch->dtmf_ts)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "DTMF TS seems to run backwards (%lu < %lu)",
				(unsigned long) dsp_frame->pts,
				(unsigned long) ch->dtmf_ts);

	int num_samples = dsp_frame->nb_samples;
	int16_t *samples = (void *) dsp_frame->extended_data[0];
	while (num_samples > 0) {
		int ret = dtmf_rx(ch->dtmf_dsp, samples, num_samples);
		if (ret < 0 || ret >= num_samples) {
			ilog(LOG_ERR | LOG_FLAG_LIMIT, "DTMF DSP returned error %i", ret);
			break;
		}
		samples += num_samples - ret;
		num_samples = ret;
	}
	ch->dtmf_ts = dsp_frame->pts + dsp_frame->nb_samples;
	av_frame_free(&dsp_frame);
}

static int __packet_decoded(decoder_t *decoder, AVFrame *frame, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilog(LOG_DEBUG, "RTP media successfully decoded: TS %llu, samples %u",
			(unsigned long long) frame->pts, frame->nb_samples);

	// switch from input codec context to output context if necessary
	struct codec_ssrc_handler *new_ch = __output_ssrc_handler(ch, mp);
	if (new_ch != ch) {
		// copy some essential parameters
		if (!new_ch->first_ts)
			new_ch->first_ts = ch->first_ts;

		ch = new_ch;
	}

	if (ch->skip_pts) {
		if (frame->nb_samples <= 0)
			;
		else if (frame->nb_samples < ch->skip_pts)
			ch->skip_pts -= frame->nb_samples;
		else
			ch->skip_pts = 0;
		ilog(LOG_DEBUG, "Discarding %i samples", frame->nb_samples);
		goto discard;
	}

	if (G_UNLIKELY(!ch->encoder)) {
		ilog(LOG_INFO | LOG_FLAG_LIMIT,
				"Discarding decoded %i PCM samples due to lack of output encoder",
				frame->nb_samples);
		goto discard;
	}

	__dtmf_detect(ch, frame);

	encoder_input_fifo(ch->encoder, frame, __packet_encoded, ch, mp);

discard:
	av_frame_free(&frame);
	//mp->iter_out++;
	obj_put(&new_ch->h);

	return 0;
}

static int packet_decode(struct codec_ssrc_handler *ch, struct transcode_packet *packet, struct media_packet *mp)
{
	if (!ch->first_ts)
		ch->first_ts = packet->ts;
	int ret = decoder_input_data(ch->decoder, packet->payload, packet->ts, __packet_decoded, ch, mp);
	//mp->iter_in++;
	mp->ssrc_out->parent->seq_diff--;
	return ret;
}

static int handler_func_transcode(struct codec_handler *h, struct media_packet *mp) {
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, mp);
	if (mp->call->block_media || mp->media->monologue->block_media)
		return 0;

	// create new packet and insert it into sequencer queue

	ilog(LOG_DEBUG, "Received RTP packet: SSRC %" PRIx32 ", PT %u, seq %u, TS %u, len %i",
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

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
			__packet_decoded, h->ssrc_handler, mp);
	return 0;
}

static int handler_func_inject_dtmf(struct codec_handler *h, struct media_packet *mp) {
	struct codec_ssrc_handler *ch = get_ssrc(mp->ssrc_in->parent->h.ssrc, h->ssrc_hash);
	decoder_input_data(ch->decoder, &mp->payload, mp->rtp->timestamp,
			__packet_decoded, ch, mp);
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


static struct rtp_payload_type *codec_add_payload_type(const str *codec, struct call_media *media) {
	struct rtp_payload_type *pt = codec_make_payload_type_sup(codec, media);
	if (!pt) {
		ilog(LOG_WARN, "Codec '" STR_FORMAT "' requested for transcoding is not supported",
				STR_FMT(codec));
		return NULL;
	}
	if (pt == (void *) 0x1)
		return NULL;

	// find an unused payload type number
	if (pt->payload_type < 0)
		pt->payload_type = 96; // default first dynamic payload type number
	while (1) {
		if (!g_hash_table_lookup(media->codecs_recv, &pt->payload_type))
			break; // OK
		pt->payload_type++;
		if (pt->payload_type < 96) // if an RFC type was taken already
			pt->payload_type = 96;
		else if (pt->payload_type >= 128) {
			ilog(LOG_WARN, "Ran out of RTP payload type numbers while adding codec '"
					STR_FORMAT "' for transcoding",
				STR_FMT(&pt->encoding_with_params));
			payload_type_free(pt);
			return NULL;
		}
	}
	return pt;
}

// handle special meaning "clock rate == 1": add one instance of this PT for each clock rate
// that is already present
static int __codec_synth_transcode_options(struct rtp_payload_type *pt, struct sdp_ng_flags *flags,
		struct call_media *media)
{
	if (pt->clock_rate != 1)
		return 0;

	struct call *call = media->call;
	GHashTable *clockrates = g_hash_table_new(g_direct_hash, g_direct_equal);

	// special handling - add one instance for each clock rate that is present
	for (GList *k = media->codecs_prefs_recv.head; k; k = k->next) {
		struct rtp_payload_type *pt_r = k->data;
		if (g_hash_table_lookup(clockrates, GUINT_TO_POINTER(pt_r->clock_rate)))
			continue;
		char *pt_s;
		if (asprintf(&pt_s, STR_FORMAT "/%u", STR_FMT(&pt->encoding), pt_r->clock_rate) < 0)
			continue;
		pt_s = call_strdup(call, pt_s);
		// XXX optimise this -^  call buffer can probably be replaced with a gstringchunk
		// and made lock free
		g_hash_table_insert(clockrates, GUINT_TO_POINTER(pt_r->clock_rate), (void *) 1);
		str pt_str;
		str_init(&pt_str, pt_s);
		ilog(LOG_DEBUG, "Synthesised transcoding option for '%s'", pt_s);
		g_queue_push_tail(&flags->codec_transcode, str_slice_dup(&pt_str));
	}

	payload_type_free(pt);
	g_hash_table_destroy(clockrates);

	return 1;
}


#endif





static void __rtp_payload_type_dup(struct call *call, struct rtp_payload_type *pt) {
	/* we must duplicate the contents */
	call_str_cpy(call, &pt->encoding_with_params, &pt->encoding_with_params);
	call_str_cpy(call, &pt->encoding, &pt->encoding);
	call_str_cpy(call, &pt->encoding_parameters, &pt->encoding_parameters);
	call_str_cpy(call, &pt->format_parameters, &pt->format_parameters);
}
static struct rtp_payload_type *__rtp_payload_type_copy(const struct rtp_payload_type *pt) {
	struct rtp_payload_type *pt_copy = g_slice_alloc(sizeof(*pt));
	*pt_copy = *pt;
	return pt_copy;
}
static void __rtp_payload_type_add_name(GHashTable *ht, struct rtp_payload_type *pt)
{
	GQueue *q = g_hash_table_lookup_queue_new(ht, &pt->encoding);
	g_queue_push_tail(q, GUINT_TO_POINTER(pt->payload_type));
	q = g_hash_table_lookup_queue_new(ht, &pt->encoding_with_params);
	g_queue_push_tail(q, GUINT_TO_POINTER(pt->payload_type));
}
// consumes 'pt'
void __rtp_payload_type_add_recv(struct call_media *media,
		struct rtp_payload_type *pt)
{
	if (!pt)
		return;
	// update ptime in case it was overridden
	if (media->ptime > 0)
		pt->ptime = media->ptime;
	g_hash_table_insert(media->codecs_recv, &pt->payload_type, pt);
	__rtp_payload_type_add_name(media->codec_names_recv, pt);
	g_queue_push_tail(&media->codecs_prefs_recv, pt);
}
// consumes 'pt'
void __rtp_payload_type_add_send(struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	if (!pt)
		return;
	// update ptime in case it was overridden
	if (other_media->ptime > 0)
		pt->ptime = other_media->ptime;
	g_hash_table_insert(other_media->codecs_send, &pt->payload_type, pt);
	__rtp_payload_type_add_name(other_media->codec_names_send, pt);
	g_queue_push_tail(&other_media->codecs_prefs_send, pt);
}
// duplicates 'pt'
void __rtp_payload_type_add_send_dup(struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	pt = __rtp_payload_type_copy(pt);
	__rtp_payload_type_add_send(other_media, pt);
}
// consumes 'pt'
static void __rtp_payload_type_add(struct call_media *media, struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	__rtp_payload_type_add_send_dup(other_media, pt);
	__rtp_payload_type_add_recv(media, pt);
}

static void __payload_queue_free(void *qq) {
	GQueue *q = qq;
	g_queue_free_full(q, (GDestroyNotify) payload_type_free);
}
static int __revert_codec_strip(GHashTable *removed, const str *codec,
		struct call_media *media, struct call_media *other_media)
{
	GQueue *q = g_hash_table_lookup(removed, codec);
	if (!q)
		return 0;
	ilog(LOG_DEBUG, "Restoring codec '" STR_FORMAT "' from stripped codecs (%u payload types)",
			STR_FMT(codec), q->length);
	g_hash_table_steal(removed, codec);
	for (GList *l = q->head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		__rtp_payload_type_add(media, other_media, pt);
	}
	g_queue_free(q);
	return 1;
}
static int __codec_options_set1(struct rtp_payload_type *pt, const str *enc, GHashTable *codec_set) {
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
	payload_type_free(pt_parsed);
	return 1;
}
static void __codec_options_set(struct rtp_payload_type *pt, GHashTable *codec_set) {
	if (!codec_set)
		return;
	if (__codec_options_set1(pt, &pt->encoding_with_params, codec_set))
		return;
	if (__codec_options_set1(pt, &pt->encoding, codec_set))
		return;
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
	GHashTable *removed = g_hash_table_new_full(str_case_hash, str_case_equal, NULL, __payload_queue_free);
	int strip_all = 0, mask_all = 0;

	// start fresh
	// receiving part for 'media'
	g_queue_clear_full(&media->codecs_prefs_recv, (GDestroyNotify) payload_type_free);
	g_hash_table_remove_all(media->codecs_recv);
	g_hash_table_remove_all(media->codec_names_recv);
	// and sending part for 'other_media'
	g_queue_clear_full(&other_media->codecs_prefs_send, (GDestroyNotify) payload_type_free);
	g_hash_table_remove_all(other_media->codecs_send);
	g_hash_table_remove_all(other_media->codec_names_send);

	if (flags->codec_strip && g_hash_table_lookup(flags->codec_strip, &str_all))
		strip_all = 1;
	if (flags->codec_mask && g_hash_table_lookup(flags->codec_mask, &str_all))
		mask_all = 1;

	/* we steal the entire list to avoid duplicate allocs */
	while ((pt = g_queue_pop_head(types))) {
		__rtp_payload_type_dup(call, pt); // this takes care of string allocation

		// codec stripping
		if (flags->codec_strip) {
			if (strip_all || g_hash_table_lookup(flags->codec_strip, &pt->encoding)
					|| g_hash_table_lookup(flags->codec_strip, &pt->encoding_with_params))
			{
				ilog(LOG_DEBUG, "Stripping codec '" STR_FORMAT "'",
						STR_FMT(&pt->encoding_with_params));
				GQueue *q = g_hash_table_lookup_queue_new(removed, &pt->encoding);
				g_queue_push_tail(q, __rtp_payload_type_copy(pt));
				q = g_hash_table_lookup_queue_new(removed, &pt->encoding_with_params);
				g_queue_push_tail(q, pt);
				continue;
			}
		}
		__codec_options_set(pt, flags->codec_set);
		if (!mask_all && (!flags->codec_mask || !g_hash_table_lookup(flags->codec_mask, &pt->encoding))
				&& (!flags->codec_mask || !g_hash_table_lookup(flags->codec_mask, &pt->encoding_with_params)))
			__rtp_payload_type_add(media, other_media, pt);
		else
			__rtp_payload_type_add_send(other_media, pt);
	}

	// now restore codecs that have been removed, but should be offered
	for (GList *l = flags->codec_offer.head; l; l = l->next) {
		str *codec = l->data;
		__revert_codec_strip(removed, codec, media, other_media);
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
			ilog(LOG_DEBUG, "Eliminating asymmetric inbound codec " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			l = __delete_receiver_codec(other_media, l);
		}
	}

#ifdef WITH_TRANSCODING
	// add transcode codecs
	for (GList *l = flags->codec_transcode.head; l; l = l->next) {
		str *codec = l->data;
		// if we wish to 'transcode' to a codec that was offered originally
		// and removed by a strip=all option,
		// simply restore it from the original list and handle it the same way
		// as 'offer'
		if (strip_all && __revert_codec_strip(removed, codec, media, other_media))
			continue;
		// also check if maybe the codec was never stripped
		if (g_hash_table_lookup(media->codec_names_recv, codec)) {
			ilog(LOG_DEBUG, "Codec '" STR_FORMAT "' requested for transcoding is already present",
					STR_FMT(codec));
			continue;
		}

		// create new payload type
		pt = codec_add_payload_type(codec, media);
		if (!pt)
			continue;

		if (__codec_synth_transcode_options(pt, flags, media))
			continue;

		ilog(LOG_DEBUG, "Codec '" STR_FORMAT "' added for transcoding with payload type %u",
				STR_FMT(&pt->encoding_with_params), pt->payload_type);
		__rtp_payload_type_add_recv(media, pt);
	}
#endif

	g_hash_table_destroy(removed);
}
