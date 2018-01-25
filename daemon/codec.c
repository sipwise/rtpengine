#include "codec.h"
#include <glib.h>
#include <assert.h>
#include "call.h"
#include "log.h"
#include "rtplib.h"
#include "codeclib.h"
#include "ssrc.h"




struct codec_ssrc_handler {
	struct ssrc_entry h; // must be first
	mutex_t lock;
	packet_sequencer_t sequencer;
	decoder_t *decoder;
};
struct transcode_packet {
	seq_packet_t p; // must be first
	unsigned long ts;
	str *payload;
};


static codec_handler_func handler_func_passthrough;
static codec_handler_func handler_func_transcode;

static struct ssrc_entry *__ssrc_handler_new(u_int32_t ssrc, void *p);
static void __ssrc_handler_free(struct codec_ssrc_handler *p);

static void __transcode_packet_free(struct transcode_packet *);

static struct rtp_payload_type *__rtp_payload_type_copy(struct rtp_payload_type *pt);
static void __rtp_payload_type_add_name(GHashTable *, struct rtp_payload_type *pt);


static struct codec_handler codec_handler_stub = {
	.source_pt.payload_type = -1,
	.func = handler_func_passthrough,
};



static void __handler_shutdown(struct codec_handler *handler) {
	free_ssrc_hash(&handler->ssrc_hash);
}

static void __codec_handler_free(void *pp) {
	struct codec_handler *h = pp;
	__handler_shutdown(h);
	g_slice_free1(sizeof(*h), h);
}

static struct codec_handler *__handler_new(int pt) {
	struct codec_handler *handler = g_slice_alloc0(sizeof(*handler));
	handler->source_pt.payload_type = pt;
	return handler;
}

static void __make_passthrough(struct codec_handler *handler) {
	__handler_shutdown(handler);
	handler->func = handler_func_passthrough;
}

static void __make_transcoder(struct codec_handler *handler, struct rtp_payload_type *source,
		struct rtp_payload_type *dest)
{
	assert(source->codec_def != NULL);
	assert(dest->codec_def != NULL);
	assert(source->payload_type == handler->source_pt.payload_type);

	__handler_shutdown(handler);

	handler->source_pt = *source;
	handler->dest_pt = *dest;
	handler->func = handler_func_transcode;

	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, (ssrc_free_func_t) __ssrc_handler_free,
			handler);

	ilog(LOG_DEBUG, "Created transcode context for '" STR_FORMAT "' -> '" STR_FORMAT "'",
			STR_FMT(&source->encoding), STR_FMT(&dest->encoding));

	return;

}

static void __ensure_codec_def(struct rtp_payload_type *pt) {
	if (!pt->codec_def)
		pt->codec_def = codec_find(&pt->encoding);
}
static GList *__delete_receiver_codec(struct call_media *receiver, GList *link) {
	struct rtp_payload_type *pt = link->data;

	g_hash_table_remove(receiver->codecs_recv, &pt->payload_type);
	g_hash_table_remove(receiver->codec_names_recv, &pt->encoding);

	GList *next = link->next;
	g_queue_delete_link(&receiver->codecs_prefs_recv, link);
	payload_type_free(pt);
	return next;
}

// call must be locked in W
void codec_handlers_update(struct call_media *receiver, struct call_media *sink) {
	if (!receiver->codec_handlers)
		receiver->codec_handlers = g_hash_table_new_full(g_int_hash, g_int_equal,
				NULL, __codec_handler_free);

	MEDIA_CLEAR(receiver, TRANSCODE);

	// we go through the list of codecs that the receiver supports and compare it
	// with the list of codecs supported by the sink. if the receiver supports
	// a codec that the sink doesn't support, we must transcode.
	//
	// if we transcode, we transcode to the highest-preference supported codec
	// that the sink specified. determine this first.
	struct rtp_payload_type *pref_dest_codec = NULL;
	for (GList *l = sink->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		__ensure_codec_def(pt);
		if (!pt->codec_def) // not supported, next
			continue;
		ilog(LOG_DEBUG, "Default sink codec is " STR_FORMAT, STR_FMT(&pt->encoding));
		pref_dest_codec = pt;
		break;
	}

	if (MEDIA_ISSET(sink, TRANSCODE)) {
		// if the other side is transcoding, we need to accept codecs that were
		// originally offered (recv->send) if we support them, even if the
		// response (sink->send) doesn't include them
		GList *insert_pos = NULL;
		for (GList *l = receiver->codecs_prefs_send.head; l; l = l->next) {
			struct rtp_payload_type *pt = l->data;
			__ensure_codec_def(pt);
			if (!pt->codec_def)
				continue;
			if (g_hash_table_lookup(receiver->codecs_recv, &pt->payload_type))
				continue; // already present

			ilog(LOG_DEBUG, "Accepting offered codec " STR_FORMAT " due to transcoding",
					STR_FMT(&pt->encoding));
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

	for (GList *l = receiver->codecs_prefs_recv.head; l; ) {
		struct rtp_payload_type *pt = l->data;

		if (MEDIA_ISSET(sink, TRANSCODE)) {
			// if the other side is transcoding, we may come across a receiver entry
			// (recv->recv) that wasn't originally offered (recv->send). we must eliminate
			// those
			// XXX sufficient to check against payload type?
			if (!g_hash_table_lookup(receiver->codec_names_send, &pt->encoding)) {
				ilog(LOG_DEBUG, "Eliminating transcoded codec " STR_FORMAT,
						STR_FMT(&pt->encoding));

				l = __delete_receiver_codec(receiver, l);
				continue;
			}
		}

		// first, make sure we have a codec_handler struct for this
		struct codec_handler *handler;
		handler = g_hash_table_lookup(receiver->codec_handlers, &pt->payload_type);
		if (!handler) {
			ilog(LOG_DEBUG, "Creating codec handler for " STR_FORMAT, STR_FMT(&pt->encoding));
			handler = __handler_new(pt->payload_type);
			g_hash_table_insert(receiver->codec_handlers, &handler->source_pt.payload_type,
					handler);
		}

		// check our own support for this codec
		__ensure_codec_def(pt);

		// if the sink's codec preferences are unknown (empty), or there are
		// no supported codecs to transcode to, then we have nothing
		// to do. most likely this is an initial offer without a received answer.
		// we default to forwarding without transcoding.
		if (!pref_dest_codec) {
			ilog(LOG_DEBUG, "No known/supported sink codec for " STR_FORMAT, STR_FMT(&pt->encoding));
			__make_passthrough(handler);
			goto next;
		}

		if (g_hash_table_lookup(sink->codec_names_send, &pt->encoding)) {
			// the sink supports this codec. forward without transcoding.
			// XXX check format parameters as well
			ilog(LOG_DEBUG, "Sink supports codec " STR_FORMAT, STR_FMT(&pt->encoding));
			__make_passthrough(handler);
			goto next;
		}

		// the sink does not support this codec -> transcode
		ilog(LOG_DEBUG, "Sink does not support codec " STR_FORMAT, STR_FMT(&pt->encoding));
		MEDIA_SET(receiver, TRANSCODE);
		__make_transcoder(handler, pt, pref_dest_codec);

next:
		l = l->next;
	}

	// if we've determined that we transcode, we must remove all unsupported codecs from
	// the list, as we must expect to potentially receive media in that codec, which we
	// then could not transcode.
	if (MEDIA_ISSET(receiver, TRANSCODE)) {
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
	}
}

// call must be locked in R
struct codec_handler *codec_handler_get(struct call_media *m, int payload_type) {
	struct codec_handler *h;

	if (payload_type < 0)
		goto out;

	h = g_atomic_pointer_get(&m->codec_handler_cache);
	if (G_LIKELY(G_LIKELY(h) && G_LIKELY(h->source_pt.payload_type == payload_type)))
		return h;

	h = g_hash_table_lookup(m->codec_handlers, &payload_type);
	if (!h)
		goto out;

	g_atomic_pointer_set(&m->codec_handler_cache, h);

	return h;

out:
	return &codec_handler_stub;
}

void codec_handlers_free(struct call_media *m) {
	g_hash_table_destroy(m->codec_handlers);
	m->codec_handlers = NULL;
	m->codec_handler_cache = NULL;
}


static int handler_func_passthrough(struct codec_handler *h, struct call_media *media,
		const struct media_packet *mp, GQueue *out)
{
	struct codec_packet *p = g_slice_alloc(sizeof(*p));
	p->s = mp->raw;
	p->free_func = NULL;
	g_queue_push_tail(out, p);
	return 0;
}


static void __transcode_packet_free(struct transcode_packet *p) {
	free(p->payload);
	g_slice_free1(sizeof(*p), p);
}

static struct ssrc_entry *__ssrc_handler_new(u_int32_t ssrc, void *p) {
	struct codec_handler *h = p;
	struct codec_ssrc_handler *ch = g_slice_alloc0(sizeof(*ch));
	init_ssrc_entry(&ch->h, ssrc);
	mutex_init(&ch->lock);
	packet_sequencer_init(&ch->sequencer, (GDestroyNotify) __transcode_packet_free);
	ch->decoder = decoder_new_fmt(h->source_pt.codec_def, h->source_pt.clock_rate, 1, 0);
	if (!ch->decoder)
		goto err;
	return &ch->h;

err:
	__ssrc_handler_free(ch);
	return NULL;
}
static void __ssrc_handler_free(struct codec_ssrc_handler *ch) {
	packet_sequencer_destroy(&ch->sequencer);
	if (ch->decoder)
		decoder_close(ch->decoder);
	g_slice_free1(sizeof(*ch), ch);
}

int __packet_decoded(decoder_t *decoder, AVFrame *frame, void *u1, void *u2) {
	//struct codec_ssrc_handler *ch = u1;

	ilog(LOG_DEBUG, "RTP media successfully decoded");

	av_frame_free(&frame);
	return 0;
}

static int handler_func_transcode(struct codec_handler *h, struct call_media *media,
		const struct media_packet *mp, GQueue *out)
{
	if (G_UNLIKELY(!mp->rtp || mp->rtcp))
		return handler_func_passthrough(h, media, mp, out);

	assert((mp->rtp->m_pt & 0x7f) == h->source_pt.payload_type);

	// create new packet and insert it into sequencer queue

	ilog(LOG_DEBUG, "Received RTP packet: SSRC %u, PT %u, seq %u, TS %u",
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp));

	struct codec_ssrc_handler *ch = get_ssrc(mp->rtp->ssrc, h->ssrc_hash);
	if (G_UNLIKELY(!ch))
		return 0;

	struct transcode_packet *packet = g_slice_alloc0(sizeof(*packet));
	packet->p.seq = ntohs(mp->rtp->seq_num);
	packet->payload = str_dup(&mp->payload);
	packet->ts = ntohl(mp->rtp->timestamp);

	mutex_lock(&ch->lock);

	if (packet_sequencer_insert(&ch->sequencer, &packet->p)) {
		// dupe
		mutex_unlock(&ch->lock);
		__transcode_packet_free(packet);
		ilog(LOG_DEBUG, "Ignoring duplicate RTP packet");
		return 0;
	}

	// got a new packet, run decoder

	while (1) {
		packet = packet_sequencer_next_packet(&ch->sequencer);
		if (G_UNLIKELY(!packet))
			break;

		ilog(LOG_DEBUG, "Decoding RTP packet: seq %u, TS %lu",
				packet->p.seq, packet->ts);

		if (decoder_input_data(ch->decoder, packet->payload, packet->ts, __packet_decoded, ch, NULL))
			ilog(LOG_WARN, "Decoder error while processing RTP packet");
		__transcode_packet_free(packet);
	}

	mutex_unlock(&ch->lock);

	return 0;
}

void codec_packet_free(void *pp) {
	struct codec_packet *p = pp;
	if (p->free_func)
		p->free_func(p->s.s);
	g_slice_free1(sizeof(*p), p);
}



static struct rtp_payload_type *codec_make_payload_type(const str *codec) {
	const codec_def_t *dec = codec_find(codec);
	if (!dec)
		return NULL;
	const struct rtp_payload_type *rfc_pt = rtp_get_rfc_codec(codec);
	if (!rfc_pt)
		return NULL; // XXX amend for other codecs

	struct rtp_payload_type *ret = g_slice_alloc(sizeof(*ret));
	*ret = *rfc_pt;
	ret->codec_def = dec;

	return ret;
}


static struct rtp_payload_type *codec_add_payload_type(const str *codec, struct call_media *media) {
	struct rtp_payload_type *pt = codec_make_payload_type(codec);
	if (!pt) {
		ilog(LOG_WARN, "Codec '" STR_FORMAT "' requested for transcoding is not supported",
				STR_FMT(codec));
		return NULL;
	}
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
				STR_FMT(codec));
			payload_type_free(pt);
			return NULL;
		}
	}
	return pt;
}









static void __rtp_payload_type_dup(struct call *call, struct rtp_payload_type *pt) {
	/* we must duplicate the contents */
	call_str_cpy(call, &pt->encoding_with_params, &pt->encoding_with_params);
	call_str_cpy(call, &pt->encoding, &pt->encoding);
	call_str_cpy(call, &pt->encoding_parameters, &pt->encoding_parameters);
	call_str_cpy(call, &pt->format_parameters, &pt->format_parameters);
}
static struct rtp_payload_type *__rtp_payload_type_copy(struct rtp_payload_type *pt) {
	struct rtp_payload_type *pt_copy = g_slice_alloc(sizeof(*pt));
	*pt_copy = *pt;
	return pt_copy;
}
static void __rtp_payload_type_add_name(GHashTable *ht, struct rtp_payload_type *pt)
{
	GQueue *q = g_hash_table_lookup_queue_new(ht, &pt->encoding);
	g_queue_push_tail(q, GUINT_TO_POINTER(pt->payload_type));
}
// consumes 'pt'
static void __rtp_payload_type_add_recv(struct call_media *media,
		struct rtp_payload_type *pt)
{
	g_hash_table_insert(media->codecs_recv, &pt->payload_type, pt);
	__rtp_payload_type_add_name(media->codec_names_recv, pt);
	g_queue_push_tail(&media->codecs_prefs_recv, pt);
}
// duplicates 'pt'
static void __rtp_payload_type_add_send(struct call_media *other_media, struct rtp_payload_type *pt) {
	pt = __rtp_payload_type_copy(pt);
	__rtp_payload_type_add_name(other_media->codec_names_send, pt);
	g_queue_push_tail(&other_media->codecs_prefs_send, pt);
}
// consumes 'pt'
static void __rtp_payload_type_add(struct call_media *media, struct call_media *other_media,
		struct rtp_payload_type *pt)
{
	__rtp_payload_type_add_recv(media, pt);
	__rtp_payload_type_add_send(other_media, pt);
}

static void __payload_queue_free(void *qq) {
	GQueue *q = qq;
	g_queue_free_full(q, (GDestroyNotify) payload_type_free);
}
static int __revert_codec_strip(GHashTable *removed, const str *codec,
		struct call_media *media, struct call_media *other_media) {
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
void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, GHashTable *strip,
		const GQueue *offer, const GQueue *transcode)
{
	// 'media' = receiver of this offer/answer; 'other_media' = sender of this offer/answer
	struct call *call = media->call;
	struct rtp_payload_type *pt;
	static const str str_all = STR_CONST_INIT("all");
	GHashTable *removed = g_hash_table_new_full(str_hash, str_equal, NULL, __payload_queue_free);
	int remove_all = 0;

	// start fresh
	// receiving part for 'media'
	g_queue_clear_full(&media->codecs_prefs_recv, (GDestroyNotify) payload_type_free);
	g_hash_table_remove_all(media->codecs_recv);
	g_hash_table_remove_all(media->codec_names_recv);
	// and sending part for 'other_media'
	g_queue_clear_full(&other_media->codecs_prefs_send, (GDestroyNotify) payload_type_free);
	g_hash_table_remove_all(other_media->codec_names_send);

	if (strip && g_hash_table_lookup(strip, &str_all))
		remove_all = 1;

	/* we steal the entire list to avoid duplicate allocs */
	while ((pt = g_queue_pop_head(types))) {
		__rtp_payload_type_dup(call, pt); // this takes care of string allocation

		// codec stripping
		if (strip) {
			if (remove_all || g_hash_table_lookup(strip, &pt->encoding)) {
				ilog(LOG_DEBUG, "Stripping codec '" STR_FORMAT "'", STR_FMT(&pt->encoding));
				GQueue *q = g_hash_table_lookup_queue_new(removed, &pt->encoding);
				g_queue_push_tail(q, pt);
				continue;
			}
		}
		__rtp_payload_type_add(media, other_media, pt);
	}

	// now restore codecs that have been removed, but should be offered
	for (GList *l = offer ? offer->head : NULL; l; l = l->next) {
		str *codec = l->data;
		__revert_codec_strip(removed, codec, media, other_media);
	}

	// add transcode codecs
	for (GList *l = transcode ? transcode->head : NULL; l; l = l->next) {
		str *codec = l->data;
		// if we wish to 'transcode' to a codec that was offered originally,
		// simply restore it from the original list and handle it the same way
		// as 'offer'
		if (__revert_codec_strip(removed, codec, media, other_media))
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

		ilog(LOG_DEBUG, "Codec '" STR_FORMAT "' added for transcoding with payload type %u",
				STR_FMT(codec), pt->payload_type);
		__rtp_payload_type_add_recv(media, pt);
	}

	g_hash_table_destroy(removed);
}
