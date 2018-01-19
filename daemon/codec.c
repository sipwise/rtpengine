#include "codec.h"
#include <glib.h>
#include "call.h"
#include "log.h"
#include "rtplib.h"




static codec_handler_func handler_func_stub;


static struct codec_handler codec_handler_stub = {
	.rtp_payload_type = -1,
	.func = handler_func_stub,
};



static void __make_stub(struct codec_handler *handler) {
	handler->func = handler_func_stub;
}

static void __codec_handler_free(void *pp) {
	struct codec_handler *h = pp;
	g_slice_free1(sizeof(*h), h);
}

// call must be locked in W
void codec_handlers_update(struct call_media *receiver, struct call_media *sink) {
	if (!receiver->codec_handlers)
		receiver->codec_handlers = g_hash_table_new_full(g_int_hash, g_int_equal,
				NULL, __codec_handler_free);

	// we go through the list of codecs that the receiver supports and compare it
	// with the list of codecs supported by the sink. if the receiver supports
	// a codec that the sink doesn't support, we must transcode.
	//
	// if we transcode, we transcode to the highest-preference supported codec
	// that the sink specified. determine this first.
	struct rtp_payload_type *pref_dest_codec = NULL;
	for (GList *l = sink->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		// XXX if supported ...
		ilog(LOG_DEBUG, "Default sink codec is " STR_FORMAT, STR_FMT(&pt->encoding));
		pref_dest_codec = pt;
		break;
	}

	for (GList *l = receiver->codecs_prefs_recv.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;

		// first, make sure we have a codec_handler struct for this
		struct codec_handler *handler;
		handler = g_hash_table_lookup(receiver->codec_handlers, &pt->payload_type);
		if (!handler) {
			ilog(LOG_DEBUG, "Creating codec handler for " STR_FORMAT, STR_FMT(&pt->encoding));
			handler = g_slice_alloc0(sizeof(*handler));
			handler->rtp_payload_type = pt->payload_type;
			g_hash_table_insert(receiver->codec_handlers, &handler->rtp_payload_type,
					handler);
		}

		// if the sink's codec preferences are unknown (empty), or there are
		// no supported codecs to transcode to, then we have nothing
		// to do. most likely this is an initial offer without a received answer.
		// we default to forwarding without transcoding.
		if (!pref_dest_codec) {
			ilog(LOG_DEBUG, "No known/supported sink codec for " STR_FORMAT, STR_FMT(&pt->encoding));
			__make_stub(handler);
			continue;
		}

		if (g_hash_table_lookup(sink->codec_names, &pt->encoding)) {
			// the sink supports this codec. forward without transcoding.
			ilog(LOG_DEBUG, "Sink supports codec " STR_FORMAT, STR_FMT(&pt->encoding));
			__make_stub(handler);
			continue;
		}

		// the sink does not support this codec XXX do something
		ilog(LOG_DEBUG, "Sink does not support codec " STR_FORMAT, STR_FMT(&pt->encoding));
		__make_stub(handler);
	}
}

// call must be locked in R
struct codec_handler *codec_handler_get(struct call_media *m, int payload_type) {
	struct codec_handler *h;

	if (payload_type < 0)
		goto out;

	h = g_atomic_pointer_get(&m->codec_handler_cache);
	if (G_LIKELY(G_LIKELY(h) && G_LIKELY(h->rtp_payload_type == payload_type)))
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


static int handler_func_stub(struct codec_handler *h, struct call_media *media, const str *s, GQueue *out) {
	struct codec_packet *p = g_slice_alloc(sizeof(*p));
	p->s = *s;
	p->free_func = NULL;
	g_queue_push_tail(out, p);
	return 0;
}

void codec_packet_free(void *pp) {
	struct codec_packet *p = pp;
	if (p->free_func)
		p->free_func(p->s.s);
	g_slice_free1(sizeof(*p), p);
}
