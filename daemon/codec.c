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




static codec_handler_func handler_func_passthrough;

static struct rtp_payload_type *__rtp_payload_type_copy(const struct rtp_payload_type *pt);
static void __rtp_payload_type_dup(struct call *call, struct rtp_payload_type *pt);
static void __rtp_payload_type_add_name(GHashTable *, struct rtp_payload_type *pt);


static struct codec_handler codec_handler_stub = {
	.source_pt.payload_type = -1,
	.func = handler_func_passthrough,
	.passthrough = 1,
};



#ifdef WITH_TRANSCODING



struct codec_ssrc_handler {
	struct ssrc_entry h; // must be first
	struct codec_handler *handler;
	mutex_t lock;
	packet_sequencer_t sequencer;
	decoder_t *decoder;
	encoder_t *encoder;
	format_t encoder_format;
	int ptime;
	int bytes_per_packet;
	unsigned long ts_out;
	u_int16_t seq_out;
	GString *sample_buffer;
};
struct transcode_packet {
	seq_packet_t p; // must be first
	unsigned long ts;
	str *payload;
};


static codec_handler_func handler_func_passthrough_ssrc;
static codec_handler_func handler_func_transcode;

static struct ssrc_entry *__ssrc_handler_new(void *p);
static void __ssrc_handler_free(struct codec_ssrc_handler *p);

static void __transcode_packet_free(struct transcode_packet *);


static struct codec_handler codec_handler_stub_ssrc = {
	.source_pt.payload_type = -1,
	.func = handler_func_passthrough_ssrc,
	.passthrough = 1,
};



static void __handler_shutdown(struct codec_handler *handler) {
	free_ssrc_hash(&handler->ssrc_hash);
	handler->passthrough = 0;
}

static void __codec_handler_free(void *pp) {
	struct codec_handler *h = pp;
	__handler_shutdown(h);
	g_slice_free1(sizeof(*h), h);
}

static struct codec_handler *__handler_new(struct rtp_payload_type *pt) {
	struct codec_handler *handler = g_slice_alloc0(sizeof(*handler));
	handler->source_pt = *pt;
	return handler;
}

static void __make_passthrough(struct codec_handler *handler) {
	__handler_shutdown(handler);
	handler->func = handler_func_passthrough;
	handler->passthrough = 1;
}

static void __make_passthrough_ssrc(struct codec_handler *handler) {
	__handler_shutdown(handler);
	handler->func = handler_func_passthrough_ssrc;
	handler->passthrough = 1;
}

static void __make_transcoder(struct codec_handler *handler, struct rtp_payload_type *source,
		struct rtp_payload_type *dest)
{
	assert(source->codec_def != NULL);
	assert(dest->codec_def != NULL);
	assert(source->payload_type == handler->source_pt.payload_type);

	// don't reset handler if it already matches what we want
	if (rtp_payload_type_cmp(source, &handler->source_pt))
		goto reset;
	if (rtp_payload_type_cmp(dest, &handler->dest_pt))
		goto reset;
	if (handler->func != handler_func_transcode)
		goto reset;

	ilog(LOG_DEBUG, "Leaving transcode context for " STR_FORMAT " -> " STR_FORMAT " intact",
			STR_FMT(&source->encoding_with_params),
			STR_FMT(&dest->encoding_with_params));

	return;

reset:
	__handler_shutdown(handler);

	handler->source_pt = *source;
	handler->dest_pt = *dest;
	handler->func = handler_func_transcode;

	handler->ssrc_hash = create_ssrc_hash_full(__ssrc_handler_new, (ssrc_free_func_t) __ssrc_handler_free,
			handler);

	ilog(LOG_DEBUG, "Created transcode context for " STR_FORMAT " -> " STR_FORMAT "",
			STR_FMT(&source->encoding_with_params),
			STR_FMT(&dest->encoding_with_params));
}

static void __ensure_codec_def(struct rtp_payload_type *pt, struct call_media *media) {
	if (pt->codec_def)
		return;

	pt->codec_def = codec_find(&pt->encoding, media->type_id);
	if (!pt->codec_def)
		return;
	if (!pt->codec_def->pseudocodec && (!pt->codec_def->support_encoding || !pt->codec_def->support_decoding))
		pt->codec_def = NULL;
}
static GList *__delete_receiver_codec(struct call_media *receiver, GList *link) {
	struct rtp_payload_type *pt = link->data;

	g_hash_table_remove(receiver->codecs_recv, &pt->payload_type);
	g_hash_table_remove(receiver->codec_names_recv, &pt->encoding);
	g_hash_table_remove(receiver->codec_names_recv, &pt->encoding_with_params);

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
	receiver->rtcp_handler = NULL;
	GSList *passthrough_handlers = NULL;

	// we go through the list of codecs that the receiver supports and compare it
	// with the list of codecs supported by the sink. if the receiver supports
	// a codec that the sink doesn't support, we must transcode.
	//
	// if we transcode, we transcode to the highest-preference supported codec
	// that the sink specified. determine this first.
	struct rtp_payload_type *pref_dest_codec = NULL;
	for (GList *l = sink->codecs_prefs_send.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		__ensure_codec_def(pt, sink);
		if (!pt->codec_def || pt->codec_def->pseudocodec) // not supported, next
			continue;

		// fix up ptime
		if (!pt->ptime)
			pt->ptime = pt->codec_def->default_ptime;
		if (sink->ptime)
			pt->ptime = sink->ptime;

		if (!pref_dest_codec) {
			ilog(LOG_DEBUG, "Default sink codec is " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
			pref_dest_codec = pt;
		}
	}

	if (MEDIA_ISSET(sink, TRANSCODE)) {
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

			if (!pt->codec_def->pseudocodec) {
				ilog(LOG_DEBUG, "Accepting offered codec " STR_FORMAT " due to transcoding",
						STR_FMT(&pt->encoding_with_params));
				MEDIA_SET(receiver, TRANSCODE);
			}

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
						STR_FMT(&pt->encoding_with_params));

				l = __delete_receiver_codec(receiver, l);
				continue;
			}
		}

		// first, make sure we have a codec_handler struct for this
		struct codec_handler *handler;
		handler = g_hash_table_lookup(receiver->codec_handlers, &pt->payload_type);
		if (!handler) {
			ilog(LOG_DEBUG, "Creating codec handler for " STR_FORMAT,
					STR_FMT(&pt->encoding_with_params));
			handler = __handler_new(pt);
			g_hash_table_insert(receiver->codec_handlers, &handler->source_pt.payload_type,
					handler);
		}

		// check our own support for this codec
		__ensure_codec_def(pt, receiver);

		if (!pt->codec_def || pt->codec_def->pseudocodec) {
			// not supported, or not a real audio codec
			__make_passthrough(handler);
			passthrough_handlers = g_slist_prepend(passthrough_handlers, handler);
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
			__make_passthrough(handler);
			passthrough_handlers = g_slist_prepend(passthrough_handlers, handler);
			goto next;
		}

		struct rtp_payload_type *dest_pt; // transcode to this

		// in case of ptime mismatch, we transcode
		//struct rtp_payload_type *dest_pt = g_hash_table_lookup(sink->codec_names_send, &pt->encoding);
		GQueue *dest_codecs = g_hash_table_lookup(sink->codec_names_send, &pt->encoding);
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
			__make_passthrough(handler);
			passthrough_handlers = g_slist_prepend(passthrough_handlers, handler);
			goto next;
		}

unsupported:
		// the sink does not support this codec -> transcode
		ilog(LOG_DEBUG, "Sink does not support codec " STR_FORMAT, STR_FMT(&pt->encoding_with_params));
		dest_pt = pref_dest_codec;
transcode:
		MEDIA_SET(receiver, TRANSCODE);
		__make_transcoder(handler, pt, dest_pt);

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

		// at least some payload types will be transcoded, which will result in SSRC
		// change. for payload types which we don't actually transcode, we still
		// must substitute the SSRC
		while (passthrough_handlers) {
			struct codec_handler *handler = passthrough_handlers->data;
			__make_passthrough_ssrc(handler);
			passthrough_handlers = g_slist_delete_link(passthrough_handlers, passthrough_handlers);

		}
	}
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
	g_hash_table_destroy(m->codec_handlers);
	m->codec_handlers = NULL;
	m->codec_handler_cache = NULL;
}


void codec_add_raw_packet(struct media_packet *mp) {
	struct codec_packet *p = g_slice_alloc(sizeof(*p));
	p->s = mp->raw;
	p->free_func = NULL;
	if (mp->rtp)
		mp->ssrc_out->payload_type = mp->rtp->m_pt & 0x7f;
	g_queue_push_tail(&mp->packets_out, p);
}
static int handler_func_passthrough(struct codec_handler *h, struct call_media *media,
		struct media_packet *mp)
{
	codec_add_raw_packet(mp);
	return 0;
}



void codec_packet_free(void *pp) {
	struct codec_packet *p = pp;
	if (p->free_func)
		p->free_func(p->s.s);
	g_slice_free1(sizeof(*p), p);
}



struct rtp_payload_type *codec_make_payload_type(const str *codec_str, struct call_media *media) {
	str codec_fmt = *codec_str;
	str codec, parms, chans, opts, extra_opts;
	if (str_token_sep(&codec, &codec_fmt, '/'))
		return NULL;
	str_token_sep(&parms, &codec_fmt, '/');
	str_token_sep(&chans, &codec_fmt, '/');
	str_token_sep(&opts, &codec_fmt, '/');
	str_token_sep(&extra_opts, &codec_fmt, '/');

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

	const codec_def_t *def = codec_find(&ret->encoding, 0);
	ret->codec_def = def;

#ifdef WITH_TRANSCODING
	if (def) {
		if (!ret->clock_rate)
			ret->clock_rate = def->default_clockrate;
		if (!ret->channels)
			ret->channels = def->default_channels;
		if (!ret->ptime)
			ret->ptime = def->default_ptime;

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
		snprintf(full_encoding, sizeof(full_encoding), STR_FORMAT "/%u/%i", STR_FMT(&codec),
				ret->clock_rate,
				ret->channels);
		snprintf(params, sizeof(params), "%i", ret->channels);
	}
	else
		snprintf(full_encoding, sizeof(full_encoding), STR_FORMAT "/%u", STR_FMT(&codec),
				ret->clock_rate);

	str_init(&ret->encoding_with_params, full_encoding);
	str_init(&ret->encoding_parameters, params);
	ret->format_parameters = STR_EMPTY;

	__rtp_payload_type_dup(media->call, ret);

	return ret;
}



#ifdef WITH_TRANSCODING


static int handler_func_passthrough_ssrc(struct codec_handler *h, struct call_media *media,
		struct media_packet *mp)
{
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, media, mp);

	// substitute out SSRC
	mp->rtp->ssrc = htonl(mp->ssrc_in->ssrc_map_out);

	// keep track of other stats here?

	codec_add_raw_packet(mp);
	return 0;
}


static void __transcode_packet_free(struct transcode_packet *p) {
	free(p->payload);
	g_slice_free1(sizeof(*p), p);
}

static struct ssrc_entry *__ssrc_handler_new(void *p) {
	struct codec_handler *h = p;

	ilog(LOG_DEBUG, "Creating SSRC transcoder from %s/%u/%i to "
			"%s/%u/%i",
			h->source_pt.codec_def->rtpname, h->source_pt.clock_rate,
			h->source_pt.channels,
			h->dest_pt.codec_def->rtpname, h->dest_pt.clock_rate,
			h->dest_pt.channels);

	struct codec_ssrc_handler *ch = g_slice_alloc0(sizeof(*ch));
	ch->handler = h;
	mutex_init(&ch->lock);
	packet_sequencer_init(&ch->sequencer, (GDestroyNotify) __transcode_packet_free);
	ch->seq_out = random();
	ch->ts_out = random();
	ch->ptime = h->dest_pt.ptime;
	ch->sample_buffer = g_string_new("");

	format_t enc_format = {
		.clockrate = h->dest_pt.clock_rate * h->dest_pt.codec_def->clockrate_mult,
		.channels = h->dest_pt.channels,
		.format = -1,
	};
	ch->encoder = encoder_new();
	if (!ch->encoder)
		goto err;
	if (encoder_config(ch->encoder, h->dest_pt.codec_def,
				h->dest_pt.bitrate ? : h->dest_pt.codec_def->default_bitrate,
				ch->ptime,
				&enc_format, &ch->encoder_format))
		goto err;

	ch->decoder = decoder_new_fmt(h->source_pt.codec_def, h->source_pt.clock_rate, h->source_pt.channels,
			&ch->encoder_format);
	if (!ch->decoder)
		goto err;

	ch->bytes_per_packet = (ch->encoder->samples_per_packet ? : ch->encoder->samples_per_frame)
		* h->dest_pt.codec_def->bits_per_sample / 8;

	ilog(LOG_DEBUG, "Encoder created with clockrate %i, %i channels, using sample format %i "
			"(ptime %i for %i samples per frame and %i samples (%i bytes) per packet)",
			ch->encoder_format.clockrate, ch->encoder_format.channels, ch->encoder_format.format,
			ch->ptime, ch->encoder->samples_per_frame, ch->encoder->samples_per_packet,
			ch->bytes_per_packet);

	return &ch->h;

err:
	__ssrc_handler_free(ch);
	return NULL;
}
static int __encoder_flush(encoder_t *enc, void *u1, void *u2) {
	int *going = u1;
	*going = 1;
	return 0;
}
static void __ssrc_handler_free(struct codec_ssrc_handler *ch) {
	packet_sequencer_destroy(&ch->sequencer);
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
	g_string_free(ch->sample_buffer, TRUE);
	g_slice_free1(sizeof(*ch), ch);
}

static int __packet_encoded(encoder_t *enc, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;
	struct media_packet *mp = u2;

	ilog(LOG_DEBUG, "RTP media successfully encoded: TS %llu, len %i",
			(unsigned long long) enc->avpkt.pts, enc->avpkt.size);

	// run this through our packetizer
	AVPacket *in_pkt = &enc->avpkt;

	while (1) {
		// figure out how big of a buffer we need
		unsigned int payload_len = MAX(enc->avpkt.size, ch->bytes_per_packet);
		unsigned int pkt_len = sizeof(struct rtp_header) + payload_len;
		// prepare our buffers
		char *buf = malloc(pkt_len);
		struct rtp_header *rh = (void *) buf;
		char *payload = buf + sizeof(struct rtp_header);
		// tell our packetizer how much we want
		str inout;
		str_init_len(&inout, payload, payload_len);
		// and request a packet
		if (in_pkt)
			ilog(LOG_DEBUG, "Adding %i bytes to packetizer", in_pkt->size);
		int ret = ch->handler->dest_pt.codec_def->packetizer(in_pkt,
				ch->sample_buffer, &inout);

		if (G_UNLIKELY(ret == -1)) {
			// nothing
			free(buf);
			break;
		}

		ilog(LOG_DEBUG, "Received packet of %i bytes from packetizer", inout.len);
		// reconstruct RTP header
		unsigned int ts = enc->avpkt.pts + ch->ts_out;
		ZERO(*rh);
		rh->v_p_x_cc = 0x80;
		rh->m_pt = ch->handler->dest_pt.payload_type;
		rh->seq_num = htons(ch->seq_out++);
		rh->timestamp = htonl(ts);
		rh->ssrc = htonl(mp->ssrc_in->ssrc_map_out);

		// add to output queue
		struct codec_packet *p = g_slice_alloc(sizeof(*p));
		p->s.s = buf;
		p->s.len = inout.len + sizeof(struct rtp_header);
		mp->ssrc_out->payload_type = ch->handler->dest_pt.payload_type;
		p->free_func = free;
		g_queue_push_tail(&mp->packets_out, p);

		atomic64_inc(&mp->ssrc_out->packets);
		atomic64_add(&mp->ssrc_out->octets, inout.len);
		atomic64_set(&mp->ssrc_out->last_ts, ts);

		if (ret == 0) {
			// no more to go
			break;
		}

		// loop around and get more
		in_pkt = NULL;
	}

	return 0;
}

static int __packet_decoded(decoder_t *decoder, AVFrame *frame, void *u1, void *u2) {
	struct codec_ssrc_handler *ch = u1;

	ilog(LOG_DEBUG, "RTP media successfully decoded: TS %llu, samples %u",
			(unsigned long long) frame->pts, frame->nb_samples);

	encoder_input_fifo(ch->encoder, frame, __packet_encoded, ch, u2);

	av_frame_free(&frame);
	return 0;
}

static int handler_func_transcode(struct codec_handler *h, struct call_media *media,
		struct media_packet *mp)
{
	if (G_UNLIKELY(!mp->rtp))
		return handler_func_passthrough(h, media, mp);

	assert((mp->rtp->m_pt & 0x7f) == h->source_pt.payload_type);

	// create new packet and insert it into sequencer queue

	ilog(LOG_DEBUG, "Received RTP packet: SSRC %" PRIx32 ", PT %u, seq %u, TS %u, len %i",
			ntohl(mp->rtp->ssrc), mp->rtp->m_pt, ntohs(mp->rtp->seq_num),
			ntohl(mp->rtp->timestamp), mp->payload.len);

	struct codec_ssrc_handler *ch = get_ssrc(mp->rtp->ssrc, h->ssrc_hash);
	if (G_UNLIKELY(!ch))
		return 0;

	atomic64_inc(&mp->ssrc_in->packets);
	atomic64_add(&mp->ssrc_in->octets, mp->payload.len);

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
		atomic64_inc(&mp->ssrc_in->duplicates);
		return 0;
	}

	// got a new packet, run decoder

	while (1) {
		packet = packet_sequencer_next_packet(&ch->sequencer);
		if (G_UNLIKELY(!packet))
			break;

		atomic64_set(&mp->ssrc_in->packets_lost, ch->sequencer.lost_count);
		atomic64_set(&mp->ssrc_in->last_seq, ch->sequencer.ext_seq);

		ilog(LOG_DEBUG, "Decoding RTP packet: seq %u, TS %lu",
				packet->p.seq, packet->ts);

		if (decoder_input_data(ch->decoder, packet->payload, packet->ts, __packet_decoded, ch, mp))
			ilog(LOG_WARN, "Decoder error while processing RTP packet");
		__transcode_packet_free(packet);
	}

	mutex_unlock(&ch->lock);

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
	__rtp_payload_type_add_recv(media, pt);
	__rtp_payload_type_add_send_dup(other_media, pt);
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
void codec_rtp_payload_types(struct call_media *media, struct call_media *other_media,
		GQueue *types, GHashTable *strip,
		const GQueue *offer, const GQueue *transcode,
		GHashTable *mask)
{
	// 'media' = receiver of this offer/answer; 'other_media' = sender of this offer/answer
	struct call *call = media->call;
	struct rtp_payload_type *pt;
	static const str str_all = STR_CONST_INIT("all");
	GHashTable *removed = g_hash_table_new_full(str_hash, str_equal, NULL, __payload_queue_free);
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

	if (strip && g_hash_table_lookup(strip, &str_all))
		strip_all = 1;
	if (mask && g_hash_table_lookup(mask, &str_all))
		mask_all = 1;

	/* we steal the entire list to avoid duplicate allocs */
	while ((pt = g_queue_pop_head(types))) {
		__rtp_payload_type_dup(call, pt); // this takes care of string allocation

		// codec stripping
		if (strip) {
			if (strip_all || g_hash_table_lookup(strip, &pt->encoding)
					|| g_hash_table_lookup(strip, &pt->encoding_with_params))
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
		if (!mask_all && !g_hash_table_lookup(mask, &pt->encoding)
				&& !g_hash_table_lookup(mask, &pt->encoding_with_params))
			__rtp_payload_type_add(media, other_media, pt);
		else
			__rtp_payload_type_add_send(other_media, pt);
	}

	// now restore codecs that have been removed, but should be offered
	for (GList *l = offer ? offer->head : NULL; l; l = l->next) {
		str *codec = l->data;
		__revert_codec_strip(removed, codec, media, other_media);
	}

#ifdef WITH_TRANSCODING
	// add transcode codecs
	for (GList *l = transcode ? transcode->head : NULL; l; l = l->next) {
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

		ilog(LOG_DEBUG, "Codec '" STR_FORMAT "' added for transcoding with payload type %u",
				STR_FMT(&pt->encoding_with_params), pt->payload_type);
		__rtp_payload_type_add_recv(media, pt);
	}
#endif

	g_hash_table_destroy(removed);
}
