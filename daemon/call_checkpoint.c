#include "call_checkpoint.h"

#include "call.h"
#include "codec.h"
#include "dtls.h"
#include "ice.h"
#include "main.h"

struct checkpoint_stream {
	struct checkpoint_stream *next;
	struct packet_stream *stream;
	stream_fd_q sfds;
	stream_fd *selected_sfd;
	struct endpoint endpoint;
	struct endpoint advertised_endpoint;
	struct endpoint learned_endpoint;
	struct endpoint detected_endpoints[4];
	endpoint_t last_local_endpoint;
	int64_t ep_detect_signal;
	enum endpoint_learning el_flags;
	uint64_t flags;
};

struct checkpoint_media {
	struct checkpoint_media *next;
	struct call_media *media;
	const struct transport_protocol *protocol;
	str protocol_str;
	str format_str;
	sockfamily_t *desired_family;
	struct logical_intf *logical_intf;
	uint64_t flags;
	sdes_q sdes_in;
	sdes_q sdes_out;
	struct dtls_fingerprint fingerprint;
	const struct dtls_hash_func *fp_hash_func;
	str tls_id;
	struct codec_store codecs;
	struct codec_store offered_codecs;
	candidate_q ice_candidates;
	str ice_ufrag[2];
	str ice_pwd[2];
	bool had_ice;
	int ptime;
	int maxptime;
	struct session_bandwidth bandwidth;
	struct checkpoint_stream *streams;
};

struct checkpoint_monologue {
	struct call_monologue *monologue;
	sockfamily_t *desired_family;
	struct logical_intf *logical_intf;
	uint64_t flags;
	struct session_bandwidth bandwidth;
	sdp_origin sdp_orig_in;
	sdp_origin sdp_orig_out;
	str session_name;
	str session_timing;
	GString *last_out_sdp;
	unsigned int medias_len;
};

struct call_checkpoint {
	struct call_checkpoint *next;
	struct call_monologue *offerer;
	struct call_monologue *answerer;
	uint64_t generation;
	uint64_t pending_generation;
	bool pending;
	struct checkpoint_monologue monologues[2];
	struct checkpoint_media *medias;
};

static void checkpoint_candidates_copy(candidate_q *dst, const candidate_q *src) {
	for (__auto_type l = src->head; l; l = l->next) {
		struct ice_candidate *copy = g_new(__typeof(*copy), 1);
		*copy = *(struct ice_candidate *) l->data;
		t_queue_push_tail(dst, copy);
	}
}
static void checkpoint_stream_free(struct checkpoint_stream *stream) {
	t_queue_clear_full(&stream->sfds, stream_fd_dec);
	g_free(stream);
}

static void checkpoint_media_free(struct checkpoint_media *media) {
	while (media->streams) {
		struct checkpoint_stream *stream = media->streams;
		media->streams = stream->next;
		checkpoint_stream_free(stream);
	}
	crypto_params_sdes_queue_clear(&media->sdes_in);
	crypto_params_sdes_queue_clear(&media->sdes_out);
	codec_store_cleanup(&media->codecs);
	codec_store_cleanup(&media->offered_codecs);
	ice_candidates_free(&media->ice_candidates);
	g_free(media);
}

static void checkpoint_clear_snapshot(struct call_checkpoint *cp) {
	while (cp->medias) {
		struct checkpoint_media *media = cp->medias;
		cp->medias = media->next;
		checkpoint_media_free(media);
	}
	for (unsigned int i = 0; i < G_N_ELEMENTS(cp->monologues); i++) {
		if (cp->monologues[i].last_out_sdp)
			g_string_free(cp->monologues[i].last_out_sdp, TRUE);
		ZERO(cp->monologues[i]);
	}
	cp->pending = false;
	cp->pending_generation = 0;
}

static void checkpoint_free(struct call_checkpoint *cp) {
	checkpoint_clear_snapshot(cp);
	g_free(cp);
}

static struct call_checkpoint *checkpoint_find(call_t *call, struct call_monologue *a,
		struct call_monologue *b)
{
	for (struct call_checkpoint *cp = call->checkpoints; cp; cp = cp->next) {
		if ((cp->offerer == a && cp->answerer == b) || (cp->offerer == b && cp->answerer == a))
			return cp;
	}
	return NULL;
}

static void checkpoint_take_stream(struct checkpoint_media *media, struct packet_stream *ps) {
	struct checkpoint_stream *stream = g_new0(__typeof(*stream), 1);
	stream->stream = ps;
	stream->endpoint = ps->endpoint;
	stream->advertised_endpoint = ps->advertised_endpoint;
	stream->learned_endpoint = ps->learned_endpoint;
	memcpy(stream->detected_endpoints, ps->detected_endpoints, sizeof(stream->detected_endpoints));
	stream->last_local_endpoint = ps->last_local_endpoint;
	stream->ep_detect_signal = ps->ep_detect_signal;
	stream->el_flags = ps->el_flags;
	stream->flags = atomic64_get_na(&ps->ps_flags);
	stream->selected_sfd = ps->selected_sfd;
	for (__auto_type l = ps->sfds.head; l; l = l->next) {
		stream_fd *sfd = l->data;
		stream_fd_inc(sfd);
		t_queue_push_tail(&stream->sfds, sfd);
	}
	stream->next = media->streams;
	media->streams = stream;
}

static void checkpoint_take_media(struct call_checkpoint *cp, struct call_media *m) {
	struct checkpoint_media *media = g_new0(__typeof(*media), 1);
	media->media = m;
	media->protocol = m->protocol;
	media->protocol_str = m->protocol_str;
	media->format_str = m->format_str;
	media->desired_family = m->desired_family;
	media->logical_intf = m->logical_intf;
	media->flags = atomic64_get_na(&m->media_flags);
	crypto_params_sdes_queue_copy(&media->sdes_in, &m->sdes_in);
	crypto_params_sdes_queue_copy(&media->sdes_out, &m->sdes_out);
	media->fingerprint = m->fingerprint;
	media->fp_hash_func = m->fp_hash_func;
	media->tls_id = m->tls_id;
	codec_store_init(&media->codecs, m);
	codec_store_init(&media->offered_codecs, m);
	codec_store_copy(&media->codecs, &m->codecs);
	codec_store_copy(&media->offered_codecs, &m->offered_codecs);
	checkpoint_candidates_copy(&media->ice_candidates, &m->ice_candidates);
	if (m->ice_agent) {
		media->had_ice = true;
		memcpy(media->ice_ufrag, m->ice_agent->ufrag, sizeof(media->ice_ufrag));
		memcpy(media->ice_pwd, m->ice_agent->pwd, sizeof(media->ice_pwd));
	}
	media->ptime = m->ptime;
	media->maxptime = m->maxptime;
	media->bandwidth = m->sdp_media_bandwidth;
	for (__auto_type l = m->streams.head; l; l = l->next)
		checkpoint_take_stream(media, l->data);
	media->next = cp->medias;
	cp->medias = media;
}

static void checkpoint_take_monologue(struct call_checkpoint *cp, unsigned int idx,
		struct call_monologue *ml)
{
	struct checkpoint_monologue *snap = &cp->monologues[idx];
	snap->monologue = ml;
	snap->desired_family = ml->desired_family;
	snap->logical_intf = ml->logical_intf;
	snap->flags = atomic64_get_na(&ml->ml_flags);
	snap->bandwidth = ml->sdp_session_bandwidth;
	snap->sdp_orig_in = ml->sdp_orig_in;
	snap->sdp_orig_out = ml->sdp_orig_out;
	snap->session_name = ml->sdp_session_name;
	snap->session_timing = ml->sdp_session_timing;
	if (ml->last_out_sdp)
		snap->last_out_sdp = g_string_new_len(ml->last_out_sdp->str, ml->last_out_sdp->len);
	snap->medias_len = ml->medias->len;
	for (unsigned int i = 0; i < ml->medias->len; i++) {
		struct call_media *media = ml->medias->pdata[i];
		if (media)
			checkpoint_take_media(cp, media);
	}
}

uint64_t call_checkpoint_offer(call_t *call, struct call_monologue *offerer,
		struct call_monologue *answerer, bool enable)
{
	struct call_checkpoint *cp = checkpoint_find(call, offerer, answerer);
	if (!cp && !enable)
		return 0;
	if (!cp) {
		cp = g_new0(__typeof(*cp), 1);
		cp->next = call->checkpoints;
		call->checkpoints = cp;
	}
	/* Multiple offers can be outstanding before either an answer or rollback
	 * arrives. They all belong to the same uncommitted exchange, so retain the
	 * snapshot and generation of the last committed state. Replacing either
	 * here would make a later rollback restore state from an earlier rejected
	 * offer instead. */
	if (cp->pending)
		return cp->pending_generation;
	checkpoint_clear_snapshot(cp);
	cp->offerer = offerer;
	cp->answerer = answerer;
	cp->pending_generation = cp->generation + 1;
	checkpoint_take_monologue(cp, 0, offerer);
	checkpoint_take_monologue(cp, 1, answerer);
	cp->pending = true;
	return cp->pending_generation;
}

uint64_t call_checkpoint_answer(call_t *call, struct call_monologue *a,
		struct call_monologue *b, bool *enabled)
{
	struct call_checkpoint *cp = checkpoint_find(call, a, b);
	*enabled = cp != NULL;
	if (!cp)
		return 0;
	if (cp->pending) {
		cp->generation = cp->pending_generation;
		checkpoint_clear_snapshot(cp);
	}
	return cp->generation;
}

static void checkpoint_restore_stream(struct checkpoint_stream *snap) {
	struct packet_stream *ps = snap->stream;
	dtls_shutdown(ps);
	t_queue_clear_full(&ps->sfds, stream_fd_dec);
	for (__auto_type l = snap->sfds.head; l; l = l->next) {
		stream_fd *sfd = l->data;
		stream_fd_inc(sfd);
		t_queue_push_tail(&ps->sfds, sfd);
	}
	ps->selected_sfd = snap->selected_sfd;
	ps->endpoint = snap->endpoint;
	ps->advertised_endpoint = snap->advertised_endpoint;
	ps->learned_endpoint = snap->learned_endpoint;
	memcpy(ps->detected_endpoints, snap->detected_endpoints, sizeof(ps->detected_endpoints));
	ps->last_local_endpoint = snap->last_local_endpoint;
	ps->ep_detect_signal = snap->ep_detect_signal;
	ps->el_flags = snap->el_flags;
	atomic64_set_na(&ps->ps_flags, snap->flags);
}

static void checkpoint_restore_media(struct checkpoint_media *snap) {
	struct call_media *m = snap->media;
	m->protocol = snap->protocol;
	m->protocol_str = snap->protocol_str;
	m->format_str = snap->format_str;
	m->desired_family = snap->desired_family;
	m->logical_intf = snap->logical_intf;
	atomic64_set_na(&m->media_flags, snap->flags);
	crypto_params_sdes_queue_clear(&m->sdes_in);
	crypto_params_sdes_queue_clear(&m->sdes_out);
	crypto_params_sdes_queue_copy(&m->sdes_in, &snap->sdes_in);
	crypto_params_sdes_queue_copy(&m->sdes_out, &snap->sdes_out);
	m->fingerprint = snap->fingerprint;
	m->fp_hash_func = snap->fp_hash_func;
	m->tls_id = snap->tls_id;
	codec_store_copy(&m->codecs, &snap->codecs);
	codec_store_copy(&m->offered_codecs, &snap->offered_codecs);
	m->ptime = snap->ptime;
	m->maxptime = snap->maxptime;
	m->sdp_media_bandwidth = snap->bandwidth;
	ice_candidates_free(&m->ice_candidates);
	checkpoint_candidates_copy(&m->ice_candidates, &snap->ice_candidates);
	for (struct checkpoint_stream *stream = snap->streams; stream; stream = stream->next)
		checkpoint_restore_stream(stream);
	codec_handlers_free(m);
	if (snap->had_ice) {
		ice_agent_init(&m->ice_agent, m);
		ice_rollback(m->ice_agent, snap->ice_ufrag, snap->ice_pwd, &snap->ice_candidates);
	}
	else
		ice_shutdown(&m->ice_agent);
}

static void checkpoint_restore_monologue(struct checkpoint_monologue *snap) {
	struct call_monologue *ml = snap->monologue;
	for (unsigned int i = snap->medias_len; i < ml->medias->len; i++) {
		struct call_media *media = ml->medias->pdata[i];
		if (media)
			call_media_stop(media);
	}
	t_ptr_array_set_size(ml->medias, snap->medias_len);
	ml->desired_family = snap->desired_family;
	ml->logical_intf = snap->logical_intf;
	atomic64_set_na(&ml->ml_flags, snap->flags);
	ml->sdp_session_bandwidth = snap->bandwidth;
	ml->sdp_orig_in = snap->sdp_orig_in;
	ml->sdp_orig_out = snap->sdp_orig_out;
	ml->sdp_session_name = snap->session_name;
	ml->sdp_session_timing = snap->session_timing;
	if (ml->last_out_sdp)
		g_string_free(ml->last_out_sdp, TRUE);
	ml->last_out_sdp = snap->last_out_sdp
		? g_string_new_len(snap->last_out_sdp->str, snap->last_out_sdp->len) : NULL;
}

int call_checkpoint_rollback(call_t *call, struct call_monologue *a, struct call_monologue *b,
		uint64_t generation, bool generation_given, uint64_t *current_generation)
{
	struct call_checkpoint *cp = checkpoint_find(call, a, b);
	if (!cp) {
		*current_generation = 0;
		return 0;
	}
	*current_generation = cp->generation;
	if (!cp->pending || (generation_given && generation != cp->pending_generation))
		return 0;

	for (struct checkpoint_media *media = cp->medias; media; media = media->next)
		checkpoint_restore_media(media);
	for (unsigned int i = 0; i < G_N_ELEMENTS(cp->monologues); i++)
		checkpoint_restore_monologue(&cp->monologues[i]);
	update_init_monologue_subscribers(cp->offerer, OP_OFFER);
	update_init_monologue_subscribers(cp->answerer, OP_ANSWER);
	checkpoint_clear_snapshot(cp);
	call->last_signal_us = rtpe_now;
	return 1;
}


void call_checkpoint_free_all(call_t *call) {
	while (call->checkpoints) {
		struct call_checkpoint *cp = call->checkpoints;
		call->checkpoints = cp->next;
		checkpoint_free(cp);
	}
}
