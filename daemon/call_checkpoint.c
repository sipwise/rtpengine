#include "call_checkpoint.h"

#include "call.h"
#include "codec.h"
#include "dtls.h"
#include "ice.h"
#include "log_d.h"
#include "main.h"
#include "redis.h"

#include <json-glib/json-glib.h>

struct checkpoint_stream {
	struct checkpoint_stream *next;
	struct packet_stream *stream;
	stream_fd_q sfds;
	GArray *sfd_local_endpoints;
	stream_fd *selected_sfd;
	bool selected_sfd_set;
	bool redis_restored;
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
	struct endpoint_map *endpoint_map;
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

static void checkpoint_stream_free(struct checkpoint_stream *);
static void checkpoint_media_free(struct checkpoint_media *);
static void checkpoint_free(struct call_checkpoint *);

static void checkpoint_json_str(JsonBuilder *b, const char *name, const str *value) {
	json_builder_set_member_name(b, name);
	if (!value || !value->s) {
		json_builder_add_string_value(b, "");
		return;
	}
	g_autofree char *string = g_strndup(value->s, value->len);
	json_builder_add_string_value(b, string);
}

static void checkpoint_json_endpoint(JsonBuilder *b, const char *name, const endpoint_t *ep) {
	json_builder_set_member_name(b, name);
	json_builder_add_string_value(b, ep->address.family ? endpoint_print_buf(ep) : "");
}

static void checkpoint_json_bandwidth(JsonBuilder *b, const struct session_bandwidth *bw) {
	json_builder_set_member_name(b, "bandwidth");
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "as");
	json_builder_add_int_value(b, bw->as);
	json_builder_set_member_name(b, "ct");
	json_builder_add_int_value(b, bw->ct);
	json_builder_set_member_name(b, "rr");
	json_builder_add_int_value(b, bw->rr);
	json_builder_set_member_name(b, "rs");
	json_builder_add_int_value(b, bw->rs);
	json_builder_set_member_name(b, "tias");
	json_builder_add_int_value(b, bw->tias);
	json_builder_end_object(b);
}

static void checkpoint_json_origin(JsonBuilder *b, const char *name, const sdp_origin *o) {
	json_builder_set_member_name(b, name);
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "parsed");
	json_builder_add_boolean_value(b, o->parsed);
	json_builder_set_member_name(b, "version");
	json_builder_add_int_value(b, o->version_num);
	checkpoint_json_str(b, "username", &o->username);
	checkpoint_json_str(b, "session-id", &o->session_id);
	checkpoint_json_str(b, "network-type", &o->address.network_type);
	checkpoint_json_str(b, "address-type", &o->address.address_type);
	checkpoint_json_str(b, "address", &o->address.address);
	json_builder_end_object(b);
}

static void checkpoint_json_stream(JsonBuilder *b, const struct checkpoint_stream *s) {
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "stream-id");
	json_builder_add_int_value(b, s->stream->unique_id);
	json_builder_set_member_name(b, "selected-sfd-id");
	json_builder_add_int_value(b, s->selected_sfd ? s->selected_sfd->unique_id : -1);
	json_builder_set_member_name(b, "selected-interface-id");
	json_builder_add_int_value(b, s->selected_sfd ? s->selected_sfd->local_intf->unique_id : -1);
	json_builder_set_member_name(b, "flags");
	json_builder_add_int_value(b, s->flags);
	json_builder_set_member_name(b, "ep-detect-signal");
	json_builder_add_int_value(b, s->ep_detect_signal);
	json_builder_set_member_name(b, "el-flags");
	json_builder_add_int_value(b, s->el_flags);
	checkpoint_json_endpoint(b, "endpoint", &s->endpoint);
	checkpoint_json_endpoint(b, "advertised-endpoint", &s->advertised_endpoint);
	checkpoint_json_endpoint(b, "learned-endpoint", &s->learned_endpoint);
	checkpoint_json_endpoint(b, "last-local-endpoint", &s->last_local_endpoint);
	json_builder_set_member_name(b, "detected-endpoints");
	json_builder_begin_array(b);
	for (unsigned int i = 0; i < G_N_ELEMENTS(s->detected_endpoints); i++)
		json_builder_add_string_value(b, s->detected_endpoints[i].address.family
				? endpoint_print_buf(&s->detected_endpoints[i]) : "");
	json_builder_end_array(b);
	json_builder_set_member_name(b, "sfd-ids");
	json_builder_begin_array(b);
	for (__auto_type l = s->sfds.head; l; l = l->next)
		json_builder_add_int_value(b, ((stream_fd *) l->data)->unique_id);
	json_builder_end_array(b);
	json_builder_set_member_name(b, "sfd-local-endpoints");
	json_builder_begin_array(b);
	if (s->sfd_local_endpoints)
		for (unsigned int i = 0; i < s->sfd_local_endpoints->len; i++) {
			const endpoint_t *ep = &g_array_index(s->sfd_local_endpoints, endpoint_t, i);
			json_builder_add_string_value(b, ep->address.family ? endpoint_print_buf(ep) : "");
		}
	json_builder_end_array(b);
	json_builder_end_object(b);
}

static void checkpoint_json_monologue(JsonBuilder *b, const struct checkpoint_monologue *m) {
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "monologue-id");
	json_builder_add_int_value(b, m->monologue->unique_id);
	json_builder_set_member_name(b, "flags");
	json_builder_add_int_value(b, m->flags);
	json_builder_set_member_name(b, "medias-len");
	json_builder_add_int_value(b, m->medias_len);
	checkpoint_json_str(b, "desired-family",
			m->desired_family ? STR_PTR(m->desired_family->rfc_name) : NULL);
	checkpoint_json_str(b, "logical-interface",
			m->logical_intf ? &m->logical_intf->name : NULL);
	checkpoint_json_str(b, "session-name", &m->session_name);
	checkpoint_json_str(b, "session-timing", &m->session_timing);
	str last_sdp = m->last_out_sdp ? STR_LEN(m->last_out_sdp->str, m->last_out_sdp->len) : STR_NULL;
	checkpoint_json_str(b, "last-out-sdp", &last_sdp);
	checkpoint_json_bandwidth(b, &m->bandwidth);
	checkpoint_json_origin(b, "origin-in", &m->sdp_orig_in);
	checkpoint_json_origin(b, "origin-out", &m->sdp_orig_out);
	json_builder_end_object(b);
}

static void checkpoint_json_candidates(JsonBuilder *b, const candidate_q *q) {
	json_builder_set_member_name(b, "ice-candidates");
	json_builder_begin_array(b);
	for (__auto_type l = q->head; l; l = l->next) {
		const struct ice_candidate *c = l->data;
		json_builder_begin_object(b);
		checkpoint_json_str(b, "foundation", &c->foundation);
		json_builder_set_member_name(b, "component");
		json_builder_add_int_value(b, c->component_id);
		checkpoint_json_str(b, "transport", c->transport ? STR_PTR(c->transport->name) : NULL);
		json_builder_set_member_name(b, "priority");
		json_builder_add_int_value(b, c->priority);
		checkpoint_json_endpoint(b, "endpoint", &c->endpoint);
		json_builder_set_member_name(b, "type");
		json_builder_add_int_value(b, c->type);
		checkpoint_json_endpoint(b, "related", &c->related);
		checkpoint_json_str(b, "ufrag", &c->ufrag);
		json_builder_end_object(b);
	}
	json_builder_end_array(b);
}

static void checkpoint_json_media(JsonBuilder *b, const struct checkpoint_media *m) {
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "media-id");
	json_builder_add_int_value(b, m->media->unique_id);
	json_builder_set_member_name(b, "endpoint-map-id");
	json_builder_add_int_value(b, m->endpoint_map ? m->endpoint_map->unique_id : -1);
	json_builder_set_member_name(b, "flags");
	json_builder_add_int_value(b, m->flags);
	json_builder_set_member_name(b, "ptime");
	json_builder_add_int_value(b, m->ptime);
	json_builder_set_member_name(b, "maxptime");
	json_builder_add_int_value(b, m->maxptime);
	json_builder_set_member_name(b, "had-ice");
	json_builder_add_boolean_value(b, m->had_ice);
	checkpoint_json_str(b, "protocol", m->protocol ? STR_PTR(m->protocol->name) : &m->protocol_str);
	checkpoint_json_str(b, "protocol-string", &m->protocol_str);
	checkpoint_json_str(b, "format-string", &m->format_str);
	checkpoint_json_str(b, "desired-family",
			m->desired_family ? STR_PTR(m->desired_family->rfc_name) : NULL);
	checkpoint_json_str(b, "logical-interface",
			m->logical_intf ? &m->logical_intf->name : NULL);
	checkpoint_json_str(b, "tls-id", &m->tls_id);
	checkpoint_json_str(b, "ice-ufrag-local", &m->ice_ufrag[0]);
	checkpoint_json_str(b, "ice-ufrag-remote", &m->ice_ufrag[1]);
	checkpoint_json_str(b, "ice-pwd-local", &m->ice_pwd[0]);
	checkpoint_json_str(b, "ice-pwd-remote", &m->ice_pwd[1]);
	checkpoint_json_bandwidth(b, &m->bandwidth);
	checkpoint_json_candidates(b, &m->ice_candidates);
	ng_parser_ctx_t crypto_ctx;
	ng_parser_json.init(&crypto_ctx, NULL);
	parser_arg crypto = ng_parser_json.dict(&crypto_ctx);
	redis_encode_sdes_params(&ng_parser_json, crypto, "sdes_in", &m->sdes_in);
	redis_encode_sdes_params(&ng_parser_json, crypto, "sdes_out", &m->sdes_out);
	redis_encode_dtls_fingerprint(&ng_parser_json, crypto, &m->fingerprint);
	if (m->fp_hash_func)
		ng_parser_json.dict_add_string(crypto, "preferred_hash_func", m->fp_hash_func->name);
	json_builder_set_member_name(b, "crypto");
	json_builder_add_value(b, crypto.json);
	parser_arg codecs = ng_parser_json.list(&crypto_ctx);
	redis_encode_codec_store(&ng_parser_json, codecs, &m->codecs);
	json_builder_set_member_name(b, "codecs");
	json_builder_add_value(b, codecs.json);
	parser_arg offered_codecs = ng_parser_json.list(&crypto_ctx);
	redis_encode_codec_store(&ng_parser_json, offered_codecs, &m->offered_codecs);
	json_builder_set_member_name(b, "offered-codecs");
	json_builder_add_value(b, offered_codecs.json);
	json_builder_set_member_name(b, "streams");
	json_builder_begin_array(b);
	for (const struct checkpoint_stream *s = m->streams; s; s = s->next)
		checkpoint_json_stream(b, s);
	json_builder_end_array(b);
	json_builder_end_object(b);
}

str call_checkpoint_serialize(call_t *call, void **to_free) {
	*to_free = NULL;
	if (!call->checkpoints)
		return STR_NULL;

	JsonBuilder *b = json_builder_new();
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "version");
	json_builder_add_int_value(b, 1);
	json_builder_set_member_name(b, "checkpoints");
	json_builder_begin_array(b);
	for (const struct call_checkpoint *cp = call->checkpoints; cp; cp = cp->next) {
		json_builder_begin_object(b);
		json_builder_set_member_name(b, "offerer-id");
		json_builder_add_int_value(b, cp->offerer->unique_id);
		json_builder_set_member_name(b, "answerer-id");
		json_builder_add_int_value(b, cp->answerer->unique_id);
		json_builder_set_member_name(b, "generation");
		json_builder_add_int_value(b, cp->generation);
		json_builder_set_member_name(b, "pending-generation");
		json_builder_add_int_value(b, cp->pending_generation);
		json_builder_set_member_name(b, "pending");
		json_builder_add_boolean_value(b, cp->pending);
		if (cp->pending) {
			json_builder_set_member_name(b, "monologues");
			json_builder_begin_array(b);
			for (unsigned int i = 0; i < G_N_ELEMENTS(cp->monologues); i++)
				checkpoint_json_monologue(b, &cp->monologues[i]);
			json_builder_end_array(b);
			json_builder_set_member_name(b, "medias");
			json_builder_begin_array(b);
			for (const struct checkpoint_media *m = cp->medias; m; m = m->next)
				checkpoint_json_media(b, m);
			json_builder_end_array(b);
		}
		json_builder_end_object(b);
	}
	json_builder_end_array(b);
	json_builder_end_object(b);

	JsonGenerator *g = json_generator_new();
	JsonNode *root = json_builder_get_root(b);
	json_generator_set_root(g, root);
	gsize len = 0;
	char *data = json_generator_to_data(g, &len);
	json_node_free(root);
	g_object_unref(g);
	g_object_unref(b);
	*to_free = data;
	return STR_LEN(data, len);
}

static struct call_monologue *checkpoint_find_monologue_id(call_t *call, unsigned int id) {
	for (__auto_type l = call->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		if (ml->unique_id == id)
			return ml;
	}
	return NULL;
}

static struct call_media *checkpoint_find_media_id(call_t *call, unsigned int id) {
	for (__auto_type l = call->medias.head; l; l = l->next) {
		struct call_media *m = l->data;
		if (m->unique_id == id)
			return m;
	}
	return NULL;
}

static struct packet_stream *checkpoint_find_stream_id(call_t *call, unsigned int id) {
	for (__auto_type l = call->streams.head; l; l = l->next) {
		struct packet_stream *s = l->data;
		if (s->unique_id == id)
			return s;
	}
	return NULL;
}

static stream_fd *checkpoint_find_sfd_id(call_t *call, unsigned int id) {
	for (__auto_type l = call->stream_fds.head; l; l = l->next) {
		stream_fd *sfd = l->data;
		if (sfd->unique_id == id)
			return sfd;
	}
	return NULL;
}

static struct endpoint_map *checkpoint_find_endpoint_map_id(call_t *call, unsigned int id) {
	for (__auto_type l = call->endpoint_maps.head; l; l = l->next) {
		struct endpoint_map *map = l->data;
		if (map->unique_id == id)
			return map;
	}
	return NULL;
}

static bool checkpoint_json_value_is(JsonObject *o, const char *name, GType type) {
	JsonNode *node = o ? json_object_get_member(o, name) : NULL;
	return node && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == type;
}

static bool checkpoint_json_int(JsonObject *o, const char *name) {
	return checkpoint_json_value_is(o, name, G_TYPE_INT64);
}

static bool checkpoint_json_bool(JsonObject *o, const char *name) {
	return checkpoint_json_value_is(o, name, G_TYPE_BOOLEAN);
}

static bool checkpoint_json_string(JsonObject *o, const char *name) {
	return checkpoint_json_value_is(o, name, G_TYPE_STRING);
}

static bool checkpoint_json_object(JsonObject *o, const char *name) {
	JsonNode *node = o ? json_object_get_member(o, name) : NULL;
	return node && JSON_NODE_HOLDS_OBJECT(node);
}

static bool checkpoint_json_array(JsonObject *o, const char *name) {
	JsonNode *node = o ? json_object_get_member(o, name) : NULL;
	return node && JSON_NODE_HOLDS_ARRAY(node);
}

static JsonObject *checkpoint_json_array_object(JsonArray *array, unsigned int index) {
	JsonNode *node = array ? json_array_get_element(array, index) : NULL;
	return node && JSON_NODE_HOLDS_OBJECT(node) ? json_node_get_object(node) : NULL;
}

static str checkpoint_json_call_str(call_t *call, JsonObject *o, const char *name) {
	const char *s = json_object_get_string_member(o, name);
	str value = STR(s);
	return call_str_cpy(&value);
}

static int checkpoint_json_get_endpoint(endpoint_t *ep, JsonObject *o, const char *name) {
	if (!checkpoint_json_string(o, name))
		return -1;
	const char *value = json_object_get_string_member(o, name);
	if (!value[0]) {
		ZERO(*ep);
		return 0;
	}
	return endpoint_parse_any(ep, value) ? 0 : -1;
}

static int checkpoint_json_parse_endpoint(endpoint_t *ep, const char *value) {
	if (!value[0]) {
		ZERO(*ep);
		return 0;
	}
	return endpoint_parse_any(ep, value) ? 0 : -1;
}

static int checkpoint_json_get_bandwidth(struct session_bandwidth *bw, JsonObject *o) {
	if (!checkpoint_json_object(o, "bandwidth"))
		return -1;
	JsonObject *b = json_object_get_object_member(o, "bandwidth");
	if (!checkpoint_json_int(b, "as") || !checkpoint_json_int(b, "ct")
			|| !checkpoint_json_int(b, "rr") || !checkpoint_json_int(b, "rs")
			|| !checkpoint_json_int(b, "tias"))
		return -1;
	bw->as = json_object_get_int_member(b, "as");
	bw->ct = json_object_get_int_member(b, "ct");
	bw->rr = json_object_get_int_member(b, "rr");
	bw->rs = json_object_get_int_member(b, "rs");
	bw->tias = json_object_get_int_member(b, "tias");
	return 0;
}

static int checkpoint_json_get_origin(call_t *call, sdp_origin *origin, JsonObject *o,
		const char *name)
{
	if (!checkpoint_json_object(o, name))
		return -1;
	JsonObject *v = json_object_get_object_member(o, name);
	if (!checkpoint_json_bool(v, "parsed") || !checkpoint_json_int(v, "version")
			|| !checkpoint_json_string(v, "username")
			|| !checkpoint_json_string(v, "session-id")
			|| !checkpoint_json_string(v, "network-type")
			|| !checkpoint_json_string(v, "address-type")
			|| !checkpoint_json_string(v, "address"))
		return -1;
	origin->parsed = json_object_get_boolean_member(v, "parsed");
	origin->version_num = json_object_get_int_member(v, "version");
	origin->username = checkpoint_json_call_str(call, v, "username");
	origin->session_id = checkpoint_json_call_str(call, v, "session-id");
	origin->address.network_type = checkpoint_json_call_str(call, v, "network-type");
	origin->address.address_type = checkpoint_json_call_str(call, v, "address-type");
	origin->address.address = checkpoint_json_call_str(call, v, "address");
	return 0;
}

static stream_fd *checkpoint_reopen_sfd(call_t *call, stream_fd *old, const endpoint_t *local,
		struct endpoint_map *map)
{
	if (!local->address.family || !local->port || old->socket.local.port)
		return old;
	stream_fd *existing = stream_fd_lookup(local);
	stream_fd *replacement;
	if (existing) {
		obj_release(existing);
		replacement = existing;
	}
	else {
		struct socket_port_link spl = get_specific_port(local->port, old->local_intf->spec,
				&call->callid);
		if (!spl.socket.family)
			return NULL;
		set_tos(&spl.socket, call->tos);
		replacement = stream_fd_new(&spl, call, old->local_intf);
	}
	for (__auto_type l = map ? map->intf_sfds.head : NULL; l; l = l->next) {
		struct sfd_intf_list *il = l->data;
		for (__auto_type k = il->list.head; k; k = k->next)
			if (k->data == old) {
				stream_fd_inc(replacement);
				k->data = replacement;
				stream_fd_dec(old);
			}
	}
	return replacement;
}

static struct checkpoint_stream *checkpoint_json_get_stream(call_t *call, JsonObject *o,
		struct endpoint_map *map)
{
	const char *integers[] = { "stream-id", "selected-sfd-id", "selected-interface-id",
		"flags", "ep-detect-signal", "el-flags" };
	for (unsigned int i = 0; i < G_N_ELEMENTS(integers); i++)
		if (!checkpoint_json_int(o, integers[i]))
			return NULL;
	if (!checkpoint_json_array(o, "detected-endpoints")
			|| !checkpoint_json_array(o, "sfd-ids")
			|| !checkpoint_json_array(o, "sfd-local-endpoints"))
		return NULL;

	struct packet_stream *ps = checkpoint_find_stream_id(call,
			json_object_get_int_member(o, "stream-id"));
	if (!ps)
		return NULL;
	struct checkpoint_stream *s = g_new0(__typeof(*s), 1);
	s->stream = ps;
	s->redis_restored = true;
	s->flags = json_object_get_int_member(o, "flags");
	s->ep_detect_signal = json_object_get_int_member(o, "ep-detect-signal");
	s->el_flags = json_object_get_int_member(o, "el-flags");
	if (checkpoint_json_get_endpoint(&s->endpoint, o, "endpoint")
			|| checkpoint_json_get_endpoint(&s->advertised_endpoint, o, "advertised-endpoint")
			|| checkpoint_json_get_endpoint(&s->learned_endpoint, o, "learned-endpoint")
			|| checkpoint_json_get_endpoint(&s->last_local_endpoint, o, "last-local-endpoint"))
		goto err;

	JsonArray *detected = json_object_get_array_member(o, "detected-endpoints");
	if (!detected || json_array_get_length(detected) != G_N_ELEMENTS(s->detected_endpoints))
		goto err;
	for (unsigned int i = 0; i < G_N_ELEMENTS(s->detected_endpoints); i++) {
		JsonNode *element = json_array_get_element(detected, i);
		if (!element || !JSON_NODE_HOLDS_VALUE(element)
				|| json_node_get_value_type(element) != G_TYPE_STRING
				|| checkpoint_json_parse_endpoint(&s->detected_endpoints[i],
					json_node_get_string(element)))
			goto err;
	}

	JsonArray *sfds = json_object_get_array_member(o, "sfd-ids");
	JsonArray *locals = json_object_get_array_member(o, "sfd-local-endpoints");
	if (!sfds || !locals || json_array_get_length(sfds) != json_array_get_length(locals))
		goto err;
	gint64 selected = json_object_get_int_member(o, "selected-sfd-id");
	s->selected_sfd_set = selected >= 0;
	s->sfd_local_endpoints = g_array_new(FALSE, FALSE, sizeof(endpoint_t));
	for (unsigned int i = 0; i < json_array_get_length(sfds); i++) {
		JsonNode *sfd_node = json_array_get_element(sfds, i);
		JsonNode *local_node = json_array_get_element(locals, i);
		if (!sfd_node || !JSON_NODE_HOLDS_VALUE(sfd_node)
				|| json_node_get_value_type(sfd_node) != G_TYPE_INT64
				|| !local_node || !JSON_NODE_HOLDS_VALUE(local_node)
				|| json_node_get_value_type(local_node) != G_TYPE_STRING)
			goto err;
		gint64 sfd_id = json_node_get_int(sfd_node);
		stream_fd *old = checkpoint_find_sfd_id(call, sfd_id);
		endpoint_t local;
		if (!old || checkpoint_json_parse_endpoint(&local,
					json_node_get_string(local_node)))
			goto err;
		stream_fd *sfd = checkpoint_reopen_sfd(call, old, &local, map);
		if (!sfd)
			goto err;
		stream_fd_inc(sfd);
		t_queue_push_tail(&s->sfds, sfd);
		g_array_append_val(s->sfd_local_endpoints, local);
		if (sfd_id == selected)
			s->selected_sfd = sfd;
	}
	if (selected >= 0 && !s->selected_sfd)
		goto err;
	return s;

err:
	checkpoint_stream_free(s);
	return NULL;
}

static int checkpoint_json_get_monologue(call_t *call, struct checkpoint_monologue *m,
		JsonObject *o)
{
	const char *integers[] = { "monologue-id", "flags", "medias-len" };
	const char *strings[] = { "desired-family", "logical-interface", "session-name",
		"session-timing", "last-out-sdp" };
	for (unsigned int i = 0; i < G_N_ELEMENTS(integers); i++)
		if (!checkpoint_json_int(o, integers[i]))
			return -1;
	for (unsigned int i = 0; i < G_N_ELEMENTS(strings); i++)
		if (!checkpoint_json_string(o, strings[i]))
			return -1;
	m->monologue = checkpoint_find_monologue_id(call,
			json_object_get_int_member(o, "monologue-id"));
	if (!m->monologue)
		return -1;
	m->flags = json_object_get_int_member(o, "flags");
	m->medias_len = json_object_get_int_member(o, "medias-len");
	str family = STR(json_object_get_string_member(o, "desired-family"));
	m->desired_family = family.len ? get_socket_family_rfc(&family) : NULL;
	str intf = STR(json_object_get_string_member(o, "logical-interface"));
	m->logical_intf = intf.len ? get_logical_interface(&intf, m->desired_family, 0) : NULL;
	if ((family.len && !m->desired_family) || (intf.len && !m->logical_intf))
		return -1;
	m->session_name = checkpoint_json_call_str(call, o, "session-name");
	m->session_timing = checkpoint_json_call_str(call, o, "session-timing");
	const char *last_sdp = json_object_get_string_member(o, "last-out-sdp");
	if (*last_sdp)
		m->last_out_sdp = g_string_new(last_sdp);
	if (checkpoint_json_get_bandwidth(&m->bandwidth, o)
			|| checkpoint_json_get_origin(call, &m->sdp_orig_in, o, "origin-in")
			|| checkpoint_json_get_origin(call, &m->sdp_orig_out, o, "origin-out"))
		return -1;
	return 0;
}

static int checkpoint_json_get_candidates(call_t *call, candidate_q *q, JsonObject *o) {
	if (!checkpoint_json_array(o, "ice-candidates"))
		return -1;
	JsonArray *array = json_object_get_array_member(o, "ice-candidates");
	if (!array)
		return -1;
	for (unsigned int i = 0; i < json_array_get_length(array); i++) {
		JsonObject *v = checkpoint_json_array_object(array, i);
		const char *integers[] = { "component", "priority", "type" };
		const char *strings[] = { "foundation", "transport", "endpoint", "related", "ufrag" };
		for (unsigned int j = 0; j < G_N_ELEMENTS(integers); j++)
			if (!checkpoint_json_int(v, integers[j]))
				goto err;
		for (unsigned int j = 0; j < G_N_ELEMENTS(strings); j++)
			if (!checkpoint_json_string(v, strings[j]))
				goto err;
		struct ice_candidate *c = g_new0(__typeof(*c), 1);
		c->foundation = checkpoint_json_call_str(call, v, "foundation");
		c->component_id = json_object_get_int_member(v, "component");
		str transport = STR(json_object_get_string_member(v, "transport"));
		c->transport = transport.len ? get_socket_type(&transport) : NULL;
		c->priority = json_object_get_int_member(v, "priority");
		gint64 type = json_object_get_int_member(v, "type");
		if (!c->transport || type <= ICT_UNKNOWN || type >= __ICT_LAST
				|| checkpoint_json_get_endpoint(&c->endpoint, v, "endpoint")
				|| checkpoint_json_get_endpoint(&c->related, v, "related")) {
			g_free(c);
			goto err;
		}
		c->type = type;
		c->ufrag = checkpoint_json_call_str(call, v, "ufrag");
		t_queue_push_tail(q, c);
	}
	return 0;

err:
	ice_candidates_free(q);
	return -1;
}

static struct checkpoint_media *checkpoint_json_get_media(call_t *call, JsonObject *o) {
	const char *stage = "required fields";
	const char *integers[] = { "media-id", "endpoint-map-id", "flags", "ptime", "maxptime" };
	const char *strings[] = { "protocol", "protocol-string", "format-string", "desired-family",
		"logical-interface", "tls-id", "ice-ufrag-local", "ice-ufrag-remote",
		"ice-pwd-local", "ice-pwd-remote" };
	for (unsigned int i = 0; i < G_N_ELEMENTS(integers); i++)
		if (!checkpoint_json_int(o, integers[i]))
			return NULL;
	for (unsigned int i = 0; i < G_N_ELEMENTS(strings); i++)
		if (!checkpoint_json_string(o, strings[i]))
			return NULL;
	if (!checkpoint_json_bool(o, "had-ice") || !checkpoint_json_object(o, "crypto")
			|| !checkpoint_json_array(o, "codecs")
			|| !checkpoint_json_array(o, "offered-codecs")
			|| !checkpoint_json_array(o, "streams"))
		return NULL;
	struct call_media *live = checkpoint_find_media_id(call,
			json_object_get_int_member(o, "media-id"));
	if (!live)
		return NULL;
	struct checkpoint_media *m = g_new0(__typeof(*m), 1);
	m->media = live;
	gint64 endpoint_map_id = json_object_get_int_member(o, "endpoint-map-id");
	if (endpoint_map_id >= 0
			&& !(m->endpoint_map = checkpoint_find_endpoint_map_id(call, endpoint_map_id)))
		goto err;
	codec_store_init(&m->codecs, live);
	codec_store_init(&m->offered_codecs, live);
	m->flags = json_object_get_int_member(o, "flags");
	m->ptime = json_object_get_int_member(o, "ptime");
	m->maxptime = json_object_get_int_member(o, "maxptime");
	m->had_ice = json_object_get_boolean_member(o, "had-ice");
	str protocol = STR(json_object_get_string_member(o, "protocol"));
	m->protocol = protocol.len ? transport_protocol(&protocol) : NULL;
	if (protocol.len && !m->protocol)
		goto err;
	m->protocol_str = checkpoint_json_call_str(call, o, "protocol-string");
	m->format_str = checkpoint_json_call_str(call, o, "format-string");
	str family = STR(json_object_get_string_member(o, "desired-family"));
	m->desired_family = family.len ? get_socket_family_rfc(&family) : NULL;
	str intf = STR(json_object_get_string_member(o, "logical-interface"));
	m->logical_intf = intf.len ? get_logical_interface(&intf, m->desired_family, 0) : NULL;
	if ((family.len && !m->desired_family) || (intf.len && !m->logical_intf))
		goto err;
	m->tls_id = checkpoint_json_call_str(call, o, "tls-id");
	m->ice_ufrag[0] = checkpoint_json_call_str(call, o, "ice-ufrag-local");
	m->ice_ufrag[1] = checkpoint_json_call_str(call, o, "ice-ufrag-remote");
	m->ice_pwd[0] = checkpoint_json_call_str(call, o, "ice-pwd-local");
	m->ice_pwd[1] = checkpoint_json_call_str(call, o, "ice-pwd-remote");
	stage = "bandwidth";
	if (checkpoint_json_get_bandwidth(&m->bandwidth, o))
		goto err;
	stage = "ICE candidates";
	if (checkpoint_json_get_candidates(call, &m->ice_candidates, o))
		goto err;
	stage = "crypto object";
	JsonNode *crypto_node = json_object_get_member(o, "crypto");
	struct redis_hash crypto = {0};
	parser_arg crypto_arg = { .json = crypto_node };
	if (redis_hash_from_parser(&crypto, &ng_parser_json, crypto_arg))
		goto err;
	stage = "crypto parameters";
	int crypto_ret = redis_decode_sdes_params(&m->sdes_in, &crypto, "sdes_in")
		|| redis_decode_sdes_params(&m->sdes_out, &crypto, "sdes_out")
		|| redis_decode_dtls_fingerprint(&m->fingerprint, &crypto);
	str *preferred = g_hash_table_lookup(crypto.ht, "preferred_hash_func");
	if (preferred)
		m->fp_hash_func = dtls_find_hash_func(preferred);
	if (preferred && !m->fp_hash_func)
		crypto_ret = -1;
	redis_hash_destroy(&crypto);
	if (crypto_ret)
		goto err;
	stage = "codec objects";
	JsonNode *codecs_node = json_object_get_member(o, "codecs");
	JsonNode *offered_node = json_object_get_member(o, "offered-codecs");
	parser_arg codecs_arg = { .json = codecs_node };
	parser_arg offered_arg = { .json = offered_node };
	stage = "codec stores";
	if (redis_decode_codec_store(&ng_parser_json, codecs_arg, &m->codecs)
			|| redis_decode_codec_store(&ng_parser_json, offered_arg, &m->offered_codecs))
		goto err;
	JsonArray *streams = json_object_get_array_member(o, "streams");
	stage = "streams array";
	stage = "stream state";
	for (unsigned int i = 0; i < json_array_get_length(streams); i++) {
		struct checkpoint_stream *s = checkpoint_json_get_stream(call,
				checkpoint_json_array_object(streams, i), m->endpoint_map);
		if (!s)
			goto err;
		s->next = m->streams;
		m->streams = s;
	}
	return m;

err:
	ilog(LOG_WARNING, "Failed to restore checkpoint media at %s", stage);
	checkpoint_media_free(m);
	return NULL;
}

int call_checkpoint_deserialize(call_t *call, const str *data) {
	const char *stage = "JSON document";
	JsonParser *parser = json_parser_new();
	GError *error = NULL;
	struct call_checkpoint *head = NULL;
	if (!json_parser_load_from_data(parser, data->s, data->len, &error))
		goto err;
	JsonNode *node = json_parser_get_root(parser);
	if (!node || !JSON_NODE_HOLDS_OBJECT(node))
		goto err;
	JsonObject *root = json_node_get_object(node);
	stage = "root object";
	if (!checkpoint_json_int(root, "version")
			|| json_object_get_int_member(root, "version") != 1
			|| !checkpoint_json_array(root, "checkpoints"))
		goto err;
	JsonArray *checkpoints = json_object_get_array_member(root, "checkpoints");
	if (!checkpoints)
		goto err;
	for (unsigned int i = 0; i < json_array_get_length(checkpoints); i++) {
		stage = "checkpoint fields";
		JsonObject *o = checkpoint_json_array_object(checkpoints, i);
		const char *integers[] = { "offerer-id", "answerer-id", "generation",
			"pending-generation" };
		for (unsigned int j = 0; j < G_N_ELEMENTS(integers); j++)
			if (!checkpoint_json_int(o, integers[j]))
				goto err;
		if (!checkpoint_json_bool(o, "pending"))
			goto err;
		struct call_checkpoint *cp = g_new0(__typeof(*cp), 1);
		cp->offerer = checkpoint_find_monologue_id(call,
				json_object_get_int_member(o, "offerer-id"));
		cp->answerer = checkpoint_find_monologue_id(call,
				json_object_get_int_member(o, "answerer-id"));
		if (!cp->offerer || !cp->answerer) {
			stage = "checkpoint monologue IDs";
			g_free(cp);
			goto err;
		}
		cp->generation = json_object_get_int_member(o, "generation");
		cp->pending_generation = json_object_get_int_member(o, "pending-generation");
		cp->pending = json_object_get_boolean_member(o, "pending");
		cp->next = head;
		head = cp;
		if (!cp->pending)
			continue;
		stage = "pending checkpoint fields";
		if (!checkpoint_json_array(o, "monologues")
				|| !checkpoint_json_array(o, "medias"))
			goto err;
		JsonArray *monologues = json_object_get_array_member(o, "monologues");
		if (!monologues || json_array_get_length(monologues) != G_N_ELEMENTS(cp->monologues))
			goto err;
		for (unsigned int j = 0; j < G_N_ELEMENTS(cp->monologues); j++)
			if (checkpoint_json_get_monologue(call, &cp->monologues[j],
						checkpoint_json_array_object(monologues, j))) {
				stage = "monologue state";
				goto err;
			}
		stage = "media array";
		JsonArray *medias = json_object_get_array_member(o, "medias");
		if (!medias)
			goto err;
		for (unsigned int j = 0; j < json_array_get_length(medias); j++) {
			stage = "media state";
			struct checkpoint_media *m = checkpoint_json_get_media(call,
					checkpoint_json_array_object(medias, j));
			if (!m)
				goto err;
			m->next = cp->medias;
			cp->medias = m;
		}
	}
	call_checkpoint_free_all(call);
	call->checkpoints = head;
	if (error)
		g_error_free(error);
	g_object_unref(parser);
	return 0;

err:
	ilog(LOG_WARNING, "Failed to deserialize checkpoint data at %s", stage);
	while (head) {
		struct call_checkpoint *cp = head;
		head = cp->next;
		checkpoint_free(cp);
	}
	if (error)
		g_error_free(error);
	g_object_unref(parser);
	return -1;
}

static void checkpoint_candidates_copy(candidate_q *dst, const candidate_q *src) {
	for (__auto_type l = src->head; l; l = l->next) {
		struct ice_candidate *copy = g_new(__typeof(*copy), 1);
		*copy = *(struct ice_candidate *) l->data;
		t_queue_push_tail(dst, copy);
	}
}
static void checkpoint_stream_free(struct checkpoint_stream *stream) {
	t_queue_clear_full(&stream->sfds, stream_fd_dec);
	if (stream->sfd_local_endpoints)
		g_array_free(stream->sfd_local_endpoints, TRUE);
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
	stream->selected_sfd_set = ps->selected_sfd != NULL;
	stream->sfd_local_endpoints = g_array_new(FALSE, FALSE, sizeof(endpoint_t));
	for (__auto_type l = ps->sfds.head; l; l = l->next) {
		stream_fd *sfd = l->data;
		stream_fd_inc(sfd);
		t_queue_push_tail(&stream->sfds, sfd);
		g_array_append_val(stream->sfd_local_endpoints, sfd->socket.local);
	}
	stream->next = media->streams;
	media->streams = stream;
}

static void checkpoint_take_media(struct call_checkpoint *cp, struct call_media *m) {
	struct checkpoint_media *media = g_new0(__typeof(*media), 1);
	media->media = m;
	media->endpoint_map = m->endpoint_map;
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
	/* A Redis-restored snapshot can refer to an SFD that existed on the old
	 * instance but could not be rebound there, while normal call restoration
	 * has already selected a usable local socket on this instance. Keep that
	 * live binding. For in-process rollback, retain it only when it is the
	 * socket captured by the snapshot. */
	bool preserve_live_binding = ps->selected_sfd && ps->selected_sfd->socket.local.port
		&& (ps->selected_sfd == snap->selected_sfd
				|| (snap->selected_sfd_set
					&& (!snap->selected_sfd || !snap->selected_sfd->socket.local.port)));
	if (!preserve_live_binding) {
		t_queue_clear_full(&ps->sfds, stream_fd_dec);
		for (__auto_type l = snap->sfds.head; l; l = l->next) {
			stream_fd *sfd = l->data;
			stream_fd_inc(sfd);
			t_queue_push_tail(&ps->sfds, sfd);
		}
		ps->selected_sfd = snap->selected_sfd;
	}
	ps->endpoint = snap->endpoint;
	ps->advertised_endpoint = snap->advertised_endpoint;
	ps->learned_endpoint = snap->learned_endpoint;
	memcpy(ps->detected_endpoints, snap->detected_endpoints, sizeof(ps->detected_endpoints));
	ps->last_local_endpoint = snap->last_local_endpoint;
	ps->ep_detect_signal = snap->ep_detect_signal;
	ps->el_flags = snap->el_flags;
	atomic64_set_na(&ps->ps_flags, snap->flags);
}

static bool checkpoint_endpoint_map_is_bound(const struct endpoint_map *map) {
	if (!map)
		return false;
	for (__auto_type l = map->intf_sfds.head; l; l = l->next) {
		struct sfd_intf_list *il = l->data;
		for (__auto_type k = il->list.head; k; k = k->next) {
			stream_fd *sfd = k->data;
			if (sfd->socket.local.port)
				return true;
		}
	}
	return false;
}

static struct endpoint_map *checkpoint_live_endpoint_map(struct call_media *media) {
	for (__auto_type l = media->endpoint_maps.head; l; l = l->next) {
		struct endpoint_map *map = l->data;
		for (__auto_type k = map->intf_sfds.head; k; k = k->next) {
			struct sfd_intf_list *il = k->data;
			for (__auto_type n = il->list.head; n; n = n->next) {
				stream_fd *sfd = n->data;
				for (__auto_type p = media->streams.head; p; p = p->next)
					if (((struct packet_stream *) p->data)->selected_sfd == sfd)
						return map;
			}
		}
	}
	return NULL;
}

static void checkpoint_prepare_live_bindings(struct checkpoint_media *snap) {
	struct endpoint_map *live_map = checkpoint_live_endpoint_map(snap->media);
	bool used_live_binding = false;
	for (struct checkpoint_stream *stream = snap->streams; stream; stream = stream->next) {
		struct packet_stream *ps = stream->stream;
		if (!stream->redis_restored || !stream->selected_sfd_set
				|| (stream->selected_sfd && stream->selected_sfd->socket.local.port)
				|| !ps->selected_sfd || !ps->selected_sfd->socket.local.port)
			continue;
		t_queue_clear_full(&stream->sfds, stream_fd_dec);
		for (__auto_type l = ps->sfds.head; l; l = l->next) {
			stream_fd *sfd = l->data;
			stream_fd_inc(sfd);
			t_queue_push_tail(&stream->sfds, sfd);
		}
		stream->selected_sfd = ps->selected_sfd;
		used_live_binding = true;
	}
	if (used_live_binding && live_map)
		snap->endpoint_map = live_map;
}

static void checkpoint_restore_media(struct checkpoint_media *snap) {
	struct call_media *m = snap->media;
	struct endpoint_map *live_map = checkpoint_live_endpoint_map(m);
	m->endpoint_map = checkpoint_endpoint_map_is_bound(snap->endpoint_map)
		? snap->endpoint_map : live_map;
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
		checkpoint_prepare_live_bindings(media);
	for (struct checkpoint_media *media = cp->medias; media; media = media->next)
		checkpoint_restore_media(media);
	for (unsigned int i = 0; i < G_N_ELEMENTS(cp->monologues); i++)
		checkpoint_restore_monologue(&cp->monologues[i]);
	update_init_monologue_subscribers(cp->offerer, OP_OFFER);
	update_init_monologue_subscribers(cp->answerer, OP_ANSWER);
	for (struct checkpoint_media *media = cp->medias; media; media = media->next)
		for (struct checkpoint_stream *stream = media->streams; stream; stream = stream->next)
		{
			checkpoint_restore_stream(stream);
			__init_stream(stream->stream);
		}
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
