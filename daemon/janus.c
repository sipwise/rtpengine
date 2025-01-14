#include "janus.h"

#include <json-glib/json-glib.h>
#include <stdbool.h>

#include "websocket.h"
#include "log.h"
#include "main.h"
#include "obj.h"
#include "call.h"
#include "sdp.h"
#include "call_interfaces.h"
#include "rtplib.h"
#include "ice.h"
#include "log_funcs.h"

TYPED_GHASHTABLE(janus_handles_set, uint64_t, void, int64_hash, int64_eq, NULL, NULL)
TYPED_DIRECT_FUNCS(websocket_conn_direct_hash, websocket_conn_direct_eq, struct websocket_conn)
TYPED_GHASHTABLE(janus_websockets_ht, struct websocket_conn, struct websocket_conn,
		websocket_conn_direct_hash, websocket_conn_direct_eq, NULL, NULL)

struct janus_session { // "login" session
	struct obj obj;
	uint64_t id;
	mutex_t lock;
	time_t last_act;
	janus_websockets_ht websockets; // controlling transports, websocket_conn -> websocket_conn
	janus_handles_set handles; // handle ID -> 0x1. handle ID owned by janus_handles
};

TYPED_GHASHTABLE(janus_sessions_ht, uint64_t, struct janus_session, int64_hash, int64_eq, NULL, __obj_put)


struct janus_handle { // corresponds to a conference participant
	uint64_t id;
	struct janus_session *session; // holds a reference
	uint64_t room;
};

TYPED_GHASHTABLE(janus_handles_ht, uint64_t, struct janus_handle, int64_hash, int64_eq, NULL, NULL)


TYPED_GHASHTABLE(janus_feeds_ht, uint64_t, uint64_t, int64_hash, int64_eq, g_free, g_free)

struct janus_room {
	uint64_t id;
	str call_id;
	int num_publishers;
	uint64_t handle_id; // controlling handle which created the room
	janus_feeds_ht publishers; // handle ID -> feed ID
	janus_feeds_ht subscribers; // handle ID -> subscribed feed ID
	janus_feeds_ht feeds; // feed ID -> handle ID
};

TYPED_GHASHTABLE(janus_rooms_ht, uint64_t, struct janus_room, int64_hash, int64_eq, NULL, NULL)


TYPED_GHASHTABLE(janus_tokens_ht, char, time_t, c_str_hash, c_str_equal, g_free, g_free)


static mutex_t janus_lock = MUTEX_STATIC_INIT;
static janus_tokens_ht janus_tokens; // auth tokens, currently mostly unused
static janus_sessions_ht janus_sessions; // session ID -> session. holds a session reference
static janus_handles_ht janus_handles; // handle ID -> handle
static janus_rooms_ht janus_rooms; // room ID -> room


static void __janus_session_free(struct janus_session *s) {
	if (t_hash_table_size(s->websockets) != 0)
		ilog(LOG_WARN, "Janus session is leaking %i WS references", t_hash_table_size(s->websockets));
	t_hash_table_destroy(s->websockets);
	if (t_hash_table_size(s->handles) != 0)
		ilog(LOG_WARN, "Janus session is leaking %i handle references", t_hash_table_size(s->handles));
	t_hash_table_destroy(s->handles);
	mutex_destroy(&s->lock);
}


// XXX we have several hash tables that hold references to objs - unify all these
static struct janus_session *janus_get_session(uint64_t id) {
	mutex_lock(&janus_lock);
	struct janus_session *ret = t_hash_table_lookup(janus_sessions, &id);
	if (ret)
		obj_hold(ret);
	mutex_unlock(&janus_lock);
	if (!ret)
		return NULL;
	mutex_lock(&ret->lock);
	ret->last_act = rtpe_now.tv_sec;
	mutex_unlock(&ret->lock);
	return ret;
}


static uint64_t *uint64_dup(uint64_t u) {
	uint64_t *ret = g_malloc(sizeof(*ret));
	*ret = u;
	return ret;
}
INLINE uint64_t janus_random(void) {
	return ssl_random() & 0x7ffffffffffffLL;
}
static uint64_t jr_str_int(JsonReader *r) {
	uint64_t ret = json_reader_get_int_value(r);
	if (ret)
		return ret;
	const char *s = json_reader_get_string_value(r);
	if (!s || !*s)
		return 0;
	char *ep;
	ret = strtoull(s, &ep, 10);
	if (*ep)
		return 0;
	return ret;
}


static struct call_monologue *janus_get_monologue(uint64_t handle_id, call_t *call,
		struct call_monologue *(*fn)(call_t *, const str *))
{
	g_autoptr(char) handle_buf = NULL;
	handle_buf = g_strdup_printf("%" PRIu64, handle_id);
	str handle_str = STR(handle_buf);

	return fn(call, &handle_str);
}


// frees 'builder'
// sends a single final response message to a received websocket message. requires a response code
static void janus_send_json_sync_response(struct websocket_message *wm, JsonBuilder *builder, int code) {
	char *result = glib_json_print(builder);

	if (wm->method == M_WEBSOCKET)
		websocket_write_text(wm->wc, result, true);
	else {
		websocket_http_response(wm->wc, code, "application/json", strlen(result));
		websocket_write_http(wm->wc, result, true);
	}

	g_free(result);
}


// frees 'builder'
// sends an asynchronous notification to all websockets connected to a session
// session must be locked already
static void janus_send_json_async(struct janus_session *session, JsonBuilder *builder) {
	char *result = glib_json_print(builder);

	janus_websockets_ht_iter iter;
	t_hash_table_iter_init(&iter, session->websockets);

	struct websocket_conn *wc;
	while (t_hash_table_iter_next(&iter, NULL, &wc)) {
		// lock order constraint: janus_session lock first, websocket_conn lock second
		websocket_write_text(wc, result, true);
	}

	g_free(result);
}


// session is locked
static void janus_send_ack(struct websocket_message *wm, const char *transaction, struct janus_session *session) {
	// build and send an early ack
	JsonBuilder *ack = json_builder_new();
	json_builder_begin_object(ack); // {
	json_builder_set_member_name(ack, "janus");
	json_builder_add_string_value(ack, "ack");
	json_builder_set_member_name(ack, "transaction");
	json_builder_add_string_value(ack, transaction);
	json_builder_set_member_name(ack, "session_id");
	json_builder_add_int_value(ack, session->id);
	json_builder_end_object(ack); // }

	janus_send_json_async(session, ack);
}


// returns g_malloc'd string
INLINE char *janus_call_id(uint64_t room_id) {
	return g_strdup_printf("janus %" PRIu64, room_id);
}


// global janus_lock is held
static const char *janus_videoroom_create(struct janus_session *session, struct janus_handle *handle,
		JsonBuilder *builder, JsonReader *reader, int *retcode)
{
	*retcode = 436;
	if (handle->room != 0)
		return "User already exists in a room";

	// create new videoroom
	struct janus_room *room = g_slice_alloc0(sizeof(*room));

	if (json_reader_read_member(reader, "publishers"))
		room->num_publishers = jr_str_int(reader);
	json_reader_end_member(reader);
	if (room->num_publishers <= 0)
		room->num_publishers = 3;
	room->handle_id = handle->id; // controlling handle
	// XXX optimise for 64-bit archs
	room->publishers = janus_feeds_ht_new();
	room->subscribers = janus_feeds_ht_new();
	room->feeds = janus_feeds_ht_new();

	uint64_t room_id = 0;
	if (json_reader_read_member(reader, "room")) {
		room_id = jr_str_int(reader);
		if (!room_id)
			return "Invalid room ID requested";
	}
	json_reader_end_member(reader);

	if (room_id) {
		*retcode = 512;
		if (t_hash_table_lookup(janus_rooms, &room_id))
			return "Requested room already exists";
	}

	while (1) {
		if (!room_id)
			room_id = janus_random();
		room->id = room_id;
		if (t_hash_table_lookup(janus_rooms, &room->id))
			continue;
		room->call_id = STR(janus_call_id(room_id));
		call_t *call = call_get_or_create(&room->call_id, true);
		if (!call) {
			ilog(LOG_WARN, "Call with reserved Janus ID '" STR_FORMAT
					"' already exists", STR_FMT(&room->call_id));
			g_free(room->call_id.s);
			continue;
		}
		if (!call->created_from)
			call->created_from = "janus";
		t_hash_table_insert(janus_rooms, &room->id, room);
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
		break;
	}

	handle->room = room_id;

	ilog(LOG_INFO, "Created new videoroom with ID %" PRIu64, room_id);

	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "created");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "permanent");
	json_builder_add_boolean_value(builder, false);

	return NULL;
}


// global janus_lock is held
static const char *janus_videoroom_exists(struct janus_session *session,
		JsonBuilder *builder, uint64_t room_id)
{
	struct janus_room *room = NULL;

	bool exists = false;

	if (room_id)
		room = t_hash_table_lookup(janus_rooms, &room_id);
	if (room) {
		call_t *call = call_get(&room->call_id);
		if (call) {
			exists = true;
			rwlock_unlock_w(&call->master_lock);
			obj_put(call);
		}
	}

	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "success");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "exists");
	json_builder_add_boolean_value(builder, exists);

	return NULL;
}


// global janus_lock is held
static const char *janus_videoroom_destroy(struct janus_session *session,
		JsonBuilder *builder, int *retcode, uint64_t room_id)
{
	struct janus_room *room = NULL;

	if (room_id)
		t_hash_table_steal_extended(janus_rooms, &room_id, NULL, &room);
	*retcode = 426;
	if (!room)
		return "No such room";

	ilog(LOG_INFO, "Destroying videoroom with ID %" PRIu64, room_id);

	call_t *call = call_get(&room->call_id);
	// XXX if call is destroyed separately, room persist -> room should be destroyed too
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		call_destroy(call);
		obj_put(call);
	}

	g_free(room->call_id.s);
	t_hash_table_destroy(room->publishers);
	t_hash_table_destroy(room->subscribers);
	t_hash_table_destroy(room->feeds);
	g_slice_free1(sizeof(*room), room);

	//XXX notify?

	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "destroyed");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "permanent");
	json_builder_add_boolean_value(builder, false);

	return NULL;
}


// adds fields "streams": [...] and "audio_codec" etc into the builder at the current position
static void janus_add_publisher_details(JsonBuilder *builder, struct call_monologue *ml) {
	json_builder_set_member_name(builder, "streams");
	json_builder_begin_array(builder);

	str *a_codec = NULL, *v_codec = NULL;

	for (unsigned int i = 0; i < ml->medias->len; i++) {
		struct call_media *media = ml->medias->pdata[i];
		if (!media)
			continue;

		str *codec = NULL;
		for (__auto_type k = media->codecs.codec_prefs.head; k; k = k->next) {
			rtp_payload_type *pt = k->data;
			codec = &pt->encoding;
			// XXX check codec support?
			break;
		}

		json_builder_begin_object(builder);

		json_builder_set_member_name(builder, "type");
		glib_json_builder_add_str(builder, &media->type);
		json_builder_set_member_name(builder, "mindex");
		json_builder_add_int_value(builder, media->index - 1);

		json_builder_set_member_name(builder, "mid");
		if (media->media_id.s)
			glib_json_builder_add_str(builder, &media->media_id);
		else
			json_builder_add_null_value(builder);

		if (!MEDIA_ISSET2(media, SEND, RECV)) {
			json_builder_set_member_name(builder, "disabled");
			json_builder_add_boolean_value(builder, true);
		}
		else if (codec) {
			json_builder_set_member_name(builder, "codec");
			glib_json_builder_add_str(builder, codec);

			if (media->type_id == MT_AUDIO && !a_codec)
				a_codec = codec;
			else if (media->type_id == MT_VIDEO && !v_codec)
				v_codec = codec;
		}

		json_builder_end_object(builder);
	}

	json_builder_end_array(builder);

	if (a_codec) {
		json_builder_set_member_name(builder, "audio_codec");
		glib_json_builder_add_str(builder, a_codec);
	}

	if (v_codec) {
		json_builder_set_member_name(builder, "video_codec");
		glib_json_builder_add_str(builder, v_codec);
	}

	// TODO add "display"
}


static void janus_publishers_list(JsonBuilder *builder, call_t *call, struct janus_room *room,
		uint64_t feed_id)
{
	json_builder_begin_array(builder); // [

	janus_feeds_ht_iter iter;
	t_hash_table_iter_init(&iter, room->publishers);

	uint64_t *feed_id_ptr, *handle_id_ptr;
	while (t_hash_table_iter_next(&iter, &handle_id_ptr, &feed_id_ptr)) {
		if (*feed_id_ptr == feed_id) // skip self
			continue;

		// get monologue
		struct call_monologue *ml = janus_get_monologue(*handle_id_ptr, call, call_get_monologue);
		if (!ml)
			continue;

		json_builder_begin_object(builder); // {
		json_builder_set_member_name(builder, "id");
		json_builder_add_int_value(builder, *feed_id_ptr);

		janus_add_publisher_details(builder, ml);

		json_builder_end_object(builder); // }
	}

	json_builder_end_array(builder); // ]
}


// global janus_lock is held
static const char *janus_videoroom_join_sub(struct janus_handle *handle, struct janus_room *room, int *retcode,
		uint64_t feed_id, call_t *call, subscription_q *medias)
{
	// does the feed actually exist? get the feed handle
	*retcode = 512;
	uint64_t *feed_handle = t_hash_table_lookup(room->feeds, &feed_id);
	if (!feed_handle)
		return "No such feed exists";
	if (!t_hash_table_lookup(room->publishers, feed_handle))
		return "No such feed handle exists";

	// handle ID points to the subscribed feed
	t_hash_table_insert(room->subscribers, uint64_dup(handle->id), uint64_dup(feed_id));

	// add the subscription
	struct call_monologue *source_ml = janus_get_monologue(*feed_handle, call, call_get_monologue);
	if (!source_ml)
		return "Feed not found";

	for (int i = 0; i < source_ml->medias->len; i++)
	{
		struct call_media * media = source_ml->medias->pdata[i];
		if (!media)
			continue;
		add_media_to_sub_list(medias, media, source_ml);
	}
	return NULL;
}


TYPED_GQUEUE(janus_ret_streams, uint64_t);

static void janus_clear_ret_streams(janus_ret_streams_q *q) {
	uint64_t *id;
	while ((id = t_queue_pop_head(q)))
		g_slice_free1(sizeof(*id), id);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(janus_ret_streams_q, janus_clear_ret_streams);


static int int64_cmp(const uint64_t *a, const void *b) {
	return !(*a == *(uint64_t *) b);
}


// global janus_lock is held
static const char *janus_videoroom_join(struct websocket_message *wm, struct janus_session *session,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcode,
		char **jsep_type_out, str *jsep_sdp_out,
		uint64_t room_id)
{
	janus_send_ack(wm, transaction, session);

	*retcode = 456;
	if (!json_reader_read_member(reader, "ptype"))
		return "JSON object does not contain 'message.ptype' key";
	const char *ptype = json_reader_get_string_value(reader);
	if (!ptype)
		return "JSON object does not contain 'message.ptype' key";
	json_reader_end_member(reader);

	bool plain_offer = false;
	if (json_reader_read_member(reader, "plain"))
		plain_offer = json_reader_get_boolean_value(reader);
	json_reader_end_member(reader);

	*retcode = 436;
	if (handle->room != 0 && handle->room != room_id)
		return "User already exists in a different room";

	*retcode = 430;
	bool is_pub = false;
	if (!strcmp(ptype, "publisher"))
		is_pub = true;
	else if (!strcmp(ptype, "subscriber") || !strcmp(ptype, "listener"))
		is_pub = false;
	else
		return "Invalid 'ptype'";

	struct janus_room *room = NULL;
	if (room_id)
		room = t_hash_table_lookup(janus_rooms, &room_id);
	*retcode = 426;
	if (!room)
		return "No such room";

	g_autoptr(call_t) call = NULL;
	*retcode = 426;
	call = call_get(&room->call_id);
	if (!call)
		return "No such room";

	*retcode = 436;
	if (!is_pub && t_hash_table_lookup(room->subscribers, &handle->id))
		return "User already exists in the room as a subscriber";
	if (is_pub && t_hash_table_lookup(room->publishers, &handle->id))
		return "User already exists in the room as a publisher";

	uint64_t feed_id = 0; // set for single feed IDs, otherwise remains 0
	g_autoptr(GString) feed_ids = g_string_new("feeds "); // for log output
	g_auto(janus_ret_streams_q) ret_streams = TYPED_GQUEUE_INIT; // return list for multiple subs

	if (is_pub) {
		if (json_reader_read_member(reader, "id")) {
			feed_id = jr_str_int(reader);
			if (!feed_id)
				return "Invalid feed ID requested";
			if (t_hash_table_lookup(room->feeds, &feed_id))
				return "Feed already exists";
		}
		json_reader_end_member(reader);

		// random feed ID?
		while (!feed_id) {
			feed_id = janus_random();
			if (feed_id && t_hash_table_lookup(room->feeds, &feed_id))
				feed_id = 0;
		}

		// feed ID points to the handle
		t_hash_table_insert(room->feeds, uint64_dup(feed_id), uint64_dup(handle->id));
		// handle ID points to the feed
		t_hash_table_insert(room->publishers, uint64_dup(handle->id), uint64_dup(feed_id));
	}
	else {
		// subscriber

		g_auto(subscription_q) srms = TYPED_GQUEUE_INIT;

		// get single feed ID if there is one
		if (json_reader_read_member(reader, "feed")) {
			*retcode = 456;
			feed_id = jr_str_int(reader);
			if (!feed_id)
				return "JSON object contains invalid 'message.feed' key";
			const char *ret = janus_videoroom_join_sub(handle, room, retcode, feed_id,
					call, &srms);
			if (ret)
				return ret;
		}
		json_reader_end_member(reader);

		// handle list of subscriptions if given
		if (json_reader_read_member(reader, "streams")) {
			*retcode = 456;
			if (!json_reader_is_array(reader))
				return "Invalid 'message.streams' key (not an array)";
			int eles = json_reader_count_elements(reader);
			if (eles < 0)
				return "Invalid 'message.streams' key (invalid array)";
			for (int i = 0; i < eles; i++) {
				if (!json_reader_read_element(reader, i))
					return "Invalid 'message.streams' key (cannot read element)";
				if (!json_reader_is_object(reader))
					return "Invalid 'message.streams' key (contains not an object)";
				if (!json_reader_read_member(reader, "feed"))
					return "Invalid 'message.streams' key (doesn't contain 'feed')";
				uint64_t fid = jr_str_int(reader); // leave `feed_id` zero
				if (!fid)
					return "Invalid 'message.streams' key (contains invalid 'feed')";

				// check for duplicate feed IDs. the "streams" list actually contains one
				// element for each media section ("streams":[{"feed":74515332221,"mid":"0"},
				// {"feed":74515332221,"mid":"1"}]) but this isn't supported right now.
				// instead always expect all media sections to be subscribed to, in order,
				// and so simply honour each unique feed ID given.
				// TODO: fix this up

				if (!t_queue_find_custom(&ret_streams, &fid, int64_cmp)) {
					const char *ret = janus_videoroom_join_sub(handle, room, retcode, fid,
						call, &srms);
					if (ret)
						return ret;

					g_string_append_printf(feed_ids, "%" PRIu64 ", ", fid);

					uint64_t *fidp = g_slice_alloc(sizeof(*fidp));
					*fidp = fid;
					t_queue_push_tail(&ret_streams, fidp);
				}

				json_reader_end_member(reader);
				json_reader_end_element(reader);
			}
		}
		json_reader_end_member(reader);

		*retcode = 456;
		if (!srms.length)
			return "No feeds to subscribe to given";

		struct call_monologue *dest_ml = janus_get_monologue(handle->id, call,
				call_get_or_create_monologue);

		g_auto(sdp_ng_flags) flags;
		call_ng_flags_init(&flags, OP_SUBSCRIBE_REQ);

		flags.generate_mid = 1;
		flags.rtcp_mirror = 1;
		flags.replace_origin_full = 1;

		if (!plain_offer)
			ng_flags_webrtc(&flags);
		else {
			flags.transport_protocol = &transport_protocols[PROTO_RTP_AVP];
			flags.ice_option = ICE_REMOVE;
			flags.rtcp_mux_demux = 1;
		}

		int ret = monologue_subscribe_request(&srms, dest_ml, &flags);
		if (ret)
			return "Subscribe error";

		/* create SDP */
		ret = sdp_create(jsep_sdp_out, dest_ml, &flags);

		if (!dest_ml->janus_session)
			dest_ml->janus_session = obj_get(session);

		dequeue_sdp_fragments(dest_ml);

		if (ret)
			return "Error generating SDP";

		*jsep_type_out = "offer";
	}

	handle->room = room_id;

	// single or multiple feed IDs?
	if (feed_id)
		g_string_printf(feed_ids, "feed %" PRIu64, feed_id);
	else if (feed_ids->len >= 2) // truncate trailing ", "
		g_string_truncate(feed_ids, feed_ids->len - 2);

	ilog(LOG_INFO, "Handle %" PRIu64 " has joined room %" PRIu64 " as %s (%s)",
			handle->id, room_id,
			is_pub ? "publisher" : "subscriber", feed_ids->str);

	*successp = "event";

	if (is_pub) {
		json_builder_set_member_name(builder, "videoroom");
		json_builder_add_string_value(builder, "joined");
		json_builder_set_member_name(builder, "room");
		json_builder_add_int_value(builder, room_id);
		json_builder_set_member_name(builder, "id");
		json_builder_add_int_value(builder, feed_id);
		json_builder_set_member_name(builder, "publishers");
		janus_publishers_list(builder, call, room, feed_id);
	}
	else {
		// subscriber
		json_builder_set_member_name(builder, "videoroom");
		json_builder_add_string_value(builder, "attached");
		json_builder_set_member_name(builder, "room");
		json_builder_add_int_value(builder, room_id);

		// output format: single feed ID or multiple?
		if (feed_id) {
			json_builder_set_member_name(builder, "id");
			json_builder_add_int_value(builder, feed_id);
		}
		else {
			json_builder_set_member_name(builder, "streams");
			json_builder_begin_array(builder);
			uint64_t idx = 0;
			for (__auto_type l = ret_streams.head; l; l = l->next) {
				uint64_t *fidp = l->data;
				json_builder_begin_object(builder);
				json_builder_set_member_name(builder, "mindex");
				json_builder_add_int_value(builder, idx++);
				json_builder_set_member_name(builder, "feed_id");
				json_builder_add_int_value(builder, *fidp);
				json_builder_end_object(builder);
			}
			json_builder_end_array(builder);
		}
	}

	return NULL;
}


// callback function for janus_notify_publishers()
static void janus_notify_publishers_joined(JsonBuilder *event, void *ptr, uint64_t u64, struct janus_room *room,
		uint64_t publisher_feed)
{
	json_builder_set_member_name(event, "publishers");
	janus_publishers_list(event, ptr, room, publisher_feed);
}


// callback function for janus_notify_publishers()
static void janus_notify_publishers_unpublished(JsonBuilder *event, void *ptr, uint64_t u64,
		struct janus_room *room, uint64_t publisher_feed)
{
	json_builder_set_member_name(event, "unpublished");
	json_builder_add_int_value(event, u64);
}


// callback function for janus_notify_publishers()
static void janus_notify_publishers_leaving(JsonBuilder *event, void *ptr, uint64_t u64, struct janus_room *room,
		uint64_t publisher_feed)
{
	json_builder_set_member_name(event, "leaving");
	json_builder_add_int_value(event, u64);
}


// global janus_lock is held
static void janus_notify_publishers(uint64_t room_id, uint64_t except, void *ptr, uint64_t u64,
		void (*callback)(JsonBuilder *event, void *ptr, uint64_t u64, struct janus_room *room,
			uint64_t publisher_feed))
{
	struct janus_room *room = t_hash_table_lookup(janus_rooms, &room_id);
	if (!room)
		return;

	janus_feeds_ht_iter iter;
	t_hash_table_iter_init(&iter, room->publishers);

	uint64_t *handle_id, *feed_id;
	while (t_hash_table_iter_next(&iter, &handle_id, &feed_id)) {
		if (*handle_id == except)
			continue;

		// look up the handle and determine which session it belongs to
		struct janus_handle *handle = t_hash_table_lookup(janus_handles, handle_id);
		if (!handle)
			continue;
		if (!handle->session)
			continue;

		// send to the handle's session

		JsonBuilder *event = json_builder_new();
		json_builder_begin_object(event); // {
		json_builder_set_member_name(event, "janus");
		json_builder_add_string_value(event, "event");
		json_builder_set_member_name(event, "session_id");
		json_builder_add_int_value(event, handle->session->id);
		json_builder_set_member_name(event, "sender");
		json_builder_add_int_value(event, handle->id); // destination of notification
		json_builder_set_member_name(event, "plugindata");
		json_builder_begin_object(event); // {
		json_builder_set_member_name(event, "plugin");
		json_builder_add_string_value(event, "janus.plugin.videoroom");
		json_builder_set_member_name(event, "data");
		json_builder_begin_object(event); // {
		json_builder_set_member_name(event, "videoroom");
		json_builder_add_string_value(event, "event");
		json_builder_set_member_name(event, "room");
		json_builder_add_int_value(event, room_id);

		callback(event, ptr, u64, room, *feed_id);

		json_builder_end_object(event); // }
		json_builder_end_object(event); // }
		json_builder_end_object(event); // }

		janus_send_json_async(handle->session, event);
	}
}


// global janus_lock is held
static const char *janus_videoroom_configure(struct websocket_message *wm, struct janus_session *session,
		const char *jsep_type, const char *jsep_sdp,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcode,
		char **jsep_type_out, str *jsep_sdp_out,
		uint64_t room_id)
{
	janus_send_ack(wm, transaction, session);

	*retcode = 456;
	if (!room_id)
		room_id = handle->room;
	if (!room_id)
		return "JSON object does not contain 'message.room' key";

	int has_audio = -1; // tri-state -1/0/1
	if (json_reader_read_member(reader, "audio"))
		has_audio = !!json_reader_get_boolean_value(reader); // 0/1
	json_reader_end_member(reader);

	int has_video = -1; // tri-state -1/0/1
	if (json_reader_read_member(reader, "video"))
		has_video = !!json_reader_get_boolean_value(reader); // 0/1
	json_reader_end_member(reader);

	// exit "body"
	json_reader_end_member(reader);

	*retcode = 512;

	if (handle->room != room_id)
		return "Not in the room";

	struct janus_room *room = t_hash_table_lookup(janus_rooms, &room_id);
	*retcode = 426;
	if (!room)
		return "No such room";
	g_autoptr(call_t) call = call_get(&room->call_id);
	// XXX if call is destroyed separately, room persists -> room should be destroyed too
	if (!call)
		return "No such room";
	*retcode = 512;
	if (!t_hash_table_lookup(room->publishers, &handle->id))
		return "Not a publisher";

	struct call_monologue *ml = NULL;

	if (jsep_type && jsep_sdp) {
		if (strcmp(jsep_type, "offer"))
			return "Not an offer";

		str sdp_in = call_str_cpy_c(jsep_sdp);

		g_auto(sdp_ng_flags) flags;
		g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
		g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
		call_ng_flags_init(&flags, OP_PUBLISH);
		*retcode = 512;
		if (sdp_parse(&sdp_in, &parsed, &flags))
			return "Failed to parse SDP";
		if (sdp_streams(&parsed, &streams, &flags))
			return "Incomplete SDP specification";

		ml = janus_get_monologue(handle->id, call, call_get_or_create_monologue);

		// accept unsupported codecs if necessary
		flags.accept_any = 1;
		flags.replace_origin_full = 1;

		int ret = monologue_publish(ml, &streams, &flags);
		if (ret)
			return "Publish error";

		// XXX check there's only one audio and one video stream?

		g_auto(str) sdp_out = STR_NULL;
		ret = sdp_create(&sdp_out, ml, &flags);
		if (ret)
			return "Publish error";

		if (!ml->janus_session)
			ml->janus_session = obj_get(session);

		save_last_sdp(ml, &sdp_in, &parsed, &streams);
		*jsep_sdp_out = sdp_out;
		sdp_out = STR_NULL; // ownership passed to output

		dequeue_sdp_fragments(ml);

		*jsep_type_out = "answer";
	}
	else {
		// reconfigure existing publisher
		ml = janus_get_monologue(handle->id, call, call_get_monologue);
		if (!ml)
			return "Not an existing publisher";
	}

	*successp = "event";
	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "event");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "configured");
	json_builder_add_string_value(builder, "ok");

	// apply audio/video bool flags
	for (unsigned int i = 0; i < ml->medias->len; i++) {
		struct call_media *media = ml->medias->pdata[i];
		if (!media)
			continue;

		if (media->type_id == MT_AUDIO) {
			if (has_audio == 0)
				MEDIA_CLEAR(media, RECV);
			else if (has_audio == 1)
				MEDIA_SET(media, RECV);
		}
		else if (media->type_id == MT_VIDEO) {
			if (has_video == 0)
				MEDIA_CLEAR(media, RECV);
			else if (has_video == 1)
				MEDIA_SET(media, RECV);
		}
	}

	janus_add_publisher_details(builder, ml);

	janus_notify_publishers(room_id, handle->id, call, 0, janus_notify_publishers_joined);

	return NULL;
}


// global janus_lock is held
static const char *janus_videoroom_start(struct websocket_message *wm, struct janus_session *session,
		const char *jsep_type, const char *jsep_sdp,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcode,
		uint64_t room_id)
{
	janus_send_ack(wm, transaction, session);

	*retcode = 456;
	if (!room_id)
		return "JSON object does not contain 'message.room' key";
	json_reader_end_member(reader);

	if (handle->room != room_id)
		return "Not in the room";
	if (!jsep_type || !jsep_sdp)
		return "No SDP";
	if (strcmp(jsep_type, "answer"))
		return "Not an answer";

	struct janus_room *room = t_hash_table_lookup(janus_rooms, &room_id);
	*retcode = 426;
	if (!room)
		return "No such room";
	g_autoptr(call_t) call = call_get(&room->call_id);
	if (!call)
		return "No such room";

	str sdp_in = call_str_cpy_c(jsep_sdp);

	g_auto(sdp_ng_flags) flags;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	call_ng_flags_init(&flags, OP_PUBLISH);
	*retcode = 512;
	if (sdp_parse(&sdp_in, &parsed, &flags))
		return "Failed to parse SDP";

	*retcode = 512;
	if (sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	*retcode = 456;
	uint64_t *feed_id = t_hash_table_lookup(room->subscribers, &handle->id);
	if (!feed_id)
		return "Not a subscriber";

	*retcode = 512;
	uint64_t *feed_handle = t_hash_table_lookup(room->feeds, feed_id);
	if (!feed_handle)
		return "No such feed exists";

	struct call_monologue *source_ml = janus_get_monologue(*feed_handle, call, call_get_monologue);
	if (!source_ml)
		return "Feed not found";
	// XXX verify that dest_ml is subscribed to source_ml

	struct call_monologue *dest_ml = janus_get_monologue(handle->id, call, call_get_monologue);
	if (!dest_ml)
		return "Subscriber not found";

	int ret = monologue_subscribe_answer(dest_ml, &flags, &streams);
	if (ret)
		return "Failed to process subscription answer";

	*successp = "event";
	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "event");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "started");
	json_builder_add_string_value(builder, "ok");

	return NULL;
}


// global janus_lock is held
static const char *janus_videoroom_unpublish(struct websocket_message *wm, struct janus_session *session,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, const char **successp,
		int *retcode)
{
	janus_send_ack(wm, transaction, session);

	// get all our info

	uint64_t room_id = handle->room;
	*retcode = 512;
	if (!room_id)
		return "Not in any room";

	struct janus_room *room = NULL;
	if (room_id)
		room = t_hash_table_lookup(janus_rooms, &room_id);
	*retcode = 426;
	if (!room)
		return "No such room";

	g_autoptr(call_t) call = call_get(&room->call_id);
	if (!call)
		return "No such room";

	uint64_t *feed_id = t_hash_table_lookup(room->publishers, &handle->id);
	*retcode = 512;
	if (!feed_id)
		return "Not a publisher";

	// all is ok

	// notify other publishers
	janus_notify_publishers(room_id, handle->id, NULL, *feed_id, janus_notify_publishers_unpublished);

	struct call_monologue *ml = janus_get_monologue(handle->id, call, call_get_monologue);
	if (ml)
		monologue_destroy(ml);

	*successp = "event";
	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "event");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "unpublished");
	json_builder_add_string_value(builder, "ok");

	return NULL;
}


// global janus_lock is held
// TODO: more granular locking
static const char *janus_videoroom(struct websocket_message *wm, struct janus_session *session,
		const char *jsep_type, const char *jsep_sdp,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcodep, char **jsep_type_out, str *jsep_sdp_out)
{
	uint64_t room_id = 0;

	if (json_reader_read_member(reader, "room"))
		room_id = jr_str_int(reader);
	json_reader_end_member(reader);

	int retcode = 456;
	const char *err = "JSON object does not contain 'message.request' key";
	if (!json_reader_read_member(reader, "request"))
		goto err;
	const char *req = json_reader_get_string_value(reader);
	if (!req)
		goto err;
	str req_str = STR(req);
	json_reader_end_member(reader);

	switch (__csh_lookup(&req_str)) {
		case CSH_LOOKUP("create"):
			err = janus_videoroom_create(session, handle, builder, reader, &retcode);
			break;

		case CSH_LOOKUP("exists"):
			err = janus_videoroom_exists(session, builder, room_id);
			break;

		case CSH_LOOKUP("destroy"):
			err = janus_videoroom_destroy(session, builder, &retcode, room_id);
			break;

		case CSH_LOOKUP("join"):
			err = janus_videoroom_join(wm, session, transaction, handle, builder, reader, successp,
					&retcode, jsep_type_out, jsep_sdp_out, room_id);
			break;

		case CSH_LOOKUP("configure"):
			err = janus_videoroom_configure(wm, session, jsep_type, jsep_sdp, transaction,
					handle, builder, reader, successp, &retcode, jsep_type_out, jsep_sdp_out,
					room_id);
			break;

		case CSH_LOOKUP("start"):
			err = janus_videoroom_start(wm, session, jsep_type, jsep_sdp, transaction,
					handle, builder, reader, successp,
					&retcode, room_id);
			break;

		case CSH_LOOKUP("unpublish"):
			err = janus_videoroom_unpublish(wm, session, transaction,
					handle, builder, successp,
					&retcode);
			break;

		default:
			retcode = 423;
			err = "Unknown videoroom request";
			break;
	}

err:
	if (err)
		*retcodep = retcode;
	return err;
}


static const char *janus_add_token(JsonReader *reader, JsonBuilder *builder, bool authorised, int *retcode) {
	*retcode = 403;
	if (!authorised)
		return "Janus 'admin_secret' key not provided or incorrect";

	const char *token = NULL;
	if (json_reader_read_member(reader, "token"))
		token = json_reader_get_string_value(reader);
	json_reader_end_member(reader);

	*retcode = 456;
	if (!token)
		return "JSON object does not contain 'token' key";

	time_t *now = g_malloc(sizeof(*now));
	*now = rtpe_now.tv_sec;
	mutex_lock(&janus_lock);
	t_hash_table_replace(janus_tokens, g_strdup(token), now);
	mutex_unlock(&janus_lock);

	json_builder_set_member_name(builder, "data");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "plugins");
	json_builder_begin_array(builder); // [
	json_builder_add_string_value(builder, "janus.plugin.videoroom");
	json_builder_end_array(builder); // ]
	json_builder_end_object(builder); // }

	return NULL;
}


static const char *janus_create(JsonReader *reader, JsonBuilder *builder, struct websocket_message *wm) {
	if (wm->method != M_WEBSOCKET)
		return "Unsupported transport protocol";

	uint64_t session_id = 0;
	if (json_reader_read_member(reader, "id"))
		session_id = jr_str_int(reader);
	json_reader_end_member(reader);

	__auto_type session = obj_alloc0(struct janus_session, __janus_session_free);
	mutex_init(&session->lock);
	mutex_lock(&session->lock); // not really necessary but Coverity complains
	session->last_act = rtpe_now.tv_sec;
	session->websockets = janus_websockets_ht_new();
	session->handles = janus_handles_set_new();

	t_hash_table_insert(session->websockets, wm->wc, wm->wc);

	do {
		while (!session_id)
			session_id = janus_random();

		mutex_lock(&janus_lock);
		if (t_hash_table_lookup(janus_sessions, &session_id))
			session_id = 0; // pick a random one
		else {
			session->id = session_id;
			t_hash_table_insert(janus_sessions, &session->id, obj_get(session));
		}
		mutex_unlock(&janus_lock);
	}
	while (!session_id);
	mutex_unlock(&session->lock);

	ilog(LOG_INFO, "Created new Janus session with ID %" PRIu64, session_id);

	websocket_conn_add_session(wm->wc, obj_get(session));

	json_builder_set_member_name(builder, "data");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "id");
	json_builder_add_int_value(builder, session_id);
	json_builder_end_object(builder); // }

	obj_put(session);

	return NULL;
}


void janus_detach_websocket(struct janus_session *session, struct websocket_conn *wc) {
	LOCK(&session->lock);
	t_hash_table_remove(session->websockets, wc);
}


// call is locked in some way
void janus_rtc_up(struct call_monologue *ml) {
	struct janus_session *session = ml->janus_session;
	if (!session)
		return;

	// the monologue tag is the handle ID
	uint64_t handle = str_to_ui(&ml->tag, 0);
	if (!handle)
		return;

	// build json

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "janus");
	json_builder_add_string_value(builder, "webrtcup");
	json_builder_set_member_name(builder, "session_id");
	json_builder_add_int_value(builder, session->id);
	json_builder_set_member_name(builder, "sender");
	json_builder_add_int_value(builder, handle);
	json_builder_end_object(builder); // }

	LOCK(&session->lock);

	janus_send_json_async(session, builder);
}


// call is locked in some way
void janus_media_up(struct call_media *media) {
	struct call_monologue *ml = media->monologue;
	if (!ml)
		return;

	struct janus_session *session = ml->janus_session;
	if (!session)
		return;

	// the monologue tag is the handle ID
	uint64_t handle = str_to_ui(&ml->tag, 0);
	if (!handle)
		return;

	// build json

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "janus");
	json_builder_add_string_value(builder, "media");
	json_builder_set_member_name(builder, "session_id");
	json_builder_add_int_value(builder, session->id);
	json_builder_set_member_name(builder, "sender");
	json_builder_add_int_value(builder, handle);
	json_builder_set_member_name(builder, "mid");
	if (media->media_id.s)
		glib_json_builder_add_str(builder, &media->media_id);
	else
		json_builder_add_null_value(builder);
	json_builder_set_member_name(builder, "type");
	glib_json_builder_add_str(builder, &media->type);
	json_builder_set_member_name(builder, "receiving");
	json_builder_add_boolean_value(builder, true);
	json_builder_end_object(builder); // }

	LOCK(&session->lock);

	janus_send_json_async(session, builder);
}


static const char *janus_attach(JsonReader *reader, JsonBuilder *builder, struct janus_session *session,
		int *retcode)
{
	*retcode = 458;
	if (!session)
		return "Session ID not found";
	// verify the plugin
	*retcode = 456;
	if (!json_reader_read_member(reader, "plugin"))
		return "No plugin given";
	const char *plugin = json_reader_get_string_value(reader);
	if (!plugin)
		return "No plugin given";
	*retcode = 460;
	if (strcmp(plugin, "janus.plugin.videoroom"))
		return "Unsupported plugin";
	json_reader_end_member(reader);

	struct janus_handle *handle = g_slice_alloc0(sizeof(*handle));
	mutex_lock(&janus_lock);
	handle->session = obj_get(session);
	uint64_t handle_id = 0;
	while (1) {
		handle_id = handle->id = janus_random();
		if (t_hash_table_lookup(janus_handles, &handle->id))
			continue;
		t_hash_table_insert(janus_handles, &handle->id, handle);
		break;
	}
	mutex_unlock(&janus_lock);

	mutex_lock(&session->lock);
	assert(t_hash_table_lookup(session->handles, &handle_id) == NULL);
	t_hash_table_insert(session->handles, &handle->id, (void *) 0x1);
	mutex_unlock(&session->lock);

	json_builder_set_member_name(builder, "data");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "id");
	json_builder_add_int_value(builder, handle_id);
	json_builder_end_object(builder); // }

	return NULL;
}


static void janus_destroy_handle(struct janus_handle *handle) {
	uint64_t room_id = handle->room;
	uint64_t handle_id = handle->id;

	// destroy handle
	if (handle->session)
		obj_put(handle->session);
	g_slice_free1(sizeof(*handle), handle);

	if (!room_id)
		return;

	struct janus_room *room = t_hash_table_lookup(janus_rooms, &room_id);
	if (!room)
		return;

	uint64_t *feed = t_hash_table_lookup(room->publishers, &handle_id);
	if (feed) {
		// was a publisher - send notifies
		janus_notify_publishers(room_id, handle_id, NULL, *feed, janus_notify_publishers_unpublished);
		janus_notify_publishers(room_id, handle_id, NULL, *feed, janus_notify_publishers_leaving);

		call_t *call = call_get(&room->call_id);
		if (call) {
			// remove publisher monologue
			struct call_monologue *ml = janus_get_monologue(handle_id, call, call_get_monologue);
			if (ml)
				monologue_destroy(ml);

			rwlock_unlock_w(&call->master_lock);
			obj_put(call);
		}

		t_hash_table_remove(room->publishers, &handle_id);
		feed = NULL;
	}

	if (t_hash_table_remove(room->subscribers, &handle_id)) {
		// was a subscriber
		call_t *call = call_get(&room->call_id);
		if (call) {
			// remove subscriber monologue
			struct call_monologue *ml = janus_get_monologue(handle_id, call, call_get_monologue);
			if (ml)
				monologue_destroy(ml);

			rwlock_unlock_w(&call->master_lock);
			obj_put(call);
		}
	}
}


static const char *janus_detach(struct websocket_message *wm, JsonReader *reader, JsonBuilder *builder,
		struct janus_session *session,
		uint64_t handle_id, int *retcode)
{
	*retcode = 458;
	if (!session)
		return "Session ID not found";
	*retcode = 457;
	if (!handle_id)
		return "Unhandled request method";

	// remove handle from session first as the handle ID in the hash is owned by the
	// janus_handle object, which is owned by janus_handles
	{
		LOCK(&session->lock);

		bool exists = t_hash_table_remove(session->handles, &handle_id);

		*retcode = 463;
		if (!exists)
			return "Could not detach handle from plugin";
	}

	LOCK(&janus_lock);

	struct janus_handle *handle = NULL;
	t_hash_table_steal_extended(janus_handles, &handle_id, NULL, &handle);

	*retcode = 463;
	if (!handle)
		return "Could not detach handle from plugin";
	if (handle->session != session) {
		t_hash_table_insert(janus_handles, &handle->id, handle);
		return "Invalid session/handle association";
	}

	janus_destroy_handle(handle);

	return NULL;
}


// janus_lock must be held
static void janus_session_cleanup(struct janus_session *session) {
	janus_handles_set_iter iter;
	t_hash_table_iter_init(&iter, session->handles);
	uint64_t *handle_id;
	while (t_hash_table_iter_next(&iter, &handle_id, NULL)) {
		struct janus_handle *handle = NULL;
		t_hash_table_steal_extended(janus_handles, handle_id, NULL, &handle);
		if (!handle) // bug?
			continue;
		janus_destroy_handle(handle);
	}
}


static const char *janus_destroy(struct websocket_message *wm, JsonReader *reader, JsonBuilder *builder,
		struct janus_session *session,
		int *retcode)
{
	*retcode = 458;
	if (!session)
		return "Session ID not found";

	LOCK(&janus_lock);

	struct janus_session *ht_session = NULL;
	t_hash_table_steal_extended(janus_sessions, &session->id, NULL, &ht_session);
	if (ht_session != session) {
		if (ht_session) // return wrongly stolen session
			t_hash_table_insert(janus_sessions, &ht_session->id, ht_session);
		return "Sesssion ID not found"; // already removed/destroyed
	}

	janus_session_cleanup(session);
	obj_put(session);

	return NULL;
}


static const char *janus_message(struct websocket_message *wm, JsonReader *reader, JsonBuilder *builder,
		struct janus_session *session,
		const char *transaction,
		uint64_t handle_id,
		const char **successp,
		int *retcode)
{
	// we only pretend to support one plugin so ignore the handle
	// and just go straight to the message
	*retcode = 458;
	if (!session)
		return "Session ID not found";
	*retcode = 457;
	if (!handle_id)
		return "No plugin handle given";

	const char *jsep_type = NULL, *jsep_sdp = NULL;
	if (json_reader_read_member(reader, "jsep")) {
		if (json_reader_read_member(reader, "type"))
			jsep_type = json_reader_get_string_value(reader);
		json_reader_end_member(reader);
		if (json_reader_read_member(reader, "sdp"))
			jsep_sdp = json_reader_get_string_value(reader);
		json_reader_end_member(reader);
	}
	json_reader_end_member(reader);

	*retcode = 456;
	if (!json_reader_read_member(reader, "body"))
		return "JSON object does not contain 'body' key";

	json_builder_set_member_name(builder, "plugindata");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "plugin");
	json_builder_add_string_value(builder, "janus.plugin.videoroom");
	json_builder_set_member_name(builder, "data");
	json_builder_begin_object(builder); // {

	char *jsep_type_out = NULL;
	g_auto(str) jsep_sdp_out = STR_NULL;

	LOCK(&janus_lock);

	struct janus_handle *handle = t_hash_table_lookup(janus_handles, &handle_id);

	const char *err = NULL;
	if (!handle || handle->session != session) {
		*retcode = 457;
		err = "No plugin handle given or invalid handle";
	}
	else
		err = janus_videoroom(wm, session, jsep_type, jsep_sdp, transaction, handle,
				builder, reader, successp, retcode, &jsep_type_out,
				&jsep_sdp_out);

	json_builder_end_object(builder); // }
	json_builder_end_object(builder); // }

	if (jsep_type_out && jsep_sdp_out.len) {
		json_builder_set_member_name(builder, "jsep");
		json_builder_begin_object(builder); // {
		json_builder_set_member_name(builder, "type");
		json_builder_add_string_value(builder, jsep_type_out);
		json_builder_set_member_name(builder, "sdp");
		glib_json_builder_add_str(builder, &jsep_sdp_out);
		json_builder_end_object(builder); // }
	}

	return err;
}


static const char *janus_trickle(JsonReader *reader, struct janus_session *session, uint64_t handle_id,
		const char **successp, int *retcode)
{
	*retcode = 458;
	if (!session)
		return "Session ID not found";
	*retcode = 457;
	if (!handle_id)
		return "Unhandled request method";

	*retcode = 456;
	if (!json_reader_read_member(reader, "candidate"))
		return "JSON object does not contain 'candidate' key";

	const char *candidate = NULL;
	if (json_reader_read_member(reader, "candidate"))
		candidate = json_reader_get_string_value(reader);
	json_reader_end_member(reader);

	if (!candidate) {
		if (json_reader_read_member(reader, "completed")) {
			*successp = "ack";
			return NULL;
		}
		return "ICE candidate string missing";
	}

	const char *ufrag = NULL;
	if (json_reader_read_member(reader, "usernameFragment"))
		ufrag = json_reader_get_string_value(reader);
	json_reader_end_member(reader);

	const char *sdp_mid = NULL;
	int64_t sdp_m_line = -1;

	if (json_reader_read_member(reader, "sdpMid"))
		sdp_mid = json_reader_get_string_value(reader);
	json_reader_end_member(reader);

	if (json_reader_read_member(reader, "sdpMLineIndex")) {
		// make sure what we're reading is an int
		JsonNode *node = json_reader_get_value(reader);
		if (node && json_node_get_value_type(node) == G_TYPE_INT64)
			sdp_m_line = json_node_get_int(node);
	}
	json_reader_end_member(reader);

	json_reader_end_member(reader);

	if (!sdp_mid && sdp_m_line < 0)
		return "Neither sdpMid nor sdpMLineIndex given";

	// fetch call

	g_autoptr(char) call_id = NULL;
	g_autoptr(call_t) call = NULL;
	{
		LOCK(&janus_lock);

		struct janus_handle *handle = t_hash_table_lookup(janus_handles, &handle_id);

		if (!handle || !handle->room || handle->session != session)
			return "Unhandled request method";

		call_id = janus_call_id(handle->room);

		struct janus_room *room = t_hash_table_lookup(janus_rooms, &handle->room);
		if (!room) {
			*retcode = 426;
			return "No such room";
		}
		call = call_get(&room->call_id);
		if (!call) {
			*retcode = 426;
			return "No such room";
		}
	}

	// set up "streams" structures to use an trickle ICE update. these must be
	// allocated in case of delayed trickle ICE updates. it's using a refcounted
	// ng_buffer as storage.

	*successp = "ack";

	// top-level structures first, with auto cleanup
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	g_autoptr(ng_buffer) ngbuf = ng_buffer_new(NULL);
	bencode_buffer_init(&ngbuf->buffer);
	g_auto(sdp_ng_flags) flags;
	call_ng_flags_init(&flags, OP_OTHER);

	// then the contained structures, and add them in
	struct stream_params *sp = g_slice_alloc0(sizeof(*sp));
	t_queue_push_tail(&streams, sp);
	struct ice_candidate *cand = g_slice_alloc0(sizeof(*cand));
	t_queue_push_tail(&sp->ice_candidates, cand);

	// allocate and parse candidate
	str cand_str;
	cand_str = bencode_strdup_str(&ngbuf->buffer, candidate);
	str_shift_cmp(&cand_str, "candidate:"); // skip prefix
	if (!cand_str.len) // end of candidates
		return NULL;

	*retcode = 466;
	int ret = sdp_parse_candidate(cand, &cand_str);
	if (ret < 0)
		return "Failed to parse trickle candidate";
	if (ret > 0)
		return NULL; // unsupported candidate type, accept and ignore it

	// set required signalling flags
	flags.fragment = 1;

	g_autoptr(char) handle_buf = NULL;
	handle_buf = g_strdup_printf("%" PRIu64, handle_id);
	flags.from_tag = bencode_strdup_str(&ngbuf->buffer, handle_buf);
	flags.call_id = bencode_strdup_str(&ngbuf->buffer, call_id);

	// populate and allocate a=mid
	if (sdp_mid)
		sp->media_id = bencode_strdup_str(&ngbuf->buffer, sdp_mid);

	// check m= line index
	if (sdp_m_line >= 0)
		sp->index = sdp_m_line + 1;

	// ufrag can be given in-line or separately
	sp->ice_ufrag = cand->ufrag;
	if (!sp->ice_ufrag.len && ufrag)
		sp->ice_ufrag = bencode_strdup_str(&ngbuf->buffer, ufrag);

	// finally do the update
	trickle_ice_update(ngbuf, call, &flags, &streams);

	return NULL;
}


static const char *janus_server_info(JsonBuilder *builder) {
	json_builder_set_member_name(builder, "name");
	json_builder_add_string_value(builder, "rtpengine Janus interface");
	json_builder_set_member_name(builder, "version_string");
	json_builder_add_string_value(builder, RTPENGINE_VERSION);
	json_builder_set_member_name(builder, "plugins");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "janus.plugin.videoroom");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "name");
	json_builder_add_string_value(builder, "rtpengine Janus videoroom");
	json_builder_end_object(builder); // }
	json_builder_end_object(builder); // }
	return "server_info";
}


static void janus_finish_response(JsonBuilder *builder, const char *success, const char *err, int retcode) {
	json_builder_set_member_name(builder, "janus");
	if (err) {
		json_builder_add_string_value(builder, "error");

		json_builder_set_member_name(builder, "error");
		json_builder_begin_object(builder); // {
		json_builder_set_member_name(builder, "code");
		json_builder_add_int_value(builder, retcode);
		json_builder_set_member_name(builder, "reason");
		json_builder_add_string_value(builder, err);
		json_builder_end_object(builder); // }

		ilog(LOG_WARN, "Janus processing returning error (code %i): %s", retcode, err);
	}
	else
		json_builder_add_string_value(builder, success);
}


static const char *websocket_janus_process_json(struct websocket_message *wm,
		uint64_t session_id, uint64_t handle_id)
{
	JsonParser *parser = NULL;
	JsonReader *reader = NULL;
	const char *err = NULL;
	int retcode = 200;
	const char *transaction = NULL;
	const char *success = "success";
	struct janus_session *session = NULL;

	ilog(LOG_DEBUG, "Processing Janus message: '%.*s'", (int) wm->body->len, wm->body->str);

	// prepare response
	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder); // {

	// start parsing message
	parser = json_parser_new();

	retcode = 454;
	err = "Failed to parse JSON";
	if (!json_parser_load_from_data(parser, wm->body->str, wm->body->len, NULL))
		goto err;
	reader = json_reader_new(json_parser_get_root(parser));
	if (!reader)
		goto err;

	retcode = 455;
	err = "JSON string is not an object";
	if (!json_reader_is_object(reader))
		goto err;

	retcode = 456;
	err = "JSON object does not contain 'janus' key";
	if (!json_reader_read_member(reader, "janus"))
		goto err;
	const char *janus_cmd = json_reader_get_string_value(reader);
	err = "'janus' key does not contain a string";
	if (!janus_cmd)
		goto err;
	json_reader_end_member(reader);

	retcode = 456;
	err = "JSON object does not contain 'transaction' key";
	if (!json_reader_read_member(reader, "transaction"))
		goto err;
	transaction = json_reader_get_string_value(reader);
	err = "'transaction' key does not contain a string";
	json_reader_end_member(reader);

	bool authorised = false;

	if (json_reader_read_member(reader, "admin_secret")) {
		const char *admin_secret = json_reader_get_string_value(reader);
		if (janus_cmd && rtpe_config.janus_secret && !strcmp(admin_secret, rtpe_config.janus_secret))
				authorised = true;
	}
	json_reader_end_member(reader);

	if (json_reader_read_member(reader, "session_id"))
		session_id = jr_str_int(reader);
	json_reader_end_member(reader);

	if (session_id)
		session = janus_get_session(session_id);

	if (json_reader_read_member(reader, "handle_id"))
		handle_id = jr_str_int(reader);
	json_reader_end_member(reader);

	ilog(LOG_DEBUG, "Processing '%s' type Janus message", janus_cmd);

	str janus_cmd_str = STR(janus_cmd);

	err = NULL;

	switch (__csh_lookup(&janus_cmd_str)) {
		case CSH_LOOKUP("add_token"):
			err = janus_add_token(reader, builder, authorised, &retcode);
			break;

		case CSH_LOOKUP("ping"):
			success = "pong";
			break;

		case CSH_LOOKUP("keepalive"):
			if (!session) {
				retcode = 458;
				err = "Session ID not found";
			}
			else
				success = "ack";
			break;

		case CSH_LOOKUP("info"):
			success = janus_server_info(builder);
			break;

		case CSH_LOOKUP("get_status"):
			// dummy output
			json_builder_set_member_name(builder, "status");
			json_builder_begin_object(builder);
			json_builder_set_member_name(builder, "token_auth");
			json_builder_add_boolean_value(builder, false);
			json_builder_end_object(builder);
			break;

		case CSH_LOOKUP("list_sessions"):
			// dummy output
			json_builder_set_member_name(builder, "sessions");
			json_builder_begin_array(builder);
			json_builder_end_array(builder);
			break;

		case CSH_LOOKUP("create"): // create new session
			err = janus_create(reader, builder, wm);
			session_id = 0; // don't add it to the reply
			break;

		case CSH_LOOKUP("attach"): // attach to a plugin, obtains handle
			err = janus_attach(reader, builder, session, &retcode);
			break;

		case CSH_LOOKUP("detach"):
			err = janus_detach(wm, reader, builder, session, handle_id, &retcode);
			break;

		case CSH_LOOKUP("destroy"): // destroy session
			err = janus_destroy(wm, reader, builder, session, &retcode);
			break;

		case CSH_LOOKUP("message"):
			err = janus_message(wm, reader, builder, session, transaction, handle_id, &success,
					&retcode);
			break;

		case CSH_LOOKUP("trickle"):
			err = janus_trickle(reader, session, handle_id, &success, &retcode);
			handle_id = 0; // don't include sender
			break;

		default:
			retcode = 457;
			err = "Unhandled request method";
			goto err;
	}

	// done

err:
	janus_finish_response(builder, success, err, retcode);

	if (transaction) {
		json_builder_set_member_name(builder, "transaction");
		json_builder_add_string_value(builder, transaction);
	}
	if (session_id) {
		json_builder_set_member_name(builder, "session_id");
		json_builder_add_int_value(builder, session_id);
	}
	if (handle_id) {
		json_builder_set_member_name(builder, "sender");
		json_builder_add_int_value(builder, handle_id);
	}
	json_builder_end_object(builder); // }

	janus_send_json_sync_response(wm, builder, 200);

	if (reader)
		g_object_unref(reader);
	if (parser)
		g_object_unref(parser);
	if (session)
		obj_put(session);

	log_info_reset();

	return NULL;
}


const char *websocket_janus_process(struct websocket_message *wm) {
	return websocket_janus_process_json(wm, 0, 0);
}


const char *websocket_janus_get(struct websocket_message *wm) {
	str uri = STR(wm->uri);

	ilog(LOG_DEBUG, "Processing Janus GET: '%s'", wm->uri);

	JsonBuilder *builder = json_builder_new();
	json_builder_begin_object(builder); // {

	int retcode = 200;
	const char *success = "success";
	const char *err = NULL;

	switch (__csh_lookup(&uri)) {
		case CSH_LOOKUP("/admin/info"):
			success = janus_server_info(builder);
			break;

		default:
			retcode = 457;
			err = "Unhandled request method";
			break;
	}

	janus_finish_response(builder, success, err, retcode);

	json_builder_end_object(builder); // }

	janus_send_json_sync_response(wm, builder, 200);

	return NULL;
}


const char *websocket_janus_post(struct websocket_message *wm) {
	str uri = STR(wm->uri);

	ilog(LOG_DEBUG, "Processing Janus POST: '%s'", wm->uri);

	uint64_t session_id = 0;
	uint64_t handle_id = 0;

	str_shift_cmp(&uri, "/");

	// parse out session ID and handle ID if given
	str s;
	if (!str_token_sep(&s, &uri, '/'))
		goto done;
	if (str_cmp(&s, "janus"))
		goto done;
	if (!str_token_sep(&s, &uri, '/'))
		goto done;
	session_id = str_to_ui(&s, 0);
	if (!str_token_sep(&s, &uri, '/'))
		goto done;
	handle_id = str_to_ui(&s, 0);

done:
	return websocket_janus_process_json(wm, session_id, handle_id);
}


void janus_init(void) {
	janus_tokens = janus_tokens_ht_new();
	janus_sessions = janus_sessions_ht_new();
	janus_handles = janus_handles_ht_new();
	janus_rooms = janus_rooms_ht_new();
	// XXX timer thread to clean up orphaned sessions
}
void janus_free(void) {
	t_hash_table_destroy(janus_tokens);
	t_hash_table_destroy(janus_sessions);
	t_hash_table_destroy(janus_handles);
	t_hash_table_destroy(janus_rooms);
}
