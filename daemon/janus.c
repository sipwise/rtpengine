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


struct janus_session { // "login" session
	struct obj obj;
	uint64_t id;
	mutex_t lock;
	time_t last_act;
	GHashTable *websockets; // controlling transports
	GHashTable *handles;
};
struct janus_handle { // corresponds to a conference participant
	uint64_t id;
	uint64_t session;
	uint64_t room;
};
struct janus_room {
	uint64_t id;
	str call_id;
	int num_publishers;
	struct janus_session *session; // controlling session
	uint64_t handle_id; // controlling handle which created the room
	GHashTable *publishers; // handle ID -> feed ID
	GHashTable *subscribers; // handle ID -> subscribed feed ID
};


static mutex_t janus_lock;
static GHashTable *janus_tokens;
static GHashTable *janus_sessions;
static GHashTable *janus_handles;
static GHashTable *janus_rooms;
static GHashTable *janus_feeds;


static void __janus_session_free(void *p) {
	struct janus_session *s = p;
	g_hash_table_destroy(s->websockets);
	g_hash_table_destroy(s->handles);
	mutex_destroy(&s->lock);
}


// XXX we have several hash tables that hold references to objs - unify all these
static struct janus_session *janus_get_session(uint64_t id) {
	mutex_lock(&janus_lock);
	struct janus_session *ret = g_hash_table_lookup(janus_sessions, &id);
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


// frees 'builder'
static const char *janus_send_json_msg(struct websocket_message *wm, JsonBuilder *builder, int code, bool done) {
	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	char *result = json_generator_to_data(gen, NULL);

	json_node_free(root);
	g_object_unref(gen);
	g_object_unref(builder);

	const char *ret = NULL;

	if (wm->method == M_WEBSOCKET)
		websocket_write_text(wm->wc, result, done);
	else {
		if (!code)
			ret = "Tried to send asynchronous event to HTTP";
		else if (websocket_http_response(wm->wc, code, "application/json", strlen(result)))
			ret = "Failed to write Janus response HTTP headers";
		else if (websocket_write_http(wm->wc, result, done))
			ret = "Failed to write Janus JSON response";
	}

	g_free(result);

	return ret;
}


static void janus_send_ack(struct websocket_message *wm, const char *transaction, uint64_t session_id) {
	// build and send an early ack
	JsonBuilder *ack = json_builder_new();
	json_builder_begin_object(ack); // {
	json_builder_set_member_name(ack, "janus");
	json_builder_add_string_value(ack, "ack");
	json_builder_set_member_name(ack, "transaction");
	json_builder_add_string_value(ack, transaction);
	json_builder_set_member_name(ack, "session_id");
	json_builder_add_int_value(ack, session_id);
	json_builder_end_object(ack); // }

	janus_send_json_msg(wm, ack, 0, false);
}


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
	room->session = obj_get(session); // XXX replace with just the ID?
	room->handle_id = handle->id; // controlling handle
	// XXX optimise for 64-bit archs
	room->publishers = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
	room->subscribers = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);

	uint64_t room_id = 0;
	if (json_reader_read_member(reader, "room")) {
		room_id = jr_str_int(reader);
		if (!room_id)
			return "Invalid room ID requested";
	}
	json_reader_end_member(reader);

	mutex_lock(&janus_lock);

	if (room_id) {
		*retcode = 512;
		if (g_hash_table_lookup(janus_rooms, &room_id)) {
			mutex_unlock(&janus_lock);
			return "Requested room already exists";
		}
	}

	while (1) {
		if (!room_id)
			room_id = janus_random();
		room->id = room_id;
		if (g_hash_table_lookup(janus_rooms, &room->id))
			continue;
		room->call_id.s = g_strdup_printf("janus %" PRIu64, room_id);
		room->call_id.len = strlen(room->call_id.s);
		struct call *call = call_get_or_create(&room->call_id, false, true);
		if (!call) {
			ilog(LOG_WARN, "Call with reserved Janus ID '" STR_FORMAT
					"' already exists", STR_FMT(&room->call_id));
			g_free(room->call_id.s);
			continue;
		}
		if (!call->created_from)
			call->created_from = "janus";
		g_hash_table_insert(janus_rooms, &room->id, room);
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
		break;
	}

	handle->room = room_id;

	mutex_unlock(&janus_lock);

	ilog(LOG_INFO, "Created new videoroom with ID %" PRIu64, room_id);

	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "created");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "permanent");
	json_builder_add_boolean_value(builder, false);

	return NULL;
}


static const char *janus_videoroom_exists(struct janus_session *session,
		JsonBuilder *builder, uint64_t room_id)
{
	struct janus_room *room = NULL;

	bool exists = false;

	{
		LOCK(&janus_lock);

		if (room_id)
			room = g_hash_table_lookup(janus_rooms, &room_id);
		if (room && room->session != session)
			room = NULL;
		if (room) {
			struct call *call = call_get(&room->call_id);
			if (call) {
				exists = true;
				rwlock_unlock_w(&call->master_lock);
				obj_put(call);
			}
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


static const char *janus_videoroom_destroy(struct janus_session *session,
		JsonBuilder *builder, int *retcode, uint64_t room_id)
{
	struct janus_room *room = NULL;

	{
		LOCK(&janus_lock);

		if (room_id)
			room = g_hash_table_lookup(janus_rooms, &room_id);
		if (room && room->session != session)
			room = NULL;
		*retcode = 426;
		if (!room)
			return "No such room";

		ilog(LOG_INFO, "Destroying videoroom with ID %" PRIu64, room_id);

		g_hash_table_remove(janus_rooms, &room_id);
	}

	struct call *call = call_get(&room->call_id);
	// XXX if call is destroyed separately, room persist -> room should be destroyed too
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		call_destroy(call);
		obj_put(call);
	}

	g_free(room->call_id.s);
	obj_put(room->session);
	g_hash_table_destroy(room->publishers);
	g_hash_table_destroy(room->subscribers);
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


static void janus_publishers_list(JsonBuilder *builder, struct janus_room *room, uint64_t feed_id) {
	json_builder_begin_array(builder); // [

	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, room->publishers);

	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		uint64_t *u64 = value;
		if (*u64 == feed_id) // skip self
			continue;
		json_builder_begin_object(builder); // {
		json_builder_set_member_name(builder, "id");
		json_builder_add_int_value(builder, *u64);
		// XXX
		json_builder_end_object(builder); // }
	}

	json_builder_end_array(builder); // ]
}


static const char *janus_videoroom_join_sub(struct janus_handle *handle, struct janus_room *room, int *retcode,
		uint64_t feed_id, struct call *call, GQueue *srcs)
{
	// does the feed actually exist? get the feed handle
	*retcode = 512;
	uint64_t *feed_handle = g_hash_table_lookup(janus_feeds, &feed_id);
	if (!feed_handle)
		return "No such feed exists";
	if (!g_hash_table_lookup(room->publishers, feed_handle))
		return "No such feed handle exists";

	// handle ID points to the subscribed feed
	g_hash_table_insert(room->subscribers, uint64_dup(handle->id), uint64_dup(feed_id));

	// add the subscription
	AUTO_CLEANUP_GBUF(source_handle_buf);
	source_handle_buf = g_strdup_printf("%" PRIu64, *feed_handle);
	str source_handle_str;
	str_init(&source_handle_str, source_handle_buf);
	struct call_monologue *source_ml = call_get_monologue(call, &source_handle_str);
	if (!source_ml)
		return "Feed not found";

	struct call_subscription *cs = g_slice_alloc0(sizeof(*cs));
	cs->monologue = source_ml;
	g_queue_push_tail(srcs, cs);

	return NULL;
}


static void janus_clear_ret_streams(GQueue *q) {
	uint64_t *id;
	while ((id = g_queue_pop_head(q)))
		g_slice_free1(sizeof(*id), id);
}


static const char *janus_videoroom_join(struct websocket_message *wm, struct janus_session *session,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcode,
		char **jsep_type_out, str *jsep_sdp_out,
		uint64_t room_id)
{
	janus_send_ack(wm, transaction, session->id);

	*retcode = 456;
	if (!json_reader_read_member(reader, "ptype"))
		return "JSON object does not contain 'message.ptype' key";
	const char *ptype = json_reader_get_string_value(reader);
	if (!ptype)
		return "JSON object does not contain 'message.ptype' key";
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

	{
		LOCK(&janus_lock);

		struct janus_room *room = NULL;
		if (room_id)
			room = g_hash_table_lookup(janus_rooms, &room_id);
		*retcode = 426;
		if (!room)
			return "No such room";

		// XXX more granular locking?
		*retcode = 436;
		if (!is_pub && g_hash_table_lookup(room->subscribers, &handle->id))
			return "User already exists in the room as a subscriber";
		if (is_pub && g_hash_table_lookup(room->publishers, &handle->id))
			return "User already exists in the room as a publisher";

		uint64_t feed_id = 0; // set for single feed IDs, otherwise remains 0
		AUTO_CLEANUP_INIT(GString *feed_ids, __g_string_free, g_string_new("feeds ")); // for log output
		AUTO_CLEANUP(GQueue ret_streams, janus_clear_ret_streams) = G_QUEUE_INIT; // return list for multiple subs

		if (is_pub) {
			// random feed ID
			while (1) {
				feed_id = janus_random();
				if (!feed_id)
					continue;
				if (g_hash_table_lookup(janus_feeds, &feed_id))
					continue;
				break;
			}

			// feed ID points to the handle
			g_hash_table_insert(janus_feeds, uint64_dup(feed_id), uint64_dup(handle->id));
			// handle ID points to the feed
			g_hash_table_insert(room->publishers, uint64_dup(handle->id), uint64_dup(feed_id));
		}
		else {
			// subscriber

			AUTO_CLEANUP(GQueue srcs, call_subscriptions_clear) = G_QUEUE_INIT;
			AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
			*retcode = 426;
			call = call_get(&room->call_id);
			if (!call)
				return "No such room";

			// get single feed ID if there is one
			if (json_reader_read_member(reader, "feed")) {
				*retcode = 456;
				feed_id = jr_str_int(reader);
				if (!feed_id)
					return "JSON object contains invalid 'message.feed' key";
				const char *ret = janus_videoroom_join_sub(handle, room, retcode, feed_id,
						call, &srcs);
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
					const char *ret = janus_videoroom_join_sub(handle, room, retcode, fid,
						call, &srcs);
					if (ret)
						return ret;
					json_reader_end_member(reader);
					json_reader_end_element(reader);

					g_string_append_printf(feed_ids, "%" PRIu64 ", ", fid);

					uint64_t *fidp = g_slice_alloc(sizeof(*fidp));
					*fidp = fid;
					g_queue_push_tail(&ret_streams, fidp);
				}
			}
			json_reader_end_member(reader);

			*retcode = 456;
			if (!srcs.length)
				return "No feeds to subscribe to given";

			AUTO_CLEANUP_GBUF(dest_handle_buf);
			dest_handle_buf = g_strdup_printf("%" PRIu64, handle->id);
			str dest_handle_str;
			str_init(&dest_handle_str, dest_handle_buf);
			struct call_monologue *dest_ml = call_get_or_create_monologue(call, &dest_handle_str);

			AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
			call_ng_flags_init(&flags, OP_REQUEST);

			// set all WebRTC-specific attributes
			flags.transport_protocol = &transport_protocols[PROTO_UDP_TLS_RTP_SAVPF];
			flags.ice_option = ICE_FORCE;
			flags.trickle_ice = 1;
			flags.generate_mid = 1;
			flags.rtcp_mux_offer = 1;
			flags.rtcp_mux_require = 1;
			flags.no_rtcp_attr = 1;
			flags.sdes_off = 1;
			flags.rtcp_mirror = 1;

			int ret = monologue_subscribe_request(&srcs, dest_ml, &flags);
			if (ret)
				return "Subscribe error";

			// create SDP: if there's only one subscription, we can use the original
			// SDP, otherwise we generate a new one
			if (srcs.length == 1) {
				struct call_subscription *cs = srcs.head->data;
				struct call_monologue *source_ml = cs->monologue;
				struct sdp_chopper *chopper = sdp_chopper_new(&source_ml->last_in_sdp);
				ret = sdp_replace(chopper, &source_ml->last_in_sdp_parsed, dest_ml, &flags);
				sdp_chopper_destroy_ret(chopper, jsep_sdp_out);
			}
			else
				ret = sdp_create(jsep_sdp_out, dest_ml, &flags);

			if (!dest_ml->janus_session)
				dest_ml->janus_session = obj_get(session);

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
			janus_publishers_list(builder, room, feed_id);
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
				for (GList *l = ret_streams.head; l; l = l->next) {
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
	}

	return NULL;
}


static void janus_notify_publishers(struct websocket_message *wm, uint64_t room_id, uint64_t except) {
	LOCK(&janus_lock);

	struct janus_room *room = g_hash_table_lookup(janus_rooms, &room_id);
	if (!room)
		return;
	if (!room->session)
		return;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, room->publishers);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		uint64_t *handle = key;
		if (*handle == except)
			continue;

		uint64_t *feed = value;

		JsonBuilder *event = json_builder_new();
		json_builder_begin_object(event); // {
		json_builder_set_member_name(event, "janus");
		json_builder_add_string_value(event, "event");
		json_builder_set_member_name(event, "session_id");
		json_builder_add_int_value(event, room->session->id);
		json_builder_set_member_name(event, "sender");
		json_builder_add_int_value(event, *handle); // destination of notification
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
		json_builder_set_member_name(event, "publishers");
		janus_publishers_list(event, room, *feed);
		json_builder_end_object(event); // }
		json_builder_end_object(event); // }
		json_builder_end_object(event); // }

		janus_send_json_msg(wm, event, 0, false);
	}
}


static const char *janus_videoroom_configure(struct websocket_message *wm, struct janus_session *session,
		const char *jsep_type, const char *jsep_sdp,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcode,
		char **jsep_type_out, str *jsep_sdp_out,
		uint64_t room_id)
{
	janus_send_ack(wm, transaction, session->id);

	*retcode = 456;
	if (!room_id)
		room_id = handle->room;
	if (!room_id)
		return "JSON object does not contain 'message.room' key";
	json_reader_end_member(reader);

//	bool is_audio = true;
//	if (json_reader_read_member(reader, "audio"))
//		is_audio = json_reader_get_boolean_value(reader);
//	json_reader_end_member(reader);

//	bool is_video = true;
//	if (json_reader_read_member(reader, "video"))
//		is_video = json_reader_get_boolean_value(reader);
//	json_reader_end_member(reader);

	*retcode = 512;

	if (handle->room != room_id)
		return "Not in the room";
	if (!jsep_type || !jsep_sdp)
		return "No SDP";
	if (strcmp(jsep_type, "offer"))
		return "Not an offer";

	AUTO_CLEANUP(str sdp_in, str_free_dup) = STR_NULL;
	str_init_dup(&sdp_in, jsep_sdp);

	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	AUTO_CLEANUP(GQueue parsed, sdp_free) = G_QUEUE_INIT;
	AUTO_CLEANUP(GQueue streams, sdp_streams_free) = G_QUEUE_INIT;
	call_ng_flags_init(&flags, OP_PUBLISH);
	*retcode = 512;
	if (sdp_parse(&sdp_in, &parsed, &flags))
		return "Failed to parse SDP";
	if (sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);

	{
		LOCK(&janus_lock);

		struct janus_room *room = g_hash_table_lookup(janus_rooms, &room_id);
		*retcode = 426;
		if (!room)
			return "No such room";
		call = call_get(&room->call_id);
		// XXX if call is destroyed separately, room persists -> room should be destroyed too
		if (!call)
			return "No such room";
		*retcode = 512;
		if (!g_hash_table_lookup(room->publishers, &handle->id))
			return "Not a publisher";
	}

	AUTO_CLEANUP_GBUF(handle_buf);
	handle_buf = g_strdup_printf("%" PRIu64, handle->id);
	str handle_str;
	str_init(&handle_str, handle_buf);
	struct call_monologue *ml = call_get_or_create_monologue(call, &handle_str);

	// accept unsupported codecs if necessary
	flags.accept_any = 1;

	int ret = monologue_publish(ml, &streams, &flags);
	if (ret)
		return "Publish error";

	// XXX check there's only one audio and one video stream?

	AUTO_CLEANUP(str sdp_out, str_free_dup) = STR_NULL;
	ret = sdp_create(&sdp_out, ml, &flags);
	if (ret)
		return "Publish error";

	if (!ml->janus_session)
		ml->janus_session = obj_get(session);

	save_last_sdp(ml, &sdp_in, &parsed, &streams);
	*jsep_sdp_out = sdp_out;
	sdp_out = STR_NULL; // ownership passed to output

	*jsep_type_out = "answer";

	*successp = "event";
	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "event");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "configured");
	json_builder_add_string_value(builder, "ok");

	json_builder_set_member_name(builder, "streams");
	json_builder_begin_array(builder);

	const char *a_codec = NULL, *v_codec = NULL;

	for (GList *l = ml->medias.head; l; l = l->next) {
		struct call_media *media = l->data;

		const char *codec = NULL;
		for (GList *k = media->codecs.codec_prefs.head; k; k = k->next) {
			struct rtp_payload_type *pt = k->data;
			codec = pt->encoding.s;
			// XXX check codec support?
			break;
		}

		json_builder_begin_object(builder);

		json_builder_set_member_name(builder, "type");
		json_builder_add_string_value(builder, media->type.s);
		json_builder_set_member_name(builder, "mindex");
		json_builder_add_int_value(builder, media->index - 1);
		json_builder_set_member_name(builder, "mid");
		if (media->media_id.s)
			json_builder_add_string_value(builder, media->media_id.s);
		else
			json_builder_add_null_value(builder);
		json_builder_set_member_name(builder, "codec");
		if (codec)
			json_builder_add_string_value(builder, codec);
		else
			json_builder_add_null_value(builder);

		json_builder_end_object(builder);

		if (media->type_id == MT_AUDIO)
			a_codec = codec;
		else if (media->type_id == MT_VIDEO)
			v_codec = codec;
	}

	json_builder_end_array(builder);

	json_builder_set_member_name(builder, "audio_codec");
	if (a_codec)
		json_builder_add_string_value(builder, a_codec);
	else
		json_builder_add_null_value(builder);

	json_builder_set_member_name(builder, "video_codec");
	if (v_codec)
		json_builder_add_string_value(builder, v_codec);
	else
		json_builder_add_null_value(builder);

	janus_notify_publishers(wm, room_id, handle->id);

	return NULL;
}


static const char *janus_videoroom_start(struct websocket_message *wm, struct janus_session *session,
		const char *jsep_type, const char *jsep_sdp,
		const char *transaction,
		struct janus_handle *handle, JsonBuilder *builder, JsonReader *reader, const char **successp,
		int *retcode,
		uint64_t room_id)
{
	janus_send_ack(wm, transaction, session->id);

	*retcode = 456;
	if (!json_reader_read_member(reader, "feed"))
		return "JSON object does not contain 'message.feed' key";
	uint64_t feed_id = jr_str_int(reader); // needed?
	if (!feed_id)
		return "JSON object does not contain 'message.feed' key";
	if (!room_id)
		return "JSON object does not contain 'message.room' key";
	json_reader_end_member(reader);

	if (handle->room != room_id)
		return "Not in the room";
	if (!jsep_type || !jsep_sdp)
		return "No SDP";
	if (strcmp(jsep_type, "answer"))
		return "Not an answer";

	AUTO_CLEANUP(str sdp_in, str_free_dup) = STR_NULL;
	str_init_dup(&sdp_in, jsep_sdp);

	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	AUTO_CLEANUP(GQueue parsed, sdp_free) = G_QUEUE_INIT;
	AUTO_CLEANUP(GQueue streams, sdp_streams_free) = G_QUEUE_INIT;
	call_ng_flags_init(&flags, OP_PUBLISH);
	*retcode = 512;
	if (sdp_parse(&sdp_in, &parsed, &flags))
		return "Failed to parse SDP";
	if (sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);

	{
		LOCK(&janus_lock);

		struct janus_room *room = g_hash_table_lookup(janus_rooms, &room_id);
		*retcode = 426;
		if (!room)
			return "No such room";
		call = call_get(&room->call_id);
		if (!call)
			return "No such room";
		*retcode = 456;
		if (!g_hash_table_lookup(room->subscribers, &handle->id))
			return "Not a subscriber";

		*retcode = 512;
		uint64_t *feed_handle = g_hash_table_lookup(janus_feeds, &feed_id);
		if (!feed_handle)
			return "No such feed exists";

		AUTO_CLEANUP_GBUF(source_handle_buf);
		source_handle_buf = g_strdup_printf("%" PRIu64, *feed_handle);
		str source_handle_str;
		str_init(&source_handle_str, source_handle_buf);
		struct call_monologue *source_ml = call_get_monologue(call, &source_handle_str);
		if (!source_ml)
			return "Feed not found";
		// XXX verify that dest_ml is subscribed to source_ml

		AUTO_CLEANUP_GBUF(dest_handle_buf);
		dest_handle_buf = g_strdup_printf("%" PRIu64, handle->id);
		str dest_handle_str;
		str_init(&dest_handle_str, dest_handle_buf);
		struct call_monologue *dest_ml = call_get_monologue(call, &dest_handle_str);
		if (!dest_ml)
			return "Subscriber not found";

		int ret = monologue_subscribe_answer(dest_ml, &flags, &streams);
		if (ret)
			return "Failed to process subscription answer";
	}

	*successp = "event";
	json_builder_set_member_name(builder, "videoroom");
	json_builder_add_string_value(builder, "event");
	json_builder_set_member_name(builder, "room");
	json_builder_add_int_value(builder, room_id);
	json_builder_set_member_name(builder, "started");
	json_builder_add_string_value(builder, "ok");

	return NULL;
}


// session is locked, which also locks handle
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
	str req_str;
	str_init(&req_str, (char *) req);
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


const char *janus_add_token(JsonReader *reader, JsonBuilder *builder, bool authorised, int *retcode) {
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
	g_hash_table_replace(janus_tokens, g_strdup(token), now);
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


const char *janus_create(JsonReader *reader, JsonBuilder *builder, struct websocket_message *wm) {
	uint64_t session_id = 0;
	if (json_reader_read_member(reader, "id"))
		session_id = jr_str_int(reader);
	json_reader_end_member(reader);

	struct janus_session *session = obj_alloc0("janus_session", sizeof(*session), __janus_session_free);
	mutex_init(&session->lock);
	mutex_lock(&session->lock); // not really necessary but Coverity complains
	session->last_act = rtpe_now.tv_sec;
	session->websockets = g_hash_table_new(g_direct_hash, g_direct_equal);
	session->handles = g_hash_table_new(g_int64_hash, g_int64_equal);

	g_hash_table_insert(session->websockets, wm->wc, wm->wc);

	do {
		while (!session_id)
			session_id = janus_random();

		mutex_lock(&janus_lock);
		if (g_hash_table_lookup(janus_sessions, &session_id))
			session_id = 0; // pick a random one
		else {
			session->id = session_id;
			g_hash_table_insert(janus_sessions, &session->id, obj_get(session));
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

	return NULL;
}


void janus_detach_websocket(struct janus_session *session, struct websocket_conn *wc) {
	LOCK(&session->lock);
	g_hash_table_remove(session->websockets, wc);
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

	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	char *result = json_generator_to_data(gen, NULL);

	json_node_free(root);
	g_object_unref(gen);
	g_object_unref(builder);

	// lock order constraint: janus_session lock first, websocket_conn lock second

	LOCK(&session->lock);

	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, session->websockets);

	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		struct websocket_conn *wc = value;
		websocket_write_text(wc, result, true);
	}

	g_free(result);
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
		json_builder_add_string_value(builder, media->media_id.s);
	else
		json_builder_add_null_value(builder);
	json_builder_set_member_name(builder, "type");
	json_builder_add_string_value(builder, media->type.s);
	json_builder_set_member_name(builder, "receiving");
	json_builder_add_boolean_value(builder, true);
	json_builder_end_object(builder); // }

	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_builder_get_root(builder);
	json_generator_set_root(gen, root);
	char *result = json_generator_to_data(gen, NULL);

	json_node_free(root);
	g_object_unref(gen);
	g_object_unref(builder);

	// lock order constraint: janus_session lock first, websocket_conn lock second

	LOCK(&session->lock);

	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, session->websockets);

	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		struct websocket_conn *wc = value;
		websocket_write_text(wc, result, true);
	}

	g_free(result);
}


const char *janus_attach(JsonReader *reader, JsonBuilder *builder, struct janus_session *session, int *retcode) {
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
	handle->session = session->id;
	uint64_t handle_id = 0;
	while (1) {
		handle_id = handle->id = janus_random();
		if (g_hash_table_lookup(janus_handles, &handle->id))
			continue;
		g_hash_table_insert(janus_handles, &handle->id, (void *) 0x1);
		break;
	}
	mutex_unlock(&janus_lock);

	mutex_lock(&session->lock);
	assert(g_hash_table_lookup(session->handles, &handle_id) == NULL);
	g_hash_table_insert(session->handles, &handle->id, handle);
	mutex_unlock(&session->lock);
	// handle is now owned by session

	json_builder_set_member_name(builder, "data");
	json_builder_begin_object(builder); // {
	json_builder_set_member_name(builder, "id");
	json_builder_add_int_value(builder, handle_id);
	json_builder_end_object(builder); // }

	return NULL;
}


const char *janus_detach(struct websocket_message *wm, JsonReader *reader, JsonBuilder *builder,
		struct janus_session *session,
		uint64_t handle_id, int *retcode)
{
	*retcode = 458;
	if (!session)
		return "Session ID not found";
	*retcode = 457;
	if (!handle_id)
		return "Unhandled request method";

	uint64_t room_id = 0;

	{
		LOCK(&session->lock);
		struct janus_handle *handle = g_hash_table_lookup(session->handles, &handle_id);

		*retcode = 463;
		if (!handle)
			return "Could not detach handle from plugin";

		room_id = handle->room;

		// destroy handle
		g_hash_table_remove(session->handles, &handle_id);
		g_slice_free1(sizeof(*handle), handle);
	}

	{
		LOCK(&janus_lock);

		if (room_id) {
			struct janus_room *room = g_hash_table_lookup(janus_rooms, &room_id);
			if (room) {
				uint64_t *feed = g_hash_table_lookup(room->publishers, &handle_id);
				if (feed) {
					// was a publisher - send notify

					GHashTableIter iter;
					gpointer key;
					g_hash_table_iter_init(&iter, room->publishers);

					while (g_hash_table_iter_next(&iter, &key, NULL)) {
						uint64_t *pub_handle = key;

						if (*pub_handle == handle_id) // skip self
							continue;

						JsonBuilder *event = json_builder_new();
						json_builder_begin_object(event); // {
						json_builder_set_member_name(event, "janus");
						json_builder_add_string_value(event, "event");
						json_builder_set_member_name(event, "session_id");
						json_builder_add_int_value(event, room->session->id);
						json_builder_set_member_name(event, "sender");
						json_builder_add_int_value(event, *pub_handle);
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
						json_builder_set_member_name(event, "unpublished");
						json_builder_add_int_value(event, *feed);
						json_builder_end_object(event); // }
						json_builder_end_object(event); // }
						json_builder_end_object(event); // }

						janus_send_json_msg(wm, event, 0, false);

						event = json_builder_new();
						json_builder_begin_object(event); // {
						json_builder_set_member_name(event, "janus");
						json_builder_add_string_value(event, "event");
						json_builder_set_member_name(event, "session_id");
						json_builder_add_int_value(event, room->session->id);
						json_builder_set_member_name(event, "sender");
						json_builder_add_int_value(event, *pub_handle);
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
						json_builder_set_member_name(event, "leaving");
						json_builder_add_int_value(event, *feed);
						json_builder_end_object(event); // }
						json_builder_end_object(event); // }
						json_builder_end_object(event); // }

						janus_send_json_msg(wm, event, 0, false);
					}

					struct call *call = call_get(&room->call_id);
					if (call) {
						// remove publisher monologue
						AUTO_CLEANUP_GBUF(handle_buf);
						handle_buf = g_strdup_printf("%" PRIu64, handle_id);
						str handle_str;
						str_init(&handle_str, handle_buf);
						struct call_monologue *ml = call_get_or_create_monologue(call,
								&handle_str);
						if (ml)
							monologue_destroy(ml);

						rwlock_unlock_w(&call->master_lock);
						obj_put(call);
					}

					g_hash_table_remove(room->publishers, &handle_id);
					feed = NULL;
				}

				if (g_hash_table_remove(room->subscribers, &handle_id)) {
					// was a subscriber
					struct call *call = call_get(&room->call_id);
					if (call) {
						// remove subscriber monologue
						AUTO_CLEANUP_GBUF(handle_buf);
						handle_buf = g_strdup_printf("%" PRIu64, handle_id);
						str handle_str;
						str_init(&handle_str, handle_buf);
						struct call_monologue *ml = call_get_or_create_monologue(call,
								&handle_str);
						if (ml)
							monologue_destroy(ml);

						rwlock_unlock_w(&call->master_lock);
						obj_put(call);
					}
				}
			}
		}
	}

	return NULL;
}


const char *janus_message(struct websocket_message *wm, JsonReader *reader, JsonBuilder *builder,
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
	str jsep_sdp_out = STR_NULL;

	mutex_lock(&session->lock);

	struct janus_handle *handle = g_hash_table_lookup(session->handles, &handle_id);

	const char *err = NULL;
	if (!handle) {
		*retcode = 457;
		err = "No plugin handle given or invalid handle";
	}
	else
		err = janus_videoroom(wm, session, jsep_type, jsep_sdp, transaction, handle,
				builder, reader, successp, retcode, &jsep_type_out,
				&jsep_sdp_out);

	mutex_unlock(&session->lock);

	json_builder_end_object(builder); // }
	json_builder_end_object(builder); // }

	if (jsep_type_out && jsep_sdp_out.len) {
		json_builder_set_member_name(builder, "jsep");
		json_builder_begin_object(builder); // {
		json_builder_set_member_name(builder, "type");
		json_builder_add_string_value(builder, jsep_type_out);
		json_builder_set_member_name(builder, "sdp");
		json_builder_add_string_value(builder, jsep_sdp_out.s);
		json_builder_end_object(builder); // }
	}

	str_free_dup(&jsep_sdp_out);

	return err;

}


const char *janus_trickle(JsonReader *reader, struct janus_session *session, uint64_t handle_id,
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

	// fetch call and monologue

	uint64_t room_id = 0;
	{
		LOCK(&session->lock);

		struct janus_handle *handle = g_hash_table_lookup(session->handles, &handle_id);

		if (!handle)
			return "Unhandled request method";

		room_id = handle->room;
	}

	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	{
		LOCK(&janus_lock);

		struct janus_room *room = g_hash_table_lookup(janus_rooms, &room_id);

		*retcode = 426;
		if (!room)
			return "No such room";
		call = call_get(&room->call_id);
		if (!call)
			return "No such room";
	}

	AUTO_CLEANUP_GBUF(handle_buf);
	handle_buf = g_strdup_printf("%" PRIu64, handle_id);
	str handle_str;
	str_init(&handle_str, handle_buf);
	struct call_monologue *ml = call_get_monologue(call, &handle_str);
	if (!ml)
		return "Handle not found in room";

	// find our media section
	struct call_media *media = NULL;
	if (sdp_mid) {
		str sdp_mid_str = STR_CONST_INIT_LEN((char *) sdp_mid, strlen(sdp_mid));
		media = g_hash_table_lookup(ml->media_ids, &sdp_mid_str);
	}
	if (!media && sdp_m_line >= 0)
		media = g_queue_peek_nth(&ml->medias, sdp_m_line);

	*retcode = 466;
	if (!media)
		return "No matching media";
	if (!media->ice_agent)
		return "Media is not ICE-enabled";

	// parse candidate
	str cand_str = STR_CONST_INIT_LEN((char *) candidate, strlen(candidate));
	str_shift_cmp(&cand_str, "candidate:"); // skip prefix
	if (!cand_str.len) {
		// end of candidates
	}
	else {
		struct ice_candidate cand;
		*retcode = 466;
		int ret = sdp_parse_candidate(&cand, &cand_str);
		if (ret < 0)
			return "Failed to parse trickle candidate";

		if (ret == 0) {
			// do the actual ICE update
			struct stream_params sp = {
				.ice_ufrag = cand.ufrag,
				.index = media->index,
			};
			if (!sp.ice_ufrag.len && ufrag)
				str_init(&sp.ice_ufrag, (char *) ufrag);
			g_queue_push_tail(&sp.ice_candidates, &cand);

			ice_update(media->ice_agent, &sp, false);

			g_queue_clear(&sp.ice_candidates);
		}
	}

	*successp = "ack";
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

	str janus_cmd_str;
	str_init(&janus_cmd_str, (char *) janus_cmd);

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

	err = janus_send_json_msg(wm, builder, 200, true);

	if (reader)
		g_object_unref(reader);
	if (parser)
		g_object_unref(parser);
	if (session)
		obj_put(session);

	return err;
}


const char *websocket_janus_process(struct websocket_message *wm) {
	return websocket_janus_process_json(wm, 0, 0);
}


const char *websocket_janus_get(struct websocket_message *wm) {
	str uri;
	str_init(&uri, wm->uri);

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

	return janus_send_json_msg(wm, builder, 200, true);
}


const char *websocket_janus_post(struct websocket_message *wm) {
	str uri;
	str_init(&uri, wm->uri);

	ilog(LOG_DEBUG, "Processing Janus POST: '%s'", wm->uri);

	uint64_t session_id = 0;
	uint64_t handle_id = 0;

	str_shift_cmp(&uri, "/");

	// parse out session ID and handle ID if given
	str s;
	if (str_token_sep(&s, &uri, '/'))
		goto done;
	if (str_cmp(&s, "janus"))
		goto done;
	if (str_token_sep(&s, &uri, '/'))
		goto done;
	session_id = str_to_ui(&s, 0);
	if (str_token_sep(&s, &uri, '/'))
		goto done;
	handle_id = str_to_ui(&s, 0);

done:
	return websocket_janus_process_json(wm, session_id, handle_id);
}


void janus_init(void) {
	mutex_init(&janus_lock);
	janus_tokens = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	janus_sessions = g_hash_table_new(g_int64_hash, g_int64_equal);
	janus_handles = g_hash_table_new(g_int64_hash, g_int64_equal);
	janus_rooms = g_hash_table_new(g_int64_hash, g_int64_equal);
	janus_feeds = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
	// XXX timer thread to clean up orphaned sessions
}
void janus_free(void) {
	mutex_destroy(&janus_lock);
	g_hash_table_destroy(janus_tokens);
	g_hash_table_destroy(janus_sessions);
	g_hash_table_destroy(janus_handles);
	g_hash_table_destroy(janus_rooms);
	g_hash_table_destroy(janus_feeds);
}
