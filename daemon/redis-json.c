#include "redis-json.h"

#include "json-helpers.h"
#include "log_funcs.h"

#define rlog(l, x...) ilog(l | LOG_FLAG_RESTORE, x)

#define JSON_UPDATE_NUM_FIELD_IF_SET(reader, key, field) {\
	long long llval = json_reader_get_ll(reader, key); \
	if (llval >= 0) field = llval; \
}

#define JSON_UPDATE_NUM_FIELD_IF_SET_OR_FAIL(reader, key, field) {\
	long long llval = json_reader_get_ll(reader, key); \
	if (llval >= 0) field = llval; \
	else goto fail; \
}

/**
 * Helper for using obj_put as a (*GDestroyNotify) parameter for glib.
 *
 * Use it to cleanup `GQueue*`s returned from redis-json calls.
 * @param o gpointerdata that references a struct that extends `struct obj`
 */
void gdestroy_obj_put(void* o) {
	obj_put_o(o);
}

/**
 * Retrieve a list of all `redis_call_media_stream_t` across all media in the call.
 * @param callref a pointer to the `redis_call_t` data
 */
GQueue* redis_call_get_streams(redis_call_t* callref) {
	GQueue* streams;
	redis_call_media_t *media;
	unsigned midx, sidx;

	streams = g_queue_new();
	for (midx = 0; midx < g_queue_get_length(callref->media); midx++) {
		media = g_queue_peek_nth(callref->media, midx);
		for (sidx = 0; sidx < g_queue_get_length(media->streams); sidx++) {
			g_queue_push_tail(streams, obj_get((redis_call_media_stream_t*)g_queue_peek_nth(media->streams, sidx)));
		}
	}

	return streams;
}


static void redis_call_media_stream_fd_free(void *rcmsf) {
	redis_call_media_stream_fd_t *streamfdref = rcmsf;
	if (!streamfdref)
		return;
	if (streamfdref->pref_family)
		free(streamfdref->pref_family);
	if (streamfdref->logical_intf)
		free(streamfdref->logical_intf);
}

static redis_call_media_stream_fd_t *redis_call_media_stream_fd_create(unsigned unique_id, JsonNode *json) {
	redis_call_media_stream_fd_t *streamfdref = NULL;
	JsonReader *reader = NULL;

	long long llval = 0;

	reader = json_reader_new(json);
	streamfdref = obj_alloc0("redis_call_media_stream_fd", sizeof(*streamfdref), redis_call_media_stream_fd_free);
	streamfdref->unique_id = unique_id;
	JSON_UPDATE_NUM_FIELD_IF_SET_OR_FAIL(reader, "stream", streamfdref->stream_unique_id);
	streamfdref->pref_family = json_reader_get_str(reader, "pref_family");
	JSON_UPDATE_NUM_FIELD_IF_SET(reader, "localport", streamfdref->localport);
	streamfdref->logical_intf = json_reader_get_str(reader, "logical_intf");
	JSON_UPDATE_NUM_FIELD_IF_SET(reader, "local_intf_uid", streamfdref->logical_intf_uid);

	goto done;

fail:
	if (streamfdref) {
		obj_put(streamfdref);
		streamfdref = NULL;
	}

done:
	if (reader)
		g_object_unref(reader);
	return streamfdref;
}

static void redis_call_media_stream_free(void *rcms) {
	redis_call_media_stream_t *streamref = rcms;
	if (!streamref)
		return;
	if (streamref->endpoint)
		free(streamref->endpoint);
	if (streamref->advertised_endpoint)
		free(streamref->advertised_endpoint);
	if (streamref->fds)
		g_queue_free_full(streamref->fds, gdestroy_obj_put);
}

static redis_call_media_stream_t *redis_call_media_stream_create(unsigned unique_id, JsonNode *json, GQueue *sfds) {
	redis_call_media_stream_t *streamref = NULL;
	redis_call_media_stream_fd_t *streamfdref;
	JsonReader *reader = NULL;

	long long llval = 0;
	unsigned idx;

	reader = json_reader_new(json);
	streamref = obj_alloc0("redis_call_media_stream", sizeof(*streamref), redis_call_media_stream_free);
	streamref->unique_id = unique_id;
	JSON_UPDATE_NUM_FIELD_IF_SET_OR_FAIL(reader, "media", streamref->media_unique_id);
	if ((llval = json_reader_get_ll(reader, "sfd")) >= 0)
		streamref->selected_sfd = llval;
	if ((llval = json_reader_get_ll(reader, "rtp_sink")) >= 0)
		/* old code writes -1 as u_int32_t */
		streamref->rtp_sink = llval < 1000 ? llval : -1;
	if ((llval = json_reader_get_ll(reader, "rtcp_sink")) >= 0)
		/* old code writes -1 as u_int32_t */
		streamref->rtcp_sink = llval < 1000 ? llval : -1;
	if ((llval = json_reader_get_ll(reader, "rtcp_sibling")) >= 0)
		/* old code writes -1 as u_int32_t */
		streamref->rtcp_sibling = llval < 1000 ? llval : -1;
	if ((llval = json_reader_get_ll(reader, "last_packet")) >= 0)
		streamref->last_packet = llval;
	if ((llval = json_reader_get_ll(reader, "ps_flags")) >= 0)
		streamref->ps_flags = llval;
	if ((llval = json_reader_get_ll(reader, "component")) >= 0)
		streamref->component = llval;
	streamref->endpoint = json_reader_get_str(reader, "endpoint");
	streamref->advertised_endpoint = json_reader_get_str(reader, "advertised_endpoint");
	if ((llval = json_reader_get_ll(reader, "stats-packets")) >= 0)
		streamref->stats_packets = llval;
	if ((llval = json_reader_get_ll(reader, "stats-bytes")) >= 0)
		streamref->stats_bytes = llval;
	if ((llval = json_reader_get_ll(reader, "stats-errors")) >= 0)
		streamref->stats_errors = llval;

	/* grab my fds */
	streamref->fds = g_queue_new();
	for (idx = 0; idx < g_queue_get_length(sfds); idx++) {
		streamfdref = g_queue_peek_nth(sfds, idx);
		if (streamfdref && streamfdref->stream_unique_id == streamref->unique_id)
			g_queue_push_tail(streamref->fds, obj_get(streamfdref));
	}

	goto done;

fail:
	if (streamref) {
		obj_put(streamref);
		streamref = NULL;
	}

done:
	if (reader)
		g_object_unref(reader);
	return streamref;
}

static void redis_call_media_tag_free(void *rcmt) {
	redis_call_media_tag_t *tagref = rcmt;
	if (!tagref)
		return;
	if (tagref->tag)
		free(tagref->tag);
	if (tagref->viabranch)
		free(tagref->viabranch);
	if (tagref->label)
		free(tagref->label);
	/* we don't free `other_tag` - it should be owned by some media */
}

static redis_call_media_tag_t *redis_call_media_tag_create(unsigned unique_id, JsonNode *json) {
	redis_call_media_tag_t *tagref = NULL;
	JsonReader *reader = NULL;

	long long llval = 0;

	reader = json_reader_new(json);
	tagref = obj_alloc0("redis_call_media_tag", sizeof(*tagref), redis_call_media_tag_free);
	tagref->unique_id = unique_id;
	if ((llval = json_reader_get_ll(reader, "created")) >= 0)
		tagref->created = llval;
	else
		goto fail;
	if ((llval = json_reader_get_ll(reader, "active")) >= 0)
		tagref->active = llval ? TRUE : FALSE;
	if ((llval = json_reader_get_ll(reader, "deleted")) >= 0)
		tagref->deleted = llval ? TRUE : FALSE;
	if ((llval = json_reader_get_ll(reader, "block_dtmf")) >= 0)
		tagref->block_dtmf = llval ? TRUE : FALSE;
	if ((llval = json_reader_get_ll(reader, "block_media")) >= 0)
		tagref->block_media = llval ? TRUE : FALSE;
	tagref->tag = json_reader_get_str(reader, "tag");
	tagref->viabranch = json_reader_get_str(reader, "viabranch");
	tagref->label = json_reader_get_str(reader, "label");

	goto done;

fail:
	if (tagref) {
		obj_put(tagref);
		tagref = NULL;
	}

done:
	if (reader)
		g_object_unref(reader);
	return tagref;
}

static void redis_call_media_free(void* rcm) {
	redis_call_media_t *mediaref = rcm;
	if (!mediaref)
		return;
	if (mediaref->type)
		free(mediaref->type);
	if (mediaref->protocol)
		free(mediaref->protocol);
	if (mediaref->desired_family)
		free(mediaref->desired_family);
	if (mediaref->logical_intf)
		free(mediaref->logical_intf);
	if (mediaref->rtpe_addr)
		free(mediaref->rtpe_addr);
	if (mediaref->tag)
		obj_put(mediaref->tag);
	if (mediaref->streams)
		g_queue_free_full(mediaref->streams, gdestroy_obj_put);
}

static redis_call_media_t *redis_call_media_create(unsigned unique_id, JsonNode *json, GQueue *tags, GQueue *streams) {
	redis_call_media_t *mediaref = NULL;
	redis_call_media_tag_t *tagref = NULL;
	redis_call_media_stream_t *streamref = NULL;
	JsonReader *reader = NULL;

	long long llval = 0;
	unsigned idx;

	reader = json_reader_new(json);
	mediaref = obj_alloc0("redis_call_media", sizeof(*mediaref), redis_call_media_free);
	mediaref->unique_id = unique_id;
	if ((llval = json_reader_get_ll(reader, "tag")) >= 0) {
		tagref = g_queue_peek_nth(tags, llval);
		if (!tagref)
			goto fail;
		mediaref->tag = obj_get(tagref);
	}
	if ((llval = json_reader_get_ll(reader, "index")) >= 0)
		mediaref->index = llval;
	mediaref->type = json_reader_get_str(reader, "type");
	mediaref->protocol = json_reader_get_str(reader, "protocol");
	mediaref->desired_family = json_reader_get_str(reader, "desired_family");
	mediaref->logical_intf = json_reader_get_str(reader, "logical_intf");
	if ((llval = json_reader_get_ll(reader, "ptime")) >= 0)
		mediaref->ptime = llval;
	if ((llval = json_reader_get_ll(reader, "media_flags")) >= 0)
		mediaref->media_flags = llval;
	mediaref->rtpe_addr = json_reader_get_str(reader, "rtpe_addr");

	/* grab my streams */
	mediaref->streams = g_queue_new();
	for (idx = 0; idx < g_queue_get_length(streams); idx++) {
		streamref = g_queue_peek_nth(streams, idx);
		if (streamref && streamref->media_unique_id == mediaref->unique_id)
			g_queue_push_tail(mediaref->streams, obj_get(streamref));
	}

	goto done;

fail:
	if (mediaref) {
		obj_put(mediaref);
		mediaref = NULL;
	}

done:
	if (reader)
		g_object_unref(reader);
	return mediaref;
}

static void redis_call_free(void* rc) {
	redis_call_t *callref = rc;
	if (!callref)
		return;
	if (callref->media)
		g_queue_free_full(callref->media, gdestroy_obj_put);
	if (callref->call_id)
		free(callref->call_id);
	if (callref->created_from)
		free(callref->created_from);
	if (callref->created_from_addr)
		free(callref->created_from_addr);
	if (callref->recording_metadata)
		free(callref->recording_metadata);
}

static redis_call_t* redis_call_create_from_metadata(const str* callid, JsonNode* json) {
	redis_call_t *callref = NULL;
	JsonReader *reader = NULL;

	long long llval = 0;

	reader = json_reader_new(json);
	callref = obj_alloc0("redis_call", sizeof(*callref), redis_call_free);
	callref->call_id = str_dup(callid);
	if ((llval = json_reader_get_ll(reader, "created")) >= 0)
		callref->created = llval;
	else
		goto fail;
	if ((llval = json_reader_get_ll(reader, "last_signal")) >= 0)
		callref->last_signal = llval;
	if ((llval = json_reader_get_ll(reader, "deleted")) >= 0)
		callref->deleted = llval ? TRUE : FALSE;
	if ((llval = json_reader_get_ll(reader, "ml_deleted")) >= 0)
		callref->ml_deleted = llval ? TRUE : FALSE;
	callref->created_from = json_reader_get_str(reader, "created_from");
	callref->created_from_addr = json_reader_get_str(reader, "created_from_addr");
	json_reader_end_member(reader);
	if ((llval = json_reader_get_ll(reader, "redis_hosted_db")) >= 0)
		callref->redis_hosted_db = llval;
	if ((llval = json_reader_get_ll(reader, "block_dtmf")) >= 0)
		callref->block_dtmf = llval ? TRUE : FALSE;
	if ((llval = json_reader_get_ll(reader, "block_media")) >= 0)
		callref->block_media = llval ? TRUE : FALSE;

	goto done;

fail:
	if (callref) {
		obj_put(callref);
		callref = NULL;
	}

done:
	if (reader)
		g_object_unref(reader);
	return callref;
}

static int redis_call_match_tags(redis_call_media_tag_t *tag, GQueue *call_tags, JsonNode* json) {
	JsonReader *reader;
	redis_call_media_tag_t *other_tag;
	int status = 1;
	unsigned num_others, other_idx, other_tagid;

	reader = json_reader_new(json);
	if (!json_reader_is_array(reader))
		goto fail;

	num_others = json_reader_count_elements(reader);
	if (num_others < 0)
		goto fail;

	for (other_idx = 0; other_idx < num_others; other_idx++) {
		other_tagid = json_reader_get_ll_element(reader, other_idx);
		if (other_tagid < 0)
			goto fail;
		other_tag = g_queue_peek_nth(call_tags, other_tagid);
		if (!other_tag)
			goto fail;
		tag->other_tag = other_tag;
		other_tag->other_tag = tag;
	}

	goto done;

fail:
	status = 0;

done:
	if (reader)
		g_object_unref(reader);
	return status;
}

static GQueue *redis_call_read_tags(JsonReader *reader) {
	GQueue *call_tags = NULL;
	unsigned tag_idx, other_tags_idx;
	str *tag_field = NULL;
	redis_call_media_tag_t *tag = NULL;

	call_tags = g_queue_new();
	for (tag_idx = 0; ; tag_idx++) {
		tag_field = str_sprintf("tag-%u", tag_idx);
		if (!json_reader_read_member(reader, tag_field->s)) {
			break; /* no more tags */
		}
		tag = redis_call_media_tag_create(tag_idx, json_reader_get_value(reader));
		if (!tag)
			goto fail;
		g_queue_push_tail(call_tags, tag);
		json_reader_end_member(reader);
		free(tag_field);
	}

	for (other_tags_idx = 0; other_tags_idx < tag_idx; other_tags_idx++) {
		json_reader_end_member(reader);
		free(tag_field);
		tag_field = str_sprintf("other_tags-%d", other_tags_idx);
		if (json_reader_read_member(reader, tag_field->s)) {
			tag = g_queue_peek_nth(call_tags, other_tags_idx);
			if (!tag) /* shouldn't actually happen, but we're sanity-first! */
				goto fail;
			if (!redis_call_match_tags(tag, call_tags, json_reader_get_value(reader)))
				goto fail;
		} /* missing other_tags list is treated like an empty list */
	}

	goto done;

fail:
	if (call_tags) {
		g_queue_free_full(call_tags, gdestroy_obj_put);
		call_tags = NULL;
	}

done:
	if (tag_field)
		free(tag_field);
	json_reader_end_member(reader);
	return call_tags;
}

static GQueue *redis_call_read_stream_fds(JsonReader *reader) {
	GQueue *call_sfds;
	unsigned sfd_idx;
	str* sfd_field;
	redis_call_media_stream_fd_t* sfd;

	call_sfds = g_queue_new();
	for (sfd_idx = 0; ; sfd_idx++) {
		sfd_field = str_sprintf("sfd-%u", sfd_idx);
		if (!json_reader_read_member(reader, sfd_field->s))
			goto done; /* no more sfds */
		sfd = redis_call_media_stream_fd_create(sfd_idx, json_reader_get_value(reader));
		if (!sfd)
			goto fail;
		g_queue_push_tail(call_sfds, sfd);
		json_reader_end_member(reader);
		free(sfd_field);
	}

	/* we shouldn't reach this point, but just playing it safe */
	sfd_field = NULL;
	goto done;

fail:
	if (call_sfds) {
		g_queue_free_full(call_sfds, gdestroy_obj_put);
		call_sfds = NULL;
	}

done:
	if (sfd_field)
		free(sfd_field);
	json_reader_end_member(reader);
	return call_sfds;
}

static GQueue *redis_call_read_streams(JsonReader *reader) {
	GQueue *call_streams = NULL, *call_sfds = NULL;
	unsigned stream_idx;
	str *stream_field = NULL;
	redis_call_media_stream_t *stream;

	if (!(call_sfds = redis_call_read_stream_fds(reader)))
		goto fail;
	call_streams = g_queue_new();
	for (stream_idx = 0; ; stream_idx++) {
		stream_field = str_sprintf("stream-%u", stream_idx);
		if (!json_reader_read_member(reader, stream_field->s))
			goto done; /* no more streams */
			stream = redis_call_media_stream_create(stream_idx, json_reader_get_value(reader), call_sfds);
		if (!stream)
			goto fail;
		g_queue_push_tail(call_streams, stream);
		json_reader_end_member(reader);
		free(stream_field);
	}

	/* we shouldn't reach this point, but just playing it safe */
	stream_field = NULL;
	goto done;

fail:
	if (call_streams) {
		g_queue_free_full(call_streams, gdestroy_obj_put);
		call_streams = NULL;
	}

done:
	if (stream_field)
		free(stream_field);
	if (call_sfds)
		g_queue_free_full(call_sfds, gdestroy_obj_put);
	json_reader_end_member(reader);
	return call_streams;
}

static GQueue *redis_call_read_media(JsonReader *reader) {
	int media_idx;
	str *media_field = NULL;
	GQueue *call_media = NULL, *call_tags = NULL, *call_streams = NULL;
	redis_call_media_t *media = NULL;

	if (!(call_tags = redis_call_read_tags(reader)))
		goto fail;
	if (!(call_streams = redis_call_read_streams(reader)))
		goto fail;
	call_media = g_queue_new();
	for (media_idx = 0; ; media_idx++) {
		media_field = str_sprintf("media-%u", media_idx);
		if (!json_reader_read_member(reader, media_field->s)) {
			goto done; /* no more media */
		}
		media = redis_call_media_create(media_idx, json_reader_get_value(reader), call_tags, call_streams);
		if (!media)
			goto fail;
		g_queue_push_tail(call_media, media);
		json_reader_end_member(reader);
		free(media_field);
	}

	/* not supposed to get here, but just making sure */
	media_field = NULL;
	goto done;

fail:
	if (call_media)
		g_queue_free_full(call_media, gdestroy_obj_put);

done:
	json_reader_end_member(reader);
	if (media_field)
		free(media_field);
	if (call_tags)
		g_queue_free_full(call_tags, gdestroy_obj_put);
	if (call_streams)
		g_queue_free_full(call_streams, gdestroy_obj_put);
	return call_media;
}

redis_call_t* redis_call_create(const str* callid, JsonNode* json) {
	redis_call_t* callref = NULL;
	JsonReader* root_reader = NULL;

	const char *err = 0;

	root_reader = json_reader_new(json);
	if (!json_reader_read_member(root_reader, "json")) {
		err = "Could not find call data";
		goto fail;
	}
	callref = redis_call_create_from_metadata(callid, json_reader_get_value(root_reader));
	json_reader_end_member(root_reader);
	if (!callref) {
		err = "Failed to read call data";
		goto fail;
	}
	if (!(callref->media = redis_call_read_media(root_reader))) {
		err = "Failed to read call media";
		goto fail;
	}

	goto done;

fail:
	if (callref) {
		obj_put(callref);
		callref = NULL;
	}
	if (err) {
		rlog(LOG_WARNING, "Failed to read call data '" STR_FORMAT_M "' from Redis: %s",
		     STR_FMT_M(callid),
		     err);
	}

done:
	if (root_reader)
		g_object_unref(root_reader);
	return callref;
}
