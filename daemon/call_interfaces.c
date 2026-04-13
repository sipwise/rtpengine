#include "call_interfaces.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <pcre2.h>
#include <inttypes.h>

#include "call.h"
#include "helpers.h"
#include "log.h"
#include "redis.h"
#include "sdp.h"
#include "str.h"
#include "control_tcp.h"
#include "control_udp.h"
#include "control_ng.h"
#include "rtp.h"
#include "ice.h"
#include "recording.h"
#include "rtplib.h"
#include "ssrc.h"
#include "tcp_listener.h"
#include "streambuf.h"
#include "main.h"
#include "load.h"
#include "media_player.h"
#include "dtmf.h"
#include "codec.h"
#include "dtmf.h"
#include "call_flags.h"


static pcre2_code *info_re;
static pcre2_code *streams_re;

str_case_value_ht rtpe_signalling_templates;
str rtpe_default_signalling_templates[OP_COUNT + 1];

enum basic_errors {
	NG_ERROR_NO_SDP_BODY = 1,
	NG_ERROR_NO_CALL_ID = 2,
	NG_ERROR_NO_FROM_TAG = 3,
	NG_ERROR_NO_TO_TAG = 4
};

static const char* _ng_basic_errors[] = {
    [NG_ERROR_NO_SDP_BODY] = "No SDP body in message",
    [NG_ERROR_NO_CALL_ID] = "No call-id in message",
    [NG_ERROR_NO_FROM_TAG] = "No from-tag in message",
    [NG_ERROR_NO_TO_TAG] = "No to-tag in message",
};

static void ng_stats_ssrc(const ng_parser_t *parser, parser_arg dict, parser_arg list,
		const struct ssrc_hash *ht);
static void call_set_dtmf_block(call_t *call, struct call_monologue *monologue, sdp_ng_flags *flags);


static str streams_print(medias_arr *s, int start, int end, const char *prefix, enum stream_address_format format) {
	GString *o;
	int i, af, port;
	struct call_media *media;
	struct packet_stream *ps;

	o = g_string_new("");
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	for (i = start; i <= end; i++) {
		if (s->len <= i || (media = s->pdata[i - 1]) == NULL) {
			ilog(LOG_WARNING, "Requested media index %i not found", i);
			break;
		}

		if (!media->streams.head) {
			ilog(LOG_WARNING, "Media has no streams");
			break;
		}
		ps = media->streams.head->data;

		if (format == SAF_TCP)
			call_stream_address(o, ps, format, NULL, true);

		port = ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0;
		g_string_append_printf(o, (format == 1) ? "%i " : " %i", port);

		if (format == SAF_UDP) {
			af = call_stream_address(o, ps, format, NULL, true);
			g_string_append_printf(o, " %c", (af == AF_INET) ? '4' : '6');
		}

	}

	g_string_append(o, "\n");

	return g_string_free_str(o);
}

static int addr_parse_udp(struct stream_params *sp, char **out) {
	const char *cp;
	char c;
	int i;

	ZERO(*sp);

	SP_SET(sp, SEND);
	SP_SET(sp, RECV);
	sp->protocol = &transport_protocols[PROTO_UNKNOWN];

	if (out[RE_UDP_UL_ADDR4] && *out[RE_UDP_UL_ADDR4]) {
		if (!sockaddr_parse_any(&sp->rtp_endpoint.address, out[RE_UDP_UL_ADDR4]))
			goto fail;
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (!sockaddr_parse_any(&sp->rtp_endpoint.address, out[RE_UDP_UL_ADDR6]))
			goto fail;
	}
	else
		goto fail;

	sp->rtp_endpoint.port = atoi(out[RE_UDP_UL_PORT]);
	if (!sp->rtp_endpoint.port && strcmp(out[RE_UDP_UL_PORT], "0"))
		goto fail;

	if (out[RE_UDP_UL_FLAGS] && *out[RE_UDP_UL_FLAGS]) {
		i = 0;
		for (cp =out[RE_UDP_UL_FLAGS]; *cp && i < 2; cp++) {
			c = chrtoupper(*cp);
			if (c == 'E')
				sp->direction[i++] = STR("external");
			else if (c == 'I')
				sp->direction[i++] = STR("internal");
		}
	}

	if (out[RE_UDP_UL_NUM] && *out[RE_UDP_UL_NUM])
		sp->index = atoi(out[RE_UDP_UL_NUM]);
	if (!sp->index)
		sp->index = 1;
	sp->consecutive_ports = 1;

	sp->rtcp_endpoint = sp->rtp_endpoint;
	sp->rtcp_endpoint.port++;

	return 0;
fail:
	return -1;
}

static void updated_created_from(call_t *c, const char *addr) {
	if (!c->created_from.len && addr)
		c->created_from = call_str_cpy_c(addr);
}

static str call_update_lookup_udp(char **out, enum ng_opmode opmode, const char* addr) {
	call_t *c;
	struct call_monologue *monologues[2]; /* subscriber lists of both monologues */
	sdp_streams_q q = TYPED_GQUEUE_INIT;
	struct stream_params sp;
	str ret;
	int i;

	g_auto(sdp_ng_flags) flags;
	call_ng_flags_init(&flags, opmode);

	str callid = STR(out[RE_UDP_UL_CALLID]);
	str fromtag = STR(out[RE_UDP_UL_FROMTAG]);
	str totag = STR(out[RE_UDP_UL_TOTAG]);
	if (opmode == OP_ANSWER)
		str_swap(&fromtag, &totag);

	c = call_get_opmode(&callid, opmode);
	if (!c) {
		ilog(LOG_WARNING, "[" STR_FORMAT_M "] Got UDP LOOKUP for unknown call-id",
			STR_FMT_M(&callid));
		return str_sprintf("%s 0 0.0.0.0\n", out[RE_UDP_COOKIE]);
	}

	updated_created_from(c, addr);

	if (call_get_mono_dialogue(monologues, c, &fromtag, &totag, NULL, NULL, NULL))
		goto ml_fail;

	struct call_monologue *from_ml = monologues[0];
	struct call_monologue *to_ml = monologues[1];

	if (opmode == OP_OFFER) {
		from_ml->tagtype = FROM_TAG;
	} else {
		from_ml->tagtype = TO_TAG;
	}

	if (addr_parse_udp(&sp, out))
		goto addr_fail;

	t_queue_push_tail(&q, &sp);
	i = monologue_offer_answer(monologues, &q, &flags);
	t_queue_clear(&q);

	if (i)
		goto unlock_fail;

	ret = streams_print(to_ml->medias,
			sp.index, sp.index, out[RE_UDP_COOKIE], SAF_UDP);
	rwlock_unlock_w(&c->master_lock);

	redis_update_onekey(c, rtpe_redis_write);

	from_ml->started = rtpe_now;

	ilog(LOG_INFO, "Returning to SIP proxy: " STR_FORMAT, STR_FMT(&ret));
	goto out;

ml_fail:
	ilog(LOG_ERR, "Invalid dialogue association");
	goto unlock_fail;

addr_fail:
	ilog(LOG_ERR, "Failed to parse a media stream: %s%s/%s:%s%s",
			FMT_M(out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]));
	goto unlock_fail;

unlock_fail:
	rwlock_unlock_w(&c->master_lock);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	obj_put(c);
	return ret;
}

str call_update_udp(char **out, const char* addr) {
	return call_update_lookup_udp(out, OP_OFFER, addr);
}
str call_lookup_udp(char **out) {
	return call_update_lookup_udp(out, OP_ANSWER, NULL);
}


static bool info_parse_func(char **a, void **ret, void *p) {
	if (!a[0] || !a[1])
		return false;

	GHashTable *ih = p;

	g_hash_table_replace(ih, strdup(a[0]), strdup(a[1]));

	return false;
}

static void info_parse(const char *s, GHashTable *ih) {
	pcre2_multi_match(info_re, s, 3, info_parse_func, ih, NULL);
}


static bool streams_parse_func(char **a, void **ret, void *p) {
	if (!a[0] || !a[1])
		return false;

	struct stream_params *sp;
	int *i;

	i = p;
	sp = g_new0(__typeof(*sp), 1);

	SP_SET(sp, SEND);
	SP_SET(sp, RECV);
	sp->protocol = &transport_protocols[PROTO_UNKNOWN];

	if (!endpoint_parse_port_any(&sp->rtp_endpoint, a[0], atoi(a[1])))
		goto fail;

	sp->index = ++(*i);
	sp->consecutive_ports = 1;

	sp->rtcp_endpoint = sp->rtp_endpoint;
	sp->rtcp_endpoint.port++;

	if (!sp->rtp_endpoint.port && strcmp(a[1], "0"))
		goto fail;

	*ret = sp;
	return true;

fail:
	ilog(LOG_WARNING, "Failed to parse a media stream: %s%s:%s%s", FMT_M(a[0], a[1]));
	g_free(sp);
	return false;
}


static void streams_parse(const char *s, sdp_streams_q *q) {
	int i;
	i = 0;
	pcre2_multi_match(streams_re, s, 4, streams_parse_func, &i, &q->q);
}
INLINE void call_unlock_release_update(call_t **c) {
	if (!*c)
		return;
	rwlock_unlock_w(&(*c)->master_lock);
	redis_update_onekey(*c, rtpe_redis_write);
	obj_release(*c);
}



static str call_request_lookup_tcp(char **out, enum ng_opmode opmode) {
	call_t *c;
	struct call_monologue *monologues[2];
	g_auto(sdp_streams_q) s = TYPED_GQUEUE_INIT;
	str ret = STR_NULL;
	GHashTable *infohash;

	g_auto(sdp_ng_flags) flags;
	call_ng_flags_init(&flags, opmode);

	str callid = STR(out[RE_TCP_RL_CALLID]);
	infohash = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	c = call_get_opmode(&callid, opmode);
	if (!c) {
		ilog(LOG_WARNING, "[" STR_FORMAT_M "] Got LOOKUP for unknown call-id", STR_FMT_M(&callid));
		goto out;
	}

	info_parse(out[RE_TCP_RL_INFO], infohash);
	streams_parse(out[RE_TCP_RL_STREAMS], &s);
	str fromtag = STR(g_hash_table_lookup(infohash, "fromtag"));
	if (!fromtag.s) {
		ilog(LOG_WARNING, "No from-tag in message");
		goto out2;
	}
	str totag = STR(g_hash_table_lookup(infohash, "totag"));
	if (opmode == OP_ANSWER) {
		if (!totag.s) {
			ilog(LOG_WARNING, "No to-tag in message");
			goto out2;
		}
		str_swap(&fromtag, &totag);
	}

	if (call_get_mono_dialogue(monologues, c, &fromtag, &totag, NULL, NULL, NULL)) {
		ilog(LOG_WARNING, "Invalid dialogue association");
		goto out2;
	}
	if (monologue_offer_answer(monologues, &s, &flags))
		goto out2;

	ret = streams_print(monologues[1]->medias, 1, s.length, NULL, SAF_TCP);

out2:
	call_unlock_release_update(&c);
	ilog(LOG_INFO, "Returning to SIP proxy: " STR_FORMAT, STR_FMT(&ret));

out:
	g_hash_table_destroy(infohash);
	return ret;
}

str call_request_tcp(char **out) {
	return call_request_lookup_tcp(out, OP_OFFER);
}
str call_lookup_tcp(char **out) {
	return call_request_lookup_tcp(out, OP_ANSWER);
}

str call_delete_udp(char **out) {
	__C_DBG("got delete for callid '%s' and viabranch '%s'",
		out[RE_UDP_DQ_CALLID], out[RE_UDP_DQ_VIABRANCH]);

	str callid = STR(out[RE_UDP_DQ_CALLID]);
	str branch = STR(out[RE_UDP_DQ_VIABRANCH]);
	str fromtag = STR(out[RE_UDP_DQ_FROMTAG]);
	str totag = STR(out[RE_UDP_DQ_TOTAG]);

	if (call_delete_branch_by_id(&callid, &branch, &fromtag, &totag, NULL, -1))
		return str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);

	return str_sprintf("%s 0\n", out[RE_UDP_COOKIE]);
}
str call_query_udp(char **out) {
	g_autoptr(call_t) c = NULL;
	str ret;
	struct call_stats stats;

	__C_DBG("got query for callid '%s'", out[RE_UDP_DQ_CALLID]);

	str callid = STR(out[RE_UDP_DQ_CALLID]);
	str fromtag = STR(out[RE_UDP_DQ_FROMTAG]);
	str totag = STR(out[RE_UDP_DQ_TOTAG]);

	c = call_get(&callid);
	if (!c) {
		ilog(LOG_INFO, "[" STR_FORMAT_M "] Call-ID to query not found", STR_FMT_M(&callid));
		goto err;
	}

	ng_call_stats(NULL, c, &fromtag, &totag, &stats);

	rwlock_unlock_w(&c->master_lock);

	ret = str_sprintf("%s %" PRId64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", out[RE_UDP_COOKIE],
		atomic_get_na(&rtpe_config.silent_timeout_us) - (rtpe_now - stats.last_packet_us),
		atomic64_get_na(&stats.totals[0].packets), atomic64_get_na(&stats.totals[1].packets),
		atomic64_get_na(&stats.totals[2].packets), atomic64_get_na(&stats.totals[3].packets));
	goto out;

err:
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	return ret;
}

void call_delete_tcp(char **out) {
	str callid = STR(out[RE_TCP_D_CALLID]);
	call_delete_branch_by_id(&callid, NULL, NULL, NULL, NULL, -1);
}

static void call_status_iterator(call_t *c, struct streambuf_stream *s) {
//	GList *l;
//	struct callstream *cs;
//	struct peer *p;
//	struct streamrelay *r1, *r2;
//	struct streamrelay *rx1, *rx2;
//	char addr1[64], addr2[64], addr3[64];

//	mutex_lock(&c->master_lock);

	streambuf_printf(s->outbuf, "session "STR_FORMAT" - - - - %" PRId64 "\n",
		STR_FMT(&c->callid),
		(rtpe_now - c->created) / 1000000L);

	/* XXX restore function */

//	mutex_unlock(&c->master_lock);
}

void calls_status_tcp(struct streambuf_stream *s) {
	rwlock_lock_r(&rtpe_callhash_lock);
	streambuf_printf(s->outbuf, "proxy %u %" PRIu64 "/%i/%i\n",
		t_hash_table_size(rtpe_callhash),
		atomic64_get(&rtpe_stats_rate.bytes_user) + atomic64_get(&rtpe_stats_rate.bytes_kernel), 0, 0);
	rwlock_unlock_r(&rtpe_callhash_lock);

	ITERATE_CALL_LIST_START(CALL_ITERATOR_MAIN, c);
		call_status_iterator(c, s);
	ITERATE_CALL_LIST_NEXT_END(c);
}


INLINE void call_ngb_hold_ref(call_t *c, ng_buffer *ngb) {
	/* We cannot guarantee that the "call" structures are still around at the time
	 * when the bencode reply is finally read and sent out. Since we use scatter/gather
	 * to avoid duplication of strings and stuff, we reserve a reference to the call
	 * structs and have it released when the bencode buffer is destroyed. This is
	 * necessary every time the bencode response may reference strings contained
	 * within the call structs. */
	ngb->call = obj_get(c);
}

static void ng_sdp_attr_manipulations_free(struct sdp_manipulations * array[__MT_MAX]) {
	for (int i = 0; i < __MT_MAX; i++) {
		struct sdp_manipulations *sdp_manipulations = array[i];
		if (!sdp_manipulations)
			continue;

		str_case_ht_destroy_ptr(&sdp_manipulations->rem_commands);
		str_case_value_ht_destroy_ptr(&sdp_manipulations->subst_commands);
		t_queue_clear_full(&sdp_manipulations->add_commands, str_free);

		g_free(sdp_manipulations);

		array[i] = NULL;
	}
}

static void ng_codecs_free(struct ng_codec *c) {
	g_free(c);
}

static void ng_media_free(struct ng_media *m) {
	t_queue_clear_full(&m->codecs, ng_codecs_free);
	t_queue_clear_full(&m->codec_list, str_free);
	g_free(m);
}

void call_ng_free_flags(sdp_ng_flags *flags) {
	str_case_value_ht_destroy_ptr(&flags->codec_set);
	if (flags->frequencies)
		g_array_free(flags->frequencies, true);

#define X(x) t_queue_clear_full(&flags->x, str_free);
RTPE_NG_FLAGS_STR_Q_PARAMS
#undef X

#define X(x) t_queue_clear_full(&flags->x, sdp_attr_free);
RTPE_NG_FLAGS_SDP_ATTR_Q_PARAMS
#undef X

#define X(x) str_case_ht_destroy_ptr(&flags->x);
RTPE_NG_FLAGS_STR_CASE_HT_PARAMS
#undef X

	str_ht_destroy_ptr(&flags->bundles);
	ng_sdp_attr_manipulations_free(flags->sdp_manipulations);

	t_queue_clear_full(&flags->medias, ng_media_free);
	t_queue_clear(&flags->groups_other);
}

static enum load_limit_reasons call_offer_session_limit(void) {
	enum load_limit_reasons ret = LOAD_LIMIT_NONE;

	if (atomic_get_na(&rtpe_config.max_sessions) >= 0) {
		rwlock_lock_r(&rtpe_callhash_lock);
		if (t_hash_table_size(rtpe_callhash) -
				atomic64_get(&rtpe_stats_gauge.foreign_sessions) >= rtpe_config.max_sessions)
		{
			/* foreign calls can't get rejected
			 * total_rejected_sess applies only to "own" sessions */
			RTPE_STATS_INC(rejected_sess);
			ilog(LOG_ERROR, "Parallel session limit reached (%i)",rtpe_config.max_sessions);

			ret = LOAD_LIMIT_MAX_SESSIONS;
		}
		rwlock_unlock_r(&rtpe_callhash_lock);
	}

	if (ret == LOAD_LIMIT_NONE && atomic_get_na(&rtpe_config.load_limit)) {
		int loadavg = g_atomic_int_get(&load_average);
		if (loadavg >= atomic_get_na(&rtpe_config.load_limit)) {
			ilog(LOG_WARN, "Load limit exceeded (%.2f > %.2f)",
					(double) loadavg / 100.0, (double) rtpe_config.load_limit / 100.0);
			ret = LOAD_LIMIT_LOAD;
		}
	}

	if (ret == LOAD_LIMIT_NONE && atomic_get_na(&rtpe_config.cpu_limit)) {
		int cpu = g_atomic_int_get(&cpu_usage);
		if (cpu >= atomic_get_na(&rtpe_config.cpu_limit)) {
			ilog(LOG_WARN, "CPU usage limit exceeded (%.1f%% > %.1f%%)",
					(double) cpu / 100.0, (double) rtpe_config.cpu_limit / 100.0);
			ret = LOAD_LIMIT_CPU;
		}
	}

	if (ret == LOAD_LIMIT_NONE && atomic_get_na(&rtpe_config.bw_limit)) {
		uint64_t bw = atomic64_get(&rtpe_stats_rate.bytes_user) +
			atomic64_get(&rtpe_stats_rate.bytes_kernel);
		if (bw >= atomic_get_na(&rtpe_config.bw_limit)) {
			ilog(LOG_WARN, "Bandwidth limit exceeded (%" PRIu64 " > %" PRIu64 ")",
					bw, rtpe_config.bw_limit);
			ret = LOAD_LIMIT_BW;
		}
	}

	return ret;
}


static enum basic_errors call_ng_basic_checks(sdp_ng_flags *flags)
{
	if (!flags->sdp.s)
		return NG_ERROR_NO_SDP_BODY;
	if (!flags->call_id.s)
		return NG_ERROR_NO_CALL_ID;
	if (!flags->from_tag.s)
		return NG_ERROR_NO_FROM_TAG;
	if (flags->opmode == OP_ANSWER && !flags->to_tag.s)
		return NG_ERROR_NO_TO_TAG;
	return 0;
}

static const char *call_offer_get_call(call_t **callp, sdp_ng_flags *flags) {
	// are we allowed to create a call? use `errstr` to determine
	const char *errstr = NULL; // creation is allowed
	enum load_limit_reasons limit = call_offer_session_limit();
	if (limit != LOAD_LIMIT_NONE) {
		if (!flags->supports_load_limit)
			errstr = "Parallel session limit reached"; // legacy protocol
		else
			errstr = magic_load_limit_strings[limit];
		// errstr is set, creation not allowed
	}

	if (!errstr)
		*callp = call_get_or_create(&flags->call_id, false);
	else {
		*callp = call_get(&flags->call_id);
		if (!*callp)
			return errstr;
	}

	return NULL;
}

static const char *call_offer_answer_ng(ng_command_ctx_t *ctx, const char *addr) {
	const char *errstr;
	str sdp = STR_NULL;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	g_autoptr(call_t) call = NULL;
	struct call_monologue *monologues[2];
	int ret;
	g_auto(sdp_ng_flags) flags;
	parser_arg output = ctx->resp;
	const ng_parser_t *parser = ctx->parser_ctx.parser;
	g_auto(str) sdp_out = STR_NULL;

	call_ng_process_flags(&flags, ctx);

	if ((ret = call_ng_basic_checks(&flags)) > 0)
		return _ng_basic_errors[ret];

	if (flags.opmode == OP_OFFER) {
		errstr = call_offer_get_call(&call, &flags);
		if (errstr)
			goto out;
	}
	else if (flags.opmode == OP_ANSWER) {
		call = call_get(&flags.call_id);

		errstr = "Unknown call-id";
		if (!call)
			goto out;

		/* for answer: swap To against From tag  */
		str_swap(&flags.to_tag, &flags.from_tag);
	}

	sdp = call_str_cpy(&flags.sdp);

	errstr = "Failed to parse SDP";
	if (!sdp_parse(&sdp, &parsed, &flags))
		goto out;

	if (flags.loop_protect && sdp_is_duplicate(&parsed)) {
		ilog(LOG_INFO, "Ignoring message as SDP has already been processed by us");
		parser->dict_add_str(output, "sdp", &flags.sdp);
		errstr = NULL;
		goto out;
	}

	errstr = "Incomplete SDP specification";
	if (!sdp_streams(&parsed, &streams, &flags))
		goto out;

	// SDP fragments for trickle ICE must always operate on an existing call
	if (flags.opmode == OP_OFFER && trickle_ice_update(ctx->ngbuf, call, &flags, &streams)) {
		errstr = NULL;
		// SDP fragments for trickle ICE are consumed with no replacement returned
		goto out;
	}

	if (flags.debug)
		CALL_SET(call, DEBUG);

	if (rtpe_config.active_switchover && IS_FOREIGN_CALL(call))
		call_make_own_foreign(call, false);

	updated_created_from(call, addr);

	if (flags.xmlrpc_callback.len)
		call->xmlrpc_callback = call_str_cpy(&flags.xmlrpc_callback);
	if (flags.dtmf_log_dest.address.family)
		call->dtmf_log_dest = flags.dtmf_log_dest;

	/* At least the random ICE strings are contained within the call struct, so we
	 * need to hold a ref until we're done sending the reply */
	call_ngb_hold_ref(call, ctx->ngbuf);

	errstr = "Invalid dialogue association";
	if (call_get_mono_dialogue(monologues, call, &flags.from_tag, &flags.to_tag,
			flags.via_branch.s ? &flags.via_branch : NULL, &flags,
			streams.length ? &streams.head->data->rtp_endpoint : NULL)) {
		goto out;
	}

	struct call_monologue *from_ml = monologues[0];
	struct call_monologue *to_ml = monologues[1];

	if (flags.opmode == OP_OFFER) {
		from_ml->tagtype = FROM_TAG;
	} else {
		from_ml->tagtype = TO_TAG;
	}

	if (flags.drop_traffic_start) {
		CALL_SET(call, DROP_TRAFFIC);
	}
	else if (flags.drop_traffic_stop) {
		CALL_CLEAR(call, DROP_TRAFFIC);
	}

	if (flags.block_dtmf)
		call_set_dtmf_block(call, from_ml, &flags);

	if (flags.alias_key == AK_SDP)
		t_hash_table_insert(call->sdps, call_str_dup(&sdp), from_ml);
	else if (flags.alias_key == AK_ADDRESS && streams.length && streams.head->data->rtp_endpoint.port)
		t_hash_table_insert(call->endpoints, memory_arena_objdup(streams.head->data->rtp_endpoint),
				from_ml);

	struct recording *recording = NULL;

	/* offer/answer model processing */
	if ((ret = monologue_offer_answer(monologues, &streams, &flags)) == 0) {
		update_metadata_monologue(from_ml, &flags);
		detect_setup_recording(call, &flags);

		recording = call->recording;

		meta_write_sdp_before(recording, &sdp, from_ml, flags.opmode);

		/* check if sender's monologue has any audio medias putting the call
		 * into the sendonly state, if so, check if it wants this call
		 * to be provided with moh playbacks */
		errstr = call_check_moh(from_ml, to_ml, &flags);
		if (errstr)
			goto out;

		/* if all fine, prepare an outer sdp and save it */
		if (sdp_create(&sdp_out, to_ml, &flags)) {
			/* TODO: should we save sdp_out? */
			ret = 0;
		}
		else
			ret = -1;

		/* place return output SDP */
		ctx->ngbuf->sdp_out = sdp_out.s;
		ctx->parser_ctx.parser->dict_add_str(output, "sdp", &sdp_out);

		meta_write_sdp_after(recording, &sdp_out, from_ml, flags.opmode);

		sdp_out = STR_NULL; /* ownership passed to output */
	}

	recording_response(recording, ctx->parser_ctx.parser, output);

	dequeue_sdp_fragments(from_ml);

	rwlock_unlock_w(&call->master_lock);

	if (!flags.no_redis_update) {
			redis_update_onekey(call, rtpe_redis_write);
	} else {
		ilog(LOG_DEBUG, "Not updating Redis due to present no-redis-update flag");
	}

	from_ml->started = rtpe_now;

	errstr = "Error rewriting SDP";

	if (ret == ERROR_NO_FREE_PORTS || ret == ERROR_NO_FREE_LOGS) {
		ilog(LOG_ERR, "Destroying call");
		errstr = "Ran out of ports";
		call_destroy(call);
	}
	obj_release(call);

	if (ret)
		goto out;

	errstr = NULL;
out:
	return errstr;
}

const char *call_offer_ng(ng_command_ctx_t *ctx,
		const char *addr)
{
	return call_offer_answer_ng(ctx, addr);
}

const char *call_answer_ng(ng_command_ctx_t *ctx) {
	return call_offer_answer_ng(ctx, NULL);
}

const char *call_delete_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) rtpp_flags;
	parser_arg output = ctx->resp;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	call_ng_process_flags(&rtpp_flags, ctx);

	if (!rtpp_flags.call_id.len)
		return "No call-id in message";

	call_t *c = call_get(&rtpp_flags.call_id);
	if (!c)
		goto err;

	if (rtpp_flags.discard_recording)
		recording_discard(c);

	if (call_delete_branch(c, &rtpp_flags.via_branch,
				&rtpp_flags.from_tag,
				(rtpp_flags.to_tag_flag ? &rtpp_flags.to_tag : NULL),
				ctx, rtpp_flags.delete_delay))
	{
		goto err;
	}

	return NULL;

err:
	if (rtpp_flags.fatal)
		return "Call-ID not found or tags didn't match";
	parser->dict_add_string(output, "warning", "Call-ID not found or tags didn't match");
	return NULL;
}

static void ng_stats(ng_command_ctx_t *ctx, parser_arg dict, const char *dict_name,
		const struct stream_stats *s,
		struct stream_stats *totals)
{
	if (ctx) {
		const ng_parser_t *parser = ctx->parser_ctx.parser;
		parser_arg d = parser->dict_add_dict(dict, dict_name);
		parser->dict_add_int(d, "packets", atomic64_get_na(&s->packets));
		parser->dict_add_int(d, "bytes", atomic64_get_na(&s->bytes));
		parser->dict_add_int(d, "errors", atomic64_get_na(&s->errors));
	}
	if (!totals)
		return;
	atomic64_add_na(&totals->packets, atomic64_get(&s->packets));
	atomic64_add_na(&totals->bytes, atomic64_get(&s->bytes));
	atomic64_add_na(&totals->errors, atomic64_get(&s->errors));
}

static void ng_stats_endpoint(const ng_parser_t *parser, parser_arg dict, const endpoint_t *ep) {
	if (!ep->address.family)
		return;
	parser->dict_add_string(dict, "family", ep->address.family->name);
	parser->dict_add_str_dup(dict, "address", STR_PTR(sockaddr_print_buf(&ep->address)));
	parser->dict_add_int(dict, "port", ep->port);
}

#define BF_PS(k, f) if (PS_ISSET(ps, f)) parser->list_add_string(flags, k)

static void ng_stats_stream(ng_command_ctx_t *ctx, parser_arg list, const struct packet_stream *ps,
		struct call_stats *totals)
{
	parser_arg dict = {0}, flags;
	struct stream_stats *s;

	if (!ctx)
		goto stats;

	const ng_parser_t *parser = ctx->parser_ctx.parser;

	dict = parser->list_add_dict(list);

	if (ps->selected_sfd && ps->selected_sfd->socket.local.address.family) {
		parser->dict_add_int(dict, "local port", ps->selected_sfd->socket.local.port);
		parser->dict_add_str_dup(dict, "local address",
				STR_PTR(sockaddr_print_buf(&ps->selected_sfd->socket.local.address)));
		parser->dict_add_string(dict, "family", ps->selected_sfd->socket.local.address.family->name);
	}
	ng_stats_endpoint(parser, parser->dict_add_dict(dict, "endpoint"), &ps->endpoint);
	ng_stats_endpoint(parser, parser->dict_add_dict(dict, "advertised endpoint"),
			&ps->advertised_endpoint);
	if (ps->crypto.params.crypto_suite)
		parser->dict_add_string(dict, "crypto suite",
				ps->crypto.params.crypto_suite->name);
	parser->dict_add_int(dict, "last packet", packet_stream_last_packet(ps) / 1000000L);
	parser->dict_add_int(dict, "last kernel packet", atomic64_get_na(&ps->stats_in->last_packet_us) / 1000000L);
	parser->dict_add_int(dict, "last user packet", atomic64_get_na(&ps->last_packet_us) / 1000000L);

	__auto_type se = call_get_first_ssrc(&ps->media->ssrc_hash_in);
	if (se)
		parser->dict_add_int(dict, "SSRC", se->h.ssrc);

	flags = parser->dict_add_list(dict, "flags");

	BF_PS("RTP", RTP);
	BF_PS("RTCP", RTCP);
	BF_PS("fallback RTCP", FALLBACK_RTCP);
	BF_PS("filled", FILLED);
	if (ps->selected_sfd && ps->selected_sfd->confirmed)
		parser->list_add_string(flags, "confirmed");
	if (ps->selected_sfd && ps->selected_sfd->kernelized)
		parser->list_add_string(flags, "kernelized");
	BF_PS("no kernel support", NO_KERNEL_SUPPORT);
	BF_PS("DTLS fingerprint verified", FINGERPRINT_VERIFIED);
	BF_PS("strict source address", STRICT_SOURCE);
	BF_PS("media handover", MEDIA_HANDOVER);
	BF_PS("ICE", ICE);

stats:
	if (totals->last_packet_us < packet_stream_last_packet(ps))
		totals->last_packet_us = packet_stream_last_packet(ps);

	/* XXX distinguish between input and output */
	s = &totals->totals[0];
	if (!PS_ISSET(ps, RTP))
		s = &totals->totals[1];
	ng_stats(ctx, dict, "stats", ps->stats_in, s);
	ng_stats(ctx, dict, "stats_out", ps->stats_out, NULL);
}

#define BF_M(k, f) if (MEDIA_ISSET(m, f)) parser->list_add_string(flags, k)

static void ng_stats_media(ng_command_ctx_t *ctx, parser_arg list, const struct call_media *m,
		struct call_stats *totals, parser_arg ssrc)
{
	parser_arg dict, streams = {0}, flags;
	struct packet_stream *ps;
	const rtp_payload_type *rtp_pt = NULL;

	if (!ctx)
		goto stats;

	const ng_parser_t *parser = ctx->parser_ctx.parser;

	rtp_pt = __rtp_stats_codec((struct call_media *)m);

	dict = parser->list_add_dict(list);

	parser->dict_add_int(dict, "index", m->index);
	parser->dict_add_str(dict, "type", &m->type);
	if (m->protocol)
		parser->dict_add_string(dict, "protocol", m->protocol->name);
	if (rtp_pt)
		parser->dict_add_str_dup(dict, "codec", &rtp_pt->encoding_with_params);

	streams = parser->dict_add_list(dict, "streams");

	flags = parser->dict_add_list(dict, "flags");

	BF_M("initialized", INITIALIZED);
	BF_M("asymmetric", ASYMMETRIC);
	BF_M("send", SEND);
	BF_M("recv", RECV);
	BF_M("rtcp-mux", RTCP_MUX);
	BF_M("DTLS-SRTP", DTLS);
	BF_M("DTLS role active", SETUP_ACTIVE);
	BF_M("DTLS role passive", SETUP_PASSIVE);
	BF_M("SDES", SDES);
	BF_M("passthrough", PASSTHRU);
	BF_M("ICE", ICE);
	BF_M("trickle ICE", TRICKLE_ICE);
	BF_M("ICE controlling", ICE_CONTROLLING);
	BF_M("ICE-lite peer", ICE_LITE_PEER);
	BF_M("ICE-lite self", ICE_LITE_SELF);
	BF_M("unidirectional", UNIDIRECTIONAL);
	BF_M("loop check", LOOP_CHECK);
	BF_M("generator/sink", GENERATOR);
	BF_M("ptime-override", PTIME_OVERRIDE);
	BF_M("RTCP feedback", RTCP_FB);
	BF_M("RTCP generator", RTCP_GEN);
	BF_M("echo", ECHO);
	BF_M("blackhole", BLACKHOLE);
	BF_M("SDES reordered", REORDER_FORCED);
	BF_M("audio player", AUDIO_PLAYER);
	BF_M("legacy OSRTP", LEGACY_OSRTP);
	BF_M("reverse legacy OSRTP", LEGACY_OSRTP_REV);
	BF_M("transcoding", TRANSCODING);
	BF_M("block egress", BLOCK_EGRESS);

	ng_stats_ssrc(parser, ssrc, parser->dict_add_list(dict, "ingress SSRCs"), &m->ssrc_hash_in);
	ng_stats_ssrc(parser, NULL, parser->dict_add_list(dict,  "egress SSRCs"), &m->ssrc_hash_out);

stats:
	for (auto_iter(l, m->streams.head); l; l = l->next) {
		ps = l->data;
		ng_stats_stream(ctx, streams, ps, totals);
	}
}

static void ng_stats_monologue(ng_command_ctx_t *ctx, parser_arg dict, const struct call_monologue *ml,
		struct call_stats *totals, parser_arg ssrc)
{
	parser_arg sub, medias = {0};
	struct call_media *m;
	g_auto(GQueue) mls_subscriptions = G_QUEUE_INIT; /* to avoid duplications */
	g_auto(GQueue) mls_subscribers = G_QUEUE_INIT; /* to avoid duplications */

	if (!ml)
		return;

	if (!ctx)
		goto stats;

	const ng_parser_t *parser = ctx->parser_ctx.parser;

	if (ml->tag.len)
		sub = parser->dict_add_dict(dict, ml->tag.s);
	else {
		char buf[32];
		snprintf(buf, sizeof(buf), "<untagged %u>", ml->unique_id);
		sub = parser->dict_add_dict_dup(dict, buf);
	}

	parser->dict_add_str(sub, "tag", &ml->tag);
	if (ml->viabranch.s)
		parser->dict_add_str(sub, "via-branch", &ml->viabranch);
	if (ml->tag_aliases.length) {
		parser_arg aliases = parser->dict_add_list(sub, "tag-aliases");
		for (auto_iter(alias, ml->tag_aliases.head); alias; alias = alias->next)
			parser->list_add_str_dup(aliases, alias->data);
	}
	if (ml->label.s)
		parser->dict_add_str(sub, "label", &ml->label);
	parser->dict_add_int(sub, "created", ml->created_us / 1000000L);
	if (ml->metadata.s)
		parser->dict_add_str(sub, "metadata", &ml->metadata);

	parser_arg b_subscriptions = parser->dict_add_list(sub, "subscriptions");
	parser_arg b_subscribers = parser->dict_add_list(sub, "subscribers");
	for (int i = 0; i < ml->medias->len; i++)
	{
		struct call_media * media = ml->medias->pdata[i];
		if (!media)
			continue;

		IQUEUE_FOREACH(&media->media_subscriptions, ms) {
			if (!g_queue_find(&mls_subscriptions, ms->monologue)) {
				parser_arg sub1 = parser->list_add_dict(b_subscriptions);
				parser->dict_add_str(sub1, "tag", &ms->monologue->tag);
				parser->dict_add_string(sub1, "type", ms->attrs.offer_answer ? "offer/answer" : "pub/sub");
				g_queue_push_tail(&mls_subscriptions, ms->monologue);
			}
		}
		IQUEUE_FOREACH(&media->media_subscribers, ms) {
			if (!g_queue_find(&mls_subscribers, ms->monologue)) {
				parser_arg sub1 = parser->list_add_dict(b_subscribers);
				parser->dict_add_str(sub1, "tag", &ms->monologue->tag);
				parser->dict_add_string(sub1, "type", ms->attrs.offer_answer ? "offer/answer" : "pub/sub");
				g_queue_push_tail(&mls_subscribers, ms->monologue);
			}
		}
	}

	medias = parser->dict_add_list(sub, "medias");

	parser_arg list = parser->dict_add_list(sub, "VSC");
	for (unsigned int i = 0; i < ml->num_dtmf_triggers; i++) {
		const struct dtmf_trigger_state *state = &ml->dtmf_trigger_state[i];
		if (state->trigger.len == 0)
			continue;
		parser_arg vsc = parser->list_add_dict(list);
		const char *type = dtmf_trigger_types[state->type];
		if (type)
			parser->dict_add_string(vsc, "type", type);
		parser->dict_add_str(vsc, "trigger", &state->trigger);
		parser->dict_add_int(vsc, "active", !state->inactive);
	}

	if (ml->call->recording) {
		parser_arg rec = parser->dict_add_dict(sub, "recording");
		parser->dict_add_int(rec, "excluded", !!ML_ISSET(ml, NO_RECORDING));
		parser->dict_add_int(rec, "forwarding", !!ML_ISSET(ml, REC_FORWARDING));
	}

stats:
	for (unsigned int i = 0; i < ml->medias->len; i++) {
		m = ml->medias->pdata[i];
		if (!m)
			continue;
		ng_stats_media(ctx, medias, m, totals, ssrc);
	}
}

static void ng_stats_ssrc_mos_entry_common(const ng_parser_t *parser, parser_arg subent,
		struct ssrc_stats_block *sb,
		unsigned int div)
{
	parser->dict_add_int(subent, "MOS", sb->mos / div);
	parser->dict_add_int(subent, "round-trip time", sb->rtt / div);
	parser->dict_add_int(subent, "round-trip time leg", sb->rtt_leg / div);
	parser->dict_add_int(subent, "jitter", sb->jitter / div);
	parser->dict_add_int(subent, "packet loss", sb->packetloss / div);
}
static void ng_stats_ssrc_mos_entry(const ng_parser_t *parser, parser_arg subent,
		struct ssrc_stats_block *sb)
{
	ng_stats_ssrc_mos_entry_common(parser, subent, sb, 1);
	parser->dict_add_int(subent, "reported at", sb->reported / 1000000L);
}
static void ng_stats_ssrc_mos_entry_dict(const ng_parser_t *parser, parser_arg ent, const char *label,
		struct ssrc_stats_block *sb)
{
	parser_arg subent = parser->dict_add_dict(ent, label);
	ng_stats_ssrc_mos_entry(parser, subent, sb);
}
static void ng_stats_ssrc_mos_entry_dict_avg(const ng_parser_t *parser, parser_arg ent, const char *label,
		struct ssrc_stats_block *sb,
		unsigned int div)
{
	parser_arg subent = parser->dict_add_dict(ent, label);
	ng_stats_ssrc_mos_entry_common(parser, subent, sb, div);
	parser->dict_add_int(subent, "samples", div);
}

static void ng_stats_ssrc_1(const ng_parser_t *parser, parser_arg ent, struct ssrc_entry_call *se) {
	parser->dict_add_int(ent, "bytes", atomic64_get_na(&se->stats->bytes));
	parser->dict_add_int(ent, "packets", atomic64_get_na(&se->stats->packets));
	parser->dict_add_int(ent, "last RTP timestamp", atomic_get_na(&se->stats->timestamp));
	parser->dict_add_int(ent, "last RTP seq", atomic_get_na(&se->stats->ext_seq));

	if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
		return;

	parser->dict_add_int(ent, "cumulative loss", se->packets_lost);

	int mos_samples = se->stats_blocks.length - se->no_mos_count;
	if (mos_samples < 1) mos_samples = 1;
	ng_stats_ssrc_mos_entry_dict_avg(parser, ent, "average MOS", &se->average_mos, mos_samples);
	ng_stats_ssrc_mos_entry_dict(parser, ent, "lowest MOS", se->lowest_mos);
	ng_stats_ssrc_mos_entry_dict(parser, ent, "highest MOS", se->highest_mos);

	parser_arg progdict = parser->dict_add_dict(ent, "MOS progression");
	// aim for about 10 entries to the list
	GList *listent = se->stats_blocks.head;
	struct ssrc_stats_block *sb = listent->data;
	int64_t interval
		= ((struct ssrc_stats_block *) se->stats_blocks.tail->data)->reported
		- sb->reported;
	interval /= 10;
	parser->dict_add_int(progdict, "interval", interval / 1000000L);
	int64_t next_step = sb->reported;
	parser_arg entlist = parser->dict_add_list(progdict, "entries");

	for (; listent; listent = listent->next) {
		sb = listent->data;
		if (sb->reported < next_step)
			continue;
		next_step += interval;
		parser_arg cent = parser->list_add_dict(entlist);
		ng_stats_ssrc_mos_entry(parser, cent, sb);
	}
}

static void ng_stats_ssrc(const ng_parser_t *parser, parser_arg dict, parser_arg list,
		const struct ssrc_hash *ht)
{
	for (GList *l = ht->nq.head; l; l = l->next) {
		struct ssrc_entry_call *se = l->data;
		char tmp[12];
		snprintf(tmp, sizeof(tmp), "%" PRIu32, se->h.ssrc);

		parser_arg ent = parser->list_add_dict(list);

		parser->dict_add_int(ent, "SSRC", se->h.ssrc);

		ng_stats_ssrc_1(parser, ent, se);

		if (dict.gen && !parser->dict_contains(dict, tmp)) {
			ent = parser->dict_add_dict_dup(dict, tmp);
			ng_stats_ssrc_1(parser, ent, se);
		}
	}
}

/* call must be locked */
void ng_call_stats(ng_command_ctx_t *ctx, call_t *call, const str *fromtag, const str *totag,
		struct call_stats *totals)
{
	parser_arg tags = {0}, dict;
	const str *match_tag;
	struct call_monologue *ml;
	struct call_stats t_b;
	parser_arg ssrc = {0};
	const ng_parser_t *parser = NULL;

	if (!totals)
		totals = &t_b;
	ZERO(*totals);

	if (!ctx)
		goto stats;

	call_ngb_hold_ref(call, ctx->ngbuf);

	parser = ctx->parser_ctx.parser;

	parser->dict_add_int(ctx->resp, "created", call->created / 1000000L);
	parser->dict_add_int(ctx->resp, "created_us", call->created % 1000000L);
	parser->dict_add_int(ctx->resp, "created_ts", call->created);
	parser->dict_add_int(ctx->resp, "last signal", call->last_signal_us / 1000000L);
	parser->dict_add_int(ctx->resp, "last redis update", atomic64_get_na(&call->last_redis_update_us) / 1000000L);
	if (call->metadata.s)
		parser->dict_add_str(ctx->resp, "metadata", &call->metadata);

	ssrc = parser->dict_add_dict(ctx->resp, "SSRC");
	tags = parser->dict_add_dict(ctx->resp, "tags");

stats:
	match_tag = (totag && totag->s && totag->len) ? totag : fromtag;

	if (!match_tag || !match_tag->len) {
		for (__auto_type l = call->monologues.head; l; l = l->next) {
			ml = l->data;
			ng_stats_monologue(ctx, tags, ml, totals, ssrc);
		}
	}
	else {
		ml = call_get_monologue(call, match_tag);
		if (ml) {
			ng_stats_monologue(ctx, tags, ml, totals, ssrc);
			g_auto(GQueue) mls = G_QUEUE_INIT; /* to avoid duplications */
			for (int i = 0; i < ml->medias->len; i++)
			{
				struct call_media * media = ml->medias->pdata[i];
				if (!media)
					continue;

				IQUEUE_FOREACH(&media->media_subscriptions, ms) {
					if (!g_queue_find(&mls, ms->monologue)) {
						ng_stats_monologue(ctx, tags, ms->monologue, totals, ssrc);
						g_queue_push_tail(&mls, ms->monologue);
					}
				}
			}
		}
	}

	if (!ctx)
		return;

	dict = parser->dict_add_dict(ctx->resp, "totals");
	ng_stats(ctx, dict, "RTP", &totals->totals[0], NULL);
	ng_stats(ctx, dict, "RTCP", &totals->totals[1], NULL);

	if (call->recording) {
		parser_arg rec = parser->dict_add_dict(ctx->resp, "recording");
		parser->dict_add_int(rec, "call recording", !!CALL_ISSET(call, RECORDING_ON));
		parser->dict_add_int(rec, "forwarding", !!CALL_ISSET(call, REC_FORWARDING));
	}
}

static void ng_list_calls(ng_command_ctx_t *ctx, parser_arg output, long long int limit) {
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	rwlock_lock_r(&rtpe_callhash_lock);

	__auto_type iter = t_hash_table_iter(rtpe_callhash);
	str *key;
	while (limit-- && t_hash_table_iter_next (&iter, &key, NULL)) {
		parser->list_add_str_dup(output, key);
	}

	rwlock_unlock_r(&rtpe_callhash_lock);
}



const char *call_query_ng(ng_command_ctx_t *ctx) {
	str callid, fromtag, totag;
	call_t *call;
	parser_arg input = ctx->req;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	if (!parser->dict_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get(&callid);
	if (!call)
		return "Unknown call-id";
	parser->dict_get_str(input, "from-tag", &fromtag);
	parser->dict_get_str(input, "to-tag", &totag);

	ng_call_stats(ctx, call, &fromtag, &totag, NULL);
	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}


const char *call_list_ng(ng_command_ctx_t *ctx) {
	parser_arg calls;
	long long int limit;
	parser_arg input = ctx->req;
	parser_arg output = ctx->resp;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	limit = parser->dict_get_int_str(input, "limit", 32);

	if (limit < 0) {
		return "invalid limit, must be >= 0";
	}
	calls = parser->dict_add_list(output, "calls");

	ng_list_calls(ctx, calls, limit);

	return NULL;
}


static const char *call_recording_common_ng(ng_command_ctx_t *ctx,
		void (*fn)(ng_command_ctx_t *, call_t *call))
{
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;
	parser_arg input = ctx->req;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	call_ng_process_flags(&flags, ctx);

	if (!parser->dict_get_str(input, "call-id", &flags.call_id))
		return "No call-id in message";
	call = call_get(&flags.call_id);
	if (!call)
		return "Unknown call-id";

	struct call_monologue *ml = NULL;

	if (parser->dict_get_str(input, "from-tag", &flags.from_tag)) {
		if (flags.from_tag.s) {
			ml = call_get_monologue(call, &flags.from_tag);
			if (!ml)
				ilog(LOG_WARN, "Given from-tag " STR_FORMAT_M " not found",
						STR_FMT_M(&flags.from_tag));
		}
	}

	if (ml)
		update_metadata_monologue(ml, &flags);
	else
		update_metadata_call(call, &flags);

	fn(ctx, call);

	call_unlock_release_update(&call);

	return NULL;
}


static void start_recording_fn(ng_command_ctx_t *ctx, call_t *call) {
	recording_start(call);
}
const char *call_start_recording_ng(ng_command_ctx_t *ctx) {
	return call_recording_common_ng(ctx, start_recording_fn);
}


static void pause_recording_fn(ng_command_ctx_t *ctx, call_t *call) {
	recording_pause(call);
}
const char *call_pause_recording_ng(ng_command_ctx_t *ctx) {
	return call_recording_common_ng(ctx, pause_recording_fn);
}


static void stop_recording_iter(str *key, unsigned int idx, helper_arg arg) {
	if (str_cmp(key, "pause") == 0)
		*arg.call_fn = recording_pause;
	else if (str_cmp(key, "discard-recording") == 0)
		*arg.call_fn = recording_discard;
}
static void stop_recording_fn(ng_command_ctx_t *ctx, call_t *call) {
	// support alternative usage for "pause" call: either `pause=yes` ...
	parser_arg input = ctx->req;
	const ng_parser_t *parser = ctx->parser_ctx.parser;
	str pause;
	if (parser->dict_get_str(input, "pause", &pause)) {
		if (!str_cmp(&pause, "yes") || !str_cmp(&pause, "on") || !str_cmp(&pause, "true")) {
			pause_recording_fn(ctx, call);
			return;
		}
	}
	// ... or `flags=[pause]`
	parser_arg item = parser->dict_get_expect(input, "flags", BENCODE_LIST);
	void (*fn)(call_t *) = recording_stop;
	if (item.gen)
		parser->list_iter(parser, item, stop_recording_iter, NULL, &fn);

	fn(call);
}
const char *call_stop_recording_ng(ng_command_ctx_t *ctx) {
	return call_recording_common_ng(ctx, stop_recording_fn);
}


static const char *media_match(call_t *call, struct call_monologue **monologue,
		sdp_ng_flags *flags)
{
	if (flags->label.s) {
		*monologue = t_hash_table_lookup(call->labels, &flags->label);
		if (!*monologue)
			return "No monologue matching the given label";
	}
	else if (flags->address.s) {
		sockaddr_t addr;
		if (!sockaddr_parse_any_str(&addr, &flags->address))
			return "Failed to parse network address";
		// walk our structures to find a matching stream
		for (__auto_type l = call->monologues.head; l; l = l->next) {
			*monologue = l->data;
			for (unsigned int k = 0; k < (*monologue)->medias->len; k++) {
				struct call_media *media = (*monologue)->medias->pdata[k];
				if (!media)
					continue;
				if (!media->streams.head)
					continue;
				struct packet_stream *ps = media->streams.head->data;
				if (!sockaddr_eq(&addr, &ps->advertised_endpoint.address))
					continue;
				ilog(LOG_DEBUG, "Matched address %s%s%s to tag '" STR_FORMAT_M "'",
						FMT_M(sockaddr_print_buf(&addr)), STR_FMT_M(&(*monologue)->tag));
				goto found;
			}
		}
		return "Failed to match address to any tag";
found:
		;
	}
	/* ignore from-tag, if directional is not set */
	else if (flags->from_tag.s &&
			(!IS_OP_DIRECTIONAL(flags->opmode) ||
			(IS_OP_DIRECTIONAL(flags->opmode) && flags->directional))) {
		*monologue = call_get_monologue(call, &flags->from_tag);
		if (!*monologue)
			return "From-tag given, but no such tag exists";
	}
	if (*monologue)
		__monologue_unconfirm(*monologue, "media blocking signalling event");
	return NULL;
}

static const char *media_block_match(call_t **call, struct call_monologue **monologue,
		sdp_ng_flags *flags, ng_command_ctx_t *ctx)
{
	*call = NULL;
	*monologue = NULL;

	call_ng_process_flags(flags, ctx);

	if (!flags->call_id.s)
		return "No call-id in message";
	*call = call_get(&flags->call_id);
	if (!*call)
		return "Unknown call-ID";

	// directional?
	if (flags->all == ALL_ALL) // explicitly non-directional, so skip the rest
		return NULL;

	const char *err = media_match(*call, monologue, flags);
	if (err)
		return err;

	// for generic ops, handle set-label here if given
	if (IS_OP_OTHER(flags->opmode) && flags->set_label.len && *monologue) {
		(*monologue)->label = call_str_cpy(&flags->set_label);
		t_hash_table_replace((*call)->labels, &(*monologue)->label, *monologue);
	}

	return NULL;
}

static const char *medias_match(call_t **call, medias_q *medias,
		sdp_ng_flags *flags, ng_command_ctx_t *ctx)
{
	call_ng_process_flags(flags, ctx);

	if (!flags->call_id.s)
		return "No call-id in message";
	*call = call_get(&flags->call_id);
	if (!*call)
		return "Unknown call-ID";

	if (flags->all == ALL_ALL) {
		for (__auto_type l = (*call)->medias.head; l; l = l->next) {
			struct call_media *media = l->data;
			if (!media || (media->monologue->tagtype != FROM_TAG &&
				media->monologue->tagtype != TO_TAG))
			{

				continue;
			}
			t_queue_push_tail(medias, media);
		}
		return NULL;
	}

	/* is a single ml given? */
	struct call_monologue *ml = NULL;
	const char *err = media_match(*call, &ml, flags);
	if (err)
		return err;
	if (ml) {
		for (int i = 0; i < ml->medias->len; i++)
		{
			struct call_media *media = ml->medias->pdata[i];
			if (!media)
				continue;
			t_queue_push_tail(medias, media);
		}
		return NULL;
	}

	/* handle from-tag list */
	for (__auto_type l = flags->from_tags.head; l; l = l->next) {
		str *s = l->data;
		struct call_monologue *mlf = call_get_monologue(*call, s);
		if (!mlf) {
			ilog(LOG_WARN, "Given from-tag " STR_FORMAT_M " not found", STR_FMT_M(s));
		} else {
			for (int i = 0; i < mlf->medias->len; i++)
			{
				struct call_media *media = mlf->medias->pdata[i];
				if (!media)
					continue;
				t_queue_push_tail(medias, media);
			}
		}
	}

	if (!medias->length)
		return "No medias found (no monologues matched)";

	return NULL;
}

// XXX these are all identical - unify and use a flags int and/or callback
const char *call_start_forwarding_ng(ng_command_ctx_t *ctx) {
	g_autoptr(call_t) call = NULL;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	g_auto(sdp_ng_flags) flags;

	errstr = media_block_match(&call, &monologue, &flags, ctx);
	if (errstr)
		return errstr;

	if (monologue) {
		ilog(LOG_INFO, "Start forwarding for single party (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		ML_SET(monologue, REC_FORWARDING);
	}
	else {
		ilog(LOG_INFO, "Start forwarding (entire call)");
		CALL_SET(call, REC_FORWARDING);
	}

	if (monologue)
		update_metadata_monologue(monologue, &flags);
	else
		update_metadata_call(call, &flags);

	recording_start_daemon(call);

	call_unlock_release_update(&call);
	return NULL;
}

const char *call_stop_forwarding_ng(ng_command_ctx_t *ctx) {
	g_autoptr(call_t) call = NULL;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	g_auto(sdp_ng_flags) flags;

	errstr = media_block_match(&call, &monologue, &flags, ctx);
	if (errstr)
		return errstr;

	if (monologue) {
		ilog(LOG_INFO, "Stop forwarding for single party (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		ML_CLEAR(monologue, REC_FORWARDING);
	}
	else {
		ilog(LOG_INFO, "Stop forwarding (entire call)");
		CALL_CLEAR(call, REC_FORWARDING);
		if (flags.all == ALL_ALL) {
			for (__auto_type l = call->monologues.head; l; l = l->next) {
				monologue = l->data;
				ML_CLEAR(monologue, REC_FORWARDING);
			}
		}
	}

	if (monologue)
		update_metadata_monologue(monologue, &flags);
	else
		update_metadata_call(call, &flags);

	recording_stop_daemon(call);

	call_unlock_release_update(&call);

	return NULL;
}

static void call_monologue_set_block_mode(struct call_monologue *ml, sdp_ng_flags *flags) {
	if (flags->delay_buffer >= 0) {
		for (unsigned int i = 0; i < ml->medias->len; i++) {
			struct call_media *media = ml->medias->pdata[i];
			if (!media)
				continue;
			media->buffer_delay = flags->delay_buffer;
		}
	}
	bf_set_clear(&ml->ml_flags, ML_FLAG_DETECT_DTMF, flags->detect_dtmf);

	if (flags->volume >= 0 && flags->volume <= 63)
		ml->tone_vol = flags->volume;
	else if (flags->volume < 0 && flags->volume >= -63)
		ml->tone_vol = -1 * flags->volume;

	if (flags->frequencies && flags->frequencies->len > 0) {
		if (ml->tone_freqs)
			g_array_free(ml->tone_freqs, true);
		ml->tone_freqs = flags->frequencies;
		flags->frequencies = NULL;
	}

	if (flags->block_dtmf_mode == BLOCK_DTMF_ZERO)
		ml->dtmf_digit = '0';
	else {
		char digit = dtmf_code_to_char(flags->digit);
		if (digit)
			ml->dtmf_digit = digit;
		else if (dtmf_code_from_char(flags->digit) != -1)
			ml->dtmf_digit = flags->digit;
	}

	dtmf_trigger_set(ml, DTMF_TRIGGER_BLOCK, &flags->trigger, false);
	dtmf_trigger_set(ml, DTMF_TRIGGER_UNBLOCK, &flags->trigger_end, false);
	ml->block_dtmf_trigger = flags->block_dtmf_mode_trigger;
	ml->dtmf_trigger_digits = flags->trigger_end_digits;
	ml->block_dtmf_trigger_end_ms = flags->trigger_end_ms;
	ml->dtmf_delay = flags->dtmf_delay;

	codec_update_all_handlers(ml);
}
static void call_set_dtmf_block(call_t *call, struct call_monologue *monologue, sdp_ng_flags *flags) {
	enum block_dtmf_mode mode = BLOCK_DTMF_DROP;
	// special case default: if there's a trigger, default block mode is none
	if (flags->block_dtmf_mode_trigger || flags->trigger.len)
		mode = BLOCK_DTMF_OFF;
	if (flags->block_dtmf_mode)
		mode = flags->block_dtmf_mode;

	if (monologue) {
		ilog(LOG_INFO, "Blocking directional DTMF (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->block_dtmf = mode;
	}
	else {
		ilog(LOG_INFO, "Blocking DTMF (entire call)");
		call->block_dtmf = mode;
	}

	if (is_dtmf_replace_mode(mode) || flags->delay_buffer >= 0 || flags->trigger.len) {
		if (monologue)
			call_monologue_set_block_mode(monologue, flags);
		else {
			for (__auto_type l = call->monologues.head; l; l = l->next) {
				struct call_monologue *ml = l->data;
				call_monologue_set_block_mode(ml, flags);
			}
		}
	}

}
const char *call_block_dtmf_ng(ng_command_ctx_t *ctx) {
	g_autoptr(call_t) call = NULL;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	g_auto(sdp_ng_flags) flags;

	errstr = media_block_match(&call, &monologue, &flags, ctx);
	if (errstr)
		return errstr;

	call_set_dtmf_block(call, monologue, &flags);

	return NULL;
}

const char *call_unblock_dtmf_ng(ng_command_ctx_t *ctx) {
	g_autoptr(call_t) call = NULL;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	g_auto(sdp_ng_flags) flags;

	errstr = media_block_match(&call, &monologue, &flags, ctx);
	if (errstr)
		return errstr;

	if (monologue) {
		ilog(LOG_INFO, "Unblocking directional DTMF (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		enum block_dtmf_mode prev_mode = monologue->block_dtmf;
		monologue->block_dtmf = BLOCK_DTMF_OFF;
		if (is_dtmf_replace_mode(prev_mode) || flags.delay_buffer >= 0) {
			if (flags.delay_buffer >= 0) {
				for (unsigned int i = 0; i < monologue->medias->len; i++) {
					struct call_media *media = monologue->medias->pdata[i];
					if (!media)
						continue;
					media->buffer_delay = flags.delay_buffer;
				}
			}
			bf_set_clear(&monologue->ml_flags, ML_FLAG_DETECT_DTMF, flags.detect_dtmf);
			codec_update_all_handlers(monologue);
		}
	}
	else {
		ilog(LOG_INFO, "Unblocking DTMF (entire call)");
		enum block_dtmf_mode prev_mode = call->block_dtmf;
		call->block_dtmf = BLOCK_DTMF_OFF;
		if (flags.all == ALL_ALL || is_dtmf_replace_mode(prev_mode) || flags.delay_buffer >= 0) {
			for (__auto_type l = call->monologues.head; l; l = l->next) {
				monologue = l->data;
				enum block_dtmf_mode prev_ml_mode = BLOCK_DTMF_OFF;
				if (flags.all == ALL_ALL) {
					prev_ml_mode = monologue->block_dtmf;
					monologue->block_dtmf = BLOCK_DTMF_OFF;
				}
				if (flags.delay_buffer >= 0) {
					for (unsigned int i = 0; i < monologue->medias->len; i++) {
						struct call_media *media = monologue->medias->pdata[i];
						if (!media)
							continue;
						media->buffer_delay = flags.delay_buffer;
					}
				}
				bf_set_clear(&monologue->ml_flags, ML_FLAG_DETECT_DTMF, flags.detect_dtmf);
				if (is_dtmf_replace_mode(prev_ml_mode) || is_dtmf_replace_mode(prev_mode)
						|| flags.delay_buffer >= 0)
					codec_update_all_handlers(monologue);
			}
		}
	}

	return NULL;
}

static const char *call_block_silence_media(ng_command_ctx_t *ctx, bool on_off, const char *ucase_verb,
		const char *lcase_verb,
		unsigned int call_flag, unsigned int ml_flag, size_t attr_offset)
{
	g_autoptr(call_t) call = NULL;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	g_auto(sdp_ng_flags) flags;
	bool found_subscriptions = false;

	errstr = media_block_match(&call, &monologue, &flags, ctx);
	if (errstr)
		return errstr;

	/* from-monologue is given */
	if (monologue) {
		/* potential sinks (medias) towards from-monologue,
		 * not particularly subscribed */
		bool sinks = false;

		/* to-monologue is given */
		if (flags.to_tag.len || flags.to_label.len) {
			struct call_monologue *sink_ml = NULL;

			/* to-monologue is given, check using to-tag */
			if (flags.to_tag.len) {
				sink_ml = t_hash_table_lookup(call->tags, &flags.to_tag);
				if (!sink_ml) {
					ilog(LOG_WARN, "Media flow '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' doesn't "
							"exist for media %s (to-tag not found)",
							STR_FMT_M(&monologue->tag), STR_FMT_M(&flags.to_tag),
							lcase_verb);
					return "Media flow not found (to-tag not found)";
				}

			/* to-monologue is given, check using to-label */
			} else {
				sink_ml = t_hash_table_lookup(call->labels, &flags.to_label);
				if (!sink_ml) {
					ilog(LOG_WARN, "Media flow '" STR_FORMAT_M "' -> label '" STR_FORMAT "' doesn't "
							"exist for media %s (to-label not found)",
							STR_FMT_M(&monologue->tag), STR_FMT(&flags.to_label),
							lcase_verb);
					return "Media flow not found (to-label not found)";
				}
			}

			/* now check if any sink ml media is susbcribed to any of monologue medias */
			for (int i = 0; i < sink_ml->medias->len; i++)
			{
				struct call_media * sink_md = monologue->medias->pdata[i];
				if (!sink_md)
					continue;
				for (int j = 0; j < monologue->medias->len; j++)
				{
					struct call_media * ml_media = monologue->medias->pdata[j];
					if (!ml_media)
						continue;
					__auto_type ll = t_hash_table_lookup(ml_media->media_subscriptions_ht, sink_md);
					if (ll) {
						found_subscriptions = true;
						G_STRUCT_MEMBER(bool, &ll->attrs, attr_offset) = on_off;
						ilog(LOG_INFO, "%s directional media flow: "
								"monologue tag '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' / "
								"media index '%d' -> '%d'",
								ucase_verb,
								STR_FMT_M(&monologue->tag), STR_FMT_M(&ll->monologue->tag),
								ml_media->index, ll->media->index);
					}
				}
				sinks = true;
			}

		/* one of the "all" flags is given, to-subscriptions */
		} else if (flags.all == ALL_OFFER_ANSWER || flags.all == ALL_NON_OFFER_ANSWER
				|| flags.all == ALL_FLOWS)
		{
			for (int i = 0; i < monologue->medias->len; i++)
			{
				struct call_media * ml_media = monologue->medias->pdata[i];
				if (!ml_media)
					continue;

				IQUEUE_FOREACH(&ml_media->media_subscribers, ms) {
					struct call_media *sub_md = ms->media;

					if (!sub_md ||
						(flags.all == ALL_OFFER_ANSWER && !ms->attrs.offer_answer) ||
						(flags.all == ALL_NON_OFFER_ANSWER && ms->attrs.offer_answer))
					{
						continue;
					}
					ilog(LOG_INFO, "%s directional media flow: "
							"monologue tag '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' / "
							"media index '%d' -> '%d'",
							ucase_verb,
							STR_FMT_M(&monologue->tag), STR_FMT_M(&sub_md->monologue->tag),
							ml_media->index, sub_md->index);
					found_subscriptions = true;
					G_STRUCT_MEMBER(bool, &ms->attrs, attr_offset) = on_off;
					sinks = true;
				}
			}
			/* having an empty sinks list is an error, as "all" would be nothing */
			if (!sinks) {
				ilog(LOG_WARN, "No eligible media subscriptions found for '" STR_FORMAT_M "' "
						"for media %s",
						STR_FMT_M(&monologue->tag),
						lcase_verb);
				return "No eligible media subscriptions found";
			}
		}

		/* media sinks */
		if (sinks) {
			if (!found_subscriptions) {
					/* no one of sink medias is subscribed to monologue medias */
					ilog(LOG_WARN, "Media flow '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' doesn't "
							"exist for media %s (to-tag not subscribed)",
							STR_FMT_M(&monologue->tag),
							STR_FMT_M(&flags.to_tag),
							lcase_verb);
					return "Media flow not found (to-tag not subscribed)";

			}
			update_init_monologue_subscribers(monologue, OP_BLOCK_SILENCE_MEDIA);

		} else {
			/* it seems no to-monologue is given and no "all" flag is given as well.
			 * In this case the from-monologue itself is flagged,
			 * and not any of the media flows (subscription objects) */
			ilog(LOG_INFO, "%s directional media (tag '" STR_FORMAT_M "')",
					ucase_verb,
					STR_FMT_M(&monologue->tag));
			bf_set_clear(&monologue->ml_flags, ml_flag, on_off);
		}
		__monologue_unconfirm(monologue, "media silencing signalling event");

	} else {
		bf_set_clear(&call->call_flags, call_flag, on_off);
		if (!on_off) {
			ilog(LOG_INFO, "%s media (entire call and participants)", ucase_verb);
			if (flags.all == ALL_ALL) {
				for (__auto_type l = call->monologues.head; l; l = l->next) {
					monologue = l->data;
					bf_set_clear(&monologue->ml_flags, ml_flag, on_off);
				}
			}
		} else {
			ilog(LOG_INFO, "%s media (entire call)", ucase_verb);
		}
		__call_unkernelize(call, "media silencing signalling event");
	}

	return NULL;
}

#define CALL_BLOCK_SILENCE_MEDIA(ctx, on_off, ucase_verb, lcase_verb, member_name, flag) \
	call_block_silence_media(ctx, on_off, ucase_verb, lcase_verb, \
			CALL_FLAG_ ## flag, \
			ML_FLAG_ ## flag, \
			G_STRUCT_OFFSET(struct sink_attrs, member_name))

const char *call_block_media_ng(ng_command_ctx_t *ctx) {
	return CALL_BLOCK_SILENCE_MEDIA(ctx, true, "Blocking", "blocking", block_media, BLOCK_MEDIA);
}
const char *call_unblock_media_ng(ng_command_ctx_t *ctx) {
	return CALL_BLOCK_SILENCE_MEDIA(ctx, false, "Unblocking", "unblocking", block_media, BLOCK_MEDIA);
}
const char *call_silence_media_ng(ng_command_ctx_t *ctx) {
	return CALL_BLOCK_SILENCE_MEDIA(ctx, true, "Silencing", "silencing", silence_media, SILENCE_MEDIA);
}
const char *call_unsilence_media_ng(ng_command_ctx_t *ctx) {
	return CALL_BLOCK_SILENCE_MEDIA(ctx, false, "Unsilencing", "unsilencing", silence_media, SILENCE_MEDIA);
}


#ifdef WITH_TRANSCODING
static const char *play_media_select_party(call_t **call, monologues_q *monologues,
		ng_command_ctx_t *ctx, sdp_ng_flags *flags)
{
	struct call_monologue *monologue;

	t_queue_init(monologues);

	const char *err = media_block_match(call, &monologue, flags, ctx);
	if (err)
		return err;
	if (flags->all == ALL_ALL)
		t_queue_append(monologues, &(*call)->monologues);
	else if (!monologue)
		return "No participant party specified";
	else
		t_queue_push_tail(monologues, monologue);
	return NULL;
}
#endif


const char *call_play_media_ng(ng_command_ctx_t *ctx) {
#ifdef WITH_TRANSCODING
	g_autoptr(call_t) call = NULL;
	g_auto(monologues_q) monologues;
	const char *err = NULL;
	g_auto(sdp_ng_flags) flags;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	err = play_media_select_party(&call, &monologues, ctx, &flags);
	if (err)
		return err;

	for (__auto_type l = monologues.head; l; l = l->next) {
		struct call_monologue *monologue = l->data;

		media_player_opts_t opts = MPO(
				.repeat = flags.repeat_times,
				.duration_spent = flags.repeat_duration,
				.start_pos = flags.start_pos,
				.block_egress = !!flags.block_egress,
				.codec_set = flags.codec_set,
				.file = flags.file,
				.blob = flags.blob,
				.db_id = flags.db_id,
			);

		err = call_play_media_for_ml(monologue, opts, &flags);
		if (err)
			return err;

		if (l == monologues.head && monologue->player->coder.duration)
			parser->dict_add_int(ctx->resp, "duration", monologue->player->coder.duration);

	}

	return NULL;
#else
	return "unsupported";
#endif
}


const char *call_stop_media_ng(ng_command_ctx_t *ctx) {
#ifdef WITH_TRANSCODING
	g_autoptr(call_t) call = NULL;
	g_auto(monologues_q) monologues;
	const char *err = NULL;
	long long last_frame_pos = 0;
	g_auto(sdp_ng_flags) flags;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	err = play_media_select_party(&call, &monologues, ctx, &flags);
	if (err)
		return err;

	for (__auto_type l = monologues.head; l; l = l->next) {
		struct call_monologue *monologue = l->data;

		if (!monologue->player)
			return "Not currently playing media";

		last_frame_pos = call_stop_media_for_ml(monologue);
	}
	parser->dict_add_int(ctx->resp, "last-frame-pos", last_frame_pos);

	return NULL;
#else
	return "unsupported";
#endif
}


const char *call_play_dtmf_ng(ng_command_ctx_t *ctx) {
#ifdef WITH_TRANSCODING
	g_autoptr(call_t) call = NULL;
	g_auto(monologues_q) monologues;
	const char *err = NULL;
	g_auto(sdp_ng_flags) flags;

	err = play_media_select_party(&call, &monologues, ctx, &flags);
	if (err)
		return err;

	// validate input parameters

	if (!flags.duration)
		flags.duration = 250;
	if (flags.duration < 100) {
		flags.duration = 100;
		ilog(LOG_WARN, "Invalid duration (%lli ms) specified, using 100 ms instead", flags.duration);
	}
	else if (flags.duration > 5000) {
		flags.duration = 5000;
		ilog(LOG_WARN, "Invalid duration (%lli ms) specified, using 5000 ms instead", flags.duration);
	}

	if (!flags.pause)
		flags.pause = 100;
	if (flags.pause < 100) {
		flags.pause = 100;
		ilog(LOG_WARN, "Invalid pause (%lli ms) specified, using 100 ms instead", flags.pause);
	}
	else if (flags.pause > 5000) {
		flags.pause = 5000;
		ilog(LOG_WARN, "Invalid pause (%lli ms) specified, using 5000 ms instead", flags.pause);
	}

	int code;
	if (dtmf_code_to_char(flags.digit))
		code = flags.digit; // already a code
	else
		code = dtmf_code_from_char(flags.digit); // convert digit to code

	if (code < 0)
		return "Out of range 'code' specified";
	else if (code > 15)
		return "Out of range 'code' specified";

	if (flags.volume > 0)
		flags.volume *= -1;

	for (__auto_type l = monologues.head; l; l = l->next) {
		struct call_monologue *monologue = l->data;

		// find a usable output media
		struct call_media *media;
		for (unsigned int i = 0; i < monologue->medias->len; i++) {
			media = monologue->medias->pdata[i];
			if (!media)
				continue;
			if (media->type_id != MT_AUDIO)
				continue;
			goto found;
		}

		return "Monologue has no media capable of DTMF injection";
		// XXX fall back to generating a secondary stream

found:
		ML_SET(monologue, DTMF_INJECTION_ACTIVE);
		dialogue_unconfirm(monologue, "DTMF playback");

		for (unsigned int i = 0; i < monologue->medias->len; i++)
		{
			struct call_media *ml_media = monologue->medias->pdata[i];
			if (!ml_media)
				continue;

			struct call_media * ms_media_sink = NULL;

			IQUEUE_FOREACH(&ml_media->media_subscribers, ms) {
				ms_media_sink = ms->media;
				if (!ms_media_sink || ms_media_sink->type_id != MT_AUDIO)
					continue;
				goto found_sink;
			}

			return "There is no sink media capable of DTMF playback";
found_sink:
			err = dtmf_inject(media, code, flags.volume, flags.duration, flags.pause, ms_media_sink);
			if (err)
				return err;
		}
	}

	return NULL;
#else
	return "unsupported";
#endif
}


const char *call_publish_ng(ng_command_ctx_t *ctx, const char *addr) {
	g_auto(sdp_ng_flags) flags;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	str sdp_in = STR_NULL;
	g_auto(str) sdp_out = STR_NULL;
	g_autoptr(call_t) call = NULL;
	int ret;
	const ng_parser_t *parser = ctx->parser_ctx.parser;
	struct recording *recording = NULL;
	char rand_call_id[65];
	char rand_from_tag[65];

	call_ng_process_flags(&flags, ctx);

	if (!flags.sdp.len)
		return "No SDP body in message";
	if (!flags.call_id.len)
		flags.call_id = STR_LEN(rand_hex_str(rand_call_id, 32), 64);
	if (!flags.from_tag.len)
		flags.from_tag = STR_LEN(rand_hex_str(rand_from_tag, 32), 64);

	call = call_get_or_create(&flags.call_id, false);

	sdp_in = call_str_cpy(&flags.sdp);

	if (!sdp_parse(&sdp_in, &parsed, &flags))
		return "Failed to parse SDP";

	if (!sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	if (trickle_ice_update(ctx->ngbuf, call, &flags, &streams))
		return NULL;

	updated_created_from(call, addr);
	struct call_monologue *ml = call_get_or_create_monologue(call, &flags.from_tag);

	ret = monologue_publish(ml, &streams, &flags);
	if (ret)
		ilog(LOG_ERR, "Publish error"); // XXX close call? handle errors?

	update_metadata_monologue(ml, &flags);
	detect_setup_recording(ml->call, &flags);

	recording = call->recording;

	meta_write_sdp_before(recording, &sdp_in, ml, flags.opmode);
	bool ok = sdp_create(&sdp_out, ml, &flags);
	if (!ok)
		return "Failed to create SDP";

	parser->dict_add_str_dup(ctx->resp, "call-id", &call->callid);
	parser->dict_add_str_dup(ctx->resp, "from-tag", &ml->tag);

	ctx->ngbuf->sdp_out = sdp_out.s;
	parser->dict_add_str(ctx->resp, "sdp", &sdp_out);

	meta_write_sdp_after(recording, &sdp_out, ml, flags.opmode);
	sdp_out = STR_NULL; // ownership passed to output

	recording_response(recording, parser, ctx->resp);

	dequeue_sdp_fragments(ml);

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_subscribe_request_ng(ng_command_ctx_t *ctx) {
	const char *err = NULL;
	g_auto(sdp_ng_flags) flags;
	char rand_buf[65];
	g_autoptr(call_t) call = NULL;
	g_auto(medias_q) mq = TYPED_GQUEUE_INIT;
	g_auto(str) sdp_out = STR_NULL;
	parser_arg output = ctx->resp;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	/* get source monologue */
	err = medias_match(&call, &mq, &flags, ctx);
	if (err)
		return err;

	if (flags.sdp.len)
		ilog(LOG_INFO, "Subscribe-request with SDP received - ignoring SDP");

	/* the `label=` option was possibly used above to select the from-tag --
	 * switch it out with `to-label=` or `set-label=` for monologue_subscribe_request
	 * below which sets the label based on `label` for a newly created monologue */
	flags.label = flags.to_label;
	if (flags.set_label.len) // set-label takes priority
		flags.label = flags.set_label;

	/* get destination monologue */
	// ignore the to-tag if rtpp_flags parsing is active and to-tag wasn't given explicitly
	if (!flags.to_tag.len || (flags.rtpp_flags && !flags.to_tag_flag)) {
		/* generate one */
		flags.to_tag = STR_CONST(rand_buf);
		rand_hex_str(flags.to_tag.s, flags.to_tag.len / 2);
	}

	struct call_monologue *dest_ml = call_get_or_create_monologue(call, &flags.to_tag);

	int ret = monologue_subscribe_request(&mq, dest_ml, &flags);
	if (ret)
		return "Failed to request subscription";

	/* create new SDP */
	bool ok = sdp_create(&sdp_out, dest_ml, &flags);
	if (!ok)
		return "Failed to create SDP";

	/* place return output SDP */
	ctx->ngbuf->sdp_out = sdp_out.s;
	parser->dict_add_str(output, "sdp", &sdp_out);
	sdp_out = STR_NULL; /* ownership passed to output */

	/* add single response ml tag if there's just one, but always add a list
	 * TODO: deprecate it, since initially added for monologue subscriptions.
	 */
	if (mq.length == 1) {
		struct call_media *media = mq.head->data;
		struct call_monologue *source_ml = media->monologue;
		parser->dict_add_str_dup(output, "from-tag", &source_ml->tag);
	}
	parser_arg tag_medias = {0}, media_labels = {0};
	if (flags.siprec) {
		tag_medias = parser->dict_add_list(output, "tag-medias");
		media_labels = parser->dict_add_dict(output, "media-labels");
	}
	parser_arg from_list = parser->dict_add_list(output, "from-tags");

	for (unsigned int i = 0; i < dest_ml->medias->len; i++) {
		struct call_media *dest_media = dest_ml->medias->pdata[i];
		if (!dest_media)
			continue;

		// each media should be subscribed to just one other media
		if (!dest_media->media_subscriptions.length)
			continue;

		struct call_media *source_media = dest_media->media_subscriptions.head->media;
		struct call_monologue *source_ml = source_media->monologue;

		parser->list_add_str_dup(from_list, &source_ml->tag);

		if (media_labels.gen && dest_media->label.len) {
			parser_arg label =
				parser->dict_add_dict(media_labels, dest_media->label.s);
			parser->dict_add_str(label, "tag", &source_ml->tag);
			parser->dict_add_int(label, "index", source_media->index);
			parser->dict_add_str(label, "type", &dest_media->type);
			if (source_ml->label.len)
				parser->dict_add_str(label, "label", &source_ml->label);
			parser->dict_add_string(label, "mode", sdp_get_sendrecv(source_media));
		}

		if (tag_medias.gen) {
			parser_arg tag_label = parser->list_add_dict(tag_medias);
			parser->dict_add_str(tag_label, "tag", &source_ml->tag);
			if (source_ml->label.len)
				parser->dict_add_str(tag_label, "label", &source_ml->label);

			parser_arg medias = parser->dict_add_list(tag_label, "medias");

			// this is a bit strange because in this mode, each list can only
			// ever get one entry...
			parser_arg med_ent = parser->list_add_dict(medias);
			parser->dict_add_int(med_ent, "index", source_media->index);
			parser->dict_add_str(med_ent, "type", &dest_media->type);
			parser->dict_add_str(med_ent, "label", &dest_media->label);
			parser->dict_add_string(med_ent, "mode", sdp_get_sendrecv(source_media));
		}
	}

	parser->dict_add_str_dup(output, "to-tag", &dest_ml->tag);

	dequeue_sdp_fragments(dest_ml);

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_subscribe_answer_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	g_autoptr(call_t) call = NULL;

	call_ng_process_flags(&flags, ctx);

	if (!flags.call_id.s)
		return "No call-id in message";
	call = call_get(&flags.call_id);
	if (!call)
		return "Unknown call-ID";

	if (!sdp_parse(&flags.sdp, &parsed, &flags))
		return "Failed to parse SDP";

	if (!sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	if (trickle_ice_update(ctx->ngbuf, call, &flags, &streams))
		return NULL;

	if (!flags.to_tag.s)
		return "No to-tag in message";
	if (!flags.sdp.len)
		return "No SDP body in message";

	// get destination monologue
	struct call_monologue *dest_ml = call_get_monologue(call, &flags.to_tag);
	if (!dest_ml)
		return "To-tag not found";

	int ret = monologue_subscribe_answer(dest_ml, &flags, &streams);
	if (ret)
		return "Failed to process subscription answer";

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_unsubscribe_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;

	call_ng_process_flags(&flags, ctx);

	if (!flags.call_id.s)
		return "No call-id in message";
	call = call_get(&flags.call_id);
	if (!call)
		return "Unknown call-ID";

	if (!flags.to_tag.s)
		return "No to-tag in message";

	// get destination monologue
	struct call_monologue *dest_ml = call_get_monologue(call, &flags.to_tag);
	if (!dest_ml)
		return "To-tag not found";

	// get optional source monologue
	struct call_monologue *src_ml = NULL;
	if (flags.directional && flags.from_tag.len) {
		src_ml = call_get_monologue(call, &flags.from_tag);
		if (!src_ml)
			return "From-tag not found";
	}

	int ret = monologue_unsubscribe(dest_ml, src_ml, &flags);
	if (ret)
		return "Failed to unsubscribe";

	call_unlock_release_update(&call);

	return NULL;
}

static const char *call_inject_ng(ng_command_ctx_t *ctx, bool start) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;
	g_autoptr(call_t) call2 = NULL;
	parser_arg input = ctx->req;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	call_ng_process_flags(&flags, ctx);

	str source_call_id = STR_NULL;
	str source_tag = STR_NULL;

	if (!flags.call_id.s)
		return "No call-id in message";
	if (!flags.to_tag.s)
		return "No to-tag in message";

	parser->dict_get_str(input, "source-tag", &source_tag);
	if (!source_tag.s)
		return "No source-tag in message";

	if (!parser->dict_get_str(input, "source-call-id", &source_call_id))
		source_call_id = flags.call_id;

	call = call_get(&flags.call_id);
	if (!call)
		return "Unknown call-ID";

	call2 = call_get2(call, &source_call_id);
	if (!call2)
		return "Unknown source call-ID";

	struct call_monologue *dst_ml = call_get_monologue(call, &flags.to_tag);
	if (!dst_ml)
		return "To-tag not found";

	struct call_monologue *src_ml = call_get_monologue(call2, &source_tag);
	if (!src_ml)
		return "Source-tag not found";

	if (src_ml == dst_ml)
		return "Trying to inject to self";

	if (!call_merge(call, call2))
		return "Failed to merge two calls into one";
	call2 = NULL;

	int ret = start
		? monologue_inject_start(src_ml, dst_ml, &flags)
		: monologue_inject_stop(src_ml, dst_ml, &flags);
	if (ret)
		return start ? "Failed to start inject" : "Failed to stop inject";

	call_unlock_release_update(&call);
	return NULL;
}

const char *call_inject_start_ng(ng_command_ctx_t *ctx) {
	return call_inject_ng(ctx, true);
}

const char *call_inject_stop_ng(ng_command_ctx_t *ctx) {
	return call_inject_ng(ctx, false);
}


const char *call_connect_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;
	g_autoptr(call_t) call2 = NULL;
	g_auto(medias_q) medias = TYPED_GQUEUE_INIT;

	const char *err = medias_match(&call, &medias, &flags, ctx);
	if (err)
		return err;

	if (!flags.to_tag.s)
		return "No to-tag in message";

	if (flags.to_call_id.len) {
		call2 = call_get2(call, &flags.to_call_id);
		if (!call2)
			return "Unknown to-tag call-ID";
	}
	else
		call2 = obj_get(call);

	struct call_monologue *dest_ml = call_get_or_create_monologue(call2, &flags.to_tag);
	if (!dest_ml)
		return "To-tag not found";

	if (!call_merge(call, call2))
		return "Failed to merge two calls into one (tag collision)";
	call2 = NULL; // reference released

	dialogue_connect(&medias, dest_ml, &flags);

	call_unlock_release_update(&call);

	return NULL;
}

const char *call_transform_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;

	/*
	 * {
	 *   command: transform
	 *   [ call-id: ... ]
	 *   [ from-tag: ... ]
	 *   [ instance: ... ]
	 *   [ interface: ... ]
	 *   media: [
	 *     {
	 *       [ id: ... ]
	 *       type: audio/video/...
	 *       codec: [
	 *         {
	 *           input: {
	 *             codec: G729
	 *             payload type: 18
	 *             clock rate: 8000
	 *             channels: 1
	 *             [ format: annexb=no ]
	 *             [ options: bitrate=xxx ]
	 *           },
	 *           output: {
	 *             ...
	 *           },
	 *         }, ...
	 *       ],
	 *       destination: {
	 *         family: IP4
	 *         address: 127.0.0.1
	 *         port: 4444
	 *       },
	 *     },
	 *     ...
	 *   ]
	 * }
	 */

	call_ng_process_flags(&flags, ctx);

	if (flags.instance.len && !str_cmp_str(&rtpe_instance_id, &flags.instance))
		return "Transform loop detected";

	char rand_call_id[65];
	if (!flags.call_id.len)
		flags.call_id = STR_LEN(rand_hex_str(rand_call_id, 32), 64);

	char rand_from_tag[65];
	if (!flags.from_tag.len)
		flags.from_tag = STR_LEN(rand_hex_str(rand_from_tag, 32), 64);

	call = call_get_or_create(&flags.call_id, false);
	struct call_monologue *ml = call_get_or_create_monologue(call, &flags.from_tag);

	g_auto(medias_q) mq = TYPED_GQUEUE_INIT;
	if (!monologue_transform(ml, &flags, &mq))
		return "Failed to set up transform";

	const ng_parser_t *parser = ctx->parser_ctx.parser;
	parser->dict_add_str_dup(ctx->resp, "call-id", &call->callid);
	parser->dict_add_str_dup(ctx->resp, "from-tag", &ml->tag);

	parser_arg list = parser->dict_add_list(ctx->resp, "media");

	for (__auto_type l = mq.head; l; l = l->next) {
		__auto_type m = l->data;
		parser_arg dict = parser->list_add_dict(list);
		parser->dict_add_str_dup(dict, "id", &m->media_id);
		__auto_type ps = m->streams.head->data;
		__auto_type sfd = ps->selected_sfd;
		parser->dict_add_str(dict, "family", STR_PTR(sfd->socket.local.address.family->rfc_name));
		parser->dict_add_str_dup(dict, "address", STR_PTR(sockaddr_print_buf(&sfd->socket.local.address)));
		parser->dict_add_int(dict, "port", sfd->socket.local.port);
	}

	call_unlock_release_update(&call);
	return NULL;
}

const char *call_create_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;
	char rand_call_id[65];
	char rand_from_tag[65];
	g_auto(str) sdp = STR_NULL;

	call_ng_process_flags(&flags, ctx);

	if (!flags.call_id.len)
		flags.call_id = STR_LEN(rand_hex_str(rand_call_id, 32), 64);
	if (!flags.from_tag.len)
		flags.from_tag = STR_LEN(rand_hex_str(rand_from_tag, 32), 64);

	call = call_get_or_create(&flags.call_id, false);
	struct call_monologue *ml = call_get_or_create_monologue(call, &flags.from_tag);
	if (!monologue_call_create(ml, &flags))
		return "failed to set up call/monologue";

	if (!sdp_create(&sdp, ml, &flags))
		return "failed to create SDP";

	const ng_parser_t *parser = ctx->parser_ctx.parser;
	parser->dict_add_str_dup(ctx->resp, "call-id", &call->callid);
	parser->dict_add_str_dup(ctx->resp, "from-tag", &ml->tag);

	ctx->ngbuf->sdp_out = sdp.s;
	parser->dict_add_str_dup(ctx->resp, "sdp", &sdp);
	sdp = STR_NULL; // ownership passed to output

	call_unlock_release_update(&call);
	return NULL;
}


const char *call_create_answer_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;

	call_ng_process_flags(&flags, ctx);

	enum basic_errors ret;
	if ((ret = call_ng_basic_checks(&flags)) > 0)
		return _ng_basic_errors[ret];

	call = call_get(&flags.call_id);
	if (!call)
		return "unknown call-ID";

	if (!sdp_parse(&flags.sdp, &parsed, &flags))
		return "Failed to parse SDP";

	if (!sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	if (trickle_ice_update(ctx->ngbuf, call, &flags, &streams))
		return NULL;

	struct call_monologue *ml = call_get_monologue(call, &flags.from_tag);
	if (!ml)
		return "from-tag not found";

	if (!monologue_call_create_answer(ml, &flags, &streams))
		return "failed to perform answer";

	call_unlock_release_update(&call);
	return NULL;
}


void call_interfaces_free(void) {
	if (info_re) {
		pcre2_code_free(info_re);
		info_re = NULL;
	}

	if (streams_re) {
		pcre2_code_free(streams_re);
		streams_re= NULL;
	}

	t_hash_table_destroy(rtpe_signalling_templates);
}

static void parse_templates(charp_ht templates) {
	if (!t_hash_table_is_set(templates))
		return;

	__auto_type iter = t_hash_table_iter(templates);
	char *keyp, *valuep;
	while (t_hash_table_iter_next(&iter, &keyp, &valuep)) {
		char *key = keyp;
		char *value = valuep;
		t_hash_table_insert(rtpe_signalling_templates, str_dup(STR_PTR(key)), str_dup(STR_PTR(value)));
	}

	// look for templates matching known commands
	for (unsigned int i = 0; i < OP_COUNT; i++) {
		const char *cmd = ng_command_strings[i];
		str *tmpl = t_hash_table_lookup(rtpe_signalling_templates, STR_PTR(cmd));
		if (tmpl)
			rtpe_default_signalling_templates[i] = *tmpl;
	}

	// finally look for "default" and store it in the OTHER slot
	str *tmpl = t_hash_table_lookup(rtpe_signalling_templates, STR_PTR("default"));
	if (tmpl)
		rtpe_default_signalling_templates[OP_OTHER] = *tmpl;
}

int call_interfaces_init(charp_ht templates) {
	int errcode;
	PCRE2_SIZE erroff;

	info_re = pcre2_compile((PCRE2_SPTR8) "^([^:,]+)(?::(.*?))?(?:$|,)", PCRE2_ZERO_TERMINATED,
			PCRE2_DOLLAR_ENDONLY | PCRE2_DOTALL, &errcode, &erroff, NULL);
	if (!info_re)
		return -1;

	streams_re = pcre2_compile((PCRE2_SPTR8) "^([\\d.]+):(\\d+)(?::(.*?))?(?:$|,)", PCRE2_ZERO_TERMINATED,
			PCRE2_DOLLAR_ENDONLY | PCRE2_DOTALL, &errcode, &erroff, NULL);
	if (!streams_re)
		return -1;

	rtpe_signalling_templates = str_case_value_ht_new();
	parse_templates(templates);

	return 0;
}
