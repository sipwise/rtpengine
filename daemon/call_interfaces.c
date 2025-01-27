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
#include "control_ng_flags_parser.h"

static pcre2_code *info_re;
static pcre2_code *streams_re;

bool trust_address_def;
bool dtls_passive_def;
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

INLINE int call_ng_flags_prefix(str *s_ori, const char *prefix,
		void (*cb)(str *, unsigned int, helper_arg), helper_arg);
static void call_ng_flags_str_ht(str *s, unsigned int, helper_arg);
static void call_ng_flags_str_q_multi(str *s, unsigned int, helper_arg);
static void call_ng_flags_str_list(const ng_parser_t *, parser_arg list,
		void (*callback)(str *, unsigned int, helper_arg), helper_arg);
static void call_ng_flags_list(const ng_parser_t *, parser_arg list,
		void (*str_callback)(str *, unsigned int, helper_arg),
		void (*item_callback)(const ng_parser_t *, parser_arg, helper_arg),
		helper_arg);
static void call_ng_flags_esc_str_list(str *s, unsigned int, helper_arg);
static void ng_stats_ssrc(const ng_parser_t *parser, parser_arg dict, struct ssrc_hash *ht);
static str *str_dup_escape(const str *s);
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
		if (sockaddr_parse_any(&sp->rtp_endpoint.address, out[RE_UDP_UL_ADDR4]))
			goto fail;
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (sockaddr_parse_any(&sp->rtp_endpoint.address, out[RE_UDP_UL_ADDR6]))
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

static void updated_created_from(call_t *c, const char *addr, const endpoint_t *sin) {
	if (!c->created_from && addr) {
		c->created_from = call_strdup(addr);
		if (sin)
			c->created_from_addr = sin->address;
	}
}

static str call_update_lookup_udp(char **out, enum ng_opmode opmode, const char* addr,
		const endpoint_t *sin)
{
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

	updated_created_from(c, addr, sin);

	if (call_get_mono_dialogue(monologues, c, &fromtag, &totag, NULL, NULL))
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

	gettimeofday(&(from_ml->started), NULL);

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

str call_update_udp(char **out, const char* addr, const endpoint_t *sin) {
	return call_update_lookup_udp(out, OP_OFFER, addr, sin);
}
str call_lookup_udp(char **out) {
	return call_update_lookup_udp(out, OP_ANSWER, NULL, NULL);
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
	sp = g_slice_alloc0(sizeof(*sp));

	SP_SET(sp, SEND);
	SP_SET(sp, RECV);
	sp->protocol = &transport_protocols[PROTO_UNKNOWN];

	if (endpoint_parse_port_any(&sp->rtp_endpoint, a[0], atoi(a[1])))
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
	g_slice_free1(sizeof(*sp), sp);
	return false;
}


static void streams_parse(const char *s, sdp_streams_q *q) {
	int i;
	i = 0;
	pcre2_multi_match(streams_re, s, 4, streams_parse_func, &i, &q->q);
}
void call_unlock_release(call_t *c) {
	rwlock_unlock_w(&c->master_lock);
	obj_put(c);
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

	if (call_get_mono_dialogue(monologues, c, &fromtag, &totag, NULL, NULL)) {
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

	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) atomic_get_na(&rtpe_config.silent_timeout) - (rtpe_now.tv_sec - stats.last_packet),
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

	streambuf_printf(s->outbuf, "session "STR_FORMAT" - - - - %lli\n",
		STR_FMT(&c->callid),
		timeval_diff(&rtpe_now, &c->created) / 1000000);

	/* XXX restore function */

//	mutex_unlock(&c->master_lock);
}

void calls_status_tcp(struct streambuf_stream *s) {
	rwlock_lock_r(&rtpe_callhash_lock);
	streambuf_printf(s->outbuf, "proxy %u "UINT64F"/%i/%i\n",
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

INLINE void ng_sdes_option(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;

	/* Accept only certain individual crypto suites */
	if (call_ng_flags_prefix(s, "only-", call_ng_flags_str_ht, &out->sdes_only))
		return;

	/* Exclude individual crypto suites */
	if (call_ng_flags_prefix(s, "no-", call_ng_flags_str_ht, &out->sdes_no))
		return;

	/* Order individual crypto suites */
	if (call_ng_flags_prefix(s, "order:", call_ng_flags_str_q_multi, &out->sdes_order))
		return;

	/* Crypto suite preferences for the offerer */
	if (call_ng_flags_prefix(s, "offerer_pref:", call_ng_flags_str_q_multi,
					&out->sdes_offerer_pref))
		return;

	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("no"):
		case CSH_LOOKUP("off"):
		case CSH_LOOKUP("disabled"):
		case CSH_LOOKUP("disable"):
			out->sdes_off = 1;
			break;
		case CSH_LOOKUP("unencrypted_srtp"):
		case CSH_LOOKUP("UNENCRYPTED_SRTP"):
			out->sdes_unencrypted_srtp = 1;
			break;
		case CSH_LOOKUP("unencrypted_srtcp"):
		case CSH_LOOKUP("UNENCRYPTED_SRTCP"):
			out->sdes_unencrypted_srtcp = 1;
			break;
		case CSH_LOOKUP("unauthenticated_srtp"):
		case CSH_LOOKUP("UNAUTHENTICATED_SRTP"):
			out->sdes_unauthenticated_srtp = 1;
			break;
		case CSH_LOOKUP("encrypted_srtp"):
		case CSH_LOOKUP("ENCRYPTED_SRTP"):
			out->sdes_encrypted_srtp = 1;
			break;
		case CSH_LOOKUP("encrypted_srtcp"):
		case CSH_LOOKUP("ENCRYPTED_SRTCP"):
			out->sdes_encrypted_srtcp = 1;
			break;
		case CSH_LOOKUP("authenticated_srtp"):
		case CSH_LOOKUP("AUTHENTICATED_SRTP"):
			out->sdes_authenticated_srtp = 1;
			break;
		case CSH_LOOKUP("lifetime"):
			out->sdes_lifetime = 1;
			break;
		case CSH_LOOKUP("pad"):
			out->sdes_pad = 1;
			break;
		case CSH_LOOKUP("static"):
			out->sdes_static = 1;
			break;
		case CSH_LOOKUP("nonew"):
			out->sdes_nonew = 1;
			break;
		case CSH_LOOKUP("prefer"):
		case CSH_LOOKUP("priority"):
			out->sdes_prefer = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'SDES' flag encountered: '"STR_FORMAT"'",
					STR_FMT(s));
	}
}

INLINE void ng_osrtp_option(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;

	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("accept-rfc"):
		case CSH_LOOKUP("accept-RFC"):
			out->osrtp_accept_rfc = 1;
			break;
		case CSH_LOOKUP("accept-legacy"):
			out->osrtp_accept_legacy = 1;
			break;
		case CSH_LOOKUP("accept"):
			out->osrtp_accept_rfc = 1;
			out->osrtp_accept_legacy = 1;
			break;
		case CSH_LOOKUP("offer-legacy"):
			out->osrtp_offer_legacy = 1;
			break;
		case CSH_LOOKUP("offer"):
		case CSH_LOOKUP("offer-RFC"):
		case CSH_LOOKUP("offer-rfc"):
			out->osrtp_offer = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'OSRTP' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}

static void call_ng_flags_str_pair_ht(str *s, unsigned int idx, helper_arg arg) {
	str *s_copy = str_dup_escape(s);
	str token;
	if (!str_token(&token, s_copy, '>')) {
		ilog(LOG_WARN, "SDP manipulations: Ignoring invalid token '" STR_FORMAT "'", STR_FMT(s));
		free(s_copy);
		return;
	}
	str_case_value_ht *ht = arg.svt;
	if (!t_hash_table_is_set(*ht))
		*ht = str_case_value_ht_new();
	t_hash_table_replace(*ht, str_dup(&token), s_copy);
}

static void call_ng_flags_item_pair_ht_iter(str *key, unsigned int idx, helper_arg arg) {
	str *from_to = arg.strs;
	if (from_to[0].len == 0)
		from_to[0] = *key;
	else if (from_to[1].len == 0)
		from_to[1] = *key;
}

static void call_ng_flags_item_pair_ht(const ng_parser_t *parser, parser_arg it, helper_arg arg) {
	str from_to[2] = {0};

	if (!parser->is_list(it))
		goto err;
	parser->list_iter(parser, it, call_ng_flags_item_pair_ht_iter, NULL, from_to);
	if (from_to[0].len == 0 || from_to[1].len == 0)
		goto err;

	str * s_copy_from = str_dup_escape(&from_to[0]);
	str * s_copy_to = str_dup_escape(&from_to[1]);

	str_case_value_ht *ht = arg.svt;
	if (!t_hash_table_is_set(*ht))
		*ht = str_case_value_ht_new();
	t_hash_table_replace(*ht, s_copy_from, s_copy_to);

	return;

err:
	ilog(LOG_WARN, "SDP manipulations: Ignoring invalid contents of string-pair list");
}

/**
 * SDP attribute manipulation praser helpers.
 */
static void ng_sdp_attr_media_iter(const ng_parser_t *parser, str *command_type, parser_arg command_value,
		helper_arg arg)
{
	struct sdp_manipulations *sm = arg.sm;

	switch (__csh_lookup(command_type)) {

		case CSH_LOOKUP("substitute"):
			call_ng_flags_list(parser, command_value, call_ng_flags_str_pair_ht, call_ng_flags_item_pair_ht,
					&sm->subst_commands);
			break;

		case CSH_LOOKUP("add"):
			call_ng_flags_str_list(parser, command_value, call_ng_flags_esc_str_list, &sm->add_commands);
			break;

		case CSH_LOOKUP("remove"):
			call_ng_flags_str_list(parser, command_value, call_ng_flags_str_ht, &sm->rem_commands);
			break;

		default:
			ilog(LOG_WARN, "SDP manipulations: Unknown SDP manipulation command type.");
	}
}
static void ng_sdp_attr_manipulations_iter(const ng_parser_t *parser, str *media_type, parser_arg command_action,
		helper_arg arg)
{
	struct sdp_manipulations *sm = sdp_manipulations_get_by_name(arg.flags->sdp_manipulations, media_type);
	if (!sm) {
		ilog(LOG_WARN, "SDP manipulations: unsupported SDP section '" STR_FORMAT "' targeted.",
				STR_FMT(media_type));
		return;
	}

	if (!parser->dict_iter(parser, command_action, ng_sdp_attr_media_iter, sm))
		ilog(LOG_WARN, "SDP manipulations: Wrong content for SDP section.");
}
INLINE void ng_sdp_attr_manipulations(const ng_parser_t *parser, sdp_ng_flags *flags, parser_arg value) {
	if (!parser->dict_iter(parser, value, ng_sdp_attr_manipulations_iter, flags))
		ilog(LOG_WARN, "SDP manipulations: Wrong type for this type of command.");
}

/**
 * SDP media section manipulation parser helpers.
 */
static void ng_sdp_media_remove_iter(str *media_type, unsigned int i, helper_arg arg)
{
	enum media_type id = codec_get_type(media_type);
	if (id == MT_UNKNOWN || (id == MT_OTHER && str_cmp(media_type, "other")))
	{
		ilog(LOG_WARN, "SDP manipulations: unsupported SDP section '" STR_FORMAT "' targeted.",
				STR_FMT(media_type));
		/* only known media types are supported */
		return;
	}
	arg.flags->sdp_media_remove[id] = true;
}
INLINE void ng_sdp_media_remove(const ng_parser_t *parser, sdp_ng_flags *flags, parser_arg value) {
	if (!parser->is_list(value))
		return;
	parser->list_iter(parser, value, ng_sdp_media_remove_iter, NULL, flags);
}

INLINE void ng_el_option(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("off"):
			out->el_option = EL_OFF;
			break;
		case CSH_LOOKUP("immediate"):
			out->el_option = EL_IMMEDIATE;
			break;
		case CSH_LOOKUP("delayed"):
			out->el_option = EL_DELAYED;
			break;
		case CSH_LOOKUP("heuristic"):
			out->el_option = EL_HEURISTIC;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'endpoint-learning' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}

#ifdef WITH_TRANSCODING
INLINE void ng_t38_option(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("decode"):
			out->t38_decode = 1;
			break;
		case CSH_LOOKUP("force"):
			out->t38_force = 1;
			break;
		case CSH_LOOKUP("stop"):
			out->t38_stop = 1;
			break;
		case CSH_LOOKUP("no-ecm"):
		case CSH_LOOKUP("no-ECM"):
		case CSH_LOOKUP("no ecm"):
		case CSH_LOOKUP("no ECM"):
			out->t38_no_ecm = 1;
			break;
		case CSH_LOOKUP("no-V17"):
		case CSH_LOOKUP("no-V.17"):
		case CSH_LOOKUP("no-v17"):
		case CSH_LOOKUP("no-v.17"):
		case CSH_LOOKUP("no V17"):
		case CSH_LOOKUP("no V.17"):
		case CSH_LOOKUP("no v17"):
		case CSH_LOOKUP("no v.17"):
			out->t38_no_v17 = 1;
			break;
		case CSH_LOOKUP("no-V.27ter"):
		case CSH_LOOKUP("no-V27ter"):
		case CSH_LOOKUP("no-v.27ter"):
		case CSH_LOOKUP("no-v27ter"):
		case CSH_LOOKUP("no V.27ter"):
		case CSH_LOOKUP("no V27ter"):
		case CSH_LOOKUP("no v.27ter"):
		case CSH_LOOKUP("no v27ter"):
			out->t38_no_v27ter = 1;
			break;
		case CSH_LOOKUP("no-V29"):
		case CSH_LOOKUP("no-V.29"):
		case CSH_LOOKUP("no-v29"):
		case CSH_LOOKUP("no-v.29"):
		case CSH_LOOKUP("no V29"):
		case CSH_LOOKUP("no V.29"):
		case CSH_LOOKUP("no v29"):
		case CSH_LOOKUP("no v.29"):
			out->t38_no_v29 = 1;
			break;
		case CSH_LOOKUP("no-V34"):
		case CSH_LOOKUP("no-V.34"):
		case CSH_LOOKUP("no-v34"):
		case CSH_LOOKUP("no-v.34"):
		case CSH_LOOKUP("no V34"):
		case CSH_LOOKUP("no V.34"):
		case CSH_LOOKUP("no v34"):
		case CSH_LOOKUP("no v.34"):
			out->t38_no_v34 = 1;
			break;
		case CSH_LOOKUP("no-IAF"):
		case CSH_LOOKUP("no-iaf"):
		case CSH_LOOKUP("no IAF"):
		case CSH_LOOKUP("no iaf"):
			out->t38_no_iaf = 1;
			break;
		case CSH_LOOKUP("FEC"):
		case CSH_LOOKUP("fec"):
			out->t38_fec = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'T.38' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
#endif


static void call_ng_flags_list(const ng_parser_t *parser, parser_arg list,
		void (*str_callback)(str *, unsigned int, helper_arg),
		void (*item_callback)(const ng_parser_t *, parser_arg, helper_arg),
		helper_arg arg)
{
	str s;
	if (!parser->is_list(list)) {
		if (parser->get_str(list, &s)) {
			str token;
			while (str_token_sep(&token, &s, ','))
				str_callback(&token, 0, arg);
		}
		else
			ilog(LOG_DEBUG, "Ignoring non-list non-string value");
		return;
	}
	parser->list_iter(parser, list, str_callback, item_callback, arg);
}
static void call_ng_flags_str_list(const ng_parser_t *parser, parser_arg list,
		void (*callback)(str *, unsigned int, helper_arg), helper_arg arg)
{
	call_ng_flags_list(parser, list, callback, NULL, arg);
}

static void call_ng_flags_rtcp_mux(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("accept"):
			out->rtcp_mux_accept = 1;
			break;
		case CSH_LOOKUP("demux"):
			out->rtcp_mux_demux = 1;
			break;
		case CSH_LOOKUP("offer"):
			out->rtcp_mux_offer = 1;
			break;
		case CSH_LOOKUP("reject"):
			out->rtcp_mux_reject = 1;
			break;
		case CSH_LOOKUP("require"):
			out->rtcp_mux_require = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'rtcp-mux' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}

static void call_ng_flags_moh(const ng_parser_t *parser, str *key, parser_arg value, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("db-id"):
			out->moh_db_id = parser->get_int_str(value, out->moh_db_id);
			break;
		case CSH_LOOKUP("blob"):
			parser->get_str(value, &out->moh_blob);
			break;
		case CSH_LOOKUP("file"):
			parser->get_str(value, &out->moh_file);
			break;
		case CSH_LOOKUP("connection"):;
			str connection = STR_NULL;
			parser->get_str(value, &connection);
			if (!str_cmp(&connection, "zero"))
				out->moh_zero_connection = 1;
			break;
		case CSH_LOOKUP("mode"):;
			str mode = STR_NULL;
			parser->get_str(value, &mode);
			if (!str_cmp(&mode, "sendrecv"))
				out->moh_sendrecv = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'moh' flag encountered: '" STR_FORMAT "'",
					STR_FMT(key));
	}
}
static void call_ng_flags_replace(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("force-increment-sdp-ver"):
		case CSH_LOOKUP("force-increment-SDP-ver"):
		case CSH_LOOKUP("force increment sdp ver"):
		case CSH_LOOKUP("force increment SDP ver"):
			out->force_inc_sdp_ver = 1;
			break;
		case CSH_LOOKUP("origin"):
			out->replace_origin = 1;
			break;
		case CSH_LOOKUP("origin full"):
		case CSH_LOOKUP("origin-full"):
		case CSH_LOOKUP("origin_full"):
			out->replace_origin_full = 1;
			break;
		case CSH_LOOKUP("sdp-version"):
		case CSH_LOOKUP("SDP-version"):
		case CSH_LOOKUP("sdp version"):
		case CSH_LOOKUP("SDP version"):
			out->replace_sdp_version = 1;
			break;
		/* TODO: after a while remove silent support for this flag */
		case CSH_LOOKUP("session-connection"):
		case CSH_LOOKUP("session connection"):
			ilog(LOG_INFO, "replace-session-connection flag encountered, but not supported anymore.");
			break;
		case CSH_LOOKUP("session-name"):
		case CSH_LOOKUP("session name"):
			out->replace_sess_name = 1;
			break;
		case CSH_LOOKUP("username"):
			out->replace_username = 1;
			break;
		case CSH_LOOKUP("zero-address"):
		case CSH_LOOKUP("zero address"):
			out->replace_zero_address = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'replace' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
static void call_ng_flags_supports(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	if (!str_cmp(s, "load limit"))
		out->supports_load_limit = 1;
	else
		ilog(LOG_INFO | LOG_FLAG_LIMIT, "Optional feature '" STR_FORMAT "' not supported",
				STR_FMT(s));
}
static str *str_dup_escape(const str *s) {
	str *ret = str_dup(s);
	int i;
	while ((i = str_str(ret, "--")) >= 0) {
		ret->s[i] = '=';
		memmove(&ret->s[i + 1], &ret->s[i + 2], ret->len - i - 2);
		ret->len--;
	}
	while ((i = str_str(ret, "..")) >= 0) {
		ret->s[i] = ' ';
		memmove(&ret->s[i + 1], &ret->s[i + 2], ret->len - i - 2);
		ret->len--;
	}
	return ret;
}
static void call_ng_flags_esc_str_list(str *s, unsigned int idx, helper_arg arg) {
	str *s_copy = str_dup_escape(s);
	t_queue_push_tail(arg.q, s_copy);
}
/**
 * Stores flag's value in the given GhashTable.
 */
static void call_ng_flags_str_ht(str *s, unsigned int idx, helper_arg arg) {
	str *s_copy = str_dup_escape(s);
	str_case_ht *ht = arg.sct;
	if (!t_hash_table_is_set(*ht))
		*ht = str_case_ht_new();
	t_hash_table_replace(*ht, s_copy, s_copy);
}
/**
 * Parses one-row flags separated by 'delimiter'.
 * Stores parsed flag's values then in the given GQueue.
 */
static void call_ng_flags_str_q_multi(str *s, unsigned int idx, helper_arg arg) {
	str *s_copy = str_dup_escape(s);
	str token;
	str_q *q = arg.q;

	if (s_copy->len == 0)
		ilog(LOG_DEBUG, "Hm, nothing to parse.");

	while (str_token_sep(&token, s_copy, ';'))
	{
		str * ret = str_dup(&token);
		t_queue_push_tail(q, ret);
	}

	free(s_copy);
}
#ifdef WITH_TRANSCODING
static void call_ng_flags_str_ht_split(str *s, unsigned int idx, helper_arg arg) {
	str_case_value_ht *ht = arg.svt;
	if (!t_hash_table_is_set(*ht))
		*ht = str_case_value_ht_new();
	str splitter = *s;
	while (1) {
		t_hash_table_replace(*ht, str_dup_escape(&splitter), str_dup_escape(s));
		char *c = memrchr(splitter.s, '/', splitter.len);
		if (!c)
			break;
		splitter.len = c - splitter.s;
	}
}
#endif

static struct sdp_manipulations *call_ng_flags_sdp_attr_helper(str *s, sdp_ng_flags *flags) {
	// get media type
	str token;
	if (!str_token(&token, s, '-'))
		return NULL;
	struct sdp_manipulations *sm = sdp_manipulations_get_by_name(flags->sdp_manipulations, &token);
	if (!sm) {
		ilog(LOG_WARN, "SDP manipulations: unsupported SDP section '" STR_FORMAT "' targeted.",
				STR_FMT(&token));
		return NULL;
	}
	return sm;
}
static void call_ng_flags_sdp_attr_helper_add(str *s, unsigned int idx, helper_arg arg) {
	struct sdp_manipulations *sm = call_ng_flags_sdp_attr_helper(s, arg.flags);
	if (!sm)
		return;
	call_ng_flags_esc_str_list(s, idx, &sm->add_commands);
}
static void call_ng_flags_sdp_attr_helper_remove(str *s, unsigned int idx, helper_arg arg) {
	struct sdp_manipulations *sm = call_ng_flags_sdp_attr_helper(s, arg.flags);
	if (!sm)
		return;
	call_ng_flags_str_ht(s, idx, &sm->rem_commands);
}
static void call_ng_flags_sdp_attr_helper_subst(str *s, unsigned int idx, helper_arg arg) {
	struct sdp_manipulations *sm = call_ng_flags_sdp_attr_helper(s, arg.flags);
	if (!sm)
		return;
	call_ng_flags_str_pair_ht(s, idx, &sm->subst_commands);
}

// helper to alias values from other dictionaries into the "flags" dictionary
INLINE int call_ng_flags_prefix(str *s_ori, const char *prefix,
		void (*cb)(str *, unsigned int, helper_arg), helper_arg arg)
{
	size_t len = strlen(prefix);
	str s = *s_ori;
	if (len > 0)
		if (str_shift_cmp(&s, prefix))
			return 0;
	cb(&s, 0, arg);
	return 1;
}
void call_ng_flags_flags(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;

	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("all"):
			out->all = ALL_ALL;
			break;
		case CSH_LOOKUP("allow-asymmetric-codecs"):
		case CSH_LOOKUP("allow-asymmetric-codec"):
		case CSH_LOOKUP("allow asymmetric codecs"):
		case CSH_LOOKUP("allow asymmetric codec"):
			out->allow_asymmetric_codecs = 1;
			break;
		case CSH_LOOKUP("allow-no-codec-media"):
		case CSH_LOOKUP("allow-no-codec-medias"):
		case CSH_LOOKUP("allow-empty-codec-media"):
		case CSH_LOOKUP("allow-empty-codec-medias"):
		case CSH_LOOKUP("allow no codec media"):
		case CSH_LOOKUP("allow no codec medias"):
		case CSH_LOOKUP("allow empty codec media"):
		case CSH_LOOKUP("allow empty codec medias"):
			out->allow_no_codec_media = 1;
			break;
		case CSH_LOOKUP("allow-transcoding"):
		case CSH_LOOKUP("allow transcoding"):
			out->allow_transcoding = 1;
			break;
		case CSH_LOOKUP("always-transcode"):
		case CSH_LOOKUP("always transcode"):;
			static const str str_all = STR_CONST("all");
			call_ng_flags_esc_str_list((str *) &str_all, 0, &out->codec_accept);
			break;
		case CSH_LOOKUP("asymmetric"):
			out->asymmetric = 1;
			break;
		case CSH_LOOKUP("asymmetric-codecs"):
		case CSH_LOOKUP("asymmetric codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `asymmetric-codecs`");
			break;
		case CSH_LOOKUP("audio-player"):
		case CSH_LOOKUP("audio player"):
		case CSH_LOOKUP("player"):
			out->audio_player = AP_TRANSCODING;
			break;
		case CSH_LOOKUP("block-dtmf"):
		case CSH_LOOKUP("block-DTMF"):
		case CSH_LOOKUP("block dtmf"):
		case CSH_LOOKUP("block DTMF"):
			out->block_dtmf = 1;
			break;
		case CSH_LOOKUP("block-egress"):
		case CSH_LOOKUP("block egress"):
			out->block_egress = 1;
			break;
		case CSH_LOOKUP("block-short"):
		case CSH_LOOKUP("block-shorts"):
		case CSH_LOOKUP("block-short-packets"):
		case CSH_LOOKUP("block short"):
		case CSH_LOOKUP("block shorts"):
		case CSH_LOOKUP("block short packets"):
			out->block_short = 1;
			break;
		case CSH_LOOKUP("debug"):
		case CSH_LOOKUP("debugging"):
			out->debug = 1;
			break;
		case CSH_LOOKUP("detect-DTMF"):
		case CSH_LOOKUP("detect-dtmf"):
		case CSH_LOOKUP("detect DTMF"):
		case CSH_LOOKUP("detect dtmf"):
			out->detect_dtmf = 1;
			break;
		case CSH_LOOKUP("directional"):
			out->directional = 1;
			break;
		case CSH_LOOKUP("discard-recording"):
		case CSH_LOOKUP("discard recording"):
			out->discard_recording = 1;
			break;
		case CSH_LOOKUP("early-media"):
		case CSH_LOOKUP("early media"):
			out->early_media = 1;
			break;
		case CSH_LOOKUP("egress"):
			out->egress = 1;
			break;
		case CSH_LOOKUP("exclude-recording"):
		case CSH_LOOKUP("exclude recording"):
			out->exclude_recording = 1;
			break;
		case CSH_LOOKUP("fatal"):
			out->fatal = 1;
			break;
		case CSH_LOOKUP("fragment"):
			out->fragment = 1;
			break;
		case CSH_LOOKUP("full-rtcp-attribute"):
		case CSH_LOOKUP("full-RTCP-attribute"):
		case CSH_LOOKUP("full rtcp attribute"):
		case CSH_LOOKUP("full RTCP attribute"):
			out->full_rtcp_attr = 1;
			break;
		case CSH_LOOKUP("generate-mid"):
		case CSH_LOOKUP("generate mid"):
			out->generate_mid = 1;
			break;
		case CSH_LOOKUP("generate-RTCP"):
		case CSH_LOOKUP("generate-rtcp"):
		case CSH_LOOKUP("generate RTCP"):
		case CSH_LOOKUP("generate rtcp"):
			out->generate_rtcp = 1;
			break;
		case CSH_LOOKUP("ICE-reject"):
		case CSH_LOOKUP("ice-reject"):
		case CSH_LOOKUP("reject-ice"):
		case CSH_LOOKUP("reject-ICE"):
		case CSH_LOOKUP("ICE reject"):
		case CSH_LOOKUP("ice reject"):
		case CSH_LOOKUP("reject ice"):
		case CSH_LOOKUP("reject ICE"):
			out->ice_reject = 1;
			break;
		case CSH_LOOKUP("inactive"):
			out->inactive = 1;
			break;
		case CSH_LOOKUP("inject-DTMF"):
		case CSH_LOOKUP("inject-dtmf"):
		case CSH_LOOKUP("inject DTMF"):
		case CSH_LOOKUP("inject dtmf"):
			out->inject_dtmf = 1;
			break;
		case CSH_LOOKUP("loop-protect"):
		case CSH_LOOKUP("loop protect"):
			out->loop_protect = 1;
			break;
		case CSH_LOOKUP("media-handover"):
		case CSH_LOOKUP("media handover"):
			out->media_handover = 1;
			break;
		case CSH_LOOKUP("mirror-RTCP"):
		case CSH_LOOKUP("mirror-rtcp"):
		case CSH_LOOKUP("RTCP-mirror"):
		case CSH_LOOKUP("rtcp-mirror"):
		case CSH_LOOKUP("mirror RTCP"):
		case CSH_LOOKUP("mirror rtcp"):
		case CSH_LOOKUP("RTCP mirror"):
		case CSH_LOOKUP("rtcp mirror"):
			out->rtcp_mirror = 1;
			break;
		case CSH_LOOKUP("NAT-wait"):
		case CSH_LOOKUP("nat-wait"):
		case CSH_LOOKUP("NAT wait"):
		case CSH_LOOKUP("nat wait"):
			out->nat_wait = 1;
			break;
		case CSH_LOOKUP("new-branch"):
		case CSH_LOOKUP("new branch"):
			out->new_branch = 1;
			break;
		case CSH_LOOKUP("no-codec-renegotiation"):
		case CSH_LOOKUP("reuse-codecs"):
		case CSH_LOOKUP("no codec renegotiation"):
		case CSH_LOOKUP("reuse codecs"):
			out->reuse_codec = 1;
			break;
		case CSH_LOOKUP("no-passthrough"):
		case CSH_LOOKUP("no passthrough"):
			out->passthrough_off = 1;
			break;
		case CSH_LOOKUP("no-player"):
		case CSH_LOOKUP("no-audio-player"):
		case CSH_LOOKUP("no player"):
		case CSH_LOOKUP("no audio player"):
			out->audio_player = AP_OFF;
			break;
		case CSH_LOOKUP("no-port-latching"):
		case CSH_LOOKUP("no port latching"):
			out->no_port_latching = 1;
			break;
		case CSH_LOOKUP("no-redis-update"):
		case CSH_LOOKUP("no redis update"):
			out->no_redis_update = 1;
			break;
		case CSH_LOOKUP("no-rtcp-attribute"):
		case CSH_LOOKUP("no-RTCP-attribute"):
		case CSH_LOOKUP("no rtcp attribute"):
		case CSH_LOOKUP("no RTCP attribute"):
			out->no_rtcp_attr = 1;
			break;
		case CSH_LOOKUP("no-jitter-buffer"):
		case CSH_LOOKUP("no jitter buffer"):
			out->disable_jb = 1;
			break;
		case CSH_LOOKUP("original-sendrecv"):
		case CSH_LOOKUP("original sendrecv"):
			out->original_sendrecv = 1;
			break;
		case CSH_LOOKUP("pad-crypto"):
		case CSH_LOOKUP("pad crypto"):
			out->sdes_pad = 1;
			break;
		case CSH_LOOKUP("passthrough"):
			out->passthrough_on = 1;
			break;
		case CSH_LOOKUP("pierce-NAT"):
		case CSH_LOOKUP("pierce-nat"):
		case CSH_LOOKUP("pierce NAT"):
		case CSH_LOOKUP("pierce nat"):
			out->pierce_nat = 1;
			break;
		case CSH_LOOKUP("port-latching"):
		case CSH_LOOKUP("port latching"):
			out->port_latching = 1;
			break;
		case CSH_LOOKUP("provisional"):
			out->provisional = 1;
			break;
		case CSH_LOOKUP("record-call"):
		case CSH_LOOKUP("record call"):
			out->record_call = 1;
			break;
		case CSH_LOOKUP("recording-vsc"):
		case CSH_LOOKUP("recording-VSC"):
		case CSH_LOOKUP("recording vsc"):
		case CSH_LOOKUP("recording VSC"):
			out->recording_vsc = 1;
			break;
		case CSH_LOOKUP("recording-announcement"):
		case CSH_LOOKUP("recording announcement"):
			out->recording_announcement = 1;
			break;
		case CSH_LOOKUP("reorder-codecs"):
		case CSH_LOOKUP("reorder codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `reorder-codecs`");
			break;
		case CSH_LOOKUP("reset"):
			out->reset = 1;
			break;
		case CSH_LOOKUP("single-codec"):
		case CSH_LOOKUP("single codec"):
			out->single_codec = 1;
			break;
		case CSH_LOOKUP("SIP-source-address"):
		case CSH_LOOKUP("sip-source-address"):
		case CSH_LOOKUP("SIP source address"):
		case CSH_LOOKUP("sip source address"):
			out->trust_address = 0;
			break;
		case CSH_LOOKUP("SIPREC"):
		case CSH_LOOKUP("siprec"):
			out->siprec = 1;
			break;
		case CSH_LOOKUP("skip-recording-db"):
		case CSH_LOOKUP("skip-recording-database"):
		case CSH_LOOKUP("skip recording db"):
		case CSH_LOOKUP("skip recording database"):
			out->skip_recording_db = 1;
			break;
		case CSH_LOOKUP("static-codec"):
		case CSH_LOOKUP("static-codecs"):
		case CSH_LOOKUP("static codec"):
		case CSH_LOOKUP("static codecs"):
			out->static_codecs = 1;
			break;
		case CSH_LOOKUP("strict-source"):
		case CSH_LOOKUP("strict source"):
			out->strict_source = 1;
			break;
		case CSH_LOOKUP("strip-extmap"):
		case CSH_LOOKUP("strip extmap"):
			out->strip_extmap = 1;
			break;
		case CSH_LOOKUP("symmetric-codecs"):
		case CSH_LOOKUP("symmetric codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `symmetric-codecs`");
			break;
		case CSH_LOOKUP("to tag"):
		case CSH_LOOKUP("to-tag"):
		case CSH_LOOKUP("to_tag"):
			/* including the “To” tag in the “delete” message allows to be more selective
			 * about monologues within a dialog to be torn down. */
			out->to_tag_flag = 1;
			break;
		case CSH_LOOKUP("trickle-ICE"):
		case CSH_LOOKUP("trickle-ice"):
		case CSH_LOOKUP("trickle ICE"):
		case CSH_LOOKUP("trickle ice"):
			out->trickle_ice = 1;
			break;
		case CSH_LOOKUP("trust-address"):
		case CSH_LOOKUP("trust address"):
			out->trust_address = 1;
			break;
		case CSH_LOOKUP("unidirectional"):
			out->unidirectional = 1;
			break;
		case CSH_LOOKUP("webrtc"):
		case CSH_LOOKUP("webRTC"):
		case CSH_LOOKUP("WebRTC"):
		case CSH_LOOKUP("WebRtc"):
			ng_flags_webrtc(out);
			break;

		default:
			/* handle values aliases from other dictionaries */

			if (call_ng_flags_prefix(s, "endpoint-learning-", ng_el_option, out))
				return;
			if (call_ng_flags_prefix(s, "from-tags-", call_ng_flags_esc_str_list,
						&out->from_tags))
				return;

			/* OSRTP */
			if (call_ng_flags_prefix(s, "OSRTP-", ng_osrtp_option, out))
				return;
			/* replacing SDP body parts */
			if (call_ng_flags_prefix(s, "replace-", call_ng_flags_replace, out))
				return;
			/* rtcp-mux */
			if (call_ng_flags_prefix(s, "rtcp-mux-", call_ng_flags_rtcp_mux, out))
				return;

			/* codec manipulations */
			{
				if (call_ng_flags_prefix(s, "codec-except-", call_ng_flags_str_ht,
							&out->codec_except))
					return;
				if (call_ng_flags_prefix(s, "codec-offer-", call_ng_flags_esc_str_list,
							&out->codec_offer))
					return;
				if (call_ng_flags_prefix(s, "codec-strip-", call_ng_flags_esc_str_list,
							&out->codec_strip))
					return;
			}
			/* SDES */
			{
				if (call_ng_flags_prefix(s, "SDES-", ng_sdes_option, out))
					return;
				if (call_ng_flags_prefix(s, "SDES-offerer_pref:", call_ng_flags_str_q_multi,
								&out->sdes_offerer_pref))
					return;
				if (call_ng_flags_prefix(s, "SDES-no-", call_ng_flags_str_ht, &out->sdes_no))
					return;
				if (call_ng_flags_prefix(s, "SDES-only-", call_ng_flags_str_ht, &out->sdes_only))
					return;
				if (call_ng_flags_prefix(s, "SDES-order:", call_ng_flags_str_q_multi, &out->sdes_order))
					return;
			}
			/* SDP attributes manipulations */
			{
				if (call_ng_flags_prefix(s, "sdp-attr-add-", call_ng_flags_sdp_attr_helper_add, out))
					return;
				if (call_ng_flags_prefix(s, "sdp-attr-remove-", call_ng_flags_sdp_attr_helper_remove, out))
					return;
				if (call_ng_flags_prefix(s, "sdp-attr-substitute-", call_ng_flags_sdp_attr_helper_subst, out))
					return;
			}
#ifdef WITH_TRANSCODING
			/* transcoding */
			{
				if (out->opmode == OP_OFFER || out->opmode == OP_SUBSCRIBE_REQ || out->opmode == OP_PUBLISH) {
					if (call_ng_flags_prefix(s, "transcode-", call_ng_flags_esc_str_list,
								&out->codec_transcode))
						return;
					if (call_ng_flags_prefix(s, "codec-transcode-", call_ng_flags_esc_str_list,
								&out->codec_transcode))
						return;
					if (call_ng_flags_prefix(s, "codec-mask-", call_ng_flags_esc_str_list,
								&out->codec_mask))
						return;
					if (call_ng_flags_prefix(s, "T38-", ng_t38_option, out))
						return;
					if (call_ng_flags_prefix(s, "T.38-", ng_t38_option, out))
						return;
				}
				if (call_ng_flags_prefix(s, "codec-accept-", call_ng_flags_esc_str_list,
							&out->codec_accept))
					return;
				if (call_ng_flags_prefix(s, "codec-consume-", call_ng_flags_esc_str_list,
							&out->codec_consume))
					return;
				if (call_ng_flags_prefix(s, "codec-set-", call_ng_flags_str_ht_split,
							&out->codec_set))
					return;
			}
#endif

			ilog(LOG_WARN, "Unknown flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}

void call_ng_flags_init(sdp_ng_flags *out, enum ng_opmode opmode) {
	ZERO(*out);
	out->opmode = opmode;

	out->trust_address = trust_address_def;
	out->dtls_passive = dtls_passive_def;
	out->dtls_reverse_passive = dtls_passive_def;
	out->el_option = rtpe_config.endpoint_learning;
	out->tos = 256;
	out->delay_buffer = -1;
	out->delete_delay = -1;
	out->volume = 9999;
	out->digit = -1;
	out->repeat_duration = -1;
	out->frequencies = g_array_new(false, false, sizeof(int));
	for (int i = 0; i < __MT_MAX; ++i)
		out->sdp_media_remove[i] = false;
}

static void call_ng_direction_flag_iter(str *s, unsigned int i, helper_arg arg) {
	if (i >= 2)
		return;
	arg.flags->direction[i] = *s;
}
void call_ng_direction_flag(const ng_parser_t *parser, sdp_ng_flags *flags, parser_arg value)
{
	if (!parser->is_list(value))
		return;
	parser->list_iter(parser, value, call_ng_direction_flag_iter, NULL, flags);
}
void call_ng_codec_flags(const ng_parser_t *parser, str *key, parser_arg value, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("except"):
			call_ng_flags_str_list(parser, value, call_ng_flags_str_ht, &out->codec_except);
			return;
		case CSH_LOOKUP("offer"):
			call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->codec_offer);
			return;
		case CSH_LOOKUP("strip"):
			call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->codec_strip);
			return;
	}
#ifdef WITH_TRANSCODING
	if (out->opmode == OP_OFFER || out->opmode == OP_SUBSCRIBE_REQ || out->opmode == OP_PUBLISH
			|| out->opmode == OP_PLAY_MEDIA)
	{
		switch (__csh_lookup(key)) {
			case CSH_LOOKUP("accept"):
				call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->codec_accept);
				return;
			case CSH_LOOKUP("consume"):
				call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->codec_consume);
				return;
			case CSH_LOOKUP("mask"):
				call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->codec_mask);
				return;
			case CSH_LOOKUP("set"):
				call_ng_flags_str_list(parser, value, call_ng_flags_str_ht_split, &out->codec_set);
				return;
			case CSH_LOOKUP("transcode"):
				call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list,
						&out->codec_transcode);
				return;
		}
	}
	else {
		// silence warnings
		switch (__csh_lookup(key)) {
			case CSH_LOOKUP("accept"):
			case CSH_LOOKUP("consume"):
			case CSH_LOOKUP("mask"):
			case CSH_LOOKUP("set"):
			case CSH_LOOKUP("transcode"):
				return;
		}
	}
#endif
	ilog(LOG_WARN, "Unknown 'codec' operation encountered: '" STR_FORMAT "'", STR_FMT(key));
}
#ifdef WITH_TRANSCODING
static void call_ng_parse_block_mode(str *s, enum block_dtmf_mode *output) {
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("drop"):
			*output = BLOCK_DTMF_DROP;
			break;
		case CSH_LOOKUP("DTMF"):
		case CSH_LOOKUP("dtmf"):
			*output = BLOCK_DTMF_DTMF;
			break;
		case CSH_LOOKUP("off"):
			*output = BLOCK_DTMF_OFF;
			break;
		case CSH_LOOKUP("random"):
			*output = BLOCK_DTMF_RANDOM;
			break;
		case CSH_LOOKUP("silence"):
			*output = BLOCK_DTMF_SILENCE;
			break;
		case CSH_LOOKUP("tone"):
			*output = BLOCK_DTMF_TONE;
			break;
		case CSH_LOOKUP("zero"):
			*output = BLOCK_DTMF_ZERO;
			break;
		default:
			ilog(LOG_WARN, "Unknown DTMF block mode encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
#endif

static void call_ng_flags_freqs(const ng_parser_t *parser, parser_arg value, sdp_ng_flags *out);
static void call_ng_flags_freqs_iter(const ng_parser_t *parser, parser_arg item, helper_arg arg) {
	call_ng_flags_freqs(parser, item, arg.flags);
}
static void call_ng_flags_freqs(const ng_parser_t *parser, parser_arg value, sdp_ng_flags *out) {
	unsigned int val;

	if (parser->is_int(value)) {
		val = parser->get_int(value);
		g_array_append_val(out->frequencies, val);
	}
	else if (parser->is_list(value))
		parser->list_iter(parser, value, NULL, call_ng_flags_freqs_iter, out);
	else {
		val = parser->get_int_str(value, 0);
		if (val)
			g_array_append_val(out->frequencies, val);
		else
			ilog(LOG_WARN, "Invalid content type in `frequencies` list");
	}
}

static void call_ng_received_from_string(sdp_ng_flags *flags, str *s) {
	flags->received_from_family = STR_NULL;
	flags->received_from_address = *s;
}
static void call_ng_received_from_iter(str *key, unsigned int i, helper_arg arg) {
	switch (i) {
		case 0:
			arg.flags->received_from_family = *key;
			break;
		case 1:
			arg.flags->received_from_address = *key;
			break;
	}
}

void call_ng_main_flags(const ng_parser_t *parser, str *key, parser_arg value, helper_arg arg) {
	str s = STR_NULL;
	sdp_ng_flags *out = arg.flags;

	parser->get_str(value, &s);

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("address"):
			out->address = s;
			break;
		case CSH_LOOKUP("address family"):
		case CSH_LOOKUP("address-family"):
			if (s.s) {
				out->address_family_str = s;
				out->address_family = get_socket_family_rfc(&out->address_family_str);
			}
			break;
		case CSH_LOOKUP("all"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "all"):
					out->all = ALL_ALL;
					break;
				case CSH_LOOKUP_N(1, "none"):
					out->all = ALL_NONE;
					break;
				case CSH_LOOKUP_N(1, "offer-answer"):
					out->all = ALL_OFFER_ANSWER;
					break;
				case CSH_LOOKUP_N(1, "not-offer-answer"):
				case CSH_LOOKUP_N(1, "non-offer-answer"):
				case CSH_LOOKUP_N(1, "except-offer-answer"):
					out->all = ALL_NON_OFFER_ANSWER;
					break;
				case CSH_LOOKUP_N(1, "flows"):
					out->all = ALL_FLOWS;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'all' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("audio-player"):
		case CSH_LOOKUP("player"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "default"):
					out->audio_player = AP_DEFAULT;
					break;
				case CSH_LOOKUP_N(1, "on"):
				case CSH_LOOKUP_N(1, "yes"):
				case CSH_LOOKUP_N(1, "enable"):
				case CSH_LOOKUP_N(1, "enabled"):
				case CSH_LOOKUP_N(1, "transcode"):
				case CSH_LOOKUP_N(1, "transcoding"):
					out->audio_player = AP_TRANSCODING;
					break;
				case CSH_LOOKUP_N(1, "no"):
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "disable"):
				case CSH_LOOKUP_N(1, "disabled"):
					out->audio_player = AP_OFF;
					break;
				case CSH_LOOKUP_N(1, "force"):
				case CSH_LOOKUP_N(1, "forced"):
				case CSH_LOOKUP_N(1, "always"):
				case CSH_LOOKUP_N(1, "everything"):
					out->audio_player = AP_FORCE;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'audio-player' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("blob"):
			out->blob = s;
			break;
		case CSH_LOOKUP("call-id"):
		case CSH_LOOKUP("call-ID"):
		case CSH_LOOKUP("call id"):
		case CSH_LOOKUP("call ID"):
			out->call_id = s;
			break;
		case CSH_LOOKUP("code"):
		case CSH_LOOKUP("digit"):
			out->digit = parser->get_int_str(value, out->digit);
			if (s.len == 1)
				out->digit = s.s[0];
			break;
		case CSH_LOOKUP("codec"):
			parser->dict_iter(parser, value, call_ng_codec_flags, out);
			break;
		case CSH_LOOKUP("command"):
			break;
		case CSH_LOOKUP("db-id"):
			out->db_id = parser->get_int_str(value, out->db_id);
			break;
		case CSH_LOOKUP("delete delay"):
		case CSH_LOOKUP("delete-delay"):
		case CSH_LOOKUP("delete_delay"):
			out->delete_delay = parser->get_int_str(value, out->delete_delay);
			break;
		case CSH_LOOKUP("direction"):
			call_ng_direction_flag(parser, out, value);
			break;
		case CSH_LOOKUP("drop-traffic"):
		case CSH_LOOKUP("drop traffic"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "start"):
					out->drop_traffic_start = 1;
					break;
				case CSH_LOOKUP_N(1, "stop"):
					out->drop_traffic_stop = 1;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'drop-traffic' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("DTLS"):
		case CSH_LOOKUP("dtls"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "passive"):
					out->dtls_passive = 1;
					break;
				case CSH_LOOKUP_N(1, "active"):
					out->dtls_passive = 0;
					break;
				case CSH_LOOKUP_N(1, "no"):
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "disabled"):
				case CSH_LOOKUP_N(1, "disable"):
					out->dtls_off = 1;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'DTLS' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("DTLS fingerprint"):
		case CSH_LOOKUP("DTLS-fingerprint"):
		case CSH_LOOKUP("dtls fingerprint"):
		case CSH_LOOKUP("dtls-fingerprint"):
			out->dtls_fingerprint = s;
			break;
		case CSH_LOOKUP("DTLS-reverse"):
		case CSH_LOOKUP("dtls-reverse"):
		case CSH_LOOKUP("DTLS reverse"):
		case CSH_LOOKUP("dtls reverse"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "passive"):
					out->dtls_reverse_passive = 1;
					break;
				case CSH_LOOKUP_N(1, "active"):
					out->dtls_reverse_passive = 0;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'DTLS-reverse' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("DTMF-delay"):
		case CSH_LOOKUP("DTMF delay"):
		case CSH_LOOKUP("dtmf-delay"):
		case CSH_LOOKUP("dtmf delay"):
			out->dtmf_delay = parser->get_int_str(value, out->dtmf_delay);
			break;
		case CSH_LOOKUP("dtmf-log-dest"):
		case CSH_LOOKUP("DTMF-log-dest"):
		case CSH_LOOKUP("dtmf-log-destination"):
		case CSH_LOOKUP("DTMF-log-destination"):
			if (endpoint_parse_any_str(&out->dtmf_log_dest, &s))
				ilog(LOG_WARN, "Failed to parse 'dtmf-log-dest' address '" STR_FORMAT "'",
						STR_FMT(&s));
			break;
		case CSH_LOOKUP("duration"):
			out->duration = parser->get_int_str(value, out->duration);
			break;
#ifdef WITH_TRANSCODING
		case CSH_LOOKUP("DTMF-security"):
		case CSH_LOOKUP("dtmf-security"):
		case CSH_LOOKUP("DTMF security"):
		case CSH_LOOKUP("dtmf security"):
			call_ng_parse_block_mode(&s, &out->block_dtmf_mode);
			break;
		case CSH_LOOKUP("DTMF-security-trigger"):
		case CSH_LOOKUP("dtmf-security-trigger"):
		case CSH_LOOKUP("DTMF security trigger"):
		case CSH_LOOKUP("dtmf security trigger"):
			call_ng_parse_block_mode(&s, &out->block_dtmf_mode_trigger);
			break;
		case CSH_LOOKUP("DTMF-security-trigger-end"):
		case CSH_LOOKUP("dtmf-security-trigger-end"):
		case CSH_LOOKUP("DTMF security trigger end"):
		case CSH_LOOKUP("dtmf security trigger end"):
			call_ng_parse_block_mode(&s, &out->block_dtmf_mode_trigger_end);
			break;
		case CSH_LOOKUP("delay-buffer"):
		case CSH_LOOKUP("delay buffer"):
			out->delay_buffer = parser->get_int_str(value, out->delay_buffer);
			break;
#endif
		case CSH_LOOKUP("endpoint-learning"):
		case CSH_LOOKUP("endpoint learning"):
			call_ng_flags_str_list(parser, value, ng_el_option, out);
			break;

		case CSH_LOOKUP("file"):
			out->file = s;
			break;
		case CSH_LOOKUP("frequency"):
		case CSH_LOOKUP("frequencies"):
			call_ng_flags_freqs(parser, value, out);
			break;
		case CSH_LOOKUP("from-interface"):
			out->direction[0] = s;
			break;
		case CSH_LOOKUP("from-label"):
		case CSH_LOOKUP("label"):
			out->label = s;
			break;
		case CSH_LOOKUP("from-tag"):
			out->from_tag = s;
			break;
		case CSH_LOOKUP("from-tags"):
			call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->from_tags);
			break;
		case CSH_LOOKUP("flags"):
			call_ng_flags_str_list(parser, value, call_ng_flags_flags, out);
			break;
		case CSH_LOOKUP("generate RTCP"):
		case CSH_LOOKUP("generate-RTCP"):
		case CSH_LOOKUP("generate rtcp"):
		case CSH_LOOKUP("generate-rtcp"):
			if (!str_cmp(&s, "on"))
				out->generate_rtcp = 1;
			else if (!str_cmp(&s, "off"))
				out->generate_rtcp_off = 1;
			break;
		case CSH_LOOKUP("ICE"):
		case CSH_LOOKUP("ice"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "remove"):
					out->ice_option = ICE_REMOVE;
					break;
				case CSH_LOOKUP_N(1, "force"):
					out->ice_option = ICE_FORCE;
					break;
				case CSH_LOOKUP_N(1, "default"):
					out->ice_option = ICE_DEFAULT;
					break;
				case CSH_LOOKUP_N(1, "optional"):
					out->ice_option = ICE_OPTIONAL;
					break;
				case CSH_LOOKUP_N(1, "force_relay"):
				case CSH_LOOKUP_N(1, "force-relay"):
				case CSH_LOOKUP_N(1, "force relay"):
					out->ice_option = ICE_FORCE_RELAY;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'ICE' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("ICE-lite"):
		case CSH_LOOKUP("ice-lite"):
		case CSH_LOOKUP("ICE lite"):
		case CSH_LOOKUP("ice lite"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "none"):
				case CSH_LOOKUP_N(1, "no"):
					out->ice_lite_option = ICE_LITE_OFF;
					break;
				case CSH_LOOKUP_N(1, "forward"):
				case CSH_LOOKUP_N(1, "offer"):
				case CSH_LOOKUP_N(1, "fwd"):
				case CSH_LOOKUP_N(1, "fw"):
					out->ice_lite_option = ICE_LITE_FWD;
					break;
				case CSH_LOOKUP_N(1, "backward"):
				case CSH_LOOKUP_N(1, "backwards"):
				case CSH_LOOKUP_N(1, "reverse"):
				case CSH_LOOKUP_N(1, "answer"):
				case CSH_LOOKUP_N(1, "back"):
				case CSH_LOOKUP_N(1, "bkw"):
				case CSH_LOOKUP_N(1, "bk"):
					out->ice_lite_option = ICE_LITE_BKW;
					break;
				case CSH_LOOKUP_N(1, "both"):
					out->ice_lite_option = ICE_LITE_BOTH;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'ICE-lite' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("interface"):
			out->interface = s;
			break;
		case CSH_LOOKUP("media address"):
		case CSH_LOOKUP("media-address"):
			if (sockaddr_parse_any_str(&out->media_address, &s))
				ilog(LOG_WARN, "Could not parse 'media-address'");
			break;
		case CSH_LOOKUP("media echo"):
		case CSH_LOOKUP("media-echo"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "blackhole"):
				case CSH_LOOKUP_N(1, "sinkhole"):
					out->media_echo = MEO_BLACKHOLE;
					break;
				case CSH_LOOKUP_N(1, "forward"):
				case CSH_LOOKUP_N(1, "fwd"):
				case CSH_LOOKUP_N(1, "fw"):
					out->media_echo = MEO_FWD;
					break;
				case CSH_LOOKUP_N(1, "backward"):
				case CSH_LOOKUP_N(1, "backwards"):
				case CSH_LOOKUP_N(1, "reverse"):
				case CSH_LOOKUP_N(1, "back"):
				case CSH_LOOKUP_N(1, "bkw"):
				case CSH_LOOKUP_N(1, "bk"):
					out->media_echo = MEO_BKW;
					break;
				case CSH_LOOKUP_N(1, "both"):
					out->media_echo = MEO_BOTH;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'media-echo' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("metadata"):
			out->metadata = s;
			break;
		case CSH_LOOKUP("moh"):
		case CSH_LOOKUP("MoH"):
		case CSH_LOOKUP("MOH"):
			parser->dict_iter(parser, value, call_ng_flags_moh, out);
			break;
		case CSH_LOOKUP("OSRTP"):
		case CSH_LOOKUP("osrtp"):
			call_ng_flags_str_list(parser, value, ng_osrtp_option, out);
			break;
		case CSH_LOOKUP("output-destination"):
		case CSH_LOOKUP("output-dest"):
		case CSH_LOOKUP("output-file"):
		case CSH_LOOKUP("recording-destination"):
		case CSH_LOOKUP("recording-dest"):
		case CSH_LOOKUP("recording-file"):
		case CSH_LOOKUP("output destination"):
		case CSH_LOOKUP("output dest"):
		case CSH_LOOKUP("output file"):
		case CSH_LOOKUP("recording destination"):
		case CSH_LOOKUP("recording dest"):
		case CSH_LOOKUP("recording file"):
			out->recording_file = s;
			break;
		case CSH_LOOKUP("recording-media-slot-offer"):
			// This needs to be > 0
			//out->media_rec_slot_offer = bencode_get_integer_str(value, out->media_rec_slot_offer);
			out->media_rec_slot_offer = parser->get_int_str(value, out->media_rec_slot_offer);
		break;
		case CSH_LOOKUP("recording-media-slot-answer"):
			// This needs to be > 0
			out->media_rec_slot_answer = parser->get_int_str(value, out->media_rec_slot_answer);
		break;
		case CSH_LOOKUP("recording-media-slots"):
			out->media_rec_slots = parser->get_int_str(value, out->media_rec_slots);
		break;
		case CSH_LOOKUP("passthrough"):
		case CSH_LOOKUP("passthru"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "on"):
				case CSH_LOOKUP_N(1, "yes"):
				case CSH_LOOKUP_N(1, "enable"):
				case CSH_LOOKUP_N(1, "enabled"):
					out->passthrough_on = 1;
					break;
				case CSH_LOOKUP_N(1, "no"):
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "disable"):
				case CSH_LOOKUP_N(1, "disabled"):
					out->passthrough_off = 1;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'passthrough' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("pause"):
			out->pause = parser->get_int_str(value, out->pause);
			break;
		case CSH_LOOKUP("ptime"):
			if (out->opmode == OP_OFFER)
				out->ptime = parser->get_int_str(value, 0);
			break;
		case CSH_LOOKUP("ptime-reverse"):
		case CSH_LOOKUP("ptime reverse"):
		case CSH_LOOKUP("reverse ptime"):
		case CSH_LOOKUP("reverse-ptime"):
			if (out->opmode == OP_OFFER)
				out->rev_ptime = parser->get_int_str(value, 0);
			break;

		case CSH_LOOKUP("received from"):
		case CSH_LOOKUP("received-from"):
			if (!parser->is_list(value)) {
				call_ng_received_from_string(out, &s);
				break;
			}
			parser->list_iter(parser, value, call_ng_received_from_iter, NULL, out);
			break;
		case CSH_LOOKUP("record call"):
		case CSH_LOOKUP("record-call"):
			out->record_call_str = s;
			break;
		case CSH_LOOKUP("recording path"):
		case CSH_LOOKUP("recording dir"):
		case CSH_LOOKUP("recording directory"):
		case CSH_LOOKUP("recording folder"):
		case CSH_LOOKUP("output path"):
		case CSH_LOOKUP("output dir"):
		case CSH_LOOKUP("output directory"):
		case CSH_LOOKUP("output folder"):
		case CSH_LOOKUP("recording-path"):
		case CSH_LOOKUP("recording-dir"):
		case CSH_LOOKUP("recording-directory"):
		case CSH_LOOKUP("recording-folder"):
		case CSH_LOOKUP("output-path"):
		case CSH_LOOKUP("output-dir"):
		case CSH_LOOKUP("output-directory"):
		case CSH_LOOKUP("output-folder"):
			out->recording_path = s;
			break;
		case CSH_LOOKUP("recording pattern"):
		case CSH_LOOKUP("recording-pattern"):
		case CSH_LOOKUP("output pattern"):
		case CSH_LOOKUP("output-pattern"):
			out->recording_pattern = s;
			break;
		case CSH_LOOKUP("repeat-times"):
			out->repeat_times = parser->get_int_str(value, out->repeat_times);
			break;
		case CSH_LOOKUP("repeat-duration"):
			out->repeat_duration = parser->get_int_str(value, out->repeat_duration);
			break;
		case CSH_LOOKUP("replace"):
			call_ng_flags_str_list(parser, value, call_ng_flags_replace, out);
			break;
		case CSH_LOOKUP("rtcp-mux"):
		case CSH_LOOKUP("RTCP-mux"):
			call_ng_flags_str_list(parser, value, call_ng_flags_rtcp_mux, out);
			break;
		case CSH_LOOKUP("rtpp-flags"):
		case CSH_LOOKUP("rtpp_flags"):;
			/* s - list of rtpp flags */
			parse_rtpp_flags(&s, out);
			break;
		case CSH_LOOKUP("SDES"):
		case CSH_LOOKUP("sdes"):
			call_ng_flags_str_list(parser, value, ng_sdes_option, out);
			break;
		case CSH_LOOKUP("SDP"):
		case CSH_LOOKUP("sdp"):
			out->sdp = s;
			break;
		case CSH_LOOKUP("sdp-attr"):
		case CSH_LOOKUP("SDP-attr"):
			ng_sdp_attr_manipulations(parser, out, value);
			break;
		case CSH_LOOKUP("sdp-media-remove"):
		case CSH_LOOKUP("SDP-media-remove"):
		case CSH_LOOKUP("sdp_media_remove"):
		case CSH_LOOKUP("SDP_media_remove"):
			ng_sdp_media_remove(parser, out, value);
			break;
		case CSH_LOOKUP("set-label"):
			out->set_label = s;
			break;
		case CSH_LOOKUP("sip-code"):
		case CSH_LOOKUP("sip_code"):
		case CSH_LOOKUP("SIP-code"):
		case CSH_LOOKUP("SIP_code"):
		case CSH_LOOKUP("sip-response-code"):
		case CSH_LOOKUP("sip_response_code"):
		case CSH_LOOKUP("SIP-response-code"):
		case CSH_LOOKUP("SIP_response_code"):
			out->code = parser->get_int_str(value, out->code);
			break;
		case CSH_LOOKUP("sip-message-type"):
		case CSH_LOOKUP("sip_message_type"):
		case CSH_LOOKUP("SIP-message-type"):
		case CSH_LOOKUP("SIP_message_type"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "request"):
				case CSH_LOOKUP_N(1, "sip-request"):
				case CSH_LOOKUP_N(1, "sip_request"):
				case CSH_LOOKUP_N(1, "SIP-request"):
				case CSH_LOOKUP_N(1, "SIP_request"):
					out->message_type = SIP_REQUEST;
					break;
				case CSH_LOOKUP_N(1, "reply"):
				case CSH_LOOKUP_N(1, "sip-response"):
				case CSH_LOOKUP_N(1, "sip_response"):
				case CSH_LOOKUP_N(1, "SIP-response"):
				case CSH_LOOKUP_N(1, "SIP_response"):
				case CSH_LOOKUP_N(1, "sip-reply"):
				case CSH_LOOKUP_N(1, "sip_reply"):
				case CSH_LOOKUP_N(1, "SIP-reply"):
				case CSH_LOOKUP_N(1, "SIP_reply"):
					out->message_type = SIP_REPLY;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'sip-message-type' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("start-pos"):
			out->start_pos = parser->get_int_str(value, out->start_pos);
			break;
		case CSH_LOOKUP("supports"):
			call_ng_flags_str_list(parser, value, call_ng_flags_supports, out);
			break;

#ifdef WITH_TRANSCODING
		case CSH_LOOKUP("T38"):
		case CSH_LOOKUP("T.38"):
		case CSH_LOOKUP("t38"):
		case CSH_LOOKUP("t.38"):
			call_ng_flags_str_list(parser, value, ng_t38_option, out);
			break;
#endif
		case CSH_LOOKUP("template"):;
			str *tplate = t_hash_table_lookup(rtpe_signalling_templates, &s);
			if (!tplate) {
				ilog(LOG_WARN, "Templates for signalling flags '" STR_FORMAT "' not found",
						STR_FMT(&s));
				break;
			}
			// naive approach: just parse them out every time
			// TODO: improve this by pre-parsing the flags at startup
			parse_rtpp_flags(tplate, out);
			break;
		case CSH_LOOKUP("to-interface"):
			out->direction[1] = s;
			break;
		case CSH_LOOKUP("to-label"):
			out->to_label = s;
			break;
		case CSH_LOOKUP("to-call-id"):
			out->to_call_id = s;
			break;
		case CSH_LOOKUP("to-tag"):
			out->to_tag = s;
			break;
		case CSH_LOOKUP("TOS"):
		case CSH_LOOKUP("tos"):
			out->tos = parser->get_int_str(value, out->tos);
			break;
		case CSH_LOOKUP("transport protocol"):
		case CSH_LOOKUP("transport-protocol"):
			if (!str_cmp(&s, "accept"))
				out->protocol_accept = 1;
			else
				out->transport_protocol = transport_protocol(&s);
			break;
		case CSH_LOOKUP("trigger"):
			out->trigger = s;
			break;
		case CSH_LOOKUP("trigger-end"):
		case CSH_LOOKUP("trigger end"):
		case CSH_LOOKUP("end trigger"):
		case CSH_LOOKUP("end-trigger"):
			out->trigger_end = s;
			break;
		case CSH_LOOKUP("trigger-end-time"):
		case CSH_LOOKUP("trigger end time"):
		case CSH_LOOKUP("end-trigger-time"):
		case CSH_LOOKUP("end trigger time"):
			out->trigger_end_ms = parser->get_int_str(value, out->trigger_end_ms);
			break;
		case CSH_LOOKUP("trigger-end-digits"):
		case CSH_LOOKUP("trigger end digits"):
		case CSH_LOOKUP("end-trigger-digits"):
		case CSH_LOOKUP("end trigger digits"):
			out->trigger_end_digits = parser->get_int_str(value, out->trigger_end_digits);
			break;

		case CSH_LOOKUP("via-branch"):
			out->via_branch = s;
			break;
		case CSH_LOOKUP("volume"):
			out->volume = parser->get_int_str(value, out->volume);
			break;
		case CSH_LOOKUP("vsc-pause-rec"):
		case CSH_LOOKUP("VSC-pause-rec"):
		case CSH_LOOKUP("vsc-pause-recording"):
		case CSH_LOOKUP("VSC-pause-recording"):
			out->vsc_pause_rec = s;
			break;
		case CSH_LOOKUP("vsc-pause-resume-rec"):
		case CSH_LOOKUP("VSC-pause-resume-rec"):
		case CSH_LOOKUP("vsc-pause-resume-recording"):
		case CSH_LOOKUP("VSC-pause-resume-recording"):
			out->vsc_pause_resume_rec = s;
			break;
		case CSH_LOOKUP("vsc-start-pause-resume-rec"):
		case CSH_LOOKUP("VSC-start-pause-resume-rec"):
		case CSH_LOOKUP("vsc-start-pause-resume-recording"):
		case CSH_LOOKUP("VSC-start-pause-resume-recording"):
			out->vsc_start_pause_resume_rec = s;
			break;
		case CSH_LOOKUP("vsc-start-rec"):
		case CSH_LOOKUP("VSC-start-rec"):
		case CSH_LOOKUP("vsc-start-recording"):
		case CSH_LOOKUP("VSC-start-recording"):
			out->vsc_start_rec = s;
			break;
		case CSH_LOOKUP("vsc-start-stop-rec"):
		case CSH_LOOKUP("VSC-start-stop-rec"):
		case CSH_LOOKUP("vsc-start-stop-recording"):
		case CSH_LOOKUP("VSC-start-stop-recording"):
			out->vsc_start_stop_rec = s;
			break;
		case CSH_LOOKUP("vsc-stop-rec"):
		case CSH_LOOKUP("VSC-stop-rec"):
		case CSH_LOOKUP("vsc-stop-recording"):
		case CSH_LOOKUP("VSC-stop-recording"):
			out->vsc_stop_rec = s;
			break;
		case CSH_LOOKUP("xmlrpc-callback"):
		case CSH_LOOKUP("XMLRPC-callback"):
			if (sockaddr_parse_any_str(&out->xmlrpc_callback, &s))
				ilog(LOG_WARN, "Failed to parse 'xmlrpc-callback' address '" STR_FORMAT "'",
						STR_FMT(&s));
			break;
		default:
			ilog(LOG_WARN, "Unknown dictionary key encountered: '" STR_FORMAT "'", STR_FMT(key));
	}
}

static void call_ng_process_flags(sdp_ng_flags *out, ng_command_ctx_t *ctx) {
	const ng_parser_t *parser = ctx->parser_ctx.parser;
	call_ng_flags_init(out, ctx->opmode);
	ctx->flags = out;

	// check for default templates, "default" first
	if (rtpe_default_signalling_templates[OP_OTHER].len)
		parse_rtpp_flags(&rtpe_default_signalling_templates[OP_OTHER], out);
	// and then one matching the current command
	if (ctx->opmode != OP_OTHER && rtpe_default_signalling_templates[ctx->opmode].len)
		parse_rtpp_flags(&rtpe_default_signalling_templates[ctx->opmode], out);

	parser->dict_iter(parser, ctx->req, call_ng_main_flags, out);
}

static void ng_sdp_attr_manipulations_free(struct sdp_manipulations * array[__MT_MAX]) {
	for (int i = 0; i < __MT_MAX; i++) {
		struct sdp_manipulations *sdp_manipulations = array[i];
		if (!sdp_manipulations)
			continue;

		str_case_ht_destroy_ptr(&sdp_manipulations->rem_commands);
		str_case_value_ht_destroy_ptr(&sdp_manipulations->subst_commands);
		t_queue_clear_full(&sdp_manipulations->add_commands, str_free);

		g_slice_free1(sizeof(*sdp_manipulations), sdp_manipulations);

		array[i] = NULL;
	}
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

	ng_sdp_attr_manipulations_free(flags->sdp_manipulations);
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


void save_last_sdp(struct call_monologue *ml, str *sdp, sdp_sessions_q *parsed, sdp_streams_q *streams) {
	sdp_streams_clear(&ml->last_in_sdp_streams);
	ml->last_in_sdp_streams = *streams;
	t_queue_init(streams);
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

static const char *call_offer_answer_ng(ng_command_ctx_t *ctx, const char* addr,
		const endpoint_t *sin)
{
	const char *errstr;
	str sdp = STR_NULL;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	g_autoptr(call_t) call = NULL;
	struct call_monologue * monologues[2];
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
	if (sdp_parse(&sdp, &parsed, &flags))
		goto out;

	if (flags.loop_protect && sdp_is_duplicate(&parsed)) {
		ilog(LOG_INFO, "Ignoring message as SDP has already been processed by us");
		parser->dict_add_str(output, "sdp", &flags.sdp);
		errstr = NULL;
		goto out;
	}

	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, &flags))
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

	updated_created_from(call, addr, sin);

	if (flags.xmlrpc_callback.family)
		call->xmlrpc_callback = flags.xmlrpc_callback;
	if (flags.dtmf_log_dest.address.family)
		call->dtmf_log_dest = flags.dtmf_log_dest;

	/* At least the random ICE strings are contained within the call struct, so we
	 * need to hold a ref until we're done sending the reply */
	call_ngb_hold_ref(call, ctx->ngbuf);

	errstr = "Invalid dialogue association";
	if (call_get_mono_dialogue(monologues, call, &flags.from_tag, &flags.to_tag,
			flags.via_branch.s ? &flags.via_branch : NULL, &flags)) {
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
		call_set_dtmf_block(call, monologues[0], &flags);

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
		if ((ret = sdp_create(&sdp_out, to_ml, &flags)) == 0) {
			/* TODO: should we save sdp_out? */
			save_last_sdp(from_ml, &sdp, &parsed, &streams);
		}

		/* place return output SDP */
		if (sdp_out.len) {
			ctx->ngbuf->sdp_out = sdp_out.s;
			ctx->parser_ctx.parser->dict_add_str(output, "sdp", &sdp_out);

			meta_write_sdp_after(recording, &sdp_out, from_ml, flags.opmode);

			sdp_out = STR_NULL; /* ownership passed to output */
		}
	}

	recording_response(recording, ctx->parser_ctx.parser, output);

	dequeue_sdp_fragments(from_ml);

	rwlock_unlock_w(&call->master_lock);

	if (!flags.no_redis_update) {
			redis_update_onekey(call, rtpe_redis_write);
	} else {
		ilog(LOG_DEBUG, "Not updating Redis due to present no-redis-update flag");
	}

	gettimeofday(&(from_ml->started), NULL);

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
		const char* addr,
		const endpoint_t *sin)
{
	return call_offer_answer_ng(ctx, addr, sin);
}

const char *call_answer_ng(ng_command_ctx_t *ctx) {
	return call_offer_answer_ng(ctx, NULL, NULL);
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

static void ng_stats_stream_ssrc(const ng_parser_t *parser, parser_arg dict,
		struct ssrc_ctx *const ssrcs[RTPE_NUM_SSRC_TRACKING],
		const char *label)
{
	parser_arg list = parser->dict_add_list(dict, label);

	for (int i = 0; i < RTPE_NUM_SSRC_TRACKING; i++) {
		struct ssrc_ctx *c = ssrcs[i];
		if (!c)
			break;

		parser_arg ssrc = parser->list_add_dict(list);

		parser->dict_add_int(ssrc, "SSRC", ssrcs[i]->parent->h.ssrc);
		parser->dict_add_int(ssrc, "bytes", atomic64_get_na(&c->stats->bytes));
		parser->dict_add_int(ssrc, "packets", atomic64_get_na(&c->stats->packets));
		parser->dict_add_int(ssrc, "last RTP timestamp", atomic_get_na(&c->stats->timestamp));
		parser->dict_add_int(ssrc, "last RTP seq", atomic_get_na(&c->stats->ext_seq));
	}
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

	if (ps->selected_sfd) {
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
	parser->dict_add_int(dict, "last packet", packet_stream_last_packet(ps));
	parser->dict_add_int(dict, "last kernel packet", atomic64_get_na(&ps->stats_in->last_packet));
	parser->dict_add_int(dict, "last user packet", atomic64_get_na(&ps->last_packet));

	flags = parser->dict_add_list(dict, "flags");

	BF_PS("RTP", RTP);
	BF_PS("RTCP", RTCP);
	BF_PS("fallback RTCP", FALLBACK_RTCP);
	BF_PS("filled", FILLED);
	BF_PS("confirmed", CONFIRMED);
	BF_PS("kernelized", KERNELIZED);
	BF_PS("no kernel support", NO_KERNEL_SUPPORT);
	BF_PS("DTLS fingerprint verified", FINGERPRINT_VERIFIED);
	BF_PS("strict source address", STRICT_SOURCE);
	BF_PS("media handover", MEDIA_HANDOVER);
	BF_PS("ICE", ICE);

	ng_stats_stream_ssrc(parser, dict, ps->ssrc_in, "ingress SSRCs");
	ng_stats_stream_ssrc(parser, dict, ps->ssrc_out, "egress SSRCs");

stats:
	if (totals->last_packet < packet_stream_last_packet(ps))
		totals->last_packet = packet_stream_last_packet(ps);

	/* XXX distinguish between input and output */
	s = &totals->totals[0];
	if (!PS_ISSET(ps, RTP))
		s = &totals->totals[1];
	ng_stats(ctx, dict, "stats", ps->stats_in, s);
	ng_stats(ctx, dict, "stats_out", ps->stats_out, NULL);
}

#define BF_M(k, f) if (MEDIA_ISSET(m, f)) parser->list_add_string(flags, k)

static void ng_stats_media(ng_command_ctx_t *ctx, parser_arg list, const struct call_media *m,
		struct call_stats *totals)
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
	parser->dict_add_int(sub, "created", ml->created);
	if (ml->metadata.s)
		parser->dict_add_str(sub, "metadata", &ml->metadata);

	parser_arg b_subscriptions = parser->dict_add_list(sub, "subscriptions");
	parser_arg b_subscribers = parser->dict_add_list(sub, "subscribers");
	for (int i = 0; i < ml->medias->len; i++)
	{
		struct call_media * media = ml->medias->pdata[i];
		if (!media)
			continue;

		for (__auto_type subscription = media->media_subscriptions.head;
				subscription;
				subscription = subscription->next)
		{
			struct media_subscription * ms = subscription->data;
			if (!g_queue_find(&mls_subscriptions, ms->monologue)) {
				parser_arg sub1 = parser->list_add_dict(b_subscriptions);
				parser->dict_add_str(sub1, "tag", &ms->monologue->tag);
				parser->dict_add_string(sub1, "type", ms->attrs.offer_answer ? "offer/answer" : "pub/sub");
				g_queue_push_tail(&mls_subscriptions, ms->monologue);
			}
		}
		for (__auto_type subscriber = media->media_subscribers.head;
				subscriber;
				subscriber = subscriber->next)
		{
			struct media_subscription * ms = subscriber->data;
			if (!g_queue_find(&mls_subscribers, ms->monologue)) {
				parser_arg sub1 = parser->list_add_dict(b_subscribers);
				parser->dict_add_str(sub1, "tag", &ms->monologue->tag);
				parser->dict_add_string(sub1, "type", ms->attrs.offer_answer ? "offer/answer" : "pub/sub");
				g_queue_push_tail(&mls_subscribers, ms->monologue);
			}
		}
	}

	ng_stats_ssrc(parser, ssrc, ml->ssrc_hash);

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
		ng_stats_media(ctx, medias, m, totals);
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
	parser->dict_add_int(subent, "reported at", sb->reported.tv_sec);
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

static void ng_stats_ssrc(const ng_parser_t *parser, parser_arg dict, struct ssrc_hash *ht) {
	GList *ll = g_hash_table_get_values(ht->ht);

	for (GList *l = ll; l; l = l->next) {
		struct ssrc_entry_call *se = l->data;
		char tmp[12];
		snprintf(tmp, sizeof(tmp), "%" PRIu32, se->h.ssrc);
		if (parser->dict_contains(dict, tmp))
			continue;
		if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
			continue;

		parser_arg ent = parser->dict_add_dict_dup(dict, tmp);

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
		int interval
			= ((struct ssrc_stats_block *) se->stats_blocks.tail->data)->reported.tv_sec
			- sb->reported.tv_sec;
		interval /= 10;
		parser->dict_add_int(progdict, "interval", interval);
		time_t next_step = sb->reported.tv_sec;
		parser_arg entlist = parser->dict_add_list(progdict, "entries");

		for (; listent; listent = listent->next) {
			sb = listent->data;
			if (sb->reported.tv_sec < next_step)
				continue;
			next_step += interval;
			parser_arg cent = parser->list_add_dict(entlist);
			ng_stats_ssrc_mos_entry(parser, cent, sb);
		}
	}

	g_list_free(ll);
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

	parser->dict_add_int(ctx->resp, "created", call->created.tv_sec);
	parser->dict_add_int(ctx->resp, "created_us", call->created.tv_usec);
	parser->dict_add_int(ctx->resp, "last signal", call->last_signal);
	parser->dict_add_int(ctx->resp, "last redis update", atomic64_get_na(&call->last_redis_update));
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

				for (__auto_type subscription = media->media_subscriptions.head;
						subscription;
						subscription = subscription->next)
				{
					struct media_subscription * ms = subscription->data;
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
	rtpe_calls_ht_iter iter;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	rwlock_lock_r(&rtpe_callhash_lock);

	t_hash_table_iter_init (&iter, rtpe_callhash);
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


static const char *media_block_match1(call_t *call, struct call_monologue **monologue,
		sdp_ng_flags *flags)
{
	if (flags->label.s) {
		*monologue = t_hash_table_lookup(call->labels, &flags->label);
		if (!*monologue)
			return "No monologue matching the given label";
	}
	else if (flags->address.s) {
		sockaddr_t addr;
		if (sockaddr_parse_any_str(&addr, &flags->address))
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

	const char *err = media_block_match1(*call, monologue, flags);
	if (err)
		return err;

	// for generic ops, handle set-label here if given
	if (IS_OP_OTHER(flags->opmode) && flags->set_label.len && *monologue) {
		(*monologue)->label = call_str_cpy(&flags->set_label);
		t_hash_table_replace((*call)->labels, &(*monologue)->label, *monologue);
	}

	return NULL;
}
void add_media_to_sub_list(subscription_q *q, struct call_media *media, struct call_monologue *ml) {
	struct media_subscription *ms = g_slice_alloc0(sizeof(*ms));
	ms->media = media;
	ms->monologue = ml;
	t_queue_push_tail(q, ms);
}
static const char *media_block_match_mult(call_t **call, subscription_q *medias,
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
			add_media_to_sub_list(medias, media, media->monologue);
		}
		return NULL;
	}

	/* is a single ml given? */
	struct call_monologue *ml = NULL;
	const char *err = media_block_match1(*call, &ml, flags);
	if (err)
		return err;
	if (ml) {
		for (int i = 0; i < ml->medias->len; i++)
		{
			struct call_media * media = ml->medias->pdata[i];
			if (!media)
				continue;
			add_media_to_sub_list(medias, media, ml);
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
				struct call_media * media = mlf->medias->pdata[i];
				if (!media)
					continue;
				add_media_to_sub_list(medias, media, mlf);
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
					subscription_list * ll = t_hash_table_lookup(ml_media->media_subscriptions_ht, sink_md);
					if (ll) {
						found_subscriptions = true;
						G_STRUCT_MEMBER(bool, &ll->data->attrs, attr_offset) = on_off;
						ilog(LOG_INFO, "%s directional media flow: "
								"monologue tag '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' / "
								"media index '%d' -> '%d'",
								ucase_verb,
								STR_FMT_M(&monologue->tag), STR_FMT_M(&ll->data->monologue->tag),
								ml_media->index, ll->data->media->index);
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

				for (__auto_type sub = ml_media->media_subscribers.head; sub; sub = sub->next)
				{
					struct media_subscription * ms = sub->data;
					struct call_media * sub_md = ms->media;

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
			update_init_subscribers(monologue, OP_BLOCK_SILENCE_MEDIA);

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

			for (__auto_type ll = ml_media->media_subscribers.head; ll; ll = ll->next)
			{
				struct media_subscription * ms = ll->data;
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


const char *call_publish_ng(ng_command_ctx_t *ctx,
		const char *addr,
		const endpoint_t *sin)
{
	g_auto(sdp_ng_flags) flags;
	g_auto(sdp_sessions_q) parsed = TYPED_GQUEUE_INIT;
	g_auto(sdp_streams_q) streams = TYPED_GQUEUE_INIT;
	str sdp_in = STR_NULL;
	g_auto(str) sdp_out = STR_NULL;
	g_autoptr(call_t) call = NULL;
	int ret;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	call_ng_process_flags(&flags, ctx);

	if ((ret = call_ng_basic_checks(&flags)) > 0)
		return _ng_basic_errors[ret];

	call = call_get_or_create(&flags.call_id, false);

	sdp_in = call_str_cpy(&flags.sdp);

	if (sdp_parse(&sdp_in, &parsed, &flags))
		return "Failed to parse SDP";

	if (sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	if (trickle_ice_update(ctx->ngbuf, call, &flags, &streams))
		return NULL;

	updated_created_from(call, addr, sin);
	struct call_monologue *ml = call_get_or_create_monologue(call, &flags.from_tag);

	ret = monologue_publish(ml, &streams, &flags);
	if (ret)
		ilog(LOG_ERR, "Publish error"); // XXX close call? handle errors?

	ret = sdp_create(&sdp_out, ml, &flags);
	if (!ret) {
		save_last_sdp(ml, &sdp_in, &parsed, &streams);
		ctx->ngbuf->sdp_out = sdp_out.s;
		parser->dict_add_str(ctx->resp, "sdp", &sdp_out);
		sdp_out = STR_NULL; // ownership passed to output
	}

	if (ret)
		return "Failed to create SDP";

	dequeue_sdp_fragments(ml);

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_subscribe_request_ng(ng_command_ctx_t *ctx) {
	const char *err = NULL;
	g_auto(sdp_ng_flags) flags;
	char rand_buf[65];
	g_autoptr(call_t) call = NULL;
	g_auto(subscription_q) srms = TYPED_GQUEUE_INIT;
	g_auto(str) sdp_out = STR_NULL;
	parser_arg output = ctx->resp;
	const ng_parser_t *parser = ctx->parser_ctx.parser;

	/* get source monologue */
	err = media_block_match_mult(&call, &srms, &flags, ctx);
	if (err)
		return err;

	if (flags.sdp.len)
		ilog(LOG_INFO, "Subscribe-request with SDP received - ignoring SDP");

	if (!srms.length)
		return "No call participants specified (no medias found)";

	/* the `label=` option was possibly used above to select the from-tag --
	 * switch it out with `to-label=` or `set-label=` for monologue_subscribe_request
	 * below which sets the label based on `label` for a newly created monologue */
	flags.label = flags.to_label;
	if (flags.set_label.len) // set-label takes priority
		flags.label = flags.set_label;

	/* get destination monologue */
	if (!flags.to_tag.len) {
		/* generate one */
		flags.to_tag = STR_CONST(rand_buf);
		rand_hex_str(flags.to_tag.s, flags.to_tag.len / 2);
	}

	struct call_monologue *dest_ml = call_get_or_create_monologue(call, &flags.to_tag);

	int ret = monologue_subscribe_request(&srms, dest_ml, &flags);
	if (ret)
		return "Failed to request subscription";

	/* create new SDP */
	ret = sdp_create(&sdp_out, dest_ml, &flags);
	if (ret)
		return "Failed to create SDP";

	/* place return output SDP */
	if (sdp_out.len) {
		ctx->ngbuf->sdp_out = sdp_out.s;
		parser->dict_add_str(output, "sdp", &sdp_out);
		sdp_out = STR_NULL; /* ownership passed to output */
	}

	/* add single response ml tag if there's just one, but always add a list
	 * TODO: deprecate it, since initially added for monologue subscriptions.
	 */
	if (srms.length == 1) {
		struct media_subscription *ms = srms.head->data;
		struct call_monologue *source_ml = ms->monologue;
		parser->dict_add_str_dup(output, "from-tag", &source_ml->tag);
	}
	parser_arg tag_medias = {0}, media_labels = {0};
	if (flags.siprec) {
		tag_medias = parser->dict_add_list(output, "tag-medias");
		media_labels = parser->dict_add_dict(output, "media-labels");
	}
	parser_arg from_list = parser->dict_add_list(output, "from-tags");
	for (__auto_type l = srms.head; l; l = l->next) {
		struct media_subscription *ms = l->data;
		struct call_monologue *source_ml = ms->monologue;
		parser->list_add_str_dup(from_list, &source_ml->tag);
		if (tag_medias.gen) {
			parser_arg tag_label = parser->list_add_dict(tag_medias);
			parser->dict_add_str(tag_label, "tag", &source_ml->tag);
			if (source_ml->label.len)
				parser->dict_add_str(tag_label, "label", &source_ml->label);
			parser_arg medias = parser->dict_add_list(tag_label, "medias");
			for (unsigned int i = 0; i < source_ml->medias->len; i++) {
				struct call_media *media = source_ml->medias->pdata[i];
				if (!media)
					continue;
				parser_arg med_ent = parser->list_add_dict(medias);
				parser->dict_add_int(med_ent, "index", media->index);
				parser->dict_add_str(med_ent, "type", &media->type);
				parser->dict_add_str(med_ent, "label", &media->label);
				parser->dict_add_string(med_ent, "mode", sdp_get_sendrecv(media));

				if (media_labels.gen) {
					parser_arg label =
						parser->dict_add_dict(media_labels, media->label.s);
					parser->dict_add_str(label, "tag", &source_ml->tag);
					parser->dict_add_int(label, "index", media->index);
					parser->dict_add_str(label, "type", &media->type);
					if (source_ml->label.len)
						parser->dict_add_str(label, "label", &source_ml->label);
					parser->dict_add_string(label, "mode", sdp_get_sendrecv(media));
				}
			}
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

	if (sdp_parse(&flags.sdp, &parsed, &flags))
		return "Failed to parse SDP";

	if (sdp_streams(&parsed, &streams, &flags))
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
	struct call_monologue *dest_ml = call_get_or_create_monologue(call, &flags.to_tag);
	if (!dest_ml)
		return "To-tag not found";

	int ret = monologue_unsubscribe(dest_ml, &flags);
	if (ret)
		return "Failed to unsubscribe";

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_connect_ng(ng_command_ctx_t *ctx) {
	g_auto(sdp_ng_flags) flags;
	g_autoptr(call_t) call = NULL;
	g_autoptr(call_t) call2 = NULL;

	call_ng_process_flags(&flags, ctx);

	if (!flags.call_id.s)
		return "No call-id in message";
	if (!flags.from_tag.s)
		return "No from-tag in message";
	if (!flags.to_tag.s)
		return "No to-tag in message";

	if (flags.to_call_id.s) {
		call_get2_ret_t ret = call_get2(&call, &call2, &flags.call_id, &flags.to_call_id);
		if (ret == CG2_NF1)
			return "Unknown call-ID";
		if (ret == CG2_NF2)
			return "Unknown to-tag call-ID";
	}
	else {
		call = call_get(&flags.call_id);
		if (!call)
			return "Unknown call-ID";
	}

	struct call_monologue *src_ml = call_get_or_create_monologue(call, &flags.from_tag);
	if (!src_ml)
		return "From-tag not found";

	struct call_monologue *dest_ml = call_get_or_create_monologue(call2 ?: call, &flags.to_tag);
	if (!dest_ml)
		return "To-tag not found";

	if (src_ml == dest_ml)
		return "Trying to connect to self"; // XXX should this be allowed?

	if (call2) {
		if (!call_merge(call, &call2))
			return "Failed to merge two calls into one";
	}

	dialogue_connect(src_ml, dest_ml, &flags);

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

static void parse_templates(GHashTable *templates) {
	if (!templates)
		return;

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, templates);
	void *keyp, *valuep;
	while (g_hash_table_iter_next(&iter, &keyp, &valuep)) {
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

int call_interfaces_init(GHashTable *templates) {
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
