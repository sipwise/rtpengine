#include "call_interfaces.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <pcre.h>
#include <inttypes.h>

#include "call_interfaces.h"
#include "call.h"
#include "helpers.h"
#include "log.h"
#include "redis.h"
#include "sdp.h"
#include "bencode.h"
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


static pcre *info_re;
static pcre_extra *info_ree;
static pcre *streams_re;
static pcre_extra *streams_ree;

int trust_address_def;
int dtls_passive_def;


INLINE int call_ng_flags_prefix(struct sdp_ng_flags *out, str *s_ori, const char *prefix,
		void (*cb)(struct sdp_ng_flags *, str *, void *), void *ptr);
static void call_ng_flags_str_ht(struct sdp_ng_flags *out, str *s, void *htp);
static void call_ng_flags_str_q_multi(struct sdp_ng_flags *out, str *s, void *qp);
static void ng_stats_ssrc(bencode_item_t *dict, struct ssrc_hash *ht);
static str *str_dup_escape(const str *s);

static int call_stream_address_gstring(GString *o, struct packet_stream *ps, enum stream_address_format format) {
	int len, ret;
	char buf[64]; /* 64 bytes ought to be enough for anybody */

	ret = call_stream_address46(buf, ps, format, &len, NULL, true);
	g_string_append_len(o, buf, len);
	return ret;
}

static str *streams_print(GPtrArray *s, int start, int end, const char *prefix, enum stream_address_format format) {
	GString *o;
	int i, af, port;
	struct call_media *media;
	struct packet_stream *ps;

	o = g_string_new_str();
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
			call_stream_address_gstring(o, ps, format);

		port = ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0;
		g_string_append_printf(o, (format == 1) ? "%i " : " %i", port);

		if (format == SAF_UDP) {
			af = call_stream_address_gstring(o, ps, format);
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
				str_init(&sp->direction[i++], "external");
			else if (c == 'I')
				str_init(&sp->direction[i++], "internal");
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

static void updated_created_from(struct call *c, const char *addr, const endpoint_t *sin) {
	if (!c->created_from && addr) {
		c->created_from = call_strdup(c, addr);
		if (sin)
			c->created_from_addr = sin->address;
	}
}

static str *call_update_lookup_udp(char **out, enum call_opmode opmode, const char* addr,
		const endpoint_t *sin)
{
	struct call *c;
	struct call_subscription *dialogue[2];
	GQueue q = G_QUEUE_INIT;
	struct stream_params sp;
	str *ret, callid, viabranch, fromtag, totag = STR_NULL;
	int i;

	str_init(&callid, out[RE_UDP_UL_CALLID]);
	str_init(&viabranch, out[RE_UDP_UL_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_UL_FROMTAG]);
	str_init(&totag, out[RE_UDP_UL_TOTAG]);
	if (opmode == OP_ANSWER)
		str_swap(&fromtag, &totag);

	c = call_get_opmode(&callid, opmode);
	if (!c) {
		ilog(LOG_WARNING, "[" STR_FORMAT_M "] Got UDP LOOKUP for unknown call-id",
			STR_FMT_M(&callid));
		return str_sprintf("%s 0 0.0.0.0\n", out[RE_UDP_COOKIE]);
	}

	updated_created_from(c, addr, sin);

	if (call_get_mono_dialogue(dialogue, c, &fromtag, &totag, NULL))
		goto ml_fail;

	struct call_monologue *from_ml = dialogue[0]->monologue;
	struct call_monologue *to_ml = dialogue[1]->monologue;

	if (opmode == OP_OFFER) {
		from_ml->tagtype = FROM_TAG;
	} else {
		from_ml->tagtype = TO_TAG;
	}

	if (addr_parse_udp(&sp, out))
		goto addr_fail;

	g_queue_push_tail(&q, &sp);
	i = monologue_offer_answer(dialogue, &q, NULL);
	g_queue_clear(&q);

	if (i)
		goto unlock_fail;

	ret = streams_print(to_ml->medias,
			sp.index, sp.index, out[RE_UDP_COOKIE], SAF_UDP);
	rwlock_unlock_w(&c->master_lock);

	redis_update_onekey(c, rtpe_redis_write);

	gettimeofday(&(from_ml->started), NULL);

	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT(ret));
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

str *call_update_udp(char **out, const char* addr, const endpoint_t *sin) {
	return call_update_lookup_udp(out, OP_OFFER, addr, sin);
}
str *call_lookup_udp(char **out) {
	return call_update_lookup_udp(out, OP_ANSWER, NULL, NULL);
}


static int info_parse_func(char **a, void **ret, void *p) {
	GHashTable *ih = p;

	g_hash_table_replace(ih, strdup(a[0]), strdup(a[1]));

	return -1;
}

static void info_parse(const char *s, GHashTable *ih) {
	pcre_multi_match(info_re, info_ree, s, 2, info_parse_func, ih, NULL);
}


static int streams_parse_func(char **a, void **ret, void *p) {
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
	return 0;

fail:
	ilog(LOG_WARNING, "Failed to parse a media stream: %s%s:%s%s", FMT_M(a[0], a[1]));
	g_slice_free1(sizeof(*sp), sp);
	return -1;
}


static void streams_parse(const char *s, GQueue *q) {
	int i;
	i = 0;
	pcre_multi_match(streams_re, streams_ree, s, 3, streams_parse_func, &i, q);
}
void call_unlock_release(struct call **c) {
	if (!*c)
		return;
	rwlock_unlock_w(&(*c)->master_lock);
	obj_put(*c);
}
INLINE void call_unlock_release_update(struct call **c) {
	if (!*c)
		return;
	rwlock_unlock_w(&(*c)->master_lock);
	redis_update_onekey(*c, rtpe_redis_write);
	obj_put(*c);
	*c = NULL;
}



static str *call_request_lookup_tcp(char **out, enum call_opmode opmode) {
	struct call *c;
	struct call_subscription *dialogue[2];
	AUTO_CLEANUP(GQueue s, sdp_streams_free) = G_QUEUE_INIT;
	str *ret = NULL, callid, fromtag, totag = STR_NULL;
	GHashTable *infohash;

	str_init(&callid, out[RE_TCP_RL_CALLID]);
	infohash = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	c = call_get_opmode(&callid, opmode);
	if (!c) {
		ilog(LOG_WARNING, "[" STR_FORMAT_M "] Got LOOKUP for unknown call-id", STR_FMT_M(&callid));
		goto out;
	}

	info_parse(out[RE_TCP_RL_INFO], infohash);
	streams_parse(out[RE_TCP_RL_STREAMS], &s);
	str_init(&fromtag, g_hash_table_lookup(infohash, "fromtag"));
	if (!fromtag.s) {
		ilog(LOG_WARNING, "No from-tag in message");
		goto out2;
	}
	str_init(&totag, g_hash_table_lookup(infohash, "totag"));
	if (opmode == OP_ANSWER) {
		if (!totag.s) {
			ilog(LOG_WARNING, "No to-tag in message");
			goto out2;
		}
		str_swap(&fromtag, &totag);
	}

	if (call_get_mono_dialogue(dialogue, c, &fromtag, &totag, NULL)) {
		ilog(LOG_WARNING, "Invalid dialogue association");
		goto out2;
	}
	if (monologue_offer_answer(dialogue, &s, NULL))
		goto out2;

	ret = streams_print(dialogue[1]->monologue->medias, 1, s.length, NULL, SAF_TCP);

out2:
	call_unlock_release_update(&c);
	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT0(ret));

out:
	g_hash_table_destroy(infohash);
	return ret;
}

str *call_request_tcp(char **out) {
	return call_request_lookup_tcp(out, OP_OFFER);
}
str *call_lookup_tcp(char **out) {
	return call_request_lookup_tcp(out, OP_ANSWER);
}

str *call_delete_udp(char **out) {
	str callid, branch, fromtag, totag;

	__C_DBG("got delete for callid '%s' and viabranch '%s'",
		out[RE_UDP_DQ_CALLID], out[RE_UDP_DQ_VIABRANCH]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&branch, out[RE_UDP_DQ_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	if (call_delete_branch_by_id(&callid, &branch, &fromtag, &totag, NULL, -1))
		return str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);

	return str_sprintf("%s 0\n", out[RE_UDP_COOKIE]);
}
str *call_query_udp(char **out) {
	AUTO_CLEANUP_NULL(struct call *c, call_unlock_release);
	str *ret, callid, fromtag, totag;
	struct call_stats stats;

	__C_DBG("got query for callid '%s'", out[RE_UDP_DQ_CALLID]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	c = call_get_opmode(&callid, OP_OTHER);
	if (!c) {
		ilog(LOG_INFO, "[" STR_FORMAT_M "] Call-ID to query not found", STR_FMT_M(&callid));
		goto err;
	}

	ng_call_stats(c, &fromtag, &totag, NULL, &stats);

	rwlock_unlock_w(&c->master_lock);

	rwlock_lock_r(&rtpe_config.config_lock);
	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) rtpe_config.silent_timeout - (rtpe_now.tv_sec - stats.last_packet),
		atomic64_get_na(&stats.totals[0].packets), atomic64_get_na(&stats.totals[1].packets),
		atomic64_get_na(&stats.totals[2].packets), atomic64_get_na(&stats.totals[3].packets));
	rwlock_unlock_r(&rtpe_config.config_lock);
	goto out;

err:
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	return ret;
}

void call_delete_tcp(char **out) {
	str callid;

	str_init(&callid, out[RE_TCP_D_CALLID]);
	call_delete_branch_by_id(&callid, NULL, NULL, NULL, NULL, -1);
}

static void call_status_iterator(struct call *c, struct streambuf_stream *s) {
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
		g_hash_table_size(rtpe_callhash),
		atomic64_get(&rtpe_stats_rate.bytes_user) + atomic64_get(&rtpe_stats_rate.bytes_kernel), 0, 0);
	rwlock_unlock_r(&rtpe_callhash_lock);

	ITERATE_CALL_LIST_START(CALL_ITERATOR_MAIN, c);
		call_status_iterator(c, s);
	ITERATE_CALL_LIST_NEXT_END(c);
}








static void call_release_ref(void *p) {
	struct call *c = p;
	obj_put(c);
}
INLINE void call_bencode_hold_ref(struct call *c, bencode_item_t *bi) {
	/* We cannot guarantee that the "call" structures are still around at the time
	 * when the bencode reply is finally read and sent out. Since we use scatter/gather
	 * to avoid duplication of strings and stuff, we reserve a reference to the call
	 * structs and have it released when the bencode buffer is destroyed. This is
	 * necessary every time the bencode response may reference strings contained
	 * within the call structs. */
	bencode_buffer_destroy_add(bi->buffer, call_release_ref, obj_get(c));
}

INLINE void str_hyphenate(str *s_ori) {
	str s;
	s = *s_ori;
	while (s.len) {
		if (!str_chr_str(&s, &s, ' '))
			break;
		*s.s = '-';
		str_shift(&s, 1);
	}
}
INLINE char *bencode_get_alt(bencode_item_t *i, const char *one, const char *two, str *out) {
	char *o;
	if ((o = bencode_dictionary_get_str(i, one, out)))
		return o;
	return bencode_dictionary_get_str(i, two, out);
}

INLINE void ng_sdes_option(struct sdp_ng_flags *out, str *s, void *dummy) {
	str_hyphenate(s);

	/* Accept only certain individual crypto suites */
	if (call_ng_flags_prefix(out, s, "only-", call_ng_flags_str_ht, &out->sdes_only))
		return;

	/* Exclude individual crypto suites */
	if (call_ng_flags_prefix(out, s, "no-", call_ng_flags_str_ht, &out->sdes_no))
		return;

	/* Order individual crypto suites */
	if (call_ng_flags_prefix(out, s, "order:", call_ng_flags_str_q_multi, &out->sdes_order))
		return;

	/* Crypto suite preferences for the offerer */
	if (call_ng_flags_prefix(out, s, "offerer_pref:", call_ng_flags_str_q_multi,
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
		default:
			ilog(LOG_WARN, "Unknown 'SDES' flag encountered: '"STR_FORMAT"'",
					STR_FMT(s));
	}
}

INLINE void ng_osrtp_option(struct sdp_ng_flags *out, str *s, void *dummy) {
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

INLINE void ng_sdp_attr_manipulations(struct sdp_manipulations_common ** sm_ptr, bencode_item_t *value) {

	if (!value || value->type != BENCODE_DICTIONARY) {
		ilog(LOG_WARN, "SDP manipulations: Wrong type for this type of command.");
		return;
	}

	/* check if it's not allocated already for this monologue */
	if (!*sm_ptr)
		*sm_ptr = g_slice_alloc0(sizeof(**sm_ptr));

	for (bencode_item_t *it = value->child; it; it = it->sibling)
	{
		bencode_item_t *command_action = it->sibling ? it->sibling : NULL;
		enum media_type media;
		str media_type;
		GQueue * q_ptr = NULL;
		GHashTable ** ht = NULL;

		if (!command_action) /* if no action, makes no sense to continue */
			continue;

		/* detect media type */
		if (!bencode_get_str(it, &media_type))
			continue;

		media = (!str_cmp(&media_type, "none") || !str_cmp(&media_type, "global")) ?
				MT_UNKNOWN : codec_get_type(&media_type);

		for (bencode_item_t *it_c = command_action->child; it_c; it_c = it_c->sibling)
		{
			bencode_item_t *command_value = it_c->sibling ? it_c->sibling : NULL;

			if (!command_value) /* if no value, makes no sense to check further */
				continue;

			/* detect command type */
			str command_type;
			if (!bencode_get_str(it_c, &command_type))
				continue;

			switch (__csh_lookup(&command_type)) {

				/* CMD_ADD / CMD_SUBST commands */
				case CSH_LOOKUP("substitute"):;

					switch (media) {
						case MT_UNKNOWN:
							ht = &(*sm_ptr)->subst_commands_glob;
							break;
						case MT_AUDIO:
							ht = &(*sm_ptr)->subst_commands_audio;
							break;
						case MT_VIDEO:
							ht = &(*sm_ptr)->subst_commands_video;
							break;
						default:
							ilog(LOG_WARN, "SDP manipulations: unsupported SDP section targeted.");
							continue;
					}

					/* a table can already be allocated by similar commands in previous iterations */
					if (!*ht)
						*ht = g_hash_table_new_full(str_case_hash, str_case_equal, free, free);

					for (bencode_item_t *it_v = command_value->child; it_v; it_v = it_v->sibling)
					{
						str from;
						str to;

						if (!bencode_get_str(it_v->child, &from))
							continue;
						if (!bencode_get_str(it_v->child->sibling, &to))
							continue;

						str * s_copy_from = str_dup_escape(&from);
						str * s_copy_to = str_dup_escape(&to);

						if (!s_copy_from->len || !s_copy_to->len) {
							free(s_copy_from);
							free(s_copy_to);
							continue;
						}

						g_hash_table_replace(*ht, s_copy_from, s_copy_to);
					}
					break;

				case CSH_LOOKUP("add"):;
					switch (media) {
						case MT_UNKNOWN:
							q_ptr = &(*sm_ptr)->add_commands_glob;
							break;
						case MT_AUDIO:
							q_ptr = &(*sm_ptr)->add_commands_audio;
							break;
						case MT_VIDEO:
							q_ptr = &(*sm_ptr)->add_commands_video;
							break;
						default:
							ilog(LOG_WARN, "SDP manipulations: unsupported SDP section targeted.");
							continue;
					}

					for (bencode_item_t *it_v = command_value->child; it_v; it_v = it_v->sibling)
					{
						/* detect command value */
						str child_value;
						if (!bencode_get_str(it_v, &child_value))
							continue;

						str * s_copy = str_dup_escape(&child_value);
						g_queue_push_tail(q_ptr, s_copy);
					}
					break;

				/* CMD_REM commands */
				case CSH_LOOKUP("remove"):;
					switch (media) {
						case MT_UNKNOWN:
							ht = &(*sm_ptr)->rem_commands_glob;
							break;
						case MT_AUDIO:
							ht = &(*sm_ptr)->rem_commands_audio;
							break;
						case MT_VIDEO:
							ht = &(*sm_ptr)->rem_commands_video;
							break;
						default:
							ilog(LOG_WARN, "SDP manipulations: unsupported SDP section targeted.");
							continue;
					}

					/* a table can already be allocated by similar commands in previous iterations */
					if (!*ht)
						*ht = g_hash_table_new_full(str_case_hash, str_case_equal, free, NULL);

					for (bencode_item_t *it_v = command_value->child; it_v; it_v = it_v->sibling)
					{
						/* detect command value */
						str child_value;
						if (!bencode_get_str(it_v, &child_value))
							continue;

						str *s_copy = str_dup_escape(&child_value);
						g_hash_table_replace(*ht, s_copy, s_copy);
					}
					break;

				default:
					ilog(LOG_WARN, "SDP manipulations: Unknown SDP manipulation command type.");
					continue;
			}
		}
	}
}

INLINE void ng_el_option(struct sdp_ng_flags *out, str *s, void *dummy) {
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
INLINE void ng_t38_option(struct sdp_ng_flags *out, str *s, void *dummy) {
	str_hyphenate(s);
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
			out->t38_no_ecm = 1;
			break;
		case CSH_LOOKUP("no-V17"):
		case CSH_LOOKUP("no-V.17"):
		case CSH_LOOKUP("no-v17"):
		case CSH_LOOKUP("no-v.17"):
			out->t38_no_v17 = 1;
			break;
		case CSH_LOOKUP("no-V.27ter"):
		case CSH_LOOKUP("no-V27ter"):
		case CSH_LOOKUP("no-v.27ter"):
		case CSH_LOOKUP("no-v27ter"):
			out->t38_no_v27ter = 1;
			break;
		case CSH_LOOKUP("no-V29"):
		case CSH_LOOKUP("no-V.29"):
		case CSH_LOOKUP("no-v29"):
		case CSH_LOOKUP("no-v.29"):
			out->t38_no_v29 = 1;
			break;
		case CSH_LOOKUP("no-V34"):
		case CSH_LOOKUP("no-V.34"):
		case CSH_LOOKUP("no-v34"):
		case CSH_LOOKUP("no-v.34"):
			out->t38_no_v34 = 1;
			break;
		case CSH_LOOKUP("no-IAF"):
		case CSH_LOOKUP("no-iaf"):
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


static void call_ng_flags_list(struct sdp_ng_flags *out, bencode_item_t *list,
		void (*callback)(struct sdp_ng_flags *, str *, void *), void *parm)
{
	str s;
	if (list->type != BENCODE_LIST) {
		if (bencode_get_str(list, &s)) {
			str token;
			while (str_token_sep(&token, &s, ',') == 0)
				callback(out, &token, parm);
		}
		else
			ilog(LOG_DEBUG, "Ignoring non-list non-string value");
		return;
	}
	for (bencode_item_t *it = list->child; it; it = it->sibling) {
		if (bencode_get_str(it, &s))
			callback(out, &s, parm);
		else
			ilog(LOG_DEBUG, "Ignoring non-string value in list");
	}
}
static void call_ng_flags_rtcp_mux(struct sdp_ng_flags *out, str *s, void *dummy) {
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("offer"):
			out->rtcp_mux_offer = 1;
			break;
		case CSH_LOOKUP("require"):
			out->rtcp_mux_require = 1;
			break;
		case CSH_LOOKUP("demux"):
			out->rtcp_mux_demux = 1;
			break;
		case CSH_LOOKUP("accept"):
			out->rtcp_mux_accept = 1;
			break;
		case CSH_LOOKUP("reject"):
			out->rtcp_mux_reject = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'rtcp-mux' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
static void call_ng_flags_replace(struct sdp_ng_flags *out, str *s, void *dummy) {
	str_hyphenate(s);
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("origin"):
			out->replace_origin = 1;
			break;
		case CSH_LOOKUP("session-connection"):
			out->replace_sess_conn = 1;
			break;
		case CSH_LOOKUP("session-name"):
			out->replace_sess_name = 1;
			break;
		case CSH_LOOKUP("force-increment-sdp-ver"):
			out->force_inc_sdp_ver = 1;
			out->replace_sdp_version = 1;
			break;
		case CSH_LOOKUP("sdp-version"):
		case CSH_LOOKUP("SDP-version"):
			out->replace_sdp_version = 1;
			break;
		case CSH_LOOKUP("username"):
			out->replace_username = 1;
			break;
		case CSH_LOOKUP("zero-address"):
			out->replace_zero_address = 1;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'replace' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
static void call_ng_flags_supports(struct sdp_ng_flags *out, str *s, void *dummy) {
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
	return ret;
}
static void call_ng_flags_esc_str_list(struct sdp_ng_flags *out, str *s, void *qp) {
	str *s_copy = str_dup_escape(s);
	g_queue_push_tail((GQueue *) qp, s_copy);
}
/**
 * Stores flag's value in the given GhashTable.
 */
static void call_ng_flags_str_ht(struct sdp_ng_flags *out, str *s, void *htp) {
	str *s_copy = str_dup_escape(s);
	GHashTable **ht = htp;
	if (!*ht)
		*ht = g_hash_table_new_full(str_case_hash, str_case_equal, free, NULL);
	g_hash_table_replace(*ht, s_copy, s_copy);
}
/**
 * Parses one-row flags separated by 'delimiter'.
 * Stores parsed flag's values then in the given GQueue.
 */
static void call_ng_flags_str_q_multi(struct sdp_ng_flags *out, str *s, void *qp) {
	str *s_copy = str_dup_escape(s);
	str token;
	GQueue *q = qp;

	if (s_copy->len == 0)
		ilog(LOG_DEBUG, "Hm, nothing to parse.");

	while (str_token_sep(&token, s_copy, ';') == 0)
	{
		str * ret = str_dup(&token);
		g_queue_push_tail(q, ret);
	}

	free(s_copy);
}
#ifdef WITH_TRANSCODING
static void call_ng_flags_str_ht_split(struct sdp_ng_flags *out, str *s, void *htp) {
	GHashTable **ht = htp;
	if (!*ht)
		*ht = g_hash_table_new_full(str_case_hash, str_case_equal, free, free);
	str splitter = *s;
	while (1) {
		g_hash_table_replace(*ht, str_dup_escape(&splitter), str_dup_escape(s));
		char *c = memrchr(splitter.s, '/', splitter.len);
		if (!c)
			break;
		splitter.len = c - splitter.s;
	}
}
#endif
// helper to alias values from other dictionaries into the "flags" dictionary
INLINE int call_ng_flags_prefix(struct sdp_ng_flags *out, str *s_ori, const char *prefix,
		void (*cb)(struct sdp_ng_flags *, str *, void *), void *ptr)
{
	size_t len = strlen(prefix);
	str s = *s_ori;
	if (len > 0)
		if (str_shift_cmp(&s, prefix))
			return 0;
	cb(out, &s, ptr);
	return 1;
}
static void call_ng_flags_flags(struct sdp_ng_flags *out, str *s, void *dummy) {
	str_hyphenate(s);

	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("trust-address"):
			out->trust_address = 1;
			break;
		case CSH_LOOKUP("SIP-source-address"):
		case CSH_LOOKUP("sip-source-address"):
			out->trust_address = 0;
			break;
		case CSH_LOOKUP("asymmetric"):
			out->asymmetric = 1;
			break;
		case CSH_LOOKUP("no-redis-update"):
			out->no_redis_update = 1;
			break;
		case CSH_LOOKUP("unidirectional"):
			out->unidirectional = 1;
			break;
		case CSH_LOOKUP("strict-source"):
			out->strict_source = 1;
			break;
		case CSH_LOOKUP("media-handover"):
			out->media_handover = 1;
			break;
		case CSH_LOOKUP("reset"):
			out->reset = 1;
			break;
		case CSH_LOOKUP("early-media"):
			out->early_media = 1;
			break;
		case CSH_LOOKUP("all"):
			out->all = ALL_ALL;
			break;
		case CSH_LOOKUP("egress"):
			out->egress = 1;
			break;
		case CSH_LOOKUP("SIPREC"):
		case CSH_LOOKUP("siprec"):
			out->siprec = 1;
			break;
		case CSH_LOOKUP("fragment"):
			out->fragment = 1;
			break;
		case CSH_LOOKUP("port-latching"):
			out->port_latching = 1;
			break;
		case CSH_LOOKUP("no-port-latching"):
			out->no_port_latching = 1;
			break;
		case CSH_LOOKUP("generate-mid"):
			out->generate_mid = 1;
			break;
		case CSH_LOOKUP("strip-extmap"):
			out->strip_extmap = 1;
			break;
		case CSH_LOOKUP("record-call"):
			out->record_call = 1;
			break;
		case CSH_LOOKUP("discard-recording"):
			out->discard_recording = 1;
			break;
		case CSH_LOOKUP("exclude-recording"):
			out->exclude_recording = 1;
			break;
		case CSH_LOOKUP("inactive"):
			out->inactive = 1;
			break;
		case CSH_LOOKUP("debug"):
		case CSH_LOOKUP("debugging"):
			out->debug = 1;
			break;
		case CSH_LOOKUP("no-rtcp-attribute"):
		case CSH_LOOKUP("no-RTCP-attribute"):
			out->no_rtcp_attr = 1;
			break;
		case CSH_LOOKUP("full-rtcp-attribute"):
		case CSH_LOOKUP("full-RTCP-attribute"):
			out->full_rtcp_attr = 1;
			break;
		case CSH_LOOKUP("generate-RTCP"):
		case CSH_LOOKUP("generate-rtcp"):
			out->generate_rtcp = 1;
			break;
		case CSH_LOOKUP("trickle-ICE"):
		case CSH_LOOKUP("trickle-ice"):
			out->trickle_ice = 1;
			break;
		case CSH_LOOKUP("ICE-reject"):
		case CSH_LOOKUP("reject-ICE"):
		case CSH_LOOKUP("ice-reject"):
		case CSH_LOOKUP("reject-ice"):
			out->ice_reject = 1;
			break;
		case CSH_LOOKUP("loop-protect"):
			out->loop_protect = 1;
			break;
		case CSH_LOOKUP("original-sendrecv"):
			out->original_sendrecv = 1;
			break;
		case CSH_LOOKUP("always-transcode"):;
			static const str str_all = STR_CONST_INIT("all");
			call_ng_flags_esc_str_list(out, (str *) &str_all, &out->codec_accept);
			break;
		case CSH_LOOKUP("asymmetric-codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `asymmetric-codecs`");
			break;
		case CSH_LOOKUP("symmetric-codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `symmetric-codecs`");
			break;
		case CSH_LOOKUP("reorder-codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `reorder-codecs`");
			break;
		case CSH_LOOKUP("reuse-codecs"):
			out->reuse_codec = 1;
			break;
		case CSH_LOOKUP("no-codec-renegotiation"):
			out->reuse_codec = 1;
			break;
		case CSH_LOOKUP("single-codec"):
			out->single_codec = 1;
			break;
		case CSH_LOOKUP("allow-transcoding"):
			out->allow_transcoding = 1;
			break;
		case CSH_LOOKUP("inject-DTMF"):
		case CSH_LOOKUP("inject-dtmf"):
			out->inject_dtmf = 1;
			break;
		case CSH_LOOKUP("detect-DTMF"):
		case CSH_LOOKUP("detect-dtmf"):
			out->detect_dtmf = 1;
			break;
		case CSH_LOOKUP("pad-crypto"):
			out->sdes_pad = 1;
			break;
		case CSH_LOOKUP("passthrough"):
			out->passthrough_on = 1;
			break;
		case CSH_LOOKUP("no-passthrough"):
			out->passthrough_off = 1;
			break;
		case CSH_LOOKUP("player"):
		case CSH_LOOKUP("audio-player"):
			out->audio_player = AP_TRANSCODING;
			break;
		case CSH_LOOKUP("no-player"):
		case CSH_LOOKUP("no-audio-player"):
			out->audio_player = AP_OFF;
			break;
		case CSH_LOOKUP("no-jitter-buffer"):
			out->disable_jb = 1;
			break;
		case CSH_LOOKUP("pierce-NAT"):
		case CSH_LOOKUP("pierce-nat"):
			out->pierce_nat = 1;
			break;
		case CSH_LOOKUP("NAT-wait"):
		case CSH_LOOKUP("nat-wait"):
			out->nat_wait = 1;
			break;
		case CSH_LOOKUP("RTCP-mirror"):
		case CSH_LOOKUP("mirror-RTCP"):
		case CSH_LOOKUP("rtcp-mirror"):
		case CSH_LOOKUP("mirror-rtcp"):
			out->rtcp_mirror = 1;
			break;
		default:
			// handle values aliases from other dictionaries
			if (call_ng_flags_prefix(out, s, "from-tags-", call_ng_flags_esc_str_list,
						&out->from_tags))
				return;
			if (call_ng_flags_prefix(out, s, "SDES-only-", call_ng_flags_str_ht, &out->sdes_only))
				return;
			if (call_ng_flags_prefix(out, s, "SDES-no-", call_ng_flags_str_ht, &out->sdes_no))
				return;
			if (call_ng_flags_prefix(out, s, "SDES-order:", call_ng_flags_str_q_multi, &out->sdes_order))
				return;
			if (call_ng_flags_prefix(out, s, "SDES-offerer_pref:", call_ng_flags_str_q_multi,
							&out->sdes_offerer_pref))
				return;
			if (call_ng_flags_prefix(out, s, "SDES-", ng_sdes_option, NULL))
				return;
			if (call_ng_flags_prefix(out, s, "OSRTP-", ng_osrtp_option, NULL))
				return;
			if (call_ng_flags_prefix(out, s, "codec-strip-", call_ng_flags_esc_str_list,
						&out->codec_strip))
				return;
			if (call_ng_flags_prefix(out, s, "codec-offer-", call_ng_flags_esc_str_list,
						&out->codec_offer))
				return;
			if (call_ng_flags_prefix(out, s, "codec-except-", call_ng_flags_str_ht,
						&out->codec_except))
				return;
			if (call_ng_flags_prefix(out, s, "endpoint-learning-", ng_el_option, NULL))
				return;
			if (call_ng_flags_prefix(out, s, "replace-", call_ng_flags_replace, NULL))
				return;
#ifdef WITH_TRANSCODING
			if (out->opmode == OP_OFFER || out->opmode == OP_REQUEST || out->opmode == OP_PUBLISH) {
				if (call_ng_flags_prefix(out, s, "transcode-", call_ng_flags_esc_str_list,
							&out->codec_transcode))
					return;
				if (call_ng_flags_prefix(out, s, "codec-transcode-", call_ng_flags_esc_str_list,
							&out->codec_transcode))
					return;
				if (call_ng_flags_prefix(out, s, "codec-mask-", call_ng_flags_esc_str_list,
							&out->codec_mask))
					return;
				if (call_ng_flags_prefix(out, s, "T38-", ng_t38_option, NULL))
					return;
				if (call_ng_flags_prefix(out, s, "T.38-", ng_t38_option, NULL))
					return;
			}
			if (call_ng_flags_prefix(out, s, "codec-set-", call_ng_flags_str_ht_split,
						&out->codec_set))
				return;
			if (call_ng_flags_prefix(out, s, "codec-accept-", call_ng_flags_esc_str_list,
						&out->codec_accept))
				return;
			if (call_ng_flags_prefix(out, s, "codec-consume-", call_ng_flags_esc_str_list,
						&out->codec_consume))
				return;
#endif

			ilog(LOG_WARN, "Unknown flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}

void call_ng_flags_init(struct sdp_ng_flags *out, enum call_opmode opmode) {
	ZERO(*out);
	out->opmode = opmode;

	out->trust_address = trust_address_def;
	out->dtls_passive = dtls_passive_def;
	out->dtls_reverse_passive = dtls_passive_def;
	out->el_option = rtpe_config.endpoint_learning;
	out->tos = 256;
	out->delay_buffer = -1;
	out->volume = 9999;
	out->digit = -1;
	out->frequencies = g_array_new(false, false, sizeof(int));
}

static void call_ng_dict_iter(struct sdp_ng_flags *out, bencode_item_t *input,
		void (*callback)(struct sdp_ng_flags *, str *key, bencode_item_t *value))
{
	if (input->type != BENCODE_DICTIONARY)
		return;

	bencode_item_t *value = NULL;
	for (bencode_item_t *key = input->child; key; key = value->sibling) {
		value = key->sibling;
		if (!value)
			break;

		str k;
		if (!bencode_get_str(key, &k))
			continue;

		callback(out, &k, value);

	}
}
static void call_ng_codec_flags(struct sdp_ng_flags *out, str *key, bencode_item_t *value) {
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("strip"):
			call_ng_flags_list(out, value, call_ng_flags_esc_str_list, &out->codec_strip);
			return;
		case CSH_LOOKUP("offer"):
			call_ng_flags_list(out, value, call_ng_flags_esc_str_list, &out->codec_offer);
			return;
		case CSH_LOOKUP("except"):
			call_ng_flags_list(out, value,  call_ng_flags_str_ht, &out->codec_except);
			return;
	}
#ifdef WITH_TRANSCODING
	if (out->opmode == OP_OFFER || out->opmode == OP_REQUEST || out->opmode == OP_PUBLISH) {
		switch (__csh_lookup(key)) {
			case CSH_LOOKUP("transcode"):
				call_ng_flags_list(out, value, call_ng_flags_esc_str_list,
						&out->codec_transcode);
				return;
			case CSH_LOOKUP("mask"):
				call_ng_flags_list(out, value, call_ng_flags_esc_str_list, &out->codec_mask);
				return;
			case CSH_LOOKUP("set"):
				call_ng_flags_list(out, value, call_ng_flags_str_ht_split, &out->codec_set);
				return;
			case CSH_LOOKUP("accept"):
				call_ng_flags_list(out, value, call_ng_flags_esc_str_list, &out->codec_accept);
				return;
			case CSH_LOOKUP("consume"):
				call_ng_flags_list(out, value, call_ng_flags_esc_str_list, &out->codec_consume);
				return;
		}
	}
	else {
		// silence warnings
		switch (__csh_lookup(key)) {
			case CSH_LOOKUP("transcode"):
			case CSH_LOOKUP("mask"):
			case CSH_LOOKUP("set"):
			case CSH_LOOKUP("accept"):
			case CSH_LOOKUP("consume"):
				return;
		}
	}
#endif
	ilog(LOG_WARN, "Unknown 'codec' operation encountered: '" STR_FORMAT "'", STR_FMT(key));
}
#ifdef WITH_TRANSCODING
static void call_ng_parse_block_mode(str *s, enum block_dtmf_mode *output) {
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("off"):
			*output = BLOCK_DTMF_OFF;
			break;
		case CSH_LOOKUP("drop"):
			*output = BLOCK_DTMF_DROP;
			break;
		case CSH_LOOKUP("silence"):
			*output = BLOCK_DTMF_SILENCE;
			break;
		case CSH_LOOKUP("tone"):
			*output = BLOCK_DTMF_TONE;
			break;
		case CSH_LOOKUP("random"):
			*output = BLOCK_DTMF_RANDOM;
			break;
		case CSH_LOOKUP("zero"):
			*output = BLOCK_DTMF_ZERO;
			break;
		case CSH_LOOKUP("DTMF"):
		case CSH_LOOKUP("dtmf"):
			*output = BLOCK_DTMF_DTMF;
			break;
		default:
			ilog(LOG_WARN, "Unknown DTMF block mode encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
#endif

static void call_ng_flags_freqs(struct sdp_ng_flags *out, bencode_item_t *value) {
	unsigned int val;

	switch (value->type) {
		case BENCODE_INTEGER:;
			val = value->value;
			g_array_append_val(out->frequencies, val);
			break;
		case BENCODE_LIST:
			for (bencode_item_t *it = value->child; it; it = it->sibling)
				call_ng_flags_freqs(out, it);
			break;
		case BENCODE_STRING:;
			str s, token;
			bencode_get_str(value, &s);
			while (str_token_sep(&token, &s, ',') == 0) {
				val = str_to_i(&token, 0);
				g_array_append_val(out->frequencies, val);
			}
			break;
		default:
			ilog(LOG_WARN, "Invalid content type in `frequencies` list");
	}
}

static void call_ng_main_flags(struct sdp_ng_flags *out, str *key, bencode_item_t *value) {
	str s = STR_NULL;
	bencode_item_t *it;

	bencode_get_str(value, &s);

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("call-id"):
		case CSH_LOOKUP("call-ID"):
		case CSH_LOOKUP("call id"):
		case CSH_LOOKUP("call ID"):
			out->call_id = s;
			break;
		case CSH_LOOKUP("from-tag"):
			out->from_tag = s;
			break;
		case CSH_LOOKUP("to-tag"):
			out->to_tag = s;
			break;
		case CSH_LOOKUP("via-branch"):
			out->via_branch = s;
			break;
		case CSH_LOOKUP("from-label"):
		case CSH_LOOKUP("label"):
			out->label = s;
			break;
		case CSH_LOOKUP("set-label"):
			out->set_label = s;
			break;
		case CSH_LOOKUP("to-label"):
			out->to_label = s;
			break;
		case CSH_LOOKUP("address"):
			out->address = s;
			break;
		case CSH_LOOKUP("SDP"):
		case CSH_LOOKUP("sdp"):
			out->sdp = s;
			break;
		case CSH_LOOKUP("interface"):
			out->interface = s;
			break;
		case CSH_LOOKUP("flags"):
			call_ng_flags_list(out, value, call_ng_flags_flags, NULL);
			break;
		case CSH_LOOKUP("replace"):
			call_ng_flags_list(out, value, call_ng_flags_replace, NULL);
			break;
		case CSH_LOOKUP("supports"):
			call_ng_flags_list(out, value, call_ng_flags_supports, NULL);
			break;
		case CSH_LOOKUP("from-tags"):
			call_ng_flags_list(out, value, call_ng_flags_esc_str_list, &out->from_tags);
			break;
		case CSH_LOOKUP("rtcp-mux"):
		case CSH_LOOKUP("RTCP-mux"):
			call_ng_flags_list(out, value, call_ng_flags_rtcp_mux, NULL);
			break;
		case CSH_LOOKUP("SDES"):
		case CSH_LOOKUP("sdes"):
			call_ng_flags_list(out, value, ng_sdes_option, NULL);
			break;
		case CSH_LOOKUP("OSRTP"):
		case CSH_LOOKUP("osrtp"):
			call_ng_flags_list(out, value, ng_osrtp_option, NULL);
			break;
		case CSH_LOOKUP("endpoint-learning"):
		case CSH_LOOKUP("endpoint learning"):
			call_ng_flags_list(out, value, ng_el_option, NULL);
			break;
		case CSH_LOOKUP("direction"):
			if (value->type != BENCODE_LIST)
				break;
			int diridx = 0;
			for (bencode_item_t *cit = value->child; cit && diridx < 2; cit = cit->sibling)
				bencode_get_str(cit, &out->direction[diridx++]);
			break;
		case CSH_LOOKUP("sdp-attr"):
		case CSH_LOOKUP("SDP-attr"):
			if (value->type != BENCODE_DICTIONARY)
				break;
			ng_sdp_attr_manipulations(&out->sdp_manipulations, value);
			break;
		case CSH_LOOKUP("received from"):
		case CSH_LOOKUP("received-from"):
			if (value->type != BENCODE_LIST)
				break;
			if ((it = value->child)) {
				bencode_get_str(it, &out->received_from_family);
				bencode_get_str(it->sibling, &out->received_from_address);
			}
			break;
		case CSH_LOOKUP("drop-traffic"):
		case CSH_LOOKUP("drop traffic"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("start"):
					out->drop_traffic_start = 1;
					break;
				case CSH_LOOKUP("stop"):
					out->drop_traffic_stop = 1;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'drop-traffic' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("ICE"):
		case CSH_LOOKUP("ice"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("remove"):
					out->ice_option = ICE_REMOVE;
					break;
				case CSH_LOOKUP("force"):
					out->ice_option = ICE_FORCE;
					break;
				case CSH_LOOKUP("default"):
					out->ice_option = ICE_DEFAULT;
					break;
				case CSH_LOOKUP("optional"):
					out->ice_option = ICE_OPTIONAL;
					break;
				case CSH_LOOKUP("force_relay"):
				case CSH_LOOKUP("force-relay"):
				case CSH_LOOKUP("force relay"):
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
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("off"):
				case CSH_LOOKUP("none"):
				case CSH_LOOKUP("no"):
					out->ice_lite_option = ICE_LITE_OFF;
					break;
				case CSH_LOOKUP("forward"):
				case CSH_LOOKUP("offer"):
				case CSH_LOOKUP("fwd"):
				case CSH_LOOKUP("fw"):
					out->ice_lite_option = ICE_LITE_FWD;
					break;
				case CSH_LOOKUP("backward"):
				case CSH_LOOKUP("backwards"):
				case CSH_LOOKUP("reverse"):
				case CSH_LOOKUP("answer"):
				case CSH_LOOKUP("back"):
				case CSH_LOOKUP("bkw"):
				case CSH_LOOKUP("bk"):
					out->ice_lite_option = ICE_LITE_BKW;
					break;
				case CSH_LOOKUP("both"):
					out->ice_lite_option = ICE_LITE_BOTH;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'ICE-lite' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("DTLS"):
		case CSH_LOOKUP("dtls"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("passive"):
					out->dtls_passive = 1;
					break;
				case CSH_LOOKUP("active"):
					out->dtls_passive = 0;
					break;
				case CSH_LOOKUP("no"):
				case CSH_LOOKUP("off"):
				case CSH_LOOKUP("disabled"):
				case CSH_LOOKUP("disable"):
					out->dtls_off = 1;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'DTLS' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("DTLS-reverse"):
		case CSH_LOOKUP("dtls-reverse"):
		case CSH_LOOKUP("DTLS reverse"):
		case CSH_LOOKUP("dtls reverse"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("passive"):
					out->dtls_reverse_passive = 1;
					break;
				case CSH_LOOKUP("active"):
					out->dtls_reverse_passive = 0;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'DTLS-reverse' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("passthrough"):
		case CSH_LOOKUP("passthru"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("on"):
				case CSH_LOOKUP("yes"):
				case CSH_LOOKUP("enable"):
				case CSH_LOOKUP("enabled"):
					out->passthrough_on = 1;
					break;
				case CSH_LOOKUP("no"):
				case CSH_LOOKUP("off"):
				case CSH_LOOKUP("disable"):
				case CSH_LOOKUP("disabled"):
					out->passthrough_off = 1;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'passthrough' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("player"):
		case CSH_LOOKUP("audio-player"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("default"):
					out->audio_player = AP_DEFAULT;
					break;
				case CSH_LOOKUP("on"):
				case CSH_LOOKUP("yes"):
				case CSH_LOOKUP("enable"):
				case CSH_LOOKUP("enabled"):
				case CSH_LOOKUP("transcode"):
				case CSH_LOOKUP("transcoding"):
					out->audio_player = AP_TRANSCODING;
					break;
				case CSH_LOOKUP("no"):
				case CSH_LOOKUP("off"):
				case CSH_LOOKUP("disable"):
				case CSH_LOOKUP("disabled"):
					out->audio_player = AP_OFF;
					break;
				case CSH_LOOKUP("force"):
				case CSH_LOOKUP("forced"):
				case CSH_LOOKUP("always"):
				case CSH_LOOKUP("everything"):
					out->audio_player = AP_FORCE;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'audio-player' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("transport protocol"):
		case CSH_LOOKUP("transport-protocol"):
			if (!str_cmp(&s, "accept"))
				out->protocol_accept = 1;
			else
				out->transport_protocol = transport_protocol(&s);
			break;
		case CSH_LOOKUP("media address"):
		case CSH_LOOKUP("media-address"):
			out->media_address = s;
			break;
		case CSH_LOOKUP("record call"):
		case CSH_LOOKUP("record-call"):
			out->record_call_str = s;
			break;
		case CSH_LOOKUP("output-destination"):
			out->output_dest = s;
			break;
		case CSH_LOOKUP("address family"):
		case CSH_LOOKUP("address-family"):
			if (bencode_get_str(value, &out->address_family_str))
				out->address_family = get_socket_family_rfc(&out->address_family_str);
			break;
		case CSH_LOOKUP("metadata"):
			out->metadata = s;
			break;
		case CSH_LOOKUP("DTLS fingerprint"):
		case CSH_LOOKUP("DTLS-fingerprint"):
		case CSH_LOOKUP("dtls fingerprint"):
		case CSH_LOOKUP("dtls-fingerprint"):
			out->dtls_fingerprint = s;
			break;
		case CSH_LOOKUP("TOS"):
		case CSH_LOOKUP("tos"):
			out->tos = bencode_get_integer_str(value, out->tos);
			break;
		case CSH_LOOKUP("ptime"):
			if (out->opmode == OP_OFFER)
				out->ptime = bencode_get_integer_str(value, 0);
			break;
		case CSH_LOOKUP("ptime-reverse"):
		case CSH_LOOKUP("ptime reverse"):
		case CSH_LOOKUP("reverse ptime"):
		case CSH_LOOKUP("reverse-ptime"):
			if (out->opmode == OP_OFFER)
				out->rev_ptime = bencode_get_integer_str(value, 0);
			break;
		case CSH_LOOKUP("xmlrpc-callback"):
		case CSH_LOOKUP("XMLRPC-callback"):
			if (sockaddr_parse_any_str(&out->xmlrpc_callback, &s))
				ilog(LOG_WARN, "Failed to parse 'xmlrpc-callback' address '" STR_FORMAT "'",
						STR_FMT(&s));
			break;
		case CSH_LOOKUP("dtmf-log-dest"):
		case CSH_LOOKUP("DTMF-log-dest"):
		case CSH_LOOKUP("dtmf-log-destination"):
		case CSH_LOOKUP("DTMF-log-destination"):
			if (endpoint_parse_any_str(&out->dtmf_log_dest, &s))
				ilog(LOG_WARN, "Failed to parse 'dtmf-log-dest' address '" STR_FORMAT "'",
						STR_FMT(&s));
			break;
		case CSH_LOOKUP("codec"):
			call_ng_dict_iter(out, value, call_ng_codec_flags);
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
		case CSH_LOOKUP("media echo"):
		case CSH_LOOKUP("media-echo"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("blackhole"):
				case CSH_LOOKUP("sinkhole"):
					out->media_echo = MEO_BLACKHOLE;
					break;
				case CSH_LOOKUP("forward"):
				case CSH_LOOKUP("fwd"):
				case CSH_LOOKUP("fw"):
					out->media_echo = MEO_FWD;
					break;
				case CSH_LOOKUP("backward"):
				case CSH_LOOKUP("backwards"):
				case CSH_LOOKUP("reverse"):
				case CSH_LOOKUP("back"):
				case CSH_LOOKUP("bkw"):
				case CSH_LOOKUP("bk"):
					out->media_echo = MEO_BKW;
					break;
				case CSH_LOOKUP("both"):
					out->media_echo = MEO_BOTH;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'media-echo' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("frequency"):
		case CSH_LOOKUP("frequencies"):
			call_ng_flags_freqs(out, value);
			break;
		case CSH_LOOKUP("volume"):
			out->volume = bencode_get_integer_str(value, out->volume);
			break;
		case CSH_LOOKUP("code"):
		case CSH_LOOKUP("digit"):
			out->digit = bencode_get_integer_str(value, out->digit);
			if (s.len == 1)
				out->digit = s.s[0];
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
			out->trigger_end_ms = bencode_get_integer_str(value, out->trigger_end_ms);
			break;
		case CSH_LOOKUP("trigger-end-digits"):
		case CSH_LOOKUP("trigger end digits"):
		case CSH_LOOKUP("end-trigger-digits"):
		case CSH_LOOKUP("end trigger digits"):
			out->trigger_end_digits = bencode_get_integer_str(value, out->trigger_end_digits);
			break;
		case CSH_LOOKUP("DTMF-delay"):
		case CSH_LOOKUP("DTMF delay"):
		case CSH_LOOKUP("dtmf-delay"):
		case CSH_LOOKUP("dtmf delay"):
			out->dtmf_delay = bencode_get_integer_str(value, out->dtmf_delay);
			break;
#ifdef WITH_TRANSCODING
		case CSH_LOOKUP("T38"):
		case CSH_LOOKUP("T.38"):
		case CSH_LOOKUP("t38"):
		case CSH_LOOKUP("t.38"):
			call_ng_flags_list(out, value, ng_t38_option, NULL);
			break;
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
			out->delay_buffer = bencode_get_integer_str(value, out->delay_buffer);
			break;
#endif
		case CSH_LOOKUP("repeat-times"):
			out->repeat_times = bencode_get_integer_str(value, out->repeat_times);
			break;
		case CSH_LOOKUP("file"):
			out->file = s;
			break;
		case CSH_LOOKUP("start-pos"):
			out->start_pos = bencode_get_integer_str(value, out->start_pos);
			break;
		case CSH_LOOKUP("blob"):
			out->blob = s;
			break;
		case CSH_LOOKUP("db-id"):
			out->db_id = bencode_get_integer_str(value, out->db_id);
			break;
		case CSH_LOOKUP("duration"):
			out->duration = bencode_get_integer_str(value, out->duration);
			break;
		case CSH_LOOKUP("pause"):
			out->pause = bencode_get_integer_str(value, out->pause);
			break;
		case CSH_LOOKUP("all"):
			switch (__csh_lookup(&s)) {
				case CSH_LOOKUP("all"):
					out->all = ALL_ALL;
					break;
				case CSH_LOOKUP("none"):
					out->all = ALL_NONE;
					break;
				case CSH_LOOKUP("offer-answer"):
					out->all = ALL_OFFER_ANSWER;
					break;
				case CSH_LOOKUP("not-offer-answer"):
				case CSH_LOOKUP("non-offer-answer"):
				case CSH_LOOKUP("except-offer-answer"):
					out->all = ALL_NON_OFFER_ANSWER;
					break;
				case CSH_LOOKUP("flows"):
					out->all = ALL_FLOWS;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'all' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("command"):
			break;
		default:
			ilog(LOG_WARN, "Unknown dictionary key encountered: '" STR_FORMAT "'", STR_FMT(key));
	}
}

static void call_ng_process_flags(struct sdp_ng_flags *out, bencode_item_t *input, enum call_opmode opmode) {
	call_ng_flags_init(out, opmode);
	call_ng_dict_iter(out, input, call_ng_main_flags);
}

static void ng_sdp_attr_manipulations_free(struct sdp_manipulations_common * sdp_manipulations) {
	if (sdp_manipulations->rem_commands_glob)
		g_hash_table_destroy(sdp_manipulations->rem_commands_glob);
	if (sdp_manipulations->rem_commands_audio)
		g_hash_table_destroy(sdp_manipulations->rem_commands_audio);
	if (sdp_manipulations->rem_commands_video)
		g_hash_table_destroy(sdp_manipulations->rem_commands_video);

	if (sdp_manipulations->subst_commands_glob)
		g_hash_table_destroy(sdp_manipulations->subst_commands_glob);
	if (sdp_manipulations->subst_commands_audio)
		g_hash_table_destroy(sdp_manipulations->subst_commands_audio);
	if (sdp_manipulations->subst_commands_video)
		g_hash_table_destroy(sdp_manipulations->subst_commands_video);

	g_queue_clear_full(&sdp_manipulations->add_commands_glob, free);
	g_queue_clear_full(&sdp_manipulations->add_commands_audio, free);
	g_queue_clear_full(&sdp_manipulations->add_commands_video, free);

	g_slice_free1(sizeof(*sdp_manipulations), sdp_manipulations);
}

void call_ng_free_flags(struct sdp_ng_flags *flags) {
	if (flags->codec_except)
		g_hash_table_destroy(flags->codec_except);
	if (flags->codec_set)
		g_hash_table_destroy(flags->codec_set);
	if (flags->sdes_no)
		g_hash_table_destroy(flags->sdes_no);
	if (flags->sdes_only)
		g_hash_table_destroy(flags->sdes_only);
	if (flags->frequencies)
		g_array_free(flags->frequencies, true);

	g_queue_clear_full(&flags->from_tags, free);
	g_queue_clear_full(&flags->codec_offer, free);
	g_queue_clear_full(&flags->codec_transcode, free);
	g_queue_clear_full(&flags->codec_strip, free);
	g_queue_clear_full(&flags->codec_accept, free);
	g_queue_clear_full(&flags->codec_consume, free);
	g_queue_clear_full(&flags->codec_mask, free);
	g_queue_clear_full(&flags->sdes_order, free);
	g_queue_clear_full(&flags->sdes_offerer_pref, free);

	if (flags->sdp_manipulations)
		ng_sdp_attr_manipulations_free(flags->sdp_manipulations);
}

static enum load_limit_reasons call_offer_session_limit(void) {
	enum load_limit_reasons ret = LOAD_LIMIT_NONE;

	rwlock_lock_r(&rtpe_config.config_lock);
	if (rtpe_config.max_sessions>=0) {
		rwlock_lock_r(&rtpe_callhash_lock);
		if (g_hash_table_size(rtpe_callhash) -
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

	if (ret == LOAD_LIMIT_NONE && rtpe_config.load_limit) {
		int loadavg = g_atomic_int_get(&load_average);
		if (loadavg >= rtpe_config.load_limit) {
			ilog(LOG_WARN, "Load limit exceeded (%.2f > %.2f)",
					(double) loadavg / 100.0, (double) rtpe_config.load_limit / 100.0);
			ret = LOAD_LIMIT_LOAD;
		}
	}

	if (ret == LOAD_LIMIT_NONE && rtpe_config.cpu_limit) {
		int cpu = g_atomic_int_get(&cpu_usage);
		if (cpu >= rtpe_config.cpu_limit) {
			ilog(LOG_WARN, "CPU usage limit exceeded (%.1f%% > %.1f%%)",
					(double) cpu / 100.0, (double) rtpe_config.cpu_limit / 100.0);
			ret = LOAD_LIMIT_CPU;
		}
	}

	if (ret == LOAD_LIMIT_NONE && rtpe_config.bw_limit) {
		uint64_t bw = atomic64_get(&rtpe_stats_rate.bytes_user) +
			atomic64_get(&rtpe_stats_rate.bytes_kernel);
		if (bw >= rtpe_config.bw_limit) {
			ilog(LOG_WARN, "Bandwidth limit exceeded (%" PRIu64 " > %" PRIu64 ")",
					bw, rtpe_config.bw_limit);
			ret = LOAD_LIMIT_BW;
		}
	}

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ret;
}


void save_last_sdp(struct call_monologue *ml, str *sdp, GQueue *parsed, GQueue *streams) {
	str_free_dup(&ml->last_in_sdp);
	ml->last_in_sdp = *sdp;
	*sdp = STR_NULL;

	sdp_free(&ml->last_in_sdp_parsed);
	ml->last_in_sdp_parsed = *parsed;
	g_queue_init(parsed);

	sdp_streams_free(&ml->last_in_sdp_streams);
	ml->last_in_sdp_streams = *streams;
	g_queue_init(streams);
}


static const char *call_offer_answer_ng(struct ng_buffer *ngbuf, bencode_item_t *input,
		bencode_item_t *output, enum call_opmode opmode, const char* addr,
		const endpoint_t *sin)
{
	const char *errstr;
	AUTO_CLEANUP(str sdp, str_free_dup) = STR_NULL;
	AUTO_CLEANUP(GQueue parsed, sdp_free) = G_QUEUE_INIT;
	AUTO_CLEANUP(GQueue streams, sdp_streams_free) = G_QUEUE_INIT;
	struct call *call;
	struct call_subscription *dialogue[2];
	int ret;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	struct sdp_chopper *chopper;

	call_ng_process_flags(&flags, input, opmode);

	if (!flags.sdp.s)
		return "No SDP body in message";
	if (!flags.call_id.s)
		return "No call-id in message";
	if (!flags.from_tag.s)
		return "No from-tag in message";
	if (opmode == OP_ANSWER) {
		if (!flags.to_tag.s)
			return "No to-tag in message";
		str_swap(&flags.to_tag, &flags.from_tag);
	}

	str_init_dup_str(&sdp, &flags.sdp);

	errstr = "Failed to parse SDP";
	if (sdp_parse(&sdp, &parsed, &flags))
		goto out;

	if (flags.loop_protect && sdp_is_duplicate(&parsed)) {
		ilog(LOG_INFO, "Ignoring message as SDP has already been processed by us");
		bencode_dictionary_add_str(output, "sdp", &flags.sdp);
		errstr = NULL;
		goto out;
	}

	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, &flags))
		goto out;

	/* OP_ANSWER; OP_OFFER && !IS_FOREIGN_CALL */
	call = call_get(&flags.call_id);

	// SDP fragments for trickle ICE must always operate on an existing call
	if (opmode == OP_OFFER && trickle_ice_update(ngbuf, call, &flags, &streams)) {
		errstr = NULL;
		// SDP fragments for trickle ICE are consumed with no replacement returned
		goto out;
	}

	if (opmode == OP_OFFER && !call) {
		enum load_limit_reasons limit = call_offer_session_limit();
		if (limit != LOAD_LIMIT_NONE) {
			if (!flags.supports_load_limit)
				errstr = "Parallel session limit reached"; // legacy protocol
			else
				errstr = magic_load_limit_strings[limit];
			goto out;
		}

		call = call_get_or_create(&flags.call_id, false, false);
	}

	errstr = "Unknown call-id";
	if (!call)
		goto out;

	if (flags.debug)
		call->debug = 1;

	if (rtpe_config.active_switchover && IS_FOREIGN_CALL(call))
		call_make_own_foreign(call, false);

	updated_created_from(call, addr, sin);

	if (flags.xmlrpc_callback.family)
		call->xmlrpc_callback = flags.xmlrpc_callback;
	if (flags.dtmf_log_dest.address.family)
		call->dtmf_log_dest = flags.dtmf_log_dest;

	/* At least the random ICE strings are contained within the call struct, so we
	 * need to hold a ref until we're done sending the reply */
	call_bencode_hold_ref(call, output);

	errstr = "Invalid dialogue association";
	if (call_get_mono_dialogue(dialogue, call, &flags.from_tag, &flags.to_tag,
			flags.via_branch.s ? &flags.via_branch : NULL)) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
		goto out;
	}

	struct call_monologue *from_ml = dialogue[0]->monologue;
	struct call_monologue *to_ml = dialogue[1]->monologue;

	if (opmode == OP_OFFER) {
		from_ml->tagtype = FROM_TAG;
	} else {
		from_ml->tagtype = TO_TAG;
	}

	chopper = sdp_chopper_new(&sdp);
	bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);

	update_metadata_monologue(from_ml, &flags.metadata);
	detect_setup_recording(call, &flags);

	if (flags.drop_traffic_start) {
		call->drop_traffic = 1;
	}

	if (flags.drop_traffic_stop) {
		call->drop_traffic = 0;
	}

	ret = monologue_offer_answer(dialogue, &streams, &flags);
	if (!ret)
		ret = sdp_replace(chopper, &parsed, to_ml, &flags);
	if (!ret)
		save_last_sdp(from_ml, &sdp, &parsed, &streams);

	struct recording *recording = call->recording;
	if (recording != NULL) {
		meta_write_sdp_before(recording, &sdp, from_ml, opmode);
		meta_write_sdp_after(recording, chopper->output,
			       from_ml, opmode);

		recording_response(recording, output);
	}

	dequeue_sdp_fragments(from_ml);

	rwlock_unlock_w(&call->master_lock);

	if (!flags.no_redis_update) {
			redis_update_onekey(call, rtpe_redis_write);
	} else {
		ilog(LOG_DEBUG, "Not updating Redis due to present no-redis-update flag");
	}
	obj_put(call);

	gettimeofday(&(from_ml->started), NULL);

	errstr = "Error rewriting SDP";

	if (ret == ERROR_NO_FREE_PORTS || ret == ERROR_NO_FREE_LOGS) {
		ilog(LOG_ERR, "Destroying call");
		errstr = "Ran out of ports";
		call_destroy(call);
	}

	if (ret)
		goto out;

	if (chopper->output->len)
		bencode_dictionary_add_string_len(output, "sdp", chopper->output->str, chopper->output->len);

	errstr = NULL;
out:
	return errstr;
}

const char *call_offer_ng(struct ng_buffer *ngbuf, bencode_item_t *input, bencode_item_t *output,
		const char* addr,
		const endpoint_t *sin)
{
	return call_offer_answer_ng(ngbuf, input, output, OP_OFFER, addr, sin);
}

const char *call_answer_ng(struct ng_buffer *ngbuf, bencode_item_t *input, bencode_item_t *output) {
	return call_offer_answer_ng(ngbuf, input, output, OP_ANSWER, NULL, NULL);
}

const char *call_delete_ng(bencode_item_t *input, bencode_item_t *output) {
	str fromtag, totag, viabranch, callid;
	bencode_item_t *flags, *it;
	bool fatal = false;
	bool discard = false;
	int delete_delay;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	bencode_dictionary_get_str(input, "from-tag", &fromtag);
	bencode_dictionary_get_str(input, "to-tag", &totag);
	bencode_dictionary_get_str(input, "via-branch", &viabranch);

	flags = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST);
	if (flags) {
		for (it = flags->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "fatal"))
				fatal = true;
			else if (!bencode_strcmp(it, "discard-recording"))
				discard = true;
		}
	}
	delete_delay = bencode_dictionary_get_int_str(input, "delete-delay", -1);
	if (delete_delay == -1) {
		delete_delay = bencode_dictionary_get_int_str(input, "delete delay", -1);
		if (delete_delay == -1) {
			/* legacy support */
			str s;
			bencode_dictionary_get_str(input, "delete-delay", &s);
			if (s.s)
				delete_delay = str_to_i(&s, -1);
		}
	}

	struct call *c = call_get(&callid);
	if (!c)
		goto err;

	if (discard)
		recording_discard(c);

	if (call_delete_branch(c, &viabranch, &fromtag, &totag, output, delete_delay))
		goto err;

	return NULL;

err:
	if (fatal)
		return "Call-ID not found or tags didn't match";
	bencode_dictionary_add_string(output, "warning", "Call-ID not found or tags didn't match");
	return NULL;
}

static void ng_stats(bencode_item_t *d, const struct stream_stats *s, struct stream_stats *totals) {
	bencode_dictionary_add_integer(d, "packets", atomic64_get(&s->packets));
	bencode_dictionary_add_integer(d, "bytes", atomic64_get(&s->bytes));
	bencode_dictionary_add_integer(d, "errors", atomic64_get(&s->errors));
	if (!totals)
		return;
	atomic64_add_na(&totals->packets, atomic64_get(&s->packets));
	atomic64_add_na(&totals->bytes, atomic64_get(&s->bytes));
	atomic64_add_na(&totals->errors, atomic64_get(&s->errors));
}

static void ng_stats_endpoint(bencode_item_t *dict, const endpoint_t *ep) {
	if (!ep->address.family)
		return;
	bencode_dictionary_add_string(dict, "family", ep->address.family->name);
	bencode_dictionary_add_string_dup(dict, "address", sockaddr_print_buf(&ep->address));
	bencode_dictionary_add_integer(dict, "port", ep->port);
}

#define BF_PS(k, f) if (PS_ISSET(ps, f)) bencode_list_add_string(flags, k)

static void ng_stats_stream(bencode_item_t *list, const struct packet_stream *ps,
		struct call_stats *totals)
{
	bencode_item_t *dict = NULL, *flags;
	struct stream_stats *s;

	if (!list)
		goto stats;

	dict = bencode_list_add_dictionary(list);

	if (ps->selected_sfd) {
		bencode_dictionary_add_integer(dict, "local port", ps->selected_sfd->socket.local.port);
		bencode_dictionary_add_string_dup(dict, "local address",
				sockaddr_print_buf(&ps->selected_sfd->socket.local.address));
		bencode_dictionary_add_string(dict, "family", ps->selected_sfd->socket.local.address.family->name);
	}
	ng_stats_endpoint(bencode_dictionary_add_dictionary(dict, "endpoint"), &ps->endpoint);
	ng_stats_endpoint(bencode_dictionary_add_dictionary(dict, "advertised endpoint"),
			&ps->advertised_endpoint);
	if (ps->crypto.params.crypto_suite)
		bencode_dictionary_add_string(dict, "crypto suite",
				ps->crypto.params.crypto_suite->name);
	bencode_dictionary_add_integer(dict, "last packet", atomic64_get(&ps->last_packet));

	flags = bencode_dictionary_add_list(dict, "flags");

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

	// XXX convert to list output?
	if (ps->ssrc_in[0])
		bencode_dictionary_add_integer(dict, "SSRC", ps->ssrc_in[0]->parent->h.ssrc);

stats:
	if (totals->last_packet < atomic64_get(&ps->last_packet))
		totals->last_packet = atomic64_get(&ps->last_packet);

	/* XXX distinguish between input and output */
	s = &totals->totals[0];
	if (!PS_ISSET(ps, RTP))
		s = &totals->totals[1];
	ng_stats(bencode_dictionary_add_dictionary(dict, "stats"), &ps->stats_in, s);
	ng_stats(bencode_dictionary_add_dictionary(dict, "stats_out"), &ps->stats_out, NULL);
}

#define BF_M(k, f) if (MEDIA_ISSET(m, f)) bencode_list_add_string(flags, k)

static void ng_stats_media(bencode_item_t *list, const struct call_media *m,
		struct call_stats *totals)
{
	bencode_item_t *dict, *streams = NULL, *flags;
	GList *l;
	struct packet_stream *ps;
	const struct rtp_payload_type *rtp_pt = NULL;

	if (!list)
		goto stats;

	rtp_pt = __rtp_stats_codec((struct call_media *)m);

	dict = bencode_list_add_dictionary(list);

	bencode_dictionary_add_integer(dict, "index", m->index);
	bencode_dictionary_add_str(dict, "type", &m->type);
	if (m->protocol)
		bencode_dictionary_add_string(dict, "protocol", m->protocol->name);
	if (rtp_pt)
		bencode_dictionary_add_str_dup(dict, "codec", &rtp_pt->encoding_with_params);

	streams = bencode_dictionary_add_list(dict, "streams");

	flags = bencode_dictionary_add_list(dict, "flags");

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
	BF_M("unidirectional", UNIDIRECTIONAL);
	BF_M("loop check", LOOP_CHECK);
	BF_M("generator/sink", GENERATOR);

stats:
	for (l = m->streams.head; l; l = l->next) {
		ps = l->data;
		ng_stats_stream(streams, ps, totals);
	}
}

static void ng_stats_monologue(bencode_item_t *dict, const struct call_monologue *ml,
		struct call_stats *totals, bencode_item_t *ssrc)
{
	bencode_item_t *sub, *medias = NULL;
	struct call_media *m;

	if (!ml)
		return;

	if (!dict)
		goto stats;

	if (ml->tag.len)
		sub = bencode_dictionary_add_dictionary(dict, ml->tag.s);
	else {
		char *buf = bencode_buffer_alloc(dict->buffer, 32);
		snprintf(buf, 32, "<untagged %u>", ml->unique_id);
		sub = bencode_dictionary_add_dictionary(dict, buf);
	}

	bencode_dictionary_add_str(sub, "tag", &ml->tag);
	if (ml->viabranch.s)
		bencode_dictionary_add_str(sub, "via-branch", &ml->viabranch);
	if (ml->label.s)
		bencode_dictionary_add_str(sub, "label", &ml->label);
	bencode_dictionary_add_integer(sub, "created", ml->created);
	bencode_item_t *subs = bencode_dictionary_add_list(sub, "subscriptions");
	for (GList *l = ml->subscriptions.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		bencode_item_t *sub1 = bencode_list_add_dictionary(subs);
		bencode_dictionary_add_str(sub1, "tag", &cs->monologue->tag);
		bencode_dictionary_add_string(sub1, "type", cs->attrs.offer_answer ? "offer/answer" : "pub/sub");
	}
	subs = bencode_dictionary_add_list(sub, "subscribers");
	for (GList *l = ml->subscribers.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		bencode_item_t *sub1 = bencode_list_add_dictionary(subs);
		bencode_dictionary_add_str(sub1, "tag", &cs->monologue->tag);
		bencode_dictionary_add_string(sub1, "type", cs->attrs.offer_answer ? "offer/answer" : "pub/sub");
	}
	ng_stats_ssrc(ssrc, ml->ssrc_hash);

	medias = bencode_dictionary_add_list(sub, "medias");

stats:
	for (unsigned int i = 0; i < ml->medias->len; i++) {
		m = ml->medias->pdata[i];
		if (!m)
			continue;
		ng_stats_media(medias, m, totals);
	}
}

static void ng_stats_ssrc_mos_entry_common(bencode_item_t *subent, struct ssrc_stats_block *sb,
		unsigned int div)
{
	bencode_dictionary_add_integer(subent, "MOS", sb->mos / div);
	bencode_dictionary_add_integer(subent, "round-trip time", sb->rtt / div);
	bencode_dictionary_add_integer(subent, "round-trip time leg", sb->rtt_leg / div);
	bencode_dictionary_add_integer(subent, "jitter", sb->jitter / div);
	bencode_dictionary_add_integer(subent, "packet loss", sb->packetloss / div);
}
static void ng_stats_ssrc_mos_entry(bencode_item_t *subent, struct ssrc_stats_block *sb) {
	ng_stats_ssrc_mos_entry_common(subent, sb, 1);
	bencode_dictionary_add_integer(subent, "reported at", sb->reported.tv_sec);
}
static void ng_stats_ssrc_mos_entry_dict(bencode_item_t *ent, const char *label, struct ssrc_stats_block *sb) {
	bencode_item_t *subent = bencode_dictionary_add_dictionary(ent, label);
	ng_stats_ssrc_mos_entry(subent, sb);
}
static void ng_stats_ssrc_mos_entry_dict_avg(bencode_item_t *ent, const char *label, struct ssrc_stats_block *sb,
		unsigned int div)
{
	bencode_item_t *subent = bencode_dictionary_add_dictionary(ent, label);
	ng_stats_ssrc_mos_entry_common(subent, sb, div);
	bencode_dictionary_add_integer(subent, "samples", div);
}

static void ng_stats_ssrc(bencode_item_t *dict, struct ssrc_hash *ht) {
	GList *ll = g_hash_table_get_values(ht->ht);

	for (GList *l = ll; l; l = l->next) {
		struct ssrc_entry_call *se = l->data;
		char *tmp = bencode_buffer_alloc(dict->buffer, 12);
		snprintf(tmp, 12, "%" PRIu32, se->h.ssrc);
		if (bencode_dictionary_get(dict, tmp))
			continue;
		if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
			continue;

		bencode_item_t *ent = bencode_dictionary_add_dictionary(dict, tmp);

		bencode_dictionary_add_integer(ent, "cumulative loss", se->packets_lost);

		int mos_samples = se->stats_blocks.length - se->no_mos_count;
		if (mos_samples < 1) mos_samples = 1;
		ng_stats_ssrc_mos_entry_dict_avg(ent, "average MOS", &se->average_mos, mos_samples);
		ng_stats_ssrc_mos_entry_dict(ent, "lowest MOS", se->lowest_mos);
		ng_stats_ssrc_mos_entry_dict(ent, "highest MOS", se->highest_mos);

		bencode_item_t *progdict = bencode_dictionary_add_dictionary(ent, "MOS progression");
		// aim for about 10 entries to the list
		GList *listent = se->stats_blocks.head;
		struct ssrc_stats_block *sb = listent->data;
		int interval
			= ((struct ssrc_stats_block *) se->stats_blocks.tail->data)->reported.tv_sec
			- sb->reported.tv_sec;
		interval /= 10;
		bencode_dictionary_add_integer(progdict, "interval", interval);
		time_t next_step = sb->reported.tv_sec;
		bencode_item_t *entlist = bencode_dictionary_add_list(progdict, "entries");

		for (; listent; listent = listent->next) {
			sb = listent->data;
			if (sb->reported.tv_sec < next_step)
				continue;
			next_step += interval;
			bencode_item_t *cent = bencode_list_add_dictionary(entlist);
			ng_stats_ssrc_mos_entry(cent, sb);
		}
	}

	g_list_free(ll);
}

/* call must be locked */
void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output,
		struct call_stats *totals)
{
	bencode_item_t *tags = NULL, *dict;
	const str *match_tag;
	GList *l;
	struct call_monologue *ml;
	struct call_stats t_b;
	bencode_item_t *ssrc = NULL;

	if (!totals)
		totals = &t_b;
	ZERO(*totals);

	if (!output)
		goto stats;

	call_bencode_hold_ref(call, output);

	bencode_dictionary_add_integer(output, "created", call->created.tv_sec);
	bencode_dictionary_add_integer(output, "created_us", call->created.tv_usec);
	bencode_dictionary_add_integer(output, "last signal", call->last_signal);
	ssrc = bencode_dictionary_add_dictionary(output, "SSRC");

	tags = bencode_dictionary_add_dictionary(output, "tags");

stats:
	match_tag = (totag && totag->s && totag->len) ? totag : fromtag;

	if (!match_tag || !match_tag->len) {
		for (l = call->monologues.head; l; l = l->next) {
			ml = l->data;
			ng_stats_monologue(tags, ml, totals, ssrc);
		}
	}
	else {
		ml = call_get_monologue(call, match_tag);
		if (ml) {
			ng_stats_monologue(tags, ml, totals, ssrc);
			for (GList *k = ml->subscriptions.head; k; k = k->next) {
				struct call_subscription *cs = k->data;
				ng_stats_monologue(tags, cs->monologue, totals, ssrc);
			}
		}
	}

	if (!output)
		return;

	dict = bencode_dictionary_add_dictionary(output, "totals");
	ng_stats(bencode_dictionary_add_dictionary(dict, "RTP"), &totals->totals[0], NULL);
	ng_stats(bencode_dictionary_add_dictionary(dict, "RTCP"), &totals->totals[1], NULL);
}

static void ng_list_calls(bencode_item_t *output, long long int limit) {
	GHashTableIter iter;
	gpointer key, value;

	rwlock_lock_r(&rtpe_callhash_lock);

	g_hash_table_iter_init (&iter, rtpe_callhash);
	while (limit-- && g_hash_table_iter_next (&iter, &key, &value)) {
		bencode_list_add_str_dup(output, key);
	}

	rwlock_unlock_r(&rtpe_callhash_lock);
}



const char *call_query_ng(bencode_item_t *input, bencode_item_t *output) {
	str callid, fromtag, totag;
	struct call *call;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get_opmode(&callid, OP_OTHER);
	if (!call)
		return "Unknown call-id";
	bencode_dictionary_get_str(input, "from-tag", &fromtag);
	bencode_dictionary_get_str(input, "to-tag", &totag);

	ng_call_stats(call, &fromtag, &totag, output, NULL);
	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}


const char *call_list_ng(bencode_item_t *input, bencode_item_t *output) {
	bencode_item_t *calls = NULL;
	long long int limit;

	limit = bencode_dictionary_get_int_str(input, "limit", 32);

	if (limit < 0) {
		return "invalid limit, must be >= 0";
	}
	calls = bencode_dictionary_add_list(output, "calls");

	ng_list_calls(calls, limit);

	return NULL;
}


static const char *call_recording_common_ng(bencode_item_t *input, bencode_item_t *output,
		void (*fn)(bencode_item_t *input, struct call *call))
{
	str callid, fromtag;
	struct call *call;
	str metadata;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	bencode_dictionary_get_str(input, "metadata", &metadata);
	call = call_get_opmode(&callid, OP_OTHER);
	if (!call)
		return "Unknown call-id";

	struct call_monologue *ml = NULL;

	if (bencode_dictionary_get_str(input, "from-tag", &fromtag)) {
		if (fromtag.s) {
			ml = call_get_monologue(call, &fromtag);
			if (!ml)
				ilog(LOG_WARN, "Given from-tag " STR_FORMAT_M " not found", STR_FMT_M(&fromtag));
		}
	}

	if (ml)
		update_metadata_monologue(ml, &metadata);
	else
		update_metadata_call(call, &metadata);

	fn(input, call);

	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}


static void start_recording_fn(bencode_item_t *input, struct call *call) {
	str output_dest;
	bencode_dictionary_get_str(input, "output-destination", &output_dest);
	call->recording_on = 1;
	recording_start(call, NULL, &output_dest);
}
const char *call_start_recording_ng(bencode_item_t *input, bencode_item_t *output) {
	return call_recording_common_ng(input, output, start_recording_fn);
}


static void pause_recording_fn(bencode_item_t *input, struct call *call) {
	call->recording_on = 0;
	recording_pause(call);
}
const char *call_pause_recording_ng(bencode_item_t *input, bencode_item_t *output) {
	return call_recording_common_ng(input, output, pause_recording_fn);
}


static void stop_recording_fn(bencode_item_t *input, struct call *call) {
	// support alternative usage for "pause" call: either `pause=yes` ...
	str pause;
	if (bencode_dictionary_get_str(input, "pause", &pause)) {
		if (!str_cmp(&pause, "yes") || !str_cmp(&pause, "on") || !str_cmp(&pause, "true")) {
			pause_recording_fn(input, call);
			return;
		}
	}
	// ... or `flags=[pause]`
	bencode_item_t *item = bencode_dictionary_get(input, "flags");
	if (item && item->type == BENCODE_LIST && item->child) {
		for (bencode_item_t *child = item->child; child; child = child->sibling) {
			if (bencode_strcmp(child, "pause") == 0) {
				pause_recording_fn(input, call);
				return;
			}
			if (bencode_strcmp(child, "discard-recording") == 0) {
				recording_discard(call);
				return;
			}
		}
	}

	call->recording_on = 0;
	recording_stop(call);
}
const char *call_stop_recording_ng(bencode_item_t *input, bencode_item_t *output) {
	return call_recording_common_ng(input, output, stop_recording_fn);
}


static const char *media_block_match1(struct call *call, struct call_monologue **monologue,
		struct sdp_ng_flags *flags)
{
	if (flags->label.s) {
		*monologue = g_hash_table_lookup(call->labels, &flags->label);
		if (!*monologue)
			return "No monologue matching the given label";
	}
	else if (flags->address.s) {
		sockaddr_t addr;
		if (sockaddr_parse_any_str(&addr, &flags->address))
			return "Failed to parse network address";
		// walk our structures to find a matching stream
		for (GList *l = call->monologues.head; l; l = l->next) {
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
	else if (flags->from_tag.s) {
		*monologue = call_get_monologue(call, &flags->from_tag);
		if (!*monologue)
			return "From-tag given, but no such tag exists";
	}
	if (*monologue)
		__monologue_unkernelize(*monologue, "media blocking signalling event");
	return NULL;
}
static const char *media_block_match(struct call **call, struct call_monologue **monologue,
		struct sdp_ng_flags *flags, bencode_item_t *input, enum call_opmode opmode)
{
	*call = NULL;
	*monologue = NULL;

	call_ng_process_flags(flags, input, opmode);

	if (!flags->call_id.s)
		return "No call-id in message";
	*call = call_get_opmode(&flags->call_id, opmode);
	if (!*call)
		return "Unknown call-ID";

	// directional?
	if (flags->all == ALL_ALL) // explicitly non-directional, so skip the rest
		return NULL;

	const char *err = media_block_match1(*call, monologue, flags);
	if (err)
		return err;

	// for generic ops, handle set-label here if given
	if (opmode == OP_OTHER && flags->set_label.len && *monologue) {
		call_str_cpy(*call, &(*monologue)->label, &flags->set_label);
		g_hash_table_replace((*call)->labels, &(*monologue)->label, *monologue);
	}

	return NULL;
}
static void add_ml_to_sub_list(GQueue *q, struct call_monologue *ml) {
	struct call_subscription *cs = g_slice_alloc0(sizeof(*cs));
	cs->monologue = ml;
	g_queue_push_tail(q, cs);
}
static const char *media_block_match_mult(struct call **call, GQueue *mls,
		struct sdp_ng_flags *flags, bencode_item_t *input, enum call_opmode opmode)
{
	call_ng_process_flags(flags, input, opmode);

	if (!flags->call_id.s)
		return "No call-id in message";
	*call = call_get_opmode(&flags->call_id, opmode);
	if (!*call)
		return "Unknown call-ID";

	if (flags->all == ALL_ALL) {
		// get and add all offer/answer mls
		for (GList *l = (*call)->monologues.head; l; l = l->next) {
			struct call_monologue *ml = l->data;
			if (ml->tagtype != FROM_TAG && ml->tagtype != TO_TAG)
				continue;
			add_ml_to_sub_list(mls, ml);
		}
		return NULL;
	}

	// is a single ml given?
	struct call_monologue *ml = NULL;
	const char *err = media_block_match1(*call, &ml, flags);
	if (err)
		return err;
	if (ml) {
		add_ml_to_sub_list(mls, ml);
		return NULL;
	}

	// handle from-tag list
	for (GList *l = flags->from_tags.head; l; l = l->next) {
		str *s = l->data;
		struct call_monologue *mlf = call_get_monologue(*call, s);
		if (!mlf)
			ilog(LOG_WARN, "Given from-tag " STR_FORMAT_M " not found", STR_FMT_M(s));
		else
			add_ml_to_sub_list(mls, mlf);
	}

	if (!mls->length)
		return "No monologues matched";

	return NULL;
}

// XXX these are all identical - unify and use a flags int and/or callback
const char *call_start_forwarding_ng(bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	struct call_monologue *monologue;
	const char *errstr = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	errstr = media_block_match(&call, &monologue, &flags, input, OP_OTHER);
	if (errstr)
		return errstr;

	if (monologue) {
		ilog(LOG_INFO, "Start forwarding for single party (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->rec_forwarding = 1;
	}
	else {
		ilog(LOG_INFO, "Start forwarding (entire call)");
		call->rec_forwarding = 1;
	}

	if (monologue)
		update_metadata_monologue(monologue, &flags.metadata);
	else
		update_metadata_call(call, &flags.metadata);

	recording_start(call, NULL, NULL);
	return NULL;
}

const char *call_stop_forwarding_ng(bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	struct call_monologue *monologue;
	const char *errstr = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	errstr = media_block_match(&call, &monologue, &flags, input, OP_OTHER);
	if (errstr)
		return errstr;

	if (monologue) {
		ilog(LOG_INFO, "Stop forwarding for single party (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->rec_forwarding = 0;
	}
	else {
		ilog(LOG_INFO, "Stop forwarding (entire call)");
		call->rec_forwarding = 0;
		if (flags.all == ALL_ALL) {
			for (GList *l = call->monologues.head; l; l = l->next) {
				monologue = l->data;
				monologue->rec_forwarding = 0;
			}
		}
	}

	if (monologue)
		update_metadata_monologue(monologue, &flags.metadata);
	else
		update_metadata_call(call, &flags.metadata);

	recording_stop(call);

	return NULL;
}

static void call_monologue_set_block_mode(struct call_monologue *ml, struct sdp_ng_flags *flags) {
	if (flags->delay_buffer >= 0) {
		for (unsigned int i = 0; i < ml->medias->len; i++) {
			struct call_media *media = ml->medias->pdata[i];
			if (!media)
				continue;
			media->buffer_delay = flags->delay_buffer;
		}
	}
	ml->detect_dtmf = flags->detect_dtmf;

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

	call_str_cpy(ml->call, &ml->dtmf_trigger, &flags->trigger);
	call_str_cpy(ml->call, &ml->dtmf_trigger_end, &flags->trigger_end);
	ml->block_dtmf_trigger = flags->block_dtmf_mode_trigger;
	ml->dtmf_trigger_match = 0;
	ml->dtmf_trigger_digits = flags->trigger_end_digits;
	ml->block_dtmf_trigger_end_ms = flags->trigger_end_ms;
	ml->dtmf_delay = flags->dtmf_delay;

	codec_update_all_handlers(ml);
}
const char *call_block_dtmf_ng(bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	struct call_monologue *monologue;
	const char *errstr = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	errstr = media_block_match(&call, &monologue, &flags, input, OP_OTHER);
	if (errstr)
		return errstr;

	enum block_dtmf_mode mode = BLOCK_DTMF_DROP;
	// special case default: if there's a trigger, default block mode is none
	if (flags.block_dtmf_mode_trigger || flags.trigger.len)
		mode = BLOCK_DTMF_OFF;
	if (flags.block_dtmf_mode)
		mode = flags.block_dtmf_mode;

	if (monologue) {
		ilog(LOG_INFO, "Blocking directional DTMF (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->block_dtmf = mode;
	}
	else {
		ilog(LOG_INFO, "Blocking DTMF (entire call)");
		call->block_dtmf = mode;
	}

	if (is_dtmf_replace_mode(mode) || flags.delay_buffer >= 0 || flags.trigger.len) {
		if (monologue)
			call_monologue_set_block_mode(monologue, &flags);
		else {
			for (GList *l = call->monologues.head; l; l = l->next) {
				struct call_monologue *ml = l->data;
				call_monologue_set_block_mode(ml, &flags);
			}
		}
	}

	return NULL;
}

const char *call_unblock_dtmf_ng(bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	struct call_monologue *monologue;
	const char *errstr = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	errstr = media_block_match(&call, &monologue, &flags, input, OP_OTHER);
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
			monologue->detect_dtmf = flags.detect_dtmf;
			codec_update_all_handlers(monologue);
		}
	}
	else {
		ilog(LOG_INFO, "Unblocking DTMF (entire call)");
		enum block_dtmf_mode prev_mode = call->block_dtmf;
		call->block_dtmf = BLOCK_DTMF_OFF;
		if (flags.all == ALL_ALL || is_dtmf_replace_mode(prev_mode) || flags.delay_buffer >= 0) {
			for (GList *l = call->monologues.head; l; l = l->next) {
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
				monologue->detect_dtmf = flags.detect_dtmf;
				if (is_dtmf_replace_mode(prev_ml_mode) || is_dtmf_replace_mode(prev_mode)
						|| flags.delay_buffer >= 0)
					codec_update_all_handlers(monologue);
			}
		}
	}

	return NULL;
}

static const char *call_block_silence_media(bencode_item_t *input, bool on_off, const char *ucase_verb,
		const char *lcase_verb,
		size_t call_offset, size_t ml_offset, size_t attr_offset)
{
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	struct call_monologue *monologue;
	const char *errstr = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	errstr = media_block_match(&call, &monologue, &flags, input, OP_OTHER);
	if (errstr)
		return errstr;

	if (monologue) {
		AUTO_CLEANUP(GQueue sinks, g_queue_clear) = G_QUEUE_INIT;
		if (flags.to_tag.len) {
			struct call_monologue *sink = g_hash_table_lookup(call->tags, &flags.to_tag);
			if (!sink) {
				ilog(LOG_WARN, "Media flow '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' doesn't "
						"exist for media %s (to-tag not found)",
						STR_FMT_M(&monologue->tag), STR_FMT_M(&flags.to_tag),
						lcase_verb);
				return "Media flow not found (to-tag not found)";
			}
			g_queue_push_tail(&sinks, sink);
		}
		else if (flags.to_label.len) {
			struct call_monologue *sink = g_hash_table_lookup(call->labels, &flags.to_label);
			if (!sink) {
				ilog(LOG_WARN, "Media flow '" STR_FORMAT_M "' -> label '" STR_FORMAT "' doesn't "
						"exist for media %s (to-label not found)",
						STR_FMT_M(&monologue->tag), STR_FMT(&flags.to_label),
						lcase_verb);
				return "Media flow not found (to-label not found)";
			}
			g_queue_push_tail(&sinks, sink);
		}
		else if (flags.all == ALL_OFFER_ANSWER || flags.all == ALL_NON_OFFER_ANSWER
				|| flags.all == ALL_FLOWS)
		{
			for (GList *l = monologue->subscribers.head; l; l = l->next) {
				struct call_subscription *cs = l->data;
				if (flags.all == ALL_OFFER_ANSWER && !cs->attrs.offer_answer)
					continue;
				else if (flags.all == ALL_NON_OFFER_ANSWER && cs->attrs.offer_answer)
					continue;
				g_queue_push_tail(&sinks, cs->monologue);
			}
			if (!sinks.length) {
				ilog(LOG_WARN, "No eligible subscriptions found for '" STR_FORMAT_M "' "
						"for media %s",
						STR_FMT_M(&monologue->tag),
						lcase_verb);
				return "No eligible subscriptions found";
			}
		}
		if (sinks.length) {
			for (GList *l = sinks.head; l; l = l->next) {
				struct call_monologue *sink = l->data;
				GList *link = g_hash_table_lookup(monologue->subscribers_ht, sink);
				if (!link) {
					ilog(LOG_WARN, "Media flow '" STR_FORMAT_M "' -> '" STR_FORMAT_M "' doesn't "
							"exist for media %s (to-tag not subscribed)",
							STR_FMT_M(&monologue->tag), STR_FMT_M(&flags.to_tag),
							lcase_verb);
					return "Media flow not found (to-tag not subscribed)";
				}
				struct call_subscription *cs = link->data;

				ilog(LOG_INFO, "%s directional media flow "
						"(tag '" STR_FORMAT_M "' -> '" STR_FORMAT_M "')",
						ucase_verb,
						STR_FMT_M(&monologue->tag), STR_FMT_M(&sink->tag));
				G_STRUCT_MEMBER(bool, &cs->attrs, attr_offset) = on_off;
			}
			update_init_subscribers(monologue, OP_OTHER);
		}
		else {
			ilog(LOG_INFO, "%s directional media (tag '" STR_FORMAT_M "')",
					ucase_verb,
					STR_FMT_M(&monologue->tag));
			G_STRUCT_MEMBER(bool, monologue, ml_offset) = on_off;
		}
		__monologue_unkernelize(monologue, "media silencing signalling event");
	}
	else {
		G_STRUCT_MEMBER(bool, call, call_offset) = on_off;
		if (!on_off) {
			ilog(LOG_INFO, "%s media (entire call and participants)", ucase_verb);
			if (flags.all == ALL_ALL) {
				for (GList *l = call->monologues.head; l; l = l->next) {
					monologue = l->data;
					G_STRUCT_MEMBER(bool, monologue, ml_offset) = on_off;
				}
			}
		}
		else
			ilog(LOG_INFO, "%s media (entire call)", ucase_verb);
		__call_unkernelize(call, "media silencing signalling event");
	}

	return NULL;
}

#define CALL_BLOCK_SILENCE_MEDIA(input, on_off, ucase_verb, lcase_verb, member_name) \
	call_block_silence_media(input, on_off, ucase_verb, lcase_verb, \
			G_STRUCT_OFFSET(struct call, member_name), \
			G_STRUCT_OFFSET(struct call_monologue, member_name), \
			G_STRUCT_OFFSET(struct sink_attrs, member_name))

const char *call_block_media_ng(bencode_item_t *input, bencode_item_t *output) {
	return CALL_BLOCK_SILENCE_MEDIA(input, true, "Blocking", "blocking", block_media);
}
const char *call_unblock_media_ng(bencode_item_t *input, bencode_item_t *output) {
	return CALL_BLOCK_SILENCE_MEDIA(input, false, "Unblocking", "unblocking", block_media);
}
const char *call_silence_media_ng(bencode_item_t *input, bencode_item_t *output) {
	return CALL_BLOCK_SILENCE_MEDIA(input, true, "Silencing", "silencing", silence_media);
}
const char *call_unsilence_media_ng(bencode_item_t *input, bencode_item_t *output) {
	return CALL_BLOCK_SILENCE_MEDIA(input, false, "Unsilencing", "unsilencing", silence_media);
}


#ifdef WITH_TRANSCODING
static const char *play_media_select_party(struct call **call, GQueue *monologues,
		bencode_item_t *input, struct sdp_ng_flags *flags)
{
	struct call_monologue *monologue;

	g_queue_init(monologues);

	const char *err = media_block_match(call, &monologue, flags, input, OP_OTHER);
	if (err)
		return err;
	if (flags->all == ALL_ALL)
		g_queue_append(monologues, &(*call)->monologues);
	else if (!monologue)
		return "No participant party specified";
	else
		g_queue_push_tail(monologues, monologue);
	return NULL;
}
#endif


const char *call_play_media_ng(bencode_item_t *input, bencode_item_t *output) {
#ifdef WITH_TRANSCODING
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	AUTO_CLEANUP(GQueue monologues, g_queue_clear);
	const char *err = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	err = play_media_select_party(&call, &monologues, input, &flags);
	if (err)
		return err;

	flags.opmode = OP_PLAY_MEDIA;

	for (GList *l = monologues.head; l; l = l->next) {
		struct call_monologue *monologue = l->data;

		// if mixing is enabled, codec handlers of all sources must be updated
		codec_update_all_source_handlers(monologue, &flags);
		// this starts the audio player if needed
		update_init_subscribers(monologue, OP_PLAY_MEDIA);
		// media_player_new() now knows that audio player is in use

		// TODO: player options can have changed if already exists
		if (!monologue->player)
			monologue->player = media_player_new(monologue);
		if (flags.repeat_times <= 0)
			flags.repeat_times = 1;

		if (flags.file.len) {
			if (media_player_play_file(monologue->player, &flags.file, flags.repeat_times, flags.start_pos))
				return "Failed to start media playback from file";
		}
		else if (flags.blob.len) {
			if (media_player_play_blob(monologue->player, &flags.blob, flags.repeat_times, flags.start_pos))
				return "Failed to start media playback from blob";
		}
		else if (flags.db_id > 0) {
			if (media_player_play_db(monologue->player, flags.db_id, flags.repeat_times, flags.start_pos))
				return "Failed to start media playback from database";
		}
		else
			return "No media file specified";

		if (l == monologues.head && monologue->player->coder.duration)
			bencode_dictionary_add_integer(output, "duration", monologue->player->coder.duration);

	}

	return NULL;
#else
	return "unsupported";
#endif
}


const char *call_stop_media_ng(bencode_item_t *input, bencode_item_t *output) {
#ifdef WITH_TRANSCODING
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	AUTO_CLEANUP(GQueue monologues, g_queue_clear);
	const char *err = NULL;
	long long last_frame_pos = 0;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	err = play_media_select_party(&call, &monologues, input, &flags);
	if (err)
		return err;

	for (GList *l = monologues.head; l; l = l->next) {
		struct call_monologue *monologue = l->data;

		if (!monologue->player)
			return "Not currently playing media";

		last_frame_pos = media_player_stop(monologue->player);

		// restore to non-mixing if needed
		codec_update_all_source_handlers(monologue, NULL);
		update_init_subscribers(monologue, OP_OTHER);
	}
	bencode_dictionary_add_integer(output, "last-frame-pos", last_frame_pos);

	return NULL;
#else
	return "unsupported";
#endif
}


const char *call_play_dtmf_ng(bencode_item_t *input, bencode_item_t *output) {
#ifdef WITH_TRANSCODING
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	AUTO_CLEANUP(GQueue monologues, g_queue_clear);
	const char *err = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);

	err = play_media_select_party(&call, &monologues, input, &flags);
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

	for (GList *l = monologues.head; l; l = l->next) {
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
		monologue->dtmf_injection_active = 1;
		dialogue_unkernelize(monologue, "DTMF playback");

		for (GList *k = monologue->subscribers.head; k; k = k->next) {
			struct call_subscription *cs = k->data;
			struct call_monologue *dialogue = cs->monologue;
			struct call_media *sink = NULL;
			for (unsigned int i = 0; i < dialogue->medias->len; i++) {
				sink = dialogue->medias->pdata[i];
				if (!sink)
					continue;
				if (sink->type_id != MT_AUDIO)
					continue;
				goto found_sink;
			}

			return "Sink monologue has no media capable of DTMF playback";

found_sink:
			err = dtmf_inject(media, code, flags.volume, flags.duration, flags.pause, sink);
			if (err)
				return err;
		}
	}

	return NULL;
#else
	return "unsupported";
#endif
}


const char *call_publish_ng(struct ng_buffer *ngbuf, bencode_item_t *input, bencode_item_t *output,
		const char *addr,
		const endpoint_t *sin)
{
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	AUTO_CLEANUP(GQueue parsed, sdp_free) = G_QUEUE_INIT;
	AUTO_CLEANUP(GQueue streams, sdp_streams_free) = G_QUEUE_INIT;
	AUTO_CLEANUP(str sdp_in, str_free_dup) = STR_NULL;
	AUTO_CLEANUP(str sdp_out, str_free_dup) = STR_NULL;
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);

	call_ng_process_flags(&flags, input, OP_PUBLISH);

	if (!flags.sdp.s)
		return "No SDP body in message";
	if (!flags.call_id.s)
		return "No call-id in message";
	if (!flags.from_tag.s)
		return "No from-tag in message";

	str_init_dup_str(&sdp_in, &flags.sdp);

	if (sdp_parse(&sdp_in, &parsed, &flags))
		return "Failed to parse SDP";
	if (sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	call = call_get_or_create(&flags.call_id, false, false);

	if (trickle_ice_update(ngbuf, call, &flags, &streams))
		return NULL;

	updated_created_from(call, addr, sin);
	struct call_monologue *ml = call_get_or_create_monologue(call, &flags.from_tag);

	int ret = monologue_publish(ml, &streams, &flags);
	if (ret)
		ilog(LOG_ERR, "Publish error"); // XXX close call? handle errors?

	ret = sdp_create(&sdp_out, ml, &flags);
	if (!ret) {
		save_last_sdp(ml, &sdp_in, &parsed, &streams);
		bencode_buffer_destroy_add(output->buffer, g_free, sdp_out.s);
		bencode_dictionary_add_str(output, "sdp", &sdp_out);
		sdp_out = STR_NULL; // ownership passed to output
	}

	if (ret)
		return "Failed to create SDP";

	dequeue_sdp_fragments(ml);

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_subscribe_request_ng(bencode_item_t *input, bencode_item_t *output) {
	const char *err = NULL;
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	char rand_buf[65];
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);
	AUTO_CLEANUP(GQueue srcs, call_subscriptions_clear) = G_QUEUE_INIT;
	AUTO_CLEANUP(str sdp_out, str_free_dup) = STR_NULL;

	// get source monologue
	err = media_block_match_mult(&call, &srcs, &flags, input, OP_REQUEST);
	if (err)
		return err;

	if (flags.sdp.len)
		ilog(LOG_INFO, "Subscribe-request with SDP received - ignoring SDP");

	if (!srcs.length)
		return "No call participant specified";

	// special case with just one source: we can use the original SDP
	struct call_monologue *sdp_ml = NULL;
	if (srcs.length == 1) {
		struct call_subscription *cs = srcs.head->data;
		sdp_ml = cs->monologue;
		if (!sdp_ml->last_in_sdp.len || !sdp_ml->last_in_sdp_parsed.length)
			sdp_ml = NULL;
	}

	// the `label=` option was possibly used above to select the from-tag --
	// switch it out with `to-label=` or `set-label=` for monologue_subscribe_request
	// below which sets the label based on `label` for a newly created monologue
	flags.label = flags.to_label;
	if (flags.set_label.len) // set-label takes priority
		flags.label = flags.set_label;

	// get destination monologue
	if (!flags.to_tag.len) {
		// generate one
		flags.to_tag = STR_CONST_INIT(rand_buf);
		rand_hex_str(flags.to_tag.s, flags.to_tag.len / 2);
	}
	struct call_monologue *dest_ml = call_get_or_create_monologue(call, &flags.to_tag);

	// rewrite SDP, or create new?
	struct sdp_chopper *chopper = NULL;
	if (sdp_ml) {
		chopper = sdp_chopper_new(&sdp_ml->last_in_sdp);
		bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);
	}

	int ret = monologue_subscribe_request(&srcs, dest_ml, &flags);
	if (ret)
		return "Failed to request subscription";

	if (chopper && sdp_ml) {
		ret = sdp_replace(chopper, &sdp_ml->last_in_sdp_parsed, dest_ml, &flags);
		if (ret)
			return "Failed to rewrite SDP";
	}
	else {
		// create new SDP
		ret = sdp_create(&sdp_out, dest_ml, &flags);
	}

	// place return output SDP
	if (chopper) {
		if (chopper->output->len)
			bencode_dictionary_add_string_len(output, "sdp", chopper->output->str,
					chopper->output->len);
	}
	else if (sdp_out.len) {
		bencode_buffer_destroy_add(output->buffer, g_free, sdp_out.s);
		bencode_dictionary_add_str(output, "sdp", &sdp_out);
		sdp_out = STR_NULL; // ownership passed to output
	}

	// add single response ml tag if there's just one, but always add a list
	if (srcs.length == 1) {
		struct call_subscription *cs = srcs.head->data;
		struct call_monologue *source_ml = cs->monologue;
		bencode_dictionary_add_str_dup(output, "from-tag", &source_ml->tag);
	}
	bencode_item_t *tag_medias = NULL, *media_labels = NULL;
	if (flags.siprec) {
		tag_medias = bencode_dictionary_add_list(output, "tag-medias");
		media_labels = bencode_dictionary_add_dictionary(output, "media-labels");
	}
	bencode_item_t *from_list = bencode_dictionary_add_list(output, "from-tags");
	for (GList *l = srcs.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		struct call_monologue *source_ml = cs->monologue;
		bencode_list_add_str_dup(from_list, &source_ml->tag);
		if (tag_medias) {
			bencode_item_t *tag_label = bencode_list_add_dictionary(tag_medias);
			bencode_dictionary_add_str(tag_label, "tag", &source_ml->tag);
			if (source_ml->label.len)
				bencode_dictionary_add_str(tag_label, "label", &source_ml->label);
			bencode_item_t *medias = bencode_dictionary_add_list(tag_label, "medias");
			for (unsigned int i = 0; i < source_ml->medias->len; i++) {
				struct call_media *media = source_ml->medias->pdata[i];
				if (!media)
					continue;
				bencode_item_t *med_ent = bencode_list_add_dictionary(medias);
				bencode_dictionary_add_integer(med_ent, "index", media->index);
				bencode_dictionary_add_str(med_ent, "type", &media->type);
				bencode_dictionary_add_str(med_ent, "label", &media->label);
				bencode_dictionary_add_string(med_ent, "mode", sdp_get_sendrecv(media));

				if (media_labels) {
					bencode_item_t *label =
						bencode_dictionary_add_dictionary(media_labels, media->label.s);
					bencode_dictionary_add_str(label, "tag", &source_ml->tag);
					bencode_dictionary_add_integer(label, "index", media->index);
					bencode_dictionary_add_str(label, "type", &media->type);
					if (source_ml->label.len)
						bencode_dictionary_add_str(label, "label", &source_ml->label);
					bencode_dictionary_add_string(label, "mode", sdp_get_sendrecv(media));
				}
			}
		}
	}

	bencode_dictionary_add_str_dup(output, "to-tag", &dest_ml->tag);

	dequeue_sdp_fragments(dest_ml);

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_subscribe_answer_ng(struct ng_buffer *ngbuf, bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	AUTO_CLEANUP(GQueue parsed, sdp_free) = G_QUEUE_INIT;
	AUTO_CLEANUP(GQueue streams, sdp_streams_free) = G_QUEUE_INIT;
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);

	call_ng_process_flags(&flags, input, OP_REQ_ANSWER);

	if (!flags.call_id.s)
		return "No call-id in message";
	call = call_get_opmode(&flags.call_id, OP_REQ_ANSWER);
	if (!call)
		return "Unknown call-ID";

	if (trickle_ice_update(ngbuf, call, &flags, &streams))
		return NULL;

	if (!flags.to_tag.s)
		return "No to-tag in message";
	if (!flags.sdp.len)
		return "No SDP body in message";

	// get destination monologue
	struct call_monologue *dest_ml = call_get_monologue(call, &flags.to_tag);
	if (!dest_ml)
		return "To-tag not found";

	if (sdp_parse(&flags.sdp, &parsed, &flags))
		return "Failed to parse SDP";
	if (sdp_streams(&parsed, &streams, &flags))
		return "Incomplete SDP specification";

	int ret = monologue_subscribe_answer(dest_ml, &flags, &streams);
	if (ret)
		return "Failed to process subscription answer";

	call_unlock_release_update(&call);

	return NULL;
}


const char *call_unsubscribe_ng(bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP(struct sdp_ng_flags flags, call_ng_free_flags);
	AUTO_CLEANUP_NULL(struct call *call, call_unlock_release);

	call_ng_process_flags(&flags, input, OP_REQ_ANSWER);

	if (!flags.call_id.s)
		return "No call-id in message";
	call = call_get_opmode(&flags.call_id, OP_REQ_ANSWER);
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


void call_interfaces_free() {
	if (info_re) {
		pcre_free(info_re);
		info_re = NULL;
	}

	if (streams_re) {
		pcre_free(streams_re);
		streams_re= NULL;
	}

	if (info_ree) {
		pcre_free_study(info_ree);
		info_ree = NULL;
	}

	if (streams_ree) {
		pcre_free_study(streams_ree);
		streams_ree = NULL;
	}
}

int call_interfaces_init() {
	const char *errptr;
	int erroff;

	info_re = pcre_compile("^([^:,]+)(?::(.*?))?(?:$|,)", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!info_re)
		return -1;
	info_ree = pcre_study(info_re, 0, &errptr);

	streams_re = pcre_compile("^([\\d.]+):(\\d+)(?::(.*?))?(?:$|,)", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!streams_re)
		return -1;
	streams_ree = pcre_study(streams_re, 0, &errptr);

	return 0;
}
