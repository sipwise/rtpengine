#include "call_interfaces.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <pcre.h>
#include <inttypes.h>

#include "call_interfaces.h"
#include "call.h"
#include "aux.h"
#include "log.h"
#include "redis.h"
#include "sdp.h"
#include "bencode.h"
#include "str.h"
#include "control_tcp.h"
#include "control_udp.h"
#include "rtp.h"
#include "ice.h"
#include "recording.h"
#include "rtplib.h"
#include "ssrc.h"



int trust_address_def;
int dtls_passive_def;


static int call_stream_address_gstring(GString *o, struct packet_stream *ps, enum stream_address_format format) {
	int len, ret;
	char buf[64]; /* 64 bytes ought to be enough for anybody */

	ret = call_stream_address46(buf, ps, format, &len, NULL);
	g_string_append_len(o, buf, len);
	return ret;
}

static str *streams_print(GQueue *s, int start, int end, const char *prefix, enum stream_address_format format) {
	GString *o;
	int i, af, port;
	GList *l;
	struct call_media *media;
	struct packet_stream *ps;

	o = g_string_new_str();
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	for (i = start; i <= end; i++) {
		for (l = s->head; l; l = l->next) {
			media = l->data;
			if (media->index == i)
				goto found;
		}
		ilog(LOG_WARNING, "Requested media index %i not found", i);
		goto out;

found:
		if (!media->streams.head) {
			ilog(LOG_WARNING, "Media has no streams");
			goto out;
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

out:
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
	sp->protocol = &transport_protocols[PROTO_RTP_AVP];

	if (out[RE_UDP_UL_ADDR4] && *out[RE_UDP_UL_ADDR4]) {
		if (sockaddr_parse_any(&sp->rtp_endpoint.address, out[RE_UDP_UL_ADDR4]))
			goto fail;
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (sockaddr_parse_any(&sp->rtp_endpoint.address, out[RE_UDP_UL_ADDR4]))
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

static str *call_update_lookup_udp(char **out, struct callmaster *m, enum call_opmode opmode, const char* addr,
		const endpoint_t *sin)
{
	struct call *c;
	struct call_monologue *monologue;
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

	c = call_get_opmode(&callid, m, opmode);
	if (!c) {
		ilog(LOG_WARNING, "["STR_FORMAT"] Got UDP LOOKUP for unknown call-id",
			STR_FMT(&callid));
		return str_sprintf("%s 0 0.0.0.0\n", out[RE_UDP_COOKIE]);
	}

	if (!c->created_from && addr) {
		c->created_from = call_strdup(c, addr);
		c->created_from_addr = sin->address;
	}

	monologue = call_get_mono_dialogue(c, &fromtag, &totag, NULL);
	if (!monologue)
		goto ml_fail;

	if (opmode == OP_OFFER) {
		monologue->tagtype = FROM_TAG;
	} else {
		monologue->tagtype = TO_TAG;
	}

	if (addr_parse_udp(&sp, out))
		goto addr_fail;

	g_queue_push_tail(&q, &sp);
	i = monologue_offer_answer(monologue, &q, NULL);
	g_queue_clear(&q);

	if (i)
		goto unlock_fail;

	ret = streams_print(&monologue->active_dialogue->medias,
			sp.index, sp.index, out[RE_UDP_COOKIE], SAF_UDP);
	rwlock_unlock_w(&c->master_lock);

	redis_update_onekey(c, m->conf.redis_write);

	gettimeofday(&(monologue->started), NULL);

	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT(ret));
	goto out;

ml_fail:
	ilog(LOG_ERR, "Invalid dialogue association");
	goto unlock_fail;

addr_fail:
	ilog(LOG_ERR, "Failed to parse a media stream: %s/%s:%s",
			out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	goto unlock_fail;

unlock_fail:
	rwlock_unlock_w(&c->master_lock);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	obj_put(c);
	return ret;
}

str *call_update_udp(char **out, struct callmaster *m, const char* addr, const endpoint_t *sin) {
	return call_update_lookup_udp(out, m, OP_OFFER, addr, sin);
}
str *call_lookup_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_ANSWER, NULL, NULL);
}


static int info_parse_func(char **a, void **ret, void *p) {
	GHashTable *ih = p;

	g_hash_table_replace(ih, strdup(a[0]), strdup(a[1]));

	return -1;
}

static void info_parse(const char *s, GHashTable *ih, struct callmaster *m) {
	pcre_multi_match(m->info_re, m->info_ree, s, 2, info_parse_func, ih, NULL);
}


static int streams_parse_func(char **a, void **ret, void *p) {
	struct stream_params *sp;
	int *i;

	i = p;
	sp = g_slice_alloc0(sizeof(*sp));

	SP_SET(sp, SEND);
	SP_SET(sp, RECV);
	sp->protocol = &transport_protocols[PROTO_RTP_AVP];

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
	ilog(LOG_WARNING, "Failed to parse a media stream: %s:%s", a[0], a[1]);
	g_slice_free1(sizeof(*sp), sp);
	return -1;
}


static void streams_parse(const char *s, struct callmaster *m, GQueue *q) {
	int i;
	i = 0;
	pcre_multi_match(m->streams_re, m->streams_ree, s, 3, streams_parse_func, &i, q);
}

/* XXX move these somewhere else */
static void rtp_pt_free(void *p) {
	g_slice_free1(sizeof(struct rtp_payload_type), p);
}
static void sp_free(void *p) {
	struct stream_params *s = p;

	if (s->crypto.mki)
		free(s->crypto.mki);
	g_queue_clear_full(&s->rtp_payload_types, rtp_pt_free);
	ice_candidates_free(&s->ice_candidates);
	g_slice_free1(sizeof(*s), s);
}
static void streams_free(GQueue *q) {
	g_queue_clear_full(q, sp_free);
}



static str *call_request_lookup_tcp(char **out, struct callmaster *m, enum call_opmode opmode) {
	struct call *c;
	struct call_monologue *monologue;
	GQueue s = G_QUEUE_INIT;
	str *ret = NULL, callid, fromtag, totag = STR_NULL;
	GHashTable *infohash;

	str_init(&callid, out[RE_TCP_RL_CALLID]);
	infohash = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	c = call_get_opmode(&callid, m, opmode);
	if (!c) {
		ilog(LOG_WARNING, "["STR_FORMAT"] Got LOOKUP for unknown call-id", STR_FMT(&callid));
		goto out;
	}

	info_parse(out[RE_TCP_RL_INFO], infohash, m);
	streams_parse(out[RE_TCP_RL_STREAMS], m, &s);
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

	monologue = call_get_mono_dialogue(c, &fromtag, &totag, NULL);
	if (!monologue) {
		ilog(LOG_WARNING, "Invalid dialogue association");
		goto out2;
	}
	if (monologue_offer_answer(monologue, &s, NULL))
		goto out2;

	ret = streams_print(&monologue->active_dialogue->medias, 1, s.length, NULL, SAF_TCP);

out2:
	rwlock_unlock_w(&c->master_lock);
	streams_free(&s);

	redis_update_onekey(c, m->conf.redis_write);

	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT0(ret));
	obj_put(c);

out:
	g_hash_table_destroy(infohash);
	return ret;
}

str *call_request_tcp(char **out, struct callmaster *m) {
	return call_request_lookup_tcp(out, m, OP_OFFER);
}
str *call_lookup_tcp(char **out, struct callmaster *m) {
	return call_request_lookup_tcp(out, m, OP_ANSWER);
}

str *call_delete_udp(char **out, struct callmaster *m) {
	str callid, branch, fromtag, totag;

	__C_DBG("got delete for callid '%s' and viabranch '%s'",
		out[RE_UDP_DQ_CALLID], out[RE_UDP_DQ_VIABRANCH]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&branch, out[RE_UDP_DQ_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	if (call_delete_branch(m, &callid, &branch, &fromtag, &totag, NULL, -1))
		return str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);

	return str_sprintf("%s 0\n", out[RE_UDP_COOKIE]);
}
str *call_query_udp(char **out, struct callmaster *m) {
	struct call *c;
	str *ret, callid, fromtag, totag;
	struct call_stats stats;

	__C_DBG("got query for callid '%s'", out[RE_UDP_DQ_CALLID]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	c = call_get_opmode(&callid, m, OP_OTHER);
	if (!c) {
		ilog(LOG_INFO, "["STR_FORMAT"] Call-ID to query not found", STR_FMT(&callid));
		goto err;
	}

	ng_call_stats(c, &fromtag, &totag, NULL, &stats);

	rwlock_unlock_w(&c->master_lock);

	rwlock_lock_r(&m->conf.config_lock);
	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) m->conf.silent_timeout - (poller_now - stats.last_packet),
		atomic64_get_na(&stats.totals[0].packets), atomic64_get_na(&stats.totals[1].packets),
		atomic64_get_na(&stats.totals[2].packets), atomic64_get_na(&stats.totals[3].packets));
	rwlock_unlock_r(&m->conf.config_lock);
	goto out;

err:
	if (c)
		rwlock_unlock_w(&c->master_lock);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	if (c)
		obj_put(c);
	return ret;
}

void call_delete_tcp(char **out, struct callmaster *m) {
	str callid;

	str_init(&callid, out[RE_TCP_D_CALLID]);
	call_delete_branch(m, &callid, NULL, NULL, NULL, NULL, -1);
}

static void call_status_iterator(struct call *c, struct control_stream *s) {
//	GList *l;
//	struct callstream *cs;
//	struct peer *p;
//	struct streamrelay *r1, *r2;
//	struct streamrelay *rx1, *rx2;
//	struct callmaster *m;
//	char addr1[64], addr2[64], addr3[64];

//	m = c->callmaster;
//	mutex_lock(&c->master_lock);

	control_stream_printf(s, "session "STR_FORMAT" - - - - %lli\n",
		STR_FMT(&c->callid),
		timeval_diff(&g_now, &c->created) / 1000000);

	/* XXX restore function */

//	mutex_unlock(&c->master_lock);
}

void calls_status_tcp(struct callmaster *m, struct control_stream *s) {
	GQueue q = G_QUEUE_INIT;
	struct call *c;

	callmaster_get_all_calls(m, &q);

	control_stream_printf(s, "proxy %u "UINT64F"/%i/%i\n",
		g_queue_get_length(&q),
		atomic64_get(&m->stats.bytes), 0, 0);

	while (q.head) {
		c = g_queue_pop_head(&q);
		call_status_iterator(c, s);
		obj_put(c);
	}
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

INLINE void str_hyphenate(bencode_item_t *it) {
	str s;
	if (!bencode_get_str(it, &s))
		return;
	while (s.len) {
		str_chr_str(&s, &s, ' ');
		if (!s.s || !s.len)
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

INLINE void ng_sdes_option(struct sdp_ng_flags *out, bencode_item_t *it, unsigned int strip) {
	str s;

	if (!bencode_get_str(it, &s))
		return;
	str_shift(&s, strip);

	if (!str_cmp(&s, "no") || !str_cmp(&s, "off") || !str_cmp(&s, "disabled")
			|| !str_cmp(&s, "disable"))
		out->sdes_off = 1;
	else if (!str_cmp(&s, "unencrypted_srtp") || !str_cmp(&s, "UNENCRYPTED_SRTP"))
		out->sdes_unencrypted_srtp = 1;
	else if (!str_cmp(&s, "unencrypted_srtcp") || !str_cmp(&s, "UNENCRYPTED_SRTCP"))
		out->sdes_unencrypted_srtcp = 1;
	else if (!str_cmp(&s, "unauthenticated_srtp") || !str_cmp(&s, "UNAUTHENTICATED_SRTP"))
		out->sdes_unauthenticated_srtp = 1;
	else if (!str_cmp(&s, "encrypted_srtp") || !str_cmp(&s, "ENCRYPTED_SRTP"))
		out->sdes_encrypted_srtp = 1;
	else if (!str_cmp(&s, "encrypted_srtcp") || !str_cmp(&s, "ENCRYPTED_SRTCP"))
		out->sdes_encrypted_srtcp = 1;
	else if (!str_cmp(&s, "authenticated_srtp") || !str_cmp(&s, "AUTHENTICATED_SRTP"))
		out->sdes_authenticated_srtp = 1;
	else
		ilog(LOG_WARN, "Unknown 'SDES' flag encountered: '"STR_FORMAT"'",
				STR_FMT(&s));
}

static void call_ng_process_flags(struct sdp_ng_flags *out, bencode_item_t *input) {
	bencode_item_t *list, *it;
	int diridx;
	str s;

	ZERO(*out);

	out->trust_address = trust_address_def;
	out->dtls_passive = dtls_passive_def;

	if ((list = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (it->type !=  BENCODE_STRING)
				continue;

			str_hyphenate(it);

			if (!bencode_strcmp(it, "trust-address"))
				out->trust_address = 1;
			else if (!bencode_strcmp(it, "SIP-source-address"))
				out->trust_address = 0;
			else if (!bencode_strcmp(it, "asymmetric"))
				out->asymmetric = 1;
			else if (!bencode_strcmp(it, "no-redis-update"))
				out->no_redis_update = 1;
			else if (!bencode_strcmp(it, "unidirectional"))
				out->unidirectional = 1;
			else if (!bencode_strcmp(it, "strict-source"))
				out->strict_source = 1;
			else if (!bencode_strcmp(it, "media-handover"))
				out->media_handover = 1;
			else if (!bencode_strcmp(it, "reset"))
				out->reset = 1;
			else if (it->iov[1].iov_len >= 5 && !memcmp(it->iov[1].iov_base, "SDES-", 5))
				ng_sdes_option(out, it, 5);
			else if (!bencode_strcmp(it, "port-latching"))
				out->port_latching = 1;
			else if (!bencode_strcmp(it, "record-call"))
				out->record_call = 1;
			else
				ilog(LOG_WARN, "Unknown flag encountered: '"BENCODE_FORMAT"'",
						BENCODE_FMT(it));
		}
	}

	if ((list = bencode_dictionary_get_expect(input, "replace", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			str_hyphenate(it);
			if (!bencode_strcmp(it, "origin"))
				out->replace_origin = 1;
			else if (!bencode_strcmp(it, "session-connection"))
				out->replace_sess_conn = 1;
			else
				ilog(LOG_WARN, "Unknown 'replace' flag encountered: '"BENCODE_FORMAT"'",
						BENCODE_FMT(it));
		}
	}

	diridx = 0;
	if ((list = bencode_dictionary_get_expect(input, "direction", BENCODE_LIST))) {
		for (it = list->child; it && diridx < 2; it = it->sibling)
			bencode_get_str(it, &out->direction[diridx++]);
	}

	list = bencode_dictionary_get_expect(input, "received from", BENCODE_LIST);
	if (!list)
		list = bencode_dictionary_get_expect(input, "received-from", BENCODE_LIST);
	if (list && (it = list->child)) {
		bencode_get_str(it, &out->received_from_family);
		bencode_get_str(it->sibling, &out->received_from_address);
	}

	if (bencode_dictionary_get_str(input, "ICE", &s)) {
		if (!str_cmp(&s, "remove"))
			out->ice_remove = 1;
		else if (!str_cmp(&s, "force"))
			out->ice_force = 1;
		else if (!str_cmp(&s, "force_relay") || !str_cmp(&s, "force-relay")
				|| !str_cmp(&s, "force relay"))
			out->ice_force_relay = 1;
		else
			ilog(LOG_WARN, "Unknown 'ICE' flag encountered: '"STR_FORMAT"'",
					STR_FMT(&s));
	}

	if (bencode_dictionary_get_str(input, "DTLS", &s)) {
		if (!str_cmp(&s, "passive"))
			out->dtls_passive = 1;
		else if (!str_cmp(&s, "no") || !str_cmp(&s, "off") || !str_cmp(&s, "disabled")
				|| !str_cmp(&s, "disable"))
			out->dtls_off = 1;
		else
			ilog(LOG_WARN, "Unknown 'DTLS' flag encountered: '"STR_FORMAT"'",
					STR_FMT(&s));
	}

	if ((list = bencode_dictionary_get_expect(input, "rtcp-mux", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "offer"))
				out->rtcp_mux_offer = 1;
			else if (!bencode_strcmp(it, "demux"))
				out->rtcp_mux_demux = 1;
			else if (!bencode_strcmp(it, "accept"))
				out->rtcp_mux_accept = 1;
			else if (!bencode_strcmp(it, "reject"))
				out->rtcp_mux_reject = 1;
			else
				ilog(LOG_WARN, "Unknown 'rtcp-mux' flag encountered: '"BENCODE_FORMAT"'",
						BENCODE_FMT(it));
		}
	}

	/* XXX abstractize the other list walking functions using callbacks */
	/* XXX module still needs to support this list */
	if ((list = bencode_dictionary_get_expect(input, "SDES", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling)
			ng_sdes_option(out, it, 0);
	}

	bencode_get_alt(input, "transport-protocol", "transport protocol", &out->transport_protocol_str);
	out->transport_protocol = transport_protocol(&out->transport_protocol_str);
	bencode_get_alt(input, "media-address", "media address", &out->media_address);
	if (bencode_get_alt(input, "address-family", "address family", &out->address_family_str))
		out->address_family = get_socket_family_rfc(&out->address_family_str);
	out->tos = bencode_dictionary_get_integer(input, "TOS", 256);
	bencode_get_alt(input, "record-call", "record call", &out->record_call_str);
	bencode_dictionary_get_str(input, "metadata", &out->metadata);
}

static const char *call_offer_answer_ng(bencode_item_t *input, struct callmaster *m,
		bencode_item_t *output, enum call_opmode opmode, const char* addr,
		const endpoint_t *sin)
{
	str sdp, fromtag, totag = STR_NULL, callid, viabranch;
	str label = STR_NULL;
	char *errstr;
	GQueue parsed = G_QUEUE_INIT;
	GQueue streams = G_QUEUE_INIT;
	struct call *call;
	struct call_monologue *monologue;
	int ret;
	struct sdp_ng_flags flags;
	struct sdp_chopper *chopper;

	if (!bencode_dictionary_get_str(input, "sdp", &sdp))
		return "No SDP body in message";
	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	if (!bencode_dictionary_get_str(input, "from-tag", &fromtag))
		return "No from-tag in message";
	bencode_dictionary_get_str(input, "to-tag", &totag);
	if (opmode == OP_ANSWER) {
		if (!totag.s)
			return "No to-tag in message";
		str_swap(&totag, &fromtag);
	}
	bencode_dictionary_get_str(input, "via-branch", &viabranch);
	bencode_dictionary_get_str(input, "label", &label);

	if (sdp_parse(&sdp, &parsed))
		return "Failed to parse SDP";

	call_ng_process_flags(&flags, input);
	flags.opmode = opmode;

	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, &flags))
		goto out;

	/* OP_ANSWER; OP_OFFER && !IS_FOREIGN_CALL */
	call = call_get(&callid, m);

    /* Failover scenario because of timeout on offer response: siprouter tries
     * to establish session with another rtpengine2 even though rtpengine1
     * might have persisted part of the session. rtpengine2 deletes previous
     * call in memory and recreates an OWN call in redis */
	if (opmode == OP_OFFER) {
        if (call) {
            if (IS_FOREIGN_CALL(call)) {
                /* destroy call and create new one */
                rwlock_unlock_w(&call->master_lock);
                call_destroy(call);
                obj_put(call);
                call = call_get_or_create(&callid, m, CT_OWN_CALL);
            }
        }
        else {
            /* call == NULL, should create call */
            call = call_get_or_create(&callid, m, CT_OWN_CALL);
        }
    }

	errstr = "Unknown call-id";
	if (!call)
		goto out;

	if (!call->created_from && addr) {
		call->created_from = call_strdup(call, addr);
		call->created_from_addr = sin->address;
	}
	/* At least the random ICE strings are contained within the call struct, so we
	 * need to hold a ref until we're done sending the reply */
	call_bencode_hold_ref(call, output);

	monologue = call_get_mono_dialogue(call, &fromtag, &totag, viabranch.s ? &viabranch : NULL);
	errstr = "Invalid dialogue association";
	if (!monologue) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
		goto out;
	}

	if (opmode == OP_OFFER) {
		monologue->tagtype = FROM_TAG;
	} else {
		monologue->tagtype = TO_TAG;
	}
	if (label.s && !monologue->label.s)
		call_str_cpy(call, &monologue->label, &label);

	chopper = sdp_chopper_new(&sdp);
	bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);

	detect_setup_recording(call, &flags.record_call_str);
	if (flags.record_call)
		recording_start(call, NULL);

	ret = monologue_offer_answer(monologue, &streams, &flags);
	if (!ret)
		ret = sdp_replace(chopper, &parsed, monologue->active_dialogue, &flags);

	struct iovec *sdp_iov = &g_array_index(chopper->iov, struct iovec, 0);

	struct recording *recording = call->recording;
	if (recording != NULL) {
		meta_write_sdp_before(recording, &sdp, monologue, opmode);
		meta_write_sdp_after(recording, sdp_iov, chopper->iov_num, chopper->str_len,
			       monologue, opmode);

		if (flags.metadata.len) {
			call_str_cpy(call, &recording->metadata, &flags.metadata);
			recording_meta_chunk(recording, "METADATA", &flags.metadata);
		}

		recording_response(recording, output);
	}

	rwlock_unlock_w(&call->master_lock);

	if (!flags.no_redis_update) {
			redis_update_onekey(call,m->conf.redis_write);
	} else {
		ilog(LOG_DEBUG, "Not updating Redis due to present no-redis-update flag");
	}
	obj_put(call);

	gettimeofday(&(monologue->started), NULL);

	errstr = "Error rewriting SDP";

	if (ret == ERROR_NO_FREE_PORTS || ret == ERROR_NO_FREE_LOGS) {
		ilog(LOG_ERR, "Destroying call");
		call_destroy(call);
	}

	if (ret)
		goto out;

	bencode_dictionary_add_iovec(output, "sdp", sdp_iov,
		chopper->iov_num, chopper->str_len);

	errstr = NULL;
out:
	sdp_free(&parsed);
	streams_free(&streams);

	return errstr;
}

const char *call_offer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output, const char* addr,
		const endpoint_t *sin)
{
	rwlock_lock_r(&m->conf.config_lock);
	if (m->conf.max_sessions>=0) {
		rwlock_lock_r(&m->hashlock);
		if (g_hash_table_size(m->callhash) -
				atomic64_get(&m->stats.foreign_sessions) >= m->conf.max_sessions) {
			rwlock_unlock_r(&m->hashlock);
			/* foreign calls can't get rejected
			 * total_rejected_sess applies only to "own" sessions */
			atomic64_inc(&m->totalstats.total_rejected_sess);
			atomic64_inc(&m->totalstats_interval.total_rejected_sess);
			ilog(LOG_ERROR, "Parallel session limit reached (%i)",m->conf.max_sessions);

			rwlock_unlock_r(&m->conf.config_lock);
			return "Parallel session limit reached";
		}
		rwlock_unlock_r(&m->hashlock);
	}

	rwlock_unlock_r(&m->conf.config_lock);
	return call_offer_answer_ng(input, m, output, OP_OFFER, addr, sin);
}

const char *call_answer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_ANSWER, NULL, NULL);
}

const char *call_delete_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str fromtag, totag, viabranch, callid;
	bencode_item_t *flags, *it;
	int fatal = 0, delete_delay;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	bencode_dictionary_get_str(input, "from-tag", &fromtag);
	bencode_dictionary_get_str(input, "to-tag", &totag);
	bencode_dictionary_get_str(input, "via-branch", &viabranch);

	flags = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST);
	if (flags) {
		for (it = flags->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "fatal"))
				fatal = 1;
		}
	}
	delete_delay = bencode_dictionary_get_integer(input, "delete-delay", -1);
	if (delete_delay == -1) {
		delete_delay = bencode_dictionary_get_integer(input, "delete delay", -1);
		if (delete_delay == -1) {
			/* legacy support */
			str s;
			bencode_dictionary_get_str(input, "delete-delay", &s);
			if (s.s)
				delete_delay = str_to_i(&s, -1);
		}
	}

	if (call_delete_branch(m, &callid, &viabranch, &fromtag, &totag, output, delete_delay)) {
		if (fatal)
			return "Call-ID not found or tags didn't match";
		bencode_dictionary_add_string(output, "warning", "Call-ID not found or tags didn't match");
	}

	return NULL;
}

static void ng_stats(bencode_item_t *d, const struct stats *s, struct stats *totals) {
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
	struct stats *s;

	if (!list)
		goto stats;

	dict = bencode_list_add_dictionary(list);

	if (ps->selected_sfd)
		bencode_dictionary_add_integer(dict, "local port", ps->selected_sfd->socket.local.port);
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

	if (ps->ssrc_in)
		bencode_dictionary_add_integer(dict, "SSRC", ps->ssrc_in->parent->ssrc);

stats:
	if (totals->last_packet < atomic64_get(&ps->last_packet))
		totals->last_packet = atomic64_get(&ps->last_packet);

	/* XXX distinguish between input and output */
	s = &totals->totals[0];
	if (!PS_ISSET(ps, RTP))
		s = &totals->totals[1];
	ng_stats(bencode_dictionary_add_dictionary(dict, "stats"), &ps->stats, s);
}

#define BF_M(k, f) if (MEDIA_ISSET(m, f)) bencode_list_add_string(flags, k)

static void ng_stats_media(bencode_item_t *list, const struct call_media *m,
		struct call_stats *totals)
{
	bencode_item_t *dict, *streams = NULL, *flags;
	GList *l;
	struct packet_stream *ps;

	if (!list)
		goto stats;

	dict = bencode_list_add_dictionary(list);

	bencode_dictionary_add_integer(dict, "index", m->index);
	bencode_dictionary_add_str(dict, "type", &m->type);
	if (m->protocol)
		bencode_dictionary_add_string(dict, "protocol", m->protocol->name);

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
	BF_M("ICE-lite", ICE_LITE);
	BF_M("unidirectional", UNIDIRECTIONAL);
	BF_M("loop check", LOOP_CHECK);

stats:
	for (l = m->streams.head; l; l = l->next) {
		ps = l->data;
		ng_stats_stream(streams, ps, totals);
	}
}

static void ng_stats_monologue(bencode_item_t *dict, const struct call_monologue *ml,
		struct call_stats *totals)
{
	bencode_item_t *sub, *medias = NULL;
	GList *l;
	struct call_media *m;

	if (!ml)
		return;

	if (!dict)
		goto stats;

	sub = bencode_dictionary_add_dictionary(dict, ml->tag.s);

	bencode_dictionary_add_str(sub, "tag", &ml->tag);
	if (ml->viabranch.s)
		bencode_dictionary_add_str(sub, "via-branch", &ml->viabranch);
	if (ml->label.s)
		bencode_dictionary_add_str(sub, "label", &ml->label);
	bencode_dictionary_add_integer(sub, "created", ml->created);
	if (ml->active_dialogue)
		bencode_dictionary_add_str(sub, "in dialogue with", &ml->active_dialogue->tag);

	medias = bencode_dictionary_add_list(sub, "medias");

stats:
	for (l = ml->medias.head; l; l = l->next) {
		m = l->data;
		ng_stats_media(medias, m, totals);
	}
}

static void ng_stats_ssrc_mos_entry_common(bencode_item_t *subent, struct ssrc_stats_block *sb,
		unsigned int div)
{
	bencode_dictionary_add_integer(subent, "MOS", sb->mos / div);
	bencode_dictionary_add_integer(subent, "round-trip time", sb->rtt / div);
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
		struct ssrc_entry *se = l->data;
		char *tmp = bencode_buffer_alloc(dict->buffer, 12);
		snprintf(tmp, 12, "%" PRIu32, se->ssrc);
		bencode_item_t *ent = bencode_dictionary_add_dictionary(dict, tmp);

		if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
			continue;

		ng_stats_ssrc_mos_entry_dict_avg(ent, "average MOS", &se->average_mos, se->stats_blocks.length);
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
			bencode_item_t *ent = bencode_list_add_dictionary(entlist);
			ng_stats_ssrc_mos_entry(ent, sb);
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

	if (!totals)
		totals = &t_b;
	ZERO(*totals);

	if (!output)
		goto stats;

	call_bencode_hold_ref(call, output);

	bencode_dictionary_add_integer(output, "created", call->created.tv_sec);
	bencode_dictionary_add_integer(output, "created_us", call->created.tv_usec);
	bencode_dictionary_add_integer(output, "last signal", call->last_signal);
	ng_stats_ssrc(bencode_dictionary_add_dictionary(output, "SSRC"), call->ssrc_hash);

	tags = bencode_dictionary_add_dictionary(output, "tags");

stats:
	match_tag = (totag && totag->s && totag->len) ? totag : fromtag;

	if (!match_tag || !match_tag->len) {
		for (l = call->monologues.head; l; l = l->next) {
			ml = l->data;
			ng_stats_monologue(tags, ml, totals);
		}
	}
	else {
		ml = g_hash_table_lookup(call->tags, match_tag);
		if (ml) {
			ng_stats_monologue(tags, ml, totals);
			ng_stats_monologue(tags, ml->active_dialogue, totals);
		}
	}

	if (!output)
		return;

	dict = bencode_dictionary_add_dictionary(output, "totals");
	ng_stats(bencode_dictionary_add_dictionary(dict, "RTP"), &totals->totals[0], NULL);
	ng_stats(bencode_dictionary_add_dictionary(dict, "RTCP"), &totals->totals[1], NULL);
}

static void ng_list_calls( struct callmaster *m, bencode_item_t *output, long long int limit) {
	GHashTableIter iter;
	gpointer key, value;

	rwlock_lock_r(&m->hashlock);

	g_hash_table_iter_init (&iter, m->callhash);
	while (limit-- && g_hash_table_iter_next (&iter, &key, &value)) {
		bencode_list_add_str_dup(output, key);
	}

	rwlock_unlock_r(&m->hashlock);
}



const char *call_query_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str callid, fromtag, totag;
	struct call *call;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get_opmode(&callid, m, OP_OTHER);
	if (!call)
		return "Unknown call-id";
	bencode_dictionary_get_str(input, "from-tag", &fromtag);
	bencode_dictionary_get_str(input, "to-tag", &totag);

	ng_call_stats(call, &fromtag, &totag, output, NULL);
	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}


const char *call_list_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	bencode_item_t *calls = NULL;
	long long int limit;

	limit = bencode_dictionary_get_integer(input, "limit", 32);

	if (limit < 0) {
		return "invalid limit, must be >= 0";
	}
	calls = bencode_dictionary_add_list(output, "calls");

	ng_list_calls(m, calls, limit);

	return NULL;
}


const char *call_start_recording_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str callid;
	struct call *call;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get_opmode(&callid, m, OP_OTHER);
	if (!call)
		return "Unknown call-id";

	recording_start(call, NULL);

	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}
