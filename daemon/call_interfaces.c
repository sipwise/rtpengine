#include "call_interfaces.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <pcre.h>

#include "call.h"
#include "aux.h"
#include "log.h"
#include "redis.h"
#include "sdp.h"
#include "bencode.h"
#include "str.h"
#include "control_tcp.h"
#include "control_udp.h"




static int call_stream_address_gstring(GString *o, struct packet_stream *ps, enum stream_address_format format) {
	int len, ret;
	char buf[64]; /* 64 bytes ought to be enough for anybody */

	ret = call_stream_address(buf, ps, format, &len);
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

	for (i = start; i < end; i++) {
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

		port = ps->sfd ? ps->sfd->fd.localport : 0;
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
	u_int32_t ip4;
	const char *cp;
	char c;
	int i;

	ZERO(*sp);
	if (out[RE_UDP_UL_ADDR4] && *out[RE_UDP_UL_ADDR4]) {
		ip4 = inet_addr(out[RE_UDP_UL_ADDR4]);
		if (ip4 == -1)
			goto fail;
		in4_to_6(&sp->rtp_endpoint.ip46, ip4);
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (inet_pton(AF_INET6, out[RE_UDP_UL_ADDR6], &sp->rtp_endpoint.ip46) != 1)
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
				sp->direction[i++] = DIR_EXTERNAL;
			else if (c == 'I')
				sp->direction[i++] = DIR_INTERNAL;
		}
	}

	if (out[RE_UDP_UL_NUM] && *out[RE_UDP_UL_NUM])
		sp->index = atoi(out[RE_UDP_UL_NUM]);
	if (!sp->index)
		sp->index = 1;
	sp->consecutive_ports = 1;

	return 0;
fail:
	return -1;
}

static str *call_update_lookup_udp(char **out, struct callmaster *m, enum call_opmode opmode) {
	struct call *c;
	struct call_monologue *monologue;
	GQueue q = G_QUEUE_INIT;
	struct stream_params sp;
	str *ret, callid, viabranch, fromtag, totag = STR_NULL;

	str_init(&callid, out[RE_UDP_UL_CALLID]);
	str_init(&viabranch, out[RE_UDP_UL_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_UL_FROMTAG]);
	if (opmode == OP_ANSWER)
		str_init(&totag, out[RE_UDP_UL_TOTAG]);

	c = call_get_opmode(&callid, m, opmode);
	if (!c) {
		ilog(LOG_WARNING, "["STR_FORMAT"] Got UDP LOOKUP for unknown call-id",
			STR_FMT(&callid));
		return str_sprintf("%s 0 " IPF "\n", out[RE_UDP_COOKIE], IPP(m->conf.ipv4));
	}
	monologue = call_get_mono_dialogue(c, &fromtag, &totag);
	if (!monologue)
		goto ml_fail;

	if (addr_parse_udp(&sp, out))
		goto addr_fail;

	g_queue_push_tail(&q, &sp);
	/* XXX return value */
	monologue_offer_answer(monologue, &q, NULL);
	g_queue_clear(&q);

	ret = streams_print(&monologue->medias, sp.index, sp.index, out[RE_UDP_COOKIE], SAF_UDP);
	rwlock_unlock_w(&c->master_lock);

	redis_update(c, m->conf.redis);

	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT(ret));
	goto out;

ml_fail:
	rwlock_unlock_w(&c->master_lock);
	ilog(LOG_WARNING, "Invalid dialogue association");
	goto fail_out;

addr_fail:
	rwlock_unlock_w(&c->master_lock);
	ilog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	goto fail_out;

fail_out:
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	obj_put(c);
	return ret;
}

str *call_update_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_OFFER);
}
str *call_lookup_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_ANSWER);
}


static int info_parse_func(char **a, void **ret, void *p) {
	GHashTable *ih = p;

	g_hash_table_replace(ih, a[0], a[1]);

	return -1;
}

static void info_parse(const char *s, GHashTable *ih, struct callmaster *m) {
	pcre_multi_match(m->info_re, m->info_ree, s, 2, info_parse_func, ih, NULL);
}


static int streams_parse_func(char **a, void **ret, void *p) {
	struct stream_params *sp;
	u_int32_t ip;
	int *i;

	i = p;
	sp = g_slice_alloc0(sizeof(*sp));

	ip = inet_addr(a[0]);
	if (ip == -1)
		goto fail;

	in4_to_6(&sp->rtp_endpoint.ip46, ip);
	sp->rtp_endpoint.port = atoi(a[1]);
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

static void streams_free(GQueue *q) {
	struct stream_params *s;

	while ((s = g_queue_pop_head(q))) {
		if (s->crypto.mki)
			free(s->crypto.mki);
		g_slice_free1(sizeof(*s), s);
	}
}



static str *call_request_lookup_tcp(char **out, struct callmaster *m, enum call_opmode opmode) {
	struct call *c;
	struct call_monologue *monologue;
	GQueue s = G_QUEUE_INIT;
	str *ret = NULL, callid, fromtag, totag = STR_NULL;
	GHashTable *infohash;

	str_init(&callid, out[RE_TCP_RL_CALLID]);
	infohash = g_hash_table_new(g_str_hash, g_str_equal);
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
	if (opmode == OP_ANSWER) {
		str_init(&totag, g_hash_table_lookup(infohash, "totag"));
		if (!totag.s) {
			ilog(LOG_WARNING, "No to-tag in message");
			goto out2;
		}
	}

	monologue = call_get_mono_dialogue(c, &fromtag, &totag);
	if (!monologue) {
		ilog(LOG_WARNING, "Invalid dialogue association");
		goto out2;
	}
	/* XXX return value */
	monologue_offer_answer(monologue, &s, NULL);

	ret = streams_print(&monologue->medias, 1, s.length, NULL, SAF_TCP);

out2:
	rwlock_unlock_w(&c->master_lock);
	streams_free(&s);

	redis_update(c, m->conf.redis);

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

	if (call_delete_branch(m, &callid, &branch, &fromtag, &totag, NULL))
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

	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) m->conf.silent_timeout - (poller_now - stats.last_packet),
		stats.totals[0].packets, stats.totals[1].packets,
		stats.totals[2].packets, stats.totals[3].packets);
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
	call_delete_branch(m, &callid, NULL, NULL, NULL, NULL);
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

	control_stream_printf(s, "session "STR_FORMAT" - - - - %i\n",
		STR_FMT(&c->callid),
		(int) (poller_now - c->created));

	/* XXX restore function */

//	mutex_unlock(&c->master_lock);
}

void calls_status_tcp(struct callmaster *m, struct control_stream *s) {
	struct stats st;
	GQueue q = G_QUEUE_INIT;
	struct call *c;

	mutex_lock(&m->statslock);
	st = m->stats;
	mutex_unlock(&m->statslock);

	callmaster_get_all_calls(m, &q);

	control_stream_printf(s, "proxy %u "UINT64F"/"UINT64F"/"UINT64F"\n",
		g_queue_get_length(&q),
		st.bytes, st.bytes - st.errors,
		st.bytes * 2 - st.errors);

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

static void call_ng_process_flags(struct sdp_ng_flags *out, bencode_item_t *input) {
	bencode_item_t *list, *it;
	int diridx;
	str s;

	ZERO(*out);

	if ((list = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "trust address"))
				out->trust_address = 1;
			else if (!bencode_strcmp(it, "asymmetric"))
				out->asymmetric = 1;
			else if (!bencode_strcmp(it, "trust-address"))
				out->trust_address = 1;
			else if (!bencode_strcmp(it, "strict source"))
				out->strict_source = 1;
			else if (!bencode_strcmp(it, "media handover"))
				out->media_handover = 1;
		}
	}

	if ((list = bencode_dictionary_get_expect(input, "replace", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "origin"))
				out->replace_origin = 1;
			else if (!bencode_strcmp(it, "session connection"))
				out->replace_sess_conn = 1;
			else if (!bencode_strcmp(it, "session-connection"))
				out->replace_sess_conn = 1;
		}
	}

	diridx = 0;
	if ((list = bencode_dictionary_get_expect(input, "direction", BENCODE_LIST))) {
		for (it = list->child; it && diridx < 2; it = it->sibling) {
			if (!bencode_strcmp(it, "internal"))
				out->directions[diridx++] = DIR_INTERNAL;
			else if (!bencode_strcmp(it, "external"))
				out->directions[diridx++] = DIR_EXTERNAL;
		}
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
		else if (!str_cmp(&s, "force_relay"))
			out->ice_force_relay = 1;
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
		}
	}

	bencode_dictionary_get_str(input, "transport protocol", &out->transport_protocol_str);
	if (!out->transport_protocol_str.s)
		bencode_dictionary_get_str(input, "transport-protocol", &out->transport_protocol_str);
	out->transport_protocol = transport_protocol(&out->transport_protocol_str);
	bencode_dictionary_get_str(input, "media address", &out->media_address);
	if (bencode_dictionary_get_str(input, "address family", &out->address_family_str))
		out->address_family = address_family(&out->address_family_str);
}

static const char *call_offer_answer_ng(bencode_item_t *input, struct callmaster *m,
		bencode_item_t *output, enum call_opmode opmode)
{
	str sdp, fromtag, totag = STR_NULL, callid;
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
	if (opmode == OP_ANSWER) {
		if (!bencode_dictionary_get_str(input, "to-tag", &totag))
			return "No to-tag in message";
	}
	//bencode_dictionary_get_str(input, "via-branch", &viabranch);

	if (sdp_parse(&sdp, &parsed))
		return "Failed to parse SDP";

	call_ng_process_flags(&flags, input);
	flags.opmode = opmode;

	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, &flags))
		goto out;

	call = call_get_opmode(&callid, m, opmode);
	errstr = "Unknown call-id";
	if (!call)
		goto out;

	/* At least the random ICE strings are contained within the call struct, so we
	 * need to hold a ref until we're done sending the reply */
	call_bencode_hold_ref(call, output);

	monologue = call_get_mono_dialogue(call, &fromtag, &totag);
	errstr = "Invalid dialogue association";
	if (!monologue) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
		goto out;
	}

	chopper = sdp_chopper_new(&sdp);
	bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);
	/* XXX return value */
	monologue_offer_answer(monologue, &streams, &flags);
	ret = sdp_replace(chopper, &parsed, monologue, &flags);

	rwlock_unlock_w(&call->master_lock);
	redis_update(call, m->conf.redis);
	obj_put(call);

	errstr = "Error rewriting SDP";
	if (ret)
		goto out;

	bencode_dictionary_add_iovec(output, "sdp", &g_array_index(chopper->iov, struct iovec, 0),
		chopper->iov_num, chopper->str_len);
	bencode_dictionary_add_string(output, "result", "ok");

	errstr = NULL;
out:
	sdp_free(&parsed);
	streams_free(&streams);

	return errstr;
}

const char *call_offer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_OFFER);
}

const char *call_answer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_ANSWER);
}

const char *call_delete_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str fromtag, totag, viabranch, callid;
	bencode_item_t *flags, *it;
	int fatal = 0;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	if (!bencode_dictionary_get_str(input, "from-tag", &fromtag))
		return "No from-tag in message";
	bencode_dictionary_get_str(input, "to-tag", &totag);
	bencode_dictionary_get_str(input, "via-branch", &viabranch);

	flags = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST);
	if (flags) {
		for (it = flags->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "fatal"))
				fatal = 1;
		}
	}

	if (call_delete_branch(m, &callid, &viabranch, &fromtag, &totag, output)) {
		if (fatal)
			return "Call-ID not found or tags didn't match";
		bencode_dictionary_add_string(output, "warning", "Call-ID not found or tags didn't match");
	}

	bencode_dictionary_add_string(output, "result", "ok");
	return NULL;
}

static void ng_stats(bencode_item_t *d, const struct stats *s, struct stats *totals) {
	bencode_dictionary_add_integer(d, "packets", s->packets);
	bencode_dictionary_add_integer(d, "bytes", s->bytes);
	bencode_dictionary_add_integer(d, "errors", s->errors);
	if (!totals)
		return;
	totals->packets += s->packets;
	totals->bytes += s->bytes;
	totals->errors += s->errors;
}

static void ng_stats_endpoint(bencode_item_t *dict, const struct endpoint *ep) {
	char buf[64];

	if (IN6_IS_ADDR_V4MAPPED(&ep->ip46)) {
		bencode_dictionary_add_string(dict, "family", "IPv4");
		inet_ntop(AF_INET, &(ep->ip46.s6_addr32[3]), buf, sizeof(buf));
	}
	else {
		bencode_dictionary_add_string(dict, "family", "IPv6");
		inet_ntop(AF_INET6, &ep->ip46, buf, sizeof(buf));
	}
	bencode_dictionary_add_string_dup(dict, "address", buf);
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

	if (ps->sfd)
		bencode_dictionary_add_integer(dict, "local port", ps->sfd->fd.localport);
	ng_stats_endpoint(bencode_dictionary_add_dictionary(dict, "endpoint"), &ps->endpoint);
	ng_stats_endpoint(bencode_dictionary_add_dictionary(dict, "advertised endpoint"),
			&ps->advertised_endpoint);
	if (ps->crypto.params.crypto_suite)
		bencode_dictionary_add_string(dict, "crypto suite",
				ps->crypto.params.crypto_suite->name);
	bencode_dictionary_add_integer(dict, "last packet", ps->last_packet);

	flags = bencode_dictionary_add_list(dict, "flags");

	BF_PS("RTP", RTP);
	BF_PS("RTCP", RTCP);
	BF_PS("fallback RTCP", FALLBACK_RTCP);
	BF_PS("filled", FILLED);
	BF_PS("confirmed", CONFIRMED);
	BF_PS("kernelized", KERNELIZED);
	BF_PS("no kernel support", NO_KERNEL_SUPPORT);

stats:
	if (totals->last_packet < ps->last_packet)
		totals->last_packet = ps->last_packet;

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
	BF_M("rtcp-mux", RTCP_MUX);
	BF_M("DTLS-SRTP", DTLS);
	BF_M("SDES", SDES);
	BF_M("passthrough", PASSTHRU);
	BF_M("ICE", ICE);

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

/* call must be locked */
void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output,
		struct call_stats *totals)
{
	bencode_item_t *tags = NULL, *dict;
	const str *match_tag;
	GSList *l;
	struct call_monologue *ml;
	struct call_stats t_b;

	if (!totals)
		totals = &t_b;
	ZERO(*totals);

	if (!output)
		goto stats;

	call_bencode_hold_ref(call, output);

	bencode_dictionary_add_integer(output, "created", call->created);
	bencode_dictionary_add_integer(output, "last_signal", call->last_signal);

	tags = bencode_dictionary_add_dictionary(output, "tags");

stats:
	match_tag = (totag && totag->s && totag->len) ? totag : fromtag;

	if (!match_tag) {
		for (l = call->monologues; l; l = l->next) {
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

	bencode_dictionary_add_string(output, "result", "ok");
	ng_call_stats(call, &fromtag, &totag, output, NULL);
	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}
