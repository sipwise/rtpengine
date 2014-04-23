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

	if (addr_parse_udp(&sp, out))
		goto fail;

	g_queue_push_tail(&q, &sp);
	/* XXX return value */
	monologue_offer_answer(monologue, &q, NULL);
	g_queue_clear(&q);

	ret = streams_print(&monologue->medias, sp.index, sp.index, out[RE_UDP_COOKIE], SAF_UDP);
	rwlock_unlock_w(&c->master_lock);

	redis_update(c, m->conf.redis);

	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT(ret));
	goto out;

fail:
	rwlock_unlock_w(&c->master_lock);
	ilog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
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
	/* XXX return value */
	monologue_offer_answer(monologue, &s, NULL);

	ret = streams_print(&monologue->medias, 1, s.length, NULL, SAF_TCP);
	rwlock_unlock_w(&c->master_lock);

out2:
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

	stats_query(c, &fromtag, &totag, &stats, NULL, NULL);

	rwlock_unlock_w(&c->master_lock);

	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) m->conf.silent_timeout - (poller_now - stats.newest),
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








static void call_ng_process_flags(struct sdp_ng_flags *out, bencode_item_t *input) {
	bencode_item_t *list, *it;
	int diridx;
	str s;

	ZERO(*out);

	if ((list = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "trust address"))
				out->trust_address = 1;
			else if (!bencode_strcmp(it, "symmetric"))
				out->symmetric = 1;
			else if (!bencode_strcmp(it, "asymmetric"))
				out->asymmetric = 1;
			else if (!bencode_strcmp(it, "trust-address"))
				out->trust_address = 1;
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

	monologue = call_get_mono_dialogue(call, &fromtag, &totag);

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

#if 0
static bencode_item_t *peer_address(bencode_buffer_t *b, struct stream *s) {
	bencode_item_t *d;
	char buf[64];

	d = bencode_dictionary(b);
	if (IN6_IS_ADDR_V4MAPPED(&s->ip46)) {
		bencode_dictionary_add_string(d, "family", "IPv4");
		inet_ntop(AF_INET, &(s->ip46.s6_addr32[3]), buf, sizeof(buf));
	}
	else {
		bencode_dictionary_add_string(d, "family", "IPv6");
		inet_ntop(AF_INET6, &s->ip46, buf, sizeof(buf));
	}
	bencode_dictionary_add_string_dup(d, "address", buf);
	bencode_dictionary_add_integer(d, "port", s->port);

	return d;
}
#endif

#if 0
static bencode_item_t *stats_encode(bencode_buffer_t *b, struct stats *s) {
	bencode_item_t *d;

	d = bencode_dictionary(b);
	bencode_dictionary_add_integer(d, "packets", s->packets);
	bencode_dictionary_add_integer(d, "bytes", s->bytes);
	bencode_dictionary_add_integer(d, "errors", s->errors);
	return d;
}
#endif

#if 0
static bencode_item_t *streamrelay_stats(bencode_buffer_t *b, struct packet_stream *ps) {
	bencode_item_t *d;

	d = bencode_dictionary(b);

	// XXX
	//bencode_dictionary_add(d, "counters", stats_encode(b, &r->stats));
	//bencode_dictionary_add(d, "peer address", peer_address(b, &r->peer));
	//bencode_dictionary_add(d, "advertised peer address", peer_address(b, &r->peer_advertised));

	bencode_dictionary_add_integer(d, "local port", ps->fd.localport);

	return d;
}
#endif

#if 0
static bencode_item_t *rtp_rtcp_stats(bencode_buffer_t *b, struct stats *rtp, struct stats *rtcp) {
	bencode_item_t *s;
	s = bencode_dictionary(b);
	bencode_dictionary_add(s, "rtp", stats_encode(b, rtp));
	bencode_dictionary_add(s, "rtcp", stats_encode(b, rtcp));
	return s;
}
#endif

#if 0
XXX
static bencode_item_t *peer_stats(bencode_buffer_t *b, struct peer *p) {
	bencode_item_t *d, *s;

	d = bencode_dictionary(b);

	bencode_dictionary_add_str_dup(d, "tag", &p->tag);
	if (p->codec)
		bencode_dictionary_add_string(d, "codec", p->codec);
	if (p->kernelized)
		bencode_dictionary_add_string(d, "status", "in kernel");
	else if (p->confirmed)
		bencode_dictionary_add_string(d, "status", "confirmed peer address");
	else if (p->filled)
		bencode_dictionary_add_string(d, "status", "known but unconfirmed peer address");
	else
		bencode_dictionary_add_string(d, "status", "unknown peer address");

	s = bencode_dictionary_add_dictionary(d, "stats");
	bencode_dictionary_add(s, "rtp", streamrelay_stats(b, &p->rtps[0]));
	bencode_dictionary_add(s, "rtcp", streamrelay_stats(b, &p->rtps[1]));

	return d;
}

static void ng_stats_cb(struct peer *p, struct peer *px, void *streams) {
	bencode_item_t *stream;

	stream = bencode_list_add_list(streams);
	bencode_list_add(stream, peer_stats(stream->buffer, p));
	bencode_list_add(stream, peer_stats(stream->buffer, px));
}
#endif

/* call must be locked */
void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output) {
	//bencode_item_t *streams, *dict;
//	struct call_stats stats;

//	bencode_dictionary_add_integer(output, "created", call->created);

	//streams = bencode_dictionary_add_list(output, "streams");
	//stats_query(call, fromtag, totag, &stats, ng_stats_cb, streams); XXX

//	dict = bencode_dictionary_add_dictionary(output, "totals");
//	bencode_dictionary_add(dict, "input", rtp_rtcp_stats(output->buffer, &stats.totals[0], &stats.totals[1]));
//	bencode_dictionary_add(dict, "output", rtp_rtcp_stats(output->buffer, &stats.totals[2], &stats.totals[3]));
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
	ng_call_stats(call, &fromtag, &totag, output);
	rwlock_unlock_w(&call->master_lock);

	return NULL;
}
