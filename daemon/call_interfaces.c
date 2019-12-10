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


static pcre *info_re;
static pcre_extra *info_ree;
static pcre *streams_re;
static pcre_extra *streams_ree;

int trust_address_def;
int dtls_passive_def;


INLINE int call_ng_flags_prefix(struct sdp_ng_flags *out, str *s_ori, const char *prefix,
		void (*cb)(struct sdp_ng_flags *, str *, void *), void *ptr);
static void call_ng_flags_str_ht(struct sdp_ng_flags *out, str *s, void *htp);


static int call_stream_address_gstring(GString *o, struct packet_stream *ps, enum stream_address_format format) {
	int len, ret;
	char buf[64]; /* 64 bytes ought to be enough for anybody */

	ret = call_stream_address46(buf, ps, format, &len, NULL, 1);
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

static str *call_update_lookup_udp(char **out, enum call_opmode opmode, const char* addr,
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

	c = call_get_opmode(&callid, opmode);
	if (!c) {
		ilog(LOG_WARNING, "[" STR_FORMAT_M "] Got UDP LOOKUP for unknown call-id",
			STR_FMT_M(&callid));
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

	redis_update_onekey(c, rtpe_redis_write);

	gettimeofday(&(monologue->started), NULL);

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
	ilog(LOG_WARNING, "Failed to parse a media stream: %s%s:%s%s", FMT_M(a[0], a[1]));
	g_slice_free1(sizeof(*sp), sp);
	return -1;
}


static void streams_parse(const char *s, GQueue *q) {
	int i;
	i = 0;
	pcre_multi_match(streams_re, streams_ree, s, 3, streams_parse_func, &i, q);
}

/* XXX move these somewhere else */
static void rtp_pt_free(void *p) {
	g_slice_free1(sizeof(struct rtp_payload_type), p);
}
static void sp_free(void *p) {
	struct stream_params *s = p;

	g_queue_clear_full(&s->rtp_payload_types, rtp_pt_free);
	ice_candidates_free(&s->ice_candidates);
	crypto_params_sdes_queue_clear(&s->sdes_params);
	g_slice_free1(sizeof(*s), s);
}
static void streams_free(GQueue *q) {
	g_queue_clear_full(q, sp_free);
}



static str *call_request_lookup_tcp(char **out, enum call_opmode opmode) {
	struct call *c;
	struct call_monologue *monologue;
	GQueue s = G_QUEUE_INIT;
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

	redis_update_onekey(c, rtpe_redis_write);

	ilog(LOG_INFO, "Returning to SIP proxy: "STR_FORMAT"", STR_FMT0(ret));
	obj_put(c);

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

	if (call_delete_branch(&callid, &branch, &fromtag, &totag, NULL, -1))
		return str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);

	return str_sprintf("%s 0\n", out[RE_UDP_COOKIE]);
}
str *call_query_udp(char **out) {
	struct call *c;
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
	if (c)
		rwlock_unlock_w(&c->master_lock);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	if (c)
		obj_put(c);
	return ret;
}

void call_delete_tcp(char **out) {
	str callid;

	str_init(&callid, out[RE_TCP_D_CALLID]);
	call_delete_branch(&callid, NULL, NULL, NULL, NULL, -1);
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
	GQueue q = G_QUEUE_INIT;
	struct call *c;

	call_get_all_calls(&q);

	streambuf_printf(s->outbuf, "proxy %u "UINT64F"/%i/%i\n",
		g_queue_get_length(&q),
		atomic64_get(&rtpe_stats.bytes), 0, 0);

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
	if (call_ng_flags_prefix(out, s, "no-", call_ng_flags_str_ht, &out->sdes_no))
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
		default:
			ilog(LOG_WARN, "Unknown 'SDES' flag encountered: '"STR_FORMAT"'",
					STR_FMT(s));
	}
}


static void call_ng_flags_list(struct sdp_ng_flags *out, bencode_item_t *input, const char *key,
		void (*callback)(struct sdp_ng_flags *, str *, void *), void *parm)
{
	bencode_item_t *list, *it;
	str s;
	if ((list = bencode_dictionary_get_expect(input, key, BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_get_str(it, &s))
				continue;
			callback(out, &s, parm);
		}
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
	if (!str_cmp(s, "origin"))
		out->replace_origin = 1;
	else if (!str_cmp(s, "session-connection"))
		out->replace_sess_conn = 1;
	else
		ilog(LOG_WARN, "Unknown 'replace' flag encountered: '" STR_FORMAT "'",
				STR_FMT(s));
}
static void call_ng_flags_supports(struct sdp_ng_flags *out, str *s, void *dummy) {
	if (!str_cmp(s, "load limit"))
		out->supports_load_limit = 1;
}
static void call_ng_flags_codec_list(struct sdp_ng_flags *out, str *s, void *qp) {
	str *s_copy = str_slice_dup(s);
	g_queue_push_tail((GQueue *) qp, s_copy);
}
static void call_ng_flags_str_ht(struct sdp_ng_flags *out, str *s, void *htp) {
	str *s_copy = str_slice_dup(s);
	GHashTable **ht = htp;
	if (!*ht)
		*ht = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
	g_hash_table_replace(*ht, s_copy, s_copy);
}
#ifdef WITH_TRANSCODING
static void call_ng_flags_str_ht_split(struct sdp_ng_flags *out, str *s, void *htp) {
	GHashTable **ht = htp;
	if (!*ht)
		*ht = g_hash_table_new_full(str_hash, str_equal, str_slice_free, str_slice_free);
	str splitter = *s;
	while (1) {
		g_hash_table_replace(*ht, str_slice_dup(&splitter), str_slice_dup(s));
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
		case CSH_LOOKUP("all"):
			out->all = 1;
			break;
		case CSH_LOOKUP("fragment"):
			out->fragment = 1;
			break;
		case CSH_LOOKUP("port-latching"):
			out->port_latching = 1;
			break;
		case CSH_LOOKUP("generate-mid"):
			out->generate_mid = 1;
			break;
		case CSH_LOOKUP("record-call"):
			out->record_call = 1;
			break;
		case CSH_LOOKUP("no-rtcp-attribute"):
			out->no_rtcp_attr = 1;
			break;
		case CSH_LOOKUP("full-rtcp-attribute"):
			out->full_rtcp_attr = 1;
			break;
		case CSH_LOOKUP("loop-protect"):
			out->loop_protect = 1;
			break;
		case CSH_LOOKUP("original-sendrecv"):
			out->original_sendrecv = 1;
			break;
		case CSH_LOOKUP("always-transcode"):
			out->always_transcode = 1;
			break;
		case CSH_LOOKUP("asymmetric-codecs"):
			out->asymmetric_codecs = 1;
			break;
		case CSH_LOOKUP("inject-DTMF"):
			out->inject_dtmf = 1;
			break;
		case CSH_LOOKUP("pad-crypto"):
			out->pad_crypto = 1;
			break;
		default:
			// handle values aliases from other dictionaries
			if (call_ng_flags_prefix(out, s, "SDES-no-", call_ng_flags_str_ht, &out->sdes_no))
				return;
			if (call_ng_flags_prefix(out, s, "SDES-", ng_sdes_option, NULL))
				return;
			if (out->opmode == OP_OFFER) {
				if (call_ng_flags_prefix(out, s, "codec-strip-", call_ng_flags_str_ht,
							&out->codec_strip))
					return;
				if (call_ng_flags_prefix(out, s, "codec-offer-", call_ng_flags_codec_list,
							&out->codec_offer))
					return;
#ifdef WITH_TRANSCODING
				if (call_ng_flags_prefix(out, s, "transcode-", call_ng_flags_codec_list,
							&out->codec_transcode))
					return;
				if (call_ng_flags_prefix(out, s, "codec-transcode-", call_ng_flags_codec_list,
							&out->codec_transcode))
					return;
				if (call_ng_flags_prefix(out, s, "codec-mask-", call_ng_flags_str_ht,
							&out->codec_mask))
					return;
				if (call_ng_flags_prefix(out, s, "codec-set-", call_ng_flags_str_ht_split,
							&out->codec_set))
					return;
#endif
			}

			ilog(LOG_WARN, "Unknown flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
static void call_ng_process_flags(struct sdp_ng_flags *out, bencode_item_t *input, enum call_opmode opmode) {
	bencode_item_t *list, *it, *dict;
	int diridx;
	str s;

	ZERO(*out);
	out->opmode = opmode;

	out->trust_address = trust_address_def;
	out->dtls_passive = dtls_passive_def;

	call_ng_flags_list(out, input, "flags", call_ng_flags_flags, NULL);
	call_ng_flags_list(out, input, "replace", call_ng_flags_replace, NULL);
	call_ng_flags_list(out, input, "supports", call_ng_flags_supports, NULL);

	bencode_dictionary_get_str(input, "call-id", &out->call_id);
	bencode_dictionary_get_str(input, "from-tag", &out->from_tag);
	bencode_dictionary_get_str(input, "to-tag", &out->to_tag);
	bencode_dictionary_get_str(input, "via-branch", &out->via_branch);
	bencode_dictionary_get_str(input, "label", &out->label);
	bencode_dictionary_get_str(input, "address", &out->address);

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
		switch (__csh_lookup(&s)) {
			case CSH_LOOKUP("remove"):
				out->ice_remove = 1;
				break;
			case CSH_LOOKUP("force"):
				out->ice_force = 1;
				break;
			case CSH_LOOKUP("force_relay"):
			case CSH_LOOKUP("force-relay"):
			case CSH_LOOKUP("force relay"):
				out->ice_force_relay = 1;
				break;
			default:
				ilog(LOG_WARN, "Unknown 'ICE' flag encountered: '"STR_FORMAT"'",
						STR_FMT(&s));
		}
	}

	if (bencode_dictionary_get_str(input, "DTLS", &s)) {
		switch (__csh_lookup(&s)) {
			case CSH_LOOKUP("passive"):
				out->dtls_passive = 1;
				break;
			case CSH_LOOKUP("no"):
			case CSH_LOOKUP("off"):
			case CSH_LOOKUP("disabled"):
			case CSH_LOOKUP("disable"):
				out->dtls_off = 1;
				break;
			default:
				ilog(LOG_WARN, "Unknown 'DTLS' flag encountered: '"STR_FORMAT"'",
						STR_FMT(&s));
		}
	}

	call_ng_flags_list(out, input, "rtcp-mux", call_ng_flags_rtcp_mux, NULL);
	call_ng_flags_list(out, input, "SDES", ng_sdes_option, NULL);

	bencode_get_alt(input, "transport-protocol", "transport protocol", &out->transport_protocol_str);
	out->transport_protocol = transport_protocol(&out->transport_protocol_str);
	bencode_get_alt(input, "media-address", "media address", &out->media_address);
	if (bencode_get_alt(input, "address-family", "address family", &out->address_family_str))
		out->address_family = get_socket_family_rfc(&out->address_family_str);
	out->tos = bencode_dictionary_get_int_str(input, "TOS", 256);
	bencode_get_alt(input, "record-call", "record call", &out->record_call_str);
	bencode_dictionary_get_str(input, "metadata", &out->metadata);

	if (opmode == OP_OFFER) {
		out->ptime = bencode_dictionary_get_int_str(input, "ptime", 0);
		out->rev_ptime = bencode_dictionary_get_int_str(input, "ptime-reverse", 0);
		if (out->rev_ptime == 0)
			out->rev_ptime = bencode_dictionary_get_int_str(input, "ptime reverse", 0);
	}

	if (bencode_dictionary_get_str(input, "xmlrpc-callback", &s)) {
		if (sockaddr_parse_any_str(&out->xmlrpc_callback, &s))
			ilog(LOG_WARN, "Failed to parse 'xmlrpc-callback' address '" STR_FORMAT "'",
					STR_FMT(&s));
	}

	if (opmode == OP_OFFER && (dict = bencode_dictionary_get_expect(input, "codec", BENCODE_DICTIONARY))) {
		call_ng_flags_list(out, dict, "strip", call_ng_flags_str_ht, &out->codec_strip);
		call_ng_flags_list(out, dict, "offer", call_ng_flags_codec_list, &out->codec_offer);
#ifdef WITH_TRANSCODING
		call_ng_flags_list(out, dict, "transcode", call_ng_flags_codec_list, &out->codec_transcode);
		call_ng_flags_list(out, dict, "mask", call_ng_flags_str_ht, &out->codec_mask);
		call_ng_flags_list(out, dict, "set", call_ng_flags_str_ht_split, &out->codec_set);
#endif
	}
}
static void call_ng_free_flags(struct sdp_ng_flags *flags) {
	if (flags->codec_strip)
		g_hash_table_destroy(flags->codec_strip);
	if (flags->codec_mask)
		g_hash_table_destroy(flags->codec_mask);
	if (flags->codec_set)
		g_hash_table_destroy(flags->codec_set);
	if (flags->sdes_no)
		g_hash_table_destroy(flags->sdes_no);
	g_queue_clear_full(&flags->codec_offer, str_slice_free);
	g_queue_clear_full(&flags->codec_transcode, str_slice_free);
}

static enum load_limit_reasons call_offer_session_limit(void) {
	enum load_limit_reasons ret = LOAD_LIMIT_NONE;

	rwlock_lock_r(&rtpe_config.config_lock);
	if (rtpe_config.max_sessions>=0) {
		rwlock_lock_r(&rtpe_callhash_lock);
		if (g_hash_table_size(rtpe_callhash) -
				atomic64_get(&rtpe_stats.foreign_sessions) >= rtpe_config.max_sessions)
		{
			/* foreign calls can't get rejected
			 * total_rejected_sess applies only to "own" sessions */
			atomic64_inc(&rtpe_totalstats.total_rejected_sess);
			atomic64_inc(&rtpe_totalstats_interval.total_rejected_sess);
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
		uint64_t bw = atomic64_get(&rtpe_stats.bytes);
		if (bw >= rtpe_config.bw_limit) {
			ilog(LOG_WARN, "Bandwidth limit exceeded (%" PRIu64 " > %" PRIu64 ")",
					bw, rtpe_config.bw_limit);
			ret = LOAD_LIMIT_BW;
		}
	}

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ret;
}

static const char *call_offer_answer_ng(bencode_item_t *input,
		bencode_item_t *output, enum call_opmode opmode, const char* addr,
		const endpoint_t *sin)
{
	str sdp;
	const char *errstr;
	GQueue parsed = G_QUEUE_INIT;
	GQueue streams = G_QUEUE_INIT;
	struct call *call;
	struct call_monologue *monologue;
	int ret;
	struct sdp_ng_flags flags;
	struct sdp_chopper *chopper;

	if (!bencode_dictionary_get_str(input, "sdp", &sdp))
		return "No SDP body in message";

	call_ng_process_flags(&flags, input, opmode);

	if (!flags.call_id.s)
		return "No call-id in message";
	if (!flags.from_tag.s)
		return "No from-tag in message";
	if (opmode == OP_ANSWER) {
		if (!flags.to_tag.s)
			return "No to-tag in message";
		str_swap(&flags.to_tag, &flags.from_tag);
	}

	if (opmode == OP_OFFER) {
		enum load_limit_reasons limit = call_offer_session_limit();
		if (limit != LOAD_LIMIT_NONE) {
			if (!flags.supports_load_limit)
				errstr = "Parallel session limit reached"; // legacy protocol
			else
				errstr = magic_load_limit_strings[limit];
			goto out;
		}
	}

	errstr = "Failed to parse SDP";
	if (sdp_parse(&sdp, &parsed, &flags))
		goto out;

	if (flags.loop_protect && sdp_is_duplicate(&parsed)) {
		ilog(LOG_INFO, "Ignoring message as SDP has already been processed by us");
		bencode_dictionary_add_str(output, "sdp", &sdp);
		errstr = NULL;
		goto out;
	}

	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, &flags))
		goto out;

	/* OP_ANSWER; OP_OFFER && !IS_FOREIGN_CALL */
	call = call_get(&flags.call_id);

	/* Failover scenario because of timeout on offer response: siprouter tries
	* to establish session with another rtpengine2 even though rtpengine1
	* might have persisted part of the session. rtpengine2 deletes previous
	* call in memory and recreates an OWN call in redis */
	// SDP fragments for trickle ICE must always operate on an existing call
	if (opmode == OP_OFFER && !flags.fragment) {
		if (call) {
			if (IS_FOREIGN_CALL(call)) {
				/* destroy call and create new one */
				rwlock_unlock_w(&call->master_lock);
				call_destroy(call);
				obj_put(call);
				call = call_get_or_create(&flags.call_id, CT_OWN_CALL);
			}
		}
		else {
			/* call == NULL, should create call */
			call = call_get_or_create(&flags.call_id, CT_OWN_CALL);
		}
	}

	errstr = "Unknown call-id";
	if (!call)
		goto out;

	if (!call->created_from && addr) {
		call->created_from = call_strdup(call, addr);
		call->created_from_addr = sin->address;
	}
	if (flags.xmlrpc_callback.family)
		call->xmlrpc_callback = flags.xmlrpc_callback;

	/* At least the random ICE strings are contained within the call struct, so we
	 * need to hold a ref until we're done sending the reply */
	call_bencode_hold_ref(call, output);

	monologue = call_get_mono_dialogue(call, &flags.from_tag, &flags.to_tag,
			flags.via_branch.s ? &flags.via_branch : NULL);
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

	chopper = sdp_chopper_new(&sdp);
	bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);

	detect_setup_recording(call, &flags.record_call_str, &flags.metadata);
	if (flags.record_call) {
		call->recording_on = 1;
		recording_start(call, NULL, &flags.metadata);
	}

	ret = monologue_offer_answer(monologue, &streams, &flags);
	if (!ret) {
		// SDP fragments for trickle ICE are consumed with no replacement returned
		if (!flags.fragment)
			ret = sdp_replace(chopper, &parsed, monologue->active_dialogue, &flags);
	}

	struct recording *recording = call->recording;
	if (recording != NULL) {
		meta_write_sdp_before(recording, &sdp, monologue, opmode);
		meta_write_sdp_after(recording, chopper->output,
			       monologue, opmode);

		recording_response(recording, output);
	}

	rwlock_unlock_w(&call->master_lock);

	if (!flags.no_redis_update) {
			redis_update_onekey(call, rtpe_redis_write);
	} else {
		ilog(LOG_DEBUG, "Not updating Redis due to present no-redis-update flag");
	}
	obj_put(call);

	gettimeofday(&(monologue->started), NULL);

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
	sdp_free(&parsed);
	streams_free(&streams);
	call_ng_free_flags(&flags);

	return errstr;
}

const char *call_offer_ng(bencode_item_t *input, bencode_item_t *output, const char* addr,
		const endpoint_t *sin)
{
	return call_offer_answer_ng(input, output, OP_OFFER, addr, sin);
}

const char *call_answer_ng(bencode_item_t *input, bencode_item_t *output) {
	return call_offer_answer_ng(input, output, OP_ANSWER, NULL, NULL);
}

const char *call_delete_ng(bencode_item_t *input, bencode_item_t *output) {
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

	if (call_delete_branch(&callid, &viabranch, &fromtag, &totag, output, delete_delay)) {
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
		bencode_dictionary_add_integer(dict, "SSRC", ps->ssrc_in->parent->h.ssrc);

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
	BF_M("ICE controlling", ICE_CONTROLLING);
	BF_M("ICE-lite", ICE_LITE);
	BF_M("unidirectional", UNIDIRECTIONAL);
	BF_M("loop check", LOOP_CHECK);
	BF_M("transcoding", TRANSCODE);

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

	sub = bencode_dictionary_add_dictionary(dict, ml->tag.s ? : "");

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
		struct ssrc_entry_call *se = l->data;
		char *tmp = bencode_buffer_alloc(dict->buffer, 12);
		snprintf(tmp, 12, "%" PRIu32, se->h.ssrc);
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


const char *call_start_recording_ng(bencode_item_t *input, bencode_item_t *output) {
	str callid;
	struct call *call;
	str metadata;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	bencode_dictionary_get_str(input, "metadata", &metadata);
	call = call_get_opmode(&callid, OP_OTHER);
	if (!call)
		return "Unknown call-id";

	call->recording_on = 1;
	recording_start(call, NULL, &metadata);

	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}

const char *call_stop_recording_ng(bencode_item_t *input, bencode_item_t *output) {
	str callid;
	struct call *call;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get_opmode(&callid, OP_OTHER);
	if (!call)
		return "Unknown call-id";

	call->recording_on = 0;
	recording_stop(call);

	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

	return NULL;
}

static const char *media_block_match(struct call **call, struct call_monologue **monologue,
		struct sdp_ng_flags *flags, bencode_item_t *input)
{
	struct sdp_ng_flags flags_store;

	if (!flags)
		flags = &flags_store;

	*call = NULL;
	*monologue = NULL;

	call_ng_process_flags(flags, input, OP_OTHER);

	if (!flags->call_id.s)
		return "No call-id in message";
	*call = call_get_opmode(&flags->call_id, OP_OTHER);
	if (!*call)
		return "Unknown call-id";

	// directional?
	if (flags->label.s) {
		*monologue = g_hash_table_lookup((*call)->labels, &flags->label);
		if (!*monologue)
			return "No monologue matching the given label";
	}
	else if (flags->address.s) {
		sockaddr_t addr;
		if (sockaddr_parse_any_str(&addr, &flags->address))
			return "Failed to parse network address";
		// walk our structures to find a matching stream
		for (GList *l = (*call)->monologues.head; l; l = l->next) {
			*monologue = l->data;
			for (GList *k = (*monologue)->medias.head; k; k = k->next) {
				struct call_media *media = k->data;
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
		*monologue = call_get_mono_dialogue(*call, &flags->from_tag, NULL, NULL);
		if (!*monologue)
			return "From-tag given, but no such tag exists";
	}

	return NULL;
}

// XXX these are all identical - unify and use a flags int and/or callback
const char *call_start_forwarding_ng(bencode_item_t *input, bencode_item_t *output) {
	struct call *call;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	struct sdp_ng_flags flags;

	errstr = media_block_match(&call, &monologue, &flags, input);
	if (errstr)
		goto out;

	if (monologue) {
		ilog(LOG_INFO, "Start forwarding for single party (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->rec_forwarding = 1;
	}
	else {
		ilog(LOG_INFO, "Start forwarding (entire call)");
		call->rec_forwarding = 1;
	}

	recording_start(call, NULL, &flags.metadata);
	errstr = NULL;
out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}

	return errstr;
}

const char *call_stop_forwarding_ng(bencode_item_t *input, bencode_item_t *output) {
	struct call *call;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	struct sdp_ng_flags flags;

	errstr = media_block_match(&call, &monologue, &flags, input);
	if (errstr)
		goto out;

	if (monologue) {
		ilog(LOG_INFO, "Stop forwarding for single party (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->rec_forwarding = 0;
	}
	else {
		ilog(LOG_INFO, "Stop forwarding (entire call)");
		call->rec_forwarding = 0;
		if (flags.all) {
			for (GList *l = call->monologues.head; l; l = l->next) {
				monologue = l->data;
				monologue->rec_forwarding = 0;
			}
		}
	}

	recording_stop(call);

	errstr = NULL;
out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}

	return NULL;
}

const char *call_block_dtmf_ng(bencode_item_t *input, bencode_item_t *output) {
	struct call *call;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	struct sdp_ng_flags flags;

	errstr = media_block_match(&call, &monologue, &flags, input);
	if (errstr)
		goto out;

	if (monologue) {
		ilog(LOG_INFO, "Blocking directional DTMF (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->block_dtmf = 1;
	}
	else {
		ilog(LOG_INFO, "Blocking DTMF (entire call)");
		call->block_dtmf = 1;
	}

	errstr = NULL;
out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}

	return errstr;
}

const char *call_unblock_dtmf_ng(bencode_item_t *input, bencode_item_t *output) {
	struct call *call;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	struct sdp_ng_flags flags;

	errstr = media_block_match(&call, &monologue, &flags, input);
	if (errstr)
		goto out;

	if (monologue) {
		ilog(LOG_INFO, "Unblocking directional DTMF (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->block_dtmf = 0;
	}
	else {
		ilog(LOG_INFO, "Unblocking DTMF (entire call)");
		call->block_dtmf = 0;
		if (flags.all) {
			for (GList *l = call->monologues.head; l; l = l->next) {
				monologue = l->data;
				monologue->block_dtmf = 0;
			}
		}
	}

	errstr = NULL;
out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}

	return NULL;
}

const char *call_block_media_ng(bencode_item_t *input, bencode_item_t *output) {
	struct call *call;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	struct sdp_ng_flags flags;

	errstr = media_block_match(&call, &monologue, &flags, input);
	if (errstr)
		goto out;

	if (monologue) {
		ilog(LOG_INFO, "Blocking directional media (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->block_media = 1;
		__monologue_unkernelize(monologue);
	}
	else {
		ilog(LOG_INFO, "Blocking media (entire call)");
		call->block_media = 1;
		__call_unkernelize(call);
	}

	errstr = NULL;
out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}

	return errstr;
}

const char *call_unblock_media_ng(bencode_item_t *input, bencode_item_t *output) {
	struct call *call;
	struct call_monologue *monologue;
	const char *errstr = NULL;
	struct sdp_ng_flags flags;

	errstr = media_block_match(&call, &monologue, &flags, input);
	if (errstr)
		goto out;

	if (monologue) {
		ilog(LOG_INFO, "Unblocking directional media (tag '" STR_FORMAT_M "')",
				STR_FMT_M(&monologue->tag));
		monologue->block_media = 0;
		__monologue_unkernelize(monologue);
	}
	else {
		ilog(LOG_INFO, "Unblocking media (entire call)");
		call->block_media = 0;
		if (flags.all) {
			for (GList *l = call->monologues.head; l; l = l->next) {
				monologue = l->data;
				monologue->block_media = 0;
			}
		}
		__call_unkernelize(call);
	}

	errstr = NULL;
out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}

	return NULL;
}


#ifdef WITH_TRANSCODING
static const char *play_media_select_party(struct call **call, struct call_monologue **monologue,
		bencode_item_t *input)
{
	const char *err = media_block_match(call, monologue, NULL, input);
	if (err)
		return err;
	if (!*monologue)
		return "No participant party specified";
	return NULL;
}
#endif


const char *call_play_media_ng(bencode_item_t *input, bencode_item_t *output) {
#ifdef WITH_TRANSCODING
	str str;
	struct call *call;
	struct call_monologue *monologue;
	const char *err = NULL;
	long long db_id;

	err = play_media_select_party(&call, &monologue, input);
	if (err)
		goto out;

	if (!monologue->player)
		monologue->player = media_player_new(monologue);

	err = "No media file specified";
	if (bencode_dictionary_get_str(input, "file", &str)) {
		err = "Failed to start media playback from file";
		if (media_player_play_file(monologue->player, &str))
			goto out;
	}
	else if (bencode_dictionary_get_str(input, "blob", &str)) {
		err = "Failed to start media playback from blob";
		if (media_player_play_blob(monologue->player, &str))
			goto out;
	}
	else if ((db_id = bencode_dictionary_get_int_str(input, "db-id", 0)) > 0) {
		err = "Failed to start media playback from database";
		if (media_player_play_db(monologue->player, db_id))
			goto out;
	}
	else
		goto out;

	if (monologue->player->duration)
		bencode_dictionary_add_integer(output, "duration", monologue->player->duration);

	err = NULL;

out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}
	return err;
#else
	return "unsupported";
#endif
}


const char *call_stop_media_ng(bencode_item_t *input, bencode_item_t *output) {
#ifdef WITH_TRANSCODING
	struct call *call;
	struct call_monologue *monologue;
	const char *err = NULL;

	err = play_media_select_party(&call, &monologue, input);
	if (err)
		goto out;

	if (!monologue->player)
		return "Not currently playing media";

	media_player_stop(monologue->player);

	err = NULL;

out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}
	return err;
#else
	return "unsupported";
#endif
}


const char *call_play_dtmf_ng(bencode_item_t *input, bencode_item_t *output) {
#ifdef WITH_TRANSCODING
	struct call *call;
	struct call_monologue *monologue;
	str str;
	const char *err = NULL;

	err = play_media_select_party(&call, &monologue, input);
	if (err)
		goto out;

	// validate input parameters

	long long duration = bencode_dictionary_get_int_str(input, "duration", 250);
	if (duration < 100) {
		duration = 100;
		ilog(LOG_WARN, "Invalid duration (%lli ms) specified, using 100 ms instead", duration);
	}
	else if (duration > 5000) {
		duration = 5000;
		ilog(LOG_WARN, "Invalid duration (%lli ms) specified, using 5000 ms instead", duration);
	}

	long long pause = bencode_dictionary_get_int_str(input, "pause", 100);
	if (pause < 100) {
		pause = 100;
		ilog(LOG_WARN, "Invalid pause (%lli ms) specified, using 100 ms instead", pause);
	}
	else if (pause > 5000) {
		pause = 5000;
		ilog(LOG_WARN, "Invalid pause (%lli ms) specified, using 5000 ms instead", pause);
	}

	long long code = bencode_dictionary_get_int_str(input, "code", -1);
	err = "Out of range 'code' specified";
	if (code == -1) {
		// try a string code
		err = "No valid 'code' specified";
		if (!bencode_dictionary_get_str(input, "code", &str))
			goto out;
		err = "Given 'code' is not a single digit";
		if (str.len != 1)
			goto out;
		code = dtmf_code_from_char(str.s[0]);
		err = "Invalid 'code' character";
		if (code == -1)
			goto out;
	}
	else if (code < 0)
		goto out;
	else if (code > 15)
		goto out;

	long long volume = bencode_dictionary_get_int_str(input, "volume", 8);
	if (volume > 0)
		volume *= -1;

	// find a usable output media
	struct call_media *media;
	for (GList *l = monologue->medias.head; l; l = l->next) {
		media = l->data;
		if (media->type_id != MT_AUDIO)
			continue;
		if (!media->dtmf_injector)
			continue;
		goto found;
	}

	err = "Monologue has no media capable of DTMF injection";
	// XXX fall back to generating a secondary stream
	goto out;

found:;
	err = dtmf_inject(media, code, volume, duration, pause);

out:
	if (call) {
		rwlock_unlock_w(&call->master_lock);
		obj_put(call);
	}
	return err;
#else
	return "unsupported";
#endif
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


void format_network_address(str* o, struct packet_stream *ps, struct sdp_ng_flags *flags, int keep_unspec) {
	if (!is_addr_unspecified(&flags->parsed_media_address))
		o->len = sprintf(o->s, "%s %s",
						 flags->parsed_media_address.family->rfc_name,
						 sockaddr_print_buf(&flags->parsed_media_address));
	else
		call_stream_address46(o->s, ps, SAF_NG, &o->len, NULL, keep_unspec);
}
