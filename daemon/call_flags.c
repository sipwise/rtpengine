#include "call_flags.h"

#include "str.h"
#include "control_ng_flags_parser.h"


bool trust_address_def;
bool dtls_passive_def;


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

static str *str_dup_escape(const str *s);


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
			out->sdes_off = true;
			break;
		case CSH_LOOKUP("unencrypted_srtp"):
		case CSH_LOOKUP("UNENCRYPTED_SRTP"):
			out->sdes_unencrypted_srtp = true;
			break;
		case CSH_LOOKUP("unencrypted_srtcp"):
		case CSH_LOOKUP("UNENCRYPTED_SRTCP"):
			out->sdes_unencrypted_srtcp = true;
			break;
		case CSH_LOOKUP("unauthenticated_srtp"):
		case CSH_LOOKUP("UNAUTHENTICATED_SRTP"):
			out->sdes_unauthenticated_srtp = true;
			break;
		case CSH_LOOKUP("encrypted_srtp"):
		case CSH_LOOKUP("ENCRYPTED_SRTP"):
			out->sdes_encrypted_srtp = true;
			break;
		case CSH_LOOKUP("encrypted_srtcp"):
		case CSH_LOOKUP("ENCRYPTED_SRTCP"):
			out->sdes_encrypted_srtcp = true;
			break;
		case CSH_LOOKUP("authenticated_srtp"):
		case CSH_LOOKUP("AUTHENTICATED_SRTP"):
			out->sdes_authenticated_srtp = true;
			break;
		case CSH_LOOKUP("lifetime"):
			out->sdes_lifetime = true;
			break;
		case CSH_LOOKUP("pad"):
			out->sdes_pad = true;
			break;
		case CSH_LOOKUP("static"):
			out->sdes_static = true;
			break;
		case CSH_LOOKUP("nonew"):
			out->sdes_nonew = true;
			break;
		case CSH_LOOKUP("prefer"):
		case CSH_LOOKUP("priority"):
			out->sdes_prefer = true;
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
			out->osrtp_accept_rfc = true;
			break;
		case CSH_LOOKUP("accept-legacy"):
			out->osrtp_accept_legacy = true;
			break;
		case CSH_LOOKUP("accept"):
			out->osrtp_accept_rfc = true;
			out->osrtp_accept_legacy = true;
			break;
		case CSH_LOOKUP("offer-legacy"):
			out->osrtp_offer_legacy = true;
			break;
		case CSH_LOOKUP("offer"):
		case CSH_LOOKUP("offer-RFC"):
		case CSH_LOOKUP("offer-rfc"):
			out->osrtp_offer = true;
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

	str *s_copy_from = str_dup_escape(&from_to[0]);
	str *s_copy_to = str_dup_escape(&from_to[1]);

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
			out->t38_decode = true;
			break;
		case CSH_LOOKUP("force"):
			out->t38_force = true;
			break;
		case CSH_LOOKUP("stop"):
			out->t38_stop = true;
			break;
		case CSH_LOOKUP("no-ecm"):
		case CSH_LOOKUP("no-ECM"):
		case CSH_LOOKUP("no ecm"):
		case CSH_LOOKUP("no ECM"):
			out->t38_no_ecm = true;
			break;
		case CSH_LOOKUP("no-V17"):
		case CSH_LOOKUP("no-V.17"):
		case CSH_LOOKUP("no-v17"):
		case CSH_LOOKUP("no-v.17"):
		case CSH_LOOKUP("no V17"):
		case CSH_LOOKUP("no V.17"):
		case CSH_LOOKUP("no v17"):
		case CSH_LOOKUP("no v.17"):
			out->t38_no_v17 = true;
			break;
		case CSH_LOOKUP("no-V.27ter"):
		case CSH_LOOKUP("no-V27ter"):
		case CSH_LOOKUP("no-v.27ter"):
		case CSH_LOOKUP("no-v27ter"):
		case CSH_LOOKUP("no V.27ter"):
		case CSH_LOOKUP("no V27ter"):
		case CSH_LOOKUP("no v.27ter"):
		case CSH_LOOKUP("no v27ter"):
			out->t38_no_v27ter = true;
			break;
		case CSH_LOOKUP("no-V29"):
		case CSH_LOOKUP("no-V.29"):
		case CSH_LOOKUP("no-v29"):
		case CSH_LOOKUP("no-v.29"):
		case CSH_LOOKUP("no V29"):
		case CSH_LOOKUP("no V.29"):
		case CSH_LOOKUP("no v29"):
		case CSH_LOOKUP("no v.29"):
			out->t38_no_v29 = true;
			break;
		case CSH_LOOKUP("no-V34"):
		case CSH_LOOKUP("no-V.34"):
		case CSH_LOOKUP("no-v34"):
		case CSH_LOOKUP("no-v.34"):
		case CSH_LOOKUP("no V34"):
		case CSH_LOOKUP("no V.34"):
		case CSH_LOOKUP("no v34"):
		case CSH_LOOKUP("no v.34"):
			out->t38_no_v34 = true;
			break;
		case CSH_LOOKUP("no-IAF"):
		case CSH_LOOKUP("no-iaf"):
		case CSH_LOOKUP("no IAF"):
		case CSH_LOOKUP("no iaf"):
			out->t38_no_iaf = true;
			break;
		case CSH_LOOKUP("FEC"):
		case CSH_LOOKUP("fec"):
			out->t38_fec = true;
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
			out->rtcp_mux_accept = true;
			break;
		case CSH_LOOKUP("demux"):
			out->rtcp_mux_demux = true;
			break;
		case CSH_LOOKUP("offer"):
			out->rtcp_mux_offer = true;
			break;
		case CSH_LOOKUP("reject"):
			out->rtcp_mux_reject = true;
			break;
		case CSH_LOOKUP("require"):
			out->rtcp_mux_offer = true;
			out->rtcp_mux_require = true;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'rtcp-mux' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}

static void call_ng_flags_bundle(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(s)) {
		case CSH_LOOKUP("accept"):
			out->bundle_accept = true;
			break;
		case CSH_LOOKUP("offer"):
			out->bundle_offer = true;
			out->generate_mid = true;
			break;
		case CSH_LOOKUP("reject"):
			out->bundle_reject = true;
			break;
		case CSH_LOOKUP("require"):
			out->bundle_offer = true;
			out->bundle_require = true;
			out->generate_mid = true;
			break;
		case CSH_LOOKUP("strict"):
			out->bundle_offer = true;
			out->bundle_require = true;
			out->bundle_strict = true;
			out->generate_mid = true;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'BUNDLE' flag encountered: '" STR_FORMAT "'",
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
				out->moh_zero_connection = true;
			break;
		case CSH_LOOKUP("mode"):;
			str mode = STR_NULL;
			parser->get_str(value, &mode);
			if (!str_cmp(&mode, "sendrecv"))
				out->moh_sendrecv = true;
			else if (!str_cmp(&mode, "reflect"))
				out->moh_reflect = true;
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
			out->force_inc_sdp_ver = true;
			break;
		case CSH_LOOKUP("origin"):
			out->replace_origin = true;
			break;
		case CSH_LOOKUP("origin full"):
		case CSH_LOOKUP("origin-full"):
		case CSH_LOOKUP("origin_full"):
			out->replace_origin_full = true;
			break;
		case CSH_LOOKUP("sdp-version"):
		case CSH_LOOKUP("SDP-version"):
		case CSH_LOOKUP("sdp version"):
		case CSH_LOOKUP("SDP version"):
			out->replace_sdp_version = true;
			break;
		/* TODO: after a while remove silent support for this flag */
		case CSH_LOOKUP("session-connection"):
		case CSH_LOOKUP("session connection"):
			ilog(LOG_INFO, "replace-session-connection flag encountered, but not supported anymore.");
			break;
		case CSH_LOOKUP("session-name"):
		case CSH_LOOKUP("session name"):
			out->replace_sess_name = true;
			break;
		case CSH_LOOKUP("username"):
			out->replace_username = true;
			break;
		case CSH_LOOKUP("zero-address"):
		case CSH_LOOKUP("zero address"):
			out->replace_zero_address = true;
			break;
		default:
			ilog(LOG_WARN, "Unknown 'replace' flag encountered: '" STR_FORMAT "'",
					STR_FMT(s));
	}
}
static void call_ng_flags_supports(str *s, unsigned int idx, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	if (!str_cmp(s, "load limit"))
		out->supports_load_limit = true;
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
			out->allow_asymmetric_codecs = true;
			break;
		case CSH_LOOKUP("allow-no-codec-media"):
		case CSH_LOOKUP("allow-no-codec-medias"):
		case CSH_LOOKUP("allow-empty-codec-media"):
		case CSH_LOOKUP("allow-empty-codec-medias"):
		case CSH_LOOKUP("allow no codec media"):
		case CSH_LOOKUP("allow no codec medias"):
		case CSH_LOOKUP("allow empty codec media"):
		case CSH_LOOKUP("allow empty codec medias"):
			out->allow_no_codec_media = true;
			break;
		case CSH_LOOKUP("allow-transcoding"):
		case CSH_LOOKUP("allow transcoding"):
			out->allow_transcoding = true;
			break;
		case CSH_LOOKUP("force-transcoding"):
		case CSH_LOOKUP("force transcoding"):
			out->force_transcoding = true;
			break;
		case CSH_LOOKUP("always-transcode"):
		case CSH_LOOKUP("always transcode"):;
			static const str str_all = STR_CONST("all");
			call_ng_flags_esc_str_list((str *) &str_all, 0, &out->codec_accept);
			break;
		case CSH_LOOKUP("asymmetric"):
			out->asymmetric = true;
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
		case CSH_LOOKUP("bidirectional"):
			out->bidirectional = true;
			break;
		case CSH_LOOKUP("block-dtmf"):
		case CSH_LOOKUP("block-DTMF"):
		case CSH_LOOKUP("block dtmf"):
		case CSH_LOOKUP("block DTMF"):
			out->block_dtmf = true;
			break;
		case CSH_LOOKUP("block-egress"):
		case CSH_LOOKUP("block egress"):
			out->block_egress = true;
			break;
		case CSH_LOOKUP("block-short"):
		case CSH_LOOKUP("block-shorts"):
		case CSH_LOOKUP("block-short-packets"):
		case CSH_LOOKUP("block short"):
		case CSH_LOOKUP("block shorts"):
		case CSH_LOOKUP("block short packets"):
			out->block_short = true;
			break;
		case CSH_LOOKUP("debug"):
		case CSH_LOOKUP("debugging"):
			out->debug = true;
			break;
		case CSH_LOOKUP("detect-DTMF"):
		case CSH_LOOKUP("detect-dtmf"):
		case CSH_LOOKUP("detect DTMF"):
		case CSH_LOOKUP("detect dtmf"):
			out->detect_dtmf = true;
			break;
		case CSH_LOOKUP("directional"):
			out->directional = true;
			break;
		case CSH_LOOKUP("discard-recording"):
		case CSH_LOOKUP("discard recording"):
			out->discard_recording = true;
			break;
		case CSH_LOOKUP("early-media"):
		case CSH_LOOKUP("early media"):
			out->early_media = true;
			break;
		case CSH_LOOKUP("egress"):
			out->egress = true;
			break;
		case CSH_LOOKUP("exclude-recording"):
		case CSH_LOOKUP("exclude recording"):
			out->exclude_recording = true;
			break;
		case CSH_LOOKUP("fatal"):
			out->fatal = true;
			break;
		case CSH_LOOKUP("fragment"):
			out->fragment = true;
			break;
		case CSH_LOOKUP("full-rtcp-attribute"):
		case CSH_LOOKUP("full-RTCP-attribute"):
		case CSH_LOOKUP("full rtcp attribute"):
		case CSH_LOOKUP("full RTCP attribute"):
			out->full_rtcp_attr = true;
			break;
		case CSH_LOOKUP("generate-mid"):
		case CSH_LOOKUP("generate mid"):
			out->generate_mid = true;
			break;
		case CSH_LOOKUP("generate-RTCP"):
		case CSH_LOOKUP("generate-rtcp"):
		case CSH_LOOKUP("generate RTCP"):
		case CSH_LOOKUP("generate rtcp"):
			out->generate_rtcp = true;
			break;
		case CSH_LOOKUP("ICE-reject"):
		case CSH_LOOKUP("ice-reject"):
		case CSH_LOOKUP("reject-ice"):
		case CSH_LOOKUP("reject-ICE"):
		case CSH_LOOKUP("ICE reject"):
		case CSH_LOOKUP("ice reject"):
		case CSH_LOOKUP("reject ice"):
		case CSH_LOOKUP("reject ICE"):
			out->ice_reject = true;
			break;
		case CSH_LOOKUP("inactive"):
			out->inactive = true;
			break;
		case CSH_LOOKUP("inject-DTMF"):
		case CSH_LOOKUP("inject-dtmf"):
		case CSH_LOOKUP("inject DTMF"):
		case CSH_LOOKUP("inject dtmf"):
			out->inject_dtmf = true;
			break;
		case CSH_LOOKUP("loop-protect"):
		case CSH_LOOKUP("loop protect"):
			out->loop_protect = true;
			break;
		case CSH_LOOKUP("media-handover"):
		case CSH_LOOKUP("media handover"):
			out->media_handover = true;
			break;
		case CSH_LOOKUP("mirror-RTCP"):
		case CSH_LOOKUP("mirror-rtcp"):
		case CSH_LOOKUP("RTCP-mirror"):
		case CSH_LOOKUP("rtcp-mirror"):
		case CSH_LOOKUP("mirror RTCP"):
		case CSH_LOOKUP("mirror rtcp"):
		case CSH_LOOKUP("RTCP mirror"):
		case CSH_LOOKUP("rtcp mirror"):
			out->rtcp_mirror = true;
			break;
		case CSH_LOOKUP("mix"):
		case CSH_LOOKUP("mixed"):
			out->mix = true;
			break;
		case CSH_LOOKUP("NAT-wait"):
		case CSH_LOOKUP("nat-wait"):
		case CSH_LOOKUP("NAT wait"):
		case CSH_LOOKUP("nat wait"):
			out->nat_wait = true;
			break;
		case CSH_LOOKUP("new-branch"):
		case CSH_LOOKUP("new branch"):
			out->new_branch = true;
			break;
		case CSH_LOOKUP("no-codec-renegotiation"):
		case CSH_LOOKUP("reuse-codecs"):
		case CSH_LOOKUP("no codec renegotiation"):
		case CSH_LOOKUP("reuse codecs"):
			out->reuse_codec = true;
			break;
		case CSH_LOOKUP("no-passthrough"):
		case CSH_LOOKUP("no passthrough"):
			out->passthrough_off = true;
			break;
		case CSH_LOOKUP("no-player"):
		case CSH_LOOKUP("no-audio-player"):
		case CSH_LOOKUP("no player"):
		case CSH_LOOKUP("no audio player"):
			out->audio_player = AP_OFF;
			break;
		case CSH_LOOKUP("no-port-latching"):
		case CSH_LOOKUP("no port latching"):
			out->no_port_latching = true;
			break;
		case CSH_LOOKUP("no-redis-update"):
		case CSH_LOOKUP("no redis update"):
			out->no_redis_update = true;
			break;
		case CSH_LOOKUP("no-rtcp-attribute"):
		case CSH_LOOKUP("no-RTCP-attribute"):
		case CSH_LOOKUP("no rtcp attribute"):
		case CSH_LOOKUP("no RTCP attribute"):
			out->no_rtcp_attr = true;
			break;
		case CSH_LOOKUP("no-tls-id"):
		case CSH_LOOKUP("no tls id"):
			out->no_tls_id = true;
			break;
		case CSH_LOOKUP("no-jitter-buffer"):
		case CSH_LOOKUP("no jitter buffer"):
			out->disable_jb = true;
			break;
		case CSH_LOOKUP("original-sendrecv"):
		case CSH_LOOKUP("original sendrecv"):
			out->original_sendrecv = true;
			break;
		case CSH_LOOKUP("pad-crypto"):
		case CSH_LOOKUP("pad crypto"):
			out->sdes_pad = true;
			break;
		case CSH_LOOKUP("passthrough"):
			out->passthrough_on = true;
			break;
		case CSH_LOOKUP("pierce-NAT"):
		case CSH_LOOKUP("pierce-nat"):
		case CSH_LOOKUP("pierce NAT"):
		case CSH_LOOKUP("pierce nat"):
			out->pierce_nat = true;
			break;
		case CSH_LOOKUP("port-latching"):
		case CSH_LOOKUP("port latching"):
			out->port_latching = true;
			break;
		case CSH_LOOKUP("provisional"):
			out->provisional = true;
			break;
		case CSH_LOOKUP("record-call"):
		case CSH_LOOKUP("record call"):
			out->record_call = true;
			break;
		case CSH_LOOKUP("recording-vsc"):
		case CSH_LOOKUP("recording-VSC"):
		case CSH_LOOKUP("recording vsc"):
		case CSH_LOOKUP("recording VSC"):
			out->recording_vsc = true;
			break;
		case CSH_LOOKUP("recording-announcement"):
		case CSH_LOOKUP("recording announcement"):
			out->recording_announcement = true;
			break;
		case CSH_LOOKUP("recrypt"):
			out->recrypt = true;
			break;
		case CSH_LOOKUP("reorder-codecs"):
		case CSH_LOOKUP("reorder codecs"):
			ilog(LOG_INFO, "Ignoring obsolete flag `reorder-codecs`");
			break;
		case CSH_LOOKUP("reset"):
			out->reset = true;
			break;
		case CSH_LOOKUP("single-codec"):
		case CSH_LOOKUP("single codec"):
			out->single_codec = true;
			break;
		case CSH_LOOKUP("SIP-source-address"):
		case CSH_LOOKUP("sip-source-address"):
		case CSH_LOOKUP("SIP source address"):
		case CSH_LOOKUP("sip source address"):
			out->trust_address = 0;
			break;
		case CSH_LOOKUP("SIPREC"):
		case CSH_LOOKUP("siprec"):
			out->siprec = true;
			break;
		case CSH_LOOKUP("skip-recording-db"):
		case CSH_LOOKUP("skip-recording-database"):
		case CSH_LOOKUP("skip recording db"):
		case CSH_LOOKUP("skip recording database"):
			out->skip_recording_db = true;
			break;
		case CSH_LOOKUP("static-codec"):
		case CSH_LOOKUP("static-codecs"):
		case CSH_LOOKUP("static codec"):
		case CSH_LOOKUP("static codecs"):
			out->static_codecs = true;
			break;
		case CSH_LOOKUP("strict-source"):
		case CSH_LOOKUP("strict source"):
			out->strict_source = true;
			break;
		case CSH_LOOKUP("strip-extmap"):
		case CSH_LOOKUP("strip extmap"):
			call_ng_flags_str_ht(STR_PTR("all"), 0, &out->rtpext_strip);
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
			out->to_tag_flag = true;
			break;
		case CSH_LOOKUP("trickle-ICE"):
		case CSH_LOOKUP("trickle-ice"):
		case CSH_LOOKUP("trickle ICE"):
		case CSH_LOOKUP("trickle ice"):
			out->trickle_ice = true;
			break;
		case CSH_LOOKUP("trust-address"):
		case CSH_LOOKUP("trust address"):
			out->trust_address = true;
			break;
		case CSH_LOOKUP("unidirectional"):
			out->unidirectional = true;
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
			/* group:BUNDLE */
			if (call_ng_flags_prefix(s, "BUNDLE-", call_ng_flags_bundle, out))
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
				if (call_ng_flags_prefix(s, "codec-ignore-", call_ng_flags_esc_str_list,
							&out->codec_ignore))
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
	out->t38_version = -1;
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
		case CSH_LOOKUP("ignore"):
			call_ng_flags_str_list(parser, value, call_ng_flags_esc_str_list, &out->codec_ignore);
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

void call_ng_extmap_flags(const ng_parser_t *parser, str *key, parser_arg value, helper_arg arg) {
	sdp_ng_flags *out = arg.flags;
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("strip"):
			call_ng_flags_str_list(parser, value, call_ng_flags_str_ht, &out->rtpext_strip);
			break;

		case CSH_LOOKUP("mask"):
			call_ng_flags_str_list(parser, value, call_ng_flags_str_ht, &out->rtpext_mask);
			break;
	}
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

static void call_ng_flags_peer_address(const str *peer_ip, str *direction, const char *direction_text) {
	const str *resolved = resolve_interface_from_peer_ip(peer_ip);
	if (resolved) {
		*direction = *resolved;
		ilog(LOG_DEBUG, "%s peer " STR_FORMAT " resolved to interface " STR_FORMAT,
			direction_text, STR_FMT(peer_ip), STR_FMT(resolved));
	}
	else
		ilog(LOG_WARN, "Failed to resolve %s peer address " STR_FORMAT, direction_text, STR_FMT(peer_ip));
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

static void call_ng_payload_type(const ng_parser_t *parser, str *key, parser_arg value,
		struct rtp_payload_type *pt)
{
	str s = STR_NULL;
	parser->get_str(value, &s);
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("codec"):
			pt->encoding = s;
			break;
		case CSH_LOOKUP("payload type"):
			pt->payload_type = parser->get_int_str(value, -1);
			break;
		case CSH_LOOKUP("clock rate"):
			pt->clock_rate = parser->get_int_str(value, 0);
			break;
		case CSH_LOOKUP("channels"):
			pt->channels = parser->get_int_str(value, 0);
			break;
		case CSH_LOOKUP("format"):
			pt->format_parameters = s;
			break;
		case CSH_LOOKUP("options"):
			pt->codec_opts = s;
			break;
		default:
			ilog(LOG_WARN, "Unknown payload type key '" STR_FORMAT "'", STR_FMT(key));
	}
}

static void call_ng_codec(const ng_parser_t *parser, str *key, parser_arg value, struct ng_codec *codec) {
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("input"):
			parser->dict_iter(parser, value, call_ng_payload_type, &codec->input);
			break;
		case CSH_LOOKUP("output"):
			parser->dict_iter(parser, value, call_ng_payload_type, &codec->output);
			break;
		default:
			ilog(LOG_WARN, "Unknown codec key '" STR_FORMAT "'", STR_FMT(key));
	}
}

static void call_ng_codec_iter(const ng_parser_t *parser, parser_arg item, struct ng_media *media) {
	// we support two types here:
	// the "transform" method supplies an extended list of codecs, as a list of dicts
	// the "create" method uses a list of strings, similar to codec->offer
	if (!parser->is_dict(item)) {
		str s;
		parser->get_str(item, &s);
		call_ng_flags_esc_str_list(&s, 0, &media->codec_list);
		return;
	}

	__auto_type codec = g_new0(struct ng_codec, 1);
	t_queue_push_tail(&media->codecs, codec);

	codec->input.payload_type = -1;
	codec->output.payload_type = -1;

	parser->dict_iter(parser, item, call_ng_codec, codec);

	if (codec->input.payload_type == -1 || codec->output.payload_type == -1)
		ilog(LOG_WARN, "Incomplete codec definition");
}

static void call_ng_endpoint(const ng_parser_t *parser, str *key, parser_arg value, struct ng_media *media) {
	str s = STR_NULL;
	parser->get_str(value, &s);
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("address"):
			media->destination_address = s;
			break;
		case CSH_LOOKUP("family"):
		case CSH_LOOKUP("address-family"):
		case CSH_LOOKUP("address family"):
			media->destination.address.family = get_socket_family_rfc(&s);
			break;
		case CSH_LOOKUP("port"):
			media->destination.port = parser->get_int_str(value, 0);
			break;
		default:
			ilog(LOG_WARN, "Unknown endpoint key '" STR_FORMAT "'", STR_FMT(key));
	}
}

static void call_ng_media(const ng_parser_t *parser, str *key, parser_arg value, struct ng_media *media) {
	str s = STR_NULL;
	parser->get_str(value, &s);
	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("codec"):
		case CSH_LOOKUP("codecs"):
			parser->list_iter(parser, value, NULL, call_ng_codec_iter, media);
			break;
		case CSH_LOOKUP("destination"):
			parser->dict_iter(parser, value, call_ng_endpoint, media);
			if (!media->destination.address.family)
				ilog(LOG_ERR, "Destination address without family specified");
			else
				if (!sockaddr_parse_str(&media->destination.address, media->destination.address.family,
							&media->destination_address))
					ilog(LOG_ERR, "Failed to parse destination address '" STR_FORMAT "'",
						STR_FMT(&media->destination_address));
			break;
		case CSH_LOOKUP("id"):
			media->id = s;
			break;
		case CSH_LOOKUP("type"):
			media->type = s;
			break;
		default:
			ilog(LOG_WARN, "Unknown media key '" STR_FORMAT "'", STR_FMT(key));
	}
}

static void call_ng_media_iter(const ng_parser_t *parser, parser_arg item, sdp_ng_flags *out) {
	__auto_type media = g_new0(struct ng_media, 1);
	t_queue_push_tail(&out->medias, media);
	parser->dict_iter(parser, item, call_ng_media, media);
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
		case CSH_LOOKUP("alias-key"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "none"):
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "no"):
					out->alias_key = AK_NONE;
					break;
				case CSH_LOOKUP_N(1, "sdp"):
				case CSH_LOOKUP_N(1, "SDP"):
					out->alias_key = AK_SDP;
					break;
				case CSH_LOOKUP_N(1, "address"):
				case CSH_LOOKUP_N(1, "endpoint"):
					out->alias_key = AK_ADDRESS;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'alias-key' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("audio-player"):
		case CSH_LOOKUP("audio player"):
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
		case CSH_LOOKUP("bundle"):
		case CSH_LOOKUP("BUNDLE"):
			call_ng_flags_str_list(parser, value, call_ng_flags_bundle, out);
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
					out->drop_traffic_start = true;
					break;
				case CSH_LOOKUP_N(1, "stop"):
					out->drop_traffic_stop = true;
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
					out->dtls_passive = true;
					break;
				case CSH_LOOKUP_N(1, "active"):
					out->dtls_passive = 0;
					break;
				case CSH_LOOKUP_N(1, "no"):
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "disabled"):
				case CSH_LOOKUP_N(1, "disable"):
					out->dtls_off = true;
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
					out->dtls_reverse_passive = true;
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
			if (!endpoint_parse_any_str(&out->dtmf_log_dest, &s))
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
		case CSH_LOOKUP("extmap"):
			parser->dict_iter(parser, value, call_ng_extmap_flags, out);
			break;
		case CSH_LOOKUP("file"):
			out->file = s;
			break;
		case CSH_LOOKUP("frequency"):
		case CSH_LOOKUP("frequencies"):
			call_ng_flags_freqs(parser, value, out);
			break;
		case CSH_LOOKUP("from-interface"):
		case CSH_LOOKUP("from interface"):
			out->direction[0] = s;
			break;
		case CSH_LOOKUP("inbound-peer"):
			call_ng_flags_peer_address(&s, &out->direction[0], "Inbound");
			break;
		case CSH_LOOKUP("from-label"):
		case CSH_LOOKUP("from label"):
		case CSH_LOOKUP("label"):
			out->label = s;
			break;
		case CSH_LOOKUP("from-tag"):
		case CSH_LOOKUP("from tag"):
			out->from_tag = s;
			break;
		case CSH_LOOKUP("from-tags"):
		case CSH_LOOKUP("from tags"):
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
				out->generate_rtcp = true;
			else if (!str_cmp(&s, "off"))
				out->generate_rtcp_off = true;
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
		case CSH_LOOKUP("peer"):
			call_ng_flags_peer_address(&s, &out->interface, "Interface");
			break;
		case CSH_LOOKUP("instance"):
			out->instance = s;
			break;
		case CSH_LOOKUP("media address"):
		case CSH_LOOKUP("media-address"):
			if (!sockaddr_parse_any_str(&out->media_address, &s))
				ilog(LOG_WARN, "Could not parse 'media-address'");
			break;
		case CSH_LOOKUP("media"):
		case CSH_LOOKUP("medias"):
			parser->list_iter(parser, value, NULL, call_ng_media_iter, out);
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
					out->passthrough_on = true;
					break;
				case CSH_LOOKUP_N(1, "no"):
				case CSH_LOOKUP_N(1, "off"):
				case CSH_LOOKUP_N(1, "disable"):
				case CSH_LOOKUP_N(1, "disabled"):
					out->passthrough_off = true;
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
		case CSH_LOOKUP("repeat times"):
			out->repeat_times = parser->get_int_str(value, out->repeat_times);
			break;
		case CSH_LOOKUP("repeat-duration"):
		case CSH_LOOKUP("repeat duration"):
			out->repeat_duration = parser->get_int_str(value, out->repeat_duration);
			break;
		case CSH_LOOKUP("replace"):
			call_ng_flags_str_list(parser, value, call_ng_flags_replace, out);
			break;
		case CSH_LOOKUP("rtcp-mux"):
		case CSH_LOOKUP("RTCP-mux"):
		case CSH_LOOKUP("rtcp mux"):
		case CSH_LOOKUP("RTCP mux"):
			call_ng_flags_str_list(parser, value, call_ng_flags_rtcp_mux, out);
			break;
		case CSH_LOOKUP("rtpp-flags"):
		case CSH_LOOKUP("rtpp_flags"):;
		case CSH_LOOKUP("rtpp flags"):;
			/* s - list of rtpp flags */
			out->rtpp_flags = true;
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
		case CSH_LOOKUP("sdp attr"):
		case CSH_LOOKUP("SDP attr"):
			ng_sdp_attr_manipulations(parser, out, value);
			break;
		case CSH_LOOKUP("sdp-media-remove"):
		case CSH_LOOKUP("SDP-media-remove"):
		case CSH_LOOKUP("sdp_media_remove"):
		case CSH_LOOKUP("SDP_media_remove"):
		case CSH_LOOKUP("sdp media remove"):
		case CSH_LOOKUP("SDP media remove"):
			ng_sdp_media_remove(parser, out, value);
			break;
		case CSH_LOOKUP("set-label"):
		case CSH_LOOKUP("set label"):
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
		case CSH_LOOKUP("sip code"):
		case CSH_LOOKUP("SIP code"):
		case CSH_LOOKUP("sip response code"):
		case CSH_LOOKUP("SIP response code"):
			out->code = parser->get_int_str(value, out->code);
			break;
		case CSH_LOOKUP("sip-message-type"):
		case CSH_LOOKUP("sip_message_type"):
		case CSH_LOOKUP("SIP-message-type"):
		case CSH_LOOKUP("SIP_message_type"):
		case CSH_LOOKUP("sip message type"):
		case CSH_LOOKUP("SIP message type"):
			switch (__csh_lookup_n(1, &s)) {
				case CSH_LOOKUP_N(1, "request"):
				case CSH_LOOKUP_N(1, "sip-request"):
				case CSH_LOOKUP_N(1, "sip_request"):
				case CSH_LOOKUP_N(1, "SIP-request"):
				case CSH_LOOKUP_N(1, "SIP_request"):
				case CSH_LOOKUP_N(1, "sip request"):
				case CSH_LOOKUP_N(1, "SIP request"):
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
				case CSH_LOOKUP_N(1, "sip response"):
				case CSH_LOOKUP_N(1, "SIP response"):
				case CSH_LOOKUP_N(1, "sip reply"):
				case CSH_LOOKUP_N(1, "SIP reply"):
					out->message_type = SIP_REPLY;
					break;
				default:
					ilog(LOG_WARN, "Unknown 'sip-message-type' flag encountered: '" STR_FORMAT "'",
							STR_FMT(&s));
			}
			break;
		case CSH_LOOKUP("start-pos"):
		case CSH_LOOKUP("start pos"):
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

		case CSH_LOOKUP("T38-version"):
		case CSH_LOOKUP("T.38-version"):
		case CSH_LOOKUP("t38-version"):
		case CSH_LOOKUP("t.38-version"):
		case CSH_LOOKUP("T38 version"):
		case CSH_LOOKUP("T.38 version"):
		case CSH_LOOKUP("t38 version"):
		case CSH_LOOKUP("t.38 version"):
			out->t38_version = parser->get_int_str(value, out->t38_version);
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
		case CSH_LOOKUP("to interface"):
			out->direction[1] = s;
			break;
		case CSH_LOOKUP("outbound-peer"):
			call_ng_flags_peer_address(&s, &out->direction[1], "Outbound");
			break;
		case CSH_LOOKUP("to-label"):
		case CSH_LOOKUP("to label"):
			out->to_label = s;
			break;
		case CSH_LOOKUP("to-call-id"):
		case CSH_LOOKUP("to call id"):
			out->to_call_id = s;
			break;
		case CSH_LOOKUP("to-tag"):
		case CSH_LOOKUP("to_tag"):
		case CSH_LOOKUP("to tag"):
			out->to_tag = s;
			break;
		case CSH_LOOKUP("TOS"):
		case CSH_LOOKUP("tos"):
			out->tos = parser->get_int_str(value, out->tos);
			break;
		case CSH_LOOKUP("transport protocol"):
		case CSH_LOOKUP("transport-protocol"):
			if (!str_cmp(&s, "accept"))
				out->protocol_accept = true;
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
			out->xmlrpc_callback = s;
			break;
		default:
			ilog(LOG_WARN, "Unknown dictionary key encountered: '" STR_FORMAT "'", STR_FMT(key));
	}
}

void call_ng_process_flags(sdp_ng_flags *out, ng_command_ctx_t *ctx) {
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
