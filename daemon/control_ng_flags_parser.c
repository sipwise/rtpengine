#include "control_ng_flags_parser.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>

#include "log.h"
#include "log_funcs.h"


/**
 * Data structures.
 */

static const char *transports[] = {
		[0x00] = "RTP/AVP",
		[0x01] = "RTP/SAVP",
		[0x02] = "RTP/AVPF",
		[0x03] = "RTP/SAVPF",
		[0x04] = "UDP/TLS/RTP/SAVP",
		[0x06] = "UDP/TLS/RTP/SAVPF",
};

/**
 * Helpers.
 */

/* parsing of key and val from string */
static bool get_key_val(str * key, str * val, str *in_out)
{
	if (!str_token_sep(key, in_out, ' '))
		return false;
	// key=value ?
	str k;
	*val = STR_NULL;
	if (!str_token_sep(&k, key, '='))
		return true;
	*val = *key;
	*key = k;
	return true;
}

/* handle either "foo-bar" or "foo=bar" from flags */
static bool str_key_val_prefix(const str * p, const char * q,
		const str * v, str * out)
{
	if(str_eq(p, q)) {
		if(!v->s || !v->len)
			return 0;

		*out = *v;
		return true;
	}
	*out = *p;
	if (str_shift_cmp(out, q))
		return false;
	if(out->len < 2)
		return false;
	if(*out->s != '-')
		return false;
	out->s++;
	out->len--;
	return true;
}

static inline bool skip_char(str *s, char c) {
	if (s->len == 0 || s->s[0] != c)
		return false;
	str_shift(s, 1);
	return true;
}
static inline void skip_chars(str *s, char c) {
	while (skip_char(s, c));
}

static int rtpp_is_dict_list(rtpp_pos *a) {
	str list = a->cur;
	if (!skip_char(&list, '['))
		return 0;
	// check contents
	if (list.len == 0)
		list = a->remainder; // could be just leading spaces?
	if (list.len == 0)
		return 0; // unexpected end of string
	if (list.s[0] == '[')
		return 1; // contains sub-list, must be a list
	// inspect first element for 'key='
	str key, val;
	if (!get_key_val(&key, &val, &list))
		return 0; // nothing to read
	if (val.len)
		return 2; // is a dict
	return 1; // is a list
}

static bool rtpp_is_list(rtpp_pos *a) {
	return rtpp_is_dict_list(a) == 1;
}
static bool rtpp_is_dict(rtpp_pos *a) {
	return rtpp_is_dict_list(a) == 2;
}
static str *rtpp_get_str(rtpp_pos *a, str *b) {
	if (rtpp_is_dict_list(a) != 0)
		return NULL;
	if (a->cur.len == 0)
		return NULL;
	*b = a->cur;
	return b;
}
static long long rtpp_get_int_str(rtpp_pos *a, long long def) {
	str s;
	if (!rtpp_get_str(a, &s))
		return def;
	return str_to_i(&s, def);
}
static bool rtpp_dict_list_end_rewind(rtpp_pos *pos) {
	// check for dict/list end, which is only valid if it doesn't also start one
	if (pos->cur.len == 0 || pos->cur.s[0] == '[' || pos->cur.s[pos->cur.len - 1] != ']')
		return false;

	pos->cur.len--;
	// remove any extra closing bracket, and return them to the remainder for
	// the upper level function to parse
	while (pos->cur.len && pos->cur.s[pos->cur.len - 1] == ']') {
		pos->cur.len--;
		pos->remainder.s--;
		pos->remainder.len++;
		// we might be on a space or something - go to the actual bracket, which must
		// be there somewhere
		while (pos->remainder.s[0] != ']') {
			pos->remainder.s--;
			pos->remainder.len++;
		}
	}

	return true;
}
static bool rtpp_dict_list_closing(rtpp_pos *pos) {
	if (pos->cur.s[0] != ']')
		return false;

	str_shift(&pos->cur, 1);
	// anything left in the string, return it to the remainder
	pos->remainder.len += pos->remainder.s - pos->cur.s;
	pos->remainder.s = pos->cur.s;

	return true;
}
static void rtpp_list_iter(const ng_parser_t *parser, rtpp_pos *pos,
		void (*str_callback)(str *key, unsigned int, helper_arg),
		void (*item_callback)(const ng_parser_t *, parser_arg, helper_arg), helper_arg arg)
{
	// list opener
	if (!skip_char(&pos->cur, '['))
		return;

	unsigned int idx = 0;

	while (true) {
		skip_chars(&pos->cur, ' ');
		if (!pos->cur.len)
			goto next; // empty token?

		// list closing?
		if (rtpp_dict_list_closing(pos))
			break;

		// does it start another list or dict?
		if (pos->cur.s[0] == '[') {
			if (item_callback)
				item_callback(parser, pos, arg);
			goto next;
		}

		// guess it's a string token
		// does it end the list?
		bool end = rtpp_dict_list_end_rewind(pos);

		if (pos->cur.len == 0)
			break; // nothing left

		if (str_callback)
			str_callback(&pos->cur, idx++, arg);
		if (end)
			break;
		goto next;

next:
		// find next token in remainder, put in `cur`
		if (!str_token_sep(&pos->cur, &pos->remainder, ' '))
			break;
	}
}
static bool rtpp_dict_iter(const ng_parser_t *parser, rtpp_pos *pos,
		void (*callback)(const ng_parser_t *, str *, parser_arg, helper_arg),
		helper_arg arg)
{
	// list opener
	if (!skip_char(&pos->cur, '['))
		return false;

	while (true) {
		skip_chars(&pos->cur, ' ');
		if (!pos->cur.len)
			goto next; // empty token?

		// dict closing?
		if (rtpp_dict_list_closing(pos))
			break;

		str key;
		if (!str_token(&key, &pos->cur, '=')) {
			ilog(LOG_ERR, "Entry in dictionary without equals sign ('" STR_FORMAT "'), aborting",
					STR_FMT(&pos->cur));
			break;
		}

		// guess it's a string token
		// does it end the dict?
		bool end = rtpp_dict_list_end_rewind(pos);

		if (pos->cur.len == 0)
			break; // nothing left

		callback(parser, &key, pos, arg);
		if (end)
			break;
		goto next;

next:
		// find next token in remainder, put in `cur`
		if (!str_token_sep(&pos->cur, &pos->remainder, ' '))
			break;
	}

	return true;
}
static bool rtpp_is_int(rtpp_pos *pos) {
	return false;
}

const ng_parser_t dummy_parser = {
	.is_list = rtpp_is_list,
	.is_dict = rtpp_is_dict,
	.is_int = rtpp_is_int,
	.list_iter = rtpp_list_iter,
	.dict_iter = rtpp_dict_iter,
	.get_str = rtpp_get_str,
	.get_int_str = rtpp_get_int_str,
};

static bool parse_codec_to_dict(str * key, str * val, const char *cmp1, const char *cmp2,
		const char * dictstr, sdp_ng_flags *flags)
{
	str s;

	if(!str_key_val_prefix(key, cmp1, val, &s)) {
		if(!cmp2)
			return false;
		if(!str_key_val_prefix(key, cmp2, val, &s))
			return false;
	}

	call_ng_codec_flags(&dummy_parser, STR_PTR(dictstr), &(rtpp_pos) {.cur = s}, flags);

	return true;
}

/* parse codec related flags */
static bool parse_codecs(sdp_ng_flags *flags, str * key, str * val) {
	if (parse_codec_to_dict(key, val, "transcode",
				"codec-transcode", "transcode", flags) ||
		parse_codec_to_dict(key, val, "codec-strip",
				NULL, "strip", flags) ||
		parse_codec_to_dict(key, val, "codec-offer",
				NULL, "offer", flags) ||
		parse_codec_to_dict(key, val, "codec-mask",
				NULL, "mask", flags) ||
		parse_codec_to_dict(key, val, "codec-set",
				NULL, "set", flags) ||
		parse_codec_to_dict(key, val, "codec-accept",
				NULL, "accept", flags) ||
		parse_codec_to_dict(key, val, "codec-except",
				NULL, "except", flags))
	{
		return true;
	}

	return false;
}

/* prase transport, such as for example RTP/AVP */
static void parse_transports(unsigned int transport, sdp_ng_flags *out)
{
	const char * val = transports[transport & 0x007];
	if (!val)
		return;
	call_ng_main_flags(&dummy_parser, &STR_CONST("transport-protocol"),
			&(rtpp_pos) {.cur = STR(val), .remainder = STR_NULL}, out);
}


static void rtpp_direction_flag(sdp_ng_flags *flags, unsigned int *flagnum, str *val) {
	static const str keys[2] = {STR_CONST("from-interface"), STR_CONST("to-interface")};
	if (*flagnum >= G_N_ELEMENTS(keys)) {
		ilog(LOG_WARN, "Too many 'direction=...' flags encountered");
		return;
	}
	str key = keys[(*flagnum)++];
	call_ng_main_flags(&dummy_parser, &key, &(rtpp_pos) {.cur = *val}, flags);
}

/**
 * Parse flags from bencode string into given bencode dictionary.
 *
 * Params:
 * @param rtpp_flags - raw str rtpp_flags
 * @param dict - root dict to store encoded flags
 */
void parse_rtpp_flags(const str * rtpp_flags, sdp_ng_flags *out)
{
	str remainder, key, val;
	unsigned int direction_flag = 0;
	unsigned int transport = 0;

	if (!rtpp_flags->s)
		return;

	remainder = *rtpp_flags;

	while (remainder.len)
	{
		/* skip spaces */
		skip_chars(&remainder, ' ');

		/* set key and val */
		if (!get_key_val(&key, &val, &remainder))
			break;

		/* codecs have own specific parsing as well */
		if (parse_codecs(out, &key, &val))
			goto next;

		/* parse other generic flags */
		switch (key.len)
		{
			case 3:
				/* transport */
				if (!val.s && str_eq(&key, "RTP"))
					transport = (transport | 0x100) & ~0x001;
				else if (!val.s && str_eq(&key, "AVP"))
					transport = (transport | 0x100) & ~0x002;
				/* other non-defined flags */
				else
					goto generic;
				goto next;
				break;
			case 4:
				/* transport */
				if (!val.s && str_eq(&key, "SRTP"))
					transport |= 0x101;
				else if (!val.s && str_eq(&key, "AVPF"))
					transport |= 0x102;
				else if (!val.s && str_eq(&key, "DTLS"))
					transport |= 0x104;
				/* other non-defined flags */
				else
					goto generic;
				goto next;
				break;
			case 7:
				/* transport */
				if (!val.s && str_eq(&key, "RTP/AVP"))
					transport = 0x100;
				/* other non-defined flags */
				else
					goto generic;
				goto next;
				break;
			case 8:
				/* transport */
				if (!val.s && str_eq(&key, "RTP/AVPF"))
					transport = 0x102;
				else if (!val.s && str_eq(&key, "RTP/SAVP"))
					transport = 0x101;
				/* from-tag can be overriden, but originally has to be provided */
				else if (val.s && str_eq(&key, "from-tag")) {
					out->directional = 1; /* explicitly add directional for this case */
					goto generic;
				}
				/* direction */
				else if (str_eq(&key, "internal") || str_eq(&key, "external"))
					rtpp_direction_flag(out, &direction_flag, &key);
				/* other non-defined flags */
				else
					goto generic;
				goto next;
				break;
			case 9:
				/* transport */
				if (!val.s && str_eq(&key, "RTP/SAVPF"))
					transport = 0x103;
				/* direction */
				else if (str_eq(&key, "direction") && rtpp_is_dict_list(&(rtpp_pos) {.cur=val}) == 0)
					rtpp_direction_flag(out, &direction_flag, &val);
				else
					goto generic;
				goto next;
				break;
			case 16:
				/* transport */
				if (!val.s && str_eq(&key, "UDP/TLS/RTP/SAVP"))
					transport = 0x104;
				else
					goto generic;
				goto next;
				break;
			case 17:
				/* transport */
				if (!val.s && str_eq(&key, "UDP/TLS/RTP/SAVPF"))
					transport = 0x106;
				else
					goto generic;
				goto next;
				break;
		}

generic:
		/* generic one key flags */
		if (!val.len)
			call_ng_flags_flags(&key, 0, out);
		/* generic flags with value, but no particular processing */
		else {
			rtpp_pos pos = { .cur = val, .remainder = remainder };
			call_ng_main_flags(&dummy_parser, &key, &pos, out);
			remainder = pos.remainder;
		}

next:;
	}

	/* define transport */
	if (transport)
		parse_transports(transport, out);
}
