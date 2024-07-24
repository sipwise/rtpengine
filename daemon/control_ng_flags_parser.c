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

static int get_ip_type(char *str_addr)
{
	struct addrinfo hint, *info = NULL;
	int ret;

	memset(&hint, '\0', sizeof hint);
	hint.ai_family = PF_UNSPEC;
	hint.ai_flags = AI_NUMERICHOST;

	ret = getaddrinfo(str_addr, NULL, &hint, &info);
	if(ret) {
		/* Invalid ip addinfos */
		return -1;
	}

	if(info->ai_family == AF_INET) {
		ilogs(control, LOG_DEBUG, "%s is an ipv4 addinfos", str_addr);
	} else if(info->ai_family == AF_INET6) {
		ilogs(control, LOG_DEBUG, "%s is an ipv6 addinfos", str_addr);
	} else {
		ilogs(control, LOG_DEBUG, "%s is an unknown addinfos format AF=%d", str_addr,
				info->ai_family);
		freeaddrinfo(info);
		return -1;
	}

	ret = info->ai_family;

	freeaddrinfo(info);

	return ret;
}

/* parsing of key and val from string */
static bool get_key_val(str * key, str * val, str *in_out)
{
	if (!str_token_sep(key, in_out, ' '))
		return false;
	// key=value ?
	str k;
	if (!str_token_sep(&k, key, '='))
		return true;
	*val = *key;
	*key = k;
	return true;
}

static inline int str_eq(const str *p, const char *q)
{
	int l = strlen(q);
	if(p->len != l)
		return 0;
	if(memcmp(p->s, q, l))
		return 0;
	return 1;
}

static inline int str_prefix(const str *p, const char *q, str *out)
{
	int l = strlen(q);
	if(p->len < l)
		return 0;
	if(memcmp(p->s, q, l))
		return 0;
	*out = *p;
	out->s += l;
	out->len -= l;
	return 1;
}

/* handle either "foo-bar" or "foo=bar" from flags */
static int str_key_val_prefix(const str * p, const char * q,
		const str * v, str * out)
{
	if(str_eq(p, q)) {
		if(!v->s || !v->len)
			return 0;

		*out = *v;
		return 1;
	}
	if(!str_prefix(p, q, out))
		return 0;
	if(out->len < 2)
		return 0;
	if(*out->s != '-')
		return 0;
	out->s++;
	out->len--;
	return 1;
}

/**
 * Work with bencode objects.
 */

/* parse `received-from` */
static bool parse_received_from(str * key, str * val, bencode_buffer_t * buf,
		sdp_ng_flags * out, enum call_opmode opmode)
{
	bencode_item_t * item;
	int ip_af = AF_UNSPEC;
	str ipfamily, s;

	if(str_key_val_prefix(key, "received-from", val, &s)) {
		item = bencode_list(buf);

		ip_af = get_ip_type(s.s);
		ipfamily.len = 3;
		ipfamily.s = (ip_af == AF_INET) ? "IP4" : "IP6";
		bencode_list_add_str(item, &ipfamily);

		bencode_list_add_str(item, &s);
		call_ng_main_flags(out, &STR_CONST_INIT("received-from"), item, opmode);
		return true;
	}
	return false;
}

static bool parse_codec_to_dict(str * key, str * val, const char *cmp1, const char *cmp2,
		const char * dictstr, sdp_ng_flags * out, bencode_buffer_t * buf,
		enum call_opmode opmode)
{
	str s;

	if(!str_key_val_prefix(key, cmp1, val, &s)) {
		if(!cmp2)
			return false;
		if(!str_key_val_prefix(key, cmp2, val, &s))
			return false;
	}

	call_ng_codec_flags(out, &STR_INIT(dictstr), bencode_str(buf, &s), opmode);

	return true;
}

/* parse codec related flags */
static bool parse_codecs(enum call_opmode opmode, sdp_ng_flags * out,
		bencode_buffer_t * buf, str * key, str * val)
{
	if (parse_codec_to_dict(key, val, "transcode",
				"codec-transcode", "transcode", out, buf, opmode) ||
		parse_codec_to_dict(key, val, "codec-strip",
				NULL, "strip", out, buf, opmode) ||
		parse_codec_to_dict(key, val, "codec-offer",
				NULL, "offer", out, buf, opmode) ||
		parse_codec_to_dict(key, val, "codec-mask",
				NULL, "mask", out, buf, opmode) ||
		parse_codec_to_dict(key, val, "codec-set",
				NULL, "set", out, buf, opmode) ||
		parse_codec_to_dict(key, val, "codec-accept",
				NULL, "accept", out, buf, opmode) ||
		parse_codec_to_dict(key, val, "codec-except",
				NULL, "except", out, buf, opmode))
	{
		return true;
	}

	return false;
}

/* prase transport, such as for example RTP/AVP */
static void parse_transports(sdp_ng_flags *out, bencode_buffer_t *buf,
		enum call_opmode opmode, unsigned int transport)
{
	const char * val = transports[transport & 0x007];
	if (!val)
		return;
	call_ng_main_flags(out, &STR_CONST_INIT("transport-protocol"), bencode_string(buf, val), opmode);
}

#if 0
static bool parse_str_flag(str * key, str * val, const char * name,
		bencode_item_t * root_dict)
{
	if(str_eq(key, name)) {
		if (val->s) {
			bencode_dictionary_str_add_str(root_dict, key, val);
			return true;
		}
	}
	return false;
}
#endif

/**
 * Parse flags from bencode string into given bencode dictionary.
 *
 * Params:
 * @param rtpp_flags - raw str rtpp_flags
 * @param dict - root dict to store encoded flags
 */
void parse_rtpp_flags(const str * rtpp_flags, bencode_buffer_t * buf,
		enum call_opmode opmode, sdp_ng_flags * out)
{
	str remainder, key, val;
	bencode_item_t * direction;
	unsigned int transport = 0;

	if (!rtpp_flags->s)
		return;

	remainder = *rtpp_flags;

	direction = bencode_list(buf);

	while (remainder.len)
	{
		/* skip spaces */
		while (remainder.len && remainder.s[0] == ' ')
			str_shift(&remainder, 1);

		/* set key and val */
		if (!get_key_val(&key, &val, &remainder))
			break;

		/* specific received-from parsing */
		if (parse_received_from(&key, &val, buf, out, opmode))
			goto next;

		/* codecs have own specific parsing as well */
		if (parse_codecs(opmode, out, buf, &key, &val))
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
					bencode_list_add_str(direction, &key);
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
				else if (str_eq(&key, "direction"))
					bencode_list_add_str(direction, &val);
				else
					goto generic;
				goto next;
				break;
			case 12:
				if (val.s && str_eq(&key, "delete-delay")) {
					call_ng_main_flags(out, &key, bencode_integer(buf, atoi(val.s)), opmode);
				} else
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
		if (!val.s)
			call_ng_flags_flags(out, &key, NULL);
		/* generic flags with value, but no particular processing */
		else
			call_ng_main_flags(out, &key, bencode_str(buf, &val), opmode);

next:;
	}

	/* define transport */
	if (transport)
		parse_transports(out, buf, opmode, transport);

	/* add directions to the root dict */
	if (direction && direction->child)
		call_ng_direction_flag(out, direction);
}
