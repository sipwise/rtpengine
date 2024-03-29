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

/* parsing of key and val from pure char array */
static bool get_key_val(str * key, str * val, const char * start, char ** eptr)
{
	key->s = (void *)start;
	val->len = key->len = -1;
	val->s = NULL;

	*eptr = strpbrk(key->s, " =");
	if(!*eptr) {
		*eptr = key->s + strlen(key->s);
	}
	/* for those flags with key=value syntax */
	else if(**eptr == '=') {
		key->len = *eptr - key->s;
		val->s = *eptr + 1;
		*eptr = strchr(val->s, ' ');
		if(!*eptr)
			*eptr = val->s + strlen(val->s);
		val->len = *eptr - val->s;
	}

	if(key->len == -1)
		key->len = *eptr - key->s;
	if(!key->len)
		return false;

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

/* parse flags, which have their own sub-list */
static bool new_list_to_dict(const char * key_name,
		str * key,
		str * val,
		str * s,
		bencode_buffer_t * buf,
		bencode_item_t * dict,
		bool received_from /* whether received-from is parsed */ )
{
	bencode_item_t * item;
	int ip_af = AF_UNSPEC;
	str ipfamily;

	if(str_key_val_prefix(key, key_name, val, s)) {
		item = bencode_list(buf);

		if (received_from) { /* only for received-from parsing */
			ip_af = get_ip_type(s->s);
			ipfamily.len = 3;
			ipfamily.s = (ip_af == AF_INET) ? "IP4" : "IP6";
			bencode_list_add_str(item, &ipfamily);
		}

		bencode_list_add_str(item, s);
		bencode_dictionary_add(dict, key_name, item); /* root dict */
		return true;
	}
	return false;
}

static bool parse_codec_to_dict(str * key, str * val, const char *cmp1, const char *cmp2,
		const char * dictstr, bencode_item_t * codec_dict, bencode_item_t * root_dict)
{
	str s;
	bencode_item_t * dictp;

	if(!str_key_val_prefix(key, cmp1, val, &s)) {
		if(!cmp2)
			return false;
		if(!str_key_val_prefix(key, cmp2, val, &s))
			return false;
	}

	dictp = bencode_list(root_dict->buffer);
	bencode_dictionary_add(codec_dict, dictstr, dictp);
	bencode_list_add_str(dictp, &s);

	return true;
}

/* parse codec related flags */
static bool parse_codecs(str * key, str * val, bencode_item_t * codec_dict, bencode_item_t * root_dict)
{
	if (parse_codec_to_dict(key, val, "transcode",
				"codec-transcode", "transcode", codec_dict, root_dict) ||
		parse_codec_to_dict(key, val, "codec-strip",
				NULL, "strip", codec_dict, root_dict) ||
		parse_codec_to_dict(key, val, "codec-offer",
				NULL, "offer", codec_dict, root_dict) ||
		parse_codec_to_dict(key, val, "codec-mask",
				NULL, "mask", codec_dict, root_dict) ||
		parse_codec_to_dict(key, val, "codec-set",
				NULL, "set", codec_dict, root_dict) ||
		parse_codec_to_dict(key, val, "codec-accept",
				NULL, "accept", codec_dict, root_dict) ||
		parse_codec_to_dict(key, val, "codec-except",
				NULL, "except", codec_dict, root_dict))
	{
		return true;
	}

	return false;
}

/* prase transport, such as for example RTP/AVP */
static void parse_transports(unsigned int transport, bencode_item_t * root_dict)
{
	const char * val = transports[transport & 0x007];
	if (!val)
		return;
	bencode_dictionary_add(root_dict, "transport-protocol",
				bencode_string(bencode_item_buffer(root_dict), val));
}

/* parse repacketize */
static void parse_repacketize(str * val, bencode_item_t * root_dict)
{
	int packetize = 0;
	while (isdigit(*val->s)) {
		packetize *= 10;
		packetize += *val->s - '0';
		val->s++;
	}
	if(!packetize)
		return;
	bencode_dictionary_add_integer(root_dict, "repacketize", packetize);
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
void parse_rtpp_flags(const str * rtpp_flags, bencode_item_t * root_dict,
		enum call_opmode opmode, sdp_ng_flags * out)
{
	char * start, * end, * eptr, c;
	str key, val, s;
	bencode_item_t * codec, * direction;
	bencode_buffer_t * buf;
	unsigned int transport = 0;

	if (!rtpp_flags->s)
		return;

	/* ensure rtpp_flags always null terminated */
	c = rtpp_flags->s[rtpp_flags->len];
	rtpp_flags->s[rtpp_flags->len] = '\0';

	buf = root_dict->buffer;
	start = rtpp_flags->s;
	end = rtpp_flags->s + rtpp_flags->len;

	codec = bencode_dictionary(buf);
	direction = bencode_list(buf);

	while (start < end)
	{
		/* skip spaces */
		while(*start == ' ')
			start++;

		/* set key and val */
		if (!get_key_val(&key, &val, start, &eptr))
			break;

		/* check for items which have their own sub-list */
		if (new_list_to_dict("replace", &key, &val, &s, buf, root_dict, false) ||
			new_list_to_dict("SDES", &key, &val, &s, buf, root_dict, false) ||
			new_list_to_dict("T38", &key, &val, &s, buf, root_dict, false) ||
			new_list_to_dict("T.38", &key, &val, &s, buf, root_dict, false) ||
			new_list_to_dict("rtcp-mux", &key, &val, &s, buf, root_dict, false) ||
			new_list_to_dict("received-from", &key, &val, &s, buf, root_dict, true))
		{
			goto next;
		}

		/* codecs have own specific parsing as well */
		if (parse_codecs(&key, &val, codec, root_dict))
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
				/* TOS */
				else if (str_eq(&key, "TOS")) {
					if (!val.s)
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					else
						bencode_dictionary_add_integer(root_dict, "TOS", atoi(val.s));
				}
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
			case 6:
				/* to-tag can be overriden, but originally could have been provided already */
				if (str_eq(&key, "to-tag")) {
					if (!val.s)
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					else
						bencode_dictionary_add_str(root_dict, "to-tag", &val);
				}
				else
					goto generic;
				goto next;
				break;
			case 7:
				/* transport */
				if (!val.s && str_eq(&key, "RTP/AVP"))
					transport = 0x100;
				/* call-id */
				else if (str_eq(&key, "call-id")) {
					if (!val.s)
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					else
						bencode_dictionary_add_str(root_dict, "call-id", &val);
				}
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
				else if (str_eq(&key, "from-tag")) {
					if (!val.s) {
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					} else {
						bencode_dictionary_add_str(root_dict, "from-tag", &val);
						out->directional = 1; /* explicitly add directional for this case */
					}
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
			case 10:
				/* via-branch can be overriddem here.
				 * but here it takes only actual value of via branch.
				 * other things, such as: auto, extra, next etc. are disallowed */
				if (str_eq(&key, "via-branch")) {
					if (!val.s)
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					else
						bencode_dictionary_add_str(root_dict, "via-branch", &val);
				}
				else
					goto generic;
				goto next;
				break;
			case 11:
				/* repacketize */
				if (str_eq(&key, "repacketize")) {
					if (!val.s)
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					else
						parse_repacketize(&val, root_dict);
				}
				else
					goto generic;
				goto next;
				break;
			case 12:
				if (str_eq(&key, "delete-delay")) {
					if (!val.s)
						ilogs(control, LOG_DEBUG, "Error processing flag '"STR_FORMAT"' (will be ignored)", STR_FMT(&key));
					else
						bencode_dictionary_add_integer(root_dict, "delete delay", atoi(val.s));
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
			bencode_dictionary_str_add_str(root_dict, &key, &val);
next:
		start = eptr;
	}

	/* define transport */
	if (transport)
		parse_transports(transport, root_dict);

	/* add codecs to the root dict */
	if (codec && codec->child)
		bencode_dictionary_add(root_dict, "codec", codec);

	/* add directions to the root dict */
	if (direction && direction->child)
		bencode_dictionary_add(root_dict, "direction", direction);

	rtpp_flags->s[rtpp_flags->len] = c;
}
