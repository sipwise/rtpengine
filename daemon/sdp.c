#include "sdp.h"

#include <glib.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <math.h>

#include "compat.h"
#include "call.h"
#include "log.h"
#include "str.h"
#include "call.h"
#include "crypto.h"
#include "dtls.h"

struct network_address {
	str network_type;
	str address_type;
	str address;
	struct in6_addr parsed;
};

struct sdp_origin {
	str username;
	str session_id;
	str version;
	struct network_address address;
	int parsed:1;
};

struct sdp_connection {
	struct network_address address;
	int parsed:1;
};

struct sdp_attributes {
	GQueue list;
	/* GHashTable *name_hash; */
	/* GHashTable *name_lists_hash; */
	GHashTable *id_lists_hash;
	GHashTable *id_hash;
};

struct sdp_session {
	str s;
	struct sdp_origin origin;
	struct sdp_connection connection;
	int rr, rs;
	struct sdp_attributes attributes;
	GQueue media_streams;
};

struct sdp_media {
	struct sdp_session *session;

	str s;
	str media_type;
	str port;
	str transport;
	/* ... format list */

	long int port_num;
	int port_count;

	struct sdp_connection connection;
	int rr, rs;
	struct sdp_attributes attributes;
};

struct attribute_rtcp {
	long int port_num;
	struct network_address address;
};

struct attribute_candidate {
	str foundation;
	str component_str;
	str transport;
	str priority_str;
	str ip_str;
	str port_str;
	str typ_str;
	str type_str;

	unsigned long component;
	unsigned long priority;
	int parsed:1;
};

struct attribute_crypto {
	str tag_str;
	str crypto_suite_str;
	str key_params_str;
	/* str session_params; */

	str key_base64_str;
	str lifetime_str;
	str mki_str;

	unsigned int tag;
	const struct crypto_suite *crypto_suite;
	str master_key;
	str salt;
	char key_salt_buf[SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN];
	u_int64_t lifetime;
	unsigned char mki[256];
	unsigned int mki_len;
};

struct attribute_ssrc {
	str id_str;
	str attr_str;

	u_int32_t id;
	str attr;
	str value;
};

struct attribute_group {
	enum {
		GROUP_OTHER = 0,
		GROUP_BUNDLE,
	} semantics;
};

struct attribute_fingerprint {
	str hash_func_str;
	str fingerprint_str;

	const struct dtls_hash_func *hash_func;
	unsigned char fingerprint[DTLS_MAX_DIGEST_LEN];
};

struct attribute_setup {
	str s;
	enum {
		SETUP_UNKNOWN = 0,
		SETUP_ACTPASS,
		SETUP_ACTIVE,
		SETUP_PASSIVE,
		SETUP_HOLDCONN,
	} value;
};

struct sdp_attribute {
	str full_line,	/* including a= and \r\n */
	    line_value,	/* without a= and without \r\n */
	    name,	/* just "rtpmap" */
	    value,	/* just "8 PCMA/8000" */
	    key,	/* "rtpmap:8" */
	    param;	/* "PCMA/8000" */

	enum {
		ATTR_OTHER = 0,
		ATTR_RTCP,
		ATTR_CANDIDATE,
		ATTR_ICE,
		ATTR_ICE_UFRAG,
		ATTR_CRYPTO,
		ATTR_SSRC,
		ATTR_INACTIVE,
		ATTR_SENDRECV,
		ATTR_SENDONLY,
		ATTR_RECVONLY,
		ATTR_RTCP_MUX,
		ATTR_EXTMAP,
		ATTR_GROUP,
		ATTR_MID,
		ATTR_FINGERPRINT,
		ATTR_SETUP,
	} attr;

	union {
		struct attribute_rtcp rtcp;
		struct attribute_candidate candidate;
		struct attribute_crypto crypto;
		struct attribute_ssrc ssrc;
		struct attribute_group group;
		struct attribute_fingerprint fingerprint;
		struct attribute_setup setup;
	} u;
};




static const char ice_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char ice_foundation[17];
static str ice_foundation_str;
static char ice_foundation_alt[17];
static str ice_foundation_str_alt;




//static int has_rtcp(struct sdp_media *media);



INLINE struct sdp_attribute *attr_get_by_id(struct sdp_attributes *a, int id) {
	return g_hash_table_lookup(a->id_hash, &id);
}

static struct sdp_attribute *attr_get_by_id_m_s(struct sdp_media *m, int id) {
	struct sdp_attribute *a;

	a = attr_get_by_id(&m->attributes, id);
	if (a)
		return a;
	return attr_get_by_id(&m->session->attributes, id);
}


/* hack hack */
INLINE int inet_pton_str(int af, str *src, void *dst) {
	char *s = src->s;
	char p;
	int ret;
	p = s[src->len];
	s[src->len] = '\0';
	ret = smart_pton(af, src->s, dst);
	s[src->len] = p;
	return ret;
}

int address_family(const str *s) {
	if (s->len != 3)
		return 0;

	if (!memcmp(s->s, "IP4", 3)
			|| !memcmp(s->s, "ip4", 3))
		return AF_INET;

	if (!memcmp(s->s, "IP6", 3)
			|| !memcmp(s->s, "ip6", 3))
		return AF_INET6;

	return 0;
}

static int __parse_address(struct in6_addr *out, str *network_type, str *address_type, str *address) {
	struct in_addr in4;
	int af;

	if (network_type) {
		if (network_type->len != 2)
			return -1;
		if (memcmp(network_type->s, "IN", 2)
				&& memcmp(network_type->s, "in", 2))
			return -1;
	}

	if (!address_type) {
		if (inet_pton_str(AF_INET, address, &in4) == 1)
			goto ip4;
		if (inet_pton_str(AF_INET6, address, out) == 1)
			return 0;
		return -1;
	}

	af = address_family(address_type);

	if (af == AF_INET) {
		if (inet_pton_str(AF_INET, address, &in4) != 1)
			return -1;
ip4:
		in4_to_6(out, in4.s_addr);
	}
	else if (af == AF_INET6) {
		if (inet_pton_str(AF_INET6, address, out) != 1)
			return -1;
	}
	else
		return -1;

	return 0;
}

static int parse_address(struct network_address *address) {
	return __parse_address(&address->parsed, &address->network_type,
			&address->address_type, &address->address);
}

INLINE int extract_token(char **sp, char *end, str *out) {
	char *space;

	out->s = *sp;
	space = memchr(*sp, ' ', end - *sp);
	if (space == *sp || end == *sp)
		return -1;

	if (!space) {
		out->len = end - *sp;
		*sp = end;
	}
	else {
		out->len = space - *sp;
		*sp = space + 1;
	}
	return 0;
	
}
#define EXTRACT_TOKEN(field) if (extract_token(&start, end, &output->field)) return -1
#define EXTRACT_NETWORK_ADDRESS(field) \
	EXTRACT_TOKEN(field.network_type); \
	EXTRACT_TOKEN(field.address_type); \
	EXTRACT_TOKEN(field.address); \
	if (parse_address(&output->field)) return -1

static int parse_origin(char *start, char *end, struct sdp_origin *output) {
	if (output->parsed)
		return -1;

	EXTRACT_TOKEN(username);
	EXTRACT_TOKEN(session_id);
	EXTRACT_TOKEN(version);
	EXTRACT_NETWORK_ADDRESS(address);

	output->parsed = 1;
	return 0;
}

static int parse_connection(char *start, char *end, struct sdp_connection *output) {
	if (output->parsed)
		return -1;

	EXTRACT_NETWORK_ADDRESS(address);

	output->parsed = 1;
	return 0;
}

static int parse_media(char *start, char *end, struct sdp_media *output) {
	char *ep;

	EXTRACT_TOKEN(media_type);
	EXTRACT_TOKEN(port);
	EXTRACT_TOKEN(transport);

	output->port_num = strtol(output->port.s, &ep, 10);
	if (ep == output->port.s)
		return -1;
	if (output->port_num < 0 || output->port_num > 0xffff)
		return -1;

	if (*ep == '/') {
		output->port_count = atoi(ep + 1);
		if (output->port_count <= 0)
			return -1;
		if (output->port_count > 10) /* unsupported */
			return -1;
	}
	else
		output->port_count = 1;

	return 0;
}

static void attrs_init(struct sdp_attributes *a) {
	g_queue_init(&a->list);
	/* a->name_hash = g_hash_table_new(str_hash, str_equal); */
	a->id_hash = g_hash_table_new(g_int_hash, g_int_equal);
	/* a->name_lists_hash = g_hash_table_new_full(str_hash, str_equal,
			NULL, (GDestroyNotify) g_queue_free); */
	a->id_lists_hash = g_hash_table_new_full(g_int_hash, g_int_equal,
			NULL, (GDestroyNotify) g_queue_free);
}

static int parse_attribute_group(struct sdp_attribute *output) {
	output->attr = ATTR_GROUP;

	output->u.group.semantics = GROUP_OTHER;
	if (output->value.len >= 7 && !strncmp(output->value.s, "BUNDLE ", 7))
		output->u.group.semantics = GROUP_BUNDLE;

	return 0;
}

static int parse_attribute_ssrc(struct sdp_attribute *output) {
	char *start, *end;
	struct attribute_ssrc *s;

	output->attr = ATTR_SSRC;

	start = output->value.s;
	end = start + output->value.len;

	EXTRACT_TOKEN(u.ssrc.id_str);
	EXTRACT_TOKEN(u.ssrc.attr_str);

	s = &output->u.ssrc;

	s->id = strtoul(s->id_str.s, NULL, 10);
	if (!s->id)
		return -1;

	s->attr = s->attr_str;
	str_chr_str(&s->value, &s->attr, ':');
	if (s->value.s) {
		s->attr.len = s->value.s - s->attr.s;
		str_shift(&s->value, 1);
	}

	return 0;
}

static int parse_attribute_crypto(struct sdp_attribute *output) {
	char *start, *end, *endp;
	struct attribute_crypto *c;
	int salt_key_len, enc_salt_key_len;
	int b64_state = 0;
	unsigned int b64_save = 0;
	gsize ret;
	str s;
	u_int32_t u32;
	const char *err;

	output->attr = ATTR_CRYPTO;

	start = output->value.s;
	end = start + output->value.len;

	EXTRACT_TOKEN(u.crypto.tag_str);
	EXTRACT_TOKEN(u.crypto.crypto_suite_str);
	EXTRACT_TOKEN(u.crypto.key_params_str);

	c = &output->u.crypto;

	c->tag = strtoul(c->tag_str.s, &endp, 10);
	err = "invalid 'tag'";
	if (endp == c->tag_str.s)
		goto error;

	c->crypto_suite = crypto_find_suite(&c->crypto_suite_str);
	err = "unknown crypto suite";
	if (!c->crypto_suite)
		goto error;
	salt_key_len = c->crypto_suite->master_key_len
			+ c->crypto_suite->master_salt_len;
	enc_salt_key_len = ceil((double) salt_key_len * 4.0/3.0);

	err = "invalid key parameter length";
	if (c->key_params_str.len < 7 + enc_salt_key_len)
		goto error;
	err = "unknown key method";
	if (strncasecmp(c->key_params_str.s, "inline:", 7))
		goto error;
	c->key_base64_str = c->key_params_str;
	str_shift(&c->key_base64_str, 7);
	ret = g_base64_decode_step(c->key_base64_str.s, enc_salt_key_len,
			(guchar *) c->key_salt_buf, &b64_state, &b64_save);
	err = "invalid base64 encoding";
	if (ret != salt_key_len)
		goto error;

	c->master_key.s = c->key_salt_buf;
	c->master_key.len = c->crypto_suite->master_key_len;
	c->salt.s = c->master_key.s + c->master_key.len;
	c->salt.len = c->crypto_suite->master_salt_len;

	c->lifetime_str = c->key_params_str;
	str_shift(&c->lifetime_str, 7 + enc_salt_key_len);
	if (c->lifetime_str.len >= 2) {
		err = "invalid key parameter syntax";
		if (c->lifetime_str.s[0] != '|')
			goto error;
		str_shift(&c->lifetime_str, 1);
		str_chr_str(&c->mki_str, &c->lifetime_str, '|');
		if (!c->mki_str.s) {
			if (str_chr(&c->lifetime_str, ':')) {
				c->mki_str = c->lifetime_str;
				c->lifetime_str = STR_NULL;
			}
		}
		else {
			c->lifetime_str.len = c->mki_str.s - c->lifetime_str.s;
			str_shift(&c->mki_str, 1);
		}
	}
	else
		c->lifetime_str = STR_NULL;

	if (c->lifetime_str.s) {
		if (c->lifetime_str.len >= 3 && !memcmp(c->lifetime_str.s, "2^", 2)) {
			c->lifetime = strtoull(c->lifetime_str.s + 2, NULL, 10);
			err = "invalid key lifetime";
			if (!c->lifetime || c->lifetime > 64)
				goto error;
			c->lifetime = 1 << c->lifetime;
		}
		else
			c->lifetime = strtoull(c->lifetime_str.s, NULL, 10);

		err = "invalid key lifetime";
		if (!c->lifetime || c->lifetime > c->crypto_suite->srtp_lifetime
				|| c->lifetime > c->crypto_suite->srtcp_lifetime)
			goto error;
	}

	if (c->mki_str.s) {
		str_chr_str(&s, &c->mki_str, ':');
		err = "invalid MKI specification";
		if (!s.s)
			goto error;
		u32 = htonl(strtoul(c->mki_str.s, NULL, 10));
		c->mki_len = strtoul(s.s + 1, NULL, 10);
		err = "MKI too long";
		if (c->mki_len > sizeof(c->mki))
			goto error;
		memset(c->mki, 0, c->mki_len);
		if (sizeof(u32) >= c->mki_len)
			memcpy(c->mki, ((void *) &u32) + (sizeof(u32) - c->mki_len), c->mki_len);
		else
			memcpy(c->mki + (c->mki_len - sizeof(u32)), &u32, sizeof(u32));
	}

	return 0;

error:
	ilog(LOG_ERROR, "Failed to parse a=crypto attribute: %s", err);
	return -1;
}

static int parse_attribute_rtcp(struct sdp_attribute *output) {
	char *ep, *start, *end;

	end = output->value.s + output->value.len;
	output->attr = ATTR_RTCP;
	output->u.rtcp.port_num = strtol(output->value.s, &ep, 10);
	if (ep == output->value.s)
		return -1;
	if (output->u.rtcp.port_num <= 0 || output->u.rtcp.port_num > 0xffff) {
		output->u.rtcp.port_num = 0;
		return -1;
	}
	if (*ep != ' ')
		return 0;
	ep++;
	if (ep >= end)
		return 0;

	start = ep;
	EXTRACT_NETWORK_ADDRESS(u.rtcp.address);

	return 0;
}

static int parse_attribute_candidate(struct sdp_attribute *output) {
	char *end, *start, *ep;

	start = output->value.s;
	end = start + output->value.len;
	output->attr = ATTR_CANDIDATE;

	EXTRACT_TOKEN(u.candidate.foundation);
	EXTRACT_TOKEN(u.candidate.component_str);
	EXTRACT_TOKEN(u.candidate.transport);
	EXTRACT_TOKEN(u.candidate.priority_str);
	EXTRACT_TOKEN(u.candidate.ip_str);
	EXTRACT_TOKEN(u.candidate.port_str);
	EXTRACT_TOKEN(u.candidate.typ_str);
	EXTRACT_TOKEN(u.candidate.type_str);

	output->u.candidate.component = strtoul(output->u.candidate.component_str.s, &ep, 10);
	if (ep == output->u.candidate.component_str.s)
		return -1;
	output->u.candidate.priority = strtoul(output->u.candidate.priority_str.s, &ep, 10);
	if (ep == output->u.candidate.priority_str.s)
		return -1;

	output->u.candidate.parsed = 1;
	return 0;
}

static int parse_attribute_fingerprint(struct sdp_attribute *output) {
	char *end, *start;
	unsigned char *c;
	int i;

	start = output->value.s;
	end = start + output->value.len;
	output->attr = ATTR_FINGERPRINT;

	EXTRACT_TOKEN(u.fingerprint.hash_func_str);
	EXTRACT_TOKEN(u.fingerprint.fingerprint_str);

	output->u.fingerprint.hash_func = dtls_find_hash_func(&output->u.fingerprint.hash_func_str);
	if (!output->u.fingerprint.hash_func)
		return -1;

	assert(sizeof(output->u.fingerprint.fingerprint) >= output->u.fingerprint.hash_func->num_bytes);

	c = (unsigned char *) output->u.fingerprint.fingerprint_str.s;
	for (i = 0; i < output->u.fingerprint.hash_func->num_bytes; i++) {
		if (c[0] >= '0' && c[0] <= '9')
			output->u.fingerprint.fingerprint[i] = c[0] - '0';
		else if (c[0] >= 'a' && c[0] <= 'f')
			output->u.fingerprint.fingerprint[i] = c[0] - 'a' + 10;
		else if (c[0] >= 'A' && c[0] <= 'F')
			output->u.fingerprint.fingerprint[i] = c[0] - 'A' + 10;
		else
			return -1;

		output->u.fingerprint.fingerprint[i] <<= 4;

		if (c[1] >= '0' && c[1] <= '9')
			output->u.fingerprint.fingerprint[i] |= c[1] - '0';
		else if (c[1] >= 'a' && c[1] <= 'f')
			output->u.fingerprint.fingerprint[i] |= c[1] - 'a' + 10;
		else if (c[1] >= 'A' && c[1] <= 'F')
			output->u.fingerprint.fingerprint[i] |= c[1] - 'A' + 10;
		else
			return -1;

		if (c[2] != ':')
			goto done;

		c += 3;
	}

	return -1;

done:
	if (++i != output->u.fingerprint.hash_func->num_bytes)
		return -1;

	return 0;
}

static int parse_attribute_setup(struct sdp_attribute *output) {
	output->attr = ATTR_SETUP;

	if (!str_cmp(&output->value, "actpass"))
		output->u.setup.value = SETUP_ACTPASS;
	else if (!str_cmp(&output->value, "active"))
		output->u.setup.value = SETUP_ACTIVE;
	else if (!str_cmp(&output->value, "passive"))
		output->u.setup.value = SETUP_PASSIVE;
	else if (!str_cmp(&output->value, "holdconn"))
		output->u.setup.value = SETUP_HOLDCONN;

	return 0;
}

static int parse_attribute(struct sdp_attribute *a) {
	int ret;

	a->name = a->line_value;
	str_chr_str(&a->value, &a->name, ':');
	if (a->value.s) {
		a->name.len -= a->value.len;
		a->value.s++;
		a->value.len--;

		a->key = a->name;
		str_chr_str(&a->param, &a->value, ' ');
		if (a->param.s) {
			a->key.len += 1 +
				(a->value.len - a->param.len);

			a->param.s++;
			a->param.len--;

			if (!a->param.len)
				a->param.s = NULL;
		}
		else
			a->key.len += 1 + a->value.len;
	}

	ret = 0;
	switch (a->name.len) {
		case 3:
			if (!str_cmp(&a->name, "mid"))
				a->attr = ATTR_MID;
			break;
		case 4:
			if (!str_cmp(&a->name, "rtcp"))
				ret = parse_attribute_rtcp(a);
			else if (!str_cmp(&a->name, "ssrc"))
				ret = parse_attribute_ssrc(a);
			break;
		case 5:
			if (!str_cmp(&a->name, "group"))
				ret = parse_attribute_group(a);
			else if (!str_cmp(&a->name, "setup"))
				ret = parse_attribute_setup(a);
			break;
		case 6:
			if (!str_cmp(&a->name, "crypto"))
				ret = parse_attribute_crypto(a);
			else if (!str_cmp(&a->name, "extmap"))
				a->attr = ATTR_EXTMAP;
			break;
		case 7:
			if (!str_cmp(&a->name, "ice-pwd"))
				a->attr = ATTR_ICE;
			break;
		case 8:
			switch (a->name.s[0]) {
				case 'i':
					if (!str_cmp(&a->name, "ice-lite"))
						a->attr = ATTR_ICE;
					else if (!str_cmp(&a->name, "inactive"))
						a->attr = ATTR_INACTIVE;
					break;
				case 's':
					if (!str_cmp(&a->name, "sendrecv"))
						a->attr = ATTR_SENDRECV;
					else if (!str_cmp(&a->name, "sendonly"))
						a->attr = ATTR_SENDONLY;
					break;
				case 'r':
					if (!str_cmp(&a->name, "recvonly"))
						a->attr = ATTR_RECVONLY;
					if (!str_cmp(&a->name, "rtcp-mux"))
						a->attr = ATTR_RTCP_MUX;
					break;
			}
			break;
		case 9:
			if (!str_cmp(&a->name, "candidate"))
				ret = parse_attribute_candidate(a);
			else if (!str_cmp(&a->name, "ice-ufrag"))
				a->attr = ATTR_ICE_UFRAG;
			break;
		case 11:
			if (!str_cmp(&a->name, "ice-options"))
				a->attr = ATTR_ICE;
			else if (!str_cmp(&a->name, "fingerprint"))
				ret = parse_attribute_fingerprint(a);
			break;
		case 12:
			if (!str_cmp(&a->name, "ice-mismatch"))
				a->attr = ATTR_ICE;
			break;
		case 17:
			if (!str_cmp(&a->name, "remote-candidates"))
				a->attr = ATTR_ICE;
			break;
	}

	return ret;
}

int sdp_parse(str *body, GQueue *sessions) {
	char *b, *end, *value, *line_end, *next_line;
	struct sdp_session *session = NULL;
	struct sdp_media *media = NULL;
	const char *errstr;
	struct sdp_attributes *attrs;
	struct sdp_attribute *attr;
	str *adj_s;
	GQueue *attr_queue;

	b = body->s;
	end = str_end(body);

	while (b && b < end - 1) {
		errstr = "Missing '=' sign";
		if (b[1] != '=')
			goto error;

		value = &b[2];
		line_end = memchr(value, '\n', end - value);
		if (!line_end) {
			/* assume missing LF at end of body */
			line_end = end;
			next_line = NULL;
		}
		else {
			next_line = line_end + 1;
			if (line_end[-1] == '\r')
				line_end--;
		}

		switch (b[0]) {
			case 'v':
				errstr = "Error in v= line";
				if (line_end != value + 1)
					goto error;
				if (value[0] != '0')
					goto error;

				session = g_slice_alloc0(sizeof(*session));
				g_queue_init(&session->media_streams);
				attrs_init(&session->attributes);
				g_queue_push_tail(sessions, session);
				media = NULL;
				session->s.s = b;
				session->rr = session->rs = -1;

				break;

			case 'o':
				errstr = "o= line found within media section";
				if (media)
					goto error;
				errstr = "Error parsing o= line";
				if (parse_origin(value, line_end, &session->origin))
					goto error;

				break;

			case 'm':
				media = g_slice_alloc0(sizeof(*media));
				media->session = session;
				attrs_init(&media->attributes);
				errstr = "Error parsing m= line";
				if (parse_media(value, line_end, media))
					goto error;
				g_queue_push_tail(&session->media_streams, media);
				media->s.s = b;
				media->rr = media->rs = -1;

				break;

			case 'c':
				errstr = "Error parsing c= line";
				if (parse_connection(value, line_end,
						media ? &media->connection : &session->connection))
					goto error;

				break;

			case 'a':
				attr = g_slice_alloc0(sizeof(*attr));

				attr->full_line.s = b;
				attr->full_line.len = next_line ? (next_line - b) : (line_end - b);

				attr->line_value.s = value;
				attr->line_value.len = line_end - value;

				if (parse_attribute(attr)) {
					g_slice_free1(sizeof(*attr), attr);
					break;
				}

				attrs = media ? &media->attributes : &session->attributes;
				g_queue_push_tail(&attrs->list, attr);
				/* g_hash_table_insert(attrs->name_hash, &attr->name, attr); */
				if (!g_hash_table_lookup(attrs->id_hash, &attr->attr))
					g_hash_table_insert(attrs->id_hash, &attr->attr, attr);
				/* if (attr->key.s)
					g_hash_table_insert(attrs->name_hash, &attr->key, attr); */

				/* attr_queue = g_hash_table_lookup(attrs->name_lists_hash, &attr->name);
				if (!attr_queue)
					g_hash_table_insert(attrs->name_lists_hash, &attr->name,
							(attr_queue = g_queue_new()));
				g_queue_push_tail(attr_queue, attr); */
				attr_queue = g_hash_table_lookup(attrs->id_lists_hash, &attr->attr);
				if (!attr_queue)
					g_hash_table_insert(attrs->id_lists_hash, &attr->attr,
							(attr_queue = g_queue_new()));
				g_queue_push_tail(attr_queue, attr);

				break;

			case 'b':
				/* RR:0 */
				if (line_end - value < 4)
					break;
				if (!memcmp(value, "RR:", 3))
					*(media ? &media->rr : &session->rr) = 
						(line_end - value == 4 && value[3] == '0') ? 0 : 1;
				else if (!memcmp(value, "RS:", 3))
					*(media ? &media->rs : &session->rs) = 
						(line_end - value == 4 && value[3] == '0') ? 0 : 1;
				break;

			case 's':
			case 'i':
			case 'u':
			case 'e':
			case 'p':
			case 't':
			case 'r':
			case 'z':
			case 'k':
				break;

			default:
				errstr = "Unknown SDP line type found";
				goto error;
		}

		errstr = "SDP doesn't start with a session definition";
		if (!session)
			goto error;

		adj_s = media ? &media->s : &session->s;
		adj_s->len = (next_line ? : end) - adj_s->s;

		b = next_line;
	}

	return 0;

error:
	ilog(LOG_WARNING, "Error parsing SDP at offset %li: %s", b - body->s, errstr);
	sdp_free(sessions);
	return -1;
}

static void free_attributes(struct sdp_attributes *a) {
	struct sdp_attribute *attr;

	/* g_hash_table_destroy(a->name_hash); */
	g_hash_table_destroy(a->id_hash);
	/* g_hash_table_destroy(a->name_lists_hash); */
	g_hash_table_destroy(a->id_lists_hash);
	while ((attr = g_queue_pop_head(&a->list))) {
		g_slice_free1(sizeof(*attr), attr);
	}
}

void sdp_free(GQueue *sessions) {
	struct sdp_session *session;
	struct sdp_media *media;

	while ((session = g_queue_pop_head(sessions))) {
		while ((media = g_queue_pop_head(&session->media_streams))) {
			free_attributes(&media->attributes);
			g_slice_free1(sizeof(*media), media);
		}
		free_attributes(&session->attributes);
		g_slice_free1(sizeof(*session), session);
	}
}

static int fill_endpoint(struct endpoint *ep, const struct sdp_media *media, struct sdp_ng_flags *flags,
		struct network_address *address, long int port) {
	struct sdp_session *session = media->session;

	if (!flags->trust_address) {
		if (is_addr_unspecified(&flags->parsed_received_from)) {
			if (__parse_address(&flags->parsed_received_from, NULL, &flags->received_from_family,
						&flags->received_from_address))
				return -1;
		}
		ep->ip46 = flags->parsed_received_from;
	}
	else if (address && !is_addr_unspecified(&address->parsed))
		ep->ip46 = address->parsed;
	else if (media->connection.parsed)
		ep->ip46 = media->connection.address.parsed;
	else if (session->connection.parsed)
		ep->ip46 = session->connection.address.parsed;
	else
		return -1;

	ep->port = port;

	return 0;
}


int sdp_streams(const GQueue *sessions, GQueue *streams, struct sdp_ng_flags *flags) {
	struct sdp_session *session;
	struct sdp_media *media;
	struct stream_params *sp;
	GList *l, *k;
	const char *errstr;
	int num;
	struct sdp_attribute *attr;

	num = 0;
	for (l = sessions->head; l; l = l->next) {
		session = l->data;

		for (k = session->media_streams.head; k; k = k->next) {
			media = k->data;

			sp = g_slice_alloc0(sizeof(*sp));
			sp->index = ++num;

			errstr = "No address info found for stream";
			if (fill_endpoint(&sp->rtp_endpoint, media, flags, NULL, media->port_num))
				goto error;

			sp->consecutive_ports = media->port_count;
			sp->protocol = transport_protocol(&media->transport);
			sp->type = media->media_type;
			memcpy(sp->direction, flags->directions, sizeof(sp->direction));
			sp->desired_family = flags->address_family;
			bf_xset(&sp->sp_flags, SP_FLAG_ASYMMETRIC, flags->asymmetric);
			bf_xset(&sp->sp_flags, SP_FLAG_STRICT_SOURCE, flags->strict_source);
			bf_xset(&sp->sp_flags, SP_FLAG_MEDIA_HANDOVER, flags->media_handover);

			/* a=crypto */
			attr = attr_get_by_id(&media->attributes, ATTR_CRYPTO);
			if (attr) {
				sp->crypto.crypto_suite = attr->u.crypto.crypto_suite;
				sp->crypto.mki_len = attr->u.crypto.mki_len;
				if (sp->crypto.mki_len) {
					sp->crypto.mki = malloc(sp->crypto.mki_len);
					memcpy(sp->crypto.mki, attr->u.crypto.mki, sp->crypto.mki_len);
				}
				sp->sdes_tag = attr->u.crypto.tag;
				assert(sizeof(sp->crypto.master_key) >= attr->u.crypto.master_key.len);
				assert(sizeof(sp->crypto.master_salt) >= attr->u.crypto.salt.len);
				memcpy(sp->crypto.master_key, attr->u.crypto.master_key.s,
						attr->u.crypto.master_key.len);
				memcpy(sp->crypto.master_salt, attr->u.crypto.salt.s,
						attr->u.crypto.salt.len);
			}

			/* a=sendrecv/sendonly/recvonly/inactive */
			SP_SET(sp, SEND);
			SP_SET(sp, RECV);
			if (attr_get_by_id_m_s(media, ATTR_RECVONLY))
				SP_CLEAR(sp, SEND);
			else if (attr_get_by_id_m_s(media, ATTR_SENDONLY))
				SP_CLEAR(sp, RECV);
			else if (attr_get_by_id_m_s(media, ATTR_INACTIVE))
			{
				SP_CLEAR(sp, RECV);
				SP_CLEAR(sp, SEND);
			}

			/* a=setup */
			attr = attr_get_by_id_m_s(media, ATTR_SETUP);
			if (attr) {
				if (attr->u.setup.value == SETUP_ACTPASS
						|| attr->u.setup.value == SETUP_ACTIVE)
					SP_SET(sp, SETUP_ACTIVE);
				if (attr->u.setup.value == SETUP_ACTPASS
						|| attr->u.setup.value == SETUP_PASSIVE)
					SP_SET(sp, SETUP_PASSIVE);
			}

			/* a=fingerprint */
			attr = attr_get_by_id_m_s(media, ATTR_FINGERPRINT);
			if (attr && attr->u.fingerprint.hash_func) {
				sp->fingerprint.hash_func = attr->u.fingerprint.hash_func;
				memcpy(sp->fingerprint.digest, attr->u.fingerprint.fingerprint,
						sp->fingerprint.hash_func->num_bytes);
			}

			/* a=candidate */
			if (attr_get_by_id(&media->attributes, ATTR_CANDIDATE))
				SP_SET(sp, ICE);

			/* determine RTCP endpoint */

			if (attr_get_by_id(&media->attributes, ATTR_RTCP_MUX)) {
				SP_SET(sp, RTCP_MUX);
				goto next;
			}

			if (media->port_count != 1)
				goto next;

			attr = attr_get_by_id(&media->attributes, ATTR_RTCP);
			if (!attr) {
				SP_SET(sp, IMPLICIT_RTCP);
				goto next;
			}
			if (attr->u.rtcp.port_num == sp->rtp_endpoint.port) {
				SP_SET(sp, RTCP_MUX);
				goto next;
			}
			errstr = "Invalid RTCP attribute";
			if (fill_endpoint(&sp->rtcp_endpoint, media, flags, &attr->u.rtcp.address,
						attr->u.rtcp.port_num))
				goto error;

next:
			g_queue_push_tail(streams, sp);
		}
	}

	return 0;

error:
	ilog(LOG_WARNING, "Failed to extract streams from SDP: %s", errstr);
	if (sp)
		g_slice_free1(sizeof(*sp), sp);
	return -1;
}

struct sdp_chopper *sdp_chopper_new(str *input) {
	struct sdp_chopper *c = g_slice_alloc0(sizeof(*c));
	c->input = input;
	c->chunk = g_string_chunk_new(512);
	c->iov = g_array_new(0, 0, sizeof(struct iovec));
	return c;
}

INLINE void chopper_append(struct sdp_chopper *c, const char *s, int len) {
	struct iovec *iov;

	g_array_set_size(c->iov, ++c->iov_num);
	iov = &g_array_index(c->iov, struct iovec, c->iov_num - 1);
	iov->iov_base = (void *) s;
	iov->iov_len = len;
	c->str_len += len;
}
INLINE void chopper_append_c(struct sdp_chopper *c, const char *s) {
	chopper_append(c, s, strlen(s));
}
INLINE void chopper_append_str(struct sdp_chopper *c, const str *s) {
	chopper_append(c, s->s, s->len);
}

static void chopper_append_dup(struct sdp_chopper *c, const char *s, int len) {
	return chopper_append(c, g_string_chunk_insert_len(c->chunk, s, len), len);
}

static void chopper_append_printf(struct sdp_chopper *c, const char *fmt, ...) __attribute__((format(printf,2,3)));

static void chopper_append_printf(struct sdp_chopper *c, const char *fmt, ...) {
	char buf[512];
	int l;
	va_list va;

	va_start(va, fmt);
	l = vsnprintf(buf, sizeof(buf) - 1, fmt, va);
	va_end(va);
	chopper_append(c, g_string_chunk_insert_len(c->chunk, buf, l), l);
}

static int copy_up_to_ptr(struct sdp_chopper *chop, const char *b) {
	int offset, len;

	offset = b - chop->input->s;
	assert(offset >= 0);
	assert(offset <= chop->input->len);

	len = offset - chop->position;
	if (len < 0) {
		ilog(LOG_WARNING, "Malformed SDP, cannot rewrite");
		return -1;
	}
	chopper_append(chop, chop->input->s + chop->position, len);
	chop->position += len;
	return 0;
}

static int copy_up_to(struct sdp_chopper *chop, str *where) {
	return copy_up_to_ptr(chop, where->s);
}

static int copy_up_to_end_of(struct sdp_chopper *chop, str *where) {
	return copy_up_to_ptr(chop, where->s + where->len);
}

static void copy_remainder(struct sdp_chopper *chop) {
	copy_up_to_ptr(chop, chop->input->s + chop->input->len);
}

static int skip_over(struct sdp_chopper *chop, str *where) {
	int offset, len;

	offset = (where->s - chop->input->s) + where->len;
	assert(offset >= 0);
	assert(offset <= chop->input->len);

	len = offset - chop->position;
	if (len < 0) {
		ilog(LOG_WARNING, "Malformed SDP, cannot rewrite");
		return -1;
	}
	chop->position += len;
	return 0;
}

static int replace_transport_protocol(struct sdp_chopper *chop,
		struct sdp_media *media, struct call_media *cm)
{
	str *tp = &media->transport;

	if (!cm->protocol)
		return 0;

	if (copy_up_to(chop, tp))
		return -1;
	chopper_append_c(chop, cm->protocol->name);
	if (skip_over(chop, tp))
		return -1;

	return 0;
}

static int replace_media_port(struct sdp_chopper *chop, struct sdp_media *media, struct packet_stream *ps) {
	str *port = &media->port;
	unsigned int p;

	if (!media->port_num)
		return 0;

	if (copy_up_to(chop, port))
		return -1;

	p = ps->sfd ? ps->sfd->fd.localport : 0;
	chopper_append_printf(chop, "%u", p);

	if (skip_over(chop, port))
		return -1;

	return 0;
}

static int replace_consecutive_port_count(struct sdp_chopper *chop, struct sdp_media *media,
		struct packet_stream *ps, GList *j)
{
	int cons;
	struct packet_stream *ps_n;

	if (media->port_count == 1 || !ps->sfd)
		return 0;

	for (cons = 1; cons < media->port_count; cons++) {
		j = j->next;
		if (!j)
			goto warn;
		ps_n = j->data;
		if (ps_n->sfd->fd.localport != ps->sfd->fd.localport + cons * 2) {
warn:
			ilog(LOG_WARN, "Failed to handle consecutive ports");
			break;
		}
	}

	chopper_append_printf(chop, "/%i", cons);

	return 0;
}

static int insert_ice_address(struct sdp_chopper *chop, struct packet_stream *ps) {
	char buf[64];
	int len;

	call_stream_address(buf, ps, SAF_ICE, &len);
	chopper_append_dup(chop, buf, len);
	chopper_append_printf(chop, " %hu", ps->sfd->fd.localport);

	return 0;
}

static int insert_ice_address_alt(struct sdp_chopper *chop, struct packet_stream *ps) {
	char buf[64];
	int len;

	call_stream_address_alt(buf, ps, SAF_ICE, &len);
	chopper_append_dup(chop, buf, len);
	chopper_append_printf(chop, " %hu", ps->sfd->fd.localport);

	return 0;
}

static int replace_network_address(struct sdp_chopper *chop, struct network_address *address,
		struct packet_stream *ps, struct sdp_ng_flags *flags)
{
	char buf[64];
	int len;

	if (is_addr_unspecified(&address->parsed))
		return 0;

	if (copy_up_to(chop, &address->address_type))
		return -1;

	if (flags->media_address.s && is_addr_unspecified(&flags->parsed_media_address))
		__parse_address(&flags->parsed_media_address, NULL, NULL, &flags->media_address);

	if (!is_addr_unspecified(&flags->parsed_media_address)) {
		if (IN6_IS_ADDR_V4MAPPED(&flags->parsed_media_address))
			len = sprintf(buf, "IP4 " IPF, IPP(flags->parsed_media_address.s6_addr32[3]));
		else {
			memcpy(buf, "IP6 ", 4);
			inet_ntop(AF_INET6, &flags->parsed_media_address, buf + 4, sizeof(buf)-4);
			len = strlen(buf);
		}
	}
	else
		call_stream_address(buf, ps, SAF_NG, &len);
	chopper_append_dup(chop, buf, len);

	if (skip_over(chop, &address->address))
		return -1;

	return 0;
}

void sdp_chopper_destroy(struct sdp_chopper *chop) {
	g_string_chunk_free(chop->chunk);
	g_array_free(chop->iov, 1);
	g_slice_free1(sizeof(*chop), chop);
}

static void random_ice_string(char *buf, int len) {
	while (len--)
		*buf++ = ice_chars[random() % strlen(ice_chars)];
}

static void create_random_ice_string(struct call *call, str *s, int len) {
	char buf[30];

	assert(len < sizeof(buf));
	if (s->s)
		return;

	random_ice_string(buf, len);
	call_str_cpy_len(call, s, buf, len);
}

static int process_session_attributes(struct sdp_chopper *chop, struct sdp_attributes *attrs,
		struct sdp_ng_flags *flags)
{
	GList *l;
	struct sdp_attribute *attr;

	for (l = attrs->list.head; l; l = l->next) {
		attr = l->data;

		switch (attr->attr) {
			case ATTR_ICE:
			case ATTR_ICE_UFRAG:
				if (!flags->ice_remove && !flags->ice_force)
					break;
				goto strip;

			case ATTR_CANDIDATE:
				if (flags->ice_force_relay) {
					if ((attr->u.candidate.type_str.len == 5) &&
					    (strncasecmp(attr->u.candidate.type_str.s, "relay", 5) == 0))
						goto strip;
					else
						break;
				}
				if (!flags->ice_remove && !flags->ice_force)
					break;
				goto strip;

			case ATTR_EXTMAP:
			case ATTR_INACTIVE:
			case ATTR_SENDONLY:
			case ATTR_RECVONLY:
			case ATTR_SENDRECV:
			case ATTR_FINGERPRINT:
			case ATTR_SETUP:
				goto strip;

			case ATTR_GROUP:
				if (attr->u.group.semantics == GROUP_BUNDLE)
					goto strip;
				break;

			default:
				break;
		}

		continue;

strip:
		if (copy_up_to(chop, &attr->full_line))
			return -1;
		if (skip_over(chop, &attr->full_line))
			return -1;
	}

	return 0;
}

static int process_media_attributes(struct sdp_chopper *chop, struct sdp_media *sdp,
		struct sdp_ng_flags *flags, struct call_media *media)
{
	GList *l;
	struct sdp_attributes *attrs = &sdp->attributes;
	struct sdp_attribute *attr, *a;

	for (l = attrs->list.head; l; l = l->next) {
		attr = l->data;

		switch (attr->attr) {
			case ATTR_ICE:
			case ATTR_ICE_UFRAG:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				if (!flags->ice_remove && !flags->ice_force)
					break;
				goto strip;

			case ATTR_CANDIDATE:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				if (flags->ice_force_relay) {
					if ((attr->u.candidate.type_str.len == 5) &&
					    (strncasecmp(attr->u.candidate.type_str.s, "relay", 5) == 0))
						goto strip;
					else
						break;
				}
				if (!flags->ice_remove && !flags->ice_force)
					break;
				goto strip;

			case ATTR_RTCP:
			case ATTR_RTCP_MUX:
				if (flags->ice_force_relay)
					break;
			case ATTR_INACTIVE:
			case ATTR_SENDONLY:
			case ATTR_RECVONLY:
			case ATTR_SENDRECV:
				goto strip;

			case ATTR_EXTMAP:
			case ATTR_CRYPTO:
			case ATTR_FINGERPRINT:
			case ATTR_SETUP:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				goto strip;

			case ATTR_MID:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				a = attr_get_by_id(&sdp->session->attributes, ATTR_GROUP);
				if (a && a->u.group.semantics == GROUP_BUNDLE)
					goto strip;
				break;

			default:
				break;
		}

		continue;

strip:
		if (copy_up_to(chop, &attr->full_line))
			return -1;
		if (skip_over(chop, &attr->full_line))
			return -1;
	}

	return 0;
}

INLINE unsigned long prio_calc(unsigned int pref, unsigned int tpref) {
	return (1 << 24) * tpref + (1 << 8) * pref + 256 * 1;
}

static unsigned long new_priority(struct sdp_media *media, int relay) {
	int id;
	GQueue *cands;
	int pref;
	unsigned long prio, tpref;
	GList *l;
	struct sdp_attribute *a;
	struct attribute_candidate *c;

	tpref = 126;
	if (relay)
		tpref = 0;
	pref = 65535;
	prio = prio_calc(pref, tpref);

	if (!media)
		goto out;

	id = ATTR_CANDIDATE;
	cands = g_hash_table_lookup(media->attributes.id_lists_hash, &id);
	if (!cands)
		goto out;

	for (l = cands->head; l; l = l->next) {
		a = l->data;
		c = &a->u.candidate;
		while (c->priority >= prio && pref >= 1) {
			pref--;
			prio = prio_calc(pref, tpref);
		}
	}

out:
	return prio;
}

static void insert_candidates(struct sdp_chopper *chop, struct packet_stream *rtp, struct packet_stream *rtcp,
			      unsigned long priority, struct sdp_media *media,
			      unsigned int relay)
{
	chopper_append_c(chop, "a=candidate:");
	chopper_append_str(chop, &ice_foundation_str);
	chopper_append_printf(chop, " 1 UDP %lu ", priority);
	insert_ice_address(chop, rtp);
	if (relay)
	    chopper_append_c(chop, " typ relay\r\n");
	else
	    chopper_append_c(chop, " typ host\r\n");

	if (rtcp) {
		/* rtcp-mux only possible in answer */
		chopper_append_c(chop, "a=candidate:");
		chopper_append_str(chop, &ice_foundation_str);
		chopper_append_printf(chop, " 2 UDP %lu ", priority - 1);
		insert_ice_address(chop, rtcp);
		if (relay)
		    chopper_append_c(chop, " typ relay\r\n");
		else
		    chopper_append_c(chop, " typ host\r\n");
	}

}

static void insert_candidates_alt(struct sdp_chopper *chop, struct packet_stream *rtp, struct packet_stream *rtcp,
				  unsigned long priority, struct sdp_media *media,
				  unsigned int relay)
{
	chopper_append_c(chop, "a=candidate:");
	chopper_append_str(chop, &ice_foundation_str_alt);
	chopper_append_printf(chop, " 1 UDP %lu ", priority);
	insert_ice_address_alt(chop, rtp);
	if (relay)
	    chopper_append_c(chop, " typ relay\r\n");
	else
	    chopper_append_c(chop, " typ host\r\n");

	if (rtcp) {
		chopper_append_c(chop, "a=candidate:");
		chopper_append_str(chop, &ice_foundation_str_alt);
		chopper_append_printf(chop, " 2 UDP %lu ", priority - 1);
		insert_ice_address_alt(chop, rtcp);
		if (relay)
		    chopper_append_c(chop, " typ relay\r\n");
		else
		    chopper_append_c(chop, " typ host\r\n");
	}

}

static int has_ice(GQueue *sessions) {
	GList *l, *m;
	struct sdp_session *session;
	struct sdp_media *media;

	for (l = sessions->head; l; l = l->next) {
		session = l->data;

		if (attr_get_by_id(&session->attributes, ATTR_ICE_UFRAG))
			return 1;

		for (m = session->media_streams.head; m; m = m->next) {
			media = m->data;

			if (attr_get_by_id(&media->attributes, ATTR_ICE_UFRAG))
				return 1;
		}
	}

	return 0;
}

static void insert_dtls(struct call_media *media, struct sdp_chopper *chop) {
	char hexbuf[DTLS_MAX_DIGEST_LEN * 3 + 2];
	unsigned char *p;
	char *o;
	int i;
	const struct dtls_hash_func *hf;
	const char *actpass;
	struct call *call = media->call;

	if (!call->dtls_cert || !MEDIA_ISSET(media, DTLS) || MEDIA_ISSET(media, PASSTHRU))
		return;

	hf = call->dtls_cert->fingerprint.hash_func;

	assert(hf->num_bytes > 0);

	p = call->dtls_cert->fingerprint.digest;
	o = hexbuf;
	for (i = 0; i < hf->num_bytes; i++)
		o += sprintf(o, "%02X:", *p++);
	*(--o) = '\0';

	actpass = "holdconn";
	if (MEDIA_ISSET(media, SETUP_PASSIVE)) {
		if (MEDIA_ISSET(media, SETUP_ACTIVE))
			actpass = "actpass";
		else
			actpass = "passive";
	}
	else if (MEDIA_ISSET(media, SETUP_ACTIVE))
		actpass = "active";

	chopper_append_c(chop, "a=setup:");
	chopper_append_c(chop, actpass);
	chopper_append_c(chop, "\r\na=fingerprint:");
	chopper_append_c(chop, hf->name);
	chopper_append_c(chop, " ");
	chopper_append_dup(chop, hexbuf, o - hexbuf);
	chopper_append_c(chop, "\r\n");
}

static void insert_crypto(struct call_media *media, struct sdp_chopper *chop) {
	char b64_buf[((SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN) / 3 + 1) * 4 + 4];
	char *p;
	int state = 0, save = 0, i;
	struct crypto_params *cp = &media->sdes_out.params;
	unsigned long long ull;

	if (!cp->crypto_suite || !MEDIA_ISSET(media, SDES) || MEDIA_ISSET(media, PASSTHRU))
		return;

	p = b64_buf;
	p += g_base64_encode_step((unsigned char *) cp->master_key,
			cp->crypto_suite->master_key_len, 0,
			p, &state, &save);
	p += g_base64_encode_step((unsigned char *) cp->master_salt,
			cp->crypto_suite->master_salt_len, 0,
			p, &state, &save);
	p += g_base64_encode_close(0, p, &state, &save);

	chopper_append_c(chop, "a=crypto:");
	chopper_append_printf(chop, "%u ", media->sdes_out.tag);
	chopper_append_c(chop, cp->crypto_suite->name);
	chopper_append_c(chop, " inline:");
	chopper_append_dup(chop, b64_buf, p - b64_buf);
	if (cp->mki_len) {
		ull = 0;
		for (i = 0; i < cp->mki_len && i < sizeof(ull); i++)
			ull |= cp->mki[cp->mki_len - i - 1] << (i * 8);
		chopper_append_printf(chop, "|%llu:%u", ull, cp->mki_len);
	}
	chopper_append_c(chop, "\r\n");
}


/* called with call->master_lock held in W */
int sdp_replace(struct sdp_chopper *chop, GQueue *sessions, struct call_monologue *monologue,
		struct sdp_ng_flags *flags)
{
	struct sdp_session *session;
	struct sdp_media *sdp_media;
	GList *l, *k, *m, *j;
	int do_ice,  media_index, sess_conn;
	unsigned long priority;
	struct call_media *call_media;
	struct packet_stream *ps, *ps_rtcp;
	struct call *call;

	m = monologue->medias.head;
	do_ice = (flags->ice_force || flags->ice_force_relay ||
		  (!has_ice(sessions) && !flags->ice_remove)) ? 1 : 0;
	call = monologue->call;

	for (l = sessions->head; l; l = l->next) {
		session = l->data;
		if (!m)
			goto error;
		call_media = m->data;
		if (call_media->index != 1)
			goto error;
		j = call_media->streams.head;
		if (!j)
			goto error;
		ps = j->data;

		sess_conn = 0;
		if (flags->replace_sess_conn)
			sess_conn = 1;
		else {
			for (k = session->media_streams.head; k; k = k->next) {
				sdp_media = k->data;
				if (!sdp_media->connection.parsed) {
					sess_conn = 1;
					break;
				}
			}
		}

		if (session->origin.parsed && flags->replace_origin &&
		    !flags->ice_force_relay) {
			if (replace_network_address(chop, &session->origin.address, ps, flags))
				goto error;
		}
		if (session->connection.parsed && sess_conn &&
		    !flags->ice_force_relay) {
			if (replace_network_address(chop, &session->connection.address, ps, flags))
				goto error;
		}

		if (!MEDIA_ISSET(call_media, PASSTHRU)) {
			if (process_session_attributes(chop, &session->attributes, flags))
				goto error;

			if (do_ice) {
				copy_up_to_end_of(chop, &session->s);
				chopper_append_c(chop, "a=ice-lite\r\n");
			}
		}

		media_index = 1;

		for (k = session->media_streams.head; k; k = k->next) {
			sdp_media = k->data;
			if (!m)
				goto error;
			call_media = m->data;
			if (call_media->index != media_index)
				goto error;
			j = call_media->streams.head;
			if (!j)
				goto error;
			ps = j->data;

			if (!flags->ice_force_relay) {
			        if (replace_media_port(chop, sdp_media, ps))
				        goto error;
			        if (replace_consecutive_port_count(chop, sdp_media, ps, j))
				        goto error;
				if (replace_transport_protocol(chop, sdp_media, call_media))
				        goto error;

				if (sdp_media->connection.parsed) {
				        if (replace_network_address(chop, &sdp_media->connection.address, ps, flags))
					        goto error;
				}
			}

			if (process_media_attributes(chop, sdp_media, flags, call_media))
				goto error;

			copy_up_to_end_of(chop, &sdp_media->s);

			ps_rtcp = NULL;
			if (ps->rtcp_sibling) {
				ps_rtcp = ps->rtcp_sibling;
				j = j->next;
				if (!j)
					goto error;
				assert(j->data == ps_rtcp);
			}

			if (!sdp_media->port_num || !ps->sfd)
				goto next;

			if (MEDIA_ISSET(call_media, SEND) && MEDIA_ISSET(call_media, RECV))
				chopper_append_c(chop, "a=sendrecv\r\n");
			else if (MEDIA_ISSET(call_media, SEND) && !MEDIA_ISSET(call_media, RECV))
				chopper_append_c(chop, "a=sendonly\r\n");
			else if (!MEDIA_ISSET(call_media, SEND) && MEDIA_ISSET(call_media, RECV))
				chopper_append_c(chop, "a=recvonly\r\n");
			else
				chopper_append_c(chop, "a=inactive\r\n");

			if (MEDIA_ISSET(call_media, RTCP_MUX) && flags->opmode == OP_ANSWER) {
				chopper_append_c(chop, "a=rtcp:");
				chopper_append_printf(chop, "%hu", ps->sfd->fd.localport);
				chopper_append_c(chop, "\r\na=rtcp-mux\r\n");
				ps_rtcp = NULL;
			}
			else if (ps_rtcp && !flags->ice_force_relay) {
				chopper_append_c(chop, "a=rtcp:");
				chopper_append_printf(chop, "%hu", ps_rtcp->sfd->fd.localport);
				if (!MEDIA_ISSET(call_media, RTCP_MUX))
					chopper_append_c(chop, "\r\n");
				else
					chopper_append_c(chop, "\r\na=rtcp-mux\r\n");
			}

			insert_crypto(call_media, chop);
			insert_dtls(call_media, chop);

			if (do_ice && !MEDIA_ISSET(call_media, PASSTHRU)) {
				if (!call_media->ice_ufrag.s) {
					create_random_ice_string(call, &call_media->ice_ufrag, 8);
					create_random_ice_string(call, &call_media->ice_pwd, 28);
				}
				PS_SET(ps, STUN);
				if (ps_rtcp)
					PS_SET(ps_rtcp, STUN);

				chopper_append_c(chop, "a=ice-ufrag:");
				chopper_append_str(chop, &call_media->ice_ufrag);
				chopper_append_c(chop, "\r\na=ice-pwd:");
				chopper_append_str(chop, &call_media->ice_pwd);
				chopper_append_c(chop, "\r\n");
			}

			if (!flags->ice_remove) {
				priority = new_priority(
						(flags->ice_force || flags->ice_force_relay) ? NULL : sdp_media,
						flags->ice_force_relay
				);

				insert_candidates(chop, ps, ps_rtcp,
						  priority, sdp_media, flags->ice_force_relay);

				if (callmaster_has_ipv6(call->callmaster)) {
					priority -= 256;
					insert_candidates_alt(chop, ps, ps_rtcp,
							      priority, sdp_media,
							      flags->ice_force_relay);
				}
			}

next:
			media_index++;
			m = m->next;
		}
	}

	copy_remainder(chop);
	return 0;

error:
	ilog(LOG_ERROR, "Error rewriting SDP");
	return -1;
}

void sdp_init() {
	random_ice_string(ice_foundation, sizeof(ice_foundation) - 1);
	ice_foundation_str.s = ice_foundation;
	ice_foundation_str.len = sizeof(ice_foundation) - 1;

	random_ice_string(ice_foundation_alt, sizeof(ice_foundation_alt) - 1);
	ice_foundation_str_alt.s = ice_foundation_alt;
	ice_foundation_str_alt.len = sizeof(ice_foundation_alt) - 1;
}
