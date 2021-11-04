#include "sdp.h"

#include <glib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <math.h>
#include <stdbool.h>

#include "compat.h"
#include "call.h"
#include "log.h"
#include "str.h"
#include "call.h"
#include "crypto.h"
#include "dtls.h"
#include "rtp.h"
#include "ice.h"
#include "socket.h"
#include "call_interfaces.h"
#include "rtplib.h"
#include "codec.h"

struct network_address {
	str network_type;
	str address_type;
	str address;
	sockaddr_t parsed;
};

struct sdp_origin {
	str username;
	str session_id;
	str version_str;
	struct network_address address;
	unsigned long long version_num;
	size_t version_output_pos;
	unsigned int parsed:1;
};

struct sdp_connection {
	str s;
	struct network_address address;
	unsigned int parsed:1;
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
	str session_name;
	struct sdp_connection connection;
	int rr, rs;
	struct sdp_attributes attributes;
	GQueue media_streams;
};

struct sdp_media {
	struct sdp_session *session;

	str s;
	str media_type_str;
	str port;
	str transport;
	str formats; /* space separated */

	long int port_num;
	int port_count;

	struct sdp_connection connection;
	const char *c_line_pos;
	int rr, rs;
	struct sdp_attributes attributes;
	GQueue format_list; /* list of slice-alloc'd str objects */
	enum media_type media_type_id;
};

struct attribute_rtcp {
	long int port_num;
	struct network_address address;
};

struct attribute_candidate {
	str component_str;
	str transport_str;
	str priority_str;
	str address_str;
	str port_str;
	str typ_str;
	str type_str;
	str raddr_str;
	str related_address_str;
	str rport_str;
	str related_port_str;

	struct ice_candidate cand_parsed;
	unsigned int parsed:1;
};

struct attribute_crypto {
	str tag_str;
	str crypto_suite_str;
	str key_params_str;

	str key_base64_str;
	str lifetime_str;
	str mki_str;

	unsigned int tag;
	/* XXX use struct crypto_params for these below? */
	const struct crypto_suite *crypto_suite;
	str master_key;
	str salt;
	char key_salt_buf[SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN];
	uint64_t lifetime;
	unsigned char mki[256];
	unsigned int mki_len;
	unsigned int unencrypted_srtcp:1,
	             unencrypted_srtp:1,
	             unauthenticated_srtp:1;
};

struct attribute_ssrc {
	str id_str;
	str attr_str;

	uint32_t id;
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

struct attribute_rtpmap {
	str payload_type_str;
	str encoding_str;
	str clock_rate_str;

	struct rtp_payload_type rtp_pt;
};

struct attribute_rtcp_fb {
	str payload_type_str;
	str value;

	unsigned int payload_type;
};

struct attribute_fmtp {
	str payload_type_str;
	str format_parms_str;

	unsigned int payload_type;
};

struct attribute_t38faxratemanagement {
	enum {
		RM_UNKNOWN = 0,
		RM_LOCALTCF,
		RM_TRANSFERREDTCF,
	} rm;
};

struct attribute_t38faxudpec {
	enum {
		EC_UNKNOWN = 0,
		EC_NONE,
		EC_REDUNDANCY,
		EC_FEC,
	} ec;
};

struct attribute_t38faxudpecdepth {
	str minred_str;
	str maxred_str;

	int minred;
	int maxred;
};

struct sdp_attribute {	/* example: a=rtpmap:8 PCMA/8000 */
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
		ATTR_ICE_LITE,
		ATTR_ICE_OPTIONS,
		ATTR_ICE_UFRAG,
		ATTR_ICE_PWD,
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
		ATTR_RTPMAP,
		ATTR_FMTP,
		ATTR_IGNORE,
		ATTR_RTPENGINE,
		ATTR_PTIME,
		ATTR_RTCP_FB,
		ATTR_T38FAXVERSION,
		ATTR_T38FAXUDPEC,
		ATTR_T38FAXUDPECDEPTH,
		ATTR_T38FAXUDPFECMAXSPAN,
		ATTR_T38FAXMAXDATAGRAM,
		ATTR_T38FAXMAXIFP,
		ATTR_T38FAXFILLBITREMOVAL,
		ATTR_T38FAXTRANSCODINGMMR,
		ATTR_T38FAXTRANSCODINGJBIG,
		ATTR_T38FAXRATEMANAGEMENT,
		ATTR_END_OF_CANDIDATES,
	} attr;

	union {
		struct attribute_rtcp rtcp;
		struct attribute_candidate candidate;
		struct attribute_crypto crypto;
		struct attribute_ssrc ssrc;
		struct attribute_group group;
		struct attribute_fingerprint fingerprint;
		struct attribute_setup setup;
		struct attribute_rtpmap rtpmap;
		struct attribute_rtcp_fb rtcp_fb;
		struct attribute_fmtp fmtp;
		struct attribute_t38faxudpec t38faxudpec;
		int i;
		struct attribute_t38faxudpecdepth t38faxudpecdepth;
		struct attribute_t38faxratemanagement t38faxratemanagement;
	} u;
};



static char __id_buf[6*2 + 1]; // 6 hex encoded characters
const str rtpe_instance_id = STR_CONST_INIT(__id_buf);




INLINE struct sdp_attribute *attr_get_by_id(struct sdp_attributes *a, int id) {
	return g_hash_table_lookup(a->id_hash, &id);
}
INLINE GQueue *attr_list_get_by_id(struct sdp_attributes *a, int id) {
	return g_hash_table_lookup(a->id_lists_hash, &id);
}

static struct sdp_attribute *attr_get_by_id_m_s(struct sdp_media *m, int id) {
	struct sdp_attribute *a;

	a = attr_get_by_id(&m->attributes, id);
	if (a)
		return a;
	return attr_get_by_id(&m->session->attributes, id);
}


static int __parse_address(sockaddr_t *out, str *network_type, str *address_type, str *address) {
	sockfamily_t *af;

	if (network_type) {
		if (network_type->len != 2)
			return -1;
		if (memcmp(network_type->s, "IN", 2)
				&& memcmp(network_type->s, "in", 2))
			return -1;
	}

	if (!address_type) {
		if (sockaddr_parse_any_str(out, address))
			return -1;
		return 0;
	}

	af = get_socket_family_rfc(address_type);
	if (sockaddr_parse_str(out, af, address))
		return -1;

	return 0;
}

static int parse_address(struct network_address *address) {
	return __parse_address(&address->parsed, &address->network_type,
			&address->address_type, &address->address);
}

#define EXTRACT_TOKEN(field) do { if (str_token_sep(&output->field, value_str, ' ')) return -1; } while (0)
#define EXTRACT_NETWORK_ADDRESS_NP(field)			\
		do { EXTRACT_TOKEN(field.network_type);		\
		EXTRACT_TOKEN(field.address_type);		\
		EXTRACT_TOKEN(field.address); } while (0)
#define EXTRACT_NETWORK_ADDRESS(field)				\
		do { EXTRACT_NETWORK_ADDRESS_NP(field);		\
		if (parse_address(&output->field)) return -1; } while (0)
#define EXTRACT_NETWORK_ADDRESS_NF(field)			\
		do { EXTRACT_NETWORK_ADDRESS_NP(field);		\
		if (parse_address(&output->field)) {		\
			output->field.parsed.family = get_socket_family_enum(SF_IP4); \
			output->field.parsed.u.ipv4.s_addr = 1;	\
		} } while (0)

#define PARSE_DECL str v_str, *value_str
#define PARSE_INIT v_str = output->value; value_str = &v_str

static int parse_origin(str *value_str, struct sdp_origin *output) {
	if (output->parsed)
		return -1;

	EXTRACT_TOKEN(username);
	EXTRACT_TOKEN(session_id);
	EXTRACT_TOKEN(version_str);
	EXTRACT_NETWORK_ADDRESS_NF(address);

	output->version_num = strtoull(output->version_str.s, NULL, 10);
	output->parsed = 1;
	return 0;
}

static int parse_connection(str *value_str, struct sdp_connection *output) {
	if (output->parsed)
		return -1;

	output->s = *value_str;

	EXTRACT_NETWORK_ADDRESS(address);

	output->parsed = 1;
	return 0;
}

static int parse_media(str *value_str, struct sdp_media *output) {
	char *ep;
	str *sp;

	EXTRACT_TOKEN(media_type_str);
	EXTRACT_TOKEN(port);
	EXTRACT_TOKEN(transport);
	output->formats = *value_str;

	output->media_type_id = codec_get_type(&output->media_type_str);
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

	/* to split the "formats" list into tokens, we abuse some vars */
	str formats = output->formats;
	str format;
	while (!str_token_sep(&format, &formats, ' ')) {
		sp = g_slice_alloc(sizeof(*sp));
		*sp = format;
		g_queue_push_tail(&output->format_list, sp);
	}

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
	PARSE_DECL;
	struct attribute_ssrc *s;

	output->attr = ATTR_SSRC;

	PARSE_INIT;
	EXTRACT_TOKEN(u.ssrc.id_str);
	EXTRACT_TOKEN(u.ssrc.attr_str);

	s = &output->u.ssrc;

	s->id = strtoul(s->id_str.s, NULL, 10);
	if (!s->id)
		return -1;

	s->attr = s->attr_str;
	if (str_chr_str(&s->value, &s->attr, ':')) {
		s->attr.len = s->value.s - s->attr.s;
		str_shift(&s->value, 1);
	}

	return 0;
}

static int parse_attribute_crypto(struct sdp_attribute *output) {
	PARSE_DECL;
	char *endp;
	struct attribute_crypto *c;
	int salt_key_len, enc_salt_key_len;
	int b64_state = 0;
	unsigned int b64_save = 0;
	gsize ret;
	str s;
	uint32_t u32;
	const char *err;

	output->attr = ATTR_CRYPTO;

	PARSE_INIT;
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
        // flush b64_state needed for AES-192: 36+2; AES-256: 45+1;
        if (enc_salt_key_len % 4) {
                ret += g_base64_decode_step("==", 4 - (enc_salt_key_len % 4),
                        (guchar *) c->key_salt_buf + ret, &b64_state, &b64_save);
        }
	err = "invalid base64 encoding";
	if (ret != salt_key_len)
		goto error;

	c->master_key.s = c->key_salt_buf;
	c->master_key.len = c->crypto_suite->master_key_len;
	c->salt.s = c->master_key.s + c->master_key.len;
	c->salt.len = c->crypto_suite->master_salt_len;

	c->lifetime_str = c->key_params_str;
	str_shift(&c->lifetime_str, 7 + enc_salt_key_len);
        // skip past base64 padding
        if (enc_salt_key_len % 4 == 2) {
                str_shift_cmp(&c->lifetime_str, "==");
        } else if (enc_salt_key_len % 4 == 3) {
                str_shift_cmp(&c->lifetime_str, "=");
        }
	if (c->lifetime_str.len >= 2) {
		err = "invalid key parameter syntax";
		if (c->lifetime_str.s[0] != '|')
			goto error;
		str_shift(&c->lifetime_str, 1);
		if (!str_chr_str(&c->mki_str, &c->lifetime_str, '|')) {
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
			if (!c->lifetime || c->lifetime >= 64)
				goto error;
			c->lifetime = 1ULL << c->lifetime;
		}
		else
			c->lifetime = strtoull(c->lifetime_str.s, NULL, 10);

		err = "invalid key lifetime";
		if (!c->lifetime || c->lifetime > c->crypto_suite->srtp_lifetime
#ifdef STRICT_SDES_KEY_LIFETIME
				|| c->lifetime > c->crypto_suite->srtcp_lifetime
#endif
				)
			goto error;
	}

	if (c->mki_str.s) {
		err = "invalid MKI specification";
		if (!str_chr_str(&s, &c->mki_str, ':'))
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

	while (str_token_sep(&s, value_str, ' ') == 0) {
		if (!str_cmp(&s, "UNENCRYPTED_SRTCP"))
			c->unencrypted_srtcp = 1;
		else if (!str_cmp(&s, "UNENCRYPTED_SRTP"))
			c->unencrypted_srtp = 1;
		else if (!str_cmp(&s, "UNAUTHENTICATED_SRTP"))
			c->unauthenticated_srtp = 1;
	}

	return 0;

error:
	ilog(LOG_ERROR, "Failed to parse a=crypto attribute, ignoring: %s", err);
	output->attr = ATTR_IGNORE;
	return 0;
}

static int parse_attribute_rtcp(struct sdp_attribute *output) {
	if (!output->value.s)
		goto err;
	output->attr = ATTR_RTCP;

	PARSE_DECL;
	PARSE_INIT;

	str portnum;
	if (str_token_sep(&portnum, value_str, ' '))
		goto err;
	output->u.rtcp.port_num = str_to_i(&portnum, 0);
	if (output->u.rtcp.port_num <= 0 || output->u.rtcp.port_num > 0xffff) {
		output->u.rtcp.port_num = 0;
		goto err;
	}

	if (value_str->len)
		EXTRACT_NETWORK_ADDRESS(u.rtcp.address);

	return 0;

err:
	ilog(LOG_WARN, "Failed to parse a=rtcp attribute, ignoring");
	output->attr = ATTR_IGNORE;
	return 0;
}

static int parse_attribute_candidate(struct sdp_attribute *output, bool extended) {
	PARSE_DECL;
	char *ep;
	struct attribute_candidate *c;

	output->attr = ATTR_CANDIDATE;
	c = &output->u.candidate;

	PARSE_INIT;
	EXTRACT_TOKEN(u.candidate.cand_parsed.foundation);
	EXTRACT_TOKEN(u.candidate.component_str);
	EXTRACT_TOKEN(u.candidate.transport_str);
	EXTRACT_TOKEN(u.candidate.priority_str);
	EXTRACT_TOKEN(u.candidate.address_str);
	EXTRACT_TOKEN(u.candidate.port_str);
	EXTRACT_TOKEN(u.candidate.typ_str);
	EXTRACT_TOKEN(u.candidate.type_str);

	c->cand_parsed.component_id = strtoul(c->component_str.s, &ep, 10);
	if (ep == c->component_str.s)
		return -1;

	c->cand_parsed.transport = get_socket_type(&c->transport_str);
	if (!c->cand_parsed.transport)
		return 0;

	c->cand_parsed.priority = strtoul(c->priority_str.s, &ep, 10);
	if (ep == c->priority_str.s)
		return -1;

	if (__parse_address(&c->cand_parsed.endpoint.address, NULL, NULL, &c->address_str))
		return 0;

	c->cand_parsed.endpoint.port = strtoul(c->port_str.s, &ep, 10);
	if (ep == c->port_str.s)
		return -1;

	if (str_cmp(&c->typ_str, "typ"))
		return -1;

	c->cand_parsed.type = ice_candidate_type(&c->type_str);
	if (!c->cand_parsed.type)
		return 0;

	if (ice_has_related(c->cand_parsed.type)) {
		// XXX guaranteed to be in order even with extended syntax?
		EXTRACT_TOKEN(u.candidate.raddr_str);
		EXTRACT_TOKEN(u.candidate.related_address_str);
		EXTRACT_TOKEN(u.candidate.rport_str);
		EXTRACT_TOKEN(u.candidate.related_port_str);

		if (str_cmp(&c->raddr_str, "raddr"))
			return -1;
		if (str_cmp(&c->rport_str, "rport"))
			return -1;

		if (__parse_address(&c->cand_parsed.related.address, NULL, NULL, &c->related_address_str))
			return 0;

		c->cand_parsed.related.port = strtoul(c->related_port_str.s, &ep, 10);
		if (ep == c->related_port_str.s)
			return -1;
	}

	if (extended) {
		while (true) {
			str field, value;
			if (str_token_sep(&field, value_str, ' '))
				break;
			if (str_token_sep(&value, value_str, ' '))
				break;
			if (!str_cmp(&field, "ufrag"))
				c->cand_parsed.ufrag = value;
		}
	}

	c->parsed = 1;
	return 0;
}

// 0 = success
// -1 = error
// 1 = parsed ok but unsupported candidate type
int sdp_parse_candidate(struct ice_candidate *cand, const str *s) {
	struct sdp_attribute attr = {
		.value = *s,
	};

	if (parse_attribute_candidate(&attr, true))
		return -1;
	if (!attr.u.candidate.parsed)
		return 1;
	*cand = attr.u.candidate.cand_parsed;

	return 0;
}


static int parse_attribute_fingerprint(struct sdp_attribute *output) {
	PARSE_DECL;
	unsigned char *c;
	int i;

	output->attr = ATTR_FINGERPRINT;

	PARSE_INIT;
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

static int parse_attribute_rtcp_fb(struct sdp_attribute *output) {
	PARSE_DECL;
	struct attribute_rtcp_fb *a;

	output->attr = ATTR_RTCP_FB;
	a = &output->u.rtcp_fb;

	PARSE_INIT;
	EXTRACT_TOKEN(u.rtcp_fb.payload_type_str);
	a->value = *value_str;

	if (!str_cmp(&output->u.rtcp_fb.value, "*"))
		a->payload_type = -1;
	else {
		a->payload_type = str_to_i(&a->payload_type_str, -1);
		if (a->payload_type == -1)
			return -1;
	}

	return 0;
}

static int parse_attribute_rtpmap(struct sdp_attribute *output) {
	PARSE_DECL;
	char *ep;
	struct attribute_rtpmap *a;
	struct rtp_payload_type *pt;

	output->attr = ATTR_RTPMAP;

	PARSE_INIT;
	EXTRACT_TOKEN(u.rtpmap.payload_type_str);
	EXTRACT_TOKEN(u.rtpmap.encoding_str);

	a = &output->u.rtpmap;
	pt = &a->rtp_pt;

	pt->encoding_with_params = a->encoding_str;

	pt->payload_type = strtoul(a->payload_type_str.s, &ep, 10);
	if (ep == a->payload_type_str.s)
		return -1;

	if (!str_chr_str(&a->clock_rate_str, &a->encoding_str, '/'))
		return -1;

	pt->encoding = a->encoding_str;
	pt->encoding.len -= a->clock_rate_str.len;
	str_shift(&a->clock_rate_str, 1);

	pt->channels = 1;
	if (str_chr_str(&pt->encoding_parameters, &a->clock_rate_str, '/')) {
		a->clock_rate_str.len -= pt->encoding_parameters.len;
		str_shift(&pt->encoding_parameters, 1);

		if (pt->encoding_parameters.len) {
			int channels = strtol(pt->encoding_parameters.s, &ep, 10);
			if (channels && (!ep || ep == pt->encoding_parameters.s + pt->encoding_parameters.len))
				pt->channels = channels;
		}
	}

	if (!a->clock_rate_str.len)
		return -1;

	pt->clock_rate = strtoul(a->clock_rate_str.s, &ep, 10);
	if (ep && ep != a->clock_rate_str.s + a->clock_rate_str.len)
		return -1;

	return 0;
}

static int parse_attribute_fmtp(struct sdp_attribute *output) {
	PARSE_DECL;
	struct attribute_fmtp *a;

	output->attr = ATTR_FMTP;
	a = &output->u.fmtp;

	PARSE_INIT;
	EXTRACT_TOKEN(u.fmtp.payload_type_str);
	a->format_parms_str = *value_str;

	a->payload_type = str_to_i(&a->payload_type_str, -1);
	if (a->payload_type == -1)
		return -1;

	return 0;
}

static int parse_attribute_int(struct sdp_attribute *output, int attr_id, int defval) {
	output->attr = attr_id;
	output->u.i = str_to_i(&output->value, defval);
	return 0;
}

// XXX combine this with parse_attribute_setup ?
static int parse_attribute_t38faxudpec(struct sdp_attribute *output) {
	output->attr = ATTR_T38FAXUDPEC;

	switch (__csh_lookup(&output->value)) {
		case CSH_LOOKUP("t38UDPNoEC"):
			output->u.t38faxudpec.ec = EC_NONE;
			break;
		case CSH_LOOKUP("t38UDPRedundancy"):
			output->u.t38faxudpec.ec = EC_REDUNDANCY;
			break;
		case CSH_LOOKUP("t38UDPFEC"):
			output->u.t38faxudpec.ec = EC_FEC;
			break;
		default:
			output->u.t38faxudpec.ec = EC_UNKNOWN;
			break;
	}

	return 0;
}

// XXX combine this with parse_attribute_setup ?
static int parse_attribute_t38faxratemanagement(struct sdp_attribute *output) {
	output->attr = ATTR_T38FAXRATEMANAGEMENT;

	switch (__csh_lookup(&output->value)) {
		case CSH_LOOKUP("localTFC"):
			output->u.t38faxratemanagement.rm = RM_LOCALTCF;
			break;
		case CSH_LOOKUP("transferredTCF"):
			output->u.t38faxratemanagement.rm = RM_TRANSFERREDTCF;
			break;
		default:
			output->u.t38faxratemanagement.rm = RM_UNKNOWN;
			break;
	}

	return 0;
}

static int parse_attribute_t38faxudpecdepth(struct sdp_attribute *output) {
	PARSE_DECL;
	struct attribute_t38faxudpecdepth *a;

	output->attr = ATTR_T38FAXUDPECDEPTH;
	a = &output->u.t38faxudpecdepth;

	PARSE_INIT;
	EXTRACT_TOKEN(u.t38faxudpecdepth.minred_str);
	a->maxred_str = *value_str;

	a->minred = str_to_i(&a->minred_str, 0);
	a->maxred = str_to_i(&a->maxred_str, -1);

	return 0;
}


static int parse_attribute(struct sdp_attribute *a) {
	int ret;

	a->name = a->line_value;
	if (str_chr_str(&a->value, &a->name, ':')) {
		a->name.len -= a->value.len;
		a->value.s++;
		a->value.len--;

		a->key = a->name;
		if (str_chr_str(&a->param, &a->value, ' ')) {
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
	switch (__csh_lookup(&a->name)) {
		case CSH_LOOKUP("mid"):
			a->attr = ATTR_MID;
			break;
		case CSH_LOOKUP("rtcp"):
			ret = parse_attribute_rtcp(a);
			break;
		case CSH_LOOKUP("ssrc"):
			ret = parse_attribute_ssrc(a);
			break;
		case CSH_LOOKUP("fmtp"):
			ret = parse_attribute_fmtp(a);
			break;
		case CSH_LOOKUP("group"):
			ret = parse_attribute_group(a);
			break;
		case CSH_LOOKUP("setup"):
			ret = parse_attribute_setup(a);
			break;
		case CSH_LOOKUP("ptime"):
			a->attr = ATTR_PTIME;
			break;
		case CSH_LOOKUP("crypto"):
			ret = parse_attribute_crypto(a);
			break;
		case CSH_LOOKUP("extmap"):
			a->attr = ATTR_EXTMAP;
			break;
		case CSH_LOOKUP("rtpmap"):
			ret = parse_attribute_rtpmap(a);
			break;
		case CSH_LOOKUP("ice-pwd"):
			a->attr = ATTR_ICE_PWD;
			break;
		case CSH_LOOKUP("ice-lite"):
			a->attr = ATTR_ICE_LITE;
			break;
		case CSH_LOOKUP("inactive"):
			a->attr = ATTR_INACTIVE;
			break;
		case CSH_LOOKUP("sendrecv"):
			a->attr = ATTR_SENDRECV;
			break;
		case CSH_LOOKUP("sendonly"):
			a->attr = ATTR_SENDONLY;
			break;
		case CSH_LOOKUP("recvonly"):
			a->attr = ATTR_RECVONLY;
			break;
		case CSH_LOOKUP("rtcp-mux"):
			a->attr = ATTR_RTCP_MUX;
			break;
		case CSH_LOOKUP("candidate"):
			ret = parse_attribute_candidate(a, false);
			break;
		case CSH_LOOKUP("ice-ufrag"):
			a->attr = ATTR_ICE_UFRAG;
			break;
		case CSH_LOOKUP("rtpengine"):
			a->attr = ATTR_RTPENGINE;
			break;
		case CSH_LOOKUP("ice-options"):
			a->attr = ATTR_ICE_OPTIONS;
			break;
		case CSH_LOOKUP("fingerprint"):
			ret = parse_attribute_fingerprint(a);
			break;
		case CSH_LOOKUP("ice-mismatch"):
			a->attr = ATTR_ICE;
			break;
		case CSH_LOOKUP("remote-candidates"):
			a->attr = ATTR_ICE;
			break;
		case CSH_LOOKUP("end-of-candidates"):
			a->attr = ATTR_END_OF_CANDIDATES;
			break;
		case CSH_LOOKUP("rtcp-fb"):
			ret = parse_attribute_rtcp_fb(a);
			break;
		case CSH_LOOKUP("T38FaxVersion"):
			ret = parse_attribute_int(a, ATTR_T38FAXVERSION, -1);
			break;
		case CSH_LOOKUP("T38FaxUdpEC"):
			ret = parse_attribute_t38faxudpec(a);
			break;
		case CSH_LOOKUP("T38FaxUdpECDepth"):
			ret = parse_attribute_t38faxudpecdepth(a);
			break;
		case CSH_LOOKUP("T38FaxUdpFECMaxSpan"):
			ret = parse_attribute_int(a, ATTR_T38FAXUDPFECMAXSPAN, 0);
			break;
		case CSH_LOOKUP("T38FaxMaxDatagram"):
			ret = parse_attribute_int(a, ATTR_T38FAXMAXDATAGRAM, -1);
			break;
		case CSH_LOOKUP("T38FaxMaxIFP"):
			ret = parse_attribute_int(a, ATTR_T38FAXMAXIFP, -1);
			break;
		case CSH_LOOKUP("T38FaxFillBitRemoval"):
			a->attr = ATTR_T38FAXFILLBITREMOVAL;
			break;
		case CSH_LOOKUP("T38FaxTranscodingMMR"):
			a->attr = ATTR_T38FAXTRANSCODINGMMR;
			break;
		case CSH_LOOKUP("T38FaxTranscodingJBIG"):
			a->attr = ATTR_T38FAXTRANSCODINGJBIG;
			break;
		case CSH_LOOKUP("T38FaxRateManagement"):
			ret = parse_attribute_t38faxratemanagement(a);
			break;
	}

	return ret;
}

int sdp_parse(str *body, GQueue *sessions, const struct sdp_ng_flags *flags) {
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
#ifdef TERMINATE_SDP_AT_BLANK_LINE
		if (b[0] == '\n' || b[0] == '\r') {
			body->len = b - body->s;
			break;
		}
#endif
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

		errstr = "SDP doesn't start with a session definition";
		if (!session && b[0] != 'v') {
			if (!flags->fragment)
				goto error;
			else
				goto new_session; // allowed for trickle ICE SDP fragments
		}

		str value_str;
		str_init_len(&value_str, value, line_end - value);

		switch (b[0]) {
			case 'v':
				errstr = "Error in v= line";
				if (line_end != value + 1)
					goto error;
				if (value[0] != '0')
					goto error;

new_session:
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
				if (parse_origin(&value_str, &session->origin))
					goto error;

				break;

			case 'm':
				if (media && !media->c_line_pos)
					media->c_line_pos = b;

				media = g_slice_alloc0(sizeof(*media));
				media->session = session;
				attrs_init(&media->attributes);
				errstr = "Error parsing m= line";
				if (parse_media(&value_str, media))
					goto error;
				g_queue_push_tail(&session->media_streams, media);
				media->s.s = b;
				media->rr = media->rs = -1;

				break;

			case 'c':
				errstr = "Error parsing c= line";
				if (parse_connection(&value_str,
						media ? &media->connection : &session->connection))
					goto error;

				break;

			case 'a':
				if (media && !media->c_line_pos)
					media->c_line_pos = b;

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

				/* attr_queue = g_hash_table_lookup_queue_new(attrs->name_lists_hash, &attr->name);
				g_queue_push_tail(attr_queue, attr); */
				attr_queue = g_hash_table_lookup_queue_new(attrs->id_lists_hash, &attr->attr,
						NULL);
				g_queue_push_tail(attr_queue, attr);

				break;

			case 'b':
				if (media && !media->c_line_pos)
					media->c_line_pos = b;

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

			case 'k':
				if (media && !media->c_line_pos)
					media->c_line_pos = b;
				break;

			case 's':
				errstr = "s= line found within media section";
				if (media)
					goto error;
				session->session_name = value_str;
				break;

			case 'i':
			case 'u':
			case 'e':
			case 'p':
			case 't':
			case 'r':
			case 'z':
				break;

			default:
				errstr = "Unknown SDP line type found";
				goto error;
		}

		errstr = "SDP doesn't start with a valid session definition";
		if (!session)
			goto error;

		adj_s = media ? &media->s : &session->s;
		adj_s->len = (next_line ? : end) - adj_s->s;

		b = next_line;
	}

	return 0;

error:
	ilog(LOG_WARNING, "Error parsing SDP at offset %li: %s", (long) (b - body->s), errstr);
	sdp_free(sessions);
	return -1;
}

static void attr_free(void *p) {
	g_slice_free1(sizeof(struct sdp_attribute), p);
}
static void free_attributes(struct sdp_attributes *a) {
	/* g_hash_table_destroy(a->name_hash); */
	g_hash_table_destroy(a->id_hash);
	/* g_hash_table_destroy(a->name_lists_hash); */
	g_hash_table_destroy(a->id_lists_hash);
	g_queue_clear_full(&a->list, attr_free);
}
static void media_free(void *p) {
	struct sdp_media *media = p;
	free_attributes(&media->attributes);
	g_queue_clear_full(&media->format_list, str_slice_free);
	g_slice_free1(sizeof(*media), media);
}
static void session_free(void *p) {
	struct sdp_session *session = p;
	g_queue_clear_full(&session->media_streams, media_free);
	free_attributes(&session->attributes);
	g_slice_free1(sizeof(*session), session);
}
void sdp_free(GQueue *sessions) {
	g_queue_clear_full(sessions, session_free);
}

static int fill_endpoint(struct endpoint *ep, const struct sdp_media *media, struct sdp_ng_flags *flags,
		struct network_address *address, long int port)
{
	struct sdp_session *session = media->session;

	if (!flags->trust_address) {
		if (is_addr_unspecified(&flags->parsed_received_from)) {
			if (__parse_address(&flags->parsed_received_from, NULL, &flags->received_from_family,
						&flags->received_from_address))
				return -1;
		}
		ep->address = flags->parsed_received_from;
	}
	else if (address && !is_addr_unspecified(&address->parsed))
		ep->address = address->parsed;
	else if (media->connection.parsed)
		ep->address = media->connection.address.parsed;
	else if (session->connection.parsed)
		ep->address = session->connection.address.parsed;
	else
		return -1;

	ep->port = port;

	return 0;
}



static int __rtp_payload_types(struct stream_params *sp, struct sdp_media *media)
{
	GHashTable *ht_rtpmap, *ht_fmtp, *ht_rtcp_fb;
	GQueue *q;
	GList *ql;
	struct sdp_attribute *attr;
	int ret = 0;

	if (!proto_is_rtp(sp->protocol))
		return 0;

	/* first go through a=rtpmap and build a hash table of attrs */
	ht_rtpmap = g_hash_table_new(g_int_hash, g_int_equal);
	q = attr_list_get_by_id(&media->attributes, ATTR_RTPMAP);
	for (ql = q ? q->head : NULL; ql; ql = ql->next) {
		struct rtp_payload_type *pt;
		attr = ql->data;
		pt = &attr->u.rtpmap.rtp_pt;
		g_hash_table_insert(ht_rtpmap, &pt->payload_type, pt);
	}
	// do the same for a=fmtp
	ht_fmtp = g_hash_table_new(g_int_hash, g_int_equal);
	q = attr_list_get_by_id(&media->attributes, ATTR_FMTP);
	for (ql = q ? q->head : NULL; ql; ql = ql->next) {
		attr = ql->data;
		g_hash_table_insert(ht_fmtp, &attr->u.fmtp.payload_type, &attr->u.fmtp.format_parms_str);
	}
	// do the same for a=rtcp-fb
	ht_rtcp_fb = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) g_queue_free);
	q = attr_list_get_by_id(&media->attributes, ATTR_RTCP_FB);
	for (ql = q ? q->head : NULL; ql; ql = ql->next) {
		attr = ql->data;
		if (attr->u.rtcp_fb.payload_type == -1)
			continue;
		GQueue *rq = g_hash_table_lookup_queue_new(ht_rtcp_fb, GINT_TO_POINTER(attr->u.rtcp_fb.payload_type), NULL);
		g_queue_push_tail(rq, &attr->u.rtcp_fb.value);
	}

	/* then go through the format list and associate */
	for (ql = media->format_list.head; ql; ql = ql->next) {
		char *ep;
		str *s;
		unsigned int i;
		struct rtp_payload_type *pt;
		const struct rtp_payload_type *ptl, *ptrfc;

		s = ql->data;
		i = (unsigned int) strtoul(s->s, &ep, 10);
		if (ep == s->s || i > 127)
			goto error;

		/* first look in rtpmap for a match, then check RFC types,
		 * else fall back to an "unknown" type */
		ptrfc = rtp_get_rfc_payload_type(i);
		ptl = g_hash_table_lookup(ht_rtpmap, &i);

		pt = g_slice_alloc0(sizeof(*pt));
		if (ptl)
			*pt = *ptl;
		else if (ptrfc)
			*pt = *ptrfc;
		else
			pt->payload_type = i;

		s = g_hash_table_lookup(ht_fmtp, &i);
		if (s)
			pt->format_parameters = *s;
		else
			pt->format_parameters = STR_EMPTY;
		GQueue *rq = g_hash_table_lookup(ht_rtcp_fb, GINT_TO_POINTER(i));
		if (rq) {
			// steal the list contents and free the list
			pt->rtcp_fb = *rq;
			g_queue_init(rq);
			g_hash_table_remove(ht_rtcp_fb, GINT_TO_POINTER(i)); // frees `rq`
		}

		// fill in ptime
		if (sp->ptime)
			pt->ptime = sp->ptime;
		else if (!pt->ptime && ptrfc)
			pt->ptime = ptrfc->ptime;

		codec_init_payload_type(pt, sp->type_id);
		codec_store_add_raw(&sp->codecs, pt);
	}

	goto out;

error:
	ret = -1;
	goto out;
out:
	g_hash_table_destroy(ht_rtpmap);
	g_hash_table_destroy(ht_fmtp);
	g_hash_table_destroy(ht_rtcp_fb);
	return ret;
}

static void __sdp_ice(struct stream_params *sp, struct sdp_media *media) {
	struct sdp_attribute *attr;
	struct attribute_candidate *ac;
	struct ice_candidate *cand;
	GQueue *q;
	GList *ql;

	attr = attr_get_by_id_m_s(media, ATTR_ICE_UFRAG);
	if (!attr)
		return;
	sp->ice_ufrag = attr->value;

	SP_SET(sp, ICE);

	q = attr_list_get_by_id(&media->attributes, ATTR_CANDIDATE);
	if (!q)
		goto no_cand;

	for (ql = q->head; ql; ql = ql->next) {
		attr = ql->data;
		ac = &attr->u.candidate;
		if (!ac->parsed)
			continue;
		cand = g_slice_alloc(sizeof(*cand));
		*cand = ac->cand_parsed;
		g_queue_push_tail(&sp->ice_candidates, cand);
	}

no_cand:
	if ((attr = attr_get_by_id(&media->attributes, ATTR_ICE_OPTIONS))) {
		if (str_str(&attr->value, "trickle") >= 0)
			SP_SET(sp, TRICKLE_ICE);
	}
	else if (is_trickle_ice_address(&sp->rtp_endpoint))
		SP_SET(sp, TRICKLE_ICE);

	if (attr_get_by_id(&media->attributes, ATTR_ICE_LITE))
		SP_SET(sp, ICE_LITE_PEER);

	attr = attr_get_by_id_m_s(media, ATTR_ICE_PWD);
	if (attr)
		sp->ice_pwd = attr->value;
}

static void __sdp_t38(struct stream_params *sp, struct sdp_media *media) {
	struct sdp_attribute *attr;
	struct t38_options *to = &sp->t38_options;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXVERSION);
	if (attr)
		to->version = attr->u.i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXUDPEC);
	if (attr) {
		if (attr->u.t38faxudpec.ec == EC_REDUNDANCY)
			to->max_ec_entries = to->min_ec_entries = 3; // defaults
		else if (attr->u.t38faxudpec.ec == EC_FEC) {
			// defaults
			to->max_ec_entries = to->min_ec_entries = 3;
			to->fec_span = 3;
		}
		// else default to 0
	}
	else // no EC specified, defaults:
		to->max_ec_entries = to->min_ec_entries = 3; // defaults

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXUDPECDEPTH);
	if (attr) {
		to->min_ec_entries = attr->u.t38faxudpecdepth.minred;
		to->max_ec_entries = attr->u.t38faxudpecdepth.maxred;
	}

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXUDPFECMAXSPAN);
	if (attr)
		to->fec_span = attr->u.i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXMAXDATAGRAM);
	if (attr)
		to->max_datagram = attr->u.i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXMAXIFP);
	if (attr)
		to->max_ifp = attr->u.i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXFILLBITREMOVAL);
	if (attr && (!attr->value.len || str_cmp(&attr->value, "0")))
		to->fill_bit_removal = 1;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXTRANSCODINGMMR);
	if (attr && (!attr->value.len || str_cmp(&attr->value, "0")))
		to->transcoding_mmr = 1;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXTRANSCODINGJBIG);
	if (attr && (!attr->value.len || str_cmp(&attr->value, "0")))
		to->transcoding_jbig = 1;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXRATEMANAGEMENT);
	if (attr)
		to->local_tcf = (attr->u.t38faxratemanagement.rm == RM_LOCALTCF) ? 1 : 0;
}


/* XXX split this function up */
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
			codec_store_init(&sp->codecs, NULL);

			__sdp_ice(sp, media);
			if (SP_ISSET(sp, ICE)) {
				// ignore "received from" (SIP-source-address) when ICE is in use
				flags->trust_address = 1;
			}

			errstr = "No address info found for stream";
			if (!flags->fragment
					&& fill_endpoint(&sp->rtp_endpoint, media, flags, NULL, media->port_num))
				goto error;

			sp->consecutive_ports = media->port_count;
			sp->num_ports = sp->consecutive_ports * 2; // only do *=2 for RTP streams?
			sp->protocol_str = media->transport;
			sp->protocol = transport_protocol(&media->transport);
			sp->type = media->media_type_str;
			sp->type_id = media->media_type_id;
			memcpy(sp->direction, flags->direction, sizeof(sp->direction));
			sp->desired_family = flags->address_family;
			bf_set_clear(&sp->sp_flags, SP_FLAG_ASYMMETRIC, flags->asymmetric);
			bf_set_clear(&sp->sp_flags, SP_FLAG_UNIDIRECTIONAL, flags->unidirectional);
			bf_set_clear(&sp->sp_flags, SP_FLAG_STRICT_SOURCE, flags->strict_source);
			bf_set_clear(&sp->sp_flags, SP_FLAG_MEDIA_HANDOVER, flags->media_handover);

			// a=ptime
			attr = attr_get_by_id(&media->attributes, ATTR_PTIME);
			if (attr && attr->value.s)
				sp->ptime = str_to_i(&attr->value, 0);

			sp->format_str = media->formats;
			errstr = "Invalid RTP payload types";
			if (__rtp_payload_types(sp, media))
				goto error;

			/* a=crypto */
			GQueue *attrs = attr_list_get_by_id(&media->attributes, ATTR_CRYPTO);
			for (GList *ll = attrs ? attrs->head : NULL; ll; ll = ll->next) {
				attr = ll->data;
				struct crypto_params_sdes *cps = g_slice_alloc0(sizeof(*cps));
				g_queue_push_tail(&sp->sdes_params, cps);

				cps->params.crypto_suite = attr->u.crypto.crypto_suite;
				cps->params.mki_len = attr->u.crypto.mki_len;
				if (cps->params.mki_len) {
					cps->params.mki = malloc(cps->params.mki_len);
					memcpy(cps->params.mki, attr->u.crypto.mki, cps->params.mki_len);
				}
				cps->tag = attr->u.crypto.tag;
				assert(sizeof(cps->params.master_key) >= attr->u.crypto.master_key.len);
				assert(sizeof(cps->params.master_salt) >= attr->u.crypto.salt.len);
				memcpy(cps->params.master_key, attr->u.crypto.master_key.s,
						attr->u.crypto.master_key.len);
				memcpy(cps->params.master_salt, attr->u.crypto.salt.s,
						attr->u.crypto.salt.len);
				cps->params.session_params.unencrypted_srtp = attr->u.crypto.unencrypted_srtp;
				cps->params.session_params.unencrypted_srtcp = attr->u.crypto.unencrypted_srtcp;
				cps->params.session_params.unauthenticated_srtp = attr->u.crypto.unauthenticated_srtp;
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
				sp->fingerprint.digest_len = sp->fingerprint.hash_func->num_bytes;
			}

			// OSRTP (RFC 8643)
			if (sp->protocol && sp->protocol->rtp && !sp->protocol->srtp
					&& sp->protocol->osrtp_proto)
			{
				if (sp->fingerprint.hash_func || sp->sdes_params.length)
					sp->protocol = &transport_protocols[sp->protocol->osrtp_proto];
			}

			// a=mid
			attr = attr_get_by_id(&media->attributes, ATTR_MID);
			if (attr)
				sp->media_id = attr->value;

			// be ignorant about the contents
			if (attr_get_by_id(&media->attributes, ATTR_RTCP_FB))
				SP_SET(sp, RTCP_FB);

			__sdp_t38(sp, media);

			/* determine RTCP endpoint */

			if (attr_get_by_id(&media->attributes, ATTR_RTCP_MUX)) {
				SP_SET(sp, RTCP_MUX);
				goto next;
			}

			attr = attr_get_by_id(&media->attributes, ATTR_RTCP);
			if (!attr || media->port_count != 1) {
				SP_SET(sp, IMPLICIT_RTCP);
				goto next;
			}
			if (attr->u.rtcp.port_num == sp->rtp_endpoint.port
					&& !is_trickle_ice_address(&sp->rtp_endpoint))
			{
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
	g_slice_free1(sizeof(*sp), sp);
	return -1;
}

static void sp_free(void *p) {
	struct stream_params *s = p;

	codec_store_cleanup(&s->codecs);
	ice_candidates_free(&s->ice_candidates);
	crypto_params_sdes_queue_clear(&s->sdes_params);
	g_slice_free1(sizeof(*s), s);
}
void sdp_streams_free(GQueue *q) {
	g_queue_clear_full(q, sp_free);
}



struct sdp_chopper *sdp_chopper_new(str *input) {
	struct sdp_chopper *c = g_slice_alloc0(sizeof(*c));
	c->input = input;
	c->output = g_string_new("");
	return c;
}

INLINE void chopper_append(struct sdp_chopper *c, const char *s, int len) {
	g_string_append_len(c->output, s, len);
}
INLINE void chopper_append_c(struct sdp_chopper *c, const char *s) {
	chopper_append(c, s, strlen(s));
}
INLINE void chopper_append_str(struct sdp_chopper *c, const str *s) {
	chopper_append(c, s->s, s->len);
}
static void chopper_replace(struct sdp_chopper *c, str *old, size_t *old_pos,
		const char *repl, size_t repl_len)
{
	// adjust for offsets created within this run
	*old_pos += c->offset;
	// is our new value longer?
	if (repl_len > old->len) {
		// overwrite + insert
		g_string_overwrite_len(c->output, *old_pos, repl, old->len);
		g_string_insert(c->output, *old_pos + old->len, repl + old->len);
		c->offset += repl_len - old->len;
		old->len = repl_len;
	}
	else {
		// overwrite + optional erase
		g_string_overwrite(c->output, *old_pos, repl);
		if (repl_len < old->len) {
			g_string_erase(c->output, *old_pos + repl_len, old->len - repl_len);
			c->offset -= old->len - repl_len;
			old->len = repl_len;
		}
	}
}

#define chopper_append_printf(c, f...) g_string_append_printf((c)->output, f)

static int copy_up_to_ptr(struct sdp_chopper *chop, const char *b) {
	int offset, len;

	if (!b)
		return 0;

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

	if (!where || !where->s)
		return 0;

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

static int print_format_str(GString *s, struct call_media *cm) {
	if (!cm->format_str.s)
		return 0;
	g_string_append(s, " ");
	g_string_append_len(s, cm->format_str.s, cm->format_str.len);
	return 0;
}

static int print_codec_list(GString *s, struct call_media *media) {
	if (!proto_is_rtp(media->protocol))
		return print_format_str(s, media);

	if (media->codecs.codec_prefs.length == 0)
		return 0; // legacy protocol or usage error

	for (GList *l = media->codecs.codec_prefs.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		g_string_append_printf(s, " %u", pt->payload_type);
	}
	return 0;
}

static int replace_codec_list(struct sdp_chopper *chop,
		struct sdp_media *media, struct call_media *cm)
{
	if (skip_over(chop, &media->formats))
		return -1;

	return print_codec_list(chop->output, cm);
}

static void insert_codec_parameters(GString *s, struct call_media *cm) {
	for (GList *l = cm->codecs.codec_prefs.head; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		if (!pt->encoding_with_params.len)
			continue;
		g_string_append_printf(s, "a=rtpmap:%u " STR_FORMAT "\r\n",
				pt->payload_type,
				STR_FMT(&pt->encoding_with_params));
		if (pt->format_parameters.len) {
			g_string_append_printf(s, "a=fmtp:%u " STR_FORMAT "\r\n",
					pt->payload_type,
					STR_FMT(&pt->format_parameters));
		}
		for (GList *l = pt->rtcp_fb.head; l; l = l->next) {
			str *fb = l->data;
			g_string_append_printf(s, "a=rtcp-fb:%u " STR_FORMAT "\r\n",
					pt->payload_type,
					STR_FMT(fb));
		}
	}
}

static void insert_sdp_attributes(GString *gs, struct call_media *cm) {
	for (GList *l = cm->sdp_attributes.head; l; l = l->next) {
		str *s = l->data;
		g_string_append_printf(gs, "a=" STR_FORMAT "\r\n",
				STR_FMT(s));
	}
}

static int replace_media_type(struct sdp_chopper *chop, struct sdp_media *media, struct call_media *cm) {
	str *type = &media->media_type_str;

	if (!cm->type.s)
		return 0;

	if (copy_up_to(chop, type))
		return -1;

	chopper_append_str(chop, &cm->type);

	if (skip_over(chop, type))
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

	p = ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0;
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

	if (media->port_count == 1 || !ps->selected_sfd)
		return 0;

	for (cons = 1; cons < media->port_count; cons++) {
		j = j->next;
		if (!j)
			goto warn;
		ps_n = j->data;
		if (ps_n->selected_sfd->socket.local.port != ps->selected_sfd->socket.local.port + cons) {
warn:
			ilog(LOG_WARN, "Failed to handle consecutive ports");
			break;
		}
	}

	chopper_append_printf(chop, "/%i", cons);

	return 0;
}

static int insert_ice_address(GString *s, struct stream_fd *sfd, struct sdp_ng_flags *flags) {
	char buf[64];
	int len;

	if (!is_addr_unspecified(&flags->parsed_media_address))
		len = sprintf(buf, "%s",
				sockaddr_print_buf(&flags->parsed_media_address));
	else
		call_stream_address46(buf, sfd->stream, SAF_ICE, &len, sfd->local_intf, 0);
	g_string_append_len(s, buf, len);
	g_string_append_printf(s, " %u", sfd->socket.local.port);

	return 0;
}

static int insert_raddr_rport(GString *s, struct stream_fd *sfd, struct sdp_ng_flags *flags) {
        char buf[64];
        int len;

	g_string_append(s, " raddr ");
	if (!is_addr_unspecified(&flags->parsed_media_address))
		len = sprintf(buf, "%s",
				sockaddr_print_buf(&flags->parsed_media_address));
	else
		call_stream_address46(buf, sfd->stream, SAF_ICE, &len, sfd->local_intf, 0);
	g_string_append_len(s, buf, len);
	g_string_append(s, " rport ");
	g_string_append_printf(s, "%u", sfd->socket.local.port);

	return 0;
}


static int replace_network_address(struct sdp_chopper *chop, struct network_address *address,
		struct packet_stream *ps, struct sdp_ng_flags *flags, int keep_unspec)
{
	char buf[64];
	int len;

	if (copy_up_to(chop, &address->address_type))
		return -1;

	if (flags->media_address.s && is_addr_unspecified(&flags->parsed_media_address))
		__parse_address(&flags->parsed_media_address, NULL, NULL, &flags->media_address);

	if (!is_addr_unspecified(&flags->parsed_media_address))
		len = sprintf(buf, "%s %s",
				flags->parsed_media_address.family->rfc_name,
				sockaddr_print_buf(&flags->parsed_media_address));
	else
		call_stream_address46(buf, ps, SAF_NG, &len, NULL, keep_unspec);
	chopper_append(chop, buf, len);

	if (skip_over(chop, &address->address))
		return -1;

	return 0;
}

static int synth_session_connection(struct sdp_chopper *chop, struct sdp_media *sdp_media) {
	if (!sdp_media->session->connection.s.s)
		return -1;

	if (sdp_media->c_line_pos)
		copy_up_to_ptr(chop, sdp_media->c_line_pos);
	else
		copy_up_to_end_of(chop, chop->input);

	chopper_append_c(chop, "c=");
	chopper_append_str(chop, &sdp_media->session->connection.s);
	chopper_append_c(chop, "\n");

	return 0;
}

void sdp_chopper_destroy(struct sdp_chopper *chop) {
	if (chop->output)
		g_string_free(chop->output, TRUE);
	g_slice_free1(sizeof(*chop), chop);
}
void sdp_chopper_destroy_ret(struct sdp_chopper *chop, str *ret) {
	*ret = STR_NULL;
	if (chop->output) {
		str_init_len(ret, chop->output->str, chop->output->len);
		g_string_free(chop->output, FALSE);
		chop->output = NULL;
	}
	sdp_chopper_destroy(chop);
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
			case ATTR_ICE_PWD:
			case ATTR_ICE_OPTIONS:
			case ATTR_ICE_LITE:
				if (flags->ice_option != ICE_REMOVE && flags->ice_option != ICE_FORCE
						&& flags->ice_option != ICE_DEFAULT)
					break;
				goto strip;

			case ATTR_CANDIDATE:
				if (flags->ice_option == ICE_FORCE_RELAY) {
					if ((attr->u.candidate.type_str.len == 5) &&
					    (strncasecmp(attr->u.candidate.type_str.s, "relay", 5) == 0))
						goto strip;
					else
						break;
				}
				if (flags->ice_option != ICE_REMOVE && flags->ice_option != ICE_FORCE
						&& flags->ice_option != ICE_DEFAULT)
					break;
				goto strip;

			case ATTR_EXTMAP:
				if (flags->strip_extmap)
					goto strip;
				break;

			case ATTR_FINGERPRINT:
			case ATTR_SETUP:
			case ATTR_IGNORE:
				goto strip;

			case ATTR_INACTIVE:
			case ATTR_SENDONLY:
			case ATTR_RECVONLY:
			case ATTR_SENDRECV:
				if (!flags->original_sendrecv)
					goto strip;
				break;

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
	struct sdp_attribute *attr /* , *a */;

	for (l = attrs->list.head; l; l = l->next) {
		attr = l->data;

		// strip all attributes if we're sink and generator - make our own clean SDP
		if (MEDIA_ISSET(media, GENERATOR))
			goto strip;

		switch (attr->attr) {
			case ATTR_ICE:
			case ATTR_ICE_UFRAG:
			case ATTR_ICE_PWD:
			case ATTR_ICE_OPTIONS:
			case ATTR_ICE_LITE:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				if (flags->ice_option != ICE_REMOVE && flags->ice_option != ICE_FORCE
						&& flags->ice_option != ICE_DEFAULT)
					break;
				goto strip;

			case ATTR_CANDIDATE:
				if (flags->ice_option == ICE_FORCE_RELAY) {
					if ((attr->u.candidate.type_str.len == 5) &&
					    (strncasecmp(attr->u.candidate.type_str.s, "relay", 5) == 0))
						goto strip;
					else
						break;
				}
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				if (flags->ice_option != ICE_REMOVE && flags->ice_option != ICE_FORCE
						&& flags->ice_option != ICE_DEFAULT)
					break;
				goto strip;

			case ATTR_RTCP:
			case ATTR_RTCP_MUX:
				if (flags->ice_option == ICE_FORCE_RELAY)
					break;
				goto strip;

			case ATTR_IGNORE:
			case ATTR_END_OF_CANDIDATES: // we strip it here and re-insert it later
			case ATTR_MID:
				goto strip;

			case ATTR_INACTIVE:
			case ATTR_SENDONLY:
			case ATTR_RECVONLY:
			case ATTR_SENDRECV:
				if (!flags->original_sendrecv)
					goto strip;
				break;

			case ATTR_RTPMAP:
			case ATTR_FMTP:
				if (media->codecs.codec_prefs.length > 0)
					goto strip;
				break;
			case ATTR_PTIME:
				if (media->ptime)
					goto strip;
				break;
			case ATTR_RTCP_FB:
				if (attr->u.rtcp_fb.payload_type == -1)
					break; // leave this one alone
				if (media->codecs.codec_prefs.length > 0)
					goto strip;
				break;

			case ATTR_EXTMAP:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				if (flags->strip_extmap)
					goto strip;
				break;

			case ATTR_CRYPTO:
			case ATTR_FINGERPRINT:
			case ATTR_SETUP:
				if (MEDIA_ISSET(media, PASSTHRU))
					break;
				goto strip;

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

static void new_priority(struct sdp_media *media, enum ice_candidate_type type, unsigned int *tprefp,
		unsigned int *lprefp)
{
	GQueue *cands;
	unsigned int lpref, tpref;
	uint32_t prio;
	GList *l;
	struct sdp_attribute *a;
	struct attribute_candidate *c;

	lpref = 0;
	tpref = ice_type_preference(type);
	prio = ice_priority_pref(tpref, lpref, 1);

	cands = attr_list_get_by_id(&media->attributes, ATTR_CANDIDATE);
	if (!cands)
		goto out;

	for (l = cands->head; l; l = l->next) {
		a = l->data;
		c = &a->u.candidate;
		if (c->cand_parsed.priority <= prio && c->cand_parsed.type == type
				&& c->cand_parsed.component_id == 1)
		{
			/* tpref should come out as 126 (if host) here, unless the client isn't following
			 * the RFC, in which case we must adapt */
			tpref = ice_type_pref_from_prio(c->cand_parsed.priority);

			lpref = ice_local_pref_from_prio(c->cand_parsed.priority);
			if (lpref)
				lpref--;
			else {
				/* we must deviate from the RFC recommended values */
				if (tpref)
					tpref--;
				lpref = 65535;
			}
			prio = ice_priority_pref(tpref, lpref, 1);
		}
	}

out:
	*tprefp = tpref;
	*lprefp = lpref;
}

static void insert_candidate(GString *s, struct stream_fd *sfd,
		unsigned int type_pref, unsigned int local_pref, enum ice_candidate_type type,
		struct sdp_ng_flags *flags)
{
	unsigned long priority;
	struct packet_stream *ps = sfd->stream;
	const struct local_intf *ifa = sfd->local_intf;

	if (local_pref == -1)
		local_pref = ifa->unique_id;

	priority = ice_priority_pref(type_pref, local_pref, ps->component);
	g_string_append(s, "a=candidate:");
	g_string_append_printf(s, STR_FORMAT, STR_FMT(&ifa->ice_foundation));
	g_string_append_printf(s, " %u UDP %lu ", ps->component, priority);
	insert_ice_address(s, sfd, flags);
	g_string_append(s, " typ ");
	g_string_append(s, ice_candidate_type_str(type));
	/* raddr and rport are required for non-host candidates: rfc5245 section-15.1 */
	if(type != ICT_HOST)
		insert_raddr_rport(s, sfd, flags);
	g_string_append(s, "\r\n");
}

static void insert_sfd_candidates(GString *s, struct packet_stream *ps,
		unsigned int type_pref, unsigned int local_pref, enum ice_candidate_type type,
		struct sdp_ng_flags *flags)
{
	GList *l;
	struct stream_fd *sfd;

	for (l = ps->sfds.head; l; l = l->next) {
		sfd = l->data;
		insert_candidate(s, sfd, type_pref, local_pref, type, flags);

		if (local_pref != -1)
			local_pref++;
	}
}

static void insert_candidates(GString *s, struct packet_stream *rtp, struct packet_stream *rtcp,
		struct sdp_ng_flags *flags, struct sdp_media *sdp_media)
{
	const struct local_intf *ifa;
	struct call_media *media;
	struct ice_agent *ag;
	unsigned int type_pref, local_pref;
	enum ice_candidate_type cand_type;
	struct ice_candidate *cand;

	media = rtp->media;

	cand_type = ICT_HOST;
	if (flags->ice_option == ICE_FORCE_RELAY)
		cand_type = ICT_RELAY;
	if (MEDIA_ISSET(media, PASSTHRU) && sdp_media)
		new_priority(sdp_media, cand_type, &type_pref, &local_pref);
	else {
		type_pref = ice_type_preference(cand_type);
		local_pref = -1;
	}

	ag = media->ice_agent;

	if (ag && AGENT_ISSET(ag, COMPLETED)) {
		ifa = rtp->selected_sfd->local_intf;
		insert_candidate(s, rtp->selected_sfd, type_pref, ifa->unique_id, cand_type, flags);
		if (rtcp) /* rtcp-mux only possible in answer */
			insert_candidate(s, rtcp->selected_sfd, type_pref, ifa->unique_id, cand_type, flags);

		if (flags->opmode == OP_OFFER && AGENT_ISSET(ag, CONTROLLING)) {
			GQueue rc;
			GList *l;
			g_string_append(s, "a=remote-candidates:");
			ice_remote_candidates(&rc, ag);
			for (l = rc.head; l; l = l->next) {
				if (l != rc.head)
					g_string_append(s, " ");
				cand = l->data;
				g_string_append_printf(s, "%lu %s %u", cand->component_id,
						sockaddr_print_buf(&cand->endpoint.address), cand->endpoint.port);
			}
			g_string_append(s, "\r\n");
			g_queue_clear(&rc);
		}
		return;
	}

	insert_sfd_candidates(s, rtp, type_pref, local_pref, cand_type, flags);

	if (rtcp) /* rtcp-mux only possible in answer */
		insert_sfd_candidates(s, rtcp, type_pref, local_pref, cand_type, flags);
}

static void insert_dtls(GString *s, struct call_media *media) {
	char hexbuf[DTLS_MAX_DIGEST_LEN * 3 + 2];
	unsigned char *p;
	char *o;
	int i;
	const struct dtls_hash_func *hf;
	const char *actpass;
	struct call *call = media->call;

	if (!call->dtls_cert || !MEDIA_ISSET(media, DTLS) || MEDIA_ISSET(media, PASSTHRU))
		return;

	hf = media->fp_hash_func;
	if (!hf)
		hf = media->fingerprint.hash_func;

	struct dtls_fingerprint *fp = NULL;
	for (GList *l = call->dtls_cert->fingerprints.head; l; l = l->next) {
		fp = l->data;
		if (!hf)
			break;
		if (!strcasecmp(hf->name, fp->hash_func->name))
			break;
		fp = NULL;
	}
	if (!fp) // use first if no match
		fp = call->dtls_cert->fingerprints.head->data;

	hf = fp->hash_func;
	media->fp_hash_func = hf;

	assert(hf->num_bytes > 0);

	p = fp->digest;
	o = hexbuf;
	for (i = 0; i < hf->num_bytes; i++)
		o += sprintf(o, "%02X:", *p++);
	*(--o) = '\0';

	actpass = "holdconn";
	if (MEDIA_ARESET2(media, SETUP_PASSIVE, SETUP_ACTIVE))
		actpass = "actpass";
	else if (MEDIA_ISSET(media, SETUP_PASSIVE))
		actpass = "passive";
	else if (MEDIA_ISSET(media, SETUP_ACTIVE))
		actpass = "active";

	g_string_append(s, "a=setup:");
	g_string_append(s, actpass);
	g_string_append(s, "\r\na=fingerprint:");
	g_string_append(s, hf->name);
	g_string_append(s, " ");
	g_string_append_len(s, hexbuf, o - hexbuf);
	g_string_append(s, "\r\n");
}

static void insert_crypto1(GString *s, struct call_media *media, struct crypto_params_sdes *cps,
		struct sdp_ng_flags *flags)
{
	char b64_buf[((SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN) / 3 + 1) * 4 + 4];
	char *p;
	int state = 0, save = 0, i;
	unsigned long long ull;

	if (!cps->params.crypto_suite || !MEDIA_ISSET(media, SDES) || MEDIA_ISSET(media, PASSTHRU))
		return;

	p = b64_buf;
	p += g_base64_encode_step((unsigned char *) cps->params.master_key,
			cps->params.crypto_suite->master_key_len, 0,
			p, &state, &save);
	p += g_base64_encode_step((unsigned char *) cps->params.master_salt,
			cps->params.crypto_suite->master_salt_len, 0,
			p, &state, &save);
	p += g_base64_encode_close(0, p, &state, &save);

	if (!flags->sdes_pad) {
		// truncate trailing ==
		while (p > b64_buf && p[-1] == '=')
			p--;
	}

	g_string_append(s, "a=crypto:");
	g_string_append_printf(s, "%u ", cps->tag);
	g_string_append(s, cps->params.crypto_suite->name);
	g_string_append(s, " inline:");
	g_string_append_len(s, b64_buf, p - b64_buf);
	if (flags->sdes_lifetime)
		g_string_append(s, "|2^31");
	if (cps->params.mki_len) {
		ull = 0;
		for (i = 0; i < cps->params.mki_len && i < sizeof(ull); i++)
			ull |= (unsigned long long) cps->params.mki[cps->params.mki_len - i - 1] << (i * 8);
		g_string_append_printf(s, "|%llu:%u", ull, cps->params.mki_len);
	}
	if (cps->params.session_params.unencrypted_srtp)
		g_string_append(s, " UNENCRYPTED_SRTP");
	if (cps->params.session_params.unencrypted_srtcp)
		g_string_append(s, " UNENCRYPTED_SRTCP");
	if (cps->params.session_params.unauthenticated_srtp)
		g_string_append(s, " UNAUTHENTICATED_SRTP");
	g_string_append(s, "\r\n");
}
static void insert_crypto(GString *s, struct call_media *media, struct sdp_ng_flags *flags) {
	for (GList *l = media->sdes_out.head; l; l = l->next)
		insert_crypto1(s, media, l->data, flags);
}
static void insert_rtcp_attr(GString *s, struct packet_stream *ps, const struct sdp_ng_flags *flags) {
	if (flags->no_rtcp_attr)
		return;
	g_string_append_printf(s, "a=rtcp:%u", ps->selected_sfd->socket.local.port);
	if (flags->full_rtcp_attr) {
		char buf[64];
		int len;
		if (!is_addr_unspecified(&flags->parsed_media_address))
			len = sprintf(buf, "%s %s",
					flags->parsed_media_address.family->rfc_name,
					sockaddr_print_buf(&flags->parsed_media_address));
		else
			call_stream_address46(buf, ps, SAF_NG, &len, NULL, 0);
		g_string_append_printf(s, " IN %.*s", len, buf);
	}
	g_string_append(s, "\r\n");
}


static void sdp_version_replace(struct sdp_chopper *chop, GQueue *sessions, struct call_monologue *monologue) {
	char version_str[64];
	snprintf(version_str, sizeof(version_str), "%llu", monologue->sdp_version);
	size_t version_len = strlen(version_str);
	chop->offset = 0; // start from the top

	for (GList *l = sessions->head; l; l = l->next) {
		struct sdp_session *session = l->data;
		struct sdp_origin *origin = &session->origin;
		// update string unconditionally to keep position tracking intact
		chopper_replace(chop, &origin->version_str, &origin->version_output_pos, version_str, version_len);
	}
}

static void sdp_version_check(struct sdp_chopper *chop, GQueue *sessions, struct call_monologue *monologue) {
	// we really expect only a single session here, but we treat all the same regardless,
	// and use the same version number on all of them

	// first update all versions to match our single version
	sdp_version_replace(chop, sessions, monologue);
	// then check if we need to change
	if (!monologue->last_out_sdp)
		goto dup;
	if (g_string_equal(monologue->last_out_sdp, chop->output))
		return;

	// mismatch detected. increment version, update again, and store copy
	monologue->sdp_version++;
	sdp_version_replace(chop, sessions, monologue);
	g_string_free(monologue->last_out_sdp, TRUE);
dup:
	monologue->last_out_sdp = g_string_new_len(chop->output->str, chop->output->len);
}


void print_sendrecv(GString *s, struct call_media *media) {
	if (MEDIA_ARESET2(media, SEND, RECV))
		g_string_append(s, "a=sendrecv\r\n");
	else if (MEDIA_ISSET(media, SEND))
		g_string_append(s, "a=sendonly\r\n");
	else if (MEDIA_ISSET(media, RECV))
		g_string_append(s, "a=recvonly\r\n");
	else
		g_string_append(s, "a=inactive\r\n");
}


struct packet_stream *print_rtcp(GString *s, struct call_media *media, GList *rtp_ps_link,
		struct sdp_ng_flags *flags)
{
	struct packet_stream *ps = rtp_ps_link->data;
	struct packet_stream *ps_rtcp = NULL;

	if (ps->rtcp_sibling) {
		ps_rtcp = ps->rtcp_sibling;
		GList *rtcp_ps_link = rtp_ps_link->next;
		if (!rtcp_ps_link)
			return NULL;
		assert(rtcp_ps_link->data == ps_rtcp);
	}

	if (proto_is_rtp(media->protocol)) {
		if (MEDIA_ISSET(media, RTCP_MUX)
				&& (flags->opmode == OP_ANSWER || flags->opmode == OP_OTHER
					|| flags->opmode == OP_PUBLISH
					|| ((flags->opmode == OP_OFFER || flags->opmode == OP_REQUEST)
						&& flags->rtcp_mux_require)))
		{
			insert_rtcp_attr(s, ps, flags);
			g_string_append(s, "a=rtcp-mux\r\n");
			ps_rtcp = NULL;
		}
		else if (ps_rtcp && flags->ice_option != ICE_FORCE_RELAY) {
			insert_rtcp_attr(s, ps_rtcp, flags);
			if (MEDIA_ISSET(media, RTCP_MUX))
				g_string_append(s, "a=rtcp-mux\r\n");
		}
	}
	else
		ps_rtcp = NULL;

	return ps_rtcp;
}


static struct packet_stream *print_sdp_media_section(GString *s, struct call_media *media,
		struct sdp_media *sdp_media,
		struct sdp_ng_flags *flags,
		GList *rtp_ps_link, bool is_active, bool force_end_of_ice)
{
	struct packet_stream *ps_rtcp = NULL;

	if (media->media_id.s) {
		g_string_append(s, "a=mid:");
		g_string_append_printf(s, STR_FORMAT, STR_FMT(&media->media_id));
		g_string_append(s, "\r\n");
	}

	if (is_active) {
		if (proto_is_rtp(media->protocol))
			insert_codec_parameters(s, media);

		insert_sdp_attributes(s, media);

		if (!flags->original_sendrecv)
			print_sendrecv(s, media);

		ps_rtcp = print_rtcp(s, media, rtp_ps_link, flags);

		insert_crypto(s, media, flags);
		insert_dtls(s, media);

		if (proto_is_rtp(media->protocol) && media->ptime)
			g_string_append_printf(s, "a=ptime:%i\r\n", media->ptime);

		if (MEDIA_ISSET(media, ICE) && media->ice_agent) {
			g_string_append(s, "a=ice-ufrag:");
			g_string_append_printf(s, STR_FORMAT, STR_FMT(&media->ice_agent->ufrag[1]));
			g_string_append(s, "\r\na=ice-pwd:");
			g_string_append_printf(s, STR_FORMAT, STR_FMT(&media->ice_agent->pwd[1]));
			g_string_append(s, "\r\n");
		}

		if (MEDIA_ISSET(media, TRICKLE_ICE) && media->ice_agent)
			g_string_append(s, "a=ice-options:trickle\r\n");
		if (MEDIA_ISSET(media, ICE))
			insert_candidates(s, rtp_ps_link->data, ps_rtcp, flags, sdp_media);
	}

	if (MEDIA_ISSET(media, TRICKLE_ICE) && media->ice_agent)
		g_string_append(s, "a=end-of-candidates\r\n");
	else if (force_end_of_ice)
		g_string_append(s, "a=end-of-candidates\r\n");

	return ps_rtcp;
}


/* called with call->master_lock held in W */
int sdp_replace(struct sdp_chopper *chop, GQueue *sessions, struct call_monologue *monologue,
		struct sdp_ng_flags *flags)
{
	struct sdp_session *session;
	struct sdp_media *sdp_media;
	GList *l, *k, *m, *rtp_ps_link;
	int media_index, sess_conn;
	struct call_media *call_media;
	struct packet_stream *ps;
	const char *err = NULL;

	m = monologue->medias.head;
	media_index = 1;

	for (l = sessions->head; l; l = l->next) {
		session = l->data;
		err = "no matching session media";
		if (!m)
			goto error;
		call_media = m->data;
		err = "mismatched session media index";
		if (call_media->index != media_index)
			goto error;
		err = "no matching session media stream";
		rtp_ps_link = call_media->streams.head;
		if (!rtp_ps_link)
			goto error;
		ps = rtp_ps_link->data;

		err = "error while processing o= line";
		if (!monologue->sdp_username)
			monologue->sdp_username = call_strdup_len(monologue->call, session->origin.username.s,
					session->origin.username.len);
		else if (flags->replace_username) {
			if (copy_up_to(chop, &session->origin.username))
				goto error;
			chopper_append_c(chop, monologue->sdp_username);
			if (skip_over(chop, &session->origin.username))
				goto error;
		}

		// record position of o= line and init SDP version
		if (copy_up_to(chop, &session->origin.version_str))
			goto error;
		session->origin.version_output_pos = chop->output->len;
		if (!monologue->sdp_version) {
			monologue->sdp_version = session->origin.version_num;
			if (monologue->sdp_version == 0 || monologue->sdp_version == ULLONG_MAX)
				monologue->sdp_version = ssl_random();
		}

		if (session->origin.parsed && flags->replace_origin &&
		    flags->ice_option != ICE_FORCE_RELAY) {
			err = "failed to replace network address";
			if (replace_network_address(chop, &session->origin.address, ps, flags, 0))
				goto error;
		}

		err = "error while processing s= line";
		if (!monologue->sdp_session_name)
			monologue->sdp_session_name = call_strdup_len(monologue->call, session->session_name.s,
					session->session_name.len);
		else if (flags->replace_sess_name) {
			if (copy_up_to(chop, &session->session_name))
				goto error;
			chopper_append_c(chop, monologue->sdp_session_name);
			if (skip_over(chop, &session->session_name))
				goto error;
		}

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

		if (session->connection.parsed && sess_conn &&
		    flags->ice_option != ICE_FORCE_RELAY) {
			err = "failed to replace network address";
			if (replace_network_address(chop, &session->connection.address, ps, flags, 1))
				goto error;
		}

		if (!MEDIA_ISSET(call_media, PASSTHRU)) {
			err = "failed to process session attributes";
			if (process_session_attributes(chop, &session->attributes, flags))
				goto error;
		}

		copy_up_to_end_of(chop, &session->s);

		if (flags->loop_protect) {
			chopper_append_c(chop, "a=rtpengine:");
			chopper_append_str(chop, &rtpe_instance_id);
			chopper_append_c(chop, "\r\n");
		}

		if (MEDIA_ISSET(call_media, ICE) && MEDIA_ISSET(call_media, ICE_LITE_SELF))
			chopper_append_c(chop, "a=ice-lite\r\n");


		for (k = session->media_streams.head; k; k = k->next) {
			sdp_media = k->data;
			err = "no matching media";
			if (!m)
				goto error;
			call_media = m->data;
			err = "media index mismatched";
			if (call_media->index != media_index)
				goto error;
			err = "no matching media stream";
			rtp_ps_link = call_media->streams.head;
			if (!rtp_ps_link)
				goto error;
			ps = rtp_ps_link->data;

			bool is_active = true;

			if (flags->ice_option != ICE_FORCE_RELAY && call_media->type_id != MT_MESSAGE) {
				err = "failed to replace media type";
				if (replace_media_type(chop, sdp_media, call_media))
					goto error;
				err = "failed to replace media port";
			        if (replace_media_port(chop, sdp_media, ps))
				        goto error;
				err = "failed to replace media port count";
			        if (replace_consecutive_port_count(chop, sdp_media, ps, rtp_ps_link))
				        goto error;
				err = "failed to replace media protocol";
				if (replace_transport_protocol(chop, sdp_media, call_media))
				        goto error;
				err = "failed to replace media formats";
				if (replace_codec_list(chop, sdp_media, call_media))
					goto error;

				if (sdp_media->connection.parsed) {
					err = "failed to replace media network address";
				        if (replace_network_address(chop, &sdp_media->connection.address, ps,
								flags, 1))
					        goto error;
				}
			}
			else if (call_media->type_id == MT_MESSAGE) {
				err = "failed to generate connection line";
				if (!sdp_media->connection.parsed)
					if (synth_session_connection(chop, sdp_media))
						goto error;
				// leave everything untouched
				is_active = false;
				goto next;
			}

			err = "failed to process media attributes";
			if (process_media_attributes(chop, sdp_media, flags, call_media))
				goto error;

			copy_up_to_end_of(chop, &sdp_media->s);

			if (!sdp_media->port_num || !ps->selected_sfd)
				is_active = false;

next:
			print_sdp_media_section(chop->output, call_media, sdp_media,flags, rtp_ps_link, is_active,
					attr_get_by_id(&sdp_media->attributes, ATTR_END_OF_CANDIDATES));

			media_index++;
			m = m->next;
		}
	}

	copy_remainder(chop);

	if (flags->replace_sdp_version)
		sdp_version_check(chop, sessions, monologue);


	return 0;

error:
	ilog(LOG_ERROR, "Error rewriting SDP: %s", err);
	return -1;
}

int sdp_create(str *out, struct call_monologue *monologue, struct sdp_ng_flags *flags) {
	const char *err = NULL;
	GString *s = NULL;

	err = "Need at least one media";
	if (!monologue->medias.length)
		goto err;

	// grab first components
	struct call_media *media = monologue->medias.head->data;
	err = "No media stream";
	if (!media->streams.length)
		goto err;
	struct packet_stream *first_ps = media->streams.head->data;
	err = "No packet stream";
	if (!first_ps->selected_sfd)
		goto err;

	s = g_string_new("v=0\r\no=- ");

	// init session params
	if (!monologue->sdp_session_id)
		monologue->sdp_session_id = (unsigned long long) rtpe_now.tv_sec << 32 | rtpe_now.tv_usec;
	if (!monologue->sdp_version)
		monologue->sdp_version = monologue->sdp_session_id;

	g_string_append_printf(s, "%llu %llu IN %s %s\r\n", monologue->sdp_session_id, monologue->sdp_version,
			first_ps->selected_sfd->local_intf->advertised_address.addr.family->rfc_name,
			sockaddr_print_buf(&first_ps->selected_sfd->local_intf->advertised_address.addr));

	g_string_append_printf(s, "s=%s\r\n", rtpe_config.software_id);
	g_string_append(s, "t=0 0\r\n");

	for (GList *l = monologue->medias.head; l; l = l->next) {
		media = l->data;
		err = "Zero length media stream";
		if (!media->streams.length)
			goto err;
		GList *rtp_ps_link = media->streams.head;
		struct packet_stream *rtp_ps = rtp_ps_link->data;
		err = "No selected FD";
		if (!rtp_ps->selected_sfd)
			goto err;
		err = "Unknown media protocol";
		if (media->protocol)
			g_string_append_printf(s, "m=" STR_FORMAT " %i %s",
					STR_FMT(&media->type),
					rtp_ps->selected_sfd->socket.local.port,
					media->protocol->name);
		else if (media->protocol_str.s)
			g_string_append_printf(s, "m=" STR_FORMAT " %i " STR_FORMAT,
					STR_FMT(&media->type),
					rtp_ps->selected_sfd->socket.local.port,
					STR_FMT(&media->protocol_str));
		else
			goto err;
		print_codec_list(s, media);
		g_string_append_printf(s, "\r\nc=IN %s %s\r\n",
				rtp_ps->selected_sfd->local_intf->advertised_address.addr.family->rfc_name,
				sockaddr_print_buf(&rtp_ps->selected_sfd->local_intf->advertised_address.addr));
		print_sdp_media_section(s, media, NULL, flags, rtp_ps_link, true, false);
	}

	out->s = s->str;
	out->len = s->len;
	g_string_free(s, FALSE);
	return 0;
err:
	if (s)
		g_string_free(s, TRUE);
	ilog(LOG_ERR, "Failed to create SDP: %s", err);
	return -1;
}

int sdp_is_duplicate(GQueue *sessions) {
	for (GList *l = sessions->head; l; l = l->next) {
		struct sdp_session *s = l->data;
		GQueue *attr_list = attr_list_get_by_id(&s->attributes, ATTR_RTPENGINE);
		if (!attr_list)
			return 0;
		for (GList *ql = attr_list->head; ql; ql = ql->next) {
			struct sdp_attribute *attr = ql->data;
			if (!str_cmp_str(&attr->value, &rtpe_instance_id))
				goto next;
		}
		return 0;
next:
		;
	}
	return 1;
}

void sdp_init() {
	rand_hex_str(rtpe_instance_id.s, rtpe_instance_id.len / 2);
}
