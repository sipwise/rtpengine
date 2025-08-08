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
#include "media_player.h"

enum attr_id {
	ATTR_OTHER = 0,
	ATTR_RTCP,
	ATTR_CANDIDATE,
	ATTR_ICE,
	ATTR_ICE_LITE,
	ATTR_ICE_OPTIONS,
	ATTR_ICE_UFRAG,
	ATTR_ICE_PWD,
	ATTR_CRYPTO,
	ATTR_INACTIVE,
	ATTR_SENDRECV,
	ATTR_SENDONLY,
	ATTR_RECVONLY,
	ATTR_RTCP_MUX,
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
	/* this is a block of attributes, which are only needed to carry attributes
	* from `sdp_media` to `call_media`structure,
	* and needs later processing in `sdp_create()`.	*/
	ATTR_T38MAXBITRATE,
	ATTR_T38FAXMAXBUFFER,
	ATTR_MAXPTIME,
	ATTR_TLS_ID,
	ATTR_END_OF_CANDIDATES,
	ATTR_MOH_ATTR_NAME,
	ATTR_EXTMAP,
};
// make sure g_direct_hash can be used
static_assert(sizeof(void *) >= sizeof(enum attr_id), "sizeof enum attr_id wrong");

struct sdp_connection {
	str s;
	struct network_address address;
	unsigned int parsed:1;
};

TYPED_GQUEUE(attributes, struct sdp_attribute)
TYPED_GHASHTABLE(attr_id_ht, void, struct sdp_attribute, g_direct_hash, g_direct_equal, NULL, NULL)
TYPED_GHASHTABLE(attr_list_ht, void, attributes_q, g_direct_hash, g_direct_equal, NULL, g_queue_free)
TYPED_GHASHTABLE_LOOKUP_INSERT(attr_list_ht, NULL, attributes_q_new)

struct sdp_attributes {
	attributes_q list;
	/* GHashTable *name_hash; */
	/* GHashTable *name_lists_hash; */
	attr_list_ht id_lists_hash;
	attr_id_ht id_hash;
};

TYPED_GQUEUE(sdp_media, struct sdp_media)

struct sdp_session {
	str s;
	sdp_origin origin;
	str session_name;
	str session_timing; /* t= */
	struct sdp_connection connection;
	struct session_bandwidth bandwidth;
	struct sdp_attributes attributes;
	sdp_media_q media_streams;
	str information; // i= line
	str uri; // u= line
	str email; // e= line
	str phone; // p= line
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
	struct session_bandwidth bandwidth;
	struct sdp_attributes attributes;
	str_slice_q format_list; /* list of slice-alloc'd str objects */
	enum media_type media_type_id;
	int media_sdp_id;

	str information; // i= line
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

	rtp_payload_type rtp_pt;
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

struct attribute_extmap {
	str id_str;
	str ext;

	int id;
};

enum attribute_other {
	ATTR_OTHER_UNKNOWN = 0,
};

struct sdp_attribute {
	/* example: a=rtpmap:8 PCMA/8000 */
	str full_line;	/* including a= and \r\n */ // XXX to be obsoleted
	str param;	/* "PCMA/8000" */

	struct sdp_attribute_strs strs;
	enum attr_id attr;

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
		struct attribute_extmap extmap;
		enum attribute_other other;
	};
};

struct sdp_attr {
	struct sdp_attribute_strs strs;
	enum attr_id attr;
	enum attribute_other other;
};

/**
 * Globaly visible variables for this file.
 */
static char __id_buf[6*2 + 1]; // 6 hex encoded characters
const str rtpe_instance_id = STR_CONST(__id_buf);

/**
 * Declarations for inner functions/helpers.
 */
static struct sdp_attr *sdp_attr_dup(const struct sdp_attribute *c);
static void attr_free(struct sdp_attribute *p);
static void attr_insert(struct sdp_attributes *attrs, struct sdp_attribute *attr);
static struct call_media *sdp_out_set_source_media_address(struct call_media *media,
		struct call_media *source_media,
		struct packet_stream *rtp_ps,
		struct sdp_ng_flags *flags,
		endpoint_t *sdp_address);

__attribute__((nonnull(1, 3)))
static void sdp_out_add_media_bandwidth(GString *out,
		struct call_media *media, sdp_ng_flags *flags);
__attribute__((nonnull(1, 3)))
static void sdp_out_add_session_bandwidth(GString *out, struct call_monologue *monologue,
		sdp_ng_flags *flags);
__attribute__((nonnull(1, 2, 3, 5)))
static void sdp_out_add_media_connection(GString *out, struct call_media *media,
		struct packet_stream *rtp_ps, const sockaddr_t *address, sdp_ng_flags *flags);
__attribute__((nonnull(1, 2, 3, 5, 6)))
static void sdp_out_original_media_attributes(GString *out, struct call_media *media,
		const endpoint_t *address, struct call_media *source_media,
		struct packet_stream *rtp_ps, sdp_ng_flags *flags);

/**
 * Checks whether an attribute removal request exists for a given session level.
 * `attr_name` must be without `a=`.
 */
static bool sdp_manipulate_remove(const struct sdp_manipulations * sdp_manipulations, const str * attr_name) {

	/* no need for checks, if not given in flags */
	if (!sdp_manipulations)
		return false;

	if (!attr_name || !attr_name->len)
		return false;

	str_case_ht ht = sdp_manipulations->rem_commands;
	if (t_hash_table_is_set(ht) && t_hash_table_lookup(ht, attr_name)) {
		ilog(LOG_DEBUG, "Cannot insert: '" STR_FORMAT "' because prevented by SDP manipulations (remove)",
				STR_FMT(attr_name));
		return true; /* means remove */
	}

	return false; /* means don't remove */
}

/**
 * Adds values into a requested session level (global, audio, video)
 */
static void sdp_manipulations_add(GString *s, const struct sdp_manipulations * sdp_manipulations) {

	if (!sdp_manipulations)
		return;

	const str_q * q_ptr = &sdp_manipulations->add_commands;

	for (auto_iter(l, q_ptr->head); l; l = l->next)
	{
		str * attr_value = l->data;
		g_string_append_len(s, "a=", 2);
		g_string_append_len(s, attr_value->s, attr_value->len);
		g_string_append_len(s, "\r\n", 2);
	}
}

/**
 * Substitute values for a requested session level (global, audio, video).
 * `attr_name` must be without `a=`.
 */
static str *sdp_manipulations_subst(const struct sdp_manipulations * sdp_manipulations,
		const str * attr_name) {

	if (!sdp_manipulations)
		return NULL;

	str_case_value_ht ht = sdp_manipulations->subst_commands;

	str * cmd_subst_value = t_hash_table_is_set(ht) ? t_hash_table_lookup(ht, attr_name) : NULL;

	if (cmd_subst_value)
		ilog(LOG_DEBUG, "Substituting '" STR_FORMAT "' with '" STR_FORMAT "' due to SDP manipulations",
				STR_FMT(attr_name), STR_FMT(cmd_subst_value));

	return cmd_subst_value;
}


__attribute__((nonnull(1, 2, 3, 4)))
static void append_str_attr_to_gstring(GString *s, const str *name, const str *value,
		const sdp_ng_flags *flags, enum media_type media_type);
__attribute__((nonnull(1, 2, 3)))
static void append_null_str_attr_to_gstring(GString *s, const str *name,
		const sdp_ng_flags *flags, enum media_type media_type);
__attribute__((nonnull(1, 2, 4, 5)))
static void append_int_tagged_str_attr_to_gstring(GString *s, const str *name, unsigned int tag, const str *value,
		const sdp_ng_flags *flags, enum media_type media_type);

#define append_int_tagged_attr_to_gstring(s, name, tag, value, flags, type) \
	append_int_tagged_str_attr_to_gstring(s, STR_PTR(name), tag, value, flags, type)
#define append_v_attr_to_gstring(s, name, flags, type, fmt, ...) \
	append_v_str_attr_to_gstring(s, STR_PTR(name), flags, type, fmt, ##__VA_ARGS__)
#define append_attr_int_to_gstring(s, name, value, flags, type) \
	append_v_attr_to_gstring(s, name, flags, type, "%u", value)
#define append_attr_to_gstring(s, name, value, flags, type) \
	append_str_attr_to_gstring(s, STR_PTR(name), value, flags, type)
#define append_null_attr_to_gstring(s, name, flags, type) \
	append_null_str_attr_to_gstring(s, STR_PTR(name), flags, type)
#define append_gen_attr_to_gstring(s, name, value, flags, type) ({ \
		if ((value)->len) \
			append_str_attr_to_gstring(s, name, value, flags, type); \
		else \
			append_null_str_attr_to_gstring(s, name, flags, type); \
	})

struct sdp_state {
	GString *s;
	size_t start;
	struct sdp_manipulations *manip;
	const sdp_ng_flags *flags;
};

// Records the current state of the output SDP and writes the attribute lead-in `a=`
static struct sdp_state __attr_begin(GString *s, const sdp_ng_flags *flags, enum media_type media_type) {
	struct sdp_manipulations *manip = sdp_manipulations_get_by_id(flags->sdp_manipulations, media_type);

	g_string_append(s, "a=");

	return (struct sdp_state) {
		.s = s,
		.start = s->len,
		.manip = manip,
		.flags = flags,
	};
}

static void __attr_end(const struct sdp_state *state) {
	g_string_append(state->s, "\r\n");
}

// Checks for attribute removal or substitutions.
// If removal or substitution was done, returns true
static bool __attr_manip(const struct sdp_state *state) {
	str attr = STR_LEN(state->s->str + state->start, state->s->len - state->start);

	/* first check if the originally present attribute is to be removed */
	if (sdp_manipulate_remove(state->manip, &attr)) {
		// remove everything including the `a=`
		g_string_truncate(state->s, state->start - 2);
		return true;
	}

	str *attr_subst = sdp_manipulations_subst(state->manip, &attr);
	if (attr_subst) {
		// rewind to `a=`, write complete attribute, and call it a day
		g_string_truncate(state->s, state->start);
		g_string_append_len(state->s, attr_subst->s, attr_subst->len);
		__attr_end(state);
		return true;
	}

	// continue...
	return false;
}

/**
 * Appends attribute fragment (`name` or `name:tag` or `value`) to the output SDP.
 * Includes substitute and remove SDP attribute manipulations.
 * Return true if attribute was substituted or removed.
 */
__attribute__((nonnull(1, 2)))
static bool __attr_append_str(const struct sdp_state *state, const str *s) {
	g_string_append_len(state->s, s->s, s->len);
	return __attr_manip(state);
}
#define __attr_append(state, s) __attr_append_str(state, STR_PTR(s))
__attribute__((nonnull(1, 2)))
static bool __attr_append_v(const struct sdp_state *state, const char *fmt, va_list ap) {
	g_string_append_vprintf(state->s, fmt, ap);
	return __attr_manip(state);
}
__attribute__((format(printf, 2, 3)))
__attribute__((nonnull(1, 2)))
static bool __attr_append_f(const struct sdp_state *state, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	bool ret = __attr_append_v(state, fmt, ap);
	va_end(ap);
	return ret;
}



INLINE struct sdp_attribute *attr_get_by_id(struct sdp_attributes *a, enum attr_id id) {
	return t_hash_table_lookup(a->id_hash, GINT_TO_POINTER(id));
}
INLINE attributes_q *attr_list_get_by_id(struct sdp_attributes *a, enum attr_id id) {
	return t_hash_table_lookup(a->id_lists_hash, GINT_TO_POINTER(id));
}

static struct sdp_attribute *attr_get_by_id_m_s(struct sdp_media *m, enum attr_id id) {
	struct sdp_attribute *a;

	a = attr_get_by_id(&m->attributes, id);
	if (a)
		return a;
	return attr_get_by_id(&m->session->attributes, id);
}


static bool __parse_address(sockaddr_t *out, str *network_type, str *address_type, str *address) {
	sockfamily_t *af;

	if (network_type) {
		if (network_type->len != 2)
			return false;
		if (memcmp(network_type->s, "IN", 2)
				&& memcmp(network_type->s, "in", 2))
			return false;
	}

	if (!address_type->len) {
		if (!sockaddr_parse_any_str(out, address))
			return false;
		return true;
	}

	af = get_socket_family_rfc(address_type);
	if (!sockaddr_parse_str(out, af, address))
		return false;

	return true;
}

static bool parse_address(struct network_address *address) {
	return __parse_address(&address->parsed, &address->network_type,
			&address->address_type, &address->address);
}

#define EXTRACT_TOKEN(field) do { if (!str_token_sep(&output->field, value_str, ' ')) return false; } while (0)
#define EXTRACT_TOKEN_EXCL_INCORRECT(field) \
		do { \
			if (!str_token_sep(&output->field, value_str, ' ')) \
				goto error; \
			} while (0)
#define EXTRACT_NETWORK_ADDRESS_NP(field)			\
		do { EXTRACT_TOKEN(field.network_type);		\
		EXTRACT_TOKEN(field.address_type);		\
		EXTRACT_TOKEN(field.address); } while (0)
#define EXTRACT_NETWORK_ADDRESS(field)				\
		do { EXTRACT_NETWORK_ADDRESS_NP(field);		\
		if (!parse_address(&output->field)) return false; } while (0)
#define EXTRACT_NETWORK_ADDRESS_ATTR(field)				\
		do { EXTRACT_NETWORK_ADDRESS_NP(field);		\
		if (!parse_address(&output->field)) goto error; } while (0)
#define EXTRACT_NETWORK_ADDRESS_NF(field)			\
		do { EXTRACT_NETWORK_ADDRESS_NP(field);		\
		if (!parse_address(&output->field)) {		\
			output->field.parsed.family = get_socket_family_enum(SF_IP4); \
			output->field.parsed.ipv4.s_addr = 1;	\
		} } while (0)

#define PARSE_INIT str v_str = output->strs.value; str *value_str = &v_str

static bool parse_origin(str *value_str, sdp_origin *output) {
	if (output->parsed)
		return false;

	EXTRACT_TOKEN(username);
	EXTRACT_TOKEN(session_id);
	EXTRACT_TOKEN(version_str);
	EXTRACT_NETWORK_ADDRESS_NF(address);

	output->version_num = strtoull(output->version_str.s, NULL, 10);
	output->parsed = 1;
	return true;
}

static bool parse_connection(str *value_str, struct sdp_connection *output) {
	if (output->parsed)
		return false;

	output->s = *value_str;

	EXTRACT_NETWORK_ADDRESS(address);

	output->parsed = 1;
	return true;
}

static bool parse_media(str *value_str, struct sdp_media *output) {
	char *ep;
	str *sp;

	EXTRACT_TOKEN(media_type_str);
	EXTRACT_TOKEN(port);
	EXTRACT_TOKEN(transport);
	output->formats = *value_str;

	output->media_type_id = codec_get_type(&output->media_type_str);
	output->port_num = strtol(output->port.s, &ep, 10);
	if (ep == output->port.s)
		return false;
	if (output->port_num < 0 || output->port_num > 0xffff)
		return false;

	if (*ep == '/') {
		output->port_count = atoi(ep + 1);
		if (output->port_count <= 0)
			return false;
		if (output->port_count > 10) /* unsupported */
			return false;
	}
	else
		output->port_count = 1;

	/* to split the "formats" list into tokens, we abuse some vars */
	str formats = output->formats;
	str format;
	while (str_token_sep(&format, &formats, ' ')) {
		sp = str_slice_dup(&format);
		t_queue_push_tail(&output->format_list, sp);
	}

	return true;
}

static void attrs_init(struct sdp_attributes *a) {
	t_queue_init(&a->list);
	/* a->name_hash = g_hash_table_new(str_hash, str_equal); */
	a->id_hash = attr_id_ht_new();
	/* a->name_lists_hash = g_hash_table_new_full(str_hash, str_equal,
			NULL, (GDestroyNotify) g_queue_free); */
	a->id_lists_hash = attr_list_ht_new();
}

static void attr_insert(struct sdp_attributes *attrs, struct sdp_attribute *attr) {
	t_queue_push_tail(&attrs->list, attr);

	if (!t_hash_table_lookup(attrs->id_hash, GINT_TO_POINTER(attr->attr)))
		t_hash_table_insert(attrs->id_hash, GINT_TO_POINTER(attr->attr), attr);

	attributes_q *attr_queue = attr_list_ht_lookup_insert(attrs->id_lists_hash,
			GINT_TO_POINTER(attr->attr));

	t_queue_push_tail(attr_queue, attr);

	/* g_hash_table_insert(attrs->name_hash, &attr->name, attr); */
	/* if (attr->key.s)
		g_hash_table_insert(attrs->name_hash, &attr->key, attr); */

	/* attr_queue = g_hash_table_lookup_queue_new(attrs->name_lists_hash, &attr->name);
	g_queue_push_tail(attr_queue, attr); */
}

static bool parse_attribute_group(struct sdp_attribute *output) {
	output->attr = ATTR_GROUP;

	output->group.semantics = GROUP_OTHER;
	if (output->strs.value.len >= 7 && !strncmp(output->strs.value.s, "BUNDLE ", 7))
		output->group.semantics = GROUP_BUNDLE;

	return true;
}

static bool parse_attribute_crypto(struct sdp_attribute *output) {
	char *endp;
	struct attribute_crypto *c;
	int salt_key_len, enc_salt_key_len;
	int b64_state = 0;
	unsigned int b64_save = 0;
	gsize ret;
	str s;
	uint32_t u32;
	const char *err = NULL;

	output->attr = ATTR_CRYPTO;

	PARSE_INIT;
	EXTRACT_TOKEN_EXCL_INCORRECT(crypto.tag_str);
	EXTRACT_TOKEN_EXCL_INCORRECT(crypto.crypto_suite_str);
	EXTRACT_TOKEN_EXCL_INCORRECT(crypto.key_params_str);

	c = &output->crypto;

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

	c->master_key = STR_LEN(c->key_salt_buf, c->crypto_suite->master_key_len);
	c->salt = STR_LEN(c->master_key.s + c->master_key.len, c->crypto_suite->master_salt_len);

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

	while (str_token_sep(&s, value_str, ' ')) {
		if (!str_cmp(&s, "UNENCRYPTED_SRTCP"))
			c->unencrypted_srtcp = 1;
		else if (!str_cmp(&s, "UNENCRYPTED_SRTP"))
			c->unencrypted_srtp = 1;
		else if (!str_cmp(&s, "UNAUTHENTICATED_SRTP"))
			c->unauthenticated_srtp = 1;
	}

	return true;

error:
	if (!err)
		err = "generic error";
	ilog(LOG_ERROR, "Failed to parse a=crypto attribute, ignoring: %s", err);
	output->attr = ATTR_IGNORE;
	return false;
}

static bool parse_attribute_rtcp(struct sdp_attribute *output) {
	if (!output->strs.value.s)
		goto error;
	output->attr = ATTR_RTCP;

	PARSE_INIT;

	str portnum;
	if (!str_token_sep(&portnum, value_str, ' '))
		goto error;
	output->rtcp.port_num = str_to_i(&portnum, 0);
	if (output->rtcp.port_num <= 0 || output->rtcp.port_num > 0xffff) {
		output->rtcp.port_num = 0;
		goto error;
	}

	if (value_str->len)
		EXTRACT_NETWORK_ADDRESS_ATTR(rtcp.address);

	return true;

error:
	ilog(LOG_WARN, "Failed to parse a=rtcp attribute, ignoring");
	output->attr = ATTR_IGNORE;
	return false;
}

static bool parse_attribute_candidate(struct sdp_attribute *output, bool extended) {
	char *ep;
	struct attribute_candidate *c;

	output->attr = ATTR_CANDIDATE;
	c = &output->candidate;

	PARSE_INIT;
	EXTRACT_TOKEN(candidate.cand_parsed.foundation);
	EXTRACT_TOKEN(candidate.component_str);
	EXTRACT_TOKEN(candidate.transport_str);
	EXTRACT_TOKEN(candidate.priority_str);
	EXTRACT_TOKEN(candidate.address_str);
	EXTRACT_TOKEN(candidate.port_str);
	EXTRACT_TOKEN(candidate.typ_str);
	EXTRACT_TOKEN(candidate.type_str);

	c->cand_parsed.component_id = strtoul(c->component_str.s, &ep, 10);
	if (ep == c->component_str.s)
		return false;

	c->cand_parsed.transport = get_socket_type(&c->transport_str);
	if (!c->cand_parsed.transport)
		return true;

	c->cand_parsed.priority = strtoul(c->priority_str.s, &ep, 10);
	if (ep == c->priority_str.s)
		return false;

	if (!sockaddr_parse_any_str(&c->cand_parsed.endpoint.address, &c->address_str))
		return true;

	c->cand_parsed.endpoint.port = strtoul(c->port_str.s, &ep, 10);
	if (ep == c->port_str.s)
		return false;

	if (str_cmp(&c->typ_str, "typ"))
		return false;

	c->cand_parsed.type = ice_candidate_type(&c->type_str);
	if (!c->cand_parsed.type)
		return true;

	if (ice_has_related(c->cand_parsed.type)) {
		// XXX guaranteed to be in order even with extended syntax?
		EXTRACT_TOKEN(candidate.raddr_str);
		EXTRACT_TOKEN(candidate.related_address_str);
		EXTRACT_TOKEN(candidate.rport_str);
		EXTRACT_TOKEN(candidate.related_port_str);

		if (str_cmp(&c->raddr_str, "raddr"))
			return false;
		if (str_cmp(&c->rport_str, "rport"))
			return false;

		if (!sockaddr_parse_any_str(&c->cand_parsed.related.address, &c->related_address_str))
			return true;

		c->cand_parsed.related.port = strtoul(c->related_port_str.s, &ep, 10);
		if (ep == c->related_port_str.s)
			return false;
	}

	if (extended) {
		while (true) {
			str field, value;
			if (!str_token_sep(&field, value_str, ' '))
				break;
			if (!str_token_sep(&value, value_str, ' '))
				break;
			if (!str_cmp(&field, "ufrag"))
				c->cand_parsed.ufrag = value;
		}
	}

	c->parsed = 1;
	return true;
}

// 0 = success
// -1 = error
// 1 = parsed ok but unsupported candidate type
int sdp_parse_candidate(struct ice_candidate *cand, const str *s) {
	struct sdp_attribute attr = {
		.strs = {
			.value = *s,
		},
	};

	if (!parse_attribute_candidate(&attr, true))
		return -1;
	if (!attr.candidate.parsed)
		return 1;
	*cand = attr.candidate.cand_parsed;

	return 0;
}


static bool parse_attribute_fingerprint(struct sdp_attribute *output) {
	unsigned char *c;
	int i;

	output->attr = ATTR_FINGERPRINT;

	PARSE_INIT;
	EXTRACT_TOKEN(fingerprint.hash_func_str);
	EXTRACT_TOKEN(fingerprint.fingerprint_str);

	output->fingerprint.hash_func = dtls_find_hash_func(&output->fingerprint.hash_func_str);
	if (!output->fingerprint.hash_func)
		return false;

	assert(sizeof(output->fingerprint.fingerprint) >= output->fingerprint.hash_func->num_bytes);

	c = (unsigned char *) output->fingerprint.fingerprint_str.s;
	for (i = 0; i < output->fingerprint.hash_func->num_bytes; i++) {
		if (c[0] >= '0' && c[0] <= '9')
			output->fingerprint.fingerprint[i] = c[0] - '0';
		else if (c[0] >= 'a' && c[0] <= 'f')
			output->fingerprint.fingerprint[i] = c[0] - 'a' + 10;
		else if (c[0] >= 'A' && c[0] <= 'F')
			output->fingerprint.fingerprint[i] = c[0] - 'A' + 10;
		else
			return false;

		output->fingerprint.fingerprint[i] <<= 4;

		if (c[1] >= '0' && c[1] <= '9')
			output->fingerprint.fingerprint[i] |= c[1] - '0';
		else if (c[1] >= 'a' && c[1] <= 'f')
			output->fingerprint.fingerprint[i] |= c[1] - 'a' + 10;
		else if (c[1] >= 'A' && c[1] <= 'F')
			output->fingerprint.fingerprint[i] |= c[1] - 'A' + 10;
		else
			return false;

		if (c[2] != ':')
			goto done;

		c += 3;
	}

	return false;

done:
	if (++i != output->fingerprint.hash_func->num_bytes)
		return false;

	return true;
}

static bool parse_attribute_setup(struct sdp_attribute *output) {
	output->attr = ATTR_SETUP;

	if (!str_cmp(&output->strs.value, "actpass"))
		output->setup.value = SETUP_ACTPASS;
	else if (!str_cmp(&output->strs.value, "active"))
		output->setup.value = SETUP_ACTIVE;
	else if (!str_cmp(&output->strs.value, "passive"))
		output->setup.value = SETUP_PASSIVE;
	else if (!str_cmp(&output->strs.value, "holdconn"))
		output->setup.value = SETUP_HOLDCONN;

	return true;
}

static bool parse_attribute_rtcp_fb(struct sdp_attribute *output) {
	struct attribute_rtcp_fb *a;

	output->attr = ATTR_RTCP_FB;
	a = &output->rtcp_fb;

	PARSE_INIT;
	EXTRACT_TOKEN(rtcp_fb.payload_type_str);
	a->value = *value_str;

	if (!str_cmp(&a->payload_type_str, "*"))
		a->payload_type = -1;
	else {
		a->payload_type = str_to_i(&a->payload_type_str, -1);
		if (a->payload_type == -1)
			return false;
	}

	return true;
}

static bool parse_attribute_rtpmap(struct sdp_attribute *output) {
	char *ep;
	struct attribute_rtpmap *a;
	rtp_payload_type *pt;

	output->attr = ATTR_RTPMAP;

	PARSE_INIT;
	EXTRACT_TOKEN(rtpmap.payload_type_str);
	EXTRACT_TOKEN(rtpmap.encoding_str);

	a = &output->rtpmap;
	pt = &a->rtp_pt;

	pt->encoding_with_params = a->encoding_str;

	pt->payload_type = strtoul(a->payload_type_str.s, &ep, 10);
	if (ep == a->payload_type_str.s)
		return false;

	if (!str_chr_str(&a->clock_rate_str, &a->encoding_str, '/'))
		return false;

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
		return false;

	pt->clock_rate = strtoul(a->clock_rate_str.s, &ep, 10);
	if (ep && ep != a->clock_rate_str.s + a->clock_rate_str.len)
		return false;

	return true;
}

static bool parse_attribute_fmtp(struct sdp_attribute *output) {
	struct attribute_fmtp *a;

	output->attr = ATTR_FMTP;
	a = &output->fmtp;

	PARSE_INIT;
	EXTRACT_TOKEN(fmtp.payload_type_str);
	a->format_parms_str = *value_str;

	a->payload_type = str_to_i(&a->payload_type_str, -1);
	if (a->payload_type == -1)
		return false;

	return true;
}

static bool parse_attribute_int(struct sdp_attribute *output, enum attr_id attr_id, int defval) {
	output->attr = attr_id;
	output->i = str_to_i(&output->strs.value, defval);
	return true;
}

// XXX combine this with parse_attribute_setup ?
static bool parse_attribute_t38faxudpec(struct sdp_attribute *output) {
	output->attr = ATTR_T38FAXUDPEC;

	switch (__csh_lookup(&output->strs.value)) {
		case CSH_LOOKUP("t38UDPNoEC"):
			output->t38faxudpec.ec = EC_NONE;
			break;
		case CSH_LOOKUP("t38UDPRedundancy"):
			output->t38faxudpec.ec = EC_REDUNDANCY;
			break;
		case CSH_LOOKUP("t38UDPFEC"):
			output->t38faxudpec.ec = EC_FEC;
			break;
		default:
			output->t38faxudpec.ec = EC_UNKNOWN;
			break;
	}

	return true;
}

// XXX combine this with parse_attribute_setup ?
static bool parse_attribute_t38faxratemanagement(struct sdp_attribute *output) {
	output->attr = ATTR_T38FAXRATEMANAGEMENT;

	switch (__csh_lookup(&output->strs.value)) {
		case CSH_LOOKUP("localTFC"):
			output->t38faxratemanagement.rm = RM_LOCALTCF;
			break;
		case CSH_LOOKUP("transferredTCF"):
			output->t38faxratemanagement.rm = RM_TRANSFERREDTCF;
			break;
		default:
			output->t38faxratemanagement.rm = RM_UNKNOWN;
			break;
	}

	return true;
}

static bool parse_attribute_t38faxudpecdepth(struct sdp_attribute *output) {
	struct attribute_t38faxudpecdepth *a;

	output->attr = ATTR_T38FAXUDPECDEPTH;
	a = &output->t38faxudpecdepth;

	PARSE_INIT;
	EXTRACT_TOKEN(t38faxudpecdepth.minred_str);
	a->maxred_str = *value_str;

	a->minred = str_to_i(&a->minred_str, 0);
	a->maxred = str_to_i(&a->maxred_str, -1);

	return true;
}

static bool parse_attribute_extmap(struct sdp_attribute *output) {
	output->attr = ATTR_EXTMAP;

	PARSE_INIT;
	EXTRACT_TOKEN(extmap.id_str);
	EXTRACT_TOKEN(extmap.ext);

	output->extmap.id = str_to_i(&output->extmap.id_str, 0);
	// RFC 8285, valid range: 1-14, 15 reserved, 16-255, 256 appbits (not supported),
	// 256-4095 invalid, 4096-4351 remap (not supported)
	if (output->extmap.id <= 0 || output->extmap.id == 15 || output->extmap.id >= 256)
		return false;

	return true;
}


static bool parse_attribute(struct sdp_attribute *a) {
	a->strs.name = a->strs.line_value;
	if (str_chr_str(&a->strs.value, &a->strs.name, ':')) {
		a->strs.name.len -= a->strs.value.len;
		a->strs.value.s++;
		a->strs.value.len--;

		a->strs.key = a->strs.name;
		if (str_chr_str(&a->param, &a->strs.value, ' ')) {
			a->strs.key.len += 1 +
				(a->strs.value.len - a->param.len);

			a->param.s++;
			a->param.len--;

			if (!a->param.len)
				a->param.s = NULL;
		}
		else
			a->strs.key.len += 1 + a->strs.value.len;
	}

	bool ret = true;
	switch (__csh_lookup(&a->strs.name)) {
		case CSH_LOOKUP("mid"):
			a->attr = ATTR_MID;
			break;
		case CSH_LOOKUP("rtcp"):
			ret = parse_attribute_rtcp(a);
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
			ret = parse_attribute_extmap(a);
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
		case CSH_LOOKUP("tls-id"):
			a->attr = ATTR_TLS_ID;
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
		case CSH_LOOKUP("T38MaxBitRate"):
			a->attr = ATTR_T38MAXBITRATE;
			break;
		case CSH_LOOKUP("T38FaxMaxBuffer"):
			a->attr = ATTR_T38FAXMAXBUFFER;
			break;
		case CSH_LOOKUP("maxptime"):
			a->attr = ATTR_MAXPTIME;
			break;
		default:
			/* check moh-attr-name (can be a variable attribute value) */
			if (rtpe_config.moh_attr_name && !str_cmp(&a->strs.name, rtpe_config.moh_attr_name))
				a->attr = ATTR_MOH_ATTR_NAME;
	}

	return ret;
}

bool sdp_parse(str *body, sdp_sessions_q *sessions, const sdp_ng_flags *flags) {
	str b;
	struct sdp_session *session = NULL;
	struct sdp_media *media = NULL;
	const char *errstr;
	struct sdp_attributes *attrs;
	struct sdp_attribute *attr;
	int media_sdp_id = 0;

	b = *body;

	while (b.len >= 2) {
		if (!rtpe_config.reject_invalid_sdp) {
			if (b.s[0] == '\n' || b.s[0] == '\r') {
				body->len = b.s - body->s;
				break;
			}
		}

		char line_code = b.s[0];

		errstr = "Missing '=' sign";
		if (b.s[1] != '=')
			goto error;

		str full_line;
		str_token(&full_line, &b, '\n');
		if (full_line.s[full_line.len - 1] == '\r')
			full_line.len--;

		errstr = "SDP doesn't start with a session definition";
		if (!session && line_code != 'v') {
			if (!flags->fragment)
				goto error;
			else
				goto new_session; // allowed for trickle ICE SDP fragments
		}

		str value = full_line;
		str_shift(&value, 2); // removes `v=` etc

		full_line.len = b.s - full_line.s; // include \r\n

		switch (line_code) {
			case 'v':
				errstr = "Error in v= line";
				if (value.len != 1)
					goto error;
				if (value.s[0] != '0')
					goto error;

new_session:
				session = g_new0(__typeof(*session), 1);
				t_queue_init(&session->media_streams);
				attrs_init(&session->attributes);
				t_queue_push_tail(sessions, session);
				media = NULL;
				session->s = full_line;
				RESET_BANDWIDTH(session->bandwidth, -1);

				break;

			case 'o':
				errstr = "o= line found within media section";
				if (media)
					goto error;
				errstr = "Error parsing o= line";
				if (!parse_origin(&value, &session->origin))
					goto error;

				break;

			case 'm':
				media = g_new0(__typeof(*media), 1);
				media->session = session;
				attrs_init(&media->attributes);
				errstr = "Error parsing m= line";
				if (!parse_media(&value, media))
					goto error;
				t_queue_push_tail(&session->media_streams, media);
				media->s = full_line;
				RESET_BANDWIDTH(media->bandwidth, -1);
				media->media_sdp_id = media_sdp_id++;
				break;

			case 'c':
				errstr = "Error parsing c= line";
				if (!parse_connection(&value,
						media ? &media->connection : &session->connection))
					goto error;

				break;

			case 'a':
				attr = g_new0(__typeof(*attr), 1);

				attr->full_line = full_line;
				attr->strs.line_value = value;

				if (!parse_attribute(attr)) {
					attr_free(attr);
					break;
				}

				attrs = media ? &media->attributes : &session->attributes;
				attr_insert(attrs, attr);

				break;

			case 'b':
				/* RR:0 */
				if (value.len < 4)
					break;

				/* AS, RR, RS */
				struct session_bandwidth *bw = media ? &media->bandwidth : &session->bandwidth;
				if (!memcmp(value.s, "AS:", 3))
					bw->as = strtol((value.s + 3), NULL, 10);
				else if (!memcmp(value.s, "RR:", 3))
					bw->rr = strtol((value.s + 3), NULL, 10);
				else if (!memcmp(value.s, "RS:", 3))
					bw->rs = strtol((value.s + 3), NULL, 10);
				else if (!memcmp(value.s, "TIAS:", 5))
					bw->tias = strtol((value.s + 5), NULL, 10);
				/* CT has only session level */
				else if (!memcmp(value.s, "CT:", 3))
					bw->ct = strtol((value.s + 3), NULL, 10);
				break;

			case 's':
				errstr = "s= line found within media section";
				if (media)
					goto error;
				session->session_name = value;
				break;

			case 't':
				errstr = "t= line found within media section";
				if (media)
					goto error;
				session->session_timing = value;
				break;

			case 'i':
				*(media ? &media->information : &session->information) = value;
				break;

			case 'u':
				errstr = "u= line found within media section";
				if (media)
					goto error;
				session->uri = value;
				break;

			case 'e':
				errstr = "e= line found within media section";
				if (media)
					goto error;
				session->email = value;
				break;

			case 'p':
				errstr = "p= line found within media section";
				if (media)
					goto error;
				session->phone = value;
				break;

			case 'k':
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

		// XXX to be obsoleted
		str *adj_s = media ? &media->s : &session->s;
		adj_s->len = b.s - adj_s->s;
	}

	return true;

error:
	ilog(LOG_WARNING, "Error parsing SDP at offset %zu: %s", (size_t) (b.s - body->s), errstr);
	sdp_sessions_clear(sessions);
	return false;
}

static void attr_free(struct sdp_attribute *p) {
	g_free(p);
}
static void free_attributes(struct sdp_attributes *a) {
	/* g_hash_table_destroy(a->name_hash); */
	t_hash_table_destroy(a->id_hash);
	/* g_hash_table_destroy(a->name_lists_hash); */
	t_hash_table_destroy(a->id_lists_hash);
	t_queue_clear_full(&a->list, attr_free);
}
static void media_free(struct sdp_media *media) {
	free_attributes(&media->attributes);
	str_slice_q_clear_full(&media->format_list);
	g_free(media);
}
static void session_free(struct sdp_session *session) {
	t_queue_clear_full(&session->media_streams, media_free);
	free_attributes(&session->attributes);
	g_free(session);
}
void sdp_sessions_clear(sdp_sessions_q *sessions) {
	t_queue_clear_full(sessions, session_free);
}

static int fill_endpoint(struct endpoint *ep, const struct sdp_media *media, sdp_ng_flags *flags,
		struct network_address *address, long int port)
{
	struct sdp_session *session = media->session;

	if (!flags->trust_address) {
		if (is_addr_unspecified(&flags->parsed_received_from)) {
			if (!__parse_address(&flags->parsed_received_from, NULL, &flags->received_from_family,
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



static bool __rtp_payload_types(struct stream_params *sp, struct sdp_media *media)
{
	struct sdp_attribute *attr;

	if (!proto_is_rtp(sp->protocol))
		return true;

	/* first go through a=rtpmap and build a hash table of attrs */
	g_autoptr(GHashTable) ht_rtpmap = g_hash_table_new(g_direct_hash, g_direct_equal);
	attributes_q *q = attr_list_get_by_id(&media->attributes, ATTR_RTPMAP);
	for (__auto_type ql = q ? q->head : NULL; ql; ql = ql->next) {
		rtp_payload_type *pt;
		attr = ql->data;
		pt = &attr->rtpmap.rtp_pt;
		g_hash_table_insert(ht_rtpmap, GINT_TO_POINTER(pt->payload_type), pt);
	}
	// do the same for a=fmtp
	g_autoptr(GHashTable) ht_fmtp = g_hash_table_new(g_direct_hash, g_direct_equal);
	q = attr_list_get_by_id(&media->attributes, ATTR_FMTP);
	for (__auto_type ql = q ? q->head : NULL; ql; ql = ql->next) {
		attr = ql->data;
		g_hash_table_insert(ht_fmtp, GINT_TO_POINTER(attr->fmtp.payload_type),
				&attr->fmtp.format_parms_str);
	}
	// do the same for a=rtcp-fb
	g_autoptr(GHashTable) ht_rtcp_fb = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) g_queue_free);
	q = attr_list_get_by_id(&media->attributes, ATTR_RTCP_FB);
	for (__auto_type ql = q ? q->head : NULL; ql; ql = ql->next) {
		attr = ql->data;
		/* rtcp-fb attributes applied on all payload types, must be added via generic attributes */
		if (attr->rtcp_fb.payload_type == -1) {
			struct sdp_attr *ac = sdp_attr_dup(attr);
			t_queue_push_tail(&sp->generic_attributes, ac);
		}
		GQueue *rq = g_hash_table_lookup_queue_new(ht_rtcp_fb, GINT_TO_POINTER(attr->rtcp_fb.payload_type), NULL);
		g_queue_push_tail(rq, &attr->rtcp_fb.value);
	}

	/* then go through the format list and associate */
	for (__auto_type ql = media->format_list.head; ql; ql = ql->next) {
		char *ep;
		str *s;
		unsigned int i;
		rtp_payload_type *pt;
		const rtp_payload_type *ptl, *ptrfc;

		s = ql->data;
		i = (unsigned int) strtoul(s->s, &ep, 10);
		if (ep == s->s || i > 127)
			return false;

		/* first look in rtpmap for a match, then check RFC types,
		 * else fall back to an "unknown" type */
		ptrfc = rtp_get_rfc_payload_type(i);
		ptl = g_hash_table_lookup(ht_rtpmap, GINT_TO_POINTER(i));

		pt = memory_arena_alloc0(rtp_payload_type);
		if (ptl)
			*pt = *ptl;
		else if (ptrfc)
			*pt = *ptrfc;
		else
			pt->payload_type = i;

		s = g_hash_table_lookup(ht_fmtp, GINT_TO_POINTER(i));
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

	return true;
}

static void __sdp_ice(struct stream_params *sp, struct sdp_media *media) {
	struct sdp_attribute *attr;
	struct attribute_candidate *ac;
	struct ice_candidate *cand;
	bool end_of_candidates = (attr_get_by_id_m_s(media, ATTR_END_OF_CANDIDATES));

	attr = attr_get_by_id_m_s(media, ATTR_ICE_UFRAG);
	if (!attr)
		return;
	sp->ice_ufrag = attr->strs.value;

	SP_SET(sp, ICE);

	attributes_q *q = attr_list_get_by_id(&media->attributes, ATTR_CANDIDATE);
	if (!q)
		goto no_cand;

	for (__auto_type ql = q->head; ql; ql = ql->next) {
		attr = ql->data;
		ac = &attr->candidate;
		if (!ac->parsed)
			continue;
		cand = g_new(__typeof(*cand), 1);
		*cand = ac->cand_parsed;
		t_queue_push_tail(&sp->ice_candidates, cand);
	}

no_cand:
	if ((attr = attr_get_by_id_m_s(media, ATTR_ICE_OPTIONS))) {
		if (str_str(&attr->strs.value, "trickle") >= 0)
			SP_SET(sp, TRICKLE_ICE);
	}
	else if (is_trickle_ice_address(&sp->rtp_endpoint))
		SP_SET(sp, TRICKLE_ICE);

	/* set end_of_candidates flag both, when it's trickle ice or not */
	if (end_of_candidates)
		SP_SET(sp, END_OF_CANDIDATES);
	/* unset end_of_candidates flag, if it's non trickle and no attribute given */
	if (!SP_ISSET(sp, TRICKLE_ICE) && !end_of_candidates)
		SP_CLEAR(sp, END_OF_CANDIDATES);

	if (attr_get_by_id_m_s(media, ATTR_ICE_LITE))
		SP_SET(sp, ICE_LITE_PEER);

	attr = attr_get_by_id_m_s(media, ATTR_ICE_PWD);
	if (attr)
		sp->ice_pwd = attr->strs.value;
}

static void __sdp_t38(struct stream_params *sp, struct sdp_media *media) {
	struct sdp_attribute *attr;
	struct t38_options *to = &sp->t38_options;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXVERSION);
	if (attr)
		to->version = attr->i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXUDPEC);
	if (attr) {
		if (attr->t38faxudpec.ec == EC_REDUNDANCY)
			to->max_ec_entries = to->min_ec_entries = 3; // defaults
		else if (attr->t38faxudpec.ec == EC_FEC) {
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
		to->min_ec_entries = attr->t38faxudpecdepth.minred;
		to->max_ec_entries = attr->t38faxudpecdepth.maxred;
	}

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXUDPFECMAXSPAN);
	if (attr)
		to->fec_span = attr->i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXMAXDATAGRAM);
	if (attr)
		to->max_datagram = attr->i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXMAXIFP);
	if (attr)
		to->max_ifp = attr->i;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXFILLBITREMOVAL);
	if (attr && (!attr->strs.value.len || str_cmp(&attr->strs.value, "0")))
		to->fill_bit_removal = 1;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXTRANSCODINGMMR);
	if (attr && (!attr->strs.value.len || str_cmp(&attr->strs.value, "0")))
		to->transcoding_mmr = 1;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXTRANSCODINGJBIG);
	if (attr && (!attr->strs.value.len || str_cmp(&attr->strs.value, "0")))
		to->transcoding_jbig = 1;

	attr = attr_get_by_id(&media->attributes, ATTR_T38FAXRATEMANAGEMENT);
	if (attr)
		to->local_tcf = (attr->t38faxratemanagement.rm == RM_LOCALTCF) ? 1 : 0;
}


static void sp_free(struct stream_params *s) {
	codec_store_cleanup(&s->codecs);
	ice_candidates_free(&s->ice_candidates);
	crypto_params_sdes_queue_clear(&s->sdes_params);
	t_queue_clear_full(&s->generic_attributes, sdp_attr_free);
	t_queue_clear_full(&s->all_attributes, sdp_attr_free);
	t_queue_clear_full(&s->extmap, rtp_extension_free);
	g_free(s);
}


// Check the list for a legacy non-RFC OSRTP offer:
// Given m= lines must be alternating between one RTP and one SRTP m= line, with matching
// types between each pair.
// If found, rewrite the list to pretend that only the SRTP m=line was given, and mark
// the session media accordingly.
// TODO: should be handled by monologue_offer_answer, without requiring OSRTP-accept to be
// set for re-invites. SDP rewriting and skipping media sections should be handled by
// associating offer/answer media sections directly with each other, instead of requiring
// the indexing to be in order and instead of requiring all sections between monologue and sdp_media
// lists to be matching.
// returns: discard this `sp` yes/no
static bool legacy_osrtp_accept(struct stream_params *sp, sdp_streams_q *streams,
		const sdp_ng_flags *flags, unsigned int *num)
{
	if (!streams->tail)
		return false;
	struct stream_params *last = streams->tail->data;

	if (!flags->osrtp_accept_legacy)
		return false;

	// protocols must be known
	if (!sp->protocol)
		return false;
	if (!last->protocol)
		return false;
	// types must match
	if (sp->type_id != last->type_id)
		return false;

	// we must be looking at RTP pairs
	if (!sp->protocol->rtp)
		return false;
	if (!last->protocol->rtp)
		return false;

	// see if this is SRTP and the previous was RTP
	if (sp->protocol->srtp && !last->protocol->srtp) {
		// is this a non-rejected SRTP section?
		if (sp->rtp_endpoint.port) {
			// looks ok. remove the previous one and only retain this one. mark it as such.
			t_queue_pop_tail(streams);
			sp_free(last);

			SP_SET(sp, LEGACY_OSRTP);
			sp->index--;
			(*num)--;
			return false;
		}

		// or is it a rejected SRTP with a non-rejected RTP counterpart?
		if (!sp->rtp_endpoint.port && last->rtp_endpoint.port) {
			// just throw the rejected SRTP section away
			sp_free(sp);
			return true;
		}
	}
	// or is it reversed? this being RTP and the previous was SRTP
	else if (!sp->protocol->srtp && last->protocol->srtp) {
		// if the SRTP one is not rejected, throw away the RTP one and mark the SRTP one
		if (last->rtp_endpoint.port) {
			SP_SET(last, LEGACY_OSRTP);
			SP_SET(last, LEGACY_OSRTP_REV);

			sp_free(sp);
			return true;
		}
	}

	return false;
}

static struct sdp_attr *sdp_attr_dup(const struct sdp_attribute *c) {
	struct sdp_attr *ac = g_new0(__typeof(*ac), 1);

	ac->strs.name = call_str_cpy(&c->strs.name);
	ac->strs.value = call_str_cpy(&c->strs.value);
	ac->other = c->other;
	ac->attr = c->attr;

	return ac;
}

void sdp_attr_free(struct sdp_attr *c) {
	g_free(c);
}

sdp_origin *sdp_orig_dup(const sdp_origin *orig) {
	sdp_origin *copy = g_new0(__typeof(*copy), 1);
	copy->username = call_str_cpy(&orig->username);
	copy->session_id = call_str_cpy(&orig->session_id);
	copy->version_str = call_str_cpy(&orig->version_str);
	copy->version_num = orig->version_num;
	copy->version_output_pos = orig->version_output_pos;
	copy->parsed = orig->parsed;
	/* struct network_address */
	copy->address.network_type = call_str_cpy(&orig->address.network_type);
	copy->address.address_type = call_str_cpy(&orig->address.address_type);
	copy->address.address = call_str_cpy(&orig->address.address);
	copy->address.parsed = orig->address.parsed;

	return copy;
}

void sdp_orig_free(sdp_origin *o) {
	g_free(o);
}

static void sdp_attr_append1(sdp_attr_q *dst, const struct sdp_attribute *attr) {
	if (!attr)
		return;
	struct sdp_attr *ac = sdp_attr_dup(attr);
	t_queue_push_tail(dst, ac);
}
// Duplicate all attributes from the source (parsed SDP attributes list) into
// the destination (string-format attribute list)
static void sdp_attr_append(sdp_attr_q *dst, attributes_q *attrs) {
	if (!attrs)
		return;
	for (__auto_type ll = attrs->head; ll; ll = ll->next)
		sdp_attr_append1(dst, ll->data);
}
// Duplicate all OTHER attributes from the source (parsed SDP attributes list) into
// the destination (string-format attribute list)
static void sdp_attr_append_other(sdp_attr_q *dst, struct sdp_attributes *src) {
	sdp_attr_append(dst, attr_list_get_by_id(src, ATTR_OTHER));
}

/* XXX split this function up */
bool sdp_streams(const sdp_sessions_q *sessions, sdp_streams_q *streams, sdp_ng_flags *flags) {
	struct sdp_session *session;
	struct sdp_media *media;
	struct stream_params *sp;
	const char *errstr;
	unsigned int num = 0;
	struct sdp_attribute *attr;

	for (auto_iter(l, sessions->head); l; l = l->next) {
		session = l->data;

		/* carry some of session level attributes for a later usage, using flags
		 * e.g. usage in `__call_monologue_init_from_flags()` or direct usage
		 * in `sdp_create()`
		 */
		sdp_attr_append_other(&flags->generic_attributes, &session->attributes);
		sdp_attr_append(&flags->all_attributes, &session->attributes.list);
		/* set only for the first SDP session, to be able to re-use versioning
		 *  for all the rest SDP sessions during replacements. See `sdp_version_check()` */
		if (!flags->session_sdp_orig.parsed)
			flags->session_sdp_orig = session->origin;
		flags->session_sdp_name = session->session_name;
		flags->session_bandwidth = session->bandwidth;
		flags->session_timing = session->session_timing;
		flags->session_information = session->information;
		flags->session_uri = session->uri;
		flags->session_email = session->email;
		flags->session_phone = session->phone;

		attr = attr_get_by_id(&session->attributes, ATTR_GROUP);
		if (attr)
			flags->session_group = attr->strs.value;

		if (rtpe_config.moh_prevent_double_hold) {
			attr = attr_get_by_id(&session->attributes, ATTR_MOH_ATTR_NAME);
			if (attr) {
				flags->moh_double_hold = 1;
				/* consider as generic, copy-paste into out SDP */
				sdp_attr_append1(&flags->generic_attributes, attr);
			}
		}

		for (__auto_type k = session->media_streams.head; k; k = k->next) {
			media = k->data;

			sp = g_new0(__typeof(*sp), 1);
			sp->index = ++num;
			codec_store_init(&sp->codecs, NULL);
			sp->media_sdp_id = media->media_sdp_id;

			errstr = "No address info found for stream";
			if (!flags->fragment
					&& fill_endpoint(&sp->rtp_endpoint, media, flags, NULL, media->port_num))
				goto error;

			__sdp_ice(sp, media);
			if (SP_ISSET(sp, ICE)) {
				// ignore "received from" (SIP-source-address) when ICE is in use
				flags->trust_address = 1;
			}

			/*
			 * pass important context parameters: sdp_media -> stream_params
			 */
			sp->consecutive_ports = media->port_count;
			sp->num_ports = sp->consecutive_ports * 2; // only do *=2 for RTP streams?
			sp->protocol_str = media->transport;
			sp->protocol = transport_protocol(&media->transport);
			sp->type = media->media_type_str;
			sp->type_id = media->media_type_id;
			memcpy(sp->direction, flags->direction, sizeof(sp->direction));
			bf_set_clear(&sp->sp_flags, SP_FLAG_ASYMMETRIC, flags->asymmetric);
			bf_set_clear(&sp->sp_flags, SP_FLAG_UNIDIRECTIONAL, flags->unidirectional);
			bf_set_clear(&sp->sp_flags, SP_FLAG_STRICT_SOURCE, flags->strict_source);
			bf_set_clear(&sp->sp_flags, SP_FLAG_MEDIA_HANDOVER, flags->media_handover);

			/* b= (bandwidth), is parsed in sdp_parse() */
			sp->media_session_bandiwdth = media->bandwidth;

			sp->sdp_information = media->information;

			// a=ptime
			attr = attr_get_by_id(&media->attributes, ATTR_PTIME);
			if (attr && attr->strs.value.s)
				sp->ptime = str_to_i(&attr->strs.value, 0);

			// a=maxptime
			attr = attr_get_by_id(&media->attributes, ATTR_MAXPTIME);
			if (attr && attr->strs.value.s)
				sp->maxptime = str_to_i(&attr->strs.value, 0);

			sp->format_str = media->formats;
			errstr = "Invalid RTP payload types";
			if (!__rtp_payload_types(sp, media))
				goto error;

			/* a=crypto */
			attributes_q *attrs = attr_list_get_by_id(&media->attributes, ATTR_CRYPTO);
			for (__auto_type ll = attrs ? attrs->head : NULL; ll; ll = ll->next) {
				attr = ll->data;
				struct crypto_params_sdes *cps = g_new0(__typeof(*cps), 1);
				t_queue_push_tail(&sp->sdes_params, cps);

				cps->params.crypto_suite = attr->crypto.crypto_suite;
				cps->params.mki_len = attr->crypto.mki_len;
				if (cps->params.mki_len) {
					cps->params.mki = malloc(cps->params.mki_len);
					memcpy(cps->params.mki, attr->crypto.mki, cps->params.mki_len);
				}
				cps->tag = attr->crypto.tag;
				assert(sizeof(cps->params.master_key) >= attr->crypto.master_key.len);
				assert(sizeof(cps->params.master_salt) >= attr->crypto.salt.len);
				memcpy(cps->params.master_key, attr->crypto.master_key.s,
						attr->crypto.master_key.len);
				memcpy(cps->params.master_salt, attr->crypto.salt.s,
						attr->crypto.salt.len);
				cps->params.session_params.unencrypted_srtp = attr->crypto.unencrypted_srtp;
				cps->params.session_params.unencrypted_srtcp = attr->crypto.unencrypted_srtcp;
				cps->params.session_params.unauthenticated_srtp = attr->crypto.unauthenticated_srtp;
			}

			sdp_attr_append_other(&sp->generic_attributes, &media->attributes);
			sdp_attr_append(&sp->all_attributes, &media->attributes.list);

			/* a=sendrecv/sendonly/recvonly/inactive */
			SP_SET(sp, SEND);
			SP_SET(sp, RECV);
			const struct sdp_attribute *sendonly = attr_get_by_id_m_s(media, ATTR_SENDONLY);
			const struct sdp_attribute *recvonly = attr_get_by_id_m_s(media, ATTR_RECVONLY);
			const struct sdp_attribute *inactive = attr_get_by_id_m_s(media, ATTR_INACTIVE);
			if (recvonly)
				SP_CLEAR(sp, SEND);
			else if (sendonly)
				SP_CLEAR(sp, RECV);
			else if (inactive)
			{
				SP_CLEAR(sp, RECV);
				SP_CLEAR(sp, SEND);
			}

			if (flags->original_sendrecv) {
				sdp_attr_append1(&sp->generic_attributes,
						attr_get_by_id_m_s(media, ATTR_SENDRECV));
				sdp_attr_append1(&sp->generic_attributes, sendonly);
				sdp_attr_append1(&sp->generic_attributes, recvonly);
				sdp_attr_append1(&sp->generic_attributes, inactive);
			}

			/* a=setup */
			attr = attr_get_by_id_m_s(media, ATTR_SETUP);
			if (attr) {
				if (attr->setup.value == SETUP_ACTPASS
						|| attr->setup.value == SETUP_ACTIVE)
					SP_SET(sp, SETUP_ACTIVE);
				if (attr->setup.value == SETUP_ACTPASS
						|| attr->setup.value == SETUP_PASSIVE)
					SP_SET(sp, SETUP_PASSIVE);
			}

			/* a=fingerprint */
			attr = attr_get_by_id_m_s(media, ATTR_FINGERPRINT);
			if (attr && attr->fingerprint.hash_func) {
				sp->fingerprint.hash_func = attr->fingerprint.hash_func;
				memcpy(sp->fingerprint.digest, attr->fingerprint.fingerprint,
						sp->fingerprint.hash_func->num_bytes);
				sp->fingerprint.digest_len = sp->fingerprint.hash_func->num_bytes;
			}

			// a=tls-id
			attr = attr_get_by_id_m_s(media, ATTR_TLS_ID);
			if (attr)
				sp->tls_id = attr->strs.value;

			// OSRTP (RFC 8643)
			if (sp->protocol && sp->protocol->rtp && !sp->protocol->srtp
					&& sp->protocol->osrtp_proto)
			{
				if (sp->fingerprint.hash_func || sp->sdes_params.length)
					sp->protocol = &transport_protocols[sp->protocol->osrtp_proto];
			}

			if (legacy_osrtp_accept(sp, streams, flags, &num))
				continue;

			// a=mid
			attr = attr_get_by_id(&media->attributes, ATTR_MID);
			if (attr)
				sp->media_id = attr->strs.value;

			// be ignorant about the contents
			if (attr_get_by_id(&media->attributes, ATTR_RTCP_FB))
				SP_SET(sp, RTCP_FB);

			__sdp_t38(sp, media);

			// a=extmap
			attrs = attr_list_get_by_id(&media->attributes, ATTR_EXTMAP);
			if (!attrs)
				attrs = attr_list_get_by_id(&session->attributes, ATTR_EXTMAP);
			for (__auto_type ll = attrs ? attrs->head : NULL; ll; ll = ll->next) {
				attr = ll->data;
				__auto_type ext = g_new0(struct rtp_extension, 1);
				ext->id = attr->extmap.id;
				ext->name = attr->extmap.ext;
				t_queue_push_tail(&sp->extmap, ext);
			}

			/* determine RTCP endpoint */

			if (attr_get_by_id(&media->attributes, ATTR_RTCP_MUX))
				SP_SET(sp, RTCP_MUX);

			attr = attr_get_by_id(&media->attributes, ATTR_RTCP);
			if (!attr || media->port_count != 1) {
				SP_SET(sp, IMPLICIT_RTCP);
				goto next;
			}
			if (attr->rtcp.port_num == sp->rtp_endpoint.port
					&& !is_trickle_ice_address(&sp->rtp_endpoint))
			{
				SP_SET(sp, RTCP_MUX);
				goto next;
			}
			errstr = "Invalid RTCP attribute";
			if (fill_endpoint(&sp->rtcp_endpoint, media, flags, &attr->rtcp.address,
						attr->rtcp.port_num))
				goto error;

next:
			t_queue_push_tail(streams, sp);
		}
	}

	return true;

error:
	ilog(LOG_WARNING, "Failed to extract streams from SDP: %s", errstr);
	g_free(sp);
	return false;
}

void sdp_streams_clear(sdp_streams_q *q) {
	t_queue_clear_full(q, sp_free);
}

static void print_format_str(GString *s, struct call_media *cm) {
	if (!cm->format_str.s)
		return;
	g_string_append_len(s, cm->format_str.s, cm->format_str.len);
	return;
}

static void print_codec_list(GString *s, struct call_media *media) {
	if (!proto_is_rtp(media->protocol)) {
		print_format_str(s, media);
		return;
	}

	if (media->codecs.codec_prefs.length == 0) {
		// legacy protocol, usage error, or allow-no-codec-media set. Print something and bail
		g_string_append(s, "0");
		return;
	}

	for (__auto_type l = media->codecs.codec_prefs.head; l; l = l->next) {
		rtp_payload_type *pt = l->data;
		if (l != media->codecs.codec_prefs.head)
			g_string_append_c(s, ' ');
		g_string_append_printf(s, "%u", pt->payload_type);
	}
	return;
}

static void insert_codec_parameters(GString *s, struct call_media *cm,
		const sdp_ng_flags *flags)
{
	for (__auto_type l = cm->codecs.codec_prefs.head; l; l = l->next)
	{
		rtp_payload_type *pt = l->data;
		if (!pt->encoding_with_params.len)
			continue;

		/* rtpmap */
		append_int_tagged_attr_to_gstring(s, "rtpmap", pt->payload_type, &pt->encoding_with_params,
				flags, cm->type_id);

		/* fmtp */
		g_autoptr(GString) fmtp = NULL;
		if (pt->codec_def && pt->codec_def->format_print) {
			fmtp = pt->codec_def->format_print(pt); /* try appending list of parameters */
			if (fmtp && fmtp->len)
				append_int_tagged_attr_to_gstring(s, "fmtp", pt->payload_type,
						&STR_GS(fmtp), flags, cm->type_id);
		}
		if (!fmtp && pt->format_parameters.len)
			append_int_tagged_attr_to_gstring(s, "fmtp", pt->payload_type,
					&pt->format_parameters, flags, cm->type_id);

		/* rtcp-fb */
		for (GList *k = pt->rtcp_fb.head; k; k = k->next) {
			str *fb = k->data;
			append_int_tagged_attr_to_gstring(s, "rtcp-fb", pt->payload_type, fb,
					flags, cm->type_id);
		}
	}
}

void sdp_insert_media_attributes(GString *gs, struct call_media *media, struct call_media *source_media,
		const sdp_ng_flags *flags)
{
	// Look up the source media. We copy the source's attributes if there is only one source
	// media. Otherwise we skip this step.

	if (!source_media)
		return;
	for (__auto_type l = source_media->generic_attributes.head; l; l = l->next) {
		__auto_type s = l->data;
		append_gen_attr_to_gstring(gs, &s->strs.name, &s->strs.value, flags, source_media->type_id);
	}
}
void sdp_insert_monologue_attributes(GString *gs, struct call_monologue *ml, const sdp_ng_flags *flags) {
	// Look up the source monologue. This must be a single source monologue for all medias. If
	// there's a mismatch or multiple source monologues, we skip this step.

	struct call_monologue *source_ml = ml_medias_subscribed_to_single_ml(ml);
	if (!source_ml)
		return;

	for (__auto_type l = source_ml->generic_attributes.head; l; l = l->next) {
		__auto_type s = l->data;
		append_gen_attr_to_gstring(gs, &s->strs.name, &s->strs.value, flags, MT_UNKNOWN);
	}
}
void sdp_insert_all_attributes(GString *s, struct call_media *media, struct sdp_ng_flags *flags) {
	for (__auto_type l = media->all_attributes.head; l; l = l->next) {
		__auto_type a = l->data;
		// the one exception: skip this and then print it separately if it was present,
		// so that we can print our own candidates first
		if (a->attr == ATTR_END_OF_CANDIDATES)
			continue;
		append_gen_attr_to_gstring(s, &a->strs.name, &a->strs.value, flags, media->type_id);
	}
}

static void sdp_print_extmap(GString *s, struct call_media *source_media, const sdp_ng_flags *flags) {
	if (!source_media)
		return;

	for (__auto_type l = source_media->extmap.head; l; l = l->next) {
		__auto_type ext = l->data;
		sdp_append_attr(s, flags, source_media->type_id,
				"extmap", "%u " STR_FORMAT, ext->id, STR_FMT(&ext->name));
	}
}

static bool insert_ice_address(const struct sdp_state *state, stream_fd *sfd, const sdp_ng_flags *flags) {
	if (!is_addr_unspecified(&flags->media_address))
		sockaddr_print_gstring(state->s, &flags->media_address);
	else
		call_stream_address(state->s, sfd->stream, SAF_ICE, sfd->local_intf, false);
	g_string_append_printf(state->s, " %u", sfd->socket.local.port);
	return __attr_manip(state);
}

static int insert_raddr_rport(GString *s, stream_fd *sfd, const sdp_ng_flags *flags) {
	g_string_append(s, " raddr ");
	if (!is_addr_unspecified(&flags->media_address))
		sockaddr_print_gstring(s, &flags->media_address);
	else
		call_stream_address(s, sfd->stream, SAF_ICE, sfd->local_intf, false);
	g_string_append(s, " rport ");
	g_string_append_printf(s, "%u", sfd->socket.local.port);

	return 0;
}

static void new_priority(struct call_media *media, enum ice_candidate_type type, unsigned int *tprefp,
		unsigned int *lprefp)
{
	unsigned int lpref, tpref;
	uint32_t prio;

	lpref = 0;
	tpref = ice_type_preference(type);
	prio = ice_priority_pref(tpref, lpref, 1);

	candidate_q *cands = &media->ice_candidates;

	for (__auto_type l = cands->head; l; l = l->next) {
		__auto_type c = l->data;
		if (c->priority <= prio && c->type == type
				&& c->component_id == 1)
		{
			/* tpref should come out as 126 (if host) here, unless the client isn't following
			 * the RFC, in which case we must adapt */
			tpref = ice_type_pref_from_prio(c->priority);

			lpref = ice_local_pref_from_prio(c->priority);
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

	*tprefp = tpref;
	*lprefp = lpref;
}

static void insert_candidate(GString *s, stream_fd *sfd,
		unsigned int type_pref, unsigned int local_pref, enum ice_candidate_type type,
		const sdp_ng_flags *flags, struct call_media *media)
{
	unsigned long priority;
	struct packet_stream *ps = sfd->stream;
	const struct local_intf *ifa = sfd->local_intf;
	__auto_type state = __attr_begin(s, flags, (media ? media->type_id : MT_UNKNOWN));
	if (__attr_append(&state, "candidate"))
		return;
	g_string_append_c(s, ':');
	if (__attr_append_str(&state, &ifa->ice_foundation))
		return;

	if (local_pref == -1)
		local_pref = ifa->unique_id;

	priority = ice_priority_pref(type_pref, local_pref, ps->component);
	if (__attr_append_f(&state, " %u", ps->component))
		return;
	if (__attr_append(&state, " UDP"))
		return;
	if (__attr_append_f(&state, " %lu", priority))
		return;
	g_string_append_c(s, ' ');
	if (insert_ice_address(&state, sfd, flags))
		return;
	g_string_append(s, " typ ");
	g_string_append(s, ice_candidate_type_str(type));
	if (__attr_manip(&state))
		return;
	/* raddr and rport are required for non-host candidates: rfc5245 section-15.1 */
	if(type != ICT_HOST)
		insert_raddr_rport(s, sfd, flags);
	if (__attr_manip(&state))
		return;
	__attr_end(&state);
}

static void insert_sfd_candidates(GString *s, struct packet_stream *ps,
		unsigned int type_pref, unsigned int local_pref, enum ice_candidate_type type,
		const sdp_ng_flags *flags)
{
	for (__auto_type l = ps->sfds.head; l; l = l->next) {
		stream_fd *sfd = l->data;
		insert_candidate(s, sfd, type_pref, local_pref, type, flags, ps->media);

		if (local_pref != -1)
			local_pref++;
	}
}

static void insert_remote_candidates(GString *s, const sdp_ng_flags *flags, struct call_media *media, struct ice_agent *ag) {
	g_auto(candidate_q) rc = TYPED_GQUEUE_INIT;
	__auto_type state = __attr_begin(s, flags, media->type_id);
	if (__attr_append(&state, "remote-candidates"))
		return;
	g_string_append_c(s, ':');

	/* prepare remote-candidates */
	ice_remote_candidates(&rc, ag);
	for (__auto_type l = rc.head; l; l = l->next) {
		if (l != rc.head)
			g_string_append(s, " ");
		__auto_type cand = l->data;
		if (__attr_append_f(&state, "%lu %s %u", cand->component_id,
				sockaddr_print_buf(&cand->endpoint.address), cand->endpoint.port))
			return;
	}
	__attr_end(&state);
}

static void insert_candidates(GString *s, struct packet_stream *rtp, struct packet_stream *rtcp,
		const sdp_ng_flags *flags, struct call_media *source_media)
{
	const struct local_intf *ifa;
	struct call_media *media;
	struct ice_agent *ag;
	unsigned int type_pref, local_pref;
	enum ice_candidate_type cand_type;

	media = rtp->media;

	cand_type = ICT_HOST;
	if (flags->ice_option == ICE_FORCE_RELAY)
		cand_type = ICT_RELAY;
	if (MEDIA_ISSET(media, PASSTHRU) && source_media)
		new_priority(source_media, cand_type, &type_pref, &local_pref);
	else {
		type_pref = ice_type_preference(cand_type);
		local_pref = -1;
	}

	ag = media->ice_agent;

	if (ag && AGENT_ISSET(ag, COMPLETED)) {
		ifa = rtp->selected_sfd->local_intf;
		insert_candidate(s, rtp->selected_sfd, type_pref, ifa->unique_id, cand_type, flags, rtp->media);
		if (rtcp) /* rtcp-mux only possible in answer */
			insert_candidate(s, rtcp->selected_sfd, type_pref, ifa->unique_id, cand_type, flags,
					rtp->media);

		if (flags->opmode == OP_OFFER && AGENT_ISSET(ag, CONTROLLING))
			insert_remote_candidates(s, flags, rtp->media, ag);

		return;
	}

	insert_sfd_candidates(s, rtp, type_pref, local_pref, cand_type, flags);

	if (rtcp) /* rtcp-mux only possible in answer */
		insert_sfd_candidates(s, rtcp, type_pref, local_pref, cand_type, flags);
}

static void insert_setup(GString *out, struct call_media *media, const sdp_ng_flags *flags,
	bool add_default)
{
	str actpass_str = STR_NULL;
	if (MEDIA_ARESET2(media, SETUP_PASSIVE, SETUP_ACTIVE))
		actpass_str = STR("actpass");
	else if (MEDIA_ISSET(media, SETUP_PASSIVE))
		actpass_str = STR("passive");
	else if (MEDIA_ISSET(media, SETUP_ACTIVE))
		actpass_str = STR("active");
	else {
		if (!add_default)
			return;
		actpass_str = STR("holdconn");
	}

	append_attr_to_gstring(out, "setup", &actpass_str, flags, media->type_id);
}

static void insert_fingerprint(GString *s, struct call_media *media, const sdp_ng_flags *flags,
		const struct dtls_hash_func *hf, struct dtls_fingerprint *fp)
{
	/* prepare fingerprint */
	__auto_type state = __attr_begin(s, flags, media->type_id);
	if (__attr_append(&state, "fingerprint"))
		return;
	g_string_append_c(s, ':');
	if (__attr_append(&state, hf->name))
		return;
	g_string_append(s, " ");

	unsigned char *p = fp->digest;
	for (unsigned int i = 0; i < hf->num_bytes; i++)
		g_string_append_printf(s, "%02X:", *p++);
	g_string_truncate(s, s->len - 1);

	__attr_end(&state);
}

static void insert_tls_id(GString *s, struct call_media *media, const sdp_ng_flags *flags, struct dtls_connection *dtls) {
	/* prepare tls-id */
	__auto_type state = __attr_begin(s, flags, media->type_id);
	if (__attr_append(&state, "tls-id"))
		return;
	g_string_append_c(s, ':');

	unsigned char *p = dtls->tls_id;
	for (unsigned int i = 0; i < sizeof(dtls->tls_id); i++)
		g_string_append_printf(s, "%02x", *p++);

	__attr_end(&state);
}

static void insert_dtls(GString *s, struct call_media *media, struct dtls_connection *dtls,
		const sdp_ng_flags *flags)
{
	const struct dtls_hash_func *hf;
	call_t *call = media->call;

	if (!media->protocol || !media->protocol->srtp)
		return;
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

	/* a=setup: */
	insert_setup(s, media, flags, true);

	insert_fingerprint(s, media, flags, hf, fp);

	if (dtls)
		insert_tls_id(s, media, flags, dtls);
}

static void insert_crypto1(GString *s, struct call_media *media, struct crypto_params_sdes *cps,
		const sdp_ng_flags *flags)
{
	char b64_buf[((SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN) / 3 + 1) * 4 + 4];
	char *p;
	int state = 0, save = 0, i;
	unsigned long long ull;

	if (!cps->params.crypto_suite || !MEDIA_ISSET(media, SDES) || MEDIA_ISSET(media, PASSTHRU))
		return;

	__auto_type a_s = __attr_begin(s, flags, media->type_id);
	if (__attr_append(&a_s, "crypto"))
		return;
	if (__attr_append_f(&a_s, ":%u", cps->tag))
		return;
	g_string_append_c(s, ' ');
	if (__attr_append(&a_s, cps->params.crypto_suite->name))
		return;
	if (__attr_append(&a_s, " inline:"))
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

	if (__attr_append_str(&a_s, &STR_LEN(b64_buf, p - b64_buf)))
		return;

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

	__attr_end(&a_s);
}

static void insert_crypto(GString *s, struct call_media *media, const sdp_ng_flags *flags) {
	if (!media->protocol || !media->protocol->srtp)
		return;
	for (__auto_type l = media->sdes_out.head; l; l = l->next)
		insert_crypto1(s, media, l->data, flags);
}
static void insert_rtcp_attr(GString *s, struct packet_stream *ps, const sdp_ng_flags *flags,
		struct call_media *media)
{
	if (flags->no_rtcp_attr)
		return;
	__auto_type state = __attr_begin(s, flags, (media ? media->type_id : MT_UNKNOWN));
	if (__attr_append(&state, "rtcp"))
		return;
	g_string_append_c(s, ':');

	if (__attr_append_f(&state, "%u", ps->selected_sfd->socket.local.port))
		return;

	if (flags->full_rtcp_attr) {
		g_string_append(s, " IN ");
		if (!is_addr_unspecified(&flags->media_address))
			g_string_append_printf(s, "%s %s",
					flags->media_address.family->rfc_name,
					sockaddr_print_buf(&flags->media_address));
		else
			call_stream_address(s, ps, SAF_NG, NULL, false);
	}
	__attr_end(&state);
}

/**
 * Handle sdp version replacements.
 */
static void sdp_version_replace(GString *s, sdp_origin *src_orig, sdp_origin *other_orig)
{
	char version_str[64];
	snprintf(version_str, sizeof(version_str), "%llu", src_orig->version_num);
	size_t version_len = strlen(version_str);

	if (!other_orig)
		return;

	other_orig->version_num = src_orig->version_num;
	/* is our new value longer? */
	if (version_len > other_orig->version_str.len) {
		/* overwrite + insert */
		g_string_overwrite_len(s, other_orig->version_output_pos, version_str, other_orig->version_str.len);
		g_string_insert(s, other_orig->version_output_pos + other_orig->version_str.len, version_str + other_orig->version_str.len);
		other_orig->version_str.len = version_len;
	}
	else {
		/* overwrite + optional erase */
		g_string_overwrite(s, other_orig->version_output_pos, version_str);
		if (version_len < other_orig->version_str.len) {
			g_string_erase(s, other_orig->version_output_pos + version_len, other_orig->version_str.len - version_len);
			other_orig->version_str.len = version_len;
		}
	}
}

/**
 * SDP session version manipulations.
 */
static void sdp_version_check(GString *s, struct call_monologue *monologue,
		struct call_monologue *source_ml,
		bool force_increase)
{
	if (!monologue->session_last_sdp_orig)
		return;

	sdp_origin *origin = monologue->session_last_sdp_orig;
	sdp_origin *other_origin = NULL;

	if (source_ml && source_ml->session_sdp_orig)
		other_origin = source_ml->session_sdp_orig;

	/* We really expect only a single session here, but we treat all the same regardless,
	* and use the same version number on all of them */

	/* First update all versions to match our single version */
	sdp_version_replace(s, origin, other_origin);

	/* Now check if we need to change the version actually.
	 * The version change will be forced with the 'force_increase',
	 * and it gets incremented, regardless whether:
	 * - we have no previously stored SDP,
	 * - we have previous SDP and it's equal to the current one */
	if (!force_increase) {
		if (!monologue->last_out_sdp)
			goto dup;
		if (g_string_equal(monologue->last_out_sdp, s))
			return;
	}

	/* mismatch detected. increment version, update again, and store copy */
	origin->version_num++;
	sdp_version_replace(s, origin, other_origin);
	if (monologue->last_out_sdp)
		g_string_free(monologue->last_out_sdp, TRUE);
dup:
	monologue->last_out_sdp = g_string_new_len(s->str, s->len);
}

const char *sdp_get_sendrecv(struct call_media *media) {
	if (MEDIA_ARESET2(media, SEND, RECV))
		return "sendrecv";
	else if (MEDIA_ISSET(media, SEND))
		return "sendonly";
	else if (MEDIA_ISSET(media, RECV))
		return "recvonly";
	else
		return "inactive";
}

/* Appends attributes (`a=name:value`) to the output SDP */
static void append_str_attr_to_gstring(GString *s, const str *name, const str *value,
		const sdp_ng_flags *flags, enum media_type media_type)
{
	__auto_type state = __attr_begin(s, flags, media_type);
	if (__attr_append_str(&state, name))
		return;
	g_string_append_c(s, ':');
	if (__attr_append_str(&state, value))
		return;
	__attr_end(&state);
}

/* Appends attributes (`a=name`) to the output SDP */
static void append_null_str_attr_to_gstring(GString *s, const str *name,
		const sdp_ng_flags *flags, enum media_type media_type)
{
	__auto_type state = __attr_begin(s, flags, media_type);
	if (__attr_append_str(&state, name))
		return;
	__attr_end(&state);
}

/* Appends attributes (`a=name:something`) to the output SDP */
void append_v_str_attr_to_gstring(GString *s, const str *name, const sdp_ng_flags *flags,
		enum media_type media_type, const char *fmt, ...)
{
	__auto_type state = __attr_begin(s, flags, media_type);
	if (__attr_append_str(&state, name))
		return;
	g_string_append_c(s, ':');
	va_list ap;
	va_start(ap, fmt);
	bool ret = __attr_append_v(&state, fmt, ap);
	va_end(ap);
	if (ret)
		return;
	__attr_end(&state);
}

/* Appends attributes (`a=name:uint value`) to the output SDP */
static void append_int_tagged_str_attr_to_gstring(GString *s, const str *name, unsigned int tag, const str *value,
		const sdp_ng_flags *flags, enum media_type media_type)
{
	__auto_type state = __attr_begin(s, flags, media_type);
	if (__attr_append_str(&state, name))
		return;
	if (__attr_append_f(&state, ":%u", tag))
		return;
	g_string_append_c(s, ' ');
	if (__attr_append_str(&state, value))
		return;
	__attr_end(&state);
}

static struct packet_stream *print_rtcp(GString *s, struct call_media *media, packet_stream_list *rtp_ps_link,
		const sdp_ng_flags *flags)
{
	struct packet_stream *ps = rtp_ps_link->data;
	struct packet_stream *ps_rtcp = NULL;

	if (ps->rtcp_sibling) {
		ps_rtcp = ps->rtcp_sibling;
		__auto_type rtcp_ps_link = rtp_ps_link->next;
		if (!rtcp_ps_link)
			return NULL;
		assert(rtcp_ps_link->data == ps_rtcp);
	}

	if (proto_is_rtp(media->protocol)) {
		if (MEDIA_ISSET(media, RTCP_MUX) &&
					(flags->opmode == OP_ANSWER ||
						flags->opmode == OP_PUBLISH ||
						((flags->opmode == OP_OFFER || flags->opmode == OP_SUBSCRIBE_REQ) && flags->rtcp_mux_require) ||
						IS_OP_OTHER(flags->opmode)))
		{
			insert_rtcp_attr(s, ps, flags, media);
			append_null_attr_to_gstring(s, "rtcp-mux", flags, media->type_id);
			ps_rtcp = NULL;
		}
		else if (ps_rtcp && flags->ice_option != ICE_FORCE_RELAY) {
			insert_rtcp_attr(s, ps_rtcp, flags, media);

			if (MEDIA_ISSET(media, RTCP_MUX))
				append_null_attr_to_gstring(s, "rtcp-mux", flags, media->type_id);
		}
	}
	else
		ps_rtcp = NULL;

	return ps_rtcp;
}

static void sdp_out_print_line(GString *out, char letter, const str *value) {
	if (!value->len)
		return;

	g_string_append_c(out, letter);
	g_string_append_c(out, '=');
	g_string_append_len(out, value->s, value->len);
	g_string_append(out, "\r\n");
}

static void sdp_out_print_information(GString *out, const str *s) {
	sdp_out_print_line(out, 'i', s);
}

/* TODO: rework an appending of parameters in terms of sdp attribute manipulations */
__attribute__((nonnull(1, 2, 3, 6, 7, 8)))
static void print_sdp_media_section(GString *s, struct call_media *media,
		const endpoint_t *address, struct call_media *copy_media,
		struct call_media *source_media,
		struct packet_stream *rtp_ps,
		packet_stream_list *rtp_ps_link, sdp_ng_flags *flags)
{
	struct packet_stream *ps_rtcp = NULL;
	bool inactive_media = (!address->port || !rtp_ps->selected_sfd); /* audio is accepted? */

	if (copy_media) {
		/* just print out all original values and attributes */
		sdp_out_original_media_attributes(s, media, address, copy_media, rtp_ps, flags);
		return;
	}

	if (source_media)
		sdp_out_print_information(s, &source_media->sdp_information);

	/* add actual media connection
	 * print zeroed address for the non accepted media, see RFC 3264 */
	sdp_out_add_media_connection(s, media, rtp_ps, (inactive_media ? NULL : &address->address), flags);

	/* add per media bandwidth */
	sdp_out_add_media_bandwidth(s, source_media, flags);

	/* mid and label must be added even for inactive streams (see #1361 and #1362). */
	if (media->media_id.s)
		append_attr_to_gstring(s, "mid", &media->media_id, flags, media->type_id);
	if (media->label.len && flags->siprec)
		append_attr_to_gstring(s, "label", &media->label, flags, media->type_id);

	/* nothing more to be printed for inactive stream (non-accepted media session) */
	if (inactive_media)
		return;

	if (proto_is_rtp(media->protocol))
		insert_codec_parameters(s, media, flags);

	sdp_print_extmap(s, media, flags);

	/* all unknown type attributes will be added here */
	media->sdp_attr_print(s, media, source_media, flags);

	/* print sendrecv */
	if (!flags->original_sendrecv) {
		/* for MoH cases, check if it's been a faked sendrecv state,
		 * then for an originator reveal a real sendrecv state.
		 */
		if (flags->opmode == OP_ANSWER && (source_media && MEDIA_ISSET(source_media, FAKE_SENDRECV)))
		{
			/* answer must be recvonly (sendonly-to-recvonly) */
			if (MEDIA_ISSET(source_media, REAL_SENDONLY))
				append_null_attr_to_gstring(s, "recvonly", flags, media->type_id);
			/* answer must be inactive (inactive-to-inactive) */
			else
				append_null_attr_to_gstring(s, "inactive", flags, media->type_id);
			/* clear flags for this MoH offer/answer exchange, so that future exchanges are real */
			MEDIA_CLEAR(source_media, FAKE_SENDRECV);
			MEDIA_CLEAR(source_media, REAL_SENDONLY);
		} else {
			append_null_attr_to_gstring(s, sdp_get_sendrecv(media), flags,
					media->type_id);
		}
	}

	ps_rtcp = print_rtcp(s, media, rtp_ps_link, flags);

	if (proto_is_rtp(media->protocol)) {
		insert_crypto(s, media, flags);
		insert_dtls(s, media, dtls_ptr(rtp_ps->selected_sfd), flags);

		if (media->ptime)
			append_attr_int_to_gstring(s, "ptime", media->ptime, flags,
					media->type_id);
		if (media->maxptime)
			append_attr_int_to_gstring(s, "maxptime", media->maxptime, flags,
					media->type_id);
	}

	if (MEDIA_ISSET(media, ICE) && media->ice_agent) {
		append_attr_to_gstring(s, "ice-ufrag", &media->ice_agent->ufrag[1], flags,
				media->type_id);
		append_attr_to_gstring(s, "ice-pwd", &media->ice_agent->pwd[1], flags,
				media->type_id);
	}

	if (MEDIA_ISSET(media, TRICKLE_ICE) && media->ice_agent) {
		append_attr_to_gstring(s, "ice-options", &STR_CONST("trickle"), flags,
				media->type_id);
	}
	if (MEDIA_ISSET(media, ICE)) {
		insert_candidates(s, rtp_ps, ps_rtcp, flags, NULL);
	}

	if ((MEDIA_ISSET(media, TRICKLE_ICE) && media->ice_agent)) {
		append_null_attr_to_gstring(s, "end-of-candidates", flags, media->type_id);
	}

	return;
}

__attribute__((nonnull(1, 2, 4, 5)))
static void sdp_out_add_origin(GString *out, struct call_monologue *monologue,
		struct call_monologue *source_ml,
		struct packet_stream *first_ps, sdp_ng_flags *flags)
{
	__auto_type ml = source_ml;
	if (!ml)
		ml = monologue;

	/* orig username
	 * session_last_sdp_orig is stored on the other media always,
	 * so if origin is meant for the A media, then it is stored on the B one */
	str * orig_username = (monologue->session_last_sdp_orig &&
			(flags->replace_username || flags->replace_origin_full)) ?
			&monologue->session_last_sdp_orig->username : &ml->session_sdp_orig->username;

	/* orig session id */
	str * orig_session_id = (monologue->session_last_sdp_orig && flags->replace_origin_full) ?
			&monologue->session_last_sdp_orig->session_id : &ml->session_sdp_orig->session_id;

	/* orig session ver
	 * replacement is handled later in sdp_create() based on SDP changes */
	unsigned long long orig_session_version = ml->session_sdp_orig->version_num;
	/* record origin version position for replacements
	 * + 4 - means: `o=` + 2 spaces between username and version / version and id */
	ml->session_sdp_orig->version_output_pos = out->len + orig_username->len + orig_session_id->len + 4;

	/* orig IP family and address */
	str orig_address_type;
	str orig_address;
	if (!source_ml || flags->replace_origin || flags->replace_origin_full) {
		/* replacing flags or PUBLISH */
		orig_address_type = STR(first_ps->selected_sfd->local_intf->advertised_address.addr.family->rfc_name);
		orig_address = STR(sockaddr_print_buf(&first_ps->selected_sfd->local_intf->advertised_address.addr));
	} else {
		orig_address_type = ml->session_sdp_orig->address.address_type;
		orig_address = ml->session_sdp_orig->address.address;
	}

	/* print it to the output sdp */
	g_string_append_printf(out,
			"o="STR_FORMAT" "STR_FORMAT" %llu IN "STR_FORMAT" "STR_FORMAT"\r\n",
			STR_FMT(orig_username),
			STR_FMT(orig_session_id),
			orig_session_version,
			STR_FMT(&orig_address_type),
			STR_FMT(&orig_address));
}

__attribute__((nonnull(1, 2)))
static void sdp_out_add_session_name(GString *out, struct call_monologue *monologue,
		struct call_monologue *source_ml)
{
	g_string_append(out, "s=");

	/* PUBLISH exceptionally doesn't include sdp session name from SDP.
	 * The session name and other values should be copied only from a source SDP,
	 * if that is also a media source. For a publish request that's not the case. */

	if (source_ml)
	{
		/* if a session name was empty in the s= attr of the coming message,
		 * while processing this ml in `__call_monologue_init_from_flags()`,
		 * then just keep it empty. */
		if (source_ml->sdp_session_name.len)
			g_string_append_len(out, source_ml->sdp_session_name.s, source_ml->sdp_session_name.len);
	}
	else
		g_string_append(out, rtpe_config.software_id);

	g_string_append(out, "\r\n");
}

__attribute__((nonnull(1)))
static void sdp_out_add_timing(GString *out, struct call_monologue *monologue)
{
	/* sdp timing per session level */
	g_string_append(out, "t=");

	if (monologue && monologue->sdp_session_timing.len)
		g_string_append_len(out, monologue->sdp_session_timing.s, monologue->sdp_session_timing.len);
	else
		g_string_append(out, "0 0"); /* default */

	g_string_append(out, "\r\n");
}

__attribute__((nonnull(1, 2, 4, 5)))
static void sdp_out_add_other(GString *out, struct call_monologue *monologue,
		struct call_monologue *source_ml,
		struct call_media *media,
		sdp_ng_flags *flags)
{
	bool media_has_ice = MEDIA_ISSET(media, ICE);
	bool media_has_ice_lite_self = MEDIA_ISSET(media, ICE_LITE_SELF);

	/* add loop protectio if required */
	if (flags->loop_protect)
		append_attr_to_gstring(out, "rtpengine", &rtpe_instance_id, flags, media->type_id);
#ifdef WITH_TRANSCODING
	if (monologue->player && monologue->player->opts.moh && rtpe_config.moh_attr_name) {
		append_null_attr_to_gstring(out, rtpe_config.moh_attr_name, flags, media->type_id);
	}
#endif
	/* ice-lite */
	if (media_has_ice && media_has_ice_lite_self)
		append_null_attr_to_gstring(out, "ice-lite", flags, media->type_id);

	/* group */
	if (source_ml && source_ml->sdp_session_group.len && flags->ice_option == ICE_FORCE_RELAY)
		append_attr_to_gstring(out, "group", &source_ml->sdp_session_group, flags, media->type_id);

	/* carry other session level a= attributes to the outgoing SDP */
	monologue->sdp_attr_print(out, monologue, flags);

	/* ADD arbitrary SDP manipulations for a session sessions */
	struct sdp_manipulations *sdp_manipulations = sdp_manipulations_get_by_id(flags->sdp_manipulations, MT_UNKNOWN);
	sdp_manipulations_add(out, sdp_manipulations);
}

__attribute__((nonnull(1, 2)))
static void sdp_out_print_bandwidth(GString *out, const struct session_bandwidth *bw) {
	if (bw->as >= 0)
		g_string_append_printf(out, "b=AS:%ld\r\n", bw->as);
	if (bw->rr >= 0)
		g_string_append_printf(out, "b=RR:%ld\r\n", bw->rr);
	if (bw->rs >= 0)
		g_string_append_printf(out, "b=RS:%ld\r\n", bw->rs);
	if (bw->ct >= 0)
		g_string_append_printf(out, "b=CT:%ld\r\n", bw->ct);
	if (bw->tias >= 0)
		g_string_append_printf(out, "b=TIAS:%ld\r\n", bw->tias);
}

__attribute__((nonnull(1, 3)))
static void sdp_out_add_session_bandwidth(GString *out, struct call_monologue *monologue,
		sdp_ng_flags *flags)
{
	/* sdp bandwidth per session/media level
	* 0 value is supported (e.g. b=RR:0 and b=RS:0), to be able to disable rtcp */
	/* don't add session level bandwidth for subscribe requests */
	if (!monologue || flags->opmode == OP_SUBSCRIBE_REQ)
		return;
	sdp_out_print_bandwidth(out, &monologue->sdp_session_bandwidth);
}

__attribute__((nonnull(1, 3)))
static void sdp_out_add_media_bandwidth(GString *out,
		struct call_media *media, sdp_ng_flags *flags)
{
	if (!media)
		return;
	sdp_out_print_bandwidth(out, &media->sdp_media_bandwidth);
}

static void sdp_out_add_media_connection(GString *out, struct call_media *media,
		struct packet_stream *rtp_ps, const sockaddr_t *address, sdp_ng_flags *flags)
{
	if (!is_addr_unspecified(&flags->media_address))
		address = &flags->media_address;

	const char *media_conn_address = NULL;
	const char *media_conn_address_type = NULL;

	/* print zeroed address */
	if (!address || !address->family || (PS_ISSET(rtp_ps, ZERO_ADDR) && !MEDIA_ISSET(media, ICE))) {
		if (!address || !address->family) {
			const struct intf_address *ifa_addr;
			const struct local_intf *ifa;
			if (rtp_ps->selected_sfd)
				ifa = rtp_ps->selected_sfd->local_intf;
			else
				ifa = get_any_interface_address(rtp_ps->media->logical_intf, rtp_ps->media->desired_family);
			ifa_addr = &ifa->spec->local_address;
			media_conn_address_type = ifa_addr->addr.family->rfc_name;
			media_conn_address = ifa_addr->addr.family->unspec_string;
		}
		else {
			media_conn_address_type = address->family->rfc_name;
			media_conn_address = address->family->unspec_string;
		}
	}
	else {
		media_conn_address_type = address->family->rfc_name;
		media_conn_address = sockaddr_print_buf(address);
	}

	g_string_append_printf(out,
			"c=IN %s %s\r\n",
			media_conn_address_type,
			media_conn_address);
}

/**
 * Add OSRTP related media line.
 */
__attribute__((nonnull(1, 2, 3)))
static void sdp_out_add_osrtp_media(GString *out, struct call_media *media,
	const struct transport_protocol *prtp, const endpoint_t *address)
{
	g_string_append_printf(out, "m=" STR_FORMAT " %d %s ",
			STR_FMT(&media->type),
			address ? address->port : 0,
			prtp->name);

	/* print codecs and add newline  */
	print_codec_list(out, media);
	g_string_append_printf(out, "\r\n");
}

/**
 * Add media line.
 */
__attribute__((nonnull(1, 2)))
static bool sdp_out_add_media(GString *out, struct call_media *media,
		unsigned int port)
{
	if (media->protocol)
		g_string_append_printf(out, "m=" STR_FORMAT " %i %s ",
				STR_FMT(&media->type),
				port,
				media->protocol->name);
	else if (media->protocol_str.s)
		g_string_append_printf(out, "m=" STR_FORMAT " %i " STR_FORMAT " ",
				STR_FMT(&media->type),
				port,
				STR_FMT(&media->protocol_str));
	else
		return false;

	/* print codecs and add newline  */
	print_codec_list(out, media);
	g_string_append_printf(out, "\r\n");

	return true;
}

__attribute__((nonnull(1, 2, 4, 6, 7, 8)))
static void sdp_out_handle_osrtp1(GString *out, struct call_media *media,
		struct call_media *source_media,
		const endpoint_t *address, const struct transport_protocol *prtp,
		struct packet_stream *rtp_ps, packet_stream_list *rtp_ps_link,
		sdp_ng_flags *flags)
{
	if (!prtp)
		return;

	if (MEDIA_ISSET(media, LEGACY_OSRTP) && !MEDIA_ISSET(media, LEGACY_OSRTP_REV))
		/* generate rejected m= line for accepted legacy OSRTP */
		sdp_out_add_osrtp_media(out, media, prtp, NULL);
	else if(flags->osrtp_offer_legacy && (flags->opmode == OP_OFFER || flags->opmode == OP_SUBSCRIBE_REQ)) {
		const struct transport_protocol *proto = media->protocol;
		media->protocol = prtp;

		sdp_out_add_osrtp_media(out, media, prtp, address);
		/* print media level attributes */
		print_sdp_media_section(out, media, address, NULL, source_media, rtp_ps, rtp_ps_link, flags);

		media->protocol = proto;
	}
}

__attribute__((nonnull(1, 2)))
static void sdp_out_handle_osrtp2(GString *out, struct call_media *media,
		const struct transport_protocol *prtp)
{
	if (!prtp)
		return;

	if (MEDIA_ISSET(media, LEGACY_OSRTP) && MEDIA_ISSET(media, LEGACY_OSRTP_REV))
		/* generate rejected m= line for accepted legacy OSRTP */
		sdp_out_add_osrtp_media(out, media, prtp, 0);
}

/**
 * Adds original attributes into the media.
 */
__attribute__((nonnull(1, 2, 3, 5, 6)))
static void sdp_out_original_media_attributes(GString *out, struct call_media *media,
		const endpoint_t *address, struct call_media *source_media,
		struct packet_stream *rtp_ps, sdp_ng_flags *flags)
{
	sdp_out_print_information(out, &source_media->sdp_information);
	sdp_out_add_media_connection(out, media, rtp_ps, &address->address, flags);
	sdp_out_add_media_bandwidth(out, source_media, flags);
	sdp_insert_all_attributes(out, source_media, flags);
	if (MEDIA_ISSET(source_media, ICE)) {
		struct packet_stream *rtcp_ps = rtp_ps->rtcp_sibling;
		/* TODO: is this a better or worse test than used in print_rtcp() ? */
		if (rtcp_ps && (!rtcp_ps->selected_sfd || rtcp_ps->selected_sfd->socket.local.port == 0))
			rtcp_ps = NULL;
		insert_candidates(out, rtp_ps, rtcp_ps, flags, source_media);
		if (MEDIA_ISSET(source_media, END_OF_CANDIDATES))
			append_null_attr_to_gstring(out, "end-of-candidates", flags, media->type_id);
	}
}

/**
 * Should we just pass through the original SDP (mostly) unchanged,
 * then we need to look up the source media.
 */
__attribute__((nonnull(1, 3, 4, 5)))
static struct call_media *sdp_out_set_source_media_address(struct call_media *media,
		struct call_media *source_media,
		struct packet_stream *rtp_ps,
		struct sdp_ng_flags *flags,
		endpoint_t *sdp_address)
{
	/* the port and address that goes into the SDP also depends on this */
	if (rtp_ps->selected_sfd) {
		sdp_address->port = rtp_ps->selected_sfd->socket.local.port;
		sdp_address->address = rtp_ps->selected_sfd->local_intf->advertised_address.addr;
	}

	if (source_media) {
		/* cases with message, force relay and pass through */
		if (media->type_id == MT_MESSAGE || flags->ice_option == ICE_FORCE_RELAY || MEDIA_ISSET(media, PASSTHRU)) {
			if (source_media->streams.head) {
				__auto_type sub_ps = source_media->streams.head->data;
				*sdp_address = sub_ps->advertised_endpoint;
			}
			return source_media;
		}
		/* detect passthrough (cases where no RTP/SRTP spotted on both media sides).
		 * Doesn't require source_address to be changed to the original one (e.g. T.38 cases),
		 * since we still probably want to proxy media for them.
		 */
		else if (!proto_is_rtp(media->protocol) && !proto_is_rtp(source_media->protocol))
			return source_media;
	}

	// handle special case: allow-no-codec-media
	if (flags->allow_no_codec_media && media->codecs.codec_prefs.length == 0
			&& proto_is_rtp(media->protocol))
	{
		// convert to rejected/removed stream
		*sdp_address = (endpoint_t) {0};
	}

	return NULL;
}

/**
 * For the offer/answer model, SDP create will be triggered for the B monologue,
 * which likely has empty paramaters (such as sdp origin, session name etc.), hence
 * such parameters have to be taken from the A monologue (so from the subscription).
 *
 * For the rest of cases (publish, subscribe, janus etc.) this works as usual:
 * given monologue is a monologue which is being processed.
 */
__attribute__((nonnull(1, 2, 3)))
int sdp_create(str *out, struct call_monologue *monologue, sdp_ng_flags *flags)
{
	const char *err = NULL;
	GString *s = NULL;
	const struct transport_protocol *prtp;
	struct call_media *media = NULL;
	struct packet_stream *first_ps = NULL;

	err = "Need at least one media";
	if (!monologue->medias->len)
		goto err;

	/* look for the first usable (non-rejected, non-empty) media and ps,
	 * thereby to determine session-level attributes, if any */
	for (int i = 0; i < monologue->medias->len; i++) {
		media = monologue->medias->pdata[i];
		if (!media)
			continue;
		if (!media->streams.head)
			continue;
		first_ps = media->streams.head->data;
		if (!first_ps->selected_sfd)
			continue;
		break;
	}

	err = "No usable packet stream";
	if (!first_ps || !first_ps->selected_sfd)
		goto err;

	// consume SDP data from ...
	__auto_type ml_ms = call_ml_get_top_ms(monologue);
	__auto_type source_ml = ml_ms ? ml_ms->monologue : NULL;

	/* init new sdp */
	s = g_string_new("v=0\r\n");

	/* add origin including name and version */
	sdp_out_add_origin(s, monologue, source_ml, first_ps, flags);

	/* add an actual sdp session name */
	sdp_out_add_session_name(s, monologue, source_ml);

	/* don't set connection on the session level
	 * but instead per media, below */

	if (source_ml) {
		sdp_out_print_information(s, &source_ml->sdp_session_information);

		sdp_out_print_line(s, 'u', &source_ml->sdp_session_uri);
		sdp_out_print_line(s, 'e', &source_ml->sdp_session_email);
		sdp_out_print_line(s, 'p', &source_ml->sdp_session_phone);
	}

	/* add bandwidth control per session level */
	sdp_out_add_session_bandwidth(s, source_ml, flags);

	/* set timing to always be: 0 0 */
	sdp_out_add_timing(s, source_ml);

	/* add other session level attributes */
	sdp_out_add_other(s, monologue, source_ml, media, flags);

	/* print media sections */
	for (unsigned int i = 0; i < monologue->medias->len; i++)
	{
		media = monologue->medias->pdata[i];

		/* check call media existence */
		err = "Empty media stream";
		if (!media)
			continue;

		/* check streams existence */
		err = "Zero length media stream";
		if (!media->streams.length)
			goto err;

		__auto_type rtp_ps_link = media->streams.head;
		struct packet_stream *rtp_ps = rtp_ps_link->data;

		__auto_type media_ms = call_media_get_top_ms(media);
		__auto_type source_media = media_ms ? media_ms->media : NULL;

		endpoint_t sdp_address = {0};
		struct call_media *copy_media = sdp_out_set_source_media_address(media, source_media, 
				rtp_ps, flags,
				&sdp_address);
		unsigned int port = sdp_address.port;

		prtp = NULL;
		if (media->protocol && media->protocol->srtp)
			prtp = &transport_protocols[media->protocol->rtp_proto];

		/* handle first OSRTP part */
		sdp_out_handle_osrtp1(s, media, source_media, &sdp_address, prtp, rtp_ps, rtp_ps_link, flags);

		/* set: media type, port, protocol (e.g. RTP/SAVP) */
		err = "Unknown media protocol";
		if (!sdp_out_add_media(s, media, port))
			goto err;

		MEDIA_SET(media, PUBLIC);

		/* print media level attributes */
		print_sdp_media_section(s, media, &sdp_address, copy_media, source_media,
				rtp_ps, rtp_ps_link, flags);

		/* handle second OSRTP part */
		sdp_out_handle_osrtp2(s, media, prtp);

		/* ADD arbitrary SDP manipulations for audio/video media sessions */
		struct sdp_manipulations *sdp_manipulations = sdp_manipulations_get_by_id(flags->sdp_manipulations, media->type_id);
		sdp_manipulations_add(s, sdp_manipulations);
	}

	/* The SDP version gets increased in case:
	* - if replace_sdp_version (sdp-version) or replace_origin_full flag is set and SDP information has been updated, or
	* - if the force_inc_sdp_ver (force-increment-sdp-ver) flag is set additionally to replace_sdp_version,
	*    which forces version increase regardless changes in the SDP information.
	*/
	if (flags->force_inc_sdp_ver || flags->replace_sdp_version || flags->replace_origin_full)
		sdp_version_check(s, monologue, source_ml, !!flags->force_inc_sdp_ver);

	out->len = s->len;
	out->s = g_string_free(s, FALSE);
	return 0;
err:
	if (s)
		g_string_free(s, TRUE);
	ilog(LOG_ERR, "Failed to create SDP: %s", err);
	return -1;
}

int sdp_is_duplicate(sdp_sessions_q *sessions) {
	for (__auto_type l = sessions->head; l; l = l->next) {
		struct sdp_session *s = l->data;
		attributes_q *attr_list = attr_list_get_by_id(&s->attributes, ATTR_RTPENGINE);
		if (!attr_list)
			return 0;
		for (__auto_type ql = attr_list->head; ql; ql = ql->next) {
			struct sdp_attribute *attr = ql->data;
			if (!str_cmp_str(&attr->strs.value, &rtpe_instance_id))
				goto next;
		}
		return 0;
next:
		;
	}
	return 1;
}

void sdp_init(void) {
	rand_hex_str(rtpe_instance_id.s, rtpe_instance_id.len / 2);
}
