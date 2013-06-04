#include "sdp.h"

#include <glib.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <math.h>

#include "call.h"
#include "log.h"
#include "str.h"
#include "call.h"
#include "crypto.h"

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
	GHashTable *hash;
	GHashTable *lists_hash;
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
	/* incomplete */

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
	enum crypto_suite crypto_suite;
	str master_key;
	str salt;
	char key_salt_buf[30];
	unsigned long long lifetime;
	unsigned int mki,
		     mki_len;
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
		ATTR_CRYPTO,
	} attr;

	union {
		struct attribute_rtcp rtcp;
		struct attribute_candidate candidate;
		struct attribute_crypto crypto;
	} u;
};




static const char ice_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char ice_foundation[17];
static str ice_foundation_str;
static char ice_foundation_alt[17];
static str ice_foundation_str_alt;




/* hack hack */
static inline int inet_pton_str(int af, str *src, void *dst) {
	char *s = src->s;
	char p;
	int ret;
	p = s[src->len];
	s[src->len] = '\0';
	ret = inet_pton(af, src->s, dst);
	s[src->len] = p;
	return ret;
}

static int __parse_address(struct in6_addr *out, str *network_type, str *address_type, str *address) {
	struct in_addr in4;

	if (network_type) {
		if (network_type->len != 2)
			return -1;
		if (memcmp(network_type->s, "IN", 2)
				&& memcmp(network_type->s, "in", 2))
			return -1;
	}
	if (address_type->len != 3)
		return -1;
	if (!memcmp(address_type->s, "IP4", 3)
			|| !memcmp(address_type->s, "ip4", 3)) {
		if (inet_pton_str(AF_INET, address, &in4) != 1)
			return -1;
		in4_to_6(out, in4.s_addr);
	}
	else if (!memcmp(address_type->s, "IP6", 3)
			|| !memcmp(address_type->s, "ip6", 3)) {
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

static inline int extract_token(char **sp, char *end, str *out) {
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
	a->hash = g_hash_table_new(str_hash, str_equal);
	a->lists_hash = g_hash_table_new_full(str_hash, str_equal,
			NULL, (GDestroyNotify) g_queue_free);
}

static int parse_attribute_crypto(struct sdp_attribute *output) {
	char *start, *end;
	struct attribute_crypto *c;
	const struct crypto_suite_params *cs;
	int salt_key_len, enc_salt_key_len;
	int b64_state = 0;
	unsigned int b64_save = 0;
	gsize ret;
	str s;

	output->attr = ATTR_CRYPTO;

	start = output->value.s;
	end = start + output->value.len;

	EXTRACT_TOKEN(u.crypto.tag_str);
	EXTRACT_TOKEN(u.crypto.crypto_suite_str);
	EXTRACT_TOKEN(u.crypto.key_params_str);

	c = &output->u.crypto;

	c->crypto_suite = crypto_find_suite(&c->crypto_suite_str);
	if (c->crypto_suite == CS_UNKNOWN)
		return -1;
	cs = &crypto_suite_params[c->crypto_suite];
	/* assume everything is a multiple of 8 */
	salt_key_len = (cs->master_key_len + cs->master_salt_len) / 8;
	assert(sizeof(c->key_salt_buf) >= salt_key_len);
	enc_salt_key_len = ceil((double) salt_key_len * 4.0/3.0);

	if (c->key_params_str.len < 7 + enc_salt_key_len)
		return -1;
	if (strncasecmp(c->key_params_str.s, "inline:", 7))
		return -1;
	c->key_base64_str = c->key_params_str;
	str_shift(&c->key_base64_str, 7);
	ret = g_base64_decode_step(c->key_base64_str.s, enc_salt_key_len,
			(guchar *) c->key_salt_buf, &b64_state, &b64_save);
	if (ret != salt_key_len)
		return -1;

	c->master_key.s = c->key_salt_buf;
	c->master_key.len = cs->master_key_len / 8;
	c->salt.s = c->master_key.s + c->master_key.len;
	c->salt.len = cs->master_salt_len / 8;

	c->lifetime_str = c->key_params_str;
	str_shift(&c->lifetime_str, 7 + enc_salt_key_len);
	if (c->lifetime_str.len >= 2) {
		if (c->lifetime_str.s[0] != '|')
			return -1;
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
			if (!c->lifetime || c->lifetime > 64)
				return -1;
			c->lifetime = 1 << c->lifetime;
		}
		else
			c->lifetime = strtoull(c->lifetime_str.s, NULL, 10);

		if (!c->lifetime || c->lifetime > cs->srtp_lifetime || c->lifetime > cs->srtcp_lifetime)
			return -1;
	}

	if (c->mki_str.s) {
		str_chr_str(&s, &c->mki_str, ':');
		if (!s.s)
			return -1;
		c->mki = strtoul(c->mki_str.s, NULL, 10);
		c->mki_len = strtoul(s.s + 1, NULL, 10);
		if (!c->mki || !c->mki_len)
			return -1;
	}

	return 0;
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

	output->u.candidate.component = strtoul(output->u.candidate.component_str.s, &ep, 10);
	if (ep == output->u.candidate.component_str.s)
		return -1;
	output->u.candidate.priority = strtoul(output->u.candidate.priority_str.s, &ep, 10);
	if (ep == output->u.candidate.priority_str.s)
		return -1;

	output->u.candidate.parsed = 1;
	return 0;
}

static void parse_attribute(struct sdp_attribute *a) {
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

	/* XXX add error handling */
	switch (a->name.len) {
		case 4:
			if (!str_cmp(&a->name, "rtcp"))
				parse_attribute_rtcp(a);
			break;
		case 6:
			if (!str_cmp(&a->name, "crypto"))
				parse_attribute_crypto(a);
			break;
		case 7:
			if (!str_cmp(&a->name, "ice-pwd"))
				a->attr = ATTR_ICE;
			break;
		case 8:
			if (!str_cmp(&a->name, "ice-lite"))
				a->attr = ATTR_ICE;
			break;
		case 9:
			if (!str_cmp(&a->name, "candidate"))
				parse_attribute_candidate(a);
			else if (!str_cmp(&a->name, "ice-ufrag"))
				a->attr = ATTR_ICE;
			break;
		case 11:
			if (!str_cmp(&a->name, "ice-options"))
				a->attr = ATTR_ICE;
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

				parse_attribute(attr);

				attrs = media ? &media->attributes : &session->attributes;
				g_queue_push_tail(&attrs->list, attr);
				g_hash_table_insert(attrs->hash, &attr->name, attr);
				if (attr->key.s)
					g_hash_table_insert(attrs->hash, &attr->key, attr);

				attr_queue = g_hash_table_lookup(attrs->lists_hash, &attr->name);
				if (!attr_queue)
					g_hash_table_insert(attrs->lists_hash, &attr->name,
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
	mylog(LOG_WARNING, "Error parsing SDP at offset %li: %s", b - body->s, errstr);
	sdp_free(sessions);
	return -1;
}

static void free_attributes(struct sdp_attributes *a) {
	struct sdp_attribute *attr;

	g_hash_table_destroy(a->hash);
	g_hash_table_destroy(a->lists_hash);
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

static int fill_stream_address(struct stream_input *si, struct sdp_media *media, struct sdp_ng_flags *flags) {
	struct sdp_session *session = media->session;

	if (!flags->trust_address) {
		if (is_addr_unspecified(&flags->parsed_address)) {
			if (__parse_address(&si->stream.ip46, NULL, &flags->received_from_family,
						&flags->received_from_address))
				return -1;
		}
		si->stream.ip46 = flags->parsed_address;
	}
	else if (media->connection.parsed)
		si->stream.ip46 = media->connection.address.parsed;
	else if (session->connection.parsed)
		si->stream.ip46 = session->connection.address.parsed;
	else
		return -1;
	return 0;
}

static int fill_stream(struct stream_input *si, struct sdp_media *media, int offset, struct sdp_ng_flags *flags) {
	if (fill_stream_address(si, media, flags))
		return -1;

	/* we ignore the media type */
	si->stream.port = (media->port_num + (offset * 2)) & 0xffff;

	return 0;
}

static int fill_stream_rtcp(struct stream_input *si, struct sdp_media *media, int port, struct sdp_ng_flags *flags) {
	if (fill_stream_address(si, media, flags))
		return -1;
	si->stream.port = port;
	return 0;
}

int sdp_streams(const GQueue *sessions, GQueue *streams, GHashTable *streamhash, struct sdp_ng_flags *flags) {
	struct sdp_session *session;
	struct sdp_media *media;
	struct stream_input *si;
	GList *l, *k;
	const char *errstr;
	int i, num;
	str s;
	struct sdp_attribute *attr;
	enum transport_protocol tp;

	num = 0;
	for (l = sessions->head; l; l = l->next) {
		session = l->data;

		for (k = session->media_streams.head; k; k = k->next) {
			media = k->data;
			tp = transport_protocol(&media->transport);

			si = NULL;
			for (i = 0; i < media->port_count; i++) {
				si = g_slice_alloc0(sizeof(*si));

				errstr = "No address info found for stream";
				if (fill_stream(si, media, i, flags))
					goto error;

				if (i == 0 && g_hash_table_contains(streamhash, si)) {
					g_slice_free1(sizeof(*si), si);
					continue;
				}

				si->stream.num = ++num;
				si->consecutive_num = (i == 0) ? media->port_count : 1;
				si->stream.protocol = tp;

				g_hash_table_insert(streamhash, si, si);
				g_queue_push_tail(streams, si);
			}

			if (!si || media->port_count != 1)
				continue;
			str_init(&s, "rtcp"); /* XXX use the enum for hash instead? */
			attr = g_hash_table_lookup(media->attributes.hash, &s);
			if (!attr || !attr->u.rtcp.port_num)
				continue;
			if (attr->u.rtcp.port_num == si->stream.port + 1)
				continue;

			si->has_rtcp = 1;

			si = g_slice_alloc0(sizeof(*si));
			if (fill_stream_rtcp(si, media, attr->u.rtcp.port_num, flags))
				goto error;
			si->stream.num = ++num;
			si->consecutive_num = 1;
			si->is_rtcp = 1;
			si->stream.protocol = tp;

			g_hash_table_insert(streamhash, si, si);
			g_queue_push_tail(streams, si);
		}
	}

	return 0;

error:
	mylog(LOG_WARNING, "Failed to extract streams from SDP: %s", errstr);
	if (si)
		g_slice_free1(sizeof(*si), si);
	return -1;
}

struct sdp_chopper *sdp_chopper_new(str *input) {
	struct sdp_chopper *c = g_slice_alloc0(sizeof(*c));
	c->input = input;
	c->chunk = g_string_chunk_new(512);
	c->iov = g_array_new(0, 0, sizeof(struct iovec));
	return c;
}

static void chopper_append(struct sdp_chopper *c, const char *s, int len) {
	struct iovec *iov;

	g_array_set_size(c->iov, ++c->iov_num);
	iov = &g_array_index(c->iov, struct iovec, c->iov_num - 1);
	iov->iov_base = (void *) s;
	iov->iov_len = len;
	c->str_len += len;
}
static inline void chopper_append_c(struct sdp_chopper *c, const char *s) {
	chopper_append(c, s, strlen(s));
}
static inline void chopper_append_str(struct sdp_chopper *c, const str *s) {
	chopper_append(c, s->s, s->len);
}

static void chopper_append_dup(struct sdp_chopper *c, const char *s, int len) {
	return chopper_append(c, g_string_chunk_insert_len(c->chunk, s, len), len);
}

static void chopper_append_printf(struct sdp_chopper *c, const char *fmt, ...) __attribute__((format(printf,2,3)));

static void chopper_append_printf(struct sdp_chopper *c, const char *fmt, ...) {
	char buf[32];
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
		mylog(LOG_WARNING, "Malformed SDP, cannot rewrite");
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
		mylog(LOG_WARNING, "Malformed SDP, cannot rewrite");
		return -1;
	}
	chop->position += len;
	return 0;
}

static void fill_relays(struct streamrelay **rtp, struct streamrelay **rtcp, GList *m,
		int off, struct stream_input *sip)
{
	*rtp = &((struct callstream *) m->data)->peers[off].rtps[0];

	if (rtcp) {
		*rtcp = &((struct callstream *) m->data)->peers[off].rtps[1];
		if (sip && sip->has_rtcp && m->next)
			*rtcp = &((struct callstream *) m->next->data)->peers[off].rtps[0];
	}
}

static int replace_transport_protocol(struct sdp_chopper *chop,
		struct sdp_media *media, struct streamrelay *sr)
{
	str *tp = &media->transport;
	const char *new_tp = transport_protocol_strings[sr->peer.protocol];

	if (!new_tp)
		return 0; /* XXX correct? or give warning? */

	if (copy_up_to(chop, tp))
		return -1;
	chopper_append_c(chop, new_tp);
	if (skip_over(chop, tp))
		return -1;

	return 0;
}

static int replace_media_port(struct sdp_chopper *chop, struct sdp_media *media, struct streamrelay *sr) {
	str *port = &media->port;

	if (!media->port_num)
		return 0;

	if (copy_up_to(chop, port))
		return -1;

	chopper_append_printf(chop, "%hu", sr->fd.localport);

	if (skip_over(chop, port))
		return -1;

	return 0;
}

static int replace_consecutive_port_count(struct sdp_chopper *chop, struct sdp_media *media,
		struct streamrelay *rtp, GList *m, int off)
{
	int cons;
	struct streamrelay *sr;

	if (media->port_count == 1)
		return 0;

	for (cons = 1; cons < media->port_count; cons++) {
		m = m->next;
		if (!m)
			goto warn;
		fill_relays(&sr, NULL, m, off, NULL);
		if (sr->fd.localport != rtp->fd.localport + cons * 2) {
warn:
			mylog(LOG_WARN, "Failed to handle consecutive ports");
			break;
		}
	}

	chopper_append_printf(chop, "/%i", cons);

	return 0;
}

static int insert_ice_address(struct sdp_chopper *chop, struct streamrelay *sr) {
	char buf[64];
	int len;

	mutex_lock(&sr->up->up->lock);
	call_stream_address(buf, sr->up, SAF_ICE, &len);
	mutex_unlock(&sr->up->up->lock);
	chopper_append_dup(chop, buf, len);
	chopper_append_printf(chop, " %hu", sr->fd.localport);

	return 0;
}

static int insert_ice_address_alt(struct sdp_chopper *chop, struct streamrelay *sr) {
	char buf[64];
	int len;

	mutex_lock(&sr->up->up->lock);
	call_stream_address_alt(buf, sr->up, SAF_ICE, &len);
	mutex_unlock(&sr->up->up->lock);
	chopper_append_dup(chop, buf, len);
	chopper_append_printf(chop, " %hu", sr->fd.localport);

	return 0;
}

static int replace_network_address(struct sdp_chopper *chop, struct network_address *address,
		struct streamrelay *sr)
{
	char buf[64];
	int len;

	if (is_addr_unspecified(&address->parsed))
		return 0;

	if (copy_up_to(chop, &address->address_type))
		return -1;

	mutex_lock(&sr->up->up->lock);
	call_stream_address(buf, sr->up, SAF_NG, &len);
	mutex_unlock(&sr->up->up->lock);
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

static void random_string(char *buf, int len) {
	while (len--)
		*buf++ = ice_chars[random() % strlen(ice_chars)];
}

static void create_random_string(struct call *call, str *s, int len) {
	char buf[30];

	assert(len < sizeof(buf));
	if (s->s)
		return;

	random_string(buf, len);
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
			case ATTR_CANDIDATE:
				if (!flags->ice_remove && !flags->ice_force)
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

static int process_media_attributes(struct sdp_chopper *chop, struct sdp_attributes *attrs,
		struct sdp_ng_flags *flags)
{
	GList *l;
	struct sdp_attribute *attr;

	for (l = attrs->list.head; l; l = l->next) {
		attr = l->data;

		switch (attr->attr) {
			case ATTR_ICE:
			case ATTR_CANDIDATE:
				if (!flags->ice_remove && !flags->ice_force)
					break;
				goto strip;

			case ATTR_RTCP:
				goto strip;

			case ATTR_CRYPTO:
				switch (flags->transport_protocol) {
					case PROTO_RTP_AVP:
					case PROTO_RTP_AVPF:
						goto strip;
					default:
						break;
				}
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

static GList *find_stream_num(GList *m, int num) {
	/* XXX use a hash instead? must link input streams to output streams */
	while (m && ((struct callstream *) m->data)->num < num)
		m = m->next;
	while (m && ((struct callstream *) m->data)->num > num)
		m = m->prev;
	return m;
}

static int has_rtcp(struct sdp_media *media) {
	struct sdp_session *session = media->session;

	if ((media->rr == -1 ? session->rr : media->rr) != 0
			&& (media->rs == -1 ? session->rs : media->rs) != 0)
		return 1;
	return 0;
}

static unsigned long prio_calc(unsigned int pref) {
	return (1 << 24) * 126 + (1 << 8) * pref + 256 * 1;
}

static unsigned long new_priority(struct sdp_media *media) {
	str s;
	GQueue *cands;
	unsigned int pref;
	unsigned long prio;
	GList *l;
	struct attribute_candidate *c;

	pref = 65535;
	prio = prio_calc(pref);

	if (!media)
		goto out;

	str_init(&s, "candidate");
	cands = g_hash_table_lookup(media->attributes.lists_hash, &s);
	if (!cands)
		goto out;

	for (l = cands->head; l; l = l->next) {
		c = l->data;
		while (c->priority >= prio) {
			pref--;
			prio = prio_calc(pref);
		}
	}

out:
	return prio;
}

static void insert_candidates(struct sdp_chopper *chop, struct streamrelay *rtp, struct streamrelay *rtcp,
		unsigned long priority, struct sdp_media *media)
{
	chopper_append_c(chop, "a=candidate:");
	chopper_append_str(chop, &ice_foundation_str);
	chopper_append_printf(chop, " 1 UDP %lu ", priority);
	insert_ice_address(chop, rtp);
	chopper_append_c(chop, " typ host\r\n");

	if (has_rtcp(media)) {
		chopper_append_c(chop, "a=candidate:");
		chopper_append_str(chop, &ice_foundation_str);
		chopper_append_printf(chop, " 2 UDP %lu ", priority - 1);
		insert_ice_address(chop, rtcp);
		chopper_append_c(chop, " typ host\r\n");
	}

}

static void insert_candidates_alt(struct sdp_chopper *chop, struct streamrelay *rtp, struct streamrelay *rtcp,
		unsigned long priority, struct sdp_media *media)
{
	chopper_append_c(chop, "a=candidate:");
	chopper_append_str(chop, &ice_foundation_str_alt);
	chopper_append_printf(chop, " 1 UDP %lu ", priority);
	insert_ice_address_alt(chop, rtp);
	chopper_append_c(chop, " typ host\r\n");

	if (has_rtcp(media)) {
		chopper_append_c(chop, "a=candidate:");
		chopper_append_str(chop, &ice_foundation_str_alt);
		chopper_append_printf(chop, " 2 UDP %lu ", priority - 1);
		insert_ice_address_alt(chop, rtcp);
		chopper_append_c(chop, " typ host\r\n");
	}

}

static int has_ice(GQueue *sessions) {
	GList *l, *m;
	struct sdp_session *session;
	struct sdp_media *media;
	str s;

	str_init(&s, "ice-ufrag");

	for (l = sessions->head; l; l = l->next) {
		session = l->data;

		if (g_hash_table_lookup(session->attributes.hash, &s))
			return 1;

		for (m = session->media_streams.head; m; m = m->next) {
			media = m->data;

			if (g_hash_table_lookup(media->attributes.hash, &s))
				return 1;
		}
	}

	return 0;
}

int sdp_replace(struct sdp_chopper *chop, GQueue *sessions, struct call *call,
		enum call_opmode opmode, struct sdp_ng_flags *flags, GHashTable *streamhash)
{
	struct sdp_session *session;
	struct sdp_media *media;
	GList *l, *k, *m;
	int off, do_ice;
	struct stream_input si, *sip;
	struct streamrelay *rtp, *rtcp;
	unsigned long priority;

	off = opmode;
	m = call->callstreams->head;
	do_ice = (flags->ice_force || (!has_ice(sessions) && !flags->ice_remove)) ? 1 : 0;

	for (l = sessions->head; l; l = l->next) {
		session = l->data;

		fill_relays(&rtp, &rtcp, m, off, NULL);

		if (session->origin.parsed && flags->replace_origin) {
			if (replace_network_address(chop, &session->origin.address, rtp))
				goto error;
		}
		if (session->connection.parsed) {
			if (replace_network_address(chop, &session->connection.address, rtp))
				goto error;
		}

		if (process_session_attributes(chop, &session->attributes, flags))
			goto error;

		if (do_ice) {
			copy_up_to_end_of(chop, &session->s);
			chopper_append_c(chop, "a=ice-lite\r\n");
		}

		for (k = session->media_streams.head; k; k = k->next) {
			media = k->data;

			if (fill_stream(&si, media, 0, flags))
				goto error;

			sip = g_hash_table_lookup(streamhash, &si);
			if (!sip)
				goto error;
			m = find_stream_num(m, sip->stream.num);
			if (!m)
				goto error;
			fill_relays(&rtp, &rtcp, m, off, sip);

			rtp->peer.protocol = flags->transport_protocol;
			rtcp->peer.protocol = rtp->peer.protocol;

			if (replace_media_port(chop, media, rtp))
				goto error;
			if (replace_consecutive_port_count(chop, media, rtp, m, off))
				goto error;
			if (replace_transport_protocol(chop, media, rtp))
				goto error;

			if (media->connection.parsed && flags->replace_sess_conn) {
				if (replace_network_address(chop, &media->connection.address, rtp))
					goto error;
			}

			if (process_media_attributes(chop, &media->attributes, flags))
				goto error;

			copy_up_to_end_of(chop, &media->s);

			if (has_rtcp(media)) {
				chopper_append_c(chop, "a=rtcp:");
				chopper_append_printf(chop, "%hu", rtcp->fd.localport);
				chopper_append_c(chop, "\r\n");
			}

			if (do_ice) {
				mutex_lock(&rtp->up->up->lock);
				if (!rtp->up->ice_ufrag.s) {
					create_random_string(call, &rtp->up->ice_ufrag, 8);
					create_random_string(call, &rtp->up->ice_pwd, 28);
				}
				rtp->stun = 1;
				mutex_unlock(&rtp->up->up->lock);

				mutex_lock(&rtcp->up->up->lock);
				if (rtp->up != rtcp->up && !rtcp->up->ice_ufrag.s) {
					/* safe to read */
					rtcp->up->ice_ufrag = rtp->up->ice_ufrag;
					rtcp->up->ice_pwd = rtp->up->ice_pwd;
				}
				rtcp->stun = 1;
				mutex_unlock(&rtcp->up->up->lock);

				chopper_append_c(chop, "a=ice-ufrag:");
				chopper_append_str(chop, &rtp->up->ice_ufrag);
				chopper_append_c(chop, "\r\na=ice-pwd:");
				chopper_append_str(chop, &rtp->up->ice_pwd);
				chopper_append_c(chop, "\r\n");
			}

			if (!flags->ice_remove) {
				priority = new_priority(flags->ice_force ? NULL : media);

				insert_candidates(chop, rtp, rtcp, priority, media);

				if (callmaster_has_ipv6(rtp->up->up->call->callmaster)) {
					priority -= 256;
					insert_candidates_alt(chop, rtp, rtcp, priority, media);
				}
			}
		}
	}

	copy_remainder(chop);
	return 0;

error:
	mylog(LOG_ERROR, "Error rewriting SDP");
	return -1;
}

void sdp_init() {
	random_string(ice_foundation, sizeof(ice_foundation) - 1);
	ice_foundation_str.s = ice_foundation;
	ice_foundation_str.len = sizeof(ice_foundation) - 1;

	random_string(ice_foundation_alt, sizeof(ice_foundation_alt) - 1);
	ice_foundation_str_alt.s = ice_foundation_alt;
	ice_foundation_str_alt.len = sizeof(ice_foundation_alt) - 1;
}
