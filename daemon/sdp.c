#include <glib.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <arpa/inet.h>

#include "sdp.h"
#include "call.h"
#include "log.h"

struct string {
	const char *s;
	int len;
};

struct network_address {
	struct string network_type;
	struct string address_type;
	struct string address;
	struct in6_addr parsed;
};

struct sdp_origin {
	struct string username;
	struct string session_id;
	struct string version;
	struct network_address address;
	int parsed:1;
};

struct sdp_connection {
	struct network_address address;
	int parsed:1;
};

struct sdp_session {
	struct sdp_origin origin;
	struct sdp_connection connection;
	GQueue media_streams;
	GQueue attributes;
};

struct sdp_media {
	struct string media_type;
	struct string port;
	struct string transport;
	/* ... format list */

	long int port_num;
	int port_count;

	struct sdp_connection connection;
	GQueue attributes;
};




/* hack hack */
static inline int inet_pton_str(int af, struct string *src, void *dst) {
	char *s = (void *) src->s;
	char p;
	int ret;
	p = s[src->len];
	s[src->len] = '\0';
	ret = inet_pton(af, src->s, dst);
	s[src->len] = p;
	return ret;
}

static int parse_address(struct network_address *address) {
	struct in_addr in4;

	if (address->network_type.len != 2)
		return -1;
	if (memcmp(address->network_type.s, "IN", 2)
			&& memcmp(address->network_type.s, "in", 2))
		return -1;
	if (address->address_type.len != 3)
		return -1;
	if (!memcmp(address->address_type.s, "IP4", 3)
			|| !memcmp(address->address_type.s, "ip4", 3)) {
		if (inet_pton_str(AF_INET, &address->address, &in4) != 1)
			return -1;
		in4_to_6(&address->parsed, in4.s_addr);
	}
	else if (!memcmp(address->address_type.s, "IP6", 3)
			|| !memcmp(address->address_type.s, "ip6", 3)) {
		if (inet_pton_str(AF_INET6, &address->address, &address->parsed) != 1)
			return -1;
	}
	else
		return -1;

	return 0;
}

static inline int extract_token(const char **sp, const char *end, struct string *out) {
	const char *space;

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
	if (parse_address(&output->address)) return -1

static int parse_origin(const char *start, const char *end, struct sdp_origin *output) {
	if (output->parsed)
		return -1;

	EXTRACT_TOKEN(username);
	EXTRACT_TOKEN(session_id);
	EXTRACT_TOKEN(version);
	EXTRACT_NETWORK_ADDRESS(address);

	output->parsed = 1;
	return 0;
}

static int parse_connection(const char *start, const char *end, struct sdp_connection *output) {
	if (output->parsed)
		return -1;

	EXTRACT_NETWORK_ADDRESS(address);

	output->parsed = 1;
	return 0;
}

static int parse_media(const char *start, const char *end, struct sdp_media *output) {
	char *ep;

	EXTRACT_TOKEN(media_type);
	EXTRACT_TOKEN(port);
	EXTRACT_TOKEN(transport);

	output->port_num = strtol(output->port.s, &ep, 10);
	if (ep == output->port.s)
		return -1;
	if (output->port_num <= 0 || output->port_num > 0xffff)
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

int sdp_parse(const char *body, int len, GQueue *sessions) {
	const char *b, *end, *value, *line_end, *next_line;
	struct sdp_session *session = NULL;
	struct sdp_media *media = NULL;
	const char *errstr;
	struct string *attribute;

	b = body;
	end = body + len;

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
			if (next_line >= end)
				next_line = NULL;
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
				g_queue_init(&session->attributes);
				g_queue_push_tail(sessions, session);
				media = NULL;

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
				g_queue_init(&media->attributes);
				errstr = "Error parsing m= line";
				if (parse_media(value, line_end, media))
					goto error;
				g_queue_push_tail(&session->media_streams, media);
				break;

			case 'c':
				errstr = "Error parsing c= line";
				if (parse_connection(value, line_end,
						media ? &media->connection : &session->connection))
					goto error;

				break;

			case 'a':
				attribute = g_slice_alloc(sizeof(*attribute));
				attribute->s = value;
				attribute->len = line_end - value;
				g_queue_push_tail(media ? &media->attributes : &session->attributes,
					attribute);
				break;

			case 's':
			case 'i':
			case 'u':
			case 'e':
			case 'p':
			case 'b':
			case 't':
			case 'r':
			case 'z':
			case 'k':
				break;

			default:
				errstr = "Unknown SDP line type found";
				goto error;
		}

		b = next_line;
	}

	return 0;

error:
	mylog(LOG_WARNING, "Error parsing SDP at offset %li: %s", (b - body), errstr);
	sdp_free(sessions);
	return -1;
}

static void __free_attributes(GQueue *a) {
	struct string *str;
	while ((str = g_queue_pop_head(a))) {
		g_slice_free1(sizeof(*str), str);
	}
}

void sdp_free(GQueue *sessions) {
	struct sdp_session *session;
	struct sdp_media *media;

	while ((session = g_queue_pop_head(sessions))) {
		while ((media = g_queue_pop_head(&session->media_streams))) {
			__free_attributes(&media->attributes);
			g_slice_free1(sizeof(*media), media);
		}
		__free_attributes(&session->attributes);
		g_slice_free1(sizeof(*session), session);
	}
}
