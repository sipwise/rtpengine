#include <glib.h>

#include "sdp.h"
#include "call.h"
#include "log.h"

struct string {
	const char *s;
	int len;
};

struct sdp_origin {
	struct string username;
	struct string session_id;
	struct string version;
	struct string network_type;
	struct string address_type;
	struct string address;
	int parsed:1;
};

struct sdp_connection {
	struct string network_type;
	struct string address_type;
	struct string address;
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

	struct sdp_connection connection;
	GQueue attributes;
};




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

static int parse_origin(const char *start, const char *end, struct sdp_origin *output) {
	if (output->parsed)
		return -1;

	EXTRACT_TOKEN(username);
	EXTRACT_TOKEN(session_id);
	EXTRACT_TOKEN(version);
	EXTRACT_TOKEN(network_type);
	EXTRACT_TOKEN(address_type);
	EXTRACT_TOKEN(address);

	output->parsed = 1;
	return 0;
}

static int parse_connection(const char *start, const char *end, struct sdp_connection *output) {
	if (output->parsed)
		return -1;

	EXTRACT_TOKEN(network_type);
	EXTRACT_TOKEN(address_type);
	EXTRACT_TOKEN(address);

	output->parsed = 1;
	return 0;
}

static int parse_media(const char *start, const char *end, struct sdp_media *output) {
	EXTRACT_TOKEN(media_type);
	EXTRACT_TOKEN(port);
	EXTRACT_TOKEN(transport);

	return 0;
}

GQueue *sdp_parse(const char *body, int len, GQueue *streams) {
	const char *b, *end, *value, *line_end, *next_line;
	struct sdp_session *session = NULL;
	GQueue *sessions;
	struct sdp_media *media = NULL;
	const char *errstr;
	struct string *attribute;

	sessions = g_queue_new();
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

	return sessions;

error:
	mylog(LOG_WARNING, "Error parsing SDP: %s", errstr);
	/* XXX free sessions */
	return NULL;
}
