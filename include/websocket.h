#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

#include <stdbool.h>

#include "str.h"

struct websocket_conn;
struct websocket_message;
enum lws_write_protocol;
struct janus_session;

typedef const char *(*websocket_message_func_t)(struct websocket_message *);


struct websocket_message {
	struct websocket_conn *wc;
	char *uri;
	enum {
		M_UNKNOWN = 0,
		M_WEBSOCKET,
		M_GET,
		M_POST,
		M_OPTIONS,
	} method;
	enum {
		CT_UNKNOWN = 0,
		CT_JSON,
		CT_NG,
		CT_TEXT,
	} content_type;
	GString *body;

	websocket_message_func_t func;
};


int websocket_init(void);
void websocket_start(void);
void websocket_stop(void);

// appends to output buffer without triggering a response
void websocket_queue_raw(struct websocket_conn *wc, const char *msg, size_t len);
// adds data to output buffer (can be null) and optionally triggers specified response
void websocket_write_raw(struct websocket_conn *wc, const char *msg, size_t len,
		enum lws_write_protocol protocol, bool done);
// adds data to output buffer (can be null) and triggers specified response: http or binary websocket
void websocket_write_http_len(struct websocket_conn *wc, const char *msg, size_t len, bool done);
void websocket_write_http(struct websocket_conn *wc, const char *msg, bool done);
void websocket_write_text(struct websocket_conn *wc, const char *msg, bool done);
void websocket_write_binary(struct websocket_conn *wc, const char *msg, size_t len, bool done);
// num bytes in output buffer
size_t websocket_queue_len(struct websocket_conn *wc);

// write HTTP response headers
void websocket_http_response(struct websocket_conn *wc, int status, const char *content_type,
		ssize_t content_length);

// mark a janus session as owned by this transport
void websocket_conn_add_session(struct websocket_conn *, struct janus_session *);

#endif
