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
	} content_type;
	GString *body;

	websocket_message_func_t func;
};


int websocket_init(void);
void websocket_start(void);
void websocket_stop(void);

// adds data to output buffer (can be null) and triggers specified response: http or binary websocket
//void websocket_write_http_len(struct websocket_conn *wc, const char *msg, size_t len);
//void websocket_write_http(struct websocket_conn *wc, const char *msg);
void websocket_write_text(struct websocket_conn *wc, const char *msg);
//void websocket_write_binary(struct websocket_conn *wc, const char *msg, size_t len);

// single shot HTTP response
void websocket_http_complete(struct websocket_conn *wc, int status, const char *content_type,
		ssize_t content_length, const char *content);

// write HTTP response headers
void websocket_http_response(struct websocket_conn *wc, int status, const char *content_type,
		ssize_t content_length);

// mark a janus session as owned by this transport
void websocket_conn_add_session(struct websocket_conn *, struct janus_session *);

#endif
