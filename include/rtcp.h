#ifndef _RTCP_H_
#define _RTCP_H_

#include "str.h"
#include "call.h"
#include "media_socket.h"
#include <glib.h>


struct crypto_context;
struct rtcp_packet;
struct ssrc_ctx;
struct rtcp_handler;


struct rtcp_parse_ctx {
	struct call *call;
	struct call_media *media;
	const struct timeval *received;
};


extern struct rtcp_handler *rtcp_transcode_handler;


int rtcp_avp2savp(str *, struct crypto_context *, struct ssrc_ctx *);
int rtcp_savp2avp(str *, struct crypto_context *, struct ssrc_ctx *);

int rtcp_payload(struct rtcp_packet **out, str *p, const str *s);

int rtcp_parse(GQueue *q, struct media_packet *);
void rtcp_list_free(GQueue *q);

rtcp_filter_func rtcp_avpf2avp_filter;

void rtcp_init(void);

#endif
