#ifndef _RTCP_H_
#define _RTCP_H_

#include <glib.h>

#include "str.h"
#include "call.h"
#include "media_socket.h"

struct crypto_context;
struct rtcp_packet;
struct rtcp_handler;
struct call_monologue;


extern struct rtcp_handler *rtcp_transcode_handler;
extern struct rtcp_handler *rtcp_sink_handler;


int rtcp_avp2savp(const struct rtcp_packet *, str *packet, str *payload, struct crypto_context *,
		struct ssrc_entry_call *);
int rtcp_savp2avp(const struct rtcp_packet *, str *packet, str *payload, struct crypto_context *,
		struct ssrc_entry_call *);

__attribute__((nonnull(2)))
struct rtcp_packet *rtcp_payload(str *p, const str *s);

int rtcp_parse(GQueue *q, struct media_packet *);
void rtcp_list_free(GQueue *q);
bool rtcp_kernel_fw(struct call_media *);

rtcp_filter_func rtcp_avpf2avp_filter;

void rtcp_init(void);


void rtcp_send_report(struct call_media *media, struct ssrc_entry_call *ssrc_out,
		const struct packet_stream *locked);

#endif
