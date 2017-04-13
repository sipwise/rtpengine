#ifndef _RTCP_H_
#define _RTCP_H_

#include "str.h"
#include "call.h"
#include <glib.h>


struct crypto_context;



int rtcp_avpf2avp(str *, struct stream_fd *sfd, const endpoint_t *, const struct timeval *);
int rtcp_avp2savp(str *, struct crypto_context *);
int rtcp_savp2avp(str *, struct crypto_context *);

//void parse_and_log_rtcp_report(struct stream_fd *sfd, const str *, const endpoint_t *, const struct timeval *);
void rtcp_parse(const str *, struct stream_fd *sfd, const endpoint_t *, const struct timeval *);

void rtcp_init();

#endif
