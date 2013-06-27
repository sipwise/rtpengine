#ifndef _RTCP_H_
#define _RTCP_H_

#include "str.h"


struct crypto_context;



struct rtcp_header {
	unsigned char v_p_x;
	unsigned char pt;
	u_int16_t length;
} __attribute__ ((packed));

struct rtcp_packet {
	struct rtcp_header header;
	u_int32_t ssrc;
} __attribute__ ((packed));



int rtcp_avpf2avp(str *);
int rtcp_avp2savp(str *, struct crypto_context *);
int rtcp_savp2avp(str *, struct crypto_context *);

int rtcp_demux_is_rtcp(const str *);



#endif
