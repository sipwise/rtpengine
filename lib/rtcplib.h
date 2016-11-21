#ifndef _RTCPLIB_H_
#define _RTCPLIB_H_

#include "str.h"
#include "compat.h"


struct rtcp_header {
	unsigned char v_p_x;
	unsigned char pt;
	u_int16_t length;
} __attribute__ ((packed));

struct rtcp_packet {
	struct rtcp_header header;
	u_int32_t ssrc;
} __attribute__ ((packed));


/* RFC 5761 section 4 */
INLINE int rtcp_demux_is_rtcp(const str *s) {
	struct rtcp_packet *rtcp;

	if (s->len < sizeof(*rtcp))
		return 0;

	rtcp = (void *) s->s;

	if (rtcp->header.pt < 194)
		return 0;
	if (rtcp->header.pt > 223)
		return 0;
	return 1;
}



#endif
