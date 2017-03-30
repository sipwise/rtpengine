#ifndef _RTCPLIB_H_
#define _RTCPLIB_H_

#include <glib.h>
#include "str.h"
#include "compat.h"


struct rtcp_header {
#if G_BYTE_ORDER == G_BIG_ENDIAN
	unsigned	    version:2;	/**< packet type            */
	unsigned	    p:1;	/**< padding flag           */
	unsigned	    count:5;	/**< varies by payload type */
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
	unsigned	    count:5;	/**< varies by payload type */
	unsigned	    p:1;	/**< padding flag           */
	unsigned	    version:2;	/**< packet type            */
#else
#error "byte order unknown"
#endif
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
