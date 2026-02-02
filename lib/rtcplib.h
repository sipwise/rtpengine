#ifndef _RTCPLIB_H_
#define _RTCPLIB_H_

#include <glib.h>
#include "str.h"
#include "compat.h"


#define RTCP_PT_SR	200	/* sender report */
#define RTCP_PT_RR	201	/* receiver report */
#define RTCP_PT_SDES	202	/* source description */
#define RTCP_PT_BYE	203	/* bye */
#define RTCP_PT_APP	204	/* application specific */
#define RTCP_PT_RTPFB	205	/* transport layer feedback message (RTP/AVPF) */
#define RTCP_PT_PSFB	206	/* payload-specific feedback message (RTP/AVPF) */
#define RTCP_PT_XR   207


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
	uint16_t length;
} __attribute__ ((packed));

struct rtcp_packet {
	struct rtcp_header header;
	uint32_t ssrc;
} __attribute__ ((packed));


/* RFC 5761 section 4 */
INLINE bool rtcp_demux_is_rtcp(const str *s) {
	struct rtcp_packet *rtcp;

	if (s->len < sizeof(*rtcp))
		return false;

	rtcp = (void *) s->s;

	if (rtcp->header.pt < 194)
		return false;
	if (rtcp->header.pt > 223)
		return false;
	return true;
}

INLINE unsigned char rtcp_pt(const str *s) {
	struct rtcp_packet *rtcp = (void *) s->s;
	return rtcp->header.pt;
}

#endif
