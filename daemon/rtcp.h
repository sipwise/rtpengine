#ifndef _RTCP_H_
#define _RTCP_H_

#include "str.h"
#include "call.h"


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

/**
 * RTCP sender report.
 */
typedef struct pjmedia_rtcp_sr
{
    u_int32_t	    ntp_sec;	    /**< NTP time, seconds part.	*/
    u_int32_t	    ntp_frac;	    /**< NTP time, fractions part.	*/
    u_int32_t	    rtp_ts;	    /**< RTP timestamp.			*/
    u_int32_t	    sender_pcount;  /**< Sender packet cound.		*/
    u_int32_t	    sender_bcount;  /**< Sender octet/bytes count.	*/
} pjmedia_rtcp_sr;


/**
 * RTCP receiver report.
 */
typedef struct pjmedia_rtcp_rr
{
	u_int32_t	    ssrc;	    /**< SSRC identification.		*/
#if defined(PJ_IS_BIG_ENDIAN) && PJ_IS_BIG_ENDIAN!=0
	u_int32_t	    fract_lost:8;   /**< Fraction lost.			*/
	u_int32_t	    total_lost_2:8; /**< Total lost, bit 16-23.		*/
	u_int32_t	    total_lost_1:8; /**< Total lost, bit 8-15.		*/
	u_int32_t	    total_lost_0:8; /**< Total lost, bit 0-7.		*/
#else
	u_int32_t	    fract_lost:8;   /**< Fraction lost.			*/
	u_int32_t	    total_lost_2:8; /**< Total lost, bit 0-7.		*/
	u_int32_t	    total_lost_1:8; /**< Total lost, bit 8-15.		*/
	u_int32_t	    total_lost_0:8; /**< Total lost, bit 16-23.		*/
#endif
	u_int32_t	    last_seq;	    /**< Last sequence number.		*/
	u_int32_t	    jitter;	    /**< Jitter.			*/
	u_int32_t	    lsr;	    /**< Last SR.			*/
	u_int32_t	    dlsr;	    /**< Delay since last SR.		*/
} pjmedia_rtcp_rr;


/**
 * RTCP common header.
 */
typedef struct pjmedia_rtcp_common
{
#if defined(PJ_IS_BIG_ENDIAN) && PJ_IS_BIG_ENDIAN!=0
    unsigned	    version:2;	/**< packet type            */
    unsigned	    p:1;	/**< padding flag           */
    unsigned	    count:5;	/**< varies by payload type */
    unsigned	    pt:8;	/**< payload type           */
#else
    unsigned	    count:5;	/**< varies by payload type */
    unsigned	    p:1;	/**< padding flag           */
    unsigned	    version:2;	/**< packet type            */
    unsigned	    pt:8;	/**< payload type           */
#endif
    unsigned	    length:16;	/**< packet length          */
    u_int32_t	    ssrc;	/**< SSRC identification    */
} pjmedia_rtcp_common;

/**
 * This structure declares default RTCP packet (SR) that is sent by pjmedia.
 * Incoming RTCP packet may have different format, and must be parsed
 * manually by application.
 */
typedef struct pjmedia_rtcp_sr_pkt
{
    pjmedia_rtcp_common  common;	/**< Common header.	    */
    pjmedia_rtcp_sr	 sr;		/**< Sender report.	    */
    pjmedia_rtcp_rr	 rr;		/**< variable-length list   */
} pjmedia_rtcp_sr_pkt;

/**
 * This structure declares RTCP RR (Receiver Report) packet.
 */
typedef struct pjmedia_rtcp_rr_pkt
{
    pjmedia_rtcp_common  common;	/**< Common header.	    */
    pjmedia_rtcp_rr	 rr;		/**< variable-length list   */
} pjmedia_rtcp_rr_pkt;


int rtcp_avpf2avp(str *);
int rtcp_avp2savp(str *, struct crypto_context *);
int rtcp_savp2avp(str *, struct crypto_context *);

int rtcp_demux_is_rtcp(const str *);

void parse_and_log_rtcp_report(struct stream_fd *sfd, const str *, const endpoint_t *);

#endif
