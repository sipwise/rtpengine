#ifndef _RTCP_H_
#define _RTCP_H_

#include "str.h"
#include "call.h"
#include <glib.h>


struct crypto_context;



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
} __attribute__ ((packed)) pjmedia_rtcp_sr;


/**
 * RTCP receiver report.
 */
typedef struct pjmedia_rtcp_rr
{
	u_int32_t	    ssrc;	    /**< SSRC identification.		*/
#if G_BYTE_ORDER == G_BIG_ENDIAN
	u_int32_t	    fract_lost:8;   /**< Fraction lost.			*/
	u_int32_t	    total_lost_2:8; /**< Total lost, bit 16-23.		*/
	u_int32_t	    total_lost_1:8; /**< Total lost, bit 8-15.		*/
	u_int32_t	    total_lost_0:8; /**< Total lost, bit 0-7.		*/
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
	u_int32_t	    fract_lost:8;   /**< Fraction lost.			*/
	u_int32_t	    total_lost_2:8; /**< Total lost, bit 0-7.		*/
	u_int32_t	    total_lost_1:8; /**< Total lost, bit 8-15.		*/
	u_int32_t	    total_lost_0:8; /**< Total lost, bit 16-23.		*/
#else
#error "byte order unknown"
#endif
	u_int32_t	    last_seq;	    /**< Last sequence number.		*/
	u_int32_t	    jitter;	    /**< Jitter.			*/
	u_int32_t	    lsr;	    /**< Last SR.			*/
	u_int32_t	    dlsr;	    /**< Delay since last SR.		*/
} __attribute__ ((packed)) pjmedia_rtcp_rr;


typedef struct _rtcp_sdes_chunk
{
	uint32_t csrc;
} __attribute__ ((packed)) rtcp_sdes_chunk_t;

typedef struct _rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
} __attribute__ ((packed)) rtcp_sdes_item_t;


/**
 * RTCP common header.
 */
typedef struct pjmedia_rtcp_common
{
#if G_BYTE_ORDER == G_BIG_ENDIAN
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


int rtcp_avpf2avp(str *);
int rtcp_avp2savp(str *, struct crypto_context *);
int rtcp_savp2avp(str *, struct crypto_context *);

void parse_and_log_rtcp_report(struct stream_fd *sfd, const str *, const endpoint_t *, const struct timeval *);

#endif
