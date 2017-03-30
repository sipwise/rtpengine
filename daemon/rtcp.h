#ifndef _RTCP_H_
#define _RTCP_H_

#include "str.h"
#include "call.h"
#include <glib.h>


struct crypto_context;



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


int rtcp_avpf2avp(str *, struct stream_fd *sfd, const endpoint_t *, const struct timeval *);
int rtcp_avp2savp(str *, struct crypto_context *);
int rtcp_savp2avp(str *, struct crypto_context *);

//void parse_and_log_rtcp_report(struct stream_fd *sfd, const str *, const endpoint_t *, const struct timeval *);
void rtcp_parse(const str *, struct stream_fd *sfd, const endpoint_t *, const struct timeval *);

void rtcp_init();

#endif
