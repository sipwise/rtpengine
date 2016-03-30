/*
 * rtcp_xr.h
 *
 *  Created on: Mar 29, 2015
 *      Author: fmetz
 */

#ifndef RTCP_XR_H_
#define RTCP_XR_H_

#include <stdint.h>
#include <sys/types.h>
#include <glib.h>

#include "str.h"
#include "rtcp.h"

/**
 * @defgroup PJMED_RTCP_XR RTCP Extended Report (XR) - RFC 3611
 * @ingroup PJMEDIA_SESSION
 * @brief RTCP XR extension to RTCP session
 * @{
 *
 * PJMEDIA implements subsets of RTCP XR specification (RFC 3611) to monitor
 * the quality of the real-time media (audio/video) transmission.
 */

/**
 * Enumeration of report types of RTCP XR. Useful for user to enable varying
 * combinations of RTCP XR report blocks.
 */
typedef enum {
    PJMEDIA_RTCP_XR_LOSS_RLE	    = (1 << 0),
    PJMEDIA_RTCP_XR_DUP_RLE	    = (1 << 1),
    PJMEDIA_RTCP_XR_RCPT_TIMES	    = (1 << 2),
    PJMEDIA_RTCP_XR_RR_TIME	    = (1 << 3),
    PJMEDIA_RTCP_XR_DLRR	    = (1 << 4),
    PJMEDIA_RTCP_XR_STATS	    = (1 << 5),
    PJMEDIA_RTCP_XR_VOIP_METRICS    = (1 << 6)
} pjmedia_rtcp_xr_type;

/**
 * Enumeration of info need to be updated manually to RTCP XR. Most info
 * could be updated automatically each time RTP received.
 */
typedef enum {
    PJMEDIA_RTCP_XR_INFO_SIGNAL_LVL = 1,
    PJMEDIA_RTCP_XR_INFO_NOISE_LVL  = 2,
    PJMEDIA_RTCP_XR_INFO_RERL	    = 3,
    PJMEDIA_RTCP_XR_INFO_R_FACTOR   = 4,
    PJMEDIA_RTCP_XR_INFO_MOS_LQ	    = 5,
    PJMEDIA_RTCP_XR_INFO_MOS_CQ	    = 6,
    PJMEDIA_RTCP_XR_INFO_CONF_PLC   = 7,
    PJMEDIA_RTCP_XR_INFO_CONF_JBA   = 8,
    PJMEDIA_RTCP_XR_INFO_CONF_JBR   = 9,
    PJMEDIA_RTCP_XR_INFO_JB_NOM	    = 10,
    PJMEDIA_RTCP_XR_INFO_JB_MAX	    = 11,
    PJMEDIA_RTCP_XR_INFO_JB_ABS_MAX = 12
} pjmedia_rtcp_xr_info;

/**
 * Enumeration of PLC types definitions for RTCP XR report.
 */
typedef enum {
    PJMEDIA_RTCP_XR_PLC_UNK	    = 0,
    PJMEDIA_RTCP_XR_PLC_DIS	    = 1,
    PJMEDIA_RTCP_XR_PLC_ENH	    = 2,
    PJMEDIA_RTCP_XR_PLC_STD	    = 3
} pjmedia_rtcp_xr_plc_type;

/**
 * Enumeration of jitter buffer types definitions for RTCP XR report.
 */
typedef enum {
    PJMEDIA_RTCP_XR_JB_UNKNOWN      = 0,
    PJMEDIA_RTCP_XR_JB_FIXED        = 2,
    PJMEDIA_RTCP_XR_JB_ADAPTIVE     = 3
} pjmedia_rtcp_xr_jb_type;


#pragma pack(1)

/**
 * This type declares RTCP XR Report Header.
 */
typedef struct pjmedia_rtcp_xr_rb_header
{
    u_int8_t		 bt;		/**< Block type.		*/
    u_int8_t		 specific;	/**< Block specific data.	*/
    u_int16_t		 length;	/**< Block length.		*/
} pjmedia_rtcp_xr_rb_header;

/**
 * This type declares RTCP XR Receiver Reference Time Report Block.
 */
typedef struct pjmedia_rtcp_xr_rb_rr_time
{
    pjmedia_rtcp_xr_rb_header header;	/**< Block header.		*/
    u_int32_t		 ntp_sec;	/**< NTP time, seconds part.	*/
    u_int32_t		 ntp_frac;	/**< NTP time, fractions part.	*/
} pjmedia_rtcp_xr_rb_rr_time;


/**
 * This type declares RTCP XR DLRR Report Sub-block
 */
typedef struct pjmedia_rtcp_xr_rb_dlrr_item
{
    u_int32_t		 ssrc;		/**< receiver SSRC		*/
    u_int32_t		 lrr;		/**< last receiver report	*/
    u_int32_t		 dlrr;		/**< delay since last receiver
					     report			*/
} pjmedia_rtcp_xr_rb_dlrr_item;

/**
 * This type declares RTCP XR DLRR Report Block
 */
typedef struct pjmedia_rtcp_xr_rb_dlrr
{
    pjmedia_rtcp_xr_rb_header header;	/**< Block header.		*/
    pjmedia_rtcp_xr_rb_dlrr_item item;	/**< Block contents,
					     variable length list	*/
} pjmedia_rtcp_xr_rb_dlrr;

/**
 * This type declares RTCP XR Statistics Summary Report Block
 */
typedef struct pjmedia_rtcp_xr_rb_stats
{
    pjmedia_rtcp_xr_rb_header header;	/**< Block header.		     */
    u_int32_t		 ssrc;		/**< Receiver SSRC		     */
    u_int16_t		 begin_seq;	/**< Begin RTP sequence reported     */
    u_int16_t		 end_seq;	/**< End RTP sequence reported       */
    u_int32_t		 lost;		/**< Number of packet lost in this
					     interval  */
    u_int32_t		 dup;		/**< Number of duplicated packet in
					     this interval */
    u_int32_t		 jitter_min;	/**< Minimum jitter in this interval */
    u_int32_t		 jitter_max;	/**< Maximum jitter in this interval */
    u_int32_t		 jitter_mean;	/**< Average jitter in this interval */
    u_int32_t		 jitter_dev;	/**< Jitter deviation in this
					     interval */
    u_int32_t		 toh_min:8;	/**< Minimum ToH in this interval    */
    u_int32_t		 toh_max:8;	/**< Maximum ToH in this interval    */
    u_int32_t		 toh_mean:8;	/**< Average ToH in this interval    */
    u_int32_t		 toh_dev:8;	/**< ToH deviation in this interval  */
} pjmedia_rtcp_xr_rb_stats;

/**
 * This type declares RTCP XR VoIP Metrics Report Block
 */
typedef struct pjmedia_rtcp_xr_rb_voip_mtc
{
    pjmedia_rtcp_xr_rb_header header;	/**< Block header.		*/
    u_int32_t		 ssrc;		/**< Receiver SSRC		*/
    u_int8_t		 loss_rate;	/**< Packet loss rate		*/
    u_int8_t		 discard_rate;	/**< Packet discarded rate	*/
    u_int8_t		 burst_den;	/**< Burst density		*/
    u_int8_t		 gap_den;	/**< Gap density		*/
    u_int16_t		 burst_dur;	/**< Burst duration		*/
    u_int16_t		 gap_dur;	/**< Gap duration		*/
    u_int16_t		 rnd_trip_delay;/**< Round trip delay		*/
    u_int16_t		 end_sys_delay; /**< End system delay		*/
    u_int8_t		 signal_lvl;	/**< Signal level		*/
    u_int8_t		 noise_lvl;	/**< Noise level		*/
    u_int8_t		 rerl;		/**< Residual Echo Return Loss	*/
    u_int8_t		 gmin;		/**< The gap threshold		*/
    u_int8_t		 r_factor;	/**< Voice quality metric carried
					     over this RTP session	*/
    u_int8_t		 ext_r_factor;  /**< Voice quality metric carried
					     outside of this RTP session*/
    u_int8_t		 mos_lq;	/**< Mean Opinion Score for
					     Listening Quality          */
    u_int8_t		 mos_cq;	/**< Mean Opinion Score for
					     Conversation Quality       */
    u_int8_t		 rx_config;	/**< Receiver configuration	*/
    u_int8_t		 reserved2;	/**< Not used			*/
    u_int16_t		 jb_nom;	/**< Current delay by jitter
					     buffer			*/
    u_int16_t		 jb_max;	/**< Maximum delay by jitter
					     buffer			*/
    u_int16_t		 jb_abs_max;	/**< Maximum possible delay by
					     jitter buffer		*/
} pjmedia_rtcp_xr_rb_voip_mtc;


/**
 * This function is called internally by RTCP session when it receives
 * incoming RTCP XR packets.
 *
 * @param rtcp_pkt  The received RTCP XR packet.
 * @param size	    Size of the incoming packet.
 */
void pjmedia_rtcp_xr_rx_rtcp_xr(GString *, pjmedia_rtcp_common *common, str *s);


#pragma pack()


#endif /* RTCP_XR_H_ */
