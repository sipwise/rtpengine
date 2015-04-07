/*
 * rtcp_xr.c
 *
 *  Created on: Mar 29, 2015
 *      Author: fmetz
 */
#include <stdio.h>
#include <arpa/inet.h>
#include "rtcp_xr.h"

/* RTCP XR payload type */
#define RTCP_XR		    207

/* RTCP XR block types */
#define BT_LOSS_RLE	    1
#define BT_DUP_RLE	    2
#define BT_RCPT_TIMES	    3
#define BT_RR_TIME	    4
#define BT_DLRR		    5
#define BT_STATS	    6
#define BT_VOIP_METRICS	    7


void print_rtcp_xr_common(char* cdrbufcur,pjmedia_rtcp_xr_pkt *rtcp_xr) {
	cdrbufcur += sprintf(cdrbufcur,"version=%u, padding=%u, count=%u, payloadtype=%u, length=%u, ssrc=%u, ",
			ntohl(rtcp_xr->common.version),
			ntohl(rtcp_xr->common.p),
			ntohl(rtcp_xr->common.count),
			ntohl(rtcp_xr->common.pt),
			ntohl(rtcp_xr->common.length),
			ntohl(rtcp_xr->common.ssrc));
}

void print_rtcp_xr_rb_header(char* cdrbufcur,pjmedia_rtcp_xr_rb_header *rb_header) {
	cdrbufcur += sprintf(cdrbufcur,"rb_header_blocktype=%u, rb_header_blockspecdata=%u, rb_header_blocklength=%u, ",
			ntohl(rb_header->bt),
			ntohl(rb_header->specific),
			ntohl(rb_header->length));
}

void print_rtcp_xr_rb_rr_time(char* cdrbufcur,pjmedia_rtcp_xr_rb_rr_time *rb_rr_time) {
	print_rtcp_xr_rb_header(cdrbufcur,&rb_rr_time->header);
	cdrbufcur += sprintf(cdrbufcur,"rb_rr_time_ntp_sec=%u, rb_rr_time_ntp_frac=%u, ",
			ntohl(rb_rr_time->ntp_sec),
			ntohl(rb_rr_time->ntp_frac));
}

void print_rtcp_xr_rb_dlrr(char* cdrbufcur,pjmedia_rtcp_xr_rb_dlrr *rb_dlrr) {
	print_rtcp_xr_rb_header(cdrbufcur,&rb_dlrr->header);
	cdrbufcur += sprintf(cdrbufcur,"rb_dlrr_ssrc=%u, rb_dlrr_lrr=%u, rb_dlrr_dlrr=%u, ",
			ntohl(rb_dlrr->item.ssrc),
			ntohl(rb_dlrr->item.lrr),
			ntohl(rb_dlrr->item.dlrr));
}

void print_rtcp_xr_rb_stats(char* cdrbufcur,pjmedia_rtcp_xr_rb_stats *rb_stats) {
	print_rtcp_xr_rb_header(cdrbufcur,&rb_stats->header);
	cdrbufcur += sprintf(cdrbufcur,"rb_stats_ssrc=%u, rb_stats_begin_seq=%u, rb_stats_end_seq=%u, rb_stats_lost_packets=%u, rb_stats_duplicate_packets=%u,"
			"rb_stats_jitter_min=%u, rb_stats_jitter_max=%u, rb_stats_jitter_mean=%u, rb_stats_jitter_deviation=%u,"
			"rb_stats_toh_min=%u, rb_stats_toh_max=%u, rb_stats_toh_mean=%u, rb_stats_toh_deviation=%u, ",
			ntohl(rb_stats->ssrc),
			ntohl(rb_stats->begin_seq),
			ntohl(rb_stats->end_seq),
			ntohl(rb_stats->lost),
			ntohl(rb_stats->dup),
			ntohl(rb_stats->jitter_min),
			ntohl(rb_stats->jitter_max),
			ntohl(rb_stats->jitter_mean),
			ntohl(rb_stats->jitter_dev),
			ntohl(rb_stats->toh_min),
			ntohl(rb_stats->toh_max),
			ntohl(rb_stats->toh_mean),
			ntohl(rb_stats->toh_dev));
}

void print_rtcp_xr_rb_voip_mtc(char* cdrbufcur,pjmedia_rtcp_xr_rb_voip_mtc *rb_voip_mtc) {
	print_rtcp_xr_rb_header(cdrbufcur,&rb_voip_mtc->header);
	cdrbufcur += sprintf(cdrbufcur,"rb_voip_mtc_ssrc=%u, rb_voip_mtc_loss_rate=%u, rb_voip_mtc_discard_rate=%u, rb_voip_mtc_burst_den=%u, "
			"rb_voip_mtc_gap_den=%u, rb_voip_mtc_burst_dur=%u, rb_voip_mtc_gap_dur=%u, rb_voip_mtc_rnd_trip_delay=%u, "
			"rb_voip_mtc_end_sys_delay=%u, rb_voip_mtc_signal_lvl=%u, rb_voip_mtc_noise_lvl=%u, rb_voip_mtc_rerl=%u, "
			"rb_voip_mtc_gmin=%u, rb_voip_mtc_r_factor=%u, rb_voip_mtc_ext_r_factor=%u, rb_voip_mtc_mos_lq=%u, "
			"rb_voip_mtc_mos_cq=%u, rb_voip_mtc_rx_config=%u, rb_voip_mtc_jb_nom=%u, rb_voip_mtc_jb_max=%u, "
			"rb_voip_mtc_jb_abs_max=%u, ",
			ntohl(rb_voip_mtc->ssrc),
			ntohl(rb_voip_mtc->loss_rate),
			ntohl(rb_voip_mtc->discard_rate),
			ntohl(rb_voip_mtc->burst_den),
			ntohl(rb_voip_mtc->gap_den),
			ntohl(rb_voip_mtc->burst_dur),
			ntohl(rb_voip_mtc->gap_dur),
			ntohl(rb_voip_mtc->rnd_trip_delay),
			ntohl(rb_voip_mtc->end_sys_delay),
			ntohl(rb_voip_mtc->signal_lvl),
			ntohl(rb_voip_mtc->noise_lvl),
			ntohl(rb_voip_mtc->rerl),
			ntohl(rb_voip_mtc->gmin),
			ntohl(rb_voip_mtc->r_factor),
			ntohl(rb_voip_mtc->ext_r_factor),
			ntohl(rb_voip_mtc->mos_lq),
			ntohl(rb_voip_mtc->mos_cq),
			ntohl(rb_voip_mtc->rx_config),
			ntohl(rb_voip_mtc->jb_nom),
			ntohl(rb_voip_mtc->jb_max),
			ntohl(rb_voip_mtc->jb_abs_max));
}

void pjmedia_rtcp_xr_rx_rtcp_xr(char* cdrbufcur, const void *pkt, size_t size) {

	const pjmedia_rtcp_xr_pkt	      *rtcp_xr = (pjmedia_rtcp_xr_pkt*) pkt;
	const pjmedia_rtcp_xr_rb_rr_time  *rb_rr_time = NULL;
	const pjmedia_rtcp_xr_rb_dlrr     *rb_dlrr = NULL;
	const pjmedia_rtcp_xr_rb_stats    *rb_stats = NULL;
	const pjmedia_rtcp_xr_rb_voip_mtc *rb_voip_mtc = NULL;
	const pjmedia_rtcp_xr_rb_header   *rb_hdr = (pjmedia_rtcp_xr_rb_header*)
								rtcp_xr->buf;
	unsigned pkt_len, rb_len;

	if (rtcp_xr->common.pt != RTCP_XR)
		return;

	print_rtcp_xr_common(cdrbufcur,rtcp_xr);

	pkt_len = ntohs((u_int16_t)rtcp_xr->common.length);

	if ((pkt_len + 1) > (size / 4))
		return;

	/* Parse report rpt_types */
	while ((int32_t*)rb_hdr < (int32_t*)pkt + pkt_len)
	{
		rb_len = ntohs((u_int16_t)rb_hdr->length);

		/* Just skip any block with length == 0 (no report content) */
		if (rb_len) {
			switch (rb_hdr->bt) {
			case BT_RR_TIME:
				rb_rr_time = (pjmedia_rtcp_xr_rb_rr_time*) rb_hdr;
				print_rtcp_xr_rb_rr_time(cdrbufcur,rb_rr_time);
				break;
			case BT_DLRR:
				rb_dlrr = (pjmedia_rtcp_xr_rb_dlrr*) rb_hdr;
				print_rtcp_xr_rb_dlrr(cdrbufcur,rb_dlrr);
				break;
			case BT_STATS:
				rb_stats = (pjmedia_rtcp_xr_rb_stats*) rb_hdr;
				print_rtcp_xr_rb_stats(cdrbufcur,rb_stats);
				break;
			case BT_VOIP_METRICS:
				rb_voip_mtc = (pjmedia_rtcp_xr_rb_voip_mtc*) rb_hdr;
				print_rtcp_xr_rb_voip_mtc(cdrbufcur,rb_voip_mtc);
				break;
			default:
				break;
			}
		}
		rb_hdr = (pjmedia_rtcp_xr_rb_header*)
				 ((int32_t*)rb_hdr + rb_len + 1);
	}
}

