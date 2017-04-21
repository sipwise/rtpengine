#ifndef _SSRC_H_
#define _SSRC_H_


#include <sys/types.h>
#include <glib.h>
#include "compat.h"
#include "aux.h"




struct call;
struct call_media;
struct timeval;
struct rtp_payload_type;
struct ssrc_entry;
enum ssrc_dir;



struct ssrc_hash {
	GHashTable *ht;
	rwlock_t lock;
};
struct ssrc_ctx {
	struct ssrc_entry *parent;
	// XXX lock this?
	u_int64_t srtp_index,
		  srtcp_index;
	// XXX move entire crypto context in here?
};

struct ssrc_stats_block {
	struct timeval reported;
	u_int64_t jitter; // ms
	u_int64_t rtt; // us - combined from both sides
	u_int64_t packetloss; // percent
	u_int64_t mos; // nominal range of 10 - 50 for MOS values 1.0 to 5.0
};

struct ssrc_entry {
	mutex_t lock;
	u_int32_t ssrc;
	struct ssrc_ctx input_ctx,
			output_ctx;
	GQueue sender_reports; // as received via RTCP
	GQueue rr_time_reports; // as received via RTCP
	GQueue stats_blocks; // calculated
	struct ssrc_stats_block *lowest_mos,
				*highest_mos,
				average_mos; // contains a running tally of all stats blocks
	int payload_type; // to determine the clock rate for jitter calculations
	unsigned int last_rtt; // last calculated raw rtt without rtt from opposide side
};
enum ssrc_dir { // these values must not be used externally
	SSRC_DIR_INPUT  = G_STRUCT_OFFSET(struct ssrc_entry, input_ctx),
	SSRC_DIR_OUTPUT = G_STRUCT_OFFSET(struct ssrc_entry, output_ctx),
};

struct ssrc_time_item {
	struct timeval received;
	u_int32_t ntp_middle_bits; // to match up with lsr/dlrr
	double ntp_ts; // XXX convert to int?
};
struct ssrc_sender_report {
	u_int32_t ssrc;
	u_int32_t ntp_msw;
	u_int32_t ntp_lsw;
	u_int32_t timestamp;
	u_int32_t packet_count;
	u_int32_t octet_count;
};
struct ssrc_sender_report_item {
	struct ssrc_time_item time_item; // must be first;
	struct ssrc_sender_report report;
};

struct ssrc_receiver_report {
	u_int32_t from;
	u_int32_t ssrc;
	unsigned char fraction_lost;
	u_int32_t packets_lost;
	u_int32_t high_seq_received;
	u_int32_t jitter;
	u_int32_t lsr;
	u_int32_t dlsr;
};
//struct ssrc_receiver_report_item {
//	struct timeval received;
//	struct ssrc_receiver_report report;
//};

struct ssrc_xr_rr_time {
	u_int32_t ssrc;
	u_int32_t ntp_msw;
	u_int32_t ntp_lsw;
};
struct ssrc_rr_time_item {
	struct ssrc_time_item time_item; // must be first;
};

struct ssrc_xr_dlrr {
	u_int32_t from;
	u_int32_t ssrc;
	u_int32_t lrr;
	u_int32_t dlrr;
};

struct ssrc_xr_voip_metrics {
	u_int32_t from;
	u_int32_t ssrc;
	u_int8_t loss_rate;
	u_int8_t discard_rate;
	u_int8_t burst_den;
	u_int8_t gap_den;
	u_int16_t burst_dur;
	u_int16_t gap_dur;
	u_int16_t rnd_trip_delay;
	u_int16_t end_sys_delay;
	u_int8_t signal_lvl;
	u_int8_t noise_lvl;
	u_int8_t rerl;
	u_int8_t gmin;
	u_int8_t r_factor;
	u_int8_t ext_r_factor;
	u_int8_t mos_lq;
	u_int8_t mos_cq;
	u_int8_t rx_config;
	u_int16_t jb_nom;
	u_int16_t jb_max;
	u_int16_t jb_abs_max;
};




void free_ssrc_hash(struct ssrc_hash **);
struct ssrc_hash *create_ssrc_hash(void);

struct ssrc_entry *find_ssrc(u_int32_t, struct ssrc_hash *); // returns NULL if not found
struct ssrc_entry *get_ssrc(u_int32_t, struct ssrc_hash * /* , int *created */); // creates new entry if not found
//struct ssrc_entry *create_ssrc_entry(u_int32_t);
struct ssrc_ctx *get_ssrc_ctx(u_int32_t, struct ssrc_hash *, enum ssrc_dir); // creates new entry if not found


void ssrc_sender_report(struct call_media *, const struct ssrc_sender_report *, const struct timeval *);
void ssrc_receiver_report(struct call_media *, const struct ssrc_receiver_report *,
		const struct timeval *);
void ssrc_receiver_rr_time(struct call_media *m, const struct ssrc_xr_rr_time *rr,
		const struct timeval *);
void ssrc_receiver_dlrr(struct call_media *m, const struct ssrc_xr_dlrr *dlrr,
		const struct timeval *);
void ssrc_voip_metrics(struct call_media *m, const struct ssrc_xr_voip_metrics *vm,
		const struct timeval *);



#endif
