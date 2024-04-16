#ifndef _SSRC_H_
#define _SSRC_H_

#include <sys/types.h>
#include <glib.h>

#include "compat.h"
#include "helpers.h"
#include "obj.h"
#include "codeclib.h"
#include "types.h"

struct call_media;
struct timeval;
struct ssrc_entry;
struct ssrc_entry_call;
enum ssrc_dir;

typedef struct ssrc_entry *(*ssrc_create_func_t)(void *uptr);

struct ssrc_hash {
	GHashTable *ht;
	GQueue q;
	rwlock_t lock;
	ssrc_create_func_t create_func;
	void *uptr;
	struct ssrc_entry *cache; // last used entry
	struct ssrc_entry *precreat; // next used entry
};
struct payload_tracker {
	mutex_t lock;
	unsigned char last[32]; // must be <= 255
	unsigned int last_idx; // rolling index into pt_last
	unsigned char count[128]; // how many of each pt
	unsigned char idx[128]; // each pt's index into most[]
	unsigned char most[128]; // sorted list of pts
	unsigned int most_len; // idx for new entries
};
struct ssrc_ctx {
	struct ssrc_entry_call *parent;
	struct payload_tracker tracker;
	void *ref; // points to the call_monologue but is opaque

	// XXX move entire crypto context in here?

	// for transcoding
	uint32_t ssrc_map_out;
	uint16_t seq_out;

	// RTCP stats
	struct ssrc_stats *stats;

	// for per-second stats:
	atomic64 last_sample,
		 sample_packets,
		 sample_octets,
		 sample_packets_lost,
		 sample_duplicates;

	struct timeval next_rtcp; // for self-generated RTCP reports
};

INLINE uint64_t ssrc_timeval_to_ts(const struct timeval *tv) {
	return (tv->tv_sec << 20) | tv->tv_usec;
}
INLINE struct timeval ssrc_ts_to_timeval(uint64_t ts) {
	return (struct timeval) { .tv_sec = ts >> 20, .tv_usec = ts & 0xfffff };
}


struct ssrc_stats_block {
	struct timeval reported;
	uint64_t jitter; // ms
	uint64_t rtt; // us - combined from both sides
	uint32_t rtt_leg; // RTT only for the leg receiving the RTCP report
	uint64_t packetloss; // percent
	uint64_t mos; // nominal range of 10 - 50 for MOS values 1.0 to 5.0
};

struct ssrc_entry {
	struct obj obj;
	mutex_t lock;
	uint32_t ssrc;
	time_t last_used;
};

struct ssrc_entry_call {
	struct ssrc_entry h; // must be first
	struct ssrc_ctx input_ctx,
			output_ctx;
	GQueue sender_reports; // as received via RTCP
	GQueue rr_time_reports; // as received via RTCP
	GQueue stats_blocks; // calculated
	struct ssrc_stats_block *lowest_mos,
				*highest_mos,
				average_mos; // contains a running tally of all stats blocks
	uint16_t no_mos_count; // how many time we where not able to compute MOS due to missing RTT
	unsigned int last_rtt; // last calculated raw rtt without rtt from opposide side
	unsigned int last_rtt_xr; // last rtt for both legs retrieved from RTCP-XR BT-7

	// input only - tracking for passthrough handling
	uint32_t last_seq_tracked;
	uint32_t lost_bits; // sliding bitfield, [0] = ext_seq
	uint32_t packets_lost; // RTCP cumulative number of packets lost
	uint32_t duplicates;

	// for transcoding
	// input only
	GHashTable *sequencers;
	uint32_t jitter, transit;
	// output only
	uint16_t seq_diff;
};
enum ssrc_dir { // these values must not be used externally
	SSRC_DIR_INPUT  = G_STRUCT_OFFSET(struct ssrc_entry_call, input_ctx),
	SSRC_DIR_OUTPUT = G_STRUCT_OFFSET(struct ssrc_entry_call, output_ctx),
};

struct ssrc_time_item {
	struct timeval received;
	uint32_t ntp_middle_bits; // to match up with lsr/dlrr
	double ntp_ts; // XXX convert to int?
};
struct ssrc_sender_report {
	uint32_t ssrc;
	uint32_t ntp_msw;
	uint32_t ntp_lsw;
	uint32_t timestamp;
	uint32_t packet_count;
	uint32_t octet_count;
};
struct ssrc_sender_report_item {
	struct ssrc_time_item time_item; // must be first;
	struct ssrc_sender_report report;
};

struct ssrc_receiver_report {
	uint32_t from;
	uint32_t ssrc;
	unsigned char fraction_lost;
	uint32_t packets_lost;
	uint32_t high_seq_received;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t dlsr;
};
//struct ssrc_receiver_report_item {
//	struct timeval received;
//	struct ssrc_receiver_report report;
//};

struct ssrc_xr_rr_time {
	uint32_t ssrc;
	uint32_t ntp_msw;
	uint32_t ntp_lsw;
};
struct ssrc_rr_time_item {
	struct ssrc_time_item time_item; // must be first;
};

struct ssrc_xr_dlrr {
	uint32_t from;
	uint32_t ssrc;
	uint32_t lrr;
	uint32_t dlrr;
};

struct ssrc_xr_voip_metrics {
	uint32_t from;
	uint32_t ssrc;
	uint8_t loss_rate;
	uint8_t discard_rate;
	uint8_t burst_den;
	uint8_t gap_den;
	uint16_t burst_dur;
	uint16_t gap_dur;
	uint16_t rnd_trip_delay;
	uint16_t end_sys_delay;
	uint8_t signal_lvl;
	uint8_t noise_lvl;
	uint8_t rerl;
	uint8_t gmin;
	uint8_t r_factor;
	uint8_t ext_r_factor;
	uint8_t mos_lq;
	uint8_t mos_cq;
	uint8_t rx_config;
	uint16_t jb_nom;
	uint16_t jb_max;
	uint16_t jb_abs_max;
};

struct crtt_args {
	struct ssrc_hash *ht;
	const struct timeval *tv;
	int * pt_p;
	uint32_t ssrc;
	uint32_t ntp_middle_bits;
	uint32_t delay;
	size_t reports_queue_offset;
};



void free_ssrc_hash(struct ssrc_hash **);
void ssrc_hash_foreach(struct ssrc_hash *, void (*)(void *, void *), void *);
struct ssrc_hash *create_ssrc_hash_full(ssrc_create_func_t, void *uptr); // pre-creates one object
struct ssrc_hash *create_ssrc_hash_full_fast(ssrc_create_func_t, void *uptr); // doesn't pre-create object

struct ssrc_hash *create_ssrc_hash_call(void);

void *get_ssrc_full(uint32_t, struct ssrc_hash *, bool *created); // creates new entry if not found
INLINE void *get_ssrc(uint32_t ssrc, struct ssrc_hash *ht) {
	return get_ssrc_full(ssrc, ht, NULL);
}

struct ssrc_ctx *get_ssrc_ctx(uint32_t, struct ssrc_hash *, enum ssrc_dir, void *ref); // creates new entry if not found


void ssrc_sender_report(struct call_media *, const struct ssrc_sender_report *, const struct timeval *);
void ssrc_receiver_report(struct call_media *, stream_fd *, const struct ssrc_receiver_report *,
		const struct timeval *);
void ssrc_receiver_rr_time(struct call_media *m, const struct ssrc_xr_rr_time *rr,
		const struct timeval *);
void ssrc_receiver_dlrr(struct call_media *m, const struct ssrc_xr_dlrr *dlrr,
		const struct timeval *);
void ssrc_voip_metrics(struct call_media *m, const struct ssrc_xr_voip_metrics *vm,
		const struct timeval *);


void ssrc_collect_metrics(struct call_media *);


void payload_tracker_init(struct payload_tracker *t);
void payload_tracker_add(struct payload_tracker *, int);


#define ssrc_ctx_put(c) \
	do { \
		struct ssrc_ctx **__cc = (c); \
		if ((__cc) && *(__cc)) { \
			obj_put(&(*__cc)->parent->h); \
			*(__cc) = NULL; \
		} \
	} while (0)
#define ssrc_ctx_hold(c) \
	do { \
		if (c) \
			obj_hold(&(c)->parent->h); \
	} while (0)



#endif
