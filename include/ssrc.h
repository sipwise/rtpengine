#ifndef _SSRC_H_
#define _SSRC_H_

#include <sys/types.h>
#include <glib.h>

#include "compat.h"
#include "helpers.h"
#include "obj.h"
#include "codeclib.h"
#include "types.h"

#define MAX_SSRC_ENTRIES 20

struct call_media;
struct ssrc_entry;
struct ssrc_entry_call;
enum ssrc_dir;

typedef struct ssrc_entry *(*ssrc_create_func_t)(void *uptr);

struct ssrc_hash {
	GQueue nq;
	mutex_t lock;
	ssrc_create_func_t create_func;
	void *uptr;
	struct ssrc_entry *precreat; // next used entry
	unsigned int iters; // tracks changes
};
struct payload_tracker {
	mutex_t lock;
	unsigned char last[32]; // must be <= 255
	unsigned int last_idx; // rolling index into pt_last
	unsigned char count[128]; // how many of each pt
	unsigned char idx[128]; // each pt's index into most[]
	unsigned char most[128]; // sorted list of pts
	unsigned int most_len; // idx for new entries

	unsigned char last_pts[16];
	int last_pt_idx;
};

struct ssrc_stats_block {
	int64_t reported;
	uint64_t jitter; // ms
	uint64_t rtt; // us - combined from both sides
	uint32_t rtt_leg; // RTT only for the leg receiving the RTCP report
	uint64_t packetloss; // percent
	uint64_t mos; // nominal range of 10 - 50 for MOS values 1.0 to 5.0
};

struct ssrc_entry {
	struct obj obj;
	GList link;
	mutex_t lock;
	uint32_t ssrc;
};

struct ssrc_entry_call {
	struct ssrc_entry h; // must be first

	struct call_media *media; // bundle receive media

	struct payload_tracker tracker;

	// XXX move entire crypto context in here?

	// for transcoding
	uint32_t ssrc_map_out;
	uint16_t seq_out;
	unsigned long ts_out;

	// RTCP stats
	struct ssrc_stats *stats;

	// for per-second stats:
	atomic64 last_sample,
		 sample_packets,
		 sample_octets,
		 sample_packets_lost,
		 sample_duplicates;

	int64_t next_rtcp; // for self-generated RTCP reports

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
	packet_sequencer_t *sequencer_cache; // to skip hash lookup
	struct call_media *media_cache; // to skip hash lookup
	uint32_t jitter, transit;
	// output only
	uint16_t seq_diff;
};

struct ssrc_time_item {
	int64_t received;
	uint32_t ntp_middle_bits; // to match up with lsr/dlrr
	int32_t ntp_ts_lsw, ntp_ts_msw;
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
	int64_t tv;
	int *pt_p;
	uint32_t ssrc;
	uint32_t ntp_middle_bits;
	uint32_t delay;
	size_t reports_queue_offset;
};



void ssrc_hash_destroy(struct ssrc_hash *);
void ssrc_hash_foreach(struct ssrc_hash *, void (*)(void *, void *), void *);
void ssrc_hash_full_init(struct ssrc_hash *, ssrc_create_func_t, void *uptr); // pre-creates one object
void ssrc_hash_full_fast_init(struct ssrc_hash *, ssrc_create_func_t, void *uptr); // doesn't pre-create object

void ssrc_hash_call_init(struct ssrc_hash *);

void *get_ssrc_full(uint32_t, struct ssrc_hash *, bool *created); // creates new entry if not found
INLINE void *get_ssrc(uint32_t ssrc, struct ssrc_hash *ht) {
	return get_ssrc_full(ssrc, ht, NULL);
}

INLINE struct ssrc_entry_call *call_get_first_ssrc(struct ssrc_hash *ht) {
	return ht->nq.head ? ht->nq.head->data : NULL;
}

void ssrc_sender_report(struct call_media *, const struct ssrc_sender_report *, int64_t);
void ssrc_receiver_report(struct call_media *, stream_fd *, const struct ssrc_receiver_report *, int64_t);
void ssrc_receiver_rr_time(struct call_media *m, const struct ssrc_xr_rr_time *rr, int64_t);
void ssrc_receiver_dlrr(struct call_media *m, const struct ssrc_xr_dlrr *dlrr, int64_t);
void ssrc_voip_metrics(struct call_media *m, const struct ssrc_xr_voip_metrics *vm, int64_t);


void ssrc_collect_metrics(struct call_media *);


void payload_tracker_init(struct payload_tracker *t);
void payload_tracker_add(struct payload_tracker *, int);


#define ssrc_entry_release(c) do { \
	if (c) { \
		obj_put(&(c)->h); \
		c = NULL; \
	} \
} while (0)

#define ssrc_entry_hold(c) obj_hold(&(c)->h)

#endif
