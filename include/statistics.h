#ifndef STATISTICS_H_
#define STATISTICS_H_

#include "aux.h"
#include "bencode.h"
#include "rtpengine_config.h"

struct call;
struct packet_stream;

struct stream_stats {
	atomic64			packets;
	atomic64			bytes;
	atomic64			errors;
#if RE_HAS_MEASUREDELAY
	uint64_t			delay_min;
	uint64_t			delay_avg;
	uint64_t			delay_max;
#endif
};



#include "control_ng.h"
#include "graphite.h"


// "gauge" style stats
struct global_stats_gauge {
// F(x) : real gauge that has a continuous value
// Fd(x) : gauge that receives values in discreet samples
// FA(x, n) / FdA(x, n) : array of the above
#define F(x) atomic64 x;
#define Fd(x) F(x)
#define FA(x, n) atomic64 x[n];
#define FdA(x, n) FA(x, n)
#include "gauge_stats_fields.inc"
#undef F
#undef Fd
#undef FA
#undef FdA
};

struct global_stats_gauge_min_max {
	struct global_stats_gauge min;
	struct global_stats_gauge max;
	struct global_stats_gauge avg; // sum while accumulation is running
	struct global_stats_gauge stddev; // sum^2 while accumulation is running
	struct global_stats_gauge count;
};

// "counter" style stats that are incremental and are kept cumulative or per-interval
struct global_stats_counter {
#define F(x) atomic64 x;
#define FA(x, n) atomic64 x[n];
#include "counter_stats_fields.inc"
#undef F
#undef FA
};

struct global_rate_min_max {
	struct global_stats_counter min;
	struct global_stats_counter max;
};
struct global_rate_min_max_avg {
	struct global_stats_counter min;
	struct global_stats_counter max;
	struct global_stats_counter avg;
};


struct rtp_stats {
	unsigned int		payload_type;
	atomic64		packets;
	atomic64		bytes;
	atomic64		kernel_packets;
	atomic64		kernel_bytes;
};

struct codec_stats {
	char			*chain;
	char			*chain_brief;
	int			num_transcoders;
	// 3 entries: [0] and [1] for per-second stats, [2] for total count
	// last_tv_sec keeps track of rollovers
	int			last_tv_sec[2];
	atomic64		packets_input[3];
	atomic64		bytes_input[3];
	atomic64		pcm_samples[3];
};

struct stats_metric {
	char *label;
	char *descr;
	char *value_short;
	char *value_long;
	char *value_raw;
	int64_t int_value;
	double double_value;
	int is_bracket;
	int is_close_bracket;
	int is_brace;
	int is_follow_up;
	int is_int;
	int is_double;
	const char *prom_name;
	const char *prom_type;
	char *prom_label;
};


struct call_stats {
	time_t		last_packet;
	struct stream_stats	totals[4]; /* rtp in, rtcp in, rtp out, rtcp out */
};

extern struct timeval rtpe_started;

extern mutex_t rtpe_codec_stats_lock;
extern GHashTable *rtpe_codec_stats;


extern struct global_stats_gauge rtpe_stats_gauge;
extern struct global_stats_gauge_min_max rtpe_stats_gauge_cumulative; // lifetime min/max/average/sums

#define RTPE_GAUGE_SET(field, num) \
	do { \
		atomic64_set(&rtpe_stats_gauge.field, num); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_stats_gauge_cumulative, num); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_stats_gauge_graphite_min_max, num); \
	} while (0)
#define RTPE_GAUGE_ADD(field, num) \
	do { \
		uint64_t __old = atomic64_add(&rtpe_stats_gauge.field, num); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_stats_gauge_graphite_min_max, __old + num); \
	} while (0)
#define RTPE_GAUGE_INC(field) RTPE_GAUGE_ADD(field, 1)
#define RTPE_GAUGE_DEC(field) RTPE_GAUGE_ADD(field, -1)

extern struct global_stats_counter rtpe_stats;			// total, cumulative, master
extern struct global_stats_counter rtpe_stats_rate;		// per-second, calculated once per timer run

#define RTPE_STATS_ADD(field, num) atomic64_add(&rtpe_stats.field, num)
#define RTPE_STATS_INC(field) RTPE_STATS_ADD(field, 1)



void statistics_update_oneway(struct call *);
void statistics_update_ip46_inc_dec(struct call *, int op);
void statistics_update_foreignown_dec(struct call *);
void statistics_update_foreignown_inc(struct call* c);

GQueue *statistics_gather_metrics(void);
void statistics_free_metrics(GQueue **);
const char *statistics_ng(bencode_item_t *input, bencode_item_t *output);

INLINE void stats_counters_calc_rate(const struct global_stats_counter *stats, long long run_diff_us,
		struct global_stats_counter *intv, struct global_stats_counter *rate)
{
	if (run_diff_us <= 0)
		return;

#define F(x) atomic64_calc_rate(&stats->x, run_diff_us, &intv->x, &rate->x);
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
}

INLINE void stats_counters_calc_diff(const struct global_stats_counter *stats,
		struct global_stats_counter *intv, struct global_stats_counter *diff)
{
#define F(x) atomic64_calc_diff(&stats->x, &intv->x, &diff->x);
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
}

// update the running min/max counter `mm` with the newly calculated per-sec rate values `inp`
INLINE void stats_rate_min_max(struct global_rate_min_max *mm, struct global_stats_counter *inp) {
#define F(x) \
	atomic64_mina(&mm->min.x, &inp->x); \
	atomic64_maxa(&mm->max.x, &inp->x);
#include "counter_stats_fields.inc"
#undef F
}
// sample running min/max from `mm` into `loc` and reset `mm` to zero.
// calculate average values in `loc` from `counter_diff` and `time_diff_us`
INLINE void stats_rate_min_max_avg_sample(struct global_rate_min_max *mm, struct global_rate_min_max_avg *loc,
		long long run_diff_us, const struct global_stats_counter *counter_diff) {
#define F(x) \
	atomic64_set(&loc->min.x, atomic64_get_set(&mm->min.x, 0)); \
	atomic64_set(&loc->max.x, atomic64_get_set(&mm->max.x, 0)); \
	atomic64_set(&loc->avg.x, run_diff_us ? atomic64_get(&counter_diff->x) * 1000000LL / run_diff_us : 0);
#include "counter_stats_fields.inc"
#undef F
}

#define RTPE_GAUGE_SET_MIN_MAX(field, min_max_struct, val) \
	do { \
		atomic64_min(&min_max_struct.min.field, val); \
		atomic64_max(&min_max_struct.max.field, val); \
		atomic64_add(&min_max_struct.avg.field, val); \
		atomic64_add(&min_max_struct.stddev.field, (val) * (val)); \
		atomic64_inc(&min_max_struct.count.field); \
	} while (0)

extern struct global_stats_gauge rtpe_stats_gauge;

INLINE void stats_gauge_calc_avg_reset(struct global_stats_gauge_min_max *out,
		struct global_stats_gauge_min_max *in_reset)
{
	uint64_t cur, count;

#define Fc(x) \
	atomic64_set(&out->min.x, atomic64_get_set(&in_reset->min.x, cur)); \
	atomic64_set(&out->max.x, atomic64_get_set(&in_reset->max.x, cur)); \
	count = atomic64_get_set(&in_reset->count.x, 0); \
	atomic64_set(&out->count.x, count); \
	atomic64_set(&out->avg.x, count ? atomic64_get_set(&in_reset->avg.x, 0) / count : 0);
#define F(x) \
	cur = atomic64_get(&rtpe_stats_gauge.x); \
	Fc(x)
#define Fd(x) \
	cur = 0; \
	Fc(x)
#define FdA(x, n) for (int i = 0; i < n; i++) { Fd(x[i]) }
#include "gauge_stats_fields.inc"
#undef Fc
#undef F
#undef Fd
#undef FdA
}


void statistics_init(void);
void statistics_free(void);

#endif /* STATISTICS_H_ */
