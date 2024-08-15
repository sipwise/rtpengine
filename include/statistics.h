#ifndef STATISTICS_H_
#define STATISTICS_H_

#include "helpers.h"
#include "bencode.h"
#include "control_ng.h"
#include "graphite.h"

// "gauge" style stats
struct global_stats_gauge {
#define F(x) atomic64 x;
#include "gauge_stats_fields.inc"
#undef F
};

// high/low water marks
struct global_gauge_min_max {
	struct global_stats_gauge min;
	struct global_stats_gauge max;
};

// "sampled" style stats
struct global_stats_sampled_fields {
#define F(x) atomic64 x;
#define FA(x, n) atomic64 x[n];
#include "sampled_stats_fields.inc"
#undef F
#undef FA
};

struct global_stats_sampled {
	struct global_stats_sampled_fields sums;
	struct global_stats_sampled_fields sums_squared;
	struct global_stats_sampled_fields counts;
};
struct global_sampled_min_max {
	struct global_stats_sampled_fields min;
	struct global_stats_sampled_fields max;
};
struct global_sampled_avg {
	struct global_stats_sampled_fields avg;
	struct global_stats_sampled_fields stddev;
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

TYPED_GQUEUE(stats_metric, stats_metric)


struct call_stats {
	time_t		last_packet;
	struct stream_stats	totals[4]; /* rtp in, rtcp in, rtp out, rtcp out */
};

extern struct timeval rtpe_started;

extern mutex_t rtpe_codec_stats_lock;
extern codec_stats_ht rtpe_codec_stats;


extern struct global_stats_gauge rtpe_stats_gauge;			// master values
extern struct global_gauge_min_max rtpe_gauge_min_max;			// master lifetime min/max

#define RTPE_GAUGE_SET_MIN_MAX(field, min_max_struct, val) \
	do { \
		atomic64_min(&min_max_struct.min.field, val); \
		atomic64_max(&min_max_struct.max.field, val); \
	} while (0)
#define RTPE_GAUGE_SET(field, num) \
	do { \
		atomic64_set_na(&rtpe_stats_gauge.field, num); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_gauge_min_max, num); \
		if (graphite_is_enabled()) \
			RTPE_GAUGE_SET_MIN_MAX(field, rtpe_gauge_graphite_min_max, num); \
	} while (0)
#define RTPE_GAUGE_ADD(field, num) \
	do { \
		uint64_t __old = atomic64_add_na(&rtpe_stats_gauge.field, num); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_gauge_min_max, __old + num); \
		if (graphite_is_enabled()) \
			RTPE_GAUGE_SET_MIN_MAX(field, rtpe_gauge_graphite_min_max, __old + num); \
	} while (0)
#define RTPE_GAUGE_INC(field) RTPE_GAUGE_ADD(field, 1)
#define RTPE_GAUGE_DEC(field) RTPE_GAUGE_ADD(field, -1)


extern struct global_stats_sampled rtpe_stats_sampled;			// master cumulative values
extern struct global_sampled_min_max rtpe_sampled_min_max;		// master lifetime min/max

#define RTPE_STATS_SAMPLE(field, num) \
	do { \
		atomic64_add_na(&rtpe_stats_sampled.sums.field, num); \
		atomic64_add_na(&rtpe_stats_sampled.sums_squared.field, num * num); \
		atomic64_inc_na(&rtpe_stats_sampled.counts.field); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_sampled_min_max, num); \
		RTPE_GAUGE_SET_MIN_MAX(field, rtpe_sampled_graphite_min_max, num); \
	} while (0)
// TODO: ^ skip doing this for graphite if it's not actually enabled
#define RTPE_SAMPLE_SFD(field, num, sfd) \
	do { \
		RTPE_STATS_SAMPLE(field, num); \
		if (sfd) { \
			struct local_intf *__intf = sfd->local_intf; \
			atomic64_add_na(&__intf->stats->sampled.sums.field, num); \
			atomic64_add_na(&__intf->stats->sampled.sums_squared.field, num * num); \
			atomic64_inc_na(&__intf->stats->sampled.counts.field); \
		} \
	} while (0)

extern struct global_stats_counter *rtpe_stats;			// total, cumulative, master
extern struct global_stats_counter rtpe_stats_rate;		// per-second, calculated once per timer run
extern struct global_stats_counter rtpe_stats_intv;		// per-second, calculated once per timer run

#define RTPE_STATS_ADD(field, num) atomic64_add_na(&rtpe_stats->field, num)
#define RTPE_STATS_INC(field) RTPE_STATS_ADD(field, 1)



void statistics_update_oneway(call_t *);
void statistics_update_ip46_inc_dec(call_t *, int op);
void statistics_update_foreignown_dec(call_t *);
void statistics_update_foreignown_inc(call_t * c);

stats_metric_q *statistics_gather_metrics(struct interface_sampled_rate_stats *);
void statistics_free_metrics(stats_metric_q *);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(stats_metric_q, statistics_free_metrics)
const char *statistics_ng(ng_command_ctx_t *);
enum thread_looper_action call_rate_stats_updater(void);

/**
 * Calculation of the call rate counters.
 * If used with the `stats_rate_min_max()` must only be called in advance, so before that.
 */
INLINE void stats_counters_calc_rate(const struct global_stats_counter *stats, long long run_diff_us,
		struct global_stats_counter *intv, struct global_stats_counter *rate)
{
#define F(x) atomic64_calc_rate(&stats->x, run_diff_us, &intv->x, &rate->x);
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
#undef FA
}

INLINE void stats_counters_calc_diff(const struct global_stats_counter *stats,
		struct global_stats_counter *intv, struct global_stats_counter *diff)
{
#define F(x) atomic64_calc_diff(&stats->x, &intv->x, &diff->x);
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
#undef FA
}

/**
 * Update the running min/max counter `mm` with the newly calculated per-sec rate values `inp`.
 * If used with the `stats_counters_calc_rate()`, it must be called only after that.
 */
INLINE void stats_rate_min_max(struct global_rate_min_max *mm, struct global_stats_counter *inp) {
#define F(x) \
	atomic64_mina(&mm->min.x, &inp->x); \
	atomic64_maxa(&mm->max.x, &inp->x);
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
#undef FA
}
// sample running min/max from `mm` into `loc` and reset `mm` to zero.
// calculate average values in `loc` from `counter_diff` and `time_diff_us`
INLINE void stats_rate_min_max_avg_sample(struct global_rate_min_max *mm, struct global_rate_min_max_avg *loc,
		long long run_diff_us, const struct global_stats_counter *counter_diff) {
#define F(x) STAT_MIN_MAX_AVG(x, mm, loc, run_diff_us, counter_diff)
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
#undef FA
}

INLINE void stats_sampled_calc_diff(const struct global_stats_sampled *stats,
		struct global_stats_sampled *intv, struct global_stats_sampled *diff)
{
#define F(x) STAT_SAMPLED_CALC_DIFF(x, stats, intv, diff)
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "sampled_stats_fields.inc"
#undef F
#undef FA
}
// sample running min/max from `mm` into `loc` and reset `mm` to zero.
INLINE void stats_sampled_min_max_sample(struct global_sampled_min_max *mm,
		struct global_sampled_min_max *loc) {
#define F(x) STAT_MIN_MAX_RESET_ZERO(x, mm, loc)
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "sampled_stats_fields.inc"
#undef F
#undef FA
}
INLINE void stats_sampled_avg(struct global_sampled_avg *loc,
		const struct global_stats_sampled *diff) {
#define F(x) STAT_SAMPLED_AVG_STDDEV(x, loc, diff)
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "sampled_stats_fields.inc"
#undef F
#undef FA
}

// sample running min/max from `in_reset` into `out` and reset `in_reset` to the current value.
INLINE void stats_gauge_min_max_sample(struct global_gauge_min_max *out,
		struct global_gauge_min_max *in_reset, const struct global_stats_gauge *cur)
{
#define F(x) STAT_MIN_MAX(x, out, in_reset, cur)
#include "gauge_stats_fields.inc"
#undef F
}


void statistics_init(void);
void statistics_free(void);

#endif /* STATISTICS_H_ */
