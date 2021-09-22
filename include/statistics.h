#ifndef STATISTICS_H_
#define STATISTICS_H_

#include "aux.h"
#include "bencode.h"
#include "rtpengine_config.h"
#include "control_ng.h"

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
#undef FA
};

struct global_stats_gauge_min_max {
	struct global_stats_gauge min;
	struct global_stats_gauge max;
	struct global_stats_gauge avg; // sum while accumulation is running
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

struct global_stats_ax {
	struct global_stats_counter ax; // running accumulator
	struct global_stats_counter intv; // last per-interval values
};
struct global_stats_min_max {
	struct global_stats_counter min;
	struct global_stats_counter max;
	struct global_stats_counter avg; // sum while accumulation is running
	atomic64 count;
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
	int64_t int_value;
	int is_bracket;
	int is_close_bracket;
	int is_brace;
	int is_follow_up;
	int is_int;
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

void statistics_update_oneway(struct call *);
void statistics_update_ip46_inc_dec(struct call *, int op);
void statistics_update_foreignown_dec(struct call *);
void statistics_update_foreignown_inc(struct call* c);

GQueue *statistics_gather_metrics(void);
void statistics_free_metrics(GQueue **);
const char *statistics_ng(bencode_item_t *input, bencode_item_t *output);

INLINE void stats_counters_ax_calc_avg1(atomic64 *ax_var, atomic64 *intv_var, atomic64 *loc_var,
		long long run_diff_us)
{
	uint64_t tmp = atomic64_get_set(ax_var, 0);
	if (loc_var)
		atomic64_set(loc_var, tmp);
	atomic64_set(intv_var, tmp * 1000000LL / run_diff_us);
}

INLINE void stats_counters_ax_calc_avg(struct global_stats_ax *stats, long long run_diff_us,
		struct global_stats_counter *loc)
{
	if (run_diff_us <= 0)
		return;

#define F(x) stats_counters_ax_calc_avg1(&stats->ax.x, &stats->intv.x, loc ? &loc->x : NULL, run_diff_us);
#define FA(x, n) for (int i = 0; i < n; i++) { F(x[i]) }
#include "counter_stats_fields.inc"
#undef F
}

INLINE void stats_counters_min1(atomic64 *min, atomic64 *inp) {
	atomic64_min(min, atomic64_get(inp));
}
INLINE void stats_counters_max1(atomic64 *max, atomic64 *inp) {
	atomic64_max(max, atomic64_get(inp));
}
INLINE void stats_counters_min_max(struct global_stats_min_max *mm, struct global_stats_counter *inp) {
#define F(x) \
	stats_counters_min1(&mm->min.x, &inp->x); \
	stats_counters_max1(&mm->max.x, &inp->x); \
	atomic64_add(&mm->avg.x, atomic64_get(&inp->x));
#include "counter_stats_fields.inc"
#undef F
	atomic64_inc(&mm->count);
}
INLINE void stats_counters_min_max_reset(struct global_stats_min_max *mm, struct global_stats_min_max *loc) {
	uint64_t count = atomic64_get_set(&mm->count, 0);

#define F(x) \
	atomic64_set(&loc->min.x, atomic64_get_set(&mm->min.x, 0)); \
	atomic64_set(&loc->max.x, atomic64_get_set(&mm->max.x, 0)); \
	if (count) \
		atomic64_set(&loc->avg.x, atomic64_get_set(&mm->avg.x, 0) / count); \
	else \
		atomic64_set(&loc->avg.x, 0);
#include "counter_stats_fields.inc"
#undef F
}

#define RTPE_GAUGE_SET_MIN_MAX(field, min_max_struct, val) \
	do { \
		atomic64_min(&min_max_struct.min.field, val); \
		atomic64_max(&min_max_struct.max.field, val); \
		atomic64_add(&min_max_struct.avg.field, val); \
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
#undef Fd
#undef FdA
#define Fd(x) \
	cur = 0; \
	Fc(x)
#define FdA(x, n) for (int i = 0; i < n; i++) { Fd(x[i]) }
#include "gauge_stats_fields.inc"
#undef F
}


void statistics_init(void);
void statistics_free(void);

#endif /* STATISTICS_H_ */
