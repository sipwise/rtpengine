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

// "gauge" style stats
struct global_stats_gauge {
	atomic64			foreign_sessions; // unresponsible via redis notification
	atomic64			transcoded_media;
	atomic64			ipv4_sessions;
	atomic64			ipv6_sessions;
	atomic64			mixed_sessions;
};

// "counter" style stats that are incremental and are kept cumulative or per-interval
struct global_stats_counter {
#define F(x) atomic64 x;
#include "counter_stats_fields.inc"
#undef F
};

struct global_stats_ax {
	struct global_stats_counter ax; // running accumulator
	struct global_stats_counter intv; // last per-interval values
};


struct request_time {
	mutex_t lock;
	uint64_t count;
	struct timeval time_min, time_max, time_avg;
};

struct requests_ps {
	mutex_t lock;
	uint64_t count;
	uint64_t ps_min;
	uint64_t ps_max;
	uint64_t ps_avg;
};


struct totalstats {
	time_t 			started;

	mutex_t			total_average_lock; /* for these two below */
	uint64_t		total_managed_sess;
	struct timeval		total_average_call_dur;

	mutex_t			managed_sess_lock; /* for these below */
	uint64_t		managed_sess_max; /* per graphite interval statistic */
	uint64_t		managed_sess_min; /* per graphite interval statistic */

	mutex_t			total_calls_duration_lock; /* for these two below */
	struct timeval		total_calls_duration_interval;

	struct request_time	offer, answer, delete;
	struct requests_ps	offers_ps, answers_ps, deletes_ps;
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

extern struct totalstats       rtpe_totalstats;
extern struct totalstats       rtpe_totalstats_interval;
extern mutex_t		       rtpe_totalstats_lastinterval_lock;
extern struct totalstats       rtpe_totalstats_lastinterval;

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
#include "counter_stats_fields.inc"
#undef F
}

void statistics_init(void);
void statistics_free(void);

#endif /* STATISTICS_H_ */
