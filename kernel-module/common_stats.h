#ifndef _RTPE_COMMON_STATS_H_
#define _RTPE_COMMON_STATS_H_


struct interface_counter_stats_dir {
#define F(n) atomic64 n;
#include "interface_counter_stats_fields_dir.inc"
#undef F
};
struct interface_counter_stats {
#define F(n) atomic64 n;
#include "interface_counter_stats_fields.inc"
#undef F
};
struct interface_sampled_stats_fields {
#define F(n) atomic64 n;
#include "interface_sampled_stats_fields.inc"
#undef F
};
struct interface_sampled_stats {
	struct interface_sampled_stats_fields sums;
	struct interface_sampled_stats_fields sums_squared;
	struct interface_sampled_stats_fields counts;
};
struct interface_sampled_stats_avg {
	struct interface_sampled_stats_fields avg;
	struct interface_sampled_stats_fields stddev;
};
struct interface_stats_block {
	struct interface_counter_stats_dir	in,
						out;
	struct interface_counter_stats		s;
	struct interface_sampled_stats		sampled;
};


#endif
