#ifndef _RTPE_COMMON_STATS_H_
#define _RTPE_COMMON_STATS_H_


#ifdef __KERNEL__
typedef atomic64_t atomic64;
static_assert(sizeof(atomic64_t) == sizeof(int64_t), "atomic64_t != int64_t");
static_assert(sizeof(atomic_t) == sizeof(int), "atomic_t != int");
#else
typedef int atomic_t;
#endif


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

struct stream_stats {
	atomic64			packets;
	atomic64			bytes;
	atomic64			errors;
	atomic64			last_packet;
	atomic_t			tos;
};

struct rtp_stats {
	unsigned int		payload_type;
	uint32_t		clock_rate;
	atomic64		packets;
	atomic64		bytes;
	atomic64		kernel_packets;
	atomic64		kernel_bytes;
};
struct ssrc_stats {
	atomic64		packets;
	atomic64		bytes;
	atomic_t		timestamp;
	atomic_t		ext_seq;
	atomic_t		rtcp_seq;
	uint32_t		lost_bits; // sliding bitfield, [0] = ext_seq
	atomic_t		total_lost;
	atomic_t		transit;
	atomic_t		jitter;
	atomic64		last_packet;
	atomic_t		last_pt;
};

#endif
