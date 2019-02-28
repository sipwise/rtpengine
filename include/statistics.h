#ifndef STATISTICS_H_
#define STATISTICS_H_

#include "aux.h"

struct call;
struct packet_stream;

struct stats {
	atomic64			packets;
	atomic64			bytes;
	atomic64			errors;
	u_int64_t			delay_min;
	u_int64_t			delay_avg;
	u_int64_t			delay_max;
	u_int8_t			in_tos_tclass; /* XXX shouldn't be here - not stats */
	atomic64			foreign_sessions; // unresponsible via redis notification
	atomic64			offers;
	atomic64			answers;
	atomic64			deletes;
};


struct request_time {
	mutex_t lock;
	u_int64_t count;
	struct timeval time_min, time_max, time_avg;
};

struct requests_ps {
	mutex_t lock;
	u_int64_t count;
	u_int64_t ps_min;
	u_int64_t ps_max;
	u_int64_t ps_avg;
};


struct totalstats {
	time_t 			started;
	atomic64		total_timeout_sess;
	atomic64		total_foreign_sessions;
	atomic64		total_rejected_sess;
	atomic64		total_silent_timeout_sess;
	atomic64		total_offer_timeout_sess;
	atomic64		total_final_timeout_sess;
	atomic64		total_regular_term_sess;
	atomic64		total_forced_term_sess;
	atomic64		total_relayed_packets;
	atomic64		total_relayed_errors;
	atomic64		total_nopacket_relayed_sess;
	atomic64		total_oneway_stream_sess;

	u_int64_t               foreign_sessions;
	u_int64_t               own_sessions;
	u_int64_t               total_sessions;

	mutex_t			total_average_lock; /* for these two below */
	u_int64_t		total_managed_sess;
	struct timeval		total_average_call_dur;

	mutex_t			managed_sess_lock; /* for these below */
	u_int64_t		managed_sess_max; /* per graphite interval statistic */
	u_int64_t		managed_sess_min; /* per graphite interval statistic */

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
	atomic64		in_tos_tclass;
};


struct call_stats {
	time_t		last_packet;
	struct stats	totals[4]; /* rtp in, rtcp in, rtp out, rtcp out */
};

extern struct totalstats       rtpe_totalstats;
extern struct totalstats       rtpe_totalstats_interval;
extern mutex_t		       rtpe_totalstats_lastinterval_lock;
extern struct totalstats       rtpe_totalstats_lastinterval;

void statistics_update_oneway(struct call *);
void statistics_update_foreignown_dec(struct call *);
void statistics_update_foreignown_inc(struct call* c);
void statistics_update_totals(struct packet_stream *) ;

void statistics_init(void);

#endif /* STATISTICS_H_ */
