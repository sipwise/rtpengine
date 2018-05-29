#include "call.h"
#include "statistics.h"
#include "graphite.h"
#include "main.h"


struct totalstats       rtpe_totalstats;
struct totalstats       rtpe_totalstats_interval;
mutex_t		       	rtpe_totalstats_lastinterval_lock;
struct totalstats       rtpe_totalstats_lastinterval;


static void timeval_totalstats_average_add(struct totalstats *s, const struct timeval *add) {
	struct timeval dp, oa;

	mutex_lock(&s->total_average_lock);

	// new average = ((old average * old num sessions) + datapoint) / new num sessions
	// ... but this will overflow when num sessions becomes very large

	// timeval_multiply(&t, &s->total_average_call_dur, s->total_managed_sess);
	// timeval_add(&t, &t, add);
	// s->total_managed_sess++;
	// timeval_divide(&s->total_average_call_dur, &t, s->total_managed_sess);

	// alternative:
	// new average = old average + (datapoint / new num sessions) - (old average / new num sessions)

	s->total_managed_sess++;
	timeval_divide(&dp, add, s->total_managed_sess);
	timeval_divide(&oa, &s->total_average_call_dur, s->total_managed_sess);
	timeval_add(&s->total_average_call_dur, &s->total_average_call_dur, &dp);
	timeval_subtract(&s->total_average_call_dur, &s->total_average_call_dur, &oa);

	mutex_unlock(&s->total_average_lock);
}

static void timeval_totalstats_interval_call_duration_add(struct totalstats *s,
		struct timeval *call_start, struct timeval *call_stop,
		struct timeval *interval_start, int interval_dur_s) {

	/* work with graphite interval start val which might be changed elsewhere in the code*/
	struct timeval real_iv_start = *interval_start;
	struct timeval call_duration;
	struct timeval *call_start_in_iv = call_start;

	/* in case graphite interval needs to be the previous one */
	if (timercmp(&real_iv_start, call_stop, >) && interval_dur_s) {
		// round up to nearest while interval_dur_s
		long long d = timeval_diff(&real_iv_start, call_stop);
		d += (interval_dur_s * 1000000) - 1;
		d /= 1000000 * interval_dur_s;
		d *= interval_dur_s;
		struct timeval graph_dur = { .tv_sec = d, .tv_usec = 0LL };
		timeval_subtract(&real_iv_start, interval_start, &graph_dur);
	}

	if (timercmp(&real_iv_start, call_start, >))
		call_start_in_iv = &real_iv_start;

	/* this should never happen and is here for sanitization of output */
	if (timercmp(call_start_in_iv, call_stop, >)) {
		ilog(LOG_ERR, "Call start seems to exceed call stop");
		return;
	}

	timeval_subtract(&call_duration, call_stop, call_start_in_iv);

	mutex_lock(&s->total_calls_duration_lock);
	timeval_add(&s->total_calls_duration_interval,
			&s->total_calls_duration_interval, &call_duration);
	mutex_unlock(&s->total_calls_duration_lock);
}


void statistics_update_totals(struct packet_stream *ps) {
	atomic64_add(&rtpe_totalstats.total_relayed_packets,
			atomic64_get(&ps->stats.packets));
	atomic64_add(&rtpe_totalstats_interval.total_relayed_packets,
		atomic64_get(&ps->stats.packets));
	atomic64_add(&rtpe_totalstats.total_relayed_errors,
		atomic64_get(&ps->stats.errors));
	atomic64_add(&rtpe_totalstats_interval.total_relayed_errors,
		atomic64_get(&ps->stats.errors));
}

void statistics_update_foreignown_dec(struct call* c) {
	if (IS_FOREIGN_CALL(c)) {
		atomic64_dec(&rtpe_stats.foreign_sessions);
	}

	if(IS_OWN_CALL(c)) 	{
		mutex_lock(&rtpe_totalstats_interval.managed_sess_lock);
		rtpe_totalstats_interval.managed_sess_min = MIN(rtpe_totalstats_interval.managed_sess_min,
				g_hash_table_size(rtpe_callhash) - atomic64_get(&rtpe_stats.foreign_sessions));
		mutex_unlock(&rtpe_totalstats_interval.managed_sess_lock);
	}

}

void statistics_update_foreignown_inc(struct call* c) {
	if (IS_OWN_CALL(c)) {
		mutex_lock(&rtpe_totalstats_interval.managed_sess_lock);
		rtpe_totalstats_interval.managed_sess_max = MAX(
				rtpe_totalstats_interval.managed_sess_max,
				g_hash_table_size(rtpe_callhash)
						- atomic64_get(&rtpe_stats.foreign_sessions));
		mutex_unlock(&rtpe_totalstats_interval.managed_sess_lock);
	}
	else if (IS_FOREIGN_CALL(c)) { /* foreign call*/
		atomic64_inc(&rtpe_stats.foreign_sessions);
		atomic64_inc(&rtpe_totalstats.total_foreign_sessions);
	}

}

void statistics_update_oneway(struct call* c) {
	struct packet_stream *ps = NULL, *ps2 = NULL;
	struct call_monologue *ml;
	struct call_media *md;
	GList *k, *o;
	int found = 0;
	GList *l;
	struct timeval tim_result_duration;

	// --- for statistics getting one way stream or no relay at all
	int total_nopacket_relayed_sess = 0;

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;

		// --- go through partner ml and search the RTP
		for (k = ml->medias.head; k; k = k->next) {
			md = k->data;

			for (o = md->streams.head; o; o = o->next) {
				ps = o->data;
				if (PS_ISSET(ps, RTP)) {
					// --- only RTP is interesting
					found = 1;
					break;
				}
			}
			if (found) { break; }
		}
		if (!found)
			ps = NULL;
		found = 0;

		if (ml->active_dialogue) {
			// --- go through partner ml and search the RTP
			for (k = ml->active_dialogue->medias.head; k; k = k->next) {
				md = k->data;

				for (o = md->streams.head; o; o = o->next) {
					ps2 = o->data;
					if (PS_ISSET(ps2, RTP)) {
						// --- only RTP is interesting
						found = 1;
						break;
					}
				}
				if (found) { break; }
			}
		}
		if (!found)
			ps2 = NULL;

		if (ps && ps2 && atomic64_get(&ps2->stats.packets)==0) {
			if (atomic64_get(&ps->stats.packets)!=0 && IS_OWN_CALL(c)){
				if (atomic64_get(&ps->stats.packets)!=0) {
					atomic64_inc(&rtpe_totalstats.total_oneway_stream_sess);
					atomic64_inc(&rtpe_totalstats_interval.total_oneway_stream_sess);
				}
			}
			else {
				total_nopacket_relayed_sess++;
			}
		}
	}

	if (IS_OWN_CALL(c)) {
		atomic64_add(&rtpe_totalstats.total_nopacket_relayed_sess, total_nopacket_relayed_sess / 2);
		atomic64_add(&rtpe_totalstats_interval.total_nopacket_relayed_sess, total_nopacket_relayed_sess / 2);
	}

	if (c->monologues.head) {
		ml = c->monologues.head->data;

		timeval_subtract(&tim_result_duration, &rtpe_now, &ml->started);

		if (IS_OWN_CALL(c)) {
			if (ml->term_reason==TIMEOUT) {
				atomic64_inc(&rtpe_totalstats.total_timeout_sess);
				atomic64_inc(&rtpe_totalstats_interval.total_timeout_sess);
			} else if (ml->term_reason==SILENT_TIMEOUT) {
				atomic64_inc(&rtpe_totalstats.total_silent_timeout_sess);
				atomic64_inc(&rtpe_totalstats_interval.total_silent_timeout_sess);
			} else if (ml->term_reason==OFFER_TIMEOUT) {
				atomic64_inc(&rtpe_totalstats.total_offer_timeout_sess);
				atomic64_inc(&rtpe_totalstats_interval.total_offer_timeout_sess);
			} else if (ml->term_reason==REGULAR) {
				atomic64_inc(&rtpe_totalstats.total_regular_term_sess);
				atomic64_inc(&rtpe_totalstats_interval.total_regular_term_sess);
			} else if (ml->term_reason==FORCED) {
				atomic64_inc(&rtpe_totalstats.total_forced_term_sess);
				atomic64_inc(&rtpe_totalstats_interval.total_forced_term_sess);
			}

			timeval_totalstats_average_add(&rtpe_totalstats, &tim_result_duration);
			timeval_totalstats_average_add(&rtpe_totalstats_interval, &tim_result_duration);
			timeval_totalstats_interval_call_duration_add(
					&rtpe_totalstats_interval, &ml->started, &ml->terminated,
					&rtpe_latest_graphite_interval_start,
					rtpe_config.graphite_interval);
		}

		if (ml->term_reason==FINAL_TIMEOUT) {
			atomic64_inc(&rtpe_totalstats.total_final_timeout_sess);
			atomic64_inc(&rtpe_totalstats_interval.total_final_timeout_sess);
		}
	}

}

void statistics_init() {
	mutex_init(&rtpe_totalstats.total_average_lock);
	mutex_init(&rtpe_totalstats_interval.total_average_lock);
	mutex_init(&rtpe_totalstats_interval.managed_sess_lock);
	mutex_init(&rtpe_totalstats_interval.total_calls_duration_lock);

	time(&rtpe_totalstats.started);
	//rtpe_totalstats_interval.managed_sess_min = 0; // already zeroed
	//rtpe_totalstats_interval.managed_sess_max = 0;

	mutex_init(&rtpe_totalstats_lastinterval_lock);

	mutex_init(&rtpe_totalstats_interval.offer.lock);
	mutex_init(&rtpe_totalstats_interval.answer.lock);
	mutex_init(&rtpe_totalstats_interval.delete.lock);

	mutex_init(&rtpe_totalstats_interval.offers_ps.lock);
	mutex_init(&rtpe_totalstats_interval.answers_ps.lock);
	mutex_init(&rtpe_totalstats_interval.deletes_ps.lock);
}
