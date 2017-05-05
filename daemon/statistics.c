#include "call.h"
#include "statistics.h"

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
	if (timercmp(&real_iv_start, call_stop, >)) {
		struct timeval graph_dur = { .tv_sec = interval_dur_s, .tv_usec = 0LL };
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


void statistics_update_totals(struct callmaster* m, struct packet_stream *ps) {
	atomic64_add(&m->totalstats.total_relayed_packets,
			atomic64_get(&ps->stats.packets));
	atomic64_add(&m->totalstats_interval.total_relayed_packets,
		atomic64_get(&ps->stats.packets));
	atomic64_add(&m->totalstats.total_relayed_errors,
		atomic64_get(&ps->stats.errors));
	atomic64_add(&m->totalstats_interval.total_relayed_errors,
		atomic64_get(&ps->stats.errors));
}

void statistics_update_foreignown_dec(struct call* c) {
	struct callmaster *m;

	m = c->callmaster;

	if (IS_FOREIGN_CALL(c)) {
		atomic64_dec(&m->stats.foreign_sessions);
	}

	if(IS_OWN_CALL(c)) 	{
		mutex_lock(&m->totalstats_interval.managed_sess_lock);
		m->totalstats_interval.managed_sess_min = MIN(m->totalstats_interval.managed_sess_min,
				g_hash_table_size(m->callhash) - atomic64_get(&m->stats.foreign_sessions));
		mutex_unlock(&m->totalstats_interval.managed_sess_lock);
	}

}

void statistics_update_foreignown_inc(struct callmaster *m, struct call* c) {
	if (IS_OWN_CALL(c)) {
		mutex_lock(&m->totalstats_interval.managed_sess_lock);
		m->totalstats_interval.managed_sess_max = MAX(
				m->totalstats_interval.managed_sess_max,
				g_hash_table_size(m->callhash)
						- atomic64_get(&m->stats.foreign_sessions));
		mutex_unlock(&m->totalstats_interval.managed_sess_lock);
	}
	else if (IS_FOREIGN_CALL(c)) { /* foreign call*/
		atomic64_inc(&m->stats.foreign_sessions);
		atomic64_inc(&m->totalstats.total_foreign_sessions);
	}

}

void statistics_update_oneway(struct call* c) {
	struct callmaster *m;
	struct packet_stream *ps=0, *ps2=0;
	struct call_monologue *ml;
	struct call_media *md;
	GList *k, *o;
	int found = 0;
	GList *l;
	struct timeval tim_result_duration;

	m = c->callmaster;

	// --- for statistics getting one way stream or no relay at all
	int total_nopacket_relayed_sess = 0;

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;

		// --- go through partner ml and search the RTP
		for (k = ml->medias.head; k; k = k->next) {
			md = k->data;

			for (o = md->streams.head; o; o = o->next) {
				ps = o->data;
				if ((PS_ISSET(ps, RTP) && !PS_ISSET(ps, RTCP))) {
					// --- only RTP is interesting
					found = 1;
					break;
				}
			}
			if (found) { break; }
		}
		found = 0;

		if (ml->active_dialogue) {
			// --- go through partner ml and search the RTP
			for (k = ml->active_dialogue->medias.head; k; k = k->next) {
				md = k->data;

				for (o = md->streams.head; o; o = o->next) {
					ps2 = o->data;
					if ((PS_ISSET(ps2, RTP) && !PS_ISSET(ps2, RTCP))) {
						// --- only RTP is interesting
						found = 1;
						break;
					}
				}
				if (found) { break; }
			}
		}

		if (ps && ps2 && atomic64_get(&ps2->stats.packets)==0) {
			if (atomic64_get(&ps->stats.packets)!=0 && IS_OWN_CALL(c)){
				if (atomic64_get(&ps->stats.packets)!=0) {
					atomic64_inc(&m->totalstats.total_oneway_stream_sess);
					atomic64_inc(&m->totalstats_interval.total_oneway_stream_sess);
				}
			}
			else {
				total_nopacket_relayed_sess++;
			}
		}
	}

	if (IS_OWN_CALL(c)) {
		atomic64_add(&m->totalstats.total_nopacket_relayed_sess, total_nopacket_relayed_sess / 2);
		atomic64_add(&m->totalstats_interval.total_nopacket_relayed_sess, total_nopacket_relayed_sess / 2);
	}

	if (c->monologues.head) {
		ml = c->monologues.head->data;

		timeval_subtract(&tim_result_duration, &g_now, &ml->started);

		if (IS_OWN_CALL(c)) {
			if (ml->term_reason==TIMEOUT) {
				atomic64_inc(&m->totalstats.total_timeout_sess);
				atomic64_inc(&m->totalstats_interval.total_timeout_sess);
			} else if (ml->term_reason==SILENT_TIMEOUT) {
				atomic64_inc(&m->totalstats.total_silent_timeout_sess);
				atomic64_inc(&m->totalstats_interval.total_silent_timeout_sess);
			} else if (ml->term_reason==REGULAR) {
				atomic64_inc(&m->totalstats.total_regular_term_sess);
				atomic64_inc(&m->totalstats_interval.total_regular_term_sess);
			} else if (ml->term_reason==FORCED) {
				atomic64_inc(&m->totalstats.total_forced_term_sess);
				atomic64_inc(&m->totalstats_interval.total_forced_term_sess);
			}

			timeval_totalstats_average_add(&m->totalstats, &tim_result_duration);
			timeval_totalstats_average_add(&m->totalstats_interval, &tim_result_duration);
			timeval_totalstats_interval_call_duration_add(
					&m->totalstats_interval, &ml->started, &ml->terminated,
					&m->latest_graphite_interval_start,
					m->conf.graphite_interval);
		}

		if (ml->term_reason==FINAL_TIMEOUT) {
			atomic64_inc(&m->totalstats.total_final_timeout_sess);
			atomic64_inc(&m->totalstats_interval.total_final_timeout_sess);
		}
	}

}
