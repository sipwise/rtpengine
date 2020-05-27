#include "call.h"
#include "statistics.h"
#include "graphite.h"
#include "main.h"
#include "control_ng.h"


struct totalstats       rtpe_totalstats;
struct totalstats       rtpe_totalstats_interval;
mutex_t		       	rtpe_totalstats_lastinterval_lock;
struct totalstats       rtpe_totalstats_lastinterval;


mutex_t rtpe_codec_stats_lock;
GHashTable *rtpe_codec_stats;


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

#define METRIC(lb, dsc, fmt1, fmt2, ...) \
	do { \
		struct stats_metric *m = g_slice_alloc0(sizeof(*m)); \
		m->label = g_strdup(lb); \
		m->descr = g_strdup(dsc); \
		if (fmt1) \
			m->value_short = g_strdup_printf(fmt1, ## __VA_ARGS__); \
		if (fmt2) \
			m->value_long = g_strdup_printf(fmt2, ## __VA_ARGS__); \
		g_queue_push_tail(ret, m); \
	} while (0)

#define HEADER(fmt1, fmt2, ...) \
	do { \
		struct stats_metric *m = g_slice_alloc0(sizeof(*m)); \
		if (fmt1) \
			m->label = g_strdup_printf(fmt1, ## __VA_ARGS__); \
		if (fmt2) \
			m->descr = g_strdup_printf(fmt2, ## __VA_ARGS__); \
		g_queue_push_tail(ret, m); \
	} while (0)

GQueue *statistics_gather_metrics(void) {
	GQueue *ret = g_queue_new();

	struct timeval avg, calls_dur_iv;
	u_int64_t num_sessions, min_sess_iv, max_sess_iv;
	struct request_time offer_iv, answer_iv, delete_iv;
	struct requests_ps offers_ps, answers_ps, deletes_ps;

	mutex_lock(&rtpe_totalstats.total_average_lock);
	avg = rtpe_totalstats.total_average_call_dur;
	num_sessions = rtpe_totalstats.total_managed_sess;
	mutex_unlock(&rtpe_totalstats.total_average_lock);

	HEADER(NULL, "");
	METRIC("totalstatistics", "Total statistics (does not include current running sessions)", NULL, NULL);
	HEADER(NULL, "");

	METRIC("uptime", "Uptime of rtpengine", "%llu", "%llu seconds", (unsigned long long) time(NULL)-rtpe_totalstats.started);

	METRIC("managedsessions", "Total managed sessions", UINT64F, UINT64F, num_sessions);
	METRIC("rejectedsessions", "Total rejected sessions", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_rejected_sess));
	METRIC("timeoutsessions", "Total timed-out sessions via TIMEOUT", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_timeout_sess));
	METRIC("silenttimeoutsessions", "Total timed-out sessions via SILENT_TIMEOUT", UINT64F, UINT64F,atomic64_get(&rtpe_totalstats.total_silent_timeout_sess));
	METRIC("finaltimeoutsessions", "Total timed-out sessions via FINAL_TIMEOUT", UINT64F, UINT64F,atomic64_get(&rtpe_totalstats.total_final_timeout_sess));
	METRIC("offertimeoutsessions", "Total timed-out sessions via OFFER_TIMEOUT", UINT64F, UINT64F,atomic64_get(&rtpe_totalstats.total_offer_timeout_sess));
	METRIC("regularterminatedsessions", "Total regular terminated sessions", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_regular_term_sess));
	METRIC("forcedterminatedsessions", "Total forced terminated sessions", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_forced_term_sess));
	METRIC("relayedpackets", "Total relayed packets", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_relayed_packets));
	METRIC("relayedpacketerrors", "Total relayed packet errors", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_relayed_errors));
	METRIC("zerowaystreams", "Total number of streams with no relayed packets", UINT64F, UINT64F, atomic64_get(&rtpe_totalstats.total_nopacket_relayed_sess));
	METRIC("onewaystreams", "Total number of 1-way streams", UINT64F, UINT64F,atomic64_get(&rtpe_totalstats.total_oneway_stream_sess));
	METRIC("avgcallduration", "Average call duration", "%ld.%06ld", "%ld.%06ld", avg.tv_sec, avg.tv_usec);

	mutex_lock(&rtpe_totalstats_lastinterval_lock);
	calls_dur_iv = rtpe_totalstats_lastinterval.total_calls_duration_interval;
	min_sess_iv = rtpe_totalstats_lastinterval.managed_sess_min;
	max_sess_iv = rtpe_totalstats_lastinterval.managed_sess_max;
	offer_iv = rtpe_totalstats_lastinterval.offer;
	answer_iv = rtpe_totalstats_lastinterval.answer;
	delete_iv = rtpe_totalstats_lastinterval.delete;
	offers_ps = rtpe_totalstats_lastinterval.offers_ps;
	answers_ps = rtpe_totalstats_lastinterval.answers_ps;
	deletes_ps = rtpe_totalstats_lastinterval.deletes_ps;
	mutex_unlock(&rtpe_totalstats_lastinterval_lock);

	HEADER(NULL, "");
	HEADER(NULL, "");
	METRIC("intervalstatistics", "Graphite interval statistics (last reported values to graphite)", NULL, NULL);

	METRIC("totalcallsduration", "Total calls duration", "%ld.%06ld", "%ld.%06ld", calls_dur_iv.tv_sec,calls_dur_iv.tv_usec);
	HEADER(NULL, "");

	METRIC("minmanagedsessions", "Min managed sessions", UINT64F, UINT64F, min_sess_iv);
	METRIC("maxmanagedsessions", "Max managed sessions", UINT64F, UINT64F, max_sess_iv);

	METRIC(NULL, "Min/Max/Avg offer processing delay", NULL, "%llu.%06llu/%llu.%06llu/%llu.%06llu sec",
			(unsigned long long)offer_iv.time_min.tv_sec,(unsigned long long)offer_iv.time_min.tv_usec,
			(unsigned long long)offer_iv.time_max.tv_sec,(unsigned long long)offer_iv.time_max.tv_usec,
			(unsigned long long)offer_iv.time_avg.tv_sec,(unsigned long long)offer_iv.time_avg.tv_usec);
	METRIC("minofferdelay", NULL, "%llu.%06llu", NULL, (unsigned long long)offer_iv.time_min.tv_sec,(unsigned long long)offer_iv.time_min.tv_usec);
	METRIC("maxofferdelay", NULL, "%llu.%06llu", NULL, (unsigned long long)offer_iv.time_max.tv_sec,(unsigned long long)offer_iv.time_max.tv_usec);
	METRIC("avgofferdelay", NULL, "%llu.%06llu", NULL, (unsigned long long)offer_iv.time_avg.tv_sec,(unsigned long long)offer_iv.time_avg.tv_usec);
	METRIC(NULL, "Min/Max/Avg answer processing delay", NULL, "%llu.%06llu/%llu.%06llu/%llu.%06llu sec",
			(unsigned long long)answer_iv.time_min.tv_sec,(unsigned long long)answer_iv.time_min.tv_usec,
			(unsigned long long)answer_iv.time_max.tv_sec,(unsigned long long)answer_iv.time_max.tv_usec,
			(unsigned long long)answer_iv.time_avg.tv_sec,(unsigned long long)answer_iv.time_avg.tv_usec);
	METRIC("minanswerdelay", NULL, "%llu.%06llu", NULL, (unsigned long long)answer_iv.time_min.tv_sec,(unsigned long long)answer_iv.time_min.tv_usec);
	METRIC("maxanswerdelay", NULL, "%llu.%06llu", NULL, (unsigned long long)answer_iv.time_max.tv_sec,(unsigned long long)answer_iv.time_max.tv_usec);
	METRIC("avganswerdelay", NULL, "%llu.%06llu", NULL, (unsigned long long)answer_iv.time_avg.tv_sec,(unsigned long long)answer_iv.time_avg.tv_usec);
	METRIC(NULL, "Min/Max/Avg delete processing delay", NULL, "%llu.%06llu/%llu.%06llu/%llu.%06llu sec",
			(unsigned long long)delete_iv.time_min.tv_sec,(unsigned long long)delete_iv.time_min.tv_usec,
			(unsigned long long)delete_iv.time_max.tv_sec,(unsigned long long)delete_iv.time_max.tv_usec,
			(unsigned long long)delete_iv.time_avg.tv_sec,(unsigned long long)delete_iv.time_avg.tv_usec);
	METRIC("mindeletedelay", NULL, "%llu.%06llu", NULL, (unsigned long long)delete_iv.time_min.tv_sec,(unsigned long long)delete_iv.time_min.tv_usec);
	METRIC("maxdeletedelay", NULL, "%llu.%06llu", NULL, (unsigned long long)delete_iv.time_max.tv_sec,(unsigned long long)delete_iv.time_max.tv_usec);
	METRIC("avgdeletedelay", NULL, "%llu.%06llu", NULL, (unsigned long long)delete_iv.time_avg.tv_sec,(unsigned long long)delete_iv.time_avg.tv_usec);

	METRIC(NULL, "Min/Max/Avg offer requests per second", NULL, "%llu/%llu/%llu per sec",
			(unsigned long long)offers_ps.ps_min,
			(unsigned long long)offers_ps.ps_max,
			(unsigned long long)offers_ps.ps_avg);
	METRIC("minofferrequestrate", NULL, "%llu", NULL, (unsigned long long)offers_ps.ps_min);
	METRIC("maxofferrequestrate", NULL, "%llu", NULL, (unsigned long long)offers_ps.ps_max);
	METRIC("avgofferrequestrate", NULL, "%llu", NULL, (unsigned long long)offers_ps.ps_avg);
	METRIC(NULL, "Min/Max/Avg answer requests per second", NULL, "%llu/%llu/%llu per sec",
			(unsigned long long)answers_ps.ps_min,
			(unsigned long long)answers_ps.ps_max,
			(unsigned long long)answers_ps.ps_avg);
	METRIC("minanswerrequestrate", NULL, "%llu", NULL,	(unsigned long long)answers_ps.ps_min);
	METRIC("maxanswerrequestrate", NULL, "%llu", NULL, (unsigned long long)answers_ps.ps_max);
	METRIC("avganswerrequestrate", NULL, "%llu", NULL, (unsigned long long)answers_ps.ps_avg);
	METRIC(NULL, "Min/Max/Avg delete requests per second", NULL, "%llu/%llu/%llu per sec",
			(unsigned long long)deletes_ps.ps_min,
			(unsigned long long)deletes_ps.ps_max,
			(unsigned long long)deletes_ps.ps_avg);
	METRIC("mindeleterequestrate", NULL, "%llu", NULL, (unsigned long long)deletes_ps.ps_min);
	METRIC("maxdeleterequestrate", NULL, "%llu", NULL, (unsigned long long)deletes_ps.ps_max);
	METRIC("avgdeleterequestrate", NULL, "%llu", NULL, (unsigned long long)deletes_ps.ps_avg);

	METRIC("controlstatistics", "Control statistics", NULL, NULL);
	HEADER(NULL, "");

	HEADER(NULL, " %20s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s ",
			"Proxy", "Offer", "Answer", "Delete", "Ping", "List", "Query", "StartRec", "StopRec", "Errors", "BlkDTMF", "UnblkDTMF");

	struct control_ng_stats total = {0,};

	mutex_lock(&rtpe_cngs_lock);
	GList *list = g_hash_table_get_values(rtpe_cngs_hash);

	if (!list) {
		//streambuf_printf(replybuffer, "\n                  No proxies have yet tried to send data.");
	}
	for (GList *l = list; l; l = l->next) {
		struct control_ng_stats* cur = l->data;
		METRIC(NULL, "", NULL, " %20s | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u",
				sockaddr_print_buf(&cur->proxy),
				cur->offer,
				cur->answer,
				cur->delete,
				cur->ping,
				cur->list,
				cur->query,
				cur->start_recording,
				cur->stop_recording,
				cur->errors,
				cur->block_dtmf,
				cur->unblock_dtmf);

		total.ping += cur->ping;
		total.offer += cur->offer;
		total.answer += cur->answer;
		total.delete += cur->delete;
		total.query += cur->query;
		total.list += cur->list;
		total.start_recording += cur->start_recording;
		total.stop_recording += cur->stop_recording;
		total.start_forwarding += cur->start_forwarding;
		total.stop_forwarding += cur->stop_forwarding;
		total.block_dtmf += cur->block_dtmf;
		total.unblock_dtmf += cur->unblock_dtmf;
		total.block_media += cur->block_media;
		total.unblock_media += cur->unblock_media;
		total.play_media += cur->play_media;
		total.stop_media += cur->stop_media;
		total.play_dtmf += cur->play_dtmf;
		total.errors += cur->errors;
		METRIC("proxy", NULL, "%s", NULL, sockaddr_print_buf(&cur->proxy));
		METRIC("pingcount", NULL, "%u", NULL, cur->ping);
		METRIC("offercount", NULL, "%u", NULL, cur->offer);
		METRIC("answercount", NULL, "%u", NULL, cur->answer);
		METRIC("deletecount", NULL, "%u", NULL, cur->delete);
		METRIC("querycount", NULL, "%u", NULL, cur->query);
		METRIC("listcount", NULL, "%u", NULL, cur->list);
		METRIC("startreccount", NULL, "%u", NULL, cur->start_recording);
		METRIC("stopreccount", NULL, "%u", NULL, cur->stop_recording);
		METRIC("startfwdcount", NULL, "%u", NULL, cur->start_forwarding);
		METRIC("stopfwdcount", NULL, "%u", NULL, cur->stop_forwarding);
		METRIC("blkdtmfcount", NULL, "%u", NULL, cur->block_dtmf);
		METRIC("unblkdtmfcount", NULL, "%u", NULL, cur->unblock_dtmf);
		METRIC("blkmedia", NULL, "%u", NULL, cur->block_media);
		METRIC("unblkmedia", NULL, "%u", NULL, cur->unblock_media);
		METRIC("playmedia", NULL, "%u", NULL, cur->play_media);
		METRIC("stopmedia", NULL, "%u", NULL, cur->stop_media);
		METRIC("playdtmf", NULL, "%u", NULL, cur->play_dtmf);
		METRIC("errorcount", NULL, "%u", NULL, cur->errors);

	}
	mutex_unlock(&rtpe_cngs_lock);
	g_list_free(list);

	return ret;
}

static void free_stats_metric(void *p) {
	struct stats_metric *m = p;
	g_free(m->descr);
	g_free(m->label);
	g_free(m->value_long);
	g_free(m->value_short);
	g_slice_free1(sizeof(*m), m);
}

void statistics_free_metrics(GQueue **q) {
	g_queue_free_full(*q, free_stats_metric);
	*q = NULL;
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

	mutex_init(&rtpe_codec_stats_lock);
	rtpe_codec_stats = g_hash_table_new(g_str_hash, g_str_equal);
}
