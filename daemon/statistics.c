#include <math.h>
#include <stdarg.h>
#include "call.h"
#include "statistics.h"
#include "graphite.h"
#include "main.h"
#include "control_ng.h"


struct timeval rtpe_started;


mutex_t rtpe_codec_stats_lock;
GHashTable *rtpe_codec_stats;


struct global_stats_gauge rtpe_stats_gauge;			// master values
struct global_gauge_min_max rtpe_gauge_min_max;			// master lifetime min/max

struct global_stats_sampled rtpe_stats_sampled;			// master cumulative values
struct global_sampled_min_max rtpe_sampled_min_max;		// master lifetime min/max

struct global_stats_counter rtpe_stats;				// total, cumulative, master
struct global_stats_counter rtpe_stats_rate;			// per-second, calculated once per timer run


// op can be CMC_INCREMENT or CMC_DECREMENT
// check not to multiple decrement or increment
void statistics_update_ip46_inc_dec(struct call* c, int op) {
	// already incremented
	if (op == CMC_INCREMENT && c->is_call_media_counted) {
		return ;

	// already decremented
	} else if (op == CMC_DECREMENT && !c->is_call_media_counted) {
		return ;
	}

	// offer is ipv4 only
	if (c->is_ipv4_media_offer && !c->is_ipv6_media_offer) {
		// answer is ipv4 only
		if (c->is_ipv4_media_answer && !c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(ipv4_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is ipv6 only
		} else if (!c->is_ipv4_media_answer && c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(mixed_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is both ipv4 and ipv6
		} else if (c->is_ipv4_media_answer && c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(ipv4_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is neither ipv4 nor ipv6
		} else {
			return ;
		}

	// offer is ipv6 only
	} else if (!c->is_ipv4_media_offer && c->is_ipv6_media_offer) {
		// answer is ipv4 only
		if (c->is_ipv4_media_answer && !c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(mixed_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is ipv6 only
		} else if (!c->is_ipv4_media_answer && c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(ipv6_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is both ipv4 and ipv6
		} else if (c->is_ipv4_media_answer && c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(ipv6_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is neither ipv4 nor ipv6
		} else {
			return ;
		}

	// offer is both ipv4 and ipv6
	} else if (c->is_ipv4_media_offer && c->is_ipv6_media_offer) {
		// answer is ipv4 only
		if (c->is_ipv4_media_answer && !c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(ipv4_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is ipv6 only
		} else if (!c->is_ipv4_media_answer && c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(ipv6_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is both ipv4 and ipv6
		} else if (c->is_ipv4_media_answer && c->is_ipv6_media_answer) {
			RTPE_GAUGE_ADD(mixed_sessions, op == CMC_INCREMENT ? 1 : -1);

		// answer is neither ipv4 nor ipv6
		} else {
			return ;
		}

	// offer is neither ipv4 nor ipv6
	} else {
		return ;
	}

	// mark if incremented or decremented
	c->is_call_media_counted = (op == CMC_INCREMENT) ? 1 : 0;
}

void statistics_update_foreignown_dec(struct call* c) {
	if (IS_FOREIGN_CALL(c)) {
		RTPE_GAUGE_DEC(foreign_sessions);
	}
}

void statistics_update_foreignown_inc(struct call* c) {
	if (IS_FOREIGN_CALL(c)) { /* foreign call*/
		RTPE_GAUGE_INC(foreign_sessions);
		RTPE_STATS_INC(foreign_sess);
	}

}

void statistics_update_oneway(struct call* c) {
	struct call_monologue *ml;
	struct call_media *md;
	GList *k, *o;
	GList *l;

	if (IS_OWN_CALL(c)) {
		// --- for statistics getting one way stream or no relay at all
		unsigned int total_nopacket_relayed_sess = 0;
		struct packet_stream *ps, *ps2;

		for (l = c->monologues.head; l; l = l->next) {
			ml = l->data;

			// --- go through partner ml and search the RTP
			for (k = ml->medias.head; k; k = k->next) {
				md = k->data;

				for (o = md->streams.head; o; o = o->next) {
					ps = o->data;
					if (PS_ISSET(ps, RTP)) {
						// --- only RTP is interesting
						goto found;
					}
				}
			}

			continue;

found:;
			struct sink_handler *sh = g_queue_peek_head(&ps->rtp_sinks);
			ps2 = sh ? sh->sink : NULL;
			if (!ps2)
				continue;

			if (atomic64_get(&ps2->stats_in.packets)==0) {
				if (atomic64_get(&ps->stats_in.packets)!=0)
					RTPE_STATS_INC(oneway_stream_sess);
				else
					total_nopacket_relayed_sess++;
			}
		}

		RTPE_STATS_ADD(nopacket_relayed_sess, total_nopacket_relayed_sess / 2);
	}

	if (c->monologues.head) {
		ml = c->monologues.head->data;

		if (IS_OWN_CALL(c)) {
			if (ml->term_reason==TIMEOUT)
				RTPE_STATS_INC(timeout_sess);
			else if (ml->term_reason==SILENT_TIMEOUT)
				RTPE_STATS_INC(silent_timeout_sess);
			else if (ml->term_reason==OFFER_TIMEOUT)
				RTPE_STATS_INC(offer_timeout_sess);
			else if (ml->term_reason==REGULAR)
				RTPE_STATS_INC(regular_term_sess);
			else if (ml->term_reason==FORCED)
				RTPE_STATS_INC(forced_term_sess);

			RTPE_STATS_INC(managed_sess);

			if (!c->destroyed.tv_sec)
				c->destroyed = rtpe_now;
			long long duration = timeval_diff(&c->destroyed, &c->created);
			RTPE_STATS_ADD(call_duration, duration);
			duration /= 1000; // millisecond precision for the squared value to avoid overflows
			RTPE_STATS_ADD(call_duration2, duration * duration);
		}

		if (ml->term_reason==FINAL_TIMEOUT)
			RTPE_STATS_INC(final_timeout_sess);
	}

}


INLINE void prom_metric(GQueue *ret, const char *name, const char *type) {
	struct stats_metric *last = g_queue_peek_tail(ret);
	last->prom_name = name;
	last->prom_type = type;
}
static void prom_label(GQueue *ret, const char *fmt, ...) {
	if (!fmt)
		return;
	va_list ap;
	va_start(ap, fmt);
	struct stats_metric *last = g_queue_peek_tail(ret);
	last->prom_label = g_strdup_vprintf(fmt, ap);
	va_end(ap);
}
#define PROM(name, type) prom_metric(ret, name, type)
#define PROMLAB(fmt, ...) prom_label(ret, fmt, ##__VA_ARGS__)

INLINE void metric_push(GQueue *ret, struct stats_metric *m) {
	struct stats_metric *last = NULL;
	for (GList *l_last = ret->tail; l_last; l_last = l_last->prev) {
		last = l_last->data;
		if (last->label)
			break;
		last = NULL;
	}
	if (!m->is_bracket && last) {
		if (!last->is_bracket || last->is_close_bracket)
			m->is_follow_up = 1;
	}
	else if (m->is_bracket && !m->is_close_bracket && last && last->is_close_bracket)
		m->is_follow_up = 1;
	g_queue_push_tail(ret, m);
}
static void add_metric(GQueue *ret, const char *label, const char *desc, const char *fmt1, const char *fmt2, ...) {
	va_list ap;

	struct stats_metric *m = g_slice_alloc0(sizeof(*m));
	if (label)
		m->label = g_strdup(label);
	if (desc)
		m->descr = g_strdup(desc);
	if (fmt1) {
		va_start(ap, fmt2);
		m->value_short = g_strdup_vprintf(fmt1, ap);
		va_end(ap);
		if (m->value_short[0] == '"' && m->value_short[1] != '\0'
				&& m->value_short[strlen(m->value_short)-1] == '"')
			m->value_raw = g_strndup(m->value_short + 1, strlen(m->value_short) - 2);
	}
	if (fmt2) {
		va_start(ap, fmt2);
		m->value_long = g_strdup_vprintf(fmt2, ap);
		va_end(ap);
	}
	if (fmt1 && fmt1[0] == '%' && (!fmt2 || !strcmp(fmt1, fmt2))) {
		va_start(ap, fmt2);
		if (!strcmp(fmt1, "%u") || !strcmp(fmt1, "%i") || !strcmp(fmt1, "%d")) {
			m->is_int = 1;
			m->int_value = va_arg(ap, int);
		}
		else if (!strcmp(fmt1, "%lu") || !strcmp(fmt1, "%li") || !strcmp(fmt1, "%ld")) {
			m->is_int = 1;
			m->int_value = va_arg(ap, long);
		}
		else if ( !strcmp(fmt1, "%llu") || !strcmp(fmt1, "%lli") || !strcmp(fmt1, "%lld")) {
			m->is_int = 1;
			m->int_value = va_arg(ap, long long);
		}
		else if (!strcmp(fmt1, "%.6f") || !strcmp(fmt1, "%.2f")) {
			m->is_double = 1;
			m->double_value = va_arg(ap, double);
		}
		va_end(ap);
	}
	metric_push(ret, m);
}
static void add_header(GQueue *ret, const char *fmt1, const char *fmt2, ...) {
	va_list ap;

	struct stats_metric *m = g_slice_alloc0(sizeof(*m));
	if (fmt1) {
		va_start(ap, fmt2);
		m->label = g_strdup_vprintf(fmt1, ap);
		va_end(ap);
	}
	if (fmt2) {
		va_start(ap, fmt2);
		m->descr = g_strdup_vprintf(fmt2, ap);
		va_end(ap);
	}
	if (m->label && (
				m->label[0] == '['
				|| m->label[0] == '{'
				|| m->label[0] == '}'
				|| m->label[0] == ']')
			&& m->label[1] == 0)
	{
		m->is_bracket = 1;
		if (m->label[0] == '}' || m->label[0] == ']')
			m->is_close_bracket = 1;
		if (m->label[0] == '{' || m->label[0] == '}')
			m->is_brace = 1;
	}
	metric_push(ret, m);
}

#define METRIC(lb, dsc, fmt1, fmt2, ...) add_metric(ret, lb, dsc, fmt1, fmt2, ## __VA_ARGS__)
#define METRICva METRIC
#define METRICl(dsc, fmt2, ...) add_metric(ret, NULL, dsc, NULL, fmt2, ##__VA_ARGS__)
#define METRICsva(lb, fmt1, ...) add_metric(ret, lb, NULL, fmt1, NULL, ##__VA_ARGS__)
#define METRICs(lb, fmt1, arg) add_metric(ret, lb, NULL, fmt1, NULL, arg)

#define HEADER(fmt1, fmt2, ...) add_header(ret, fmt1, fmt2, ##__VA_ARGS__)
#define HEADERl(fmt2, ...) add_header(ret, NULL, fmt2, ##__VA_ARGS__)


GQueue *statistics_gather_metrics(struct interface_sampled_rate_stats *interface_rate_stats) {
	GQueue *ret = g_queue_new();

	double calls_dur_iv;
	uint64_t cur_sessions, num_sessions, min_sess_iv, max_sess_iv;

	HEADER("{", "");
	HEADER("currentstatistics", "Statistics over currently running sessions:");
	HEADER("{", "");

	rwlock_lock_r(&rtpe_callhash_lock);
	cur_sessions = g_hash_table_size(rtpe_callhash);
	rwlock_unlock_r(&rtpe_callhash_lock);

	METRIC("sessionsown", "Owned sessions", UINT64F, UINT64F, cur_sessions - atomic64_get(&rtpe_stats_gauge.foreign_sessions));
	PROM("sessions", "gauge");
	PROMLAB("type=\"own\"");
	METRIC("sessionsforeign", "Foreign sessions", UINT64F, UINT64F, atomic64_get(&rtpe_stats_gauge.foreign_sessions));
	PROM("sessions", "gauge");
	PROMLAB("type=\"foreign\"");

	METRIC("sessionstotal", "Total sessions", UINT64F, UINT64F, cur_sessions);
	METRIC("transcodedmedia", "Transcoded media", UINT64F, UINT64F, atomic64_get(&rtpe_stats_gauge.transcoded_media));
	PROM("transcoded_media", "gauge");

	METRIC("packetrate_user", "Packets per second (userspace)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.packets_user));
	METRIC("byterate_user", "Bytes per second (userspace)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.bytes_user));
	METRIC("errorrate_user", "Errors per second (userspace)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.errors_user));
	METRIC("packetrate_kernel", "Packets per second (kernel)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.packets_kernel));
	METRIC("byterate_kernel", "Bytes per second (kernel)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.bytes_kernel));
	METRIC("errorrate_kernel", "Errors per second (kernel)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.errors_kernel));
	METRIC("packetrate", "Packets per second (total)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.packets_user) +
			atomic64_get(&rtpe_stats_rate.packets_kernel));
	METRIC("byterate", "Bytes per second (total)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.bytes_user) +
			atomic64_get(&rtpe_stats_rate.bytes_kernel));
	METRIC("errorrate", "Errors per second (total)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_rate.errors_user) +
			atomic64_get(&rtpe_stats_rate.errors_kernel));

	METRIC("media_userspace", "Userspace-only media streams", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_gauge.userspace_streams));
	PROM("mediastreams", "gauge");
	PROMLAB("type=\"userspace\"");

	METRIC("media_kernel", "Kernel-only media streams", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_gauge.kernel_only_streams));
	PROM("mediastreams", "gauge");
	PROMLAB("type=\"kernel\"");

	METRIC("media_mixed", "Mixed kernel/userspace media streams", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats_gauge.kernel_user_streams));
	PROM("mediastreams", "gauge");
	PROMLAB("type=\"mixed\"");

	num_sessions = atomic64_get(&rtpe_stats.managed_sess);
	uint64_t total_duration = atomic64_get(&rtpe_stats.call_duration);
	uint64_t avg_us = num_sessions ? total_duration / num_sessions : 0;

	HEADER("}", "");
	HEADER("totalstatistics", "Total statistics (does not include current running sessions):");
	HEADER("{", "");

	METRIC("uptime", "Uptime of rtpengine", "%llu", "%llu seconds", (long long) timeval_diff(&rtpe_now, &rtpe_started) / 1000000);
	PROM("uptime_seconds", "gauge");

	METRIC("managedsessions", "Total managed sessions", UINT64F, UINT64F, num_sessions);
	PROM("sessions_total", "counter");
	METRIC("rejectedsessions", "Total rejected sessions", UINT64F, UINT64F, atomic64_get(&rtpe_stats.rejected_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"rejected\"");
	METRIC("timeoutsessions", "Total timed-out sessions via TIMEOUT", UINT64F, UINT64F, atomic64_get(&rtpe_stats.timeout_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"timeout\"");
	METRIC("silenttimeoutsessions", "Total timed-out sessions via SILENT_TIMEOUT", UINT64F, UINT64F,atomic64_get(&rtpe_stats.silent_timeout_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"silent_timeout\"");
	METRIC("finaltimeoutsessions", "Total timed-out sessions via FINAL_TIMEOUT", UINT64F, UINT64F,atomic64_get(&rtpe_stats.final_timeout_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"final_timeout\"");
	METRIC("offertimeoutsessions", "Total timed-out sessions via OFFER_TIMEOUT", UINT64F, UINT64F,atomic64_get(&rtpe_stats.offer_timeout_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"offer_timeout\"");
	METRIC("regularterminatedsessions", "Total regular terminated sessions", UINT64F, UINT64F, atomic64_get(&rtpe_stats.regular_term_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"terminated\"");
	METRIC("forcedterminatedsessions", "Total forced terminated sessions", UINT64F, UINT64F, atomic64_get(&rtpe_stats.forced_term_sess));
	PROM("closed_sessions_total", "counter");
	PROMLAB("reason=\"force_terminated\"");

	METRIC("relayedpackets_user", "Total relayed packets (userspace)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.packets_user));
	PROM("packets_total", "counter");
	PROMLAB("type=\"userspace\"");
	METRIC("relayedpacketerrors_user", "Total relayed packet errors (userspace)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.errors_user));
	PROM("packet_errors_total", "counter");
	PROMLAB("type=\"userspace\"");
	METRIC("relayedbytes_user", "Total relayed bytes (userspace)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.bytes_user));
	PROM("bytes_total", "counter");
	PROMLAB("type=\"userspace\"");

	METRIC("relayedpackets_kernel", "Total relayed packets (kernel)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.packets_kernel));
	PROM("packets_total", "counter");
	PROMLAB("type=\"kernel\"");
	METRIC("relayedpacketerrors_kernel", "Total relayed packet errors (kernel)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.errors_kernel));
	PROM("packet_errors_total", "counter");
	PROMLAB("type=\"kernel\"");
	METRIC("relayedbytes_kernel", "Total relayed bytes (kernel)", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.bytes_kernel));
	PROM("bytes_total", "counter");
	PROMLAB("type=\"kernel\"");

	METRIC("relayedpackets", "Total relayed packets", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.packets_kernel) +
			atomic64_get(&rtpe_stats.packets_user));
	METRIC("relayedpacketerrors", "Total relayed packet errors", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.errors_kernel) +
			atomic64_get(&rtpe_stats.errors_user));
	METRIC("relayedbytes", "Total relayed bytes", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.bytes_kernel) +
			atomic64_get(&rtpe_stats.bytes_user));

	METRIC("zerowaystreams", "Total number of streams with no relayed packets", UINT64F, UINT64F, atomic64_get(&rtpe_stats.nopacket_relayed_sess));
	PROM("zero_packet_streams_total", "counter");
	METRIC("onewaystreams", "Total number of 1-way streams", UINT64F, UINT64F,atomic64_get(&rtpe_stats.oneway_stream_sess));
	PROM("one_way_sessions_total", "counter");
	METRICva("avgcallduration", "Average call duration", "%.6f", "%.6f seconds", (double) avg_us / 1000000.0);
	PROM("call_duration_avg", "gauge");

	METRICva("totalcallsduration", "Total calls duration", "%.6f", "%.6f seconds", (double) total_duration / 1000000.0);
	PROM("call_duration_total", "counter");

	total_duration = atomic64_get(&rtpe_stats.call_duration2);
	METRICva("totalcallsduration2", "Total calls duration squared", "%.6f", "%.6f seconds squared", (double) total_duration / 1000000.0);
	PROM("call_duration2_total", "counter");

	double variance = num_sessions ? fabs((double) total_duration / (double) num_sessions - ((double) avg_us / 1000.0) * ((double) avg_us / 1000.0)) : 0.0;
	METRICva("totalcallsduration_stddev", "Total calls duration standard deviation", "%.6f", "%.6f seconds", sqrt(variance) / 1000.0);

	HEADER(NULL, "");
	HEADER("}", "");

	if (graphite_is_enabled()) {
		calls_dur_iv = (double) atomic64_get_na(&rtpe_stats_graphite_diff.total_calls_duration_intv) / 1000000.0;
		min_sess_iv = atomic64_get(&rtpe_gauge_graphite_min_max_sampled.min.total_sessions);
		max_sess_iv = atomic64_get(&rtpe_gauge_graphite_min_max_sampled.max.total_sessions);

		HEADER("intervalstatistics", "Graphite interval statistics (last reported values to graphite):");
		HEADER("{", NULL);

		METRICva("totalcallsduration", "Total calls duration", "%.6f", "%.6f seconds", calls_dur_iv);
		HEADER(NULL, "");

		METRIC("minmanagedsessions", "Min managed sessions", UINT64F, UINT64F, min_sess_iv);
		METRIC("maxmanagedsessions", "Max managed sessions", UINT64F, UINT64F, max_sess_iv);

		for (int i = 0; i < NGC_COUNT; i++) {
			double min = (double) atomic64_get(&rtpe_sampled_graphite_min_max_sampled.min.ng_command_times[i]) / 1000000.0;
			double max = (double) atomic64_get(&rtpe_sampled_graphite_min_max_sampled.max.ng_command_times[i]) / 1000000.0;
			double avg = (double) atomic64_get(&rtpe_sampled_graphite_avg.avg.ng_command_times[i]) / 1000000.0;
			AUTO_CLEANUP(char *min_label, free_gbuf) = g_strdup_printf("min%sdelay", ng_command_strings[i]);
			AUTO_CLEANUP(char *max_label, free_gbuf) = g_strdup_printf("max%sdelay", ng_command_strings[i]);
			AUTO_CLEANUP(char *avg_label, free_gbuf) = g_strdup_printf("avg%sdelay", ng_command_strings[i]);
			AUTO_CLEANUP(char *long_label, free_gbuf) = g_strdup_printf("Min/Max/Avg %s processing delay", ng_command_strings[i]);
			METRICl(long_label, "%.6f/%.6f/%.6f sec", min, max, avg);
			METRICsva(min_label, "%.6f", min);
			METRICsva(max_label, "%.6f", max);
			METRICsva(avg_label, "%.6f", avg);
		}

		for (int i = 0; i < NGC_COUNT; i++) {
			uint64_t min = atomic64_get(&rtpe_rate_graphite_min_max_avg_sampled.min.ng_commands[i]);
			uint64_t max = atomic64_get(&rtpe_rate_graphite_min_max_avg_sampled.max.ng_commands[i]);
			uint64_t avg = atomic64_get(&rtpe_rate_graphite_min_max_avg_sampled.avg.ng_commands[i]);
			AUTO_CLEANUP(char *min_label, free_gbuf) = g_strdup_printf("min%srequestrate", ng_command_strings[i]);
			AUTO_CLEANUP(char *max_label, free_gbuf) = g_strdup_printf("max%srequestrate", ng_command_strings[i]);
			AUTO_CLEANUP(char *avg_label, free_gbuf) = g_strdup_printf("avg%srequestrate", ng_command_strings[i]);
			AUTO_CLEANUP(char *long_label, free_gbuf) = g_strdup_printf("Min/Max/Avg %s requests per second", ng_command_strings[i]);
			METRICl(long_label, "%" PRIu64 "/%" PRIu64 "/%" PRIu64 " per sec", min, max, avg);
			METRICsva(min_label, "%" PRIu64 "", min);
			METRICsva(max_label, "%" PRIu64 "", max);
			METRICsva(avg_label, "%" PRIu64 "", avg);
		}

		HEADER(NULL, "");
		HEADER("}", "");
	}

	struct global_sampled_avg sampled_avgs;
	stats_sampled_avg(&sampled_avgs, &rtpe_stats_sampled);

#define STAT_GET_PRINT_GEN(source, avgs, stat_name, name, divisor, prefix, label...) \
	METRIC(#stat_name "_total", "Sum of all " name " values sampled", "%.6f", "%.6f", \
			(double) atomic64_get(&(source)->sums.stat_name) / (divisor)); \
	PROM(prefix #stat_name "_total", "counter"); \
	PROMLAB(label); \
	METRIC(#stat_name "2_total", "Sum of all " name " square values sampled", "%.6f", "%.6f", \
			(double) atomic64_get(&(source)->sums_squared.stat_name) / (divisor * divisor)); \
	PROM(prefix #stat_name "2_total", "counter"); \
	PROMLAB(label); \
	METRIC(#stat_name "_samples_total", "Total number of " name " samples", UINT64F, UINT64F, \
			atomic64_get(&(source)->counts.stat_name)); \
	PROM(prefix #stat_name "_samples_total", "counter"); \
	PROMLAB(label); \
	METRIC(#stat_name "_average", "Average " name, "%.6f", "%.6f", \
			(double) atomic64_get(&(avgs)->avg.stat_name) / (divisor)); \
	METRIC(#stat_name "_stddev", name " standard deviation", "%.6f", "%.6f", \
			(double) atomic64_get(&(avgs)->stddev.stat_name) / (divisor * divisor));

#define STAT_GET_PRINT(stat_name, name, divisor) \
	STAT_GET_PRINT_GEN(&rtpe_stats_sampled, &sampled_avgs, stat_name, name, divisor, "", NULL)

	HEADER("mos", "MOS statistics:");
	HEADER("{", "");
	STAT_GET_PRINT(mos, "MOS", 10.0);
	HEADER(NULL, "");
	HEADER("}", "");

	HEADER("voip_metrics", "VoIP metrics:");
	HEADER("{", "");
	STAT_GET_PRINT(jitter, "jitter (reported)", 1.0);
	STAT_GET_PRINT(rtt_e2e, "end-to-end round-trip time", 1.0);
	STAT_GET_PRINT(rtt_dsct, "discrete round-trip time", 1.0);
	STAT_GET_PRINT(packetloss, "packet loss", 1.0);
	STAT_GET_PRINT(jitter_measured, "jitter (measured)", 1.0);
	METRIC("packets_lost", "Packets lost", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.packets_lost));
	PROM("packets_lost", "counter");
	METRIC("rtp_duplicates", "Duplicate RTP packets", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.rtp_duplicates));
	PROM("rtp_duplicates", "counter");
	METRIC("rtp_skips", "RTP sequence skips", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.rtp_skips));
	PROM("rtp_skips", "counter");
	METRIC("rtp_seq_resets", "RTP sequence resets", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.rtp_seq_resets));
	PROM("rtp_seq_resets", "counter");
	METRIC("rtp_reordered", "Out-of-order RTP packets", UINT64F, UINT64F,
			atomic64_get(&rtpe_stats.rtp_reordered));
	PROM("rtp_reordered", "counter");
	HEADER(NULL, "");
	HEADER("}", "");

	HEADER("controlstatistics", "Control statistics:");
	HEADER("{", "");
	HEADER("proxies", NULL);
	HEADER("[", NULL);

	GString *tmp = g_string_new("");
	g_string_append_printf(tmp, " %20s ", "Proxy");
	for (int i = 0; i < NGC_COUNT; i++)
		g_string_append_printf(tmp, "| %10s ", ng_command_strings_short[i]);
	HEADERl("%s", tmp->str);
	g_string_free(tmp, TRUE);

	struct control_ng_stats total = {0,};

	mutex_lock(&rtpe_cngs_lock);
	GList *list = g_hash_table_get_values(rtpe_cngs_hash);

	if (!list) {
		//streambuf_printf(replybuffer, "\n                  No proxies have yet tried to send data.");
	}
	for (GList *l = list; l; l = l->next) {
		struct control_ng_stats* cur = l->data;

		HEADER("{", NULL);

		GString *tmp = g_string_new("");
		METRICsva("proxy", "\"%s\"", sockaddr_print_buf(&cur->proxy));
		g_string_append_printf(tmp, " %20s ", sockaddr_print_buf(&cur->proxy));
		for (int i = 0; i < NGC_COUNT; i++) {
			mutex_lock(&cur->cmd[i].lock);

			g_string_append_printf(tmp, "| %10u ", cur->cmd[i].count);
			total.cmd[i].count += cur->cmd[i].count;

			char *mn = g_strdup_printf("%scount", ng_command_strings_short[i]);
			char *lw = g_ascii_strdown(mn, -1);
			METRICs(lw, "%u", cur->cmd[i].count);
			PROM("requests_total", "counter");
			PROMLAB("proxy=\"%s\",request=\"%s\"", sockaddr_print_buf(&cur->proxy),
					ng_command_strings[i]);
			free(mn);
			free(lw);

			mn = g_strdup_printf("%sduration", ng_command_strings_short[i]);
			lw = g_ascii_strdown(mn, -1);
			METRICs(lw, "%.6f", (double) cur->cmd[i].time.tv_sec +
					(double) cur->cmd[i].time.tv_usec / 1000000.);
			PROM("request_seconds_total", "counter");
			PROMLAB("proxy=\"%s\",request=\"%s\"", sockaddr_print_buf(&cur->proxy),
					ng_command_strings[i]);
			free(mn);
			free(lw);

			mutex_unlock(&cur->cmd[i].lock);
		}
		METRICl("", "%s", tmp->str);
		g_string_free(tmp, TRUE);

		int errors = g_atomic_int_get(&cur->errors);
		total.errors += errors;
		METRICs("errorcount", "%i", errors);
		PROM("errors_total", "counter");
		PROMLAB("proxy=\"%s\"", sockaddr_print_buf(&cur->proxy));
		HEADER("}", NULL);

	}
	mutex_unlock(&rtpe_cngs_lock);
	g_list_free(list);

	HEADER("]", "");

	for (int i = 0; i < NGC_COUNT; i++) {
		char *mn = g_strdup_printf("total%scount", ng_command_strings_short[i]);
		char *lw = g_ascii_strdown(mn, -1);
		METRICs(lw, "%u", total.cmd[i].count);
		free(mn);
		free(lw);
	}

	HEADER("}", "");

	HEADER("interfaces", NULL);
	HEADER("[", NULL);
	for (GList *l = all_local_interfaces.head; l; l = l->next) {
		struct local_intf *lif = l->data;
		// only show first-order interface entries: socket families must match
		if (lif->logical->preferred_family != lif->spec->local_address.addr.family)
			continue;

		HEADER("{", NULL);

		METRICsva("name", "\"%s\"", lif->logical->name.s);
		METRICsva("address", "\"%s\"", sockaddr_print_buf(&lif->spec->local_address.addr));

		HEADER("ports", NULL);
		HEADER("{", NULL);

		METRICs("min", "%u", lif->spec->port_pool.min);
		METRICs("max", "%u", lif->spec->port_pool.max);
		unsigned int f = g_atomic_int_get(&lif->spec->port_pool.free_ports);
		unsigned int l = g_atomic_int_get(&lif->spec->port_pool.last_used);
		unsigned int r = lif->spec->port_pool.max - lif->spec->port_pool.min + 1;
		METRICs("used", "%u", r - f);
		PROM("ports_used", "gauge");
		PROMLAB("name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		METRICs("used_pct", "%.2f", (double) (r - f) * 100.0 / r);
		METRICs("free", "%u", f);
		PROM("ports_free", "gauge");
		PROMLAB("name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		METRICs("totals", "%u", r);
		PROM("ports", "gauge");
		PROMLAB("name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		METRICs("last", "%u", l);

		HEADER("}", NULL);

#define F(f) \
		METRICs(#f, UINT64F, atomic64_get(&lif->stats.s.f)); \
		PROM("interface_" #f, "counter"); \
		PROMLAB("name=\"%s\",address=\"%s\"", lif->logical->name.s, \
				sockaddr_print_buf(&lif->spec->local_address.addr));
#include "interface_counter_stats_fields.inc"
#undef F

		// expected to be single thread only, so no locking
		long long time_diff_us;
		struct interface_stats_block *intv_stats
			= interface_sampled_rate_stats_get(interface_rate_stats, lif, &time_diff_us);

		if (intv_stats) {
			HEADER("interval", NULL);
			HEADER("{", NULL);

			struct interface_counter_stats diff;
			interface_counter_calc_diff(&lif->stats.s, &intv_stats->s, &diff);

#define F(f) METRICs(#f, UINT64F, atomic64_get(&diff.f));
#include "interface_counter_stats_fields.inc"
#undef F

			HEADER("}", NULL);

			if (time_diff_us) {
				HEADER("rate", NULL);
				HEADER("{", NULL);

				struct interface_counter_stats rate;
				interface_counter_calc_rate_from_diff(time_diff_us, &diff, &rate);

#define F(f) METRICs(#f, UINT64F, atomic64_get(&rate.f));
#include "interface_counter_stats_fields.inc"
#undef F

				HEADER("}", NULL);
			}
		}

		HEADER("voip_metrics", NULL);
		HEADER("{", NULL);

		struct interface_sampled_stats_avg stat_avg;
		interface_sampled_avg(&stat_avg, &lif->stats.sampled);

#define INTF_SAMPLED_STAT(stat_name, name, divisor, prefix, label...) \
	STAT_GET_PRINT_GEN(&lif->stats.sampled, &stat_avg, stat_name, name, divisor, prefix, label)

		INTF_SAMPLED_STAT(mos, "MOS", 10.0, "interface_",
				"name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		INTF_SAMPLED_STAT(jitter, "jitter (reported)", 1.0, "interface_",
				"name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		INTF_SAMPLED_STAT(rtt_e2e, "end-to-end round-trip time", 1.0, "interface_",
				"name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		INTF_SAMPLED_STAT(rtt_dsct, "discrete round-trip time", 1.0, "interface_",
				"name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		INTF_SAMPLED_STAT(packetloss, "packet loss", 1.0, "interface_",
				"name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));
		INTF_SAMPLED_STAT(jitter_measured, "jitter (measured)", 1.0, "interface_",
				"name=\"%s\",address=\"%s\"", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr));

		HEADER("}", NULL);

		if (intv_stats) {

			HEADER("voip_metrics_interval", NULL);
			HEADER("{", NULL);

			struct interface_sampled_stats diff;
			interface_sampled_calc_diff(&lif->stats.sampled, &intv_stats->sampled, &diff);
			struct interface_sampled_stats_avg avg;
			interface_sampled_avg(&avg, &diff);

			METRIC("mos", "Average interval MOS", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.avg.mos) / 10.0); \
			METRIC("mos_stddev", "Standard deviation interval MOS", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.stddev.mos) / 100.0); \
			METRIC("jitter", "Average interval jitter (reported)", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.avg.jitter)); \
			METRIC("jitter_stddev", "Standard deviation interval jitter (reported)", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.stddev.jitter)); \
			METRIC("rtt_e2e", "Average interval end-to-end round-trip time", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.avg.rtt_e2e)); \
			METRIC("rtt_e2e_stddev", "Standard deviation interval end-to-end round-trip time", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.stddev.rtt_e2e)); \
			METRIC("rtt_dsct", "Average interval discrete round-trip time", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.avg.rtt_dsct)); \
			METRIC("rtt_dsct_stddev", "Standard deviation interval discrete round-trip time", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.stddev.rtt_dsct)); \
			METRIC("packetloss", "Average interval packet loss", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.avg.packetloss)); \
			METRIC("packetloss_stddev", "Standard deviation interval packet loss", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.stddev.packetloss)); \
			METRIC("jitter_measured", "Average interval jitter (measured)", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.avg.jitter_measured)); \
			METRIC("jitter_measured_stddev", "Standard deviation interval jitter (measured)", "%.6f", "%.6f", \
					(double) atomic64_get(&avg.stddev.jitter_measured)); \

			HEADER("}", NULL);
		}

		HEADER("ingress", NULL);
		HEADER("{", NULL);
#define F(f) \
		METRICs(#f, UINT64F, atomic64_get(&lif->stats.in.f)); \
		PROM("interface_" #f, "gauge"); \
		PROMLAB("name=\"%s\",address=\"%s\",direction=\"ingress\"", lif->logical->name.s, \
				sockaddr_print_buf(&lif->spec->local_address.addr));
#include "interface_counter_stats_fields_dir.inc"
#undef F
		HEADER("}", NULL);

		HEADER("egress", NULL);
		HEADER("{", NULL);
#define F(f) \
		METRICs(#f, UINT64F, atomic64_get(&lif->stats.out.f)); \
		PROM("interface_" #f, "gauge"); \
		PROMLAB("name=\"%s\",address=\"%s\",direction=\"egress\"", lif->logical->name.s, \
				sockaddr_print_buf(&lif->spec->local_address.addr));
#include "interface_counter_stats_fields_dir.inc"
#undef F
		HEADER("}", NULL);

		if (intv_stats) {
			HEADER("ingress_interval", NULL);
			HEADER("{", NULL);

			struct interface_counter_stats_dir diff_in;
			interface_counter_calc_diff_dir(&lif->stats.in, &intv_stats->in, &diff_in);

#define F(f) METRICs(#f, UINT64F, atomic64_get(&diff_in.f));
#include "interface_counter_stats_fields_dir.inc"
#undef F

			HEADER("}", NULL);

			HEADER("egress_interval", NULL);
			HEADER("{", NULL);

			struct interface_counter_stats_dir diff_out;
			interface_counter_calc_diff_dir(&lif->stats.out, &intv_stats->out, &diff_out);

#define F(f) METRICs(#f, UINT64F, atomic64_get(&diff_out.f));
#include "interface_counter_stats_fields_dir.inc"
#undef F

			HEADER("}", NULL);

			if (time_diff_us) {
				HEADER("ingress_rate", NULL);
				HEADER("{", NULL);

				struct interface_counter_stats_dir rate;
				interface_counter_calc_rate_from_diff_dir(time_diff_us, &diff_in,
						&rate);

#define F(f) METRICs(#f, UINT64F, atomic64_get(&rate.f));
#include "interface_counter_stats_fields_dir.inc"
#undef F

				HEADER("}", NULL);

				HEADER("egress_rate", NULL);
				HEADER("{", NULL);

				interface_counter_calc_rate_from_diff_dir(time_diff_us, &diff_out,
						&rate);

#define F(f) METRICs(#f, UINT64F, atomic64_get(&rate.f));
#include "interface_counter_stats_fields_dir.inc"
#undef F

				HEADER("}", NULL);
			}
		}

		HEADER("}", NULL);
	}
	HEADER("]", NULL);

	mutex_lock(&rtpe_codec_stats_lock);
	HEADER("transcoders", NULL);
	HEADER("[", "");
	GList *chains = g_hash_table_get_keys(rtpe_codec_stats);

	int last_tv_sec = rtpe_now.tv_sec - 1;
	unsigned int idx = last_tv_sec & 1;
	for (GList *l = chains; l; l = l->next) {
		char *chain = l->data;
		struct codec_stats *stats_entry = g_hash_table_lookup(rtpe_codec_stats, chain);
		HEADER("{", "");
		METRICsva("chain", "\"%s\"", chain);
		METRICs("num", "%i", g_atomic_int_get(&stats_entry->num_transcoders));
		PROM("transcoders", "gauge");
		PROMLAB("chain=\"%s\"", chain);
		if (g_atomic_int_get(&stats_entry->last_tv_sec[idx]) == last_tv_sec) {
			METRICs("packetrate", UINT64F, atomic64_get(&stats_entry->packets_input[idx]));
			METRICs("byterate", UINT64F, atomic64_get(&stats_entry->bytes_input[idx]));
			METRICs("samplerate", UINT64F, atomic64_get(&stats_entry->pcm_samples[idx]));
		}
		METRICs("packets", UINT64F, atomic64_get(&stats_entry->packets_input[2]));
		PROM("transcode_packets_total", "counter");
		PROMLAB("chain=\"%s\"", chain);
		METRICs("bytes", UINT64F, atomic64_get(&stats_entry->bytes_input[2]));
		PROM("transcode_bytes_total", "counter");
		PROMLAB("chain=\"%s\"", chain);
		METRICs("samples", UINT64F, atomic64_get(&stats_entry->pcm_samples[2]));
		PROM("transcode_samples_total", "counter");
		PROMLAB("chain=\"%s\"", chain);
		HEADER("}", "");
	}

	mutex_unlock(&rtpe_codec_stats_lock);
	g_list_free(chains);
	HEADER("]", "");

	HEADER("}", NULL);

	return ret;
}
#pragma GCC diagnostic warning "-Wformat-zero-length"

static void free_stats_metric(void *p) {
	struct stats_metric *m = p;
	g_free(m->descr);
	g_free(m->label);
	g_free(m->value_long);
	g_free(m->value_short);
	g_free(m->value_raw);
	g_free(m->prom_label);
	g_slice_free1(sizeof(*m), m);
}

void statistics_free_metrics(GQueue **q) {
	g_queue_free_full(*q, free_stats_metric);
	*q = NULL;
}

void statistics_free() {
	mutex_destroy(&rtpe_codec_stats_lock);
	g_hash_table_destroy(rtpe_codec_stats);
}

static void codec_stats_free(void *p) {
	struct codec_stats *stats_entry = p;
	free(stats_entry->chain);
	g_free(stats_entry->chain_brief);
	g_slice_free1(sizeof(*stats_entry), stats_entry);
}

void statistics_init() {
	gettimeofday(&rtpe_started, NULL);
	//rtpe_totalstats_interval.managed_sess_min = 0; // already zeroed
	//rtpe_totalstats_interval.managed_sess_max = 0;

	mutex_init(&rtpe_codec_stats_lock);
	rtpe_codec_stats = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, codec_stats_free);
}

const char *statistics_ng(bencode_item_t *input, bencode_item_t *output) {
	AUTO_CLEANUP_INIT(GQueue *metrics, statistics_free_metrics, statistics_gather_metrics(NULL));
	AUTO_CLEANUP_INIT(GQueue bstack, g_queue_clear, G_QUEUE_INIT);

	bencode_item_t *dict = output;
	const char *sub_label = "statistics"; // top level
	bencode_buffer_t *buf = output->buffer;

	for (GList *l = metrics->head; l; l = l->next) {
		struct stats_metric *m = l->data;
		if (!m->label)
			continue;

		// key:value entry?
		if (m->value_short) {
			if (m->is_int)
				bencode_dictionary_add_integer(dict, bencode_strdup(buf, m->label),
						m->int_value);
			else if (m->value_raw)
				bencode_dictionary_add_string_dup(dict, bencode_strdup(buf, m->label),
						m->value_raw);
			else
				bencode_dictionary_add_string_dup(dict, bencode_strdup(buf, m->label),
						m->value_short);
			continue;
		}

		// list or dict end?
		if (m->is_close_bracket) {
			dict = g_queue_pop_tail(&bstack);
			assert(dict != NULL);
			continue;
		}

		// label without value precedes an immediate sub-entry, so save the label
		if (!m->is_bracket) {
			assert(sub_label == NULL);
			sub_label = m->label;
			continue;
		}

		// open bracket of some sort - new sub-entry follows
		bencode_item_t *sub = NULL;
		if (m->is_brace)
			sub = bencode_dictionary(buf);
		else
			sub = bencode_list(buf);

		assert(sub != NULL);

		// is this a dictionary?
		if (dict->type == BENCODE_DICTIONARY) {
			assert(sub_label != NULL);
			bencode_dictionary_add(dict, bencode_strdup(buf, sub_label), sub);
		}
		else if (dict->type == BENCODE_LIST)
			bencode_list_add(dict, sub);
		else
			abort();

		sub_label = NULL;
		g_queue_push_tail(&bstack, dict);
		dict = sub;
	}

	return NULL;
}
