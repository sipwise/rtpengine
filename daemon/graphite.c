/*
 * graphite.c
 *
 *  Created on: Jan 19, 2015
 *      Author: fmetz
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "log.h"
#include "call.h"
#include "graphite.h"
#include "socket.h"
#include "statistics.h"
#include "main.h"

struct timeval rtpe_latest_graphite_interval_start;

static socket_t graphite_sock;
static int connection_state = STATE_DISCONNECTED;
//struct totalstats totalstats_prev;
static time_t next_run;
// HEAD: static time_t rtpe_now, next_run;
static char* graphite_prefix = NULL;
static struct timeval graphite_interval_tv;
static struct totalstats graphite_stats;

void set_graphite_interval_tv(struct timeval *tv) {
	graphite_interval_tv = *tv;
}

void set_prefix(char* prefix) {
	graphite_prefix = g_strdup(prefix);
}

void free_prefix(void) {
	g_free(graphite_prefix);
}

static struct requests_ps clear_requests_per_second(struct requests_ps *requests) {
	struct requests_ps ret;
	mutex_lock(&requests->lock);
	ret = *requests;
	requests->count=0;
	requests->ps_max = 0;
	requests->ps_min = 0;
	requests->ps_avg = 0;
	mutex_unlock(&requests->lock);
	return ret;
}

static struct request_time timeval_clear_request_time(struct request_time *request) {
	struct request_time ret;

        mutex_lock(&request->lock);
        ret = *request;
        request->time_min.tv_sec = 0;
        request->time_min.tv_usec = 0;
        request->time_max.tv_sec = 0;
        request->time_max.tv_usec = 0;
        request->time_avg.tv_sec = 0;
        request->time_avg.tv_usec = 0;
        request->count = 0;
        mutex_unlock(&request->lock);

	return ret;
}

static int connect_to_graphite_server(const endpoint_t *graphite_ep) {
	int rc;

        if (!graphite_ep) {
                ilog(LOG_ERROR, "NULL graphite_ep");
                return -1;
        }

	ilog(LOG_INFO, "Connecting to graphite server %s", endpoint_print_buf(graphite_ep));

	rc = connect_socket_nb(&graphite_sock, SOCK_STREAM, graphite_ep);
	if (rc == -1) {
		ilog(LOG_ERROR,"Couldn't make socket for connecting to graphite.");
		return -1;
	}
	if (rc == 0)
		ilog(LOG_INFO, "Graphite server connected.");
	else {
		/* EINPROGRESS */
		ilog(LOG_INFO, "Connection to graphite is in progress.");
		connection_state = STATE_IN_PROGRESS;
	}

	return 0;
}

static int send_graphite_data(struct totalstats *sent_data) {

	if (graphite_sock.fd < 0) {
		ilog(LOG_ERROR,"Graphite socket is not connected.");
		return -1;
	}

	struct totalstats *ts = sent_data;

	/* atomically copy values to stack and reset to zero */
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_timeout_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_rejected_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_silent_timeout_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_final_timeout_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_offer_timeout_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_regular_term_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_forced_term_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_relayed_packets);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_relayed_errors);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_nopacket_relayed_sess);
	atomic64_local_copy_zero_struct(ts, &rtpe_totalstats_interval, total_oneway_stream_sess);

	mutex_lock(&rtpe_totalstats_interval.total_average_lock);
	ts->total_average_call_dur = rtpe_totalstats_interval.total_average_call_dur;
	ts->total_managed_sess = rtpe_totalstats_interval.total_managed_sess;
	ZERO(rtpe_totalstats_interval.total_average_call_dur);
	ZERO(rtpe_totalstats_interval.total_managed_sess);
	mutex_unlock(&rtpe_totalstats_interval.total_average_lock);

	mutex_lock(&rtpe_totalstats_interval.total_calls_duration_lock);
	ts->total_calls_duration_interval = rtpe_totalstats_interval.total_calls_duration_interval;
	rtpe_totalstats_interval.total_calls_duration_interval.tv_sec = 0;
	rtpe_totalstats_interval.total_calls_duration_interval.tv_usec = 0;
	//ZERO(rtpe_totalstats_interval.total_calls_duration_interval);
	mutex_unlock(&rtpe_totalstats_interval.total_calls_duration_lock);

	ts->offer = timeval_clear_request_time(&rtpe_totalstats_interval.offer);
	ts->answer = timeval_clear_request_time(&rtpe_totalstats_interval.answer);
	ts->delete = timeval_clear_request_time(&rtpe_totalstats_interval.delete);

	ts->offers_ps = clear_requests_per_second(&rtpe_totalstats_interval.offers_ps);
	ts->answers_ps = clear_requests_per_second(&rtpe_totalstats_interval.answers_ps);
	ts->deletes_ps = clear_requests_per_second(&rtpe_totalstats_interval.deletes_ps);

	rwlock_lock_r(&rtpe_callhash_lock);
	mutex_lock(&rtpe_totalstats_interval.managed_sess_lock);
	ts->managed_sess_max = rtpe_totalstats_interval.managed_sess_max;
	ts->managed_sess_min = rtpe_totalstats_interval.managed_sess_min;
        ts->total_sessions = g_hash_table_size(rtpe_callhash);
        ts->foreign_sessions = atomic64_get(&rtpe_stats.foreign_sessions);
	ts->own_sessions = ts->total_sessions - ts->foreign_sessions;
	rtpe_totalstats_interval.managed_sess_max = ts->own_sessions;;
	rtpe_totalstats_interval.managed_sess_min = ts->own_sessions;
	mutex_unlock(&rtpe_totalstats_interval.managed_sess_lock);
	rwlock_unlock_r(&rtpe_callhash_lock);

	// compute average offer/answer/delete time
	timeval_divide(&ts->offer.time_avg, &ts->offer.time_avg, ts->offer.count);
	timeval_divide(&ts->answer.time_avg, &ts->answer.time_avg, ts->answer.count);
	timeval_divide(&ts->delete.time_avg, &ts->delete.time_avg, ts->delete.count);
	//compute average offers/answers/deletes per second
	ts->offers_ps.ps_avg = (ts->offers_ps.count?(ts->offers_ps.ps_avg/ts->offers_ps.count):0);
	ts->answers_ps.ps_avg = (ts->answers_ps.count?(ts->answers_ps.ps_avg/ts->answers_ps.count):0);
	ts->deletes_ps.ps_avg = (ts->deletes_ps.count?(ts->deletes_ps.ps_avg/ts->deletes_ps.count):0);

	GString *graph_str = g_string_new("");

#define GPF(fmt, ...) \
	if (graphite_prefix) \
		g_string_append(graph_str, graphite_prefix); \
	g_string_append_printf(graph_str, fmt " %llu\n", ##__VA_ARGS__, (unsigned long long)rtpe_now.tv_sec)

	GPF("offer_time_min %llu.%06llu",(unsigned long long)ts->offer.time_min.tv_sec,(unsigned long long)ts->offer.time_min.tv_usec);
	GPF("offer_time_max %llu.%06llu",(unsigned long long)ts->offer.time_max.tv_sec,(unsigned long long)ts->offer.time_max.tv_usec);
	GPF("offer_time_avg %llu.%06llu",(unsigned long long)ts->offer.time_avg.tv_sec,(unsigned long long)ts->offer.time_avg.tv_usec);

	GPF("answer_time_min %llu.%06llu",(unsigned long long)ts->answer.time_min.tv_sec,(unsigned long long)ts->answer.time_min.tv_usec);
	GPF("answer_time_max %llu.%06llu",(unsigned long long)ts->answer.time_max.tv_sec,(unsigned long long)ts->answer.time_max.tv_usec);
	GPF("answer_time_avg %llu.%06llu",(unsigned long long)ts->answer.time_avg.tv_sec,(unsigned long long)ts->answer.time_avg.tv_usec);

	GPF("delete_time_min %llu.%06llu",(unsigned long long)ts->delete.time_min.tv_sec,(unsigned long long)ts->delete.time_min.tv_usec);
	GPF("delete_time_max %llu.%06llu",(unsigned long long)ts->delete.time_max.tv_sec,(unsigned long long)ts->delete.time_max.tv_usec);
	GPF("delete_time_avg %llu.%06llu",(unsigned long long)ts->delete.time_avg.tv_sec,(unsigned long long)ts->delete.time_avg.tv_usec);

	GPF("call_dur %llu.%06llu",(unsigned long long)ts->total_calls_duration_interval.tv_sec,(unsigned long long)ts->total_calls_duration_interval.tv_usec);
	GPF("average_call_dur %llu.%06llu",(unsigned long long)ts->total_average_call_dur.tv_sec,(unsigned long long)ts->total_average_call_dur.tv_usec);
	GPF("forced_term_sess "UINT64F, atomic64_get_na(&ts->total_forced_term_sess));
	GPF("managed_sess "UINT64F, ts->total_managed_sess);
	GPF("managed_sess_min "UINT64F, ts->managed_sess_min);
	GPF("managed_sess_max "UINT64F, ts->managed_sess_max);
	GPF("current_sessions_total "UINT64F, ts->total_sessions);
	GPF("current_sessions_own "UINT64F, ts->own_sessions);
	GPF("current_sessions_foreign "UINT64F, ts->foreign_sessions);
	GPF("current_transcoded_media "UINT64F, atomic64_get(&rtpe_stats.transcoded_media));
	GPF("nopacket_relayed_sess "UINT64F, atomic64_get_na(&ts->total_nopacket_relayed_sess));
	GPF("oneway_stream_sess "UINT64F, atomic64_get_na(&ts->total_oneway_stream_sess));
	GPF("regular_term_sess "UINT64F, atomic64_get_na(&ts->total_regular_term_sess));
	GPF("relayed_errors "UINT64F, atomic64_get_na(&ts->total_relayed_errors));
	GPF("relayed_packets "UINT64F, atomic64_get_na(&ts->total_relayed_packets));
	GPF("silent_timeout_sess "UINT64F, atomic64_get_na(&ts->total_silent_timeout_sess));
	GPF("final_timeout_sess "UINT64F, atomic64_get_na(&ts->total_final_timeout_sess));
	GPF("offer_timeout_sess "UINT64F, atomic64_get_na(&ts->total_offer_timeout_sess));
	GPF("timeout_sess "UINT64F, atomic64_get_na(&ts->total_timeout_sess));
	GPF("reject_sess "UINT64F, atomic64_get_na(&ts->total_rejected_sess));

	GPF("offers_ps_min %llu",(unsigned long long)ts->offers_ps.ps_min);
	GPF("offers_ps_max %llu",(unsigned long long)ts->offers_ps.ps_max);
	GPF("offers_ps_avg %llu",(unsigned long long)ts->offers_ps.ps_avg);

	GPF("answers_ps_min %llu",(unsigned long long)ts->answers_ps.ps_min);
	GPF("answers_ps_max %llu",(unsigned long long)ts->answers_ps.ps_max);
	GPF("answers_ps_avg %llu",(unsigned long long)ts->answers_ps.ps_avg);

	GPF("deletes_ps_min %llu",(unsigned long long)ts->deletes_ps.ps_min);
	GPF("deletes_ps_max %llu",(unsigned long long)ts->deletes_ps.ps_max);
	GPF("deletes_ps_avg %llu",(unsigned long long)ts->deletes_ps.ps_avg);

	for (GList *l = all_local_interfaces.head; l; l = l->next) {
		struct local_intf *lif = l->data;
		// only show first-order interface entries: socket families must match
		if (lif->logical->preferred_family != lif->spec->local_address.addr.family)
			continue;
		int num_ports = lif->spec->port_pool.max - lif->spec->port_pool.min + 1;
		GPF("ports_free_%s_%s %i", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr),
				g_atomic_int_get(&lif->spec->port_pool.free_ports));
		GPF("ports_used_%s_%s %i", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr),
				num_ports - g_atomic_int_get(&lif->spec->port_pool.free_ports));
	}

	mutex_lock(&rtpe_codec_stats_lock);

	GList *chains = g_hash_table_get_keys(rtpe_codec_stats);
	int last_tv_sec = rtpe_now.tv_sec - 1;
	unsigned int idx = last_tv_sec & 1;
	for (GList *l = chains; l; l = l->next) {
		char *chain = l->data;
		struct codec_stats *stats_entry = g_hash_table_lookup(rtpe_codec_stats, chain);
		GPF("transcoder_%s %i", stats_entry->chain_brief,
				g_atomic_int_get(&stats_entry->num_transcoders));
		if (g_atomic_int_get(&stats_entry->last_tv_sec[idx]) != last_tv_sec)
			continue;
		GPF("transcoder_%s_packets %llu", stats_entry->chain_brief,
				(unsigned long long) atomic64_get(&stats_entry->packets_input[idx]));
		GPF("transcoder_%s_bytes %llu", stats_entry->chain_brief,
				(unsigned long long) atomic64_get(&stats_entry->bytes_input[idx]));
		GPF("transcoder_%s_samples %llu", stats_entry->chain_brief,
				(unsigned long long) atomic64_get(&stats_entry->pcm_samples[idx]));
	}

	mutex_unlock(&rtpe_codec_stats_lock);

	g_list_free(chains);


	ilog(LOG_DEBUG, "min_sessions:%llu max_sessions:%llu, call_dur_per_interval:%llu.%06llu at time %llu\n",
			(unsigned long long) ts->managed_sess_min,
			(unsigned long long) ts->managed_sess_max,
			(unsigned long long ) ts->total_calls_duration_interval.tv_sec,
			(unsigned long long ) ts->total_calls_duration_interval.tv_usec,
			(unsigned long long ) rtpe_now.tv_sec);

	ilog(LOG_DEBUG, "Min/Max/Avg offer processing delay: %llu.%06llu/%llu.%06llu/%llu.%06llu sec",
		(unsigned long long)ts->offer.time_min.tv_sec,(unsigned long long)ts->offer.time_min.tv_usec,
		(unsigned long long)ts->offer.time_max.tv_sec,(unsigned long long)ts->offer.time_max.tv_usec,
		(unsigned long long)ts->offer.time_avg.tv_sec,(unsigned long long)ts->offer.time_avg.tv_usec);
	ilog(LOG_DEBUG, "Min/Max/Avg answer processing delay: %llu.%06llu/%llu.%06llu/%llu.%06llu sec",
		(unsigned long long)ts->answer.time_min.tv_sec,(unsigned long long)ts->answer.time_min.tv_usec,
		(unsigned long long)ts->answer.time_max.tv_sec,(unsigned long long)ts->answer.time_max.tv_usec,
		(unsigned long long)ts->answer.time_avg.tv_sec,(unsigned long long)ts->answer.time_avg.tv_usec);
	ilog(LOG_DEBUG, "Min/Max/Avg delete processing delay: %llu.%06llu/%llu.%06llu/%llu.%06llu sec",
		(unsigned long long)ts->delete.time_min.tv_sec,(unsigned long long)ts->delete.time_min.tv_usec,
		(unsigned long long)ts->delete.time_max.tv_sec,(unsigned long long)ts->delete.time_max.tv_usec,
		(unsigned long long)ts->delete.time_avg.tv_sec,(unsigned long long)ts->delete.time_avg.tv_usec);

	size_t sent = 0;
	int blockings = 10; // let it block that many times
	while (sent < graph_str->len) {
		int rc = write(graphite_sock.fd, graph_str->str + sent, graph_str->len - sent);
		if (rc<0) {
			if (blockings <= 0 || (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR)) {
				ilog(LOG_ERROR,"Could not write to graphite socket (%s). " \
						"Disconnecting graphite server.", strerror(errno));
				goto error;
			}
			rc = 0;
		}
		if (rc == 0) {
			// poor man's blocking handling
			blockings--;
			usleep(500000);
			continue;
		}
		sent += rc;
	}

	g_string_free(graph_str, TRUE);
	return 0;

error:
	g_string_free(graph_str, TRUE);
	close_socket(&graphite_sock);
	return -1;
}

static inline void copy_with_lock(struct totalstats *ts_dst, struct totalstats *ts_src, mutex_t *ts_lock) {
	mutex_lock(ts_lock);
	memcpy(ts_dst, ts_src, sizeof(struct totalstats));
	mutex_unlock(ts_lock);
}

static void graphite_loop_run(endpoint_t *graphite_ep, int seconds) {

	int rc=0;
	struct pollfd wfds[1];

        if (!graphite_ep) {
                ilog(LOG_ERROR, "NULL graphite_ep");
                return ;
        }

	if (connection_state == STATE_IN_PROGRESS && graphite_sock.fd >= 0) {
		wfds[0].fd=graphite_sock.fd;
		wfds[0].events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;

		rc = poll(wfds,1,1000);
		if (rc == -1) {
			ilog(LOG_ERROR,"Error on the socket.");
			close_socket(&graphite_sock);
			connection_state = STATE_DISCONNECTED;
			return;
		} else if (rc==0) {
			// timeout
			return;
		} else {
			if (!(wfds[0].revents & POLLOUT)) {
				ilog(LOG_WARN,"fd is active but not ready for writing, poll events=%x",wfds[0].revents);
				close_socket(&graphite_sock);
				connection_state = STATE_DISCONNECTED;
				return;
			}
			rc = socket_error(&graphite_sock);
			if (rc < 0) ilog(LOG_ERROR,"getsockopt failure.");
			if (rc != 0) {
				ilog(LOG_ERROR,"Socket connect failed. fd: %i, Reason: %s\n",graphite_sock.fd, strerror(rc));
				close_socket(&graphite_sock);
				connection_state = STATE_DISCONNECTED;
				return;
			}
			ilog(LOG_INFO, "Graphite server connected.");
			connection_state = STATE_CONNECTED;
			next_run=0; // fake next run to skip sleep after reconnect
		}
	}

	gettimeofday(&rtpe_now, NULL);
	if (rtpe_now.tv_sec < next_run) {
		usleep(100000);
		return;
	}

	next_run = rtpe_now.tv_sec + seconds;

	if (graphite_sock.fd < 0 && connection_state == STATE_DISCONNECTED) {
		connect_to_graphite_server(graphite_ep);
	}

	if (graphite_sock.fd >= 0 && connection_state == STATE_CONNECTED) {
		add_total_calls_duration_in_interval(&graphite_interval_tv);

		rc = send_graphite_data(&graphite_stats);
		gettimeofday(&rtpe_latest_graphite_interval_start, NULL);
		if (rc < 0) {
			ilog(LOG_ERROR,"Sending graphite data failed.");
			close_socket(&graphite_sock);
			connection_state = STATE_DISCONNECTED;
		}

		copy_with_lock(&rtpe_totalstats_lastinterval, &graphite_stats, &rtpe_totalstats_lastinterval_lock);
	}

}

void graphite_loop(void *d) {
	if (rtpe_config.graphite_interval <= 0) {
		ilog(LOG_WARNING,"Graphite send interval was not set. Setting it to 1 second.");
		rtpe_config.graphite_interval=1;
	}

	connect_to_graphite_server(&rtpe_config.graphite_ep);

	while (!rtpe_shutdown)
		graphite_loop_run(&rtpe_config.graphite_ep, rtpe_config.graphite_interval); // time in seconds
}
