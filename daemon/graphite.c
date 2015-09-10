/*
 * graphite.c
 *
 *  Created on: Jan 19, 2015
 *      Author: fmetz
 */
#include <sys/types.h>
#include <sys/socket.h>
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

static socket_t graphite_sock;
static const endpoint_t *graphite_ep;
static int connectinprogress=0;
static struct callmaster* cm=0;
//struct totalstats totalstats_prev;
static time_t next_run;
// HEAD: static time_t g_now, next_run;
static char* graphite_prefix = NULL;
static struct timeval graphite_interval_tv;

void set_graphite_interval_tv(struct timeval *tv) {
	graphite_interval_tv = *tv;
}

void set_prefix(char* prefix) {
	graphite_prefix = prefix;
}

int connect_to_graphite_server(const endpoint_t *ep) {
	graphite_ep = ep;
	int rc;

	ilog(LOG_INFO, "Connecting to graphite server %s", endpoint_print_buf(ep));

	rc = connect_socket_nb(&graphite_sock, SOCK_STREAM, ep);
	if (rc == -1) {
		ilog(LOG_ERROR,"Couldn't make socket for connecting to graphite.");
		return -1;
	}
	if (rc == 0)
		ilog(LOG_INFO, "Graphite server connected.");
	else {
		/* EINPROGRESS */
		ilog(LOG_INFO, "Connection to graphite is in progress.");
		connectinprogress = 1;
	}

	return 0;
}

int send_graphite_data() {

	int rc=0;

	if (graphite_sock.fd < 0) {
		ilog(LOG_ERROR,"Graphite socket is not connected.");
		return -1;
	}

	// format hostname "." totals.subkey SPACE value SPACE timestamp
	char hostname[256];
	rc = gethostname(hostname,256);
	if (rc<0) {
		ilog(LOG_ERROR, "Could not retrieve host name information.");
		goto error;
	}

	char data_to_send[8192];
	char* ptr = data_to_send;
	struct totalstats ts;

	/* atomically copy values to stack and reset to zero */
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_timeout_sess);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_rejected_sess);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_silent_timeout_sess);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_regular_term_sess);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_forced_term_sess);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_relayed_packets);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_relayed_errors);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_nopacket_relayed_sess);
	atomic64_local_copy_zero_struct(&ts, &cm->totalstats_interval, total_oneway_stream_sess);

	mutex_lock(&cm->totalstats_interval.total_average_lock);
	ts.total_average_call_dur = cm->totalstats_interval.total_average_call_dur;
	ts.total_managed_sess = cm->totalstats_interval.total_managed_sess;
	ZERO(cm->totalstats_interval.total_average_call_dur);
	ZERO(cm->totalstats_interval.total_managed_sess);
	mutex_unlock(&cm->totalstats_interval.total_average_lock);

	mutex_lock(&cm->totalstats_interval.total_calls_duration_lock);
	ts.total_calls_duration_interval = cm->totalstats_interval.total_calls_duration_interval;
	cm->totalstats_interval.total_calls_duration_interval.tv_sec = 0;
	cm->totalstats_interval.total_calls_duration_interval.tv_usec = 0;
 
	//ZERO(cm->totalstats_interval.total_calls_duration_interval);
	mutex_unlock(&cm->totalstats_interval.total_calls_duration_lock);

	rwlock_lock_r(&cm->hashlock);
	mutex_lock(&cm->totalstats_interval.managed_sess_lock);
	ts.managed_sess_max = cm->totalstats_interval.managed_sess_max;
	ts.managed_sess_min = cm->totalstats_interval.managed_sess_min;
	cm->totalstats_interval.managed_sess_max = cm->totalstats.managed_sess_crt;
	cm->totalstats_interval.managed_sess_min = cm->totalstats.managed_sess_crt;
	mutex_unlock(&cm->totalstats_interval.managed_sess_lock);
	rwlock_unlock_r(&cm->hashlock);

	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr, "%s.totals.call_dur %llu.%06llu %llu\n",hostname,(unsigned long long)ts.total_calls_duration_interval.tv_sec,(unsigned long long)ts.total_calls_duration_interval.tv_usec,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.average_call_dur %llu.%06llu %llu\n",hostname,(unsigned long long)ts.total_average_call_dur.tv_sec,(unsigned long long)ts.total_average_call_dur.tv_usec,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.forced_term_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_forced_term_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.managed_sess "UINT64F" %llu\n",hostname, ts.total_managed_sess,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.managed_sess_min "UINT64F" %llu\n",hostname, ts.managed_sess_min,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.managed_sess_max "UINT64F" %llu\n",hostname, ts.managed_sess_max,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.nopacket_relayed_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_nopacket_relayed_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.oneway_stream_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_oneway_stream_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.regular_term_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_regular_term_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.relayed_errors "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_relayed_errors),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.relayed_packets "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_relayed_packets),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.silent_timeout_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_silent_timeout_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.timeout_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_timeout_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.reject_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_rejected_sess),(unsigned long long)g_now.tv_sec); ptr += rc;

	ilog(LOG_DEBUG, "min_sessions:%llu max_sessions:%llu, call_dur_per_interval:%llu.%06llu at time %llu\n",
			(unsigned long long) ts.managed_sess_min,
			(unsigned long long) ts.managed_sess_max, 
			(unsigned long long ) ts.total_calls_duration_interval.tv_sec,
			(unsigned long long ) ts.total_calls_duration_interval.tv_usec,
			(unsigned long long ) g_now.tv_sec);

	rc = write(graphite_sock.fd, data_to_send, ptr - data_to_send);
	if (rc<0) {
		ilog(LOG_ERROR,"Could not write to graphite socket. Disconnecting graphite server.");
		goto error;
	}
	return 0;

error:
	close_socket(&graphite_sock);
	return -1;
}

void graphite_loop_run(struct callmaster* callmaster, int seconds) {

	int rc=0;
	fd_set wfds;
	FD_ZERO(&wfds);
	struct timeval tv;
	int optval=0;
	socklen_t optlen=sizeof(optval);

	if (connectinprogress && graphite_sock.fd >= 0) {
		FD_SET(graphite_sock.fd,&wfds);
		tv.tv_sec = 0;
		tv.tv_usec = 1000000;

		rc = select (graphite_sock.fd+1, NULL, &wfds, NULL, &tv);
		if ((rc == -1) && (errno == EINTR)) {
			ilog(LOG_ERROR,"Error on the socket.");
			close_socket(&graphite_sock);
			return;
		} else if (rc==0) {
			// timeout
			return;
		} else {
			if (!FD_ISSET(graphite_sock.fd,&wfds)) {
				ilog(LOG_WARN,"fd active but not the graphite fd.");
			close_socket(&graphite_sock);
				return;
			}
			rc = getsockopt(graphite_sock.fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
			if (rc) ilog(LOG_ERROR,"getsockopt failure.");
			if (optval != 0) {
				ilog(LOG_ERROR,"Socket connect failed. fd: %i, Reason: %s\n",graphite_sock.fd, strerror(optval));
				close_socket(&graphite_sock);
				return;
			}
			ilog(LOG_INFO, "Graphite server connected.");
			connectinprogress=0;
			next_run=0; // fake next run to skip sleep after reconnect
		}
	}

	gettimeofday(&g_now, NULL);
	if (g_now.tv_sec < next_run) {
		usleep(100000);
		return;
	}

	next_run = g_now.tv_sec + seconds;

	if (!cm)
		cm = callmaster;

	if (graphite_sock.fd < 0 && !connectinprogress) {
		rc = connect_to_graphite_server(graphite_ep);
	}

	if (graphite_sock.fd >= 0 && !connectinprogress) {
		add_total_calls_duration_in_interval(cm, &graphite_interval_tv);
		rc = send_graphite_data();
		gettimeofday(&cm->latest_graphite_interval_start, NULL);
		if (rc<0) {
			ilog(LOG_ERROR,"Sending graphite data failed.");
		}
	}

}

void graphite_loop(void *d) {
	struct callmaster *cm = d;

	if (!cm->conf.graphite_interval) {
		ilog(LOG_WARNING,"Graphite send interval was not set. Setting it to 1 second.");
		cm->conf.graphite_interval=1;
	}

	connect_to_graphite_server(&cm->conf.graphite_ep);

	while (!g_shutdown)
		graphite_loop_run(cm,cm->conf.graphite_interval); // time in seconds
}
