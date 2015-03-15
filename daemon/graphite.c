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

static int graphite_sock=-1;
static int connectinprogress=0;
static u_int32_t graphite_ipaddress;
static int graphite_port=0;
static struct callmaster* cm=0;
//struct totalstats totalstats_prev;
static time_t next_run;
// HEAD: static time_t g_now, next_run;
static char* graphite_prefix = NULL;

void set_prefix(char* prefix) {
	graphite_prefix = prefix;
}

/**
 * Set a file descriptor to blocking or non-blocking mode.
 *
 * @param fd The file descriptor
 * @param blocking 0:non-blocking mode, 1:blocking mode
 *
 * @return 1:success, 0:failure.
 **/
int fd_set_blocking(int fd, int blocking) {
	/* Save the current flags */
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		return 0;

	if (blocking)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;
	return fcntl(fd, F_SETFL, flags) != -1;
}

int connect_to_graphite_server(u_int32_t ipaddress, int port) {

	if (graphite_sock>0)
		close(graphite_sock);

	graphite_sock=-1;

	int rc=0;
	struct sockaddr_in sin;
	memset(&sin,0,sizeof(sin));
	int val=1;

	graphite_ipaddress = ipaddress;
	graphite_port = port;

	graphite_sock = socket(AF_INET, SOCK_STREAM,0);
	if(graphite_sock<0) {
		ilog(LOG_ERROR,"Couldn't make socket for connecting to graphite.Reason:%s\n",strerror(errno));
		return -1;
	}

	sin.sin_family=AF_INET;
	sin.sin_addr.s_addr=graphite_ipaddress;
	sin.sin_port=htons(graphite_port);

	rc = setsockopt(graphite_sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
	if(rc<0) {
		ilog(LOG_ERROR,"Couldn't set sockopt for graphite descriptor.");
		goto error;
	}

	rc = fd_set_blocking(graphite_sock,0);
	if (!rc) {
		ilog(LOG_ERROR,"Could not set the socket to nonblocking.");
		goto error;
	}

	struct in_addr ip;
	ip.s_addr = graphite_ipaddress;
	ilog(LOG_INFO, "Connecting to graphite server %s at port:%i with fd:%i",inet_ntoa(ip),graphite_port,graphite_sock);
	rc = connect(graphite_sock, (struct sockaddr *)&sin, sizeof(sin));
	if (rc==-1) {
		ilog(LOG_WARN, "Connection information:%s\n",strerror(errno));
		if (errno==EINPROGRESS) {
			connectinprogress=1;
			return 0;
		}
		goto error;
	}

	return 0;

error:
	close(graphite_sock);
	graphite_sock = -1;
	return -1;
}

int send_graphite_data() {

	int rc=0;

	if (graphite_sock < 0) {
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
	ZERO(ts.total_average_call_dur);
	ZERO(ts.total_managed_sess);
	mutex_unlock(&cm->totalstats_interval.total_average_lock);

	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.average_call_dur.tv_sec %llu %llu\n",hostname, (unsigned long long) ts.total_average_call_dur.tv_sec,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.average_call_dur.tv_usec %lu %llu\n",hostname, ts.total_average_call_dur.tv_usec,(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.forced_term_sess "UINT64F" %llu\n",hostname, atomic64_get_na(&ts.total_forced_term_sess),(unsigned long long)g_now.tv_sec); ptr += rc;
	if (graphite_prefix!=NULL) { rc = sprintf(ptr,"%s.",graphite_prefix); ptr += rc; }
	rc = sprintf(ptr,"%s.totals.managed_sess "UINT64F" %llu\n",hostname, ts.total_managed_sess,(unsigned long long)g_now.tv_sec); ptr += rc;
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

	rc = write(graphite_sock, data_to_send, ptr - data_to_send);
	if (rc<0) {
		ilog(LOG_ERROR,"Could not write to graphite socket. Disconnecting graphite server.");
		goto error;
	}
	return 0;

error:
	close(graphite_sock); graphite_sock=-1;
	return -1;
}

void graphite_loop_run(struct callmaster* callmaster, int seconds) {

	int rc=0;
	fd_set wfds;
	FD_ZERO(&wfds);
	struct timeval tv;
	int optval=0;
	socklen_t optlen=sizeof(optval);

	if (connectinprogress && graphite_sock>0) {
		FD_SET(graphite_sock,&wfds);
		tv.tv_sec = 0;
		tv.tv_usec = 1000000;

		rc = select (graphite_sock+1, NULL, &wfds, NULL, &tv);
		if ((rc == -1) && (errno == EINTR)) {
			ilog(LOG_ERROR,"Error on the socket.");
		    close(graphite_sock);
			graphite_sock=-1;connectinprogress=0;
			return;
		} else if (rc==0) {
			// timeout
			return;
		} else {
			if (!FD_ISSET(graphite_sock,&wfds)) {
				ilog(LOG_WARN,"fd active but not the graphite fd.");
			    close(graphite_sock);
				graphite_sock=-1;connectinprogress=0;
				return;
			}
			rc = getsockopt(graphite_sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
			if (rc) ilog(LOG_ERROR,"getsockopt failure.");
			if (optval != 0) {
			    ilog(LOG_ERROR,"Socket connect failed. fd: %i, Reason: %s\n",graphite_sock, strerror(optval));
			    close(graphite_sock);
				graphite_sock=-1;connectinprogress=0;
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

	if (graphite_sock < 0 && !connectinprogress) {
		rc = connect_to_graphite_server(graphite_ipaddress, graphite_port);
		if (rc) {
		    close(graphite_sock);
			graphite_sock=-1;
		}
	}

	if (graphite_sock>0 && !connectinprogress) {
		rc = send_graphite_data();
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

	connect_to_graphite_server(cm->conf.graphite_ip,cm->conf.graphite_port);

	while (!g_shutdown)
		graphite_loop_run(cm,cm->conf.graphite_interval); // time in seconds
}
