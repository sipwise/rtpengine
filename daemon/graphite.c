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

#include "log.h"
#include "call.h"

int graphite_sock=0;
u_int32_t graphite_ipaddress;
int graphite_port=0;
struct callmaster* cm=0;
struct totalstats totalstats_prev;

int connect_to_graphite_server(u_int32_t ipaddress, int port) {

	graphite_sock=0;
	int reconnect=0;
	int rc=0;
	struct sockaddr_in sin;
	memset(&sin,0,sizeof(sin));
	int val=1;

	graphite_ipaddress = ipaddress;
	graphite_port = port;

	rc = graphite_sock = socket(AF_INET, SOCK_STREAM,0);
	if(rc<0) {
		ilog(LOG_ERROR,"Couldn't make socket for connecting to graphite.");
		return -1;
	}

	sin.sin_family=AF_INET;
	sin.sin_addr.s_addr=graphite_ipaddress;
	sin.sin_port=htons(graphite_port);

	rc = setsockopt(graphite_sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
	if(rc<0) {
		ilog(LOG_ERROR,"Couldn't set sockopt for graphite descriptor.");
		return -1;
	}

	struct in_addr ip;
	ip.s_addr = graphite_ipaddress;
	ilog(LOG_INFO, "Connecting to graphite server %s at port:%i with fd:%i",inet_ntoa(ip),graphite_port,graphite_sock);
	rc = connect(graphite_sock, (struct sockaddr *)&sin, sizeof(sin));
	if (rc==-1) {
		ilog(LOG_ERROR, "Connection could not be established. Trying again next time of graphite-interval.");
		return -1;
	}

	ilog(LOG_INFO, "Graphite server connected.");

	return graphite_sock;
}

int send_graphite_data() {

	int rc=0;

	if (!graphite_sock) {
		ilog(LOG_ERROR,"Graphite socket is not connected.");
		return -1;
	}

	// format hostname "." totals.subkey SPACE value SPACE timestamp
	char hostname[256]; memset(&hostname,0,256);
	rc = gethostname(hostname,256);
	if (rc<0) {
		ilog(LOG_ERROR, "Could not retrieve host name information.");
		return -1;
	}

	char data_to_send[8192]; memset(&data_to_send,0,8192);
	char* ptr = data_to_send;

	mutex_lock(&cm->totalstats_lock);

	rc = sprintf(ptr,"%s.totals.average_call_dur.tv_sec %i %u\n",hostname, cm->totalstats_interval.total_average_call_dur.tv_sec,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.average_call_dur.tv_usec %i %u\n",hostname, cm->totalstats_interval.total_average_call_dur.tv_usec,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.forced_term_sess %i %u\n",hostname, cm->totalstats_interval.total_forced_term_sess,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.managed_sess %i %u\n",hostname, cm->totalstats_interval.total_managed_sess,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.nopacket_relayed_sess %i %u\n",hostname, cm->totalstats_interval.total_nopacket_relayed_sess,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.oneway_stream_sess %i %u\n",hostname, cm->totalstats_interval.total_oneway_stream_sess,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.regular_term_sess %i %u\n",hostname, cm->totalstats_interval.total_regular_term_sess,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.relayed_errors %i %u\n",hostname, cm->totalstats_interval.total_relayed_errors,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.relayed_packets %i %u\n",hostname, cm->totalstats_interval.total_relayed_packets,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.silent_timeout_sess %i %u\n",hostname, cm->totalstats_interval.total_silent_timeout_sess,(unsigned)time(NULL)); ptr += rc;
	rc = sprintf(ptr,"%s.totals.timeout_sess %i %u\n",hostname, cm->totalstats_interval.total_timeout_sess,(unsigned)time(NULL)); ptr += rc;

	ZERO(cm->totalstats_interval);

	mutex_unlock(&cm->totalstats_lock);

	rc = write(graphite_sock, data_to_send, strlen(data_to_send));
	if (rc<0) {
		ilog(LOG_ERROR,"Could not write to graphite socket. Disconnecting graphite server.");
		close(graphite_sock); graphite_sock=0;
		return -1;
	}
	return 0;
}

void graphite_loop_run(struct callmaster* callmaster, int seconds) {

	int rc=0;

	if (!cm)
		cm = callmaster;

	if (!graphite_sock) {
		rc = connect_to_graphite_server(graphite_ipaddress, graphite_port);
	}

	if (rc>=0) {
		rc = send_graphite_data();
		if (rc<0) {
			ilog(LOG_ERROR,"Sending graphite data failed.");
			graphite_sock=0;
		}
	}

	sleep(seconds);
}
