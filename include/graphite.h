/*
 * graphite.h
 *
 *  Created on: Jan 19, 2015
 *      Author: fmetz
 */

#ifndef GRAPHITE_H_
#define GRAPHITE_H_

#include "call.h"

enum connection_state {
	STATE_DISCONNECTED = 0,
	STATE_IN_PROGRESS,
	STATE_CONNECTED,
};

extern struct timeval rtpe_latest_graphite_interval_start;

int connect_to_graphite_server(const endpoint_t *ep);
int send_graphite_data(struct totalstats *sent_data);
void graphite_loop_run(endpoint_t *graphite_ep, int seconds);
void set_prefix(char* prefix);
void graphite_loop(void *d);
void set_latest_graphite_interval_start(struct timeval *tv);
void set_graphite_interval_tv(struct timeval *tv);
#endif /* GRAPHITE_H_ */
