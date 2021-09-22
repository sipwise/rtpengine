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

void set_prefix(char* prefix);
void free_prefix(void);
void graphite_loop(void *d);
void set_latest_graphite_interval_start(struct timeval *tv);
void set_graphite_interval_tv(struct timeval *tv);

GString *print_graphite_data(void);

#endif /* GRAPHITE_H_ */
