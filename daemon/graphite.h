/*
 * graphite.h
 *
 *  Created on: Jan 19, 2015
 *      Author: fmetz
 */

#ifndef GRAPHITE_H_
#define GRAPHITE_H_

#include "call.h"

int connect_to_graphite_server(const endpoint_t *ep);
int send_graphite_data();
void graphite_loop_run(struct callmaster* cm, int seconds);
void set_prefix(char* prefix);
void graphite_loop(void *d);

#endif /* GRAPHITE_H_ */
