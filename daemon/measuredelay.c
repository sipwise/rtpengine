/*
 * meauredelay.c
 *
 *  Created on: Feb 13, 2015
 *      Author: fmetz
 */

#include "log.h"
#include "call.h"
#include "measuredelay.h"
#include "kernel.h"

static struct callmaster* cm=0;
static time_t g_now, next_run;

void measuredelay_loop_run(struct callmaster* callmaster, int seconds) {

	int rc=0;

	g_now = time(NULL);
	if (g_now < next_run)
		goto sleep;

	next_run = g_now + seconds;

	if (!cm)
		cm = callmaster;

	kernel_measure_delay(cm->conf.kernelfd);

sleep:
	usleep(100000);
}
