#include "load.h"
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "aux.h"
#include "log.h"
#include "main.h"

int load_average; // times 100
int cpu_usage; // percent times 100 (0 - 9999)

static long used_last, idle_last;

void load_thread(void *dummy) {
	// anything to do?
	if (!rtpe_config.load_limit && !rtpe_config.cpu_limit)
		return;

	while (!rtpe_shutdown) {
		if (rtpe_config.load_limit) {
			double loadavg;
			if (getloadavg(&loadavg, 1) >= 1)
				g_atomic_int_set(&load_average, (int) (loadavg * 100.0));
			else
				ilog(LOG_WARN, "Failed to obtain load average: %s", strerror(errno));
		}

		if (rtpe_config.cpu_limit) {
			FILE *f;
			f = fopen("/proc/stat", "r");
			if (f) {
				long user_now, nice_now, system_now, idle_now;
				if (fscanf(f, "cpu  %li %li %li %li",
							&user_now, &nice_now, &system_now, &idle_now) == 4)
				{
					long used_now = user_now + nice_now + system_now;
					long used_secs = used_now - used_last;
					long idle_secs = idle_now - idle_last;
					long total_secs = used_secs + idle_secs;
					if (total_secs > 0 && used_last && idle_last)
						g_atomic_int_set(&cpu_usage, (int) (used_secs
									* 10000 / total_secs));
					used_last = used_now;
					idle_last = idle_now;
				}
				else
					ilog(LOG_WARN, "Failed to obtain CPU usage");
				fclose(f);
			}
		}

		thread_cancel_enable();
		usleep(500000);
		thread_cancel_disable();
	}
}
