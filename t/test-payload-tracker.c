#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ssrc.h"
#include "main.h"
#include "statistics.h"

struct rtpengine_config rtpe_config;
struct global_stats_gauge rtpe_stats_gauge;
struct global_stats_gauge_min_max rtpe_stats_gauge_graphite_min_max;
struct global_stats_gauge_min_max rtpe_stats_gauge_graphite_min_max_interval;
struct global_stats_ax rtpe_stats;
struct global_stats_counter rtpe_stats_interval;
struct global_stats_counter rtpe_stats_cumulative;
struct global_stats_ax rtpe_stats_graphite;
struct global_stats_counter rtpe_stats_graphite_interval;
struct global_stats_min_max rtpe_stats_graphite_min_max;
struct global_stats_min_max rtpe_stats_graphite_min_max_interval;


static void most_cmp(struct payload_tracker *t, const char *cmp, const char *file, int line) {
	char buf[1024] = "";
	int len = 0;

	for (int i = 0; i < t->most_len; i++) {
		if (i > 0)
			len += sprintf(buf+len, ",");
		len += sprintf(buf+len, "%u", t->most[i]);
	}

	if (strcmp(buf, cmp)) {
		printf("test nok: %s:%i\n", file, line);
		printf("expected: %s\n", cmp);
		printf("got: %s\n", buf);
		abort();
	}

	printf("test ok: %s:%i\n", file, line);
}

#define cmp(s) most_cmp(&t, s, __FILE__, __LINE__)
#define add(p) payload_tracker_add(&t, p)

int main(void) {
	struct payload_tracker t;

	payload_tracker_init(&t);

	cmp("");

	add(0);
	cmp("0");

	add(0);
	add(0);
	cmp("0");

	add(5);
	cmp("0,5");

	add(5);
	add(5);
	cmp("0,5");

	add(5);
	cmp("5,0");

	add(0);
	cmp("5,0");

	add(0);
	cmp("0,5");

	add(120);
	cmp("0,5,120");

	add(120);
	add(120);
	add(120);
	add(120);
	cmp("0,120,5");

	add(120);
	cmp("120,0,5");

	add(120);
	add(120);
	add(120);
	cmp("120,0,5");

	add(5);
	add(5);
	cmp("120,5,0");

	// saturation fill test
	for (int i = 0; i < 32; i++)
		add(10);
	cmp("10,5,120,0");

	// bubble up all the way
	for (int i = 0; i < 32; i++)
		add(0);
	cmp("0,10,5,120");

	// filled with 0s, so a single 1 goes in second place
	add(1);
	cmp("0,1,10,5,120");

	return 0;
}

int get_local_log_level(unsigned int u) {
	return -1;
}
