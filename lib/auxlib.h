#ifndef _AUXLIB_H_
#define _AUXLIB_H_

#include <glib.h>
#include <assert.h>
#include "compat.h"
#include <openssl/rand.h>

struct rtpengine_common_config {
	char *config_file;
	char *config_section;
	char *log_facility;
	volatile int log_level;
	int log_stderr;
	char *pidfile;
	int foreground;
};

extern struct rtpengine_common_config *rtpe_common_config_ptr;

void daemonize(void);
void wpidfile(void);
void service_notify(const char *message);
void config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *);

INLINE void random_string(unsigned char *buf, int len) {
	int ret = RAND_bytes(buf, len);
	assert(ret == 1);
}

INLINE int g_tree_clear_cb(void *k, void *v, void *p) {
	GQueue *q = p;
	g_queue_push_tail(q, k);
	return 0;
}
INLINE void g_tree_clear(GTree *t) {
	GQueue q = G_QUEUE_INIT;
	g_tree_foreach(t, g_tree_clear_cb, &q);
	while (q.length) {
		void *k = g_queue_pop_head(&q);
		g_tree_remove(t, k);
	}
}


#endif
