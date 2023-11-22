#include "log.h"
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include "loglib.h"


static const uint max_log_lines = 10000;

mutex_t log_lock = MUTEX_STATIC_INIT;
static GQueue log_buffer = G_QUEUE_INIT;


void __ilog(int prio, const char *fmt, ...) {
        va_list ap;

	GSList *to_free = NULL;

        va_start(ap, fmt);
	char *line = g_strdup_vprintf(fmt, ap);
	{
		LOCK(&log_lock);
		g_queue_push_tail(&log_buffer, line);
		while (log_buffer.length > max_log_lines)
			to_free = g_slist_prepend(to_free, g_queue_pop_head(&log_buffer));
	}
        va_end(ap);

	g_slist_free_full(to_free, g_free);
}


GQueue *get_log_lines(uint num, uint end) {
	GQueue *ret = g_queue_new();

	LOCK(&log_lock);

	GList *l = log_buffer.tail;
	while (l && end--)
		l = l->prev;
	for (; l && num; num--, l = l->prev)
		g_queue_push_head(ret, g_strdup(l->data));

	return ret;
}


void log_clear(void) {
	LOCK(&log_lock);
	g_queue_clear_full(&log_buffer, g_free);
}


int get_local_log_level(unsigned int subsystem_idx) {
	return -1;
}
