#include "log.h"
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <glib.h>
#include "str.h"
#include "call.h"



struct log_info __thread log_info;
volatile gint log_level = LOG_INFO;



void ilog(int prio, const char *fmt, ...) {
	char prefix[256];
	char *msg;
	va_list ap;
	int ret, xprio;

	xprio = LOG_LEVEL_MASK(prio);

#ifndef __DEBUG
	int level; /* thank you C99 */
	level = g_atomic_int_get(&log_level);
	if (xprio > LOG_LEVEL_MASK(level))
		return;
	if ((level & LOG_FLAG_RESTORE) && !(prio & LOG_FLAG_RESTORE))
		return;
#endif

	switch (log_info.e) {
		case LOG_INFO_NONE:
			prefix[0] = 0;
			break;
		case LOG_INFO_CALL:
			snprintf(prefix, sizeof(prefix), "["STR_FORMAT"] ",
					STR_FMT(&log_info.u.call->callid));
			break;
		case LOG_INFO_STREAM_FD:
			if (log_info.u.stream_fd->call)
				snprintf(prefix, sizeof(prefix), "["STR_FORMAT" port %5hu] ",
						STR_FMT(&log_info.u.stream_fd->call->callid),
						log_info.u.stream_fd->fd.localport);
			break;
	}

	va_start(ap, fmt);
	ret = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		syslog(LOG_ERROR, "Failed to print syslog message - message dropped");
		return;
	}

	syslog(xprio, "%s%s", prefix, msg);

	free(msg);
}


