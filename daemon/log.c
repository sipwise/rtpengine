#include "log.h"
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <glib.h>
#include "str.h"
#include "call.h"



struct log_info __thread log_info;
#ifndef __DEBUG
volatile gint log_level = LOG_INFO;
#else
volatile gint log_level = LOG_DEBUG;
#endif

#ifndef MAX_LOG_LINE_LENGTH
#define MAX_LOG_LINE_LENGTH 500
#endif

write_log_t write_log = (write_log_t) syslog;

const _fac_code_t _facilitynames[] =
	{
		{ "auth", LOG_AUTH },
		{ "authpriv", LOG_AUTHPRIV },
		{ "cron", LOG_CRON },
		{ "daemon", LOG_DAEMON },
		{ "ftp", LOG_FTP },
		{ "kern", LOG_KERN },
		{ "lpr", LOG_LPR },
		{ "mail", LOG_MAIL },
		{ "news", LOG_NEWS },
		{ "syslog", LOG_SYSLOG },
		{ "user", LOG_USER },
		{ "uucp", LOG_UUCP },
		{ "local0", LOG_LOCAL0 },
		{ "local1", LOG_LOCAL1 },
		{ "local2", LOG_LOCAL2 },
		{ "local3", LOG_LOCAL3 },
		{ "local4", LOG_LOCAL4 },
		{ "local5", LOG_LOCAL5 },
		{ "local6", LOG_LOCAL6 },
		{ "local7", LOG_LOCAL7 },
		{ NULL, -1 }
	};

const char const* prio_str[] = {
		"EMERG",
		"ALERT",
		"CRIT",
		"ERR",
		"WARNING",
		"NOTICE",
		"INFO",
		"DEBUG"
	};

gboolean _log_stderr = 0;
int _log_facility = LOG_DAEMON;

void log_to_stderr(int facility_priority, char *format, ...) {
	char *msg;
	int ret;
	va_list ap;

	va_start(ap, format);
	ret = vasprintf(&msg, format, ap);
	va_end(ap);

	if (ret < 0) {
		fprintf(stderr,"ERR: Failed to print log message - message dropped\n");
		return;
	}

	fprintf(stderr, "%s: %s\n", prio_str[facility_priority & LOG_PRIMASK], msg);

	free(msg);
}

void ilog(int prio, const char *fmt, ...) {
	char prefix[256];
	char *msg, *piece;
	const char *infix = "";
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
		write_log(LOG_ERROR, "Failed to print syslog message - message dropped");
		return;
	}

	piece = msg;

	while (ret > MAX_LOG_LINE_LENGTH) {
		write_log(xprio, "%s%s%.*s ...", prefix, infix, MAX_LOG_LINE_LENGTH, piece);
		ret -= MAX_LOG_LINE_LENGTH;
		piece += MAX_LOG_LINE_LENGTH;
		infix = "... ";
	}

	write_log(xprio, "%s%s%s", prefix, infix, piece);

	free(msg);
}


