#include "log.h"
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <glib.h>
#include "str.h"
#include "call.h"
#include "poller.h"
#include "ice.h"




struct log_limiter_entry {
	char *prefix;
	char *msg;
};



struct log_info __thread log_info;
#ifndef __DEBUG
volatile gint log_level = LOG_INFO;
#else
volatile gint log_level = LOG_DEBUG;
#endif

unsigned int max_log_line_length = 500;
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

static const char* const prio_str[] = {
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
int _log_facility_cdr = 0;
int _log_facility_rtcp = 0;


static GHashTable *__log_limiter;
static mutex_t __log_limiter_lock;
static GStringChunk *__log_limiter_strings;
static unsigned int __log_limiter_count;


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

	fprintf(stderr, "[%lu.%06lu] %s: %s\n", (unsigned long) g_now.tv_sec, (unsigned long) g_now.tv_usec,
			prio_str[facility_priority & LOG_PRIMASK], msg);

	free(msg);
}

void __ilog(int prio, const char *fmt, ...) {
	char prefix[256];
	char *msg, *piece;
	const char *infix = "";
	va_list ap;
	int ret, xprio;

	xprio = LOG_LEVEL_MASK(prio);

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
		case LOG_INFO_STR:
			snprintf(prefix, sizeof(prefix), "["STR_FORMAT"] ",
					STR_FMT(log_info.u.str));
			break;
		case LOG_INFO_C_STRING:
			snprintf(prefix, sizeof(prefix), "[%s] ", log_info.u.cstr);
			break;
		case LOG_INFO_ICE_AGENT:
			snprintf(prefix, sizeof(prefix), "["STR_FORMAT"/"STR_FORMAT"/%u] ",
					STR_FMT(&log_info.u.ice_agent->call->callid),
					STR_FMT(&log_info.u.ice_agent->media->monologue->tag),
					log_info.u.ice_agent->media->index);
			break;
	}

	va_start(ap, fmt);
	ret = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		write_log(LOG_ERROR, "Failed to print syslog message - message dropped");
		return;
	}

	while (ret > 0 && msg[ret-1] == '\n')
		ret--;

	if ((prio & LOG_FLAG_LIMIT)) {
		time_t when;
		struct log_limiter_entry lle, *llep;

		lle.prefix = prefix;
		lle.msg = msg;

		mutex_lock(&__log_limiter_lock);

		if (__log_limiter_count > 10000) {
			g_hash_table_remove_all(__log_limiter);
			g_string_chunk_clear(__log_limiter_strings);
			__log_limiter_count = 0;
		}

		when = (time_t) g_hash_table_lookup(__log_limiter, &lle);
		if (!when || (poller_now - when) >= 15) {
			lle.prefix = g_string_chunk_insert(__log_limiter_strings, prefix);
			lle.msg = g_string_chunk_insert(__log_limiter_strings, msg);
			llep = (void *) g_string_chunk_insert_len(__log_limiter_strings,
					(void *) &lle, sizeof(lle));
			g_hash_table_insert(__log_limiter, llep, (void *) poller_now);
			__log_limiter_count++;
			when = 0;
		}

		mutex_unlock(&__log_limiter_lock);

		if (when)
			goto out;
	}

	piece = msg;

	while (max_log_line_length && ret > max_log_line_length) {
		write_log(xprio, "%s%s%.*s ...", prefix, infix, max_log_line_length, piece);
		ret -= max_log_line_length;
		piece += max_log_line_length;
		infix = "... ";
	}

	write_log(xprio, "%s%s%.*s", prefix, infix, ret, piece);

out:
	free(msg);
}

void cdrlog(const char* cdrbuffer) {
    syslog(LOG_INFO | _log_facility_cdr, "%s", cdrbuffer);
}

static unsigned int log_limiter_entry_hash(const void *p) {
	const struct log_limiter_entry *lle = p;
	return g_str_hash(lle->msg) ^ g_str_hash(lle->prefix);
}

static int log_limiter_entry_equal(const void *a, const void *b) {
	const struct log_limiter_entry *A = a, *B = b;
	if (!g_str_equal(A->msg, B->msg))
		return 0;
	if (!g_str_equal(A->prefix, B->prefix))
		return 0;
	return 1;
}

void rtcplog(const char* cdrbuffer) {
    syslog(LOG_INFO | _log_facility_rtcp, "%s", cdrbuffer);
}

void log_init() {
	mutex_init(&__log_limiter_lock);
	__log_limiter = g_hash_table_new(log_limiter_entry_hash, log_limiter_entry_equal);
	__log_limiter_strings = g_string_chunk_new(1024);
}
