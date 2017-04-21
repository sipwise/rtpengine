#include "loglib.h"
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <string.h>


struct log_limiter_entry {
	char *prefix;
	char *msg;
};

typedef struct _fac_code {
	char	*c_name;
	int	c_val;
} _fac_code_t;



#ifndef __DEBUG
volatile gint log_level = LOG_INFO;
#else
volatile gint log_level = LOG_DEBUG;
#endif



static write_log_t log_both;

unsigned int max_log_line_length = 500;
write_log_t *write_log = (write_log_t *) log_both;



static const _fac_code_t _facilitynames[] =
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

gboolean ilog_stderr = 0;
int ilog_facility = LOG_DAEMON;



static GHashTable *__log_limiter;
static pthread_mutex_t __log_limiter_lock;
static GStringChunk *__log_limiter_strings;
static unsigned int __log_limiter_count;




static void vlog_to_stderr(int facility_priority, const char *format, va_list ap) {
	char *msg;
	int ret;
	struct timeval tv_now;

	ret = vasprintf(&msg, format, ap);

	if (ret < 0) {
		fprintf(stderr,"ERR: Failed to print log message - message dropped\n");
		return;
	}

	gettimeofday(&tv_now, NULL);

	fprintf(stderr, "[%lu.%06lu] %s\n", (unsigned long) tv_now.tv_sec,
			(unsigned long) tv_now.tv_usec, msg);

	free(msg);
}

void log_to_stderr(int facility_priority, const char *format, ...) {
	va_list ap;

	va_start(ap, format);
	vlog_to_stderr(facility_priority, format, ap);
	va_end(ap);
}

static void log_both(int facility_priority, const char *format, ...) {
	va_list ap;

	va_start(ap, format);
	vsyslog(facility_priority, format, ap);
	va_end(ap);

	if (LOG_LEVEL_MASK(facility_priority) <= LOG_WARN) {
		va_start(ap, format);
		vlog_to_stderr(facility_priority, format, ap);
		va_end(ap);
	}
}



void __vpilog(int prio, const char *prefix, const char *fmt, va_list ap) {
	char *msg, *piece;
	const char *infix = "";
	int ret, xprio;
	const char *prio_prefix;

	xprio = LOG_LEVEL_MASK(prio);
	prio_prefix = prio_str[prio & LOG_PRIMASK];
	if (!prefix)
		prefix = "";

	ret = vasprintf(&msg, fmt, ap);

	if (ret < 0) {
		write_log(LOG_ERROR, "Failed to print syslog message - message dropped");
		return;
	}

	while (ret > 0 && msg[ret-1] == '\n')
		ret--;

	if ((prio & LOG_FLAG_LIMIT)) {
		time_t when;
		struct log_limiter_entry lle, *llep;

		lle.prefix = (char *) prefix;
		lle.msg = msg;

		pthread_mutex_lock(&__log_limiter_lock);

		if (__log_limiter_count > 10000) {
			g_hash_table_remove_all(__log_limiter);
			g_string_chunk_clear(__log_limiter_strings);
			__log_limiter_count = 0;
		}

		time_t now = time(NULL);

		when = (time_t) GPOINTER_TO_UINT(g_hash_table_lookup(__log_limiter, &lle));
		if (!when || (now - when) >= 15) {
			lle.prefix = g_string_chunk_insert(__log_limiter_strings, prefix);
			lle.msg = g_string_chunk_insert(__log_limiter_strings, msg);
			llep = (void *) g_string_chunk_insert_len(__log_limiter_strings,
					(void *) &lle, sizeof(lle));
			g_hash_table_insert(__log_limiter, llep, GUINT_TO_POINTER(now));
			__log_limiter_count++;
			when = 0;
		}

		pthread_mutex_unlock(&__log_limiter_lock);

		if (when)
			goto out;
	}

	piece = msg;

	while (max_log_line_length && ret > max_log_line_length) {
		write_log(xprio, "%s: %s%s%.*s ...", prio_prefix, prefix, infix, max_log_line_length, piece);
		ret -= max_log_line_length;
		piece += max_log_line_length;
		infix = "... ";
	}

	write_log(xprio, "%s: %s%s%.*s", prio_prefix, prefix, infix, ret, piece);

out:
	free(msg);
}


void __ilog_np(int prio, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	__vpilog(prio, NULL, fmt, ap);
	va_end(ap);
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

void log_init(const char *handle) {
	pthread_mutex_init(&__log_limiter_lock, NULL);
	__log_limiter = g_hash_table_new(log_limiter_entry_hash, log_limiter_entry_equal);
	__log_limiter_strings = g_string_chunk_new(1024);

	if (!ilog_stderr)
		openlog(handle, LOG_PID | LOG_NDELAY, ilog_facility);
}

int parse_log_facility(const char *name, int *dst) {
	int i;
	for (i = 0 ; _facilitynames[i].c_name; i++) {
		if (strcmp(_facilitynames[i].c_name, name) == 0) {
			*dst = _facilitynames[i].c_val;
			return 1;
		}
	}
	return 0;
}

void print_available_log_facilities () {
	int i;

	fprintf(stderr, "available facilities:");
	for (i = 0 ; _facilitynames[i].c_name; i++) {
		fprintf(stderr, " %s",  _facilitynames[i].c_name);
	}
	fprintf(stderr, "\n");
}
