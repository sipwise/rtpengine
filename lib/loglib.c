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
#include <glib/gprintf.h>
#include "auxlib.h"


struct log_limiter_entry {
	char *prefix;
	char *msg;
};

typedef struct _fac_code {
	char	*c_name;
	int	c_val;
} _fac_code_t;



static write_log_t log_both;

unsigned int max_log_line_length = 500;
write_log_t *write_log = (write_log_t *) log_both;



#define ll(system, descr) #system,
const char * const log_level_names[] = {
#include "loglevels.h"
NULL
};
#undef ll
#define ll(system, descr) descr,
const char * const log_level_descriptions[] = {
#include "loglevels.h"
NULL
};
#undef ll



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

int ilog_facility = LOG_DAEMON;



static GHashTable *__log_limiter;
static pthread_mutex_t __log_limiter_lock;
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

	if (rtpe_common_config_ptr->no_log_timestamps)
		fprintf(stderr, "%s\n", msg);
	else {
		gettimeofday(&tv_now, NULL);

		fprintf(stderr, "[%lu.%06lu] %s\n", (unsigned long) tv_now.tv_sec,
				(unsigned long) tv_now.tv_usec, msg);
	}

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
	AUTO_CLEANUP_GBUF(msg);
	char *piece;
	const char *infix = "";
	int len, xprio;
	const char *prio_prefix;

	xprio = LOG_LEVEL_MASK(prio);
	prio_prefix = prio_str[prio & LOG_PRIMASK];
	if (!prefix)
		prefix = "";

	len = g_vasprintf(&msg, fmt, ap);

	while (len > 0 && msg[len-1] == '\n')
		len--;

	if ((prio & LOG_FLAG_LIMIT)) {
		time_t when;
		struct log_limiter_entry lle, *llep;

		lle.prefix = (char *) prefix;
		lle.msg = msg;

		pthread_mutex_lock(&__log_limiter_lock);

		if (__log_limiter_count > 10000) {
			g_hash_table_remove_all(__log_limiter);
			__log_limiter_count = 0;
		}

		time_t now = time(NULL);

		when = (time_t) GPOINTER_TO_UINT(g_hash_table_lookup(__log_limiter, &lle));
		if (!when || (now - when) >= 15) {
			llep = g_slice_alloc0(sizeof(*llep));
			llep->prefix = strdup(prefix);
			llep->msg = strdup(msg);
			g_hash_table_insert(__log_limiter, llep, GUINT_TO_POINTER(now));
			__log_limiter_count++;
			when = 0;
		}

		pthread_mutex_unlock(&__log_limiter_lock);

		if (when)
			return;
	}

	piece = msg;

	while (1) {
		unsigned int max_line_len = rtpe_common_config_ptr->max_log_line_length;
		unsigned int skip_len = max_line_len;
		if (rtpe_common_config_ptr->split_logs) {
			char *newline = strchr(piece, '\n');
			if (newline) {
				unsigned int nl_pos = newline - piece;
				if (!max_line_len || nl_pos < max_line_len) {
					max_line_len = nl_pos;
					skip_len = nl_pos + 1;
					if (nl_pos >= 1 && piece[nl_pos-1] == '\r')
						max_line_len--;
				}
			}
		}

		if (!max_line_len)
			break;
		if (len <= max_line_len)
			break;

		write_log(xprio, "%s: %s%s%.*s ...", prio_prefix, prefix, infix, max_line_len, piece);
		len -= skip_len;
		piece += skip_len;
		infix = "... ";
	}

	write_log(xprio, "%s: %s%s%.*s", prio_prefix, prefix, infix, len, piece);
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

static void log_limiter_entry_free(void *p) {
	struct log_limiter_entry *lle = p;
	free(lle->prefix);
	free(lle->msg);
	g_slice_free1(sizeof(*lle), lle);
}

void log_init(const char *handle) {
	pthread_mutex_init(&__log_limiter_lock, NULL);
	__log_limiter = g_hash_table_new_full(log_limiter_entry_hash, log_limiter_entry_equal,
			log_limiter_entry_free, NULL);

	if (!rtpe_common_config_ptr->log_stderr)
		openlog(handle, LOG_PID | LOG_NDELAY, ilog_facility);
}

void log_free() {
	g_hash_table_destroy(__log_limiter);
	pthread_mutex_destroy(&__log_limiter_lock);
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
