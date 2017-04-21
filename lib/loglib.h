#ifndef _LOGLIB_H_
#define _LOGLIB_H_


#include <glib.h>
#include <syslog.h>
#include <stdarg.h>
#include "compat.h"


extern gboolean ilog_stderr;
extern int ilog_facility;


extern volatile gint log_level;
extern unsigned int max_log_line_length;


typedef void write_log_t(int facility_priority, const char *format, ...) __attribute__ ((format (printf, 2, 3)));
extern write_log_t *write_log;

int parse_log_facility(const char *name, int *dst);
void print_available_log_facilities ();

void log_to_stderr(int facility_priority, const char *format, ...) __attribute__ ((format (printf, 2, 3)));

void log_init(const char *);

void __vpilog(int prio, const char *prefix, const char *fmt, va_list);
void __ilog_np(int prio, const char *format, ...) __attribute__ ((format (printf, 2, 3)));


#ifndef __DEBUG
#define ilog(prio, fmt, ...)									\
	do {											\
		int __loglevel = get_log_level();						\
		if (LOG_LEVEL_MASK((prio)) > LOG_LEVEL_MASK(__loglevel))			\
			break;									\
		if ((__loglevel & LOG_FLAG_RESTORE) && !((prio) & LOG_FLAG_RESTORE))		\
			break;									\
		__ilog(prio, fmt, ##__VA_ARGS__);						\
	} while (0)
#else
#define ilog(prio, fmt, ...) __ilog(prio, fmt, ##__VA_ARGS__)
#endif


INLINE int get_log_level(void) {
	return g_atomic_int_get(&log_level);
}



#define die(fmt, ...) do { ilog(LOG_CRIT, "Fatal error: " fmt, ##__VA_ARGS__); exit(-1); } while (0)
#define die_errno(msg) die("%s: %s", msg, strerror(errno))



#define LOG_ERROR LOG_ERR
#define LOG_WARN LOG_WARNING


#define LOG_LEVEL_MASK(v)	((v) & 0x0f)

#define LOG_FLAG_RESTORE	0x10
#define LOG_FLAG_LIMIT		0x20


#endif
