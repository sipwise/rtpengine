#ifndef _LOGLIB_H_
#define _LOGLIB_H_


#include <sys/time.h> /* __USE_TIME_BITS64 */
#include <glib.h>
#include <syslog.h>
#include <stdarg.h>
#include "compat.h"
#include "auxlib.h"

#ifndef TIME_T_INT_FMT
#ifdef __USE_TIME_BITS64
#define TIME_T_INT_FMT PRId64
#else
#define TIME_T_INT_FMT "ld"
#endif
#endif

extern int ilog_facility;

extern int get_local_log_level(unsigned int);


typedef void write_log_t(int facility_priority, const char *format, ...) __attribute__ ((format (printf, 2, 3)));
extern write_log_t *write_log;

int parse_log_facility(const char *name, int *dst);
void print_available_log_facilities (void);

void log_to_stderr(int facility_priority, const char *format, ...) __attribute__ ((format (printf, 2, 3)));

void log_init(const char *);
void log_free(void);

void __vpilog(int prio, const char *prefix, const char *fmt, va_list);
void __ilog_np(int prio, const char *format, ...) __attribute__ ((format (printf, 2, 3)));



#define ll(system, descr) log_level_index_ ## system,
enum __loglevels {
#include "loglevels.h"
	ll(LAST, NULL)
};
#undef ll

#define num_log_levels log_level_index_LAST

extern const char * const log_level_names[];
extern const char * const log_level_descriptions[];


#ifndef __DEBUG
#define ilogsn(system, prio, fmt, ...)								\
	do {											\
		int __loglevel = __get_log_level(system);					\
		if (LOG_LEVEL_MASK((prio)) > LOG_LEVEL_MASK(__loglevel))			\
			break;									\
		if ((__loglevel & LOG_FLAG_RESTORE) && !((prio) & LOG_FLAG_RESTORE))		\
			break;									\
		__ilog(prio, "[%s] " fmt, log_level_names[system], ##__VA_ARGS__);						\
	} while (0)
#else
#define ilogsn(system, prio, fmt, ...) __ilog(prio, "[%s] " fmt, log_level_names[system], ##__VA_ARGS__)
#endif


#define ilog(prio, fmt, ...) ilogs(core, prio, fmt, ##__VA_ARGS__)
#define ilogs(system, prio, fmt, ...) ilogsn(log_level_index_ ## system, prio, fmt, ##__VA_ARGS__)


#define LOG_LEVEL_MASK(v)	((v) & 0x0f)

#define LOG_FLAG_RESTORE	0x10
#define LOG_FLAG_LIMIT		0x20
#define LOG_FLAG_MAX		0x40
#define LOG_FLAG_MIN		0x80


INLINE int __get_log_level(unsigned int idx) {
	if (!rtpe_common_config_ptr)
		return 8;
	if (idx >= MAX_LOG_LEVELS)
		return 8;
	int local_log_level = get_local_log_level(idx);
	if (local_log_level >= 0) {
		if ((local_log_level & LOG_FLAG_MAX)) {
			int level = g_atomic_int_get(&rtpe_common_config_ptr->log_levels[idx]);
			local_log_level = LOG_LEVEL_MASK(local_log_level);
			return MIN(level, local_log_level);
		}
		if ((local_log_level & LOG_FLAG_MIN)) {
			int level = g_atomic_int_get(&rtpe_common_config_ptr->log_levels[idx]);
			local_log_level = LOG_LEVEL_MASK(local_log_level);
			return MAX(level, local_log_level);
		}
		return local_log_level;
	}
	return g_atomic_int_get(&rtpe_common_config_ptr->log_levels[idx]);
}
#define get_log_level(system) __get_log_level(log_level_index_ ## system)



#define die(fmt, ...) do { \
	fprintf(stderr, "Fatal error: " fmt "\n", ##__VA_ARGS__); \
	ilog(LOG_CRIT, "Fatal error: " fmt, ##__VA_ARGS__); \
	exit(-1); \
} while (0)
#define die_errno(msg, ...) die(msg ": %s", ##__VA_ARGS__, strerror(errno))



#define LOG_ERROR LOG_ERR
#define LOG_WARN LOG_WARNING


#endif
