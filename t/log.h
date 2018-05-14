#ifndef __LOG_H__
#define __LOG_H__

#include "loglib.h"
#define __ilog(prio, fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

INLINE void rtcplog(const char *x) {
}
INLINE void cdrlog(const char *x) {
}
extern int _log_facility_rtcp;
extern int _log_facility_cdr;

#endif
