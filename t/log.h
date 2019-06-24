#ifndef __LOG_H__
#define __LOG_H__

#include "loglib.h"
#define __ilog(prio, fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define __C_DBG(x...) ilog(LOG_DEBUG, x)

INLINE void rtcplog(const char *x) {
}
INLINE void cdrlog(const char *x) {
}
extern int _log_facility_rtcp;
extern int _log_facility_cdr;
extern int _log_facility_dtmf;
extern GString *dtmf_logs;

INLINE void dtmflog(GString *s) {
	if (!dtmf_logs)
		dtmf_logs = g_string_new("");
	if (dtmf_logs->len > 0)
		g_string_append(dtmf_logs, "\n");
	g_string_append_len(dtmf_logs, s->str, s->len);
}

#endif
