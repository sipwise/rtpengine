#include "log_d.h"
#include <stdarg.h>

void rtcplog(const char *x) { }
void cdrlog(const char *x) { }

GString *dtmf_logs;


#define ll(system, descr) #system,
const char * const log_level_names[] = {
#include "loglevels_common.inc"
#include "loglevels_d.inc"
};
#undef ll
#define ll(system, descr) descr,
const char * const log_level_descriptions[] = {
#include "loglevels_common.inc"
#include "loglevels_d.inc"
};
#undef ll

const unsigned int num_log_levels = __log_level_last;


void dtmflog(GString *s) {
	if (!dtmf_logs)
		dtmf_logs = g_string_new("");
	if (dtmf_logs->len > 0)
		g_string_append(dtmf_logs, "\n");
	g_string_append_len(dtmf_logs, s->str, s->len);
}

void __ilog(int prio, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

void log_info_pop(void) { }
void log_info_pop_until(void *p) { }
void log_info_reset(void) { }

void log_info_call(call_t *c) { }
void log_info_stream_fd(stream_fd *sfd) { }
void log_info_str(const str *s) { }
void log_info_c_string(const char *s) { }
void log_info_ice_agent(struct ice_agent *ag) { }
void log_info_media(struct call_media *m) { }
