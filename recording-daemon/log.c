#include "log.h"
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include "loglib.h"


__thread const char *log_info_call, *log_info_stream;
__thread unsigned long log_info_ssrc;


void __ilog(int prio, const char *fmt, ...) {
        va_list ap;
	char prefix[300] = "";
	char *pp = prefix;
	char *endp = prefix + sizeof(prefix);

	if (log_info_call)
		pp += snprintf(pp, endp - pp, "[C %s%s%s] ", FMT_M(log_info_call));
	if (log_info_stream)
		pp += snprintf(pp, endp - pp, "[S %s%s%s] ", FMT_M(log_info_stream));
	if (log_info_ssrc)
		pp += snprintf(pp, endp - pp, "[%s0x%lx%s] ", FMT_M(log_info_ssrc));

        va_start(ap, fmt);
        __vpilog(prio, prefix, fmt, ap);
        va_end(ap);
}

int get_local_log_level(unsigned int subsystem_idx) {
	return -1;
}
