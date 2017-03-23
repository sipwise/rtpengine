#include "log.h"
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <glib.h>
#include "str.h"
#include "call.h"
#include "poller.h"
#include "ice.h"
#include "loglib.h"




struct log_info __thread log_info;

int _log_facility_cdr = 0;
int _log_facility_rtcp = 0;



void __ilog(int prio, const char *fmt, ...) {
	char prefix[300];
	va_list ap;

	switch (log_info.e) {
		case LOG_INFO_NONE:
			prefix[0] = 0;
			break;
		case LOG_INFO_CALL:
			snprintf(prefix, sizeof(prefix), "["STR_FORMAT"]: ",
					STR_FMT(&log_info.u.call->callid));
			break;
		case LOG_INFO_STREAM_FD:
			if (log_info.u.stream_fd->call)
				snprintf(prefix, sizeof(prefix), "["STR_FORMAT" port %5u]: ",
						STR_FMT(&log_info.u.stream_fd->call->callid),
						log_info.u.stream_fd->socket.local.port);
			break;
		case LOG_INFO_STR:
			snprintf(prefix, sizeof(prefix), "["STR_FORMAT"]: ",
					STR_FMT(log_info.u.str));
			break;
		case LOG_INFO_C_STRING:
			snprintf(prefix, sizeof(prefix), "[%s]: ", log_info.u.cstr);
			break;
		case LOG_INFO_ICE_AGENT:
			snprintf(prefix, sizeof(prefix), "["STR_FORMAT"/"STR_FORMAT"/%u]: ",
					STR_FMT(&log_info.u.ice_agent->call->callid),
					STR_FMT(&log_info.u.ice_agent->media->monologue->tag),
					log_info.u.ice_agent->media->index);
			break;
	}

	va_start(ap, fmt);
	__vpilog(prio, prefix, fmt, ap);
	va_end(ap);
}

void cdrlog(const char* cdrbuffer) {
	if (_log_facility_cdr) {
		syslog(LOG_INFO | _log_facility_cdr, "%s", cdrbuffer);
	}
}


void rtcplog(const char* cdrbuffer) {
    syslog(LOG_INFO | _log_facility_rtcp, "%s", cdrbuffer);
}
