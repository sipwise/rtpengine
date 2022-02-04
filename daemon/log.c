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
#include "main.h"




__thread struct log_info log_info;
__thread GSList *log_info_stack;

int _log_facility_cdr = 0;
int _log_facility_rtcp = 0;
int _log_facility_dtmf = 0;

typedef void (ilog_prefix_func)(char *prefix, size_t prefix_len);

static ilog_prefix_func ilog_prefix_default;
static ilog_prefix_func ilog_prefix_parsable;

static ilog_prefix_func *ilog_prefix = ilog_prefix_default;

static ilog_prefix_func * const ilog_prefix_funcs[__LF_LAST] = {
	[LF_DEFAULT] = ilog_prefix_default,
	[LF_PARSABLE] = ilog_prefix_parsable,
};



static void ilog_prefix_default(char *prefix, size_t prefix_len) {
	switch (log_info.e) {
		case LOG_INFO_NONE:
			prefix[0] = 0;
			break;
		case LOG_INFO_CALL:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "]: ",
					STR_FMT_M(&log_info.u.call->callid));
			break;
		case LOG_INFO_STREAM_FD:
			if (log_info.u.stream_fd->call)
				snprintf(prefix, prefix_len, "[" STR_FORMAT_M " port %5u]: ",
						STR_FMT_M(&log_info.u.stream_fd->call->callid),
						log_info.u.stream_fd->socket.local.port);
			else
				snprintf(prefix, prefix_len, "[no call, port %5u]: ",
						log_info.u.stream_fd->socket.local.port);

			break;
		case LOG_INFO_STR:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "]: ",
					STR_FMT_M(log_info.u.str));
			break;
		case LOG_INFO_C_STRING:
			snprintf(prefix, prefix_len, "[%s%s%s]: ",
					FMT_M(log_info.u.cstr));
			break;
		case LOG_INFO_ICE_AGENT:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "/" STR_FORMAT_M "/%u]: ",
					STR_FMT_M(&log_info.u.ice_agent->call->callid),
					STR_FMT_M(&log_info.u.ice_agent->media->monologue->tag),
					log_info.u.ice_agent->media->index);
			break;
	}
}

static void ilog_prefix_parsable(char *prefix, size_t prefix_len) {
	switch (log_info.e) {
		case LOG_INFO_NONE:
			prefix[0] = 0;
			break;
		case LOG_INFO_CALL:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\"]: ",
					STR_FMT(&log_info.u.call->callid));
			break;
		case LOG_INFO_STREAM_FD:
			if (log_info.u.stream_fd->call)
				snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\" port=\"%5u\"]: ",
						STR_FMT(&log_info.u.stream_fd->call->callid),
						log_info.u.stream_fd->socket.local.port);
			break;
		case LOG_INFO_STR:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\"]: ",
					STR_FMT(log_info.u.str));
			break;
		case LOG_INFO_C_STRING:
			snprintf(prefix, prefix_len, "[ID=\"%s\"]: ", log_info.u.cstr);
			break;
		case LOG_INFO_ICE_AGENT:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\" tag=\""STR_FORMAT"\" index=\"%u\"]: ",
					STR_FMT(&log_info.u.ice_agent->call->callid),
					STR_FMT(&log_info.u.ice_agent->media->monologue->tag),
					log_info.u.ice_agent->media->index);
			break;
	}
}

void __ilog(int prio, const char *fmt, ...) {
	char prefix[300];
	va_list ap;

	ilog_prefix(prefix, sizeof(prefix));

	va_start(ap, fmt);
	__vpilog(prio, prefix, fmt, ap);
	va_end(ap);
}

void log_format(enum log_format f) {
	if (f >= __LF_LAST)
		die("Invalid log format enum");
	ilog_prefix = ilog_prefix_funcs[f];
	if (!ilog_prefix)
		die("Invalid log format enum");
}

void cdrlog(const char* cdrbuffer) {
	if (_log_facility_cdr) {
		syslog(LOG_INFO | _log_facility_cdr, "%s", cdrbuffer);
	}
}

void dtmflog(GString *s) {
	if (_log_facility_dtmf) {
		syslog(LOG_INFO | _log_facility_dtmf, "%s", s->str);
	}
}


void rtcplog(const char* cdrbuffer) {
    syslog(LOG_INFO | _log_facility_rtcp, "%s", cdrbuffer);
}

int get_local_log_level(unsigned int subsystem_idx) {
	struct call *call = NULL;

	switch (log_info.e) {
		case LOG_INFO_CALL:
			call = log_info.u.call;
			break;
		case LOG_INFO_STREAM_FD:
			call = log_info.u.stream_fd->call;
			break;
		case LOG_INFO_ICE_AGENT:
			call = log_info.u.ice_agent->call;
			break;
		default:
			break;
	}
	if (!call)
		return -1;
	if (call->foreign_call)
		return 5 | LOG_FLAG_MAX;
	if (call->debug)
		return 8;
	return -1;
}
