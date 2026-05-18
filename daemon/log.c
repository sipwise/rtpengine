#include "log_d.h"

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <glib.h>

#include "str.h"
#include "call.h"
#include "poller.h"
#include "ice.h"
#include "main.h"

__thread struct log_info log_info[LOG_INFO_STACK_SIZE];
__thread unsigned int log_info_idx;

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


static void ilog_prefix_default(char *prefix, size_t prefix_len) {
	switch (log_info[log_info_idx].e) {
		case LOG_INFO_NONE:
			prefix[0] = 0;
			break;
		case LOG_INFO_CALL:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "]: ",
					STR_FMT_M(&log_info[log_info_idx].call->callid));
			break;
		case LOG_INFO_STREAM_FD:
			if (log_info[log_info_idx].stream_fd->call) {
				if (log_info[log_info_idx].stream_fd->stream)
					snprintf(prefix, prefix_len, "[" STR_FORMAT_M "/" STR_FORMAT_M "/%u port %5u]: ",
							STR_FMT_M(&log_info[log_info_idx].stream_fd->call->callid),
							STR_FMT_M(&log_info[log_info_idx].stream_fd->stream->media->monologue->tag),
							log_info[log_info_idx].stream_fd->stream->media->index,
							log_info[log_info_idx].stream_fd->socket.local.port);
				else
					snprintf(prefix, prefix_len, "[" STR_FORMAT_M " port %5u]: ",
							STR_FMT_M(&log_info[log_info_idx].stream_fd->call->callid),
							log_info[log_info_idx].stream_fd->socket.local.port);
			}
			else
				snprintf(prefix, prefix_len, "[no call, port %5u]: ",
						log_info[log_info_idx].stream_fd->socket.local.port);

			break;
		case LOG_INFO_STR:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "]: ",
					STR_FMT_M(log_info[log_info_idx].str));
			break;
		case LOG_INFO_C_STRING:
			snprintf(prefix, prefix_len, "[%s%s%s]: ",
					FMT_M(log_info[log_info_idx].cstr));
			break;
		case LOG_INFO_ICE_AGENT:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "/" STR_FORMAT_M "/%u]: ",
					STR_FMT_M(&log_info[log_info_idx].ice_agent->call->callid),
					STR_FMT_M(&log_info[log_info_idx].ice_agent->media->monologue->tag),
					log_info[log_info_idx].ice_agent->media->index);
			break;
		case LOG_INFO_MEDIA:
			snprintf(prefix, prefix_len, "[" STR_FORMAT_M "/" STR_FORMAT_M "/%u]: ",
					STR_FMT_M(&log_info[log_info_idx].call->callid),
					STR_FMT_M(&log_info[log_info_idx].media->monologue->tag),
					log_info[log_info_idx].media->index);
			break;
	}
}

static void ilog_prefix_parsable(char *prefix, size_t prefix_len) {
	switch (log_info[log_info_idx].e) {
		case LOG_INFO_NONE:
			prefix[0] = 0;
			break;
		case LOG_INFO_CALL:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\"]: ",
					STR_FMT(&log_info[log_info_idx].call->callid));
			break;
		case LOG_INFO_STREAM_FD:
			if (log_info[log_info_idx].stream_fd->call) {
				if (log_info[log_info_idx].stream_fd->stream)
					snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\" tag=\""STR_FORMAT"\" index=\"%u\" port=\"%5u\"]: ",
							STR_FMT(&log_info[log_info_idx].stream_fd->call->callid),
							STR_FMT(&log_info[log_info_idx].stream_fd->stream->media->monologue->tag),
							log_info[log_info_idx].stream_fd->stream->media->index,
							log_info[log_info_idx].stream_fd->socket.local.port);
				else
					snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\" port=\"%5u\"]: ",
							STR_FMT(&log_info[log_info_idx].stream_fd->call->callid),
							log_info[log_info_idx].stream_fd->socket.local.port);
			}
			break;
		case LOG_INFO_STR:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\"]: ",
					STR_FMT(log_info[log_info_idx].str));
			break;
		case LOG_INFO_C_STRING:
			snprintf(prefix, prefix_len, "[ID=\"%s\"]: ", log_info[log_info_idx].cstr);
			break;
		case LOG_INFO_ICE_AGENT:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\" tag=\""STR_FORMAT"\" index=\"%u\"]: ",
					STR_FMT(&log_info[log_info_idx].ice_agent->call->callid),
					STR_FMT(&log_info[log_info_idx].ice_agent->media->monologue->tag),
					log_info[log_info_idx].ice_agent->media->index);
			break;
		case LOG_INFO_MEDIA:
			snprintf(prefix, prefix_len, "[ID=\""STR_FORMAT"\" tag=\""STR_FORMAT"\" index=\"%u\"]: ",
					STR_FMT(&log_info[log_info_idx].call->callid),
					STR_FMT(&log_info[log_info_idx].media->monologue->tag),
					log_info[log_info_idx].media->index);
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
	call_t *call = NULL;

	switch (log_info[log_info_idx].e) {
		case LOG_INFO_CALL:
		case LOG_INFO_MEDIA:
			call = log_info[log_info_idx].call;
			break;
		case LOG_INFO_STREAM_FD:
			call = log_info[log_info_idx].stream_fd->call;
			break;
		case LOG_INFO_ICE_AGENT:
			call = log_info[log_info_idx].ice_agent->call;
			break;
		default:
			break;
	}
	if (!call)
		return -1;
	if (CALL_ISSET(call, FOREIGN))
		return 5 | LOG_FLAG_MAX;
	if (CALL_ISSET(call, DEBUG))
		return 8;
	return -1;
}



INLINE void __log_info_release(struct log_info *li) {
	switch (li->e) {
		case LOG_INFO_NONE:
			return;
		case LOG_INFO_CALL:
		case LOG_INFO_MEDIA:
			obj_put(li->call);
			break;
		case LOG_INFO_STREAM_FD:
			obj_put(li->stream_fd);
			break;
		case LOG_INFO_ICE_AGENT:
			obj_put(&li->ice_agent->tt_obj);
			break;
		case LOG_INFO_STR:
		case LOG_INFO_C_STRING:
			break;
	}
}
INLINE bool __log_info_push(void) {
	if (log_info[log_info_idx].e == LOG_INFO_NONE)
		return true;
	log_info_idx++;
	if (log_info_idx >= LOG_INFO_STACK_SIZE) {
		log_info_idx = LOG_INFO_STACK_SIZE - 1;
		return false;
	}
	ZERO(log_info[log_info_idx]);
	return true;
}

// should be paired with any invocation of log_info_X()
void log_info_pop(void) {
	__log_info_release(&log_info[log_info_idx]);

	if (log_info_idx == 0) {
		ZERO(log_info[0]);
		call_memory_arena_release();
		return;
	}

	log_info_idx--;
}
// should be used with non-refcounted log info pieces
void log_info_pop_until(void *p) {
	assert(p != NULL);
	while (log_info_idx || log_info[log_info_idx].ptr) {
		void *prev = log_info[log_info_idx].ptr;
		log_info_pop();
		if (prev == p)
			break;
	}
}
// clears current log context and entire stack
void log_info_reset(void) {
	while (log_info_idx)
		log_info_pop();

	__log_info_release(&log_info[0]);
	ZERO(log_info[0]);
	call_memory_arena_release();
}

void log_info_call(call_t *c) {
	if (!c)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_CALL;
	log_info[log_info_idx].call = obj_get(c);
	call_memory_arena_set(c);
}
void log_info_stream_fd(stream_fd *sfd) {
	if (!sfd)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_STREAM_FD;
	log_info[log_info_idx].stream_fd = obj_get(sfd);
	call_memory_arena_set(sfd->call);
}
void log_info_str(const str *s) {
	if (!s || !s->s)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_STR;
	log_info[log_info_idx].str = s;
}
void log_info_c_string(const char *s) {
	if (!s)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_C_STRING;
	log_info[log_info_idx].cstr = s;
}
void log_info_ice_agent(struct ice_agent *ag) {
	if (!ag)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_ICE_AGENT;
	log_info[log_info_idx].ice_agent = (struct ice_agent *) obj_get(&ag->tt_obj);
	call_memory_arena_set(ag->call);
}
void log_info_media(struct call_media *m) {
	if (!m)
		return;
	if (!m->call)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_MEDIA;
	log_info[log_info_idx].call = obj_get(m->call);
	log_info[log_info_idx].media = m;
	call_memory_arena_set(m->call);
}
