#ifndef __LOG_FUNCS_H__
#define __LOG_FUNCS_H__

#include "helpers.h"
#include "obj.h"
#include "call.h"
#include "media_socket.h"
#include "ice.h"
#include "log.h"

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
INLINE void log_info_pop(void) {
	__log_info_release(&log_info[log_info_idx]);

	if (log_info_idx == 0) {
		ZERO(log_info[0]);
		call_memory_arena_release();
		return;
	}

	log_info_idx--;
}
// should be used with non-refcounted log info pieces
INLINE void log_info_pop_until(void *p) {
	assert(p != NULL);
	while (log_info_idx || log_info[log_info_idx].ptr) {
		void *prev = log_info[log_info_idx].ptr;
		log_info_pop();
		if (prev == p)
			break;
	}
}
// clears current log context and entire stack
INLINE void log_info_reset(void) {
	while (log_info_idx)
		log_info_pop();

	__log_info_release(&log_info[0]);
	ZERO(log_info[0]);
	call_memory_arena_release();
}

INLINE void log_info_call(call_t *c) {
	if (!c)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_CALL;
	log_info[log_info_idx].call = obj_get(c);
	call_memory_arena_set(c);
}
INLINE void log_info_stream_fd(stream_fd *sfd) {
	if (!sfd)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_STREAM_FD;
	log_info[log_info_idx].stream_fd = obj_get(sfd);
	call_memory_arena_set(sfd->call);
}
INLINE void log_info_str(const str *s) {
	if (!s || !s->s)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_STR;
	log_info[log_info_idx].str = s;
}
INLINE void log_info_c_string(const char *s) {
	if (!s)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_C_STRING;
	log_info[log_info_idx].cstr = s;
}
INLINE void log_info_ice_agent(struct ice_agent *ag) {
	if (!ag)
		return;
	if (!__log_info_push())
		return;
	log_info[log_info_idx].e = LOG_INFO_ICE_AGENT;
	log_info[log_info_idx].ice_agent = (struct ice_agent *) obj_get(&ag->tt_obj);
	call_memory_arena_set(ag->call);
}
INLINE void log_info_media(struct call_media *m) {
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




#endif
