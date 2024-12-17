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
INLINE void __log_info_push(void) {
	if (log_info.e == LOG_INFO_NONE)
		return;
	struct log_info *copy = g_slice_alloc(sizeof(*copy));
	*copy = log_info;
	log_info_stack = g_slist_prepend(log_info_stack, copy);
	ZERO(log_info);
}

// should be paired with any invocation of log_info_X()
INLINE void log_info_pop(void) {
	__log_info_release(&log_info);

	if (!log_info_stack) {
		ZERO(log_info);
		call_memory_arena_release();
		return;
	}

	struct log_info *next = log_info_stack->data;
	log_info = *next;
	g_slice_free1(sizeof(*next), next);
	log_info_stack = g_slist_delete_link(log_info_stack, log_info_stack);
}
// should be used with non-refcounted log info pieces
INLINE void log_info_pop_until(void *p) {
	assert(p != NULL);
	while (log_info.ptr) {
		void *prev = log_info.ptr;
		log_info_pop();
		if (prev == p)
			break;
	}
}
// clears current log context and entire stack
INLINE void log_info_reset(void) {
	__log_info_release(&log_info);
	ZERO(log_info);
	call_memory_arena_release();

	while (log_info_stack) {
		struct log_info *element = log_info_stack->data;
		__log_info_release(element);
		g_slice_free1(sizeof(*element), element);
		log_info_stack = g_slist_delete_link(log_info_stack, log_info_stack);
	}
}

INLINE void log_info_call(call_t *c) {
	if (!c)
		return;
	__log_info_push();
	log_info.e = LOG_INFO_CALL;
	log_info.call = obj_get(c);
	call_memory_arena_set(c);
}
INLINE void log_info_stream_fd(stream_fd *sfd) {
	if (!sfd)
		return;
	__log_info_push();
	log_info.e = LOG_INFO_STREAM_FD;
	log_info.stream_fd = obj_get(sfd);
	call_memory_arena_set(sfd->call);
}
INLINE void log_info_str(const str *s) {
	if (!s || !s->s)
		return;
	__log_info_push();
	log_info.e = LOG_INFO_STR;
	log_info.str = s;
}
INLINE void log_info_c_string(const char *s) {
	if (!s)
		return;
	__log_info_push();
	log_info.e = LOG_INFO_C_STRING;
	log_info.cstr = s;
}
INLINE void log_info_ice_agent(struct ice_agent *ag) {
	if (!ag)
		return;
	__log_info_push();
	log_info.e = LOG_INFO_ICE_AGENT;
	log_info.ice_agent = (struct ice_agent *) obj_get(&ag->tt_obj);
	call_memory_arena_set(ag->call);
}
INLINE void log_info_media(struct call_media *m) {
	if (!m)
		return;
	if (!m->call)
		return;
	__log_info_push();
	log_info.e = LOG_INFO_MEDIA;
	log_info.call = obj_get(m->call);
	log_info.media = m;
	call_memory_arena_set(m->call);
}




#endif
