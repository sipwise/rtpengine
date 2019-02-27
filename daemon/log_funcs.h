#ifndef __LOG_FUNCS_H__
#define __LOG_FUNCS_H__

#include "aux.h"
#include "obj.h"
#include "call.h"
#include "media_socket.h"
#include "ice.h"
#include "log.h"

INLINE void log_info_clear(void) {
	switch (log_info.e) {
		case LOG_INFO_NONE:
			return;
		case LOG_INFO_CALL:
			obj_put(log_info.u.call);
			break;
		case LOG_INFO_STREAM_FD:
			obj_put(log_info.u.stream_fd);
			break;
		case LOG_INFO_ICE_AGENT:
			obj_put(&log_info.u.ice_agent->tt_obj);
			break;
		case LOG_INFO_STR:
		case LOG_INFO_C_STRING:
			break;
	}
	log_info.e = LOG_INFO_NONE;
	log_info.u.ptr = NULL;
}
INLINE void log_info_call(struct call *c) {
	log_info_clear();
	if (!c)
		return;
	log_info.e = LOG_INFO_CALL;
	log_info.u.call = obj_get(c);
}
INLINE void log_info_stream_fd(struct stream_fd *sfd) {
	log_info_clear();
	if (!sfd)
		return;
	log_info.e = LOG_INFO_STREAM_FD;
	log_info.u.stream_fd = obj_get(sfd);
}
INLINE void log_info_str(const str *s) {
	log_info_clear();
	if (!s || !s->s)
		return;
	log_info.e = LOG_INFO_STR;
	log_info.u.str = s;
}
INLINE void log_info_c_string(const char *s) {
	log_info_clear();
	if (!s)
		return;
	log_info.e = LOG_INFO_C_STRING;
	log_info.u.cstr = s;
}
INLINE void log_info_ice_agent(struct ice_agent *ag) {
	log_info_clear();
	if (!ag)
		return;
	log_info.e = LOG_INFO_ICE_AGENT;
	log_info.u.ice_agent = obj_get(&ag->tt_obj);
}




#endif
