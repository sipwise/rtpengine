#ifndef __LOG_H__
#define __LOG_H__


#include <syslog.h>
#include <glib.h>
#include "compat.h"



struct log_info {
	union {
		struct call *call;
		struct stream_fd *stream_fd;
	} u;
	enum {
		LOG_INFO_NONE = 0,
		LOG_INFO_CALL,
		LOG_INFO_STREAM_FD,
	} e;
};




extern struct log_info __thread log_info;
extern volatile gint log_level;




void ilog(int prio, const char *fmt, ...)__attribute__ ((format (printf, 2, 3)));




#include "obj.h"




INLINE void log_info_clear() {
	switch (log_info.e) {
		case LOG_INFO_NONE:
			return;
		case LOG_INFO_CALL:
			__obj_put((void *) log_info.u.call);
			break;
		case LOG_INFO_STREAM_FD:
			__obj_put((void *) log_info.u.stream_fd);
			break;
	}
	log_info.e = LOG_INFO_NONE;
}
INLINE void log_info_call(struct call *c) {
	log_info_clear();
	if (!c)
		return;
	log_info.e = LOG_INFO_CALL;
	log_info.u.call =  __obj_get((void *) c);
}
INLINE void log_info_stream_fd(struct stream_fd *sfd) {
	log_info_clear();
	if (!sfd)
		return;
	log_info.e = LOG_INFO_STREAM_FD;
	log_info.u.stream_fd = __obj_get((void *) sfd);
}






#define LOG_ERROR LOG_ERR
#define LOG_WARN LOG_WARNING


#define LOG_LEVEL_MASK(v)	((v) & 0x0f)

#define LOG_FLAG_RESTORE	0x10



#endif
