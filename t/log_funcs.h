#ifndef _LOG_FUNCS_H_
#define _LOG_FUNCS_H_

#include "aux.h"
#include "str.h"

struct call;
struct stream_fd;
struct ice_agent;

INLINE void log_info_reset(void) {
}
INLINE void log_info_pop(void) {
}
INLINE void log_info_pop_until(void *p) {
}
INLINE void log_info_call(struct call *c) {
}
INLINE void log_info_stream_fd(struct stream_fd *sfd) {
}
INLINE void log_info_str(const str *s) {
}
INLINE void log_info_c_string(const char *s) {
}
INLINE void log_info_ice_agent(struct ice_agent *ag) {
}

#endif
