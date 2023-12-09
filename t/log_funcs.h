#ifndef _LOG_FUNCS_H_
#define _LOG_FUNCS_H_

#include "helpers.h"
#include "str.h"
#include "types.h"

struct ice_agent;
struct call_media;

INLINE void log_info_reset(void) {
}
INLINE void log_info_pop(void) {
}
INLINE void log_info_pop_until(void *p) {
}
INLINE void log_info_call(call_t *c) {
}
INLINE void log_info_stream_fd(stream_fd *sfd) {
}
INLINE void log_info_str(const str *s) {
}
INLINE void log_info_c_string(const char *s) {
}
INLINE void log_info_ice_agent(struct ice_agent *ag) {
}
INLINE void log_info_media(struct call_media *m) {
}

#endif
