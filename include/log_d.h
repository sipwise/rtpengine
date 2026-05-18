#ifndef _LOG_D_H_
#define _LOG_D_H_

#include "types.h"
#include "str.h"
#include "loglib.h"
#include "ll_d.h"


struct ice_agent;
enum log_format;


struct log_info {
	union {
		call_t *call;
		stream_fd *stream_fd;
		const str *str;
		const char *cstr;
		struct ice_agent *ice_agent;
		void *ptr;
	};
	union {
		struct call_media *media;
	};
	enum {
		LOG_INFO_NONE = 0,
		LOG_INFO_CALL,
		LOG_INFO_STREAM_FD,
		LOG_INFO_STR,
		LOG_INFO_C_STRING,
		LOG_INFO_ICE_AGENT,
		LOG_INFO_MEDIA,
	} e;
};


extern int _log_facility_cdr;
extern int _log_facility_rtcp;
extern int _log_facility_dtmf;


#define LOG_INFO_STACK_SIZE 8
extern __thread struct log_info log_info[LOG_INFO_STACK_SIZE];
extern __thread unsigned int log_info_idx;



void cdrlog(const char* cdrbuffer);
void rtcplog(const char* cdrbuffer);
void dtmflog(GString *s);


void log_format(enum log_format);
void __ilog(int prio, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));


void log_info_pop(void);
void log_info_pop_until(void *p);

void log_info_call(call_t *c);
void log_info_stream_fd(stream_fd *sfd);
void log_info_str(const str *s);
void log_info_c_string(const char *s);
void log_info_ice_agent(struct ice_agent *ag);
void log_info_media(struct call_media *m);

#endif
