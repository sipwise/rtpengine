#ifndef __LOG_H__
#define __LOG_H__


#include "str.h"
#include "loglib.h"
#include "types.h"



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

// call debug
#ifdef __DEBUG
#define __C_DBG(x...) ilog(LOG_DEBUG, x)
#else
#define __C_DBG(x...) ilogs(internals, LOG_DEBUG, x)
#endif


#endif
