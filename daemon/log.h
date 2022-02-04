#ifndef __LOG_H__
#define __LOG_H__


#include "str.h"
#include "loglib.h"



struct call;
struct stream_fd;
struct ice_agent;
enum log_format;

struct log_info {
	union {
		struct call *call;
		struct stream_fd *stream_fd;
		const str *str;
		const char *cstr;
		struct ice_agent *ice_agent;
		void *ptr;
	} u;
	enum {
		LOG_INFO_NONE = 0,
		LOG_INFO_CALL,
		LOG_INFO_STREAM_FD,
		LOG_INFO_STR,
		LOG_INFO_C_STRING,
		LOG_INFO_ICE_AGENT,
	} e;
};

extern int _log_facility_cdr;
extern int _log_facility_rtcp;
extern int _log_facility_dtmf;


extern __thread struct log_info log_info;
extern __thread GSList *log_info_stack;



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
