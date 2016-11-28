#ifndef __LOG_H__
#define __LOG_H__


#include "str.h"
#include "loglib.h"



struct call;
struct stream_fd;
struct ice_agent;

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


extern struct log_info __thread log_info;



void cdrlog(const char* cdrbuffer);
void rtcplog(const char* cdrbuffer);


#define ilog(...) __ilog(__VA_ARGS__)
void __ilog(int prio, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));


#endif
