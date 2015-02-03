#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

#include "obj.h"
#include "cookie_cache.h"
#include "udp_listener.h"


struct poller;
struct callmaster;

struct control_ng_stats {
	struct sockaddr_in6 proxy;
	u_int32_t ping;
	u_int32_t offer;
	u_int32_t answer;
	u_int32_t delete;
	u_int32_t query;
	u_int32_t list;
	u_int32_t errors;
	struct control_ng_stats* next;
};

struct control_ng {
	struct obj obj;
	struct callmaster *callmaster;
	struct cookie_cache cookie_cache;
	struct udp_listener udp_listener;
};

struct control_ng *control_ng_new(struct poller *, struct in6_addr, u_int16_t, struct callmaster *);


#endif
