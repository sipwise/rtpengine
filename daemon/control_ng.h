#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

#include "obj.h"
#include "cookie_cache.h"
#include "udp_listener.h"
#include "socket.h"


struct poller;
struct callmaster;

struct control_ng_stats {
	sockaddr_t proxy;
	int ping;
	int offer;
	int answer;
	int delete;
	int query;
	int list;
	int start_recording;
	int errors;
};

struct control_ng {
	struct obj obj;
	struct callmaster *callmaster;
	struct cookie_cache cookie_cache;
	struct udp_listener udp_listeners[2];
};

struct control_ng *control_ng_new(struct poller *, endpoint_t *, struct callmaster *);

#endif
