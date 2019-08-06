#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

#include "obj.h"
#include "cookie_cache.h"
#include "udp_listener.h"
#include "socket.h"


struct poller;

struct control_ng_stats {
	sockaddr_t proxy;
	int ping;
	int offer;
	int answer;
	int delete;
	int query;
	int list;
	int start_recording;
	int stop_recording;
	int start_forwarding;
	int stop_forwarding;
	int block_dtmf;
	int unblock_dtmf;
	int block_media;
	int unblock_media;
	int play_media;
	int stop_media;
	int play_dtmf;
	int errors;
};

struct control_ng {
	struct obj obj;
	struct cookie_cache cookie_cache;
	socket_t udp_listeners[2];
};

struct control_ng *control_ng_new(struct poller *, endpoint_t *, unsigned char);
void control_ng_init(void);

extern mutex_t rtpe_cngs_lock;
extern GHashTable *rtpe_cngs_hash;
extern struct control_ng *rtpe_control_ng;

enum load_limit_reasons {
	LOAD_LIMIT_NONE = -1,
	LOAD_LIMIT_MAX_SESSIONS = 0,
	LOAD_LIMIT_CPU,
	LOAD_LIMIT_LOAD,
	LOAD_LIMIT_BW,

	__LOAD_LIMIT_MAX
};
extern const char magic_load_limit_strings[__LOAD_LIMIT_MAX][64];

#endif
