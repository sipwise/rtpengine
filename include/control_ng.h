#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

struct poller;

enum ng_command {
	NGC_PING = 0,
	NGC_OFFER,
	NGC_ANSWER,
	NGC_DELETE,
	NGC_QUERY,
	NGC_LIST,
	NGC_START_RECORDING,
	NGC_STOP_RECORDING,
	NGC_START_FORWARDING,
	NGC_STOP_FORWARDING,
	NGC_BLOCK_DTMF,
	NGC_UNBLOCK_DTMF,
	NGC_BLOCK_MEDIA,
	NGC_UNBLOCK_MEDIA,
	NGC_PLAY_MEDIA,
	NGC_STOP_MEDIA,
	NGC_PLAY_DTMF,
	NGC_STATISTICS,
	NGC_SILENCE_MEDIA,
	NGC_UNSILENCE_MEDIA,
	NGC_PUBLISH,
	NGC_SUBSCRIBE_REQ,
	NGC_SUBSCRIBE_ANS,
	NGC_UNSUBSCRIBE,

	NGC_COUNT // last, number of elements
};

#include "obj.h"
#include "udp_listener.h"
#include "socket.h"
#include "str.h"
#include "tcp_listener.h"
#include "bencode.h"

struct ng_command_stats {
	mutex_t lock;
	unsigned int count;
	struct timeval time;
};

struct control_ng_stats {
	sockaddr_t proxy;
	struct ng_command_stats cmd[NGC_COUNT];
	int errors;
};

struct control_ng {
	struct obj obj;
	socket_t udp_listeners[2];
	struct streambuf_listener tcp_listeners[2];
	struct poller *poller;
};

struct ng_buffer {
	struct obj obj;
	mutex_t lock;
	bencode_buffer_t buffer;
	struct obj *ref;
};

extern const char *ng_command_strings[NGC_COUNT];
extern const char *ng_command_strings_short[NGC_COUNT];

struct control_ng *control_ng_new(struct poller *, endpoint_t *, unsigned char);
struct control_ng *control_ng_tcp_new(struct poller *, endpoint_t *, struct control_ng *);
void notify_ng_tcp_clients(str *);
void control_ng_init(void);
void control_ng_cleanup(void);
int control_ng_process(str *buf, const endpoint_t *sin, char *addr,
		void (*cb)(str *, str *, const endpoint_t *, void *), void *p1, struct obj *);

INLINE void ng_buffer_release(struct ng_buffer *ngbuf) {
	mutex_unlock(&ngbuf->lock);
	obj_put(ngbuf);
}

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
