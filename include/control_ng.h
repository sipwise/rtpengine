#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

enum ng_command {
	NGC_PING = 0,
	NGC_OFFER,
	NGC_ANSWER,
	NGC_DELETE,
	NGC_QUERY,
	NGC_LIST,
	NGC_START_RECORDING,
	NGC_STOP_RECORDING,
	NGC_PAUSE_RECORDING,
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
#include "types.h"

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
	socket_t udp_listener;
	struct streambuf_listener tcp_listener;
};

struct ng_buffer {
	struct obj obj;
	bencode_buffer_t buffer;
	struct obj *ref;
};

extern const char *ng_command_strings[NGC_COUNT];
extern const char *ng_command_strings_esc[NGC_COUNT];
extern const char *ng_command_strings_short[NGC_COUNT];

struct control_ng *control_ng_new(const endpoint_t *);
struct control_ng *control_ng_tcp_new(const endpoint_t *);
void notify_ng_tcp_clients(str *);
void control_ng_init(void);
void control_ng_cleanup(void);
int control_ng_process(str *buf, const endpoint_t *sin, char *addr, const sockaddr_t *local,
		void (*cb)(str *, str *, const endpoint_t *, const sockaddr_t *, void *), void *p1, struct obj *);
int control_ng_process_plain(str *buf, const endpoint_t *sin, char *addr, const sockaddr_t *local,
		void (*cb)(str *, str *, const endpoint_t *, const sockaddr_t *, void *), void *p1, struct obj *);
void init_ng_tracing(void);

ng_buffer *ng_buffer_new(struct obj *ref);

INLINE void ng_buffer_release(ng_buffer *ngbuf) {
	obj_put(ngbuf);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(ng_buffer, ng_buffer_release)

extern mutex_t rtpe_cngs_lock;
extern GHashTable *rtpe_cngs_hash;

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
