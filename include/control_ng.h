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
	JsonParser *json;
	struct sdp_chopper *chopper;
	char *sdp_out;
	struct call *call;
};


enum call_opmode {
	OP_OFFER = 0,
	OP_ANSWER = 1,
	OP_REQUEST,
	OP_REQ_ANSWER,
	OP_PUBLISH,
	OP_DELETE,
	OP_QUERY,
	OP_LIST,
	OP_PING,
	OP_STATISTICS,
	OP_PLAY_DTMF,
	OP_BLOCK_DTMF,
	OP_UNBLOCK_DTMF,
	OP_BLOCK_MEDIA,
	OP_UNBLOCK_MEDIA,
	OP_SILENCE_MEDIA,
	OP_UNSILENCE_MEDIA,
	OP_BLOCK_SILENCE_MEDIA,
	OP_UNBLOCK_SILENCE_MEDIA,
	OP_PLAY_MEDIA,
	OP_STOP_MEDIA,
	OP_START_FORWARDING,
	OP_STOP_FORWARDING,
	OP_SUBSCRIBER_REQ,
	OP_SUBSCRIBER_ANS,
	OP_UNSUBSCRIBE,
	OP_START_RECORDING,
	OP_STOP_RECORDING,
	OP_PAUSE_RECORDING,
	OP_OTHER,
};

typedef union {
	const struct sdp_attr_helper *attr_helper;
	str_q *q;
	str_case_ht *sct;
	str_case_value_ht *svt;
	int *i;
	struct sdp_manipulations *sm;
	void *generic;
} helper_arg  __attribute__ ((__transparent_union__));

struct ng_parser {
	str *(*collapse)(bencode_item_t *root, str *out);
	bool (*dict_iter)(ng_parser_ctx_t *, bencode_item_t *,
		void (*callback)(ng_parser_ctx_t *, str *, bencode_item_t *, helper_arg),
		helper_arg);
	bool (*is_list)(bencode_item_t *);
	void (*list_iter)(ng_parser_ctx_t *, bencode_item_t *input,
			void (*str_callback)(ng_parser_ctx_t *, str *key, helper_arg),
			void (*item_callback)(ng_parser_ctx_t *, bencode_item_t *, helper_arg),
			helper_arg);
	str *(*get_str)(bencode_item_t *, str *s);
	long long (*get_int_str)(bencode_item_t *, long long def);
	bool (*is_int)(bencode_item_t *);
	long long (*get_int)(bencode_item_t *);
	bool (*is_dict)(bencode_item_t *);
	bencode_item_t *(*dict)(ng_parser_ctx_t *);
	char *(*dict_get_str)(bencode_item_t *, const char *, str *);
	bencode_item_t *(*dict_add)(bencode_item_t *, const char *, bencode_item_t *);
	void (*dict_add_string)(bencode_item_t *, const char *, const char *);
	void (*dict_add_str)(bencode_item_t *, const char *, const str *);
	void (*dict_add_str_dup)(bencode_item_t *, const char *, const str *);
	void (*dict_add_int)(bencode_item_t *, const char *, long long);
	bencode_item_t *(*dict_add_dict)(bencode_item_t *, const char *);
	bencode_item_t *(*dict_add_list)(bencode_item_t *, const char *);
	bencode_item_t *(*list)(ng_parser_ctx_t *);
	bencode_item_t *(*list_add)(bencode_item_t *, bencode_item_t *);
	bencode_item_t *(*list_add_dict)(bencode_item_t *);
	void (*list_add_string)(bencode_item_t *, const char *);
	void (*pretty_print)(bencode_item_t *, GString *);
};
struct ng_parser_ctx {
	const ng_parser_t *parser;
	struct ng_buffer *ngbuf;
	bencode_item_t *req;
	bencode_item_t *resp;
	sdp_ng_flags *flags;
	enum call_opmode opmode;
};


extern const ng_parser_t ng_parser_native;
extern const ng_parser_t ng_parser_json;


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
