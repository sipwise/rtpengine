#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

enum ng_opmode {
	OP_PING = 0,
	OP_OFFER,
	OP_ANSWER,
	OP_DELETE,
	OP_QUERY,
	OP_LIST,
	OP_START_RECORDING,
	OP_STOP_RECORDING,
	OP_PAUSE_RECORDING,
	OP_START_FORWARDING,
	OP_STOP_FORWARDING,
	OP_BLOCK_DTMF,
	OP_UNBLOCK_DTMF,
	OP_BLOCK_MEDIA,
	OP_UNBLOCK_MEDIA,
	OP_PLAY_MEDIA,
	OP_STOP_MEDIA,
	OP_PLAY_DTMF,
	OP_STATISTICS,
	OP_SILENCE_MEDIA,
	OP_UNSILENCE_MEDIA,
	OP_BLOCK_SILENCE_MEDIA,
	OP_UNBLOCK_SILENCE_MEDIA,
	OP_PUBLISH,
	OP_SUBSCRIBE_REQ,
	OP_SUBSCRIBE_ANS,
	OP_UNSUBSCRIBE,
	OP_CONNECT,
	OP_CLI,

	OP_COUNT,		// last, number of elements
	OP_OTHER = OP_COUNT	// alias to above
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
	struct ng_command_stats cmd[OP_COUNT];
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
	char *sdp_out;
	struct call *call;
	void *collapsed;
};


typedef union {
	str_q *q;
	str_case_ht *sct;
	str_case_value_ht *svt;
	struct sdp_manipulations *sm;
	struct call *call;
	bool *bools;
	str *strs;
	sdp_ng_flags *flags;
	void (**call_fn)(call_t *);
	GHashTable *ht;
	struct call_monologue *ml;
	void *generic;
} helper_arg  __attribute__ ((__transparent_union__));

struct ng_parser {
	void (*init)(ng_parser_ctx_t *, bencode_buffer_t *);
	str (*collapse)(ng_parser_ctx_t *, parser_arg, void **);
	bool (*dict_iter)(const ng_parser_t *, parser_arg,
		void (*callback)(const ng_parser_t *, str *, parser_arg, helper_arg),
		helper_arg);
	bool (*is_list)(parser_arg);
	void (*list_iter)(const ng_parser_t *, parser_arg input,
			void (*str_callback)(str *key, unsigned int, helper_arg),
			void (*item_callback)(const ng_parser_t *, parser_arg, helper_arg),
			helper_arg);
	str *(*get_str)(parser_arg, str *s);
	int (*strcmp)(parser_arg, const char *);
	const char *(*strdup)(ng_parser_ctx_t *, const char *);
	long long (*get_int_str)(parser_arg, long long def);
	bool (*is_int)(parser_arg);
	long long (*get_int)(parser_arg);
	bool (*is_dict)(parser_arg);
	parser_arg (*dict)(ng_parser_ctx_t *);
	char *(*dict_get_str)(parser_arg, const char *, str *);
	long long (*dict_get_int_str)(parser_arg, const char *, long long def);
	parser_arg (*dict_get_expect)(parser_arg, const char *, bencode_type_t);
	bool (*dict_contains)(parser_arg, const char *);
	parser_arg (*dict_add)(parser_arg, const char *, parser_arg);
	void (*dict_add_string)(parser_arg, const char *, const char *);
	void (*dict_add_str)(parser_arg, const char *, const str *);
	void (*dict_add_str_dup)(parser_arg, const char *, const str *);
	void (*dict_add_int)(parser_arg, const char *, long long);
	parser_arg (*dict_add_dict)(parser_arg, const char *);
	parser_arg (*dict_add_dict_dup)(parser_arg, const char *);
	parser_arg (*dict_add_list)(parser_arg, const char *);
	parser_arg (*dict_add_list_dup)(parser_arg, const char *);
	parser_arg (*list)(ng_parser_ctx_t *);
	parser_arg (*list_add)(parser_arg, parser_arg);
	parser_arg (*list_add_dict)(parser_arg);
	void (*list_add_str_dup)(parser_arg, const str *);
	void (*list_add_string)(parser_arg , const char *);
	void (*pretty_print)(parser_arg, GString *);
	str (*escape)(char *, const char *, size_t);
	str *(*unescape)(const char *, size_t);
};
struct ng_parser_ctx {
	const ng_parser_t *parser;
	bencode_buffer_t *buffer;
};
struct ng_command_ctx {
	ng_parser_ctx_t parser_ctx;
	struct ng_buffer *ngbuf;
	parser_arg req;
	parser_arg resp;
	sdp_ng_flags *flags;
	enum ng_opmode opmode;
};


extern const ng_parser_t ng_parser_native;
extern const ng_parser_t ng_parser_json;


extern const char *ng_command_strings[OP_COUNT];
extern const char *ng_command_strings_esc[OP_COUNT];
extern const char *ng_command_strings_short[OP_COUNT];

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
