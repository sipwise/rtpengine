#ifndef _CONTROL_NG_H_
#define _CONTROL_NG_H_

#define NG_COMMANDS(X, XA) \
	X(OP_PING,                  "ping",                  "ping",                  "Ping",       call_ping_ng) \
	XA(OP_OFFER,                 "offer",                 "offer",                 "Offer",      call_offer_ng) \
	X(OP_ANSWER,                "answer",                "answer",                "Answer",     call_answer_ng) \
	X(OP_DELETE,                "delete",                "delete",                "Delete",     call_delete_ng) \
	X(OP_QUERY,                 "query",                 "query",                 "Query",      call_query_ng) \
	X(OP_LIST,                  "list",                  "list",                  "List",       call_list_ng) \
	X(OP_START_RECORDING,       "start recording",       "start_recording",       "StartRec",   call_start_recording_ng) \
	X(OP_STOP_RECORDING,        "stop recording",        "stop_recording",        "StopRec",    call_stop_recording_ng) \
	X(OP_PAUSE_RECORDING,       "pause recording",       "pause_recording",       "PauseRec",   call_pause_recording_ng) \
	X(OP_START_FORWARDING,      "start forwarding",      "start_forwarding",      "StartFwd",   call_start_forwarding_ng) \
	X(OP_STOP_FORWARDING,       "stop forwarding",       "stop_forwarding",       "StopFwd",    call_stop_forwarding_ng) \
	X(OP_BLOCK_DTMF,            "block DTMF",            "block_DTMF",            "BlkDTMF",    call_block_dtmf_ng) \
	X(OP_UNBLOCK_DTMF,          "unblock DTMF",          "unblock_DTMF",          "UnblkDTMF",  call_unblock_dtmf_ng) \
	X(OP_BLOCK_MEDIA,           "block media",           "block_media",           "BlkMedia",   call_block_media_ng) \
	X(OP_UNBLOCK_MEDIA,         "unblock media",         "unblock_media",         "UnblkMedia", call_unblock_media_ng) \
	X(OP_PLAY_MEDIA,            "play media",            "play_media",            "PlayMedia",  call_play_media_ng) \
	X(OP_STOP_MEDIA,            "stop media",            "stop_media",            "StopMedia",  call_stop_media_ng) \
	X(OP_PLAY_DTMF,             "play DTMF",             "play_DTMF",             "PlayDTMF",   call_play_dtmf_ng) \
	X(OP_STATISTICS,            "statistics",            "statistics",            "Stats",      statistics_ng) \
	X(OP_SILENCE_MEDIA,         "silence media",         "silence_media",         "SlnMedia",   call_silence_media_ng) \
	X(OP_UNSILENCE_MEDIA,       "unsilence media",       "unsilence_media",       "UnslnMedia", call_unsilence_media_ng) \
	XA(OP_PUBLISH,               "publish",               "publish",               "Pub",        call_publish_ng) \
	X(OP_SUBSCRIBE_REQ,         "subscribe request",     "subscribe_request",     "SubReq",     call_subscribe_request_ng) \
	X(OP_SUBSCRIBE_ANS,         "subscribe answer",      "subscribe_answer",      "SubAns",     call_subscribe_answer_ng) \
	X(OP_UNSUBSCRIBE,           "unsubscribe",           "unsubscribe",           "Unsub",      call_unsubscribe_ng) \
	X(OP_INJECT_START,          "inject start",          "inject_start",          "InjStart",   call_inject_start_ng) \
	X(OP_INJECT_STOP,           "inject stop",           "inject_stop",           "InjStop",    call_inject_stop_ng) \
	X(OP_CONNECT,               "connect",               "connect",               "Conn",       call_connect_ng) \
	X(OP_CLI,                   "cli",                   "cli",                   "CLI",        cli_ng) \
	X(OP_TRANSFORM,             "transform",             "transform",             "Trnsfm",     call_transform_ng) \
	X(OP_CREATE,                "create",                "create",                "Create",     call_create_ng) \
	X(OP_CREATE_ANSWER,         "create answer",         "create_answer",         "CrtAnsw",    call_create_answer_ng) \
	X(OP_MESH,                  "mesh",                  "mesh",                  "Mesh",       call_mesh_ng)

enum ng_opmode {
#define X(op, name, esc, short_name, handler) op,
#define XA(op, name, esc, short_name, handler) op,
	NG_COMMANDS(X, XA)
#undef XA
#undef X

	OP_COUNT,             /* last, number of real command elements */
	OP_OTHER = OP_COUNT   /* sentinel/alias only, do not use as array index */
};

#include "obj.h"
#include "udp_listener.h"
#include "socket.h"
#include "str.h"
#include "tcp_listener.h"
#include "bencode.h"
#include "types.h"
#include "cli.h"

struct ng_command_stats {
	mutex_t lock;
	unsigned int count;
	int64_t time;
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
	struct call_media *md;
	struct ng_media *media;
	struct ng_codec *codec;
	struct rtp_payload_type *pt;
	struct ng_tag *tag;
	void *generic;
} helper_arg  __attribute__ ((__transparent_union__));


struct ng_parser {
	void (*init)(ng_parser_ctx_t *, bencode_buffer_t *);
	str (*collapse)(ng_parser_ctx_t *, parser_arg, void **);
	const char *(*dict_iter)(const ng_parser_t *, parser_arg,
		const char *(*callback)(const ng_parser_t *, str *, parser_arg, helper_arg),
		helper_arg);
	bool (*is_list)(parser_arg);
	const char *(*list_iter)(const ng_parser_t *, parser_arg input,
			const char *(*str_callback)(str *key, unsigned int, helper_arg),
			const char *(*item_callback)(const ng_parser_t *, parser_arg, helper_arg),
			helper_arg);
	str *(*get_str)(parser_arg, str *s);
	int (*strcmp)(parser_arg, const char *);
	const char *(*strdup)(ng_parser_ctx_t *, const char *);
	long long (*get_int_str)(parser_arg, long long def);
	bool (*is_int)(parser_arg);
	long long (*get_int)(parser_arg);
	bool (*is_dict)(parser_arg);
	parser_arg (*dict)(ng_parser_ctx_t *);
	str (*dict_get_str)(parser_arg, const char *);
	long long (*dict_get_int_str)(parser_arg, const char *, long long def);
	parser_arg (*dict_get_expect)(parser_arg, const char *, bencode_type_t);
	bool (*dict_contains)(parser_arg, const char *);
	parser_arg (*dict_add)(parser_arg, const char *, parser_arg);
	void (*dict_add_string)(parser_arg, const char *, const char *);
	void (*dict_add_str)(parser_arg, const char *, const str *);
	void (*dict_add_str_dup)(parser_arg, const char *, const str *);
	void (*dict_add_str_dup_dup)(parser_arg, const char *, const str *);
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
