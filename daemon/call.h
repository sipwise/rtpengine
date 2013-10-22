#ifndef __CALL_H__
#define __CALL_H__




#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <pcre.h>

#include "control_tcp.h"
#include "control_udp.h"
#include "obj.h"
#include "aux.h"
#include "bencode.h"
#include "str.h"
#include "crypto.h"



#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	256
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)



struct poller;
struct control_stream;
struct peer;
struct callstream;
struct call;
struct callmaster;
struct redis;
struct crypto_suite;




enum stream_address_format {
	SAF_TCP,
	SAF_UDP,
	SAF_NG,
	SAF_ICE,
};
enum stream_direction {
	DIR_UNKNOWN = 0,
	DIR_INTERNAL,
	DIR_EXTERNAL,
};
enum call_opmode {
	OP_OFFER = 0,
	OP_ANSWER = 1,
	OP_OTHER,
};

enum transport_protocol {
	PROTO_UNKNOWN = 0,
	PROTO_RTP_AVP,
	PROTO_RTP_SAVP,
	PROTO_RTP_AVPF,
	PROTO_RTP_SAVPF,

	__PROTO_LAST
};
extern const char *transport_protocol_strings[__PROTO_LAST];

struct stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
};

struct stream {
	struct in6_addr		ip46;
	u_int16_t		port;
	int			num;
	enum transport_protocol	protocol;
};
struct stream_input {
	struct stream		stream;
	enum stream_direction	direction[2];
	int			consecutive_num;
	struct crypto_context	crypto;
	int			has_rtcp:1;
	int			is_rtcp:1;
	int			rtcp_mux:1;
};
struct udp_fd {
	int			fd;
	u_int16_t		localport;
};

struct streamrelay;
struct mediaproxy_srtp;
struct streamhandler;

struct streamrelay {
	struct udp_fd		fd;
	struct stream		peer;
	struct stream		peer_advertised;
	unsigned char		idx;
	struct peer		*up;
	struct streamrelay	*other;
	struct stats		stats;
	struct stats		kstats;
	time_t			last;
	const struct streamhandler *handler;
	struct crypto_context_pair crypto;
	int			stun:1;
	int			rtcp:1;
	int			rtcp_mux:1;
	int			no_kernel_support:1;
};
struct relays_cache {
	struct udp_fd		relays_A[16];
	struct udp_fd		relays_B[16];
	struct udp_fd		*array_ptrs[2];
	int			relays_open;
};
struct peer {
	struct streamrelay	rtps[2];
	str			tag;
	char			*codec;
	unsigned char		idx;
	struct callstream	*up;
	struct peer		*other;
	int			desired_family;
	str			ice_ufrag;
	str			ice_pwd;
	int			kernelized:1;
	int			filled:1;
	int			confirmed:1;
};
struct callstream {
	struct obj		obj;
	mutex_t			lock;
	struct peer		peers[2];
	struct call		*call;
	int			num;
};

struct call {
	struct obj		obj;

	struct callmaster	*callmaster;

	mutex_t			chunk_lock;
	GStringChunk		*chunk;

	mutex_t			lock;
	GQueue			*callstreams;
	GHashTable		*branches;

	str			callid;
	char			redis_uuid[37];
	time_t			created;
	time_t			lookup_done;
};

struct callmaster_config {
	int			kernelfd;
	unsigned int		kernelid;
	u_int32_t		ipv4;
	u_int32_t		adv_ipv4;
	struct in6_addr		ipv6;
	struct in6_addr		adv_ipv6;
	int			port_min;
	int			port_max;
	unsigned int		timeout;
	unsigned int		silent_timeout;
	struct redis		*redis;
	char			*b2b_url;
	unsigned char		tos;
};

struct callmaster;



struct callmaster *callmaster_new(struct poller *);
void callmaster_config(struct callmaster *m, struct callmaster_config *c);
void callmaster_exclude_port(struct callmaster *m, u_int16_t p);
int callmaster_has_ipv6(struct callmaster *);
void callmaster_msg_mh_src(struct callmaster *, struct msghdr *);


str *call_request_tcp(char **, struct callmaster *);
str *call_lookup_tcp(char **, struct callmaster *);
void call_delete_tcp(char **, struct callmaster *);
void calls_status_tcp(struct callmaster *, struct control_stream *);

str *call_update_udp(char **, struct callmaster *);
str *call_lookup_udp(char **, struct callmaster *);
str *call_delete_udp(char **, struct callmaster *);
str *call_query_udp(char **, struct callmaster *);

const char *call_offer_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);
const char *call_answer_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);
const char *call_delete_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);
const char *call_query_ng(bencode_item_t *, struct callmaster *, bencode_item_t *);


void calls_dump_redis(struct callmaster *);

struct call *call_get_or_create(const str *callid, const str *viabranch, struct callmaster *m);
struct callstream *callstream_new(struct call *ca, int num);
void callstream_init(struct callstream *s, struct relays_cache *);
void kernelize(struct callstream *c);
int call_stream_address(char *o, struct peer *p, enum stream_address_format format, int *len);
int call_stream_address_alt(char *o, struct peer *p, enum stream_address_format format, int *len);

void relays_cache_init(struct relays_cache *c);
int relays_cache_want_ports(struct relays_cache *c, int portA, int portB, struct call *call);
void relays_cache_cleanup(struct relays_cache *c, struct callmaster *m);

enum transport_protocol transport_protocol(const str *s);




static inline char *call_strdup(struct call *c, const char *s) {
	char *r;
	if (!s)
		return NULL;
	mutex_lock(&c->chunk_lock);
	r = g_string_chunk_insert(c->chunk, s);
	mutex_unlock(&c->chunk_lock);
	return r;
}
static inline str *call_str_cpy_len(struct call *c, str *out, const char *in, int len) {
	if (!in) {
		*out = STR_NULL;
		return out;
	}
	mutex_lock(&c->chunk_lock);
	out->s = g_string_chunk_insert_len(c->chunk, in, len);
	mutex_unlock(&c->chunk_lock);
	out->len = len;
	return out;
}
static inline str *call_str_cpy(struct call *c, str *out, const str *in) {
	return call_str_cpy_len(c, out, in ? in->s : NULL, in ? in->len : 0);
}
static inline str *call_str_cpy_c(struct call *c, str *out, const char *in) {
	return call_str_cpy_len(c, out, in, in ? strlen(in) : 0);
}
static inline str *call_str_dup(struct call *c, const str *in) {
	str *out;
	mutex_lock(&c->chunk_lock);
	out = str_chunk_insert(c->chunk, in);
	mutex_unlock(&c->chunk_lock);
	return out;
}
static inline str *call_str_init_dup(struct call *c, char *s) {
	str t;
	str_init(&t, s);
	return call_str_dup(c, &t);
}



#endif
