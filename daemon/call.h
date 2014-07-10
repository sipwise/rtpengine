#ifndef __CALL_H__
#define __CALL_H__




#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <pcre.h>
#include <openssl/x509.h>
#include "compat.h"




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

enum transport_protocol_index {
	PROTO_RTP_AVP = 0,
	PROTO_RTP_SAVP,
	PROTO_RTP_AVPF,
	PROTO_RTP_SAVPF,
	PROTO_UDP_TLS_RTP_SAVP,
	PROTO_UDP_TLS_RTP_SAVPF,
	PROTO_UDPTL,
};

struct call_monologue;




#include "obj.h"
#include "aux.h"
#include "bencode.h"
#include "str.h"
#include "crypto.h"
#include "dtls.h"



#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	512
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)

#ifdef __DEBUG
#define __C_DBG(x...) ilog(LOG_DEBUG, x)
#else
#define __C_DBG(x...) ((void)0)
#endif




/* flags shared by several of the structs below */
#define SHARED_FLAG_IMPLICIT_RTCP		0x00000001
#define SHARED_FLAG_ASYMMETRIC			0x00000002
#define SHARED_FLAG_SEND			0x00000004
#define SHARED_FLAG_RECV			0x00000008
#define SHARED_FLAG_RTCP_MUX			0x00000010
#define SHARED_FLAG_SETUP_ACTIVE		0x00000020
#define SHARED_FLAG_SETUP_PASSIVE		0x00000040
#define SHARED_FLAG_ICE				0x00000080
#define SHARED_FLAG_STRICT_SOURCE		0x00000100
#define SHARED_FLAG_MEDIA_HANDOVER		0x00000200

/* struct stream_params */
#define SP_FLAG_NO_RTCP				0x00010000
#define SP_FLAG_IMPLICIT_RTCP			SHARED_FLAG_IMPLICIT_RTCP
#define SP_FLAG_RTCP_MUX			SHARED_FLAG_RTCP_MUX
#define SP_FLAG_SEND				SHARED_FLAG_SEND
#define SP_FLAG_RECV				SHARED_FLAG_RECV
#define SP_FLAG_ASYMMETRIC			SHARED_FLAG_ASYMMETRIC
#define SP_FLAG_SETUP_ACTIVE			SHARED_FLAG_SETUP_ACTIVE
#define SP_FLAG_SETUP_PASSIVE			SHARED_FLAG_SETUP_PASSIVE
#define SP_FLAG_ICE				SHARED_FLAG_ICE
#define SP_FLAG_STRICT_SOURCE			SHARED_FLAG_STRICT_SOURCE
#define SP_FLAG_MEDIA_HANDOVER			SHARED_FLAG_MEDIA_HANDOVER

/* struct packet_stream */
#define PS_FLAG_RTP				0x00010000
#define PS_FLAG_RTCP				0x00020000
#define PS_FLAG_IMPLICIT_RTCP			SHARED_FLAG_IMPLICIT_RTCP
#define PS_FLAG_FALLBACK_RTCP			0x00040000
#define PS_FLAG_STUN				0x00080000
#define PS_FLAG_FILLED				0x00100000
#define PS_FLAG_CONFIRMED			0x00200000
#define PS_FLAG_KERNELIZED			0x00400000
#define PS_FLAG_NO_KERNEL_SUPPORT		0x00800000
#define PS_FLAG_HAS_HANDLER			0x01000000
#define PS_FLAG_FINGERPRINT_VERIFIED		0x02000000
#define PS_FLAG_STRICT_SOURCE			SHARED_FLAG_STRICT_SOURCE
#define PS_FLAG_MEDIA_HANDOVER			SHARED_FLAG_MEDIA_HANDOVER

/* struct call_media */
#define MEDIA_FLAG_INITIALIZED			0x00010000
#define MEDIA_FLAG_ASYMMETRIC			SHARED_FLAG_ASYMMETRIC
#define MEDIA_FLAG_SEND				SHARED_FLAG_SEND
#define MEDIA_FLAG_RECV				SHARED_FLAG_RECV
#define MEDIA_FLAG_RTCP_MUX			SHARED_FLAG_RTCP_MUX
#define MEDIA_FLAG_RTCP_MUX_OVERRIDE		0x00020000
#define MEDIA_FLAG_DTLS				0x00040000
#define MEDIA_FLAG_SDES				0x00080000
#define MEDIA_FLAG_SETUP_ACTIVE			SHARED_FLAG_SETUP_ACTIVE
#define MEDIA_FLAG_SETUP_PASSIVE		SHARED_FLAG_SETUP_PASSIVE
#define MEDIA_FLAG_PASSTHRU			0x00100000
#define MEDIA_FLAG_ICE				SHARED_FLAG_ICE

/* access macros */
#define SP_ISSET(p, f)		bf_isset(&(p)->sp_flags, SP_FLAG_ ## f)
#define SP_SET(p, f)		bf_set(&(p)->sp_flags, SP_FLAG_ ## f)
#define SP_CLEAR(p, f)		bf_clear(&(p)->sp_flags, SP_FLAG_ ## f)
#define PS_ISSET(p, f)		bf_isset(&(p)->ps_flags, PS_FLAG_ ## f)
#define PS_SET(p, f)		bf_set(&(p)->ps_flags, PS_FLAG_ ## f)
#define PS_CLEAR(p, f)		bf_clear(&(p)->ps_flags, PS_FLAG_ ## f)
#define MEDIA_ISSET(p, f)	bf_isset(&(p)->media_flags, MEDIA_FLAG_ ## f)
#define MEDIA_SET(p, f)		bf_set(&(p)->media_flags, MEDIA_FLAG_ ## f)
#define MEDIA_CLEAR(p, f)	bf_clear(&(p)->media_flags, MEDIA_FLAG_ ## f)




struct poller;
struct control_stream;
struct call;
struct redis;
struct crypto_suite;
struct mediaproxy_srtp;
struct streamhandler;
struct sdp_ng_flags;


typedef bencode_buffer_t call_buffer_t;
#define call_buffer_alloc bencode_buffer_alloc
#define call_buffer_init bencode_buffer_init
#define call_buffer_free bencode_buffer_free




struct transport_protocol {
	enum transport_protocol_index	index;
	const char			*name;
	int				srtp:1;
	int				avpf:1;
};
extern const struct transport_protocol transport_protocols[];




struct stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
};

struct udp_fd {
	int			fd;
	u_int16_t		localport;
};
struct endpoint {
	struct in6_addr		ip46;
	u_int16_t		port;
};
struct stream_params {
	unsigned int		index; /* starting with 1 */
	str			type;
	struct endpoint		rtp_endpoint;
	struct endpoint		rtcp_endpoint;
	unsigned int		consecutive_ports;
	const struct transport_protocol *protocol;
	struct crypto_params	crypto;
	unsigned int		sdes_tag;
	enum stream_direction	direction[2];
	int			desired_family;
	struct dtls_fingerprint fingerprint;
	unsigned int		sp_flags;
};

struct stream_fd {
	struct obj		obj;
	struct udp_fd		fd;		/* RO */
	struct call		*call;		/* RO */
	struct packet_stream	*stream;	/* LOCK: call->master_lock */
	struct crypto_context	crypto;		/* IN direction, LOCK: stream->in_lock */
	struct dtls_connection	dtls;		/* LOCK: stream->in_lock */
};

struct endpoint_map {
	struct endpoint		endpoint;
	GQueue			sfds;
	int			wildcard:1;
};

struct packet_stream {
	mutex_t			in_lock,
				out_lock;
	/* Both locks valid only with call->master_lock held in R.
	 * Preempted by call->master_lock held in W.
	 * If both in/out are to be locked, in_lock must be locked first. */

	struct call_media	*media;		/* RO */
	struct call		*call;		/* RO */

	struct stream_fd	*sfd;		/* LOCK: call->master_lock */
	struct packet_stream	*rtp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sibling;	/* LOCK: call->master_lock */
	const struct streamhandler *handler;	/* LOCK: in_lock */
	struct endpoint		endpoint;	/* LOCK: out_lock */
	struct endpoint		advertised_endpoint; /* RO */
	struct crypto_context	crypto;		/* OUT direction, LOCK: out_lock */

	struct stats		stats;		/* LOCK: in_lock */
	struct stats		kernel_stats;	/* LOCK: in_lock */
	time_t			last_packet;	/* LOCK: in_lock */

	X509			*dtls_cert;	/* LOCK: in_lock */

	/* in_lock must be held for SETTING these: */
	/* (XXX replace with atomic ops where appropriate) */
	unsigned int		ps_flags;
};

/* protected by call->master_lock, except the RO elements */
struct call_media {
	struct call_monologue	*monologue;	/* RO */
	struct call		*call;		/* RO */

	unsigned int		index;		/* RO */
	str			type;		/* RO */
	const struct transport_protocol *protocol;
	int			desired_family;

	str			ice_ufrag;
	str			ice_pwd;
	struct {
		struct crypto_params	params;
		unsigned int		tag;
	}			sdes_in,
				sdes_out;

	struct dtls_fingerprint fingerprint; /* as received */

	GQueue			streams; /* normally RTP + RTCP */
	GSList			*endpoint_maps;

	unsigned int		media_flags;
};

/* half a dialogue */
/* protected by call->master_lock, except the RO elements */
struct call_monologue {
	struct call		*call;		/* RO */

	str			tag;	
	time_t			created;	/* RO */
	GHashTable		*other_tags;
	struct call_monologue	*active_dialogue;

	GQueue			medias;
};

struct call {
	struct obj		obj;

	struct callmaster	*callmaster;	/* RO */

	mutex_t			buffer_lock;
	call_buffer_t		buffer;

	/* everything below protected by master_lock */
	rwlock_t		master_lock;
	GSList			*monologues;
	GHashTable		*tags;	
	//GHashTable		*branches;
	GSList			*streams;
	GSList			*stream_fds;
	struct dtls_cert	*dtls_cert; /* for outgoing */

	str			callid;	
	time_t			created;
	time_t			last_signal;
};

struct callmaster_config {
	int			kernelfd;
	int			kernelid;
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

struct callmaster {
	struct obj		obj;

	rwlock_t		hashlock;
	GHashTable		*callhash;

	mutex_t			portlock;
	u_int16_t		lastport;
	BIT_ARRAY_DECLARE(ports_used, 0x10000);

	/* XXX rework these */
	mutex_t			statspslock;
	struct stats		statsps;	/* per second stats, running timer */
	mutex_t			statslock;
	struct stats		stats;		/* copied from statsps once a second */

	struct poller		*poller;
	pcre			*info_re;
	pcre_extra		*info_ree;
	pcre			*streams_re;
	pcre_extra		*streams_ree;

	struct callmaster_config conf;
};

struct call_stats {
	time_t		last_packet;
	struct stats	totals[4]; /* rtp in, rtcp in, rtp out, rtcp out */
};



struct callmaster *callmaster_new(struct poller *);
void callmaster_msg_mh_src(struct callmaster *, struct msghdr *);
void callmaster_get_all_calls(struct callmaster *m, GQueue *q);


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
struct call_monologue *__monologue_create(struct call *call);
void __monologue_tag(struct call_monologue *ml, const str *tag);
struct stream_fd *__stream_fd_new(struct udp_fd *fd, struct call *call);
int __get_consecutive_ports(struct udp_fd *array, int array_len, int wanted_start_port, struct call *c);
struct packet_stream *__packet_stream_new(struct call *call);


struct call *call_get_or_create(const str *callid, struct callmaster *m);
struct call *call_get_opmode(const str *callid, struct callmaster *m, enum call_opmode opmode);
struct call_monologue *call_get_mono_dialogue(struct call *call, const str *fromtag, const str *totag);
int monologue_offer_answer(struct call_monologue *monologue, GQueue *streams, const struct sdp_ng_flags *flags);
int call_delete_branch(struct callmaster *m, const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output);
void call_destroy(struct call *);

void kernelize(struct packet_stream *);
int call_stream_address_alt(char *, struct packet_stream *, enum stream_address_format, int *);
int call_stream_address(char *, struct packet_stream *, enum stream_address_format, int *);

const struct transport_protocol *transport_protocol(const str *s);




INLINE void *call_malloc(struct call *c, size_t l) {
	void *ret;
	mutex_lock(&c->buffer_lock);
	ret = call_buffer_alloc(&c->buffer, l);
	mutex_unlock(&c->buffer_lock);
	return ret;
}

INLINE char *call_strdup_len(struct call *c, const char *s, unsigned int len) {
	char *r;
	r = call_malloc(c, len + 1);
	memcpy(r, s, len);
	r[len] = 0;
	return r;
}

INLINE char *call_strdup(struct call *c, const char *s) {
	if (!s)
		return NULL;
	return call_strdup_len(c, s, strlen(s));
}
INLINE str *call_str_cpy_len(struct call *c, str *out, const char *in, int len) {
	if (!in) {
		*out = STR_NULL;
		return out;
	}
	out->s = call_strdup_len(c, in, len);
	out->len = len;
	return out;
}
INLINE str *call_str_cpy(struct call *c, str *out, const str *in) {
	return call_str_cpy_len(c, out, in ? in->s : NULL, in ? in->len : 0);
}
INLINE str *call_str_cpy_c(struct call *c, str *out, const char *in) {
	return call_str_cpy_len(c, out, in, in ? strlen(in) : 0);
}
INLINE str *call_str_dup(struct call *c, const str *in) {
	str *out;
	out = call_malloc(c, sizeof(*out));
	call_str_cpy_len(c, out, in->s, in->len);
	return out;
}
INLINE str *call_str_init_dup(struct call *c, char *s) {
	str t;
	str_init(&t, s);
	return call_str_dup(c, &t);
}
INLINE int callmaster_has_ipv6(struct callmaster *m) {
	return is_addr_unspecified(&m->conf.ipv6) ? 0 : 1;
}
INLINE void callmaster_exclude_port(struct callmaster *m, u_int16_t p) {
	/* XXX atomic bit field? */
	mutex_lock(&m->portlock);
	bit_array_set(m->ports_used, p);
	mutex_unlock(&m->portlock);
}
INLINE struct packet_stream *packet_stream_sink(struct packet_stream *ps) {
	struct packet_stream *ret;
	ret = ps->rtp_sink;
	if (!ret)
		ret = ps->rtcp_sink;
	return ret;
}


#endif
