#ifndef __CALL_H__
#define __CALL_H__



/* XXX split everything into call_signalling.[ch] and call_packets.[ch] or w/e */

#include <glib-object.h>

#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <pcre.h>
#include <openssl/x509.h>
#include <limits.h>
#include "compat.h"
#include "socket.h"
#include "media_socket.h"
#include "recording.h"
#include "statistics.h"

#define UNDEFINED ((unsigned int) -1)

enum termination_reason {
	UNKNOWN=0,
	REGULAR=1,
	FORCED=2,
	TIMEOUT=3,
	SILENT_TIMEOUT=4,
	FINAL_TIMEOUT=5
};

enum tag_type {
	UNKNOWN_TAG=0,
	FROM_TAG=1,
	TO_TAG=2
};

enum stream_address_format {
	SAF_TCP,
	SAF_UDP,
	SAF_NG,
	SAF_ICE,
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

	__PROTO_LAST,
};

enum xmlrpc_format {
	XF_SEMS = 0,
	XF_CALLID,
};

enum call_stream_state {
	CSS_UNKNOWN = 0,
	CSS_SHUTDOWN,
	CSS_ICE,
	CSS_DTLS,
	CSS_RUNNING,
};

enum call_type {
	CT_OWN_CALL = 0,
	CT_FOREIGN_CALL,
};

#define ERROR_NO_FREE_PORTS	-100
#define ERROR_NO_FREE_LOGS	-101

#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	512
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)

#ifndef RTP_LOOP_PROTECT
#define RTP_LOOP_PROTECT	28 /* number of bytes */
#define RTP_LOOP_PACKETS	2  /* number of packets */
#define RTP_LOOP_MAX_COUNT	30 /* number of consecutively detected dupes to trigger protection */
#endif

#ifdef __DEBUG
#define __C_DBG(x...) ilog(LOG_DEBUG, x)
#else
#define __C_DBG(x...) ((void)0)
#endif

#define IS_FOREIGN_CALL(c) (c->foreign_call)
#define IS_OWN_CALL(c) !IS_FOREIGN_CALL(c)

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
#define SHARED_FLAG_TRICKLE_ICE			0x00000400
#define SHARED_FLAG_ICE_LITE			0x00000800
#define SHARED_FLAG_UNIDIRECTIONAL		0x00001000

/* struct stream_params */
#define SP_FLAG_NO_RTCP				0x00010000
#define SP_FLAG_IMPLICIT_RTCP			SHARED_FLAG_IMPLICIT_RTCP
#define SP_FLAG_RTCP_MUX			SHARED_FLAG_RTCP_MUX
#define SP_FLAG_SEND				SHARED_FLAG_SEND
#define SP_FLAG_RECV				SHARED_FLAG_RECV
#define SP_FLAG_ASYMMETRIC			SHARED_FLAG_ASYMMETRIC
#define SP_FLAG_UNIDIRECTIONAL			SHARED_FLAG_UNIDIRECTIONAL
#define SP_FLAG_SETUP_ACTIVE			SHARED_FLAG_SETUP_ACTIVE
#define SP_FLAG_SETUP_PASSIVE			SHARED_FLAG_SETUP_PASSIVE
#define SP_FLAG_ICE				SHARED_FLAG_ICE
#define SP_FLAG_STRICT_SOURCE			SHARED_FLAG_STRICT_SOURCE
#define SP_FLAG_MEDIA_HANDOVER			SHARED_FLAG_MEDIA_HANDOVER
#define SP_FLAG_TRICKLE_ICE			SHARED_FLAG_TRICKLE_ICE
#define SP_FLAG_ICE_LITE			SHARED_FLAG_ICE_LITE

/* struct packet_stream */
#define PS_FLAG_RTP				0x00010000
#define PS_FLAG_RTCP				0x00020000
#define PS_FLAG_IMPLICIT_RTCP			SHARED_FLAG_IMPLICIT_RTCP
#define PS_FLAG_FALLBACK_RTCP			0x00040000
#define PS_FLAG_UNUSED2				0x00080000
#define PS_FLAG_FILLED				0x00100000
#define PS_FLAG_CONFIRMED			0x00200000
#define PS_FLAG_KERNELIZED			0x00400000
#define PS_FLAG_NO_KERNEL_SUPPORT		0x00800000
#define PS_FLAG_UNUSED				0x01000000
#define PS_FLAG_FINGERPRINT_VERIFIED		0x02000000
#define PS_FLAG_STRICT_SOURCE			SHARED_FLAG_STRICT_SOURCE
#define PS_FLAG_MEDIA_HANDOVER			SHARED_FLAG_MEDIA_HANDOVER
#define PS_FLAG_ICE				SHARED_FLAG_ICE

/* struct call_media */
#define MEDIA_FLAG_INITIALIZED			0x00010000
#define MEDIA_FLAG_ASYMMETRIC			SHARED_FLAG_ASYMMETRIC
#define MEDIA_FLAG_UNIDIRECTIONAL		SHARED_FLAG_UNIDIRECTIONAL
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
#define MEDIA_FLAG_TRICKLE_ICE			SHARED_FLAG_TRICKLE_ICE
#define MEDIA_FLAG_ICE_LITE			SHARED_FLAG_ICE_LITE
#define MEDIA_FLAG_ICE_CONTROLLING		0x00200000
#define MEDIA_FLAG_LOOP_CHECK			0x00400000

/* access macros */
#define SP_ISSET(p, f)		bf_isset(&(p)->sp_flags, SP_FLAG_ ## f)
#define SP_SET(p, f)		bf_set(&(p)->sp_flags, SP_FLAG_ ## f)
#define SP_CLEAR(p, f)		bf_clear(&(p)->sp_flags, SP_FLAG_ ## f)
#define PS_ISSET(p, f)		bf_isset(&(p)->ps_flags, PS_FLAG_ ## f)
#define PS_ISSET2(p, f, g)	bf_isset(&(p)->ps_flags, PS_FLAG_ ## f | PS_FLAG_ ## g)
#define PS_ARESET2(p, f, g)	bf_areset(&(p)->ps_flags, PS_FLAG_ ## f | PS_FLAG_ ## g)
#define PS_SET(p, f)		bf_set(&(p)->ps_flags, PS_FLAG_ ## f)
#define PS_CLEAR(p, f)		bf_clear(&(p)->ps_flags, PS_FLAG_ ## f)
#define MEDIA_ISSET(p, f)	bf_isset(&(p)->media_flags, MEDIA_FLAG_ ## f)
#define MEDIA_ISSET2(p, f, g)	bf_isset(&(p)->media_flags, MEDIA_FLAG_ ## f | MEDIA_FLAG_ ## g)
#define MEDIA_ARESET2(p, f, g)	bf_areset(&(p)->media_flags, MEDIA_FLAG_ ## f | MEDIA_FLAG_ ## g)
#define MEDIA_SET(p, f)		bf_set(&(p)->media_flags, MEDIA_FLAG_ ## f)
#define MEDIA_CLEAR(p, f)	bf_clear(&(p)->media_flags, MEDIA_FLAG_ ## f)




#include "obj.h"
#include "bencode.h"
#include "crypto.h"
#include "dtls.h"


struct poller;
struct control_stream;
struct call;
struct redis;
struct crypto_suite;
struct rtpengine_srtp;
struct streamhandler;
struct sdp_ng_flags;
struct local_interface;
struct call_monologue;
struct ice_agent;
struct ssrc_hash;


typedef bencode_buffer_t call_buffer_t;
#define call_buffer_alloc bencode_buffer_alloc
#define call_buffer_init bencode_buffer_init
#define call_buffer_free bencode_buffer_free




struct transport_protocol {
	enum transport_protocol_index	index;
	const char			*name;
	int				rtp:1; /* also set to 1 for SRTP */
	int				srtp:1;
	int				avpf:1;
	int				tcp:1;
};
extern const struct transport_protocol transport_protocols[];


struct stream_params {
	unsigned int		index; /* starting with 1 */
	str			type;
	struct endpoint		rtp_endpoint;
	struct endpoint		rtcp_endpoint;
	unsigned int		consecutive_ports;
	const struct transport_protocol *protocol;
	struct crypto_params	crypto;
	unsigned int		sdes_tag;
	str			direction[2];
	sockfamily_t		*desired_family;
	struct dtls_fingerprint fingerprint;
	unsigned int		sp_flags;
	GQueue			rtp_payload_types; /* slice-alloc'd */
	GQueue			ice_candidates; /* slice-alloc'd */
	str			ice_ufrag;
	str			ice_pwd;
};

struct endpoint_map {
	unsigned int		unique_id;
	struct endpoint		endpoint;
	unsigned int		num_ports;
	const struct logical_intf *logical_intf;
	GQueue			intf_sfds; /* list of struct intf_list - contains stream_fd list */
	int			wildcard:1;
};

struct loop_protector {
	unsigned int		len;
	unsigned char		buf[RTP_LOOP_PROTECT];
};



struct packet_stream {
	mutex_t			in_lock,
				out_lock;
	/* Both locks valid only with call->master_lock held in R.
	 * Preempted by call->master_lock held in W.
	 * If both in/out are to be locked, in_lock must be locked first. */

	struct call_media	*media;		/* RO */
	struct call		*call;		/* RO */
	unsigned int		component;	/* RO, starts with 1 */
	unsigned int		unique_id;	/* RO */
	struct recording_stream recording;	/* LOCK: call->master_lock */

	GQueue			sfds;		/* LOCK: call->master_lock */
	struct stream_fd * volatile selected_sfd;
	struct packet_stream	*rtp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sibling;	/* LOCK: call->master_lock */
	const struct streamhandler *handler;	/* LOCK: in_lock */
	struct endpoint		endpoint;	/* LOCK: out_lock */
	struct endpoint		advertised_endpoint; /* RO */
	struct crypto_context	crypto;		/* OUT direction, LOCK: out_lock */
	struct ssrc_ctx		*ssrc_in,	/* LOCK: in_lock */
				*ssrc_out;	/* LOCK: out_lock */

	struct stats		stats;
	struct stats		kernel_stats;
	atomic64		last_packet;
	GHashTable		*rtp_stats;	/* LOCK: call->master_lock */

#if RTP_LOOP_PROTECT
	/* LOCK: in_lock: */
	unsigned int		lp_idx;
	struct loop_protector	lp_buf[RTP_LOOP_PACKETS];
	unsigned int		lp_count;
#endif

	X509			*dtls_cert;	/* LOCK: in_lock */

	/* in_lock must be held for SETTING these: */
	volatile unsigned int	ps_flags;
};

/* protected by call->master_lock, except the RO elements */
struct call_media {
	struct call_monologue	*monologue;	/* RO */
	struct call		*call;		/* RO */

	unsigned int		index;		/* RO */
	unsigned int		unique_id;	/* RO */
	str			type;		/* RO */
	const struct transport_protocol *protocol;
	sockfamily_t		*desired_family;
	const struct logical_intf *logical_intf;

	struct ice_agent	*ice_agent;

	struct {
		struct crypto_params	params;
		unsigned int		tag;
	}			sdes_in,
				sdes_out;

	struct dtls_fingerprint fingerprint; /* as received */

	GQueue			streams; /* normally RTP + RTCP */
	GQueue			endpoint_maps;
	GHashTable		*rtp_payload_types;

	volatile unsigned int	media_flags;
};

/* half a dialogue */
/* protected by call->master_lock, except the RO elements */
struct call_monologue {
	struct call		*call;		/* RO */
	unsigned int		unique_id;	/* RO */

	str			tag;
	str			viabranch;
	enum tag_type		tagtype;
	str			label;
	time_t			created;	/* RO */
	time_t			deleted;
	struct timeval         started; /* for CDR */
	struct timeval         terminated; /* for CDR */
	enum termination_reason term_reason;
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
	GQueue			monologues;
	GQueue			medias;
	GHashTable		*tags;
	GHashTable		*viabranches;
	GQueue			streams;
	GQueue			stream_fds;
	GQueue			endpoint_maps;
	struct dtls_cert	*dtls_cert; /* for outgoing */
	struct ssrc_hash	*ssrc_hash;

	str			callid;
	struct timeval		created;
	time_t			last_signal;
	time_t			deleted;
	time_t			ml_deleted;
	unsigned char		tos;
	char			*created_from;
	sockaddr_t		created_from_addr;

	unsigned int		redis_hosted_db;
	unsigned int		foreign_call; // created_via_redis_notify call

	struct recording 	*recording;
};

struct callmaster_config {
	/* everything below protected by config_lock */
	rwlock_t		config_lock;
	int			max_sessions;
	unsigned int		timeout;
	unsigned int		silent_timeout;
	unsigned int		final_timeout;

	unsigned int		delete_delay;
	struct redis		*redis;
	struct redis		*redis_write;
	struct redis		*redis_notify;
	struct event_base   *redis_notify_event_base;
	GQueue		        *redis_subscribed_keyspaces;
	struct redisAsyncContext *redis_notify_async_context;
	unsigned int        redis_expires_secs;
	char			*b2b_url;
	unsigned char		default_tos;
	enum xmlrpc_format	fmt;
	endpoint_t		graphite_ep;
	int			graphite_interval;

	int			redis_num_threads;
};

struct callmaster {
	struct obj		obj;

	rwlock_t		hashlock;
	GHashTable		*callhash;

	/* XXX rework these */
	struct stats			statsps;	/* per second stats, running timer */
	struct stats			stats;		/* copied from statsps once a second */
	struct totalstats       totalstats;
	struct totalstats       totalstats_interval;
	mutex_t		        	totalstats_lastinterval_lock;
	struct totalstats       totalstats_lastinterval;

	/* control_ng_stats stuff */
	mutex_t			cngs_lock;
	GHashTable		*cngs_hash;

	struct poller	        *poller;
	pcre			*info_re;
	pcre_extra		*info_ree;
	pcre			*streams_re;
	pcre_extra		*streams_ree;

	struct callmaster_config conf;
	struct timeval          latest_graphite_interval_start;
};

struct callmaster *callmaster_new(struct poller *);
void callmaster_get_all_calls(struct callmaster *m, GQueue *q);

//void calls_dump_redis(struct callmaster *);
//void calls_dump_redis_read(struct callmaster *);
//void calls_dump_redis_write(struct callmaster *);
struct call_monologue *__monologue_create(struct call *call);
void __monologue_tag(struct call_monologue *ml, const str *tag);
void __monologue_viabranch(struct call_monologue *ml, const str *viabranch);
struct packet_stream *__packet_stream_new(struct call *call);


struct call *call_get_or_create(const str *callid, struct callmaster *m, enum call_type);
struct call *call_get_opmode(const str *callid, struct callmaster *m, enum call_opmode opmode);
struct call_monologue *call_get_mono_dialogue(struct call *call, const str *fromtag, const str *totag,
		const str *viabranch);
struct call *call_get(const str *callid, struct callmaster *m);
int monologue_offer_answer(struct call_monologue *monologue, GQueue *streams, const struct sdp_ng_flags *flags);
int call_delete_branch(struct callmaster *m, const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay);
void call_destroy(struct call *);
enum call_stream_state call_stream_state_machine(struct packet_stream *);
void call_media_state_machine(struct call_media *m);
void call_media_unkernelize(struct call_media *media);

int call_stream_address46(char *o, struct packet_stream *ps, enum stream_address_format format,
		int *len, const struct local_intf *ifa);

const struct transport_protocol *transport_protocol(const str *s);
void add_total_calls_duration_in_interval(struct callmaster *cm, struct timeval *interval_tv);

void __payload_type_free(void *p);
void __rtp_stats_update(GHashTable *dst, GHashTable *src);

const struct rtp_payload_type *__rtp_stats_codec(struct call_media *m);

#include "str.h"
#include "rtp.h"

INLINE void *call_malloc(struct call *c, size_t l) {
	void *ret;
	mutex_lock(&c->buffer_lock);
	ret = call_buffer_alloc(&c->buffer, l);
	mutex_unlock(&c->buffer_lock);
	return ret;
}

INLINE char *call_strdup_len(struct call *c, const char *s, unsigned int len) {
	char *r;
	if (!s)
		return NULL;
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
INLINE struct packet_stream *packet_stream_sink(struct packet_stream *ps) {
	struct packet_stream *ret;
	ret = ps->rtp_sink;
	if (!ret)
		ret = ps->rtcp_sink;
	return ret;
}


#endif
