#ifndef __CALL_H__
#define __CALL_H__



/* XXX split everything into call_signalling.[ch] and call_packets.[ch] or w/e */



#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <pcre.h>
#include <openssl/x509.h>
#include "compat.h"
#include "control_ng.h"
#include "aux.h"

enum termination_reason {
	UNKNOWN=0,
	REGULAR=1,
	FORCED=2,
	TIMEOUT=3,
	SILENT_TIMEOUT=4
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





#include "obj.h"
#include "aux.h"
#include "bencode.h"
#include "str.h"
#include "crypto.h"
#include "dtls.h"
#include "rtp.h"



#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	512
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)

#ifndef RTP_LOOP_PROTECT
#define RTP_LOOP_PROTECT	16 /* number of bytes */
#define RTP_LOOP_PACKETS	2  /* number of packets */
#define RTP_LOOP_MAX_COUNT	30 /* number of consecutively detected dupes to trigger protection */
#endif

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
#define SHARED_FLAG_TRICKLE_ICE			0x00000400
#define SHARED_FLAG_ICE_LITE			0x00000800

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
};
extern const struct transport_protocol transport_protocols[];

struct stats {
	atomic64			packets;
	atomic64			bytes;
	atomic64			errors;
	struct timespec		delay_min;
	struct timespec		delay_avg;
	struct timespec		delay_max;
	atomic64			in_tos_tclass;
};

struct totalstats {
	time_t 				started;
	atomic64			total_timeout_sess;
	atomic64			total_silent_timeout_sess;
	atomic64			total_regular_term_sess;
	atomic64			total_forced_term_sess;
	atomic64			total_relayed_packets;
	atomic64			total_relayed_errors;
	atomic64			total_nopacket_relayed_sess;
	atomic64			total_oneway_stream_sess;

	mutex_t				total_average_lock; /* for these two below */
	u_int64_t			total_managed_sess;
	struct timeval			total_average_call_dur;
};

struct udp_fd {
	int			fd;
	u_int16_t		localport;
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
	str			direction[2];
	int			desired_family;
	struct dtls_fingerprint fingerprint;
	unsigned int		sp_flags;
	GQueue			rtp_payload_types; /* slice-alloc'd */
	GQueue			ice_candidates; /* slice-alloc'd */
	str			ice_ufrag;
	str			ice_pwd;
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

struct loop_protector {
	unsigned int		len;
	unsigned char		buf[RTP_LOOP_PROTECT];
};

struct rtp_stats {
	unsigned int		payload_type;
	atomic64		packets;
	atomic64		bytes;
	atomic64		kernel_packets;
	atomic64		kernel_bytes;
	atomic64		in_tos_tclass;
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

	struct stream_fd	*sfd;		/* LOCK: call->master_lock */
	struct packet_stream	*rtp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sink;	/* LOCK: call->master_lock */
	struct packet_stream	*rtcp_sibling;	/* LOCK: call->master_lock */
	const struct streamhandler *handler;	/* LOCK: in_lock */
	struct endpoint		endpoint;	/* LOCK: out_lock */
	struct endpoint		advertised_endpoint; /* RO */
	struct crypto_context	crypto;		/* OUT direction, LOCK: out_lock */

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
	str			type;		/* RO */
	const struct transport_protocol *protocol;
	int			desired_family;
	struct local_interface	*interface;

	/* local_address is protected by call->master_lock in W mode, but may
	 * still be modified if the lock is held in R mode, therefore we use
	 * atomic ops to access it when holding an R lock. */
	volatile struct interface_address *local_address;

	struct ice_agent	*ice_agent;

	struct {
		struct crypto_params	params;
		unsigned int		tag;
	}			sdes_in,
				sdes_out;

	struct dtls_fingerprint fingerprint; /* as received */

	GQueue			streams; /* normally RTP + RTCP */
	GSList			*endpoint_maps;
	GHashTable		*rtp_payload_types;

	volatile unsigned int	media_flags;
};

/* half a dialogue */
/* protected by call->master_lock, except the RO elements */
struct call_monologue {
	struct call		*call;		/* RO */

	str			tag;
	enum tag_type    tagtype;
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
	GSList			*monologues;
	GHashTable		*tags;	
	//GHashTable		*branches;
	GSList			*streams;
	GSList			*stream_fds;
	struct dtls_cert	*dtls_cert; /* for outgoing */

	str			callid;	
	time_t			created;
	time_t			last_signal;
	time_t			deleted;
	time_t			ml_deleted;
	unsigned char		tos;
	char			*created_from;
	struct sockaddr_in6	created_from_addr;
};

struct local_interface {
	str			name;
	int			preferred_family;
	GQueue			list; /* struct interface_address */
	GHashTable		*addr_hash;
};
struct interface_address {
	str			interface_name;
	int			family;
	struct in6_addr		addr;
	struct in6_addr		advertised;
	str			ice_foundation;
	char			foundation_buf[16];
	unsigned int		preference; /* starting with 0 */
};

struct callmaster_config {
	int			kernelfd;
	int			kernelid;
	GQueue			*interfaces; /* struct interface_address */
	int			port_min;
	int			port_max;
	unsigned int		timeout;
	unsigned int		silent_timeout;
	unsigned int		delete_delay;
	struct redis		*redis;
	char			*b2b_url;
	unsigned char		default_tos;
	enum xmlrpc_format	fmt;
	u_int32_t		graphite_ip;
	u_int16_t		graphite_port;
	int			graphite_interval;
};

struct callmaster {
	struct obj		obj;

	rwlock_t		hashlock;
	GHashTable		*callhash;

	GHashTable		*interfaces; /* struct local_interface */
	GQueue			interface_list_v4; /* ditto */
	GQueue			interface_list_v6; /* ditto */

	volatile unsigned int	lastport;
	BIT_ARRAY_DECLARE(ports_used, 0x10000);

	/* XXX rework these */
	struct stats		statsps;	/* per second stats, running timer */
	struct stats		stats;		/* copied from statsps once a second */
	mutex_t			statspslock;
	struct totalstats   totalstats;
	struct totalstats   totalstats_interval;
	/* control_ng_stats stuff */
	mutex_t			cngs_lock;
	GHashTable		*cngs_hash;

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
void callmaster_config_init(struct callmaster *);
void stream_msg_mh_src(struct packet_stream *, struct msghdr *);
void callmaster_get_all_calls(struct callmaster *m, GQueue *q);


void calls_dump_redis(struct callmaster *);
struct call_monologue *__monologue_create(struct call *call);
void __monologue_tag(struct call_monologue *ml, const str *tag);
struct stream_fd *__stream_fd_new(struct udp_fd *fd, struct call *call);
int __get_consecutive_ports(struct udp_fd *array, int array_len, int wanted_start_port, const struct call *c);
struct packet_stream *__packet_stream_new(struct call *call);


struct call *call_get_or_create(const str *callid, struct callmaster *m);
struct call *call_get_opmode(const str *callid, struct callmaster *m, enum call_opmode opmode);
struct call_monologue *call_get_mono_dialogue(struct call *call, const str *fromtag, const str *totag);
struct call *call_get(const str *callid, struct callmaster *m);
int monologue_offer_answer(struct call_monologue *monologue, GQueue *streams, const struct sdp_ng_flags *flags);
int call_delete_branch(struct callmaster *m, const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output);
void call_destroy(struct call *);
enum call_stream_state call_stream_state_machine(struct packet_stream *);
void call_media_unkernelize(struct call_media *media);

void kernelize(struct packet_stream *);
int call_stream_address(char *, struct packet_stream *, enum stream_address_format, int *);
int call_stream_address46(char *o, struct packet_stream *ps, enum stream_address_format format,
		int *len, struct interface_address *ifa);
struct local_interface *get_local_interface(struct callmaster *m, const str *name, int familiy);
INLINE struct interface_address *get_interface_from_address(struct local_interface *lif,
		const struct in6_addr *addr)
{
	return g_hash_table_lookup(lif->addr_hash, addr);
}
struct interface_address *get_any_interface_address(struct local_interface *lif, int family);

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
INLINE void callmaster_exclude_port(struct callmaster *m, u_int16_t p) {
	bit_array_set(m->ports_used, p);
}
INLINE struct packet_stream *packet_stream_sink(struct packet_stream *ps) {
	struct packet_stream *ret;
	ret = ps->rtp_sink;
	if (!ret)
		ret = ps->rtcp_sink;
	return ret;
}

const char * get_tag_type_text(enum tag_type t);

#endif
