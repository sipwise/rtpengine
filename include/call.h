#ifndef __CALL_H__
#define __CALL_H__



/* XXX split everything into call_signalling.[ch] and call_packets.[ch] or w/e */

#include <glib-object.h>

#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/x509.h>
#include <limits.h>
#include <stdbool.h>

#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	512
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)

#include "compat.h"
#include "socket.h"
#include "media_socket.h"
#include "recording.h"
#include "statistics.h"
#include "codeclib.h"
#include "t38.h"
#include "xt_RTPENGINE.h"

#define UNDEFINED ((unsigned int) -1)

enum termination_reason {
	UNKNOWN=0,
	REGULAR=1,
	FORCED=2,
	TIMEOUT=3,
	SILENT_TIMEOUT=4,
	FINAL_TIMEOUT=5,
	OFFER_TIMEOUT=6,
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
	OP_REQUEST,
	OP_REQ_ANSWER,
	OP_PUBLISH,
	OP_PLAY_MEDIA,
	OP_OTHER,
};

enum call_media_counted {
	CMC_INCREMENT = 0,
	CMC_DECREMENT,
};

enum call_stream_state {
	CSS_UNKNOWN = 0,
	CSS_SHUTDOWN,
	CSS_ICE,
	CSS_DTLS,
	CSS_PIERCE_NAT,
	CSS_RUNNING,
};
enum {
	CALL_ITERATOR_MAIN = 0,
	CALL_ITERATOR_TIMER,
	CALL_ITERATOR_GRAPHITE,
	CALL_ITERATOR_MQTT,

	NUM_CALL_ITERATORS
};

#define ERROR_NO_FREE_PORTS	-100
#define ERROR_NO_FREE_LOGS	-101

#ifndef RTP_LOOP_PROTECT
#define RTP_LOOP_PROTECT	28 /* number of bytes */
#define RTP_LOOP_PACKETS	2  /* number of packets */
#define RTP_LOOP_MAX_COUNT	30 /* number of consecutively detected dupes to trigger protection */
#endif

#define IS_FOREIGN_CALL(c) CALL_ISSET(c, FOREIGN)
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
#define SHARED_FLAG_ICE_LITE_PEER		0x00000800
#define SHARED_FLAG_UNIDIRECTIONAL		0x00001000
#define SHARED_FLAG_RTCP_FB			0x00002000
#define SHARED_FLAG_LEGACY_OSRTP		0x00004000
#define SHARED_FLAG_LEGACY_OSRTP_REV		0x00008000

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
#define SP_FLAG_ICE_LITE_PEER			SHARED_FLAG_ICE_LITE_PEER
#define SP_FLAG_RTCP_FB				SHARED_FLAG_RTCP_FB
#define SP_FLAG_LEGACY_OSRTP			SHARED_FLAG_LEGACY_OSRTP
#define SP_FLAG_LEGACY_OSRTP_REV		SHARED_FLAG_LEGACY_OSRTP_REV

/* struct packet_stream */
#define PS_FLAG_RTP				0x00010000
#define PS_FLAG_RTCP				0x00020000
#define PS_FLAG_IMPLICIT_RTCP			SHARED_FLAG_IMPLICIT_RTCP
#define PS_FLAG_FALLBACK_RTCP			0x00040000
#define PS_FLAG_RECEIVED			0x00080000
#define PS_FLAG_FILLED				0x00100000
#define PS_FLAG_CONFIRMED			0x00200000
#define PS_FLAG_KERNELIZED			0x00400000
#define PS_FLAG_NO_KERNEL_SUPPORT		0x00800000
#define PS_FLAG_UNUSED				0x01000000
#define PS_FLAG_FINGERPRINT_VERIFIED		0x02000000
#define PS_FLAG_STRICT_SOURCE			SHARED_FLAG_STRICT_SOURCE
#define PS_FLAG_MEDIA_HANDOVER			SHARED_FLAG_MEDIA_HANDOVER
#define PS_FLAG_ICE				SHARED_FLAG_ICE
#define PS_FLAG_ZERO_ADDR			0x04000000
#define PS_FLAG_PIERCE_NAT			0x08000000
#define PS_FLAG_NAT_WAIT			0x10000000

// packet_stream stats_flags
#define PS_STATS_USERSPACE			0x00000001
#define PS_STATS_KERNEL				0x00000002
#define PS_STATS_USERSPACE_COUNTED		0x00000004
#define PS_STATS_KERNEL_COUNTED			0x00000008
#define PS_STATS_MIXED_COUNTED			0x00000010

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
#define MEDIA_FLAG_ICE_LITE_PEER		SHARED_FLAG_ICE_LITE_PEER
#define MEDIA_FLAG_ICE_CONTROLLING		0x00200000
#define MEDIA_FLAG_LOOP_CHECK			0x00400000
#define MEDIA_FLAG_PTIME_OVERRIDE		0x01000000
#define MEDIA_FLAG_RTCP_FB			SHARED_FLAG_RTCP_FB
#define MEDIA_FLAG_GENERATOR			0x02000000
#define MEDIA_FLAG_ICE_LITE_SELF		0x04000000
#define MEDIA_FLAG_RTCP_GEN			0x08000000
#define MEDIA_FLAG_ECHO				0x10000000
#define MEDIA_FLAG_BLACKHOLE			0x20000000
#define MEDIA_FLAG_REORDER_FORCED		0x40000000
#define MEDIA_FLAG_AUDIO_PLAYER			0x80000000
#define MEDIA_FLAG_LEGACY_OSRTP			SHARED_FLAG_LEGACY_OSRTP
#define MEDIA_FLAG_LEGACY_OSRTP_REV		SHARED_FLAG_LEGACY_OSRTP_REV

/* struct call_monologue */
#define ML_FLAG_REC_FORWARDING			0x00010000
#define ML_FLAG_INJECT_DTMF			0x00020000
#define ML_FLAG_DTMF_INJECTION_ACTIVE		0x00040000
#define ML_FLAG_DETECT_DTMF			0x00080000
#define ML_FLAG_NO_RECORDING			0x00100000
#define ML_FLAG_TRANSCODING			0x00200000
#define ML_FLAG_BLOCK_SHORT			0x00400000
#define ML_FLAG_BLOCK_MEDIA			0x00800000
#define ML_FLAG_SILENCE_MEDIA			0x01000000

/* struct call */
#define CALL_FLAG_IPV4_OFFER			0x00010000
#define CALL_FLAG_IPV6_OFFER			0x00020000
#define CALL_FLAG_IPV4_ANSWER			0x00040000
#define CALL_FLAG_IPV6_ANSWER			0x00080000
#define CALL_FLAG_MEDIA_COUNTED			0x00100000
#define CALL_FLAG_RECORDING_ON			0x00200000
#define CALL_FLAG_REC_FORWARDING		0x00400000
#define CALL_FLAG_DROP_TRAFFIC			0x00800000
#define CALL_FLAG_FOREIGN			0x01000000 // created_via_redis_notify call
#define CALL_FLAG_FOREIGN_MEDIA			0x02000000 // for calls taken over, tracks whether we have media
#define CALL_FLAG_DISABLE_JB			0x04000000
#define CALL_FLAG_DEBUG				0x08000000
#define CALL_FLAG_BLOCK_MEDIA			0x10000000
#define CALL_FLAG_SILENCE_MEDIA			0x20000000

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
#define ML_ISSET(p, f)		bf_isset(&(p)->ml_flags, ML_FLAG_ ## f)
#define ML_ISSET2(p, f, g)	bf_isset(&(p)->ml_flags, ML_FLAG_ ## f | ML_FLAG_ ## g)
#define ML_ARESET2(p, f, g)	bf_areset(&(p)->ml_flags, ML_FLAG_ ## f | ML_FLAG_ ## g)
#define ML_SET(p, f)		bf_set(&(p)->ml_flags, ML_FLAG_ ## f)
#define ML_CLEAR(p, f)		bf_clear(&(p)->ml_flags, ML_FLAG_ ## f)
#define CALL_ISSET(p, f)		bf_isset(&(p)->call_flags, CALL_FLAG_ ## f)
#define CALL_ISSET2(p, f, g)	bf_isset(&(p)->call_flags, CALL_FLAG_ ## f | CALL_FLAG_ ## g)
#define CALL_ARESET2(p, f, g)	bf_areset(&(p)->call_flags, CALL_FLAG_ ## f | CALL_FLAG_ ## g)
#define CALL_SET(p, f)		bf_set(&(p)->call_flags, CALL_FLAG_ ## f)
#define CALL_CLEAR(p, f)		bf_clear(&(p)->call_flags, CALL_FLAG_ ## f)

enum block_dtmf_mode {
	BLOCK_DTMF_OFF = 0,
	BLOCK_DTMF_DROP = 1,

	BLOCK_DTMF___REPLACE_START = 2,
	BLOCK_DTMF___PCM_REPLACE_START = 2,
	// block modes that replace any DTMF with PCM
	BLOCK_DTMF_SILENCE = 2,
	BLOCK_DTMF_TONE = 3,
	BLOCK_DTMF_RANDOM = 4,
	BLOCK_DTMF___PCM_REPLACE_END = 4,
	// block modes that replace DTMF events with other DTMF events if possible
	BLOCK_DTMF_ZERO = 5,
	BLOCK_DTMF_DTMF = 6,
	BLOCK_DTMF___REPLACE_END = 6,
};




#include "obj.h"
#include "bencode.h"
#include "crypto.h"
#include "dtls.h"


struct control_stream;
struct call;
struct redis;
struct crypto_suite;
struct rtpengine_srtp;
struct sdp_ng_flags;
struct local_interface;
struct call_monologue;
struct ice_agent;
struct ssrc_hash;
struct codec_handler;
struct rtp_payload_type;
struct media_player;
struct send_timer;
struct transport_protocol;
struct jitter_buffer;
struct codec_tracker;
struct rtcp_timer;
struct mqtt_timer;
struct janus_session;
struct audio_player;


typedef bencode_buffer_t call_buffer_t;
#define call_buffer_alloc bencode_buffer_alloc
#define call_buffer_init bencode_buffer_init
#define call_buffer_free bencode_buffer_free




struct codec_store {
	GHashTable		*codecs; // int payload type -> struct rtp_payload_type
	GHashTable		*codec_names; // codec name -> GQueue of int payload types; storage container
	GQueue			codec_prefs; // preference by order in SDP; storage container
	GList			*supp_link; // tracks location for codec_store_add_end
	struct codec_tracker	*tracker;
	struct call_media	*media;
	unsigned int		strip_all:1, // set by codec_store_strip
				strip_full:1; // set by codec_store_strip
};

struct stream_params {
	unsigned int		index; /* starting with 1 */
	str			type;
	enum media_type		type_id;
	struct endpoint		rtp_endpoint;
	struct endpoint		rtcp_endpoint;
	unsigned int		consecutive_ports;
	unsigned int		num_ports;
	str			protocol_str;
	const struct transport_protocol *protocol;
	str			format_str;
	GQueue			sdes_params; // slice-alloc'd
	str			direction[2];
	sockfamily_t		*desired_family;
	struct dtls_fingerprint fingerprint;
	unsigned int		sp_flags;
	struct codec_store	codecs;
	GQueue			ice_candidates; /* slice-alloc'd */
	str			ice_ufrag;
	str			ice_pwd;
	int			ptime;
	str			media_id;
	struct t38_options	t38_options;
	str			tls_id;
};

struct endpoint_map {
	unsigned int		unique_id;
	struct endpoint		endpoint;
	unsigned int		num_ports;
	const struct logical_intf *logical_intf;
	GQueue			intf_sfds; /* list of struct intf_list - contains stream_fd list */
	unsigned int		wildcard:1;
};

struct loop_protector {
	unsigned int		len;
	unsigned char		buf[RTP_LOOP_PROTECT];
};



/**
 * The packet_stream itself can be marked as:
 * - SRTP endpoint
 * - ICE endpoint
 * - send/receive-only
 * 
 * This is done through the various bit flags.
 */
struct packet_stream {
	/* Both locks valid only with call->master_lock held in R.
	 * Preempted by call->master_lock held in W.
	 * If both in/out are to be locked, in_lock must be locked first.
	 * 
	 * The in_lock protects fields relevant to packet reception on that stream,
	 * meanwhile the out_lock protects fields relevant to packet egress.
	 * 
	 * This allows packet handling on multiple ports and streams belonging
	 * to the same call to happen at the same time.
	 */
	mutex_t			in_lock,
				out_lock;

	struct call_media	*media;		/* RO */
	struct call		*call;		/* RO */
	unsigned int		component;	/* RO, starts with 1 */
	unsigned int		unique_id;	/* RO */
	struct recording_stream recording;	/* LOCK: call->master_lock */

	GQueue			sfds;		/* LOCK: call->master_lock */
	struct stream_fd *	selected_sfd;	// LOCK: in_lock
	endpoint_t		last_local_endpoint;
	struct dtls_connection	ice_dtls;	/* LOCK: in_lock */
	GQueue			rtp_sinks;	/* LOCK: call->master_lock, in_lock for streamhandler */
	GQueue			rtcp_sinks;	/* LOCK: call->master_lock, in_lock for streamhandler */
	struct packet_stream	*rtcp_sibling;	/* LOCK: call->master_lock */
	GQueue			rtp_mirrors;	/* LOCK: call->master_lock, in_lock for streamhandler */
	struct endpoint		endpoint;	/* LOCK: out_lock */
	struct endpoint		detected_endpoints[4];		/* LOCK: out_lock */
	time_t			ep_detect_signal;		/* LOCK: out_lock */
	struct endpoint		advertised_endpoint;		/* RO */
	struct endpoint		learned_endpoint;		/* LOCK: out_lock */
	struct crypto_context	crypto;				/* OUT direction, LOCK: out_lock */
	struct ssrc_ctx		*ssrc_in[RTPE_NUM_SSRC_TRACKING],	/* LOCK: in_lock */
				*ssrc_out[RTPE_NUM_SSRC_TRACKING];	/* LOCK: out_lock */
	unsigned int		ssrc_in_idx,				/* LOCK: in_lock */
				ssrc_out_idx;				/* LOCK: out_lock */
	struct send_timer	*send_timer;				/* RO */
	struct jitter_buffer	*jb;					/* RO */
	time_t kernel_time;

	struct stream_stats	stats_in;
	struct stream_stats	stats_out;
	struct stream_stats	kernel_stats_in;
	struct stream_stats	kernel_stats_out;
	unsigned char		in_tos_tclass;
	atomic64		last_packet;
	GHashTable		*rtp_stats;				/* LOCK: call->master_lock */
	struct rtp_stats	*rtp_stats_cache;
	unsigned int		stats_flags;
	enum endpoint_learning		el_flags;

#if RTP_LOOP_PROTECT
	/* LOCK: in_lock: */
	unsigned int		lp_idx;
	struct loop_protector	lp_buf[RTP_LOOP_PACKETS];
	unsigned int		lp_count;
#endif

	X509			*dtls_cert;				/* LOCK: in_lock */

	/* in_lock must be held for SETTING these: */
	volatile unsigned int	ps_flags;
};

/**
 * Protected by call->master_lock, except the RO elements.
 * 
 * call_media is not reference-counted and is completely owned by the call object.
 * Therefore call_media is released when the call is destroyed.
 */
struct call_media {
	struct call_monologue	*monologue;			/* RO */
	struct call		*call;				/* RO */

	unsigned int		index;				/* RO */
	unsigned int		unique_id;			/* RO */
	str			type;
	enum media_type		type_id;
	str			protocol_str;
	const struct transport_protocol *protocol;
	str			format_str;
	sockfamily_t		*desired_family;
	const struct logical_intf *logical_intf;

	struct ice_agent	*ice_agent;

	str			media_id;
	str			label;
	GQueue			sdes_in, sdes_out;
	struct dtls_fingerprint fingerprint;			/* as received */
	const struct dtls_hash_func *fp_hash_func;		/* outgoing */
	str			tls_id;

	GQueue			streams;			/* normally RTP + RTCP */
	GQueue			endpoint_maps;

	struct codec_store	codecs;
	GQueue			sdp_attributes;			/* str_sprintf() */
	GHashTable		*codec_handlers;		/* int payload type -> struct codec_handler
														XXX combine this with 'codecs' hash table? */
	GQueue			codec_handlers_store;		/* storage for struct codec_handler */
	struct codec_handler	*codec_handler_cache;
	struct rtcp_handler	*rtcp_handler;
	struct rtcp_timer	*rtcp_timer;			/* master lock for scheduling purposes */
	struct mqtt_timer	*mqtt_timer;			/* master lock for scheduling purposes */
	//struct codec_handler	*dtmf_injector;
	struct t38_gateway	*t38_gateway;
	struct audio_player	*audio_player;
	struct codec_handler	*t38_handler;

	unsigned int		buffer_delay;

	mutex_t			dtmf_lock;
	unsigned long		dtmf_ts;			/* TS of last processed end event */
	unsigned int		dtmf_count;
	// lists are append-only
	GQueue			dtmf_recv;
	GQueue			dtmf_send;

#ifdef WITH_TRANSCODING
	encoder_callback_t	encoder_callback;
#endif

	int			ptime;				/* either from SDP or overridden */

	volatile unsigned int	media_flags;
};

/** 
 * Link between subscribers and subscriptions.
 * 
 * Contain flags and attributes, which can be used
 * to mark a subscription (for example, as an egress subscription).
 * 
 * During signalling events, the list of subscriptions for each call_monologue
 * is used to create the list of rtp_sink and rtcp_sink given in each packet_stream.
 * 
 * Each entry in these lists is a sink_handler object, which again contains flags and attributes.
 * Flags from a call_subscription are copied into the sink_handler.
 */
struct call_subscription {
	struct call_monologue	*monologue;
	GList			*link; // link into the corresponding opposite list
	unsigned int		media_offset; // 0 if media indexes match up
	struct sink_attrs	attrs;
};

/**
 * Half a dialogue.
 * Protected by call->master_lock, except the RO elements.
 * 
 * call_monologue (call participant) contains a list of subscribers
 * and subscriptions, which are other call_monologue's.
 * 
 * These lists are mutual.
 * A regular A/B call has two call_monologue objects with each subscribed to the other.
 */
struct call_monologue {
	struct call		*call;			/* RO */
	unsigned int		unique_id;		/* RO */

	str			tag;
	str			viabranch;
	enum tag_type		tagtype;
	str			label;
	time_t			created;		/* RO */
	time_t			deleted;
	struct timeval		started;		/* for CDR */
	struct timeval		terminated;		/* for CDR */
	enum termination_reason	term_reason;
	sockfamily_t		*desired_family;
	const struct logical_intf *logical_intf;
	GHashTable 		*associated_tags;
	GQueue			subscriptions;		/* who am I subscribed to (sources) */
	GHashTable		*subscriptions_ht;	/* for quick lookup */
	GQueue			subscribers;		/* who is subscribed to me (sinks) */
	GHashTable		*subscribers_ht;	/* for quick lookup */
	GPtrArray		*medias;
	GHashTable		*media_ids;
	struct media_player	*player;
	unsigned long long	sdp_session_id;
	unsigned long long	sdp_version;
	str			last_in_sdp;
	GQueue			last_in_sdp_parsed;
	GQueue			last_in_sdp_streams;
	GString			*last_out_sdp;
	char			*sdp_username;
	char			*sdp_session_name;
	struct ssrc_hash	*ssrc_hash;
	str			metadata;
	struct janus_session	*janus_session;

	// DTMF blocking/replacement stuff:
	enum block_dtmf_mode	block_dtmf;
	GArray			*tone_freqs;
	unsigned int		tone_vol;
	char			dtmf_digit;
	str			dtmf_trigger;
	unsigned int		dtmf_trigger_match;
	enum block_dtmf_mode	block_dtmf_trigger;
	str			dtmf_trigger_end;
	int			dtmf_trigger_digits;
	enum block_dtmf_mode	block_dtmf_trigger_end;
	unsigned int		block_dtmf_trigger_end_ms;
	unsigned int		dtmf_delay;

	volatile unsigned int	ml_flags;
};

struct call_iterator_list {
	GList *first;
	mutex_t lock; // protects .first and every entry's .data
};
struct call_iterator_entry {
	GList link; // .data is protected by the list's main lock
	mutex_t next_lock; // held while the link is in use, protects link.data and link.next
	mutex_t prev_lock; // held while the link is in use, protects link.prev
};

#define ITERATE_CALL_LIST_START(which, varname) \
	do { \
		int __which = (which); \
		mutex_lock(&rtpe_call_iterators[__which].lock); \
		\
		GList *__l = rtpe_call_iterators[__which].first; \
		bool __has_lock = true; \
		struct call *next_ ## varname = NULL; \
		while (__l) { \
			struct call *varname = NULL; \
			if (next_ ## varname) \
				varname = next_ ## varname; \
			else { \
				varname = __l->data; \
				obj_hold(varname); \
				mutex_lock(&varname->iterator[__which].next_lock); \
			} \
			if (__has_lock) \
				mutex_unlock(&rtpe_call_iterators[__which].lock); \
			__has_lock = false

#define ITERATE_CALL_LIST_NEXT_END(varname) \
			GList *__next = varname->iterator[__which].link.next; \
			if (__next) { \
				next_ ## varname = __next->data; \
				obj_hold(next_ ## varname); \
				mutex_lock(&next_ ## varname->iterator[__which].next_lock); \
			} \
			else \
				next_ ## varname = NULL; \
			mutex_unlock(&varname->iterator[__which].next_lock); \
			__l = __next; \
			obj_put(varname); \
		} \
		if (__has_lock) \
			mutex_unlock(&rtpe_call_iterators[__which].lock); \
	} while (0)

/**
 * struct call is the main parent structure of all call-related objects.
 * 
 * The logical object hierarchy under the 'struct call':
 * call > call_monologue > call_media > packet_stream > stream_fd
 * 
 * struct call usually has multiple call_monologue objects.
 * Meanwhile each sub-object of call, as a parent of own sub-objects,
 * can also contain multiple child objects.
 * 
 * Furthermore, each child object contains a back ptr to its parent object.
 * 
 * The parent call object contains one list (as GQueue) for each kind of child object.
 * These lists are what is used to free and release the child objects
 * during a call teardown.
 * Every child object owned by the call is added to its respective list exactly once.
 * 
 * Call object is reference-counted through the struct obj.
 */
struct call {

	/* struct obj member must always be the first member in a struct.
	 *
	 * obj is created with a cleanup handler, see obj_alloc(),
	 * and this handler is executed whenever the reference count drops to zero.
	 * 
	 * References are acquired and released through obj_get() and obj_put()
	 * (plus some other wrapper functions).
	 */
	struct obj		obj;

	mutex_t			buffer_lock;
	call_buffer_t		buffer;

	/* master_lock protects the entire call and all the contained objects.
	 * 
	 * All the fields and any nested sub-object must:
	 * - only be accessed with the master_lock held as a read lock
	 * - only be modified with the master_lock held as a write lock
	 * 
	 * Therefore, during signalling events acquire a write-lock,
	 * and during RTP packets handling acquire a read-lock.
	 */
	rwlock_t		master_lock;

	/* everything below is protected by the master_lock */
	GQueue			monologues;	/* call_monologue */
	GQueue			medias;		/* call_media */
	GHashTable		*tags;
	GHashTable		*viabranches;
	GHashTable		*labels;
	GQueue			streams;
	GQueue			stream_fds;	/* stream_fd */
	GQueue			endpoint_maps;
	struct dtls_cert	*dtls_cert;	/* for outgoing */
	struct mqtt_timer	*mqtt_timer;

	str			callid;
	struct timeval		created;
	struct timeval		destroyed;
	time_t			last_signal;
	time_t			deleted;
	time_t			ml_deleted;
	unsigned char		tos;
	char			*created_from;
	sockaddr_t		created_from_addr;
	sockaddr_t		xmlrpc_callback;
	endpoint_t		dtmf_log_dest;

	int			redis_hosted_db;

	struct recording 	*recording;
	str			metadata;

	struct call_iterator_entry iterator[NUM_CALL_ITERATORS];
	int			cpu_affinity;
	enum block_dtmf_mode	block_dtmf;

	unsigned int		call_flags;
};


/**
 * The main entry point into call objects for signalling events is the call-ID:
 * Therefore the main entry point is the global hash table rtpe_callhash (protected by rtpe_callhash_lock),
 * which uses call-IDs as keys and call objects as values,
 * while holding a reference to each contained call.
 */
extern rwlock_t rtpe_callhash_lock;
extern GHashTable *rtpe_callhash;
extern struct call_iterator_list rtpe_call_iterators[NUM_CALL_ITERATORS];



int call_init(void);
void call_free(void);

struct call_monologue *__monologue_create(struct call *call);
void __monologue_free(struct call_monologue *m);
void __monologue_tag(struct call_monologue *ml, const str *tag);
void __monologue_viabranch(struct call_monologue *ml, const str *viabranch);
struct packet_stream *__packet_stream_new(struct call *call);
void __add_subscription(struct call_monologue *ml, struct call_monologue *other,
		unsigned int media_offset, const struct sink_attrs *);
struct call_subscription *call_get_call_subscription(GHashTable *ht, struct call_monologue *ml);
void free_sink_handler(void *);
void __add_sink_handler(GQueue *, struct packet_stream *, const struct sink_attrs *);

void call_subscription_free(void *);
void call_subscriptions_clear(GQueue *q);


struct call *call_get_or_create(const str *callid, bool exclusive);
struct call *call_get_opmode(const str *callid, enum call_opmode opmode);
void call_make_own_foreign(struct call *c, bool foreign);
int call_get_mono_dialogue(struct call_subscription *dialogue[2], struct call *call, const str *fromtag,
		const str *totag,
		const str *viabranch);
struct call_monologue *call_get_monologue(struct call *call, const str *fromtag);
struct call_monologue *call_get_or_create_monologue(struct call *call, const str *fromtag);
struct call *call_get(const str *callid);
int monologue_offer_answer(struct call_subscription *dialogue[2], GQueue *streams, struct sdp_ng_flags *flags);
__attribute__((nonnull(1, 2, 3, 5)))
void codecs_offer_answer(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, struct sdp_ng_flags *flags, struct call_subscription *dialogue[2]);
int monologue_publish(struct call_monologue *ml, GQueue *streams, struct sdp_ng_flags *flags);
int monologue_subscribe_request(const GQueue *srcs, struct call_monologue *dst, struct sdp_ng_flags *);
int monologue_subscribe_answer(struct call_monologue *dst, struct sdp_ng_flags *,
		GQueue *);
int monologue_unsubscribe(struct call_monologue *dst, struct sdp_ng_flags *);
void monologue_destroy(struct call_monologue *ml);
int call_delete_branch_by_id(const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay);
int call_delete_branch(struct call *, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay);
void call_destroy(struct call *);
struct call_media *call_media_new(struct call *call);
void call_media_free(struct call_media **mdp);
enum call_stream_state call_stream_state_machine(struct packet_stream *);
void call_media_state_machine(struct call_media *m);
void call_media_unkernelize(struct call_media *media, const char *);
void dialogue_unkernelize(struct call_monologue *ml, const char *);
void __monologue_unkernelize(struct call_monologue *monologue, const char *);
void update_init_subscribers(struct call_monologue *ml, enum call_opmode opmode);

int call_stream_address46(char *o, struct packet_stream *ps, enum stream_address_format format,
		int *len, const struct local_intf *ifa, bool keep_unspec);

void add_total_calls_duration_in_interval(struct timeval *interval_tv);
enum thread_looper_action call_timer(void);

void __rtp_stats_update(GHashTable *dst, struct codec_store *);
int __init_stream(struct packet_stream *ps);
void call_stream_crypto_reset(struct packet_stream *ps);

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
INLINE void __call_unkernelize(struct call *call, const char *reason) {
	for (GList *l = call->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		__monologue_unkernelize(ml, reason);
	}
}
INLINE endpoint_t *packet_stream_local_addr(struct packet_stream *ps) {
	if (ps->selected_sfd)
		return &ps->selected_sfd->socket.local;
	if (ps->last_local_endpoint.port)
		return &ps->last_local_endpoint;
	static endpoint_t dummy = {
		.address = {
			.ipv4.s_addr = 0,
		},
		.port = 0,
	};
	// one-time init
	if (!dummy.address.family)
		dummy.address.family = get_socket_family_enum(SF_IP4);
	return &dummy;
}

#endif
