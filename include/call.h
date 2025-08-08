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

#include "compat.h"
#include "socket.h"
#include "media_socket.h"
#include "recording.h"
#include "statistics.h"
#include "codeclib.h"
#include "t38.h"
#include "types.h"

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

enum message_type {
	SIP_OTHER = 0,
	SIP_REQUEST,
	SIP_REPLY,
};

#define IS_OP_OTHER(opmode)                                                                      \
		 ((opmode == OP_DELETE || opmode == OP_QUERY)                                    \
		 || (opmode == OP_LIST || opmode == OP_PING)                                     \
		 || (opmode == OP_STATISTICS || opmode == OP_PLAY_DTMF)                          \
		 || (opmode == OP_BLOCK_DTMF || opmode == OP_UNBLOCK_DTMF)                       \
		 || (opmode == OP_BLOCK_MEDIA || opmode == OP_UNBLOCK_MEDIA)                     \
		 || (opmode == OP_SILENCE_MEDIA || opmode == OP_UNSILENCE_MEDIA)                 \
		 || (opmode == OP_BLOCK_SILENCE_MEDIA || opmode == OP_UNBLOCK_SILENCE_MEDIA)     \
		 || (opmode == OP_PLAY_MEDIA || opmode == OP_STOP_MEDIA)                         \
		 || (opmode == OP_START_FORWARDING || opmode == OP_STOP_FORWARDING)              \
		 || (opmode == OP_UNSUBSCRIBE || opmode == OP_START_RECORDING)                   \
		 || (opmode == OP_STOP_RECORDING || opmode == OP_PAUSE_RECORDING)                \
		 || (opmode == OP_OTHER))

#define IS_OP_DIRECTIONAL(opmode)                                                                \
		 ((opmode == OP_BLOCK_DTMF || opmode == OP_BLOCK_MEDIA)                          \
		 || (opmode == OP_UNBLOCK_DTMF || opmode == OP_UNBLOCK_MEDIA)                    \
		 || (opmode == OP_START_FORWARDING || opmode == OP_STOP_FORWARDING))

#define RESET_BANDWIDTH(union_var, value) \
	do { \
		union_var.as = value; \
		union_var.rr = value; \
		union_var.rs = value; \
		union_var.ct = value; \
		union_var.tias = value; \
	} while(0)

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
#define SHARED_FLAG_IMPLICIT_RTCP		(1LL <<  0)
#define SHARED_FLAG_ASYMMETRIC			(1LL <<  1)
#define SHARED_FLAG_SEND			(1LL <<  2)
#define SHARED_FLAG_RECV			(1LL <<  3)
#define SHARED_FLAG_RTCP_MUX			(1LL <<  4)
#define SHARED_FLAG_SETUP_ACTIVE		(1LL <<  5)
#define SHARED_FLAG_SETUP_PASSIVE		(1LL <<  6)
#define SHARED_FLAG_ICE				(1LL <<  7)
#define SHARED_FLAG_STRICT_SOURCE		(1LL <<  8)
#define SHARED_FLAG_MEDIA_HANDOVER		(1LL <<  9)
#define SHARED_FLAG_TRICKLE_ICE			(1LL << 10)
#define SHARED_FLAG_ICE_LITE_PEER		(1LL << 11)
#define SHARED_FLAG_UNIDIRECTIONAL		(1LL << 12)
#define SHARED_FLAG_RTCP_FB			(1LL << 13)
#define SHARED_FLAG_LEGACY_OSRTP		(1LL << 14)
#define SHARED_FLAG_LEGACY_OSRTP_REV		(1LL << 15)
/* empty range [16 - 29] in-between for non-shared flags */
#define SHARED_FLAG_END_OF_CANDIDATES		(1LL << 30)

/* struct stream_params */
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
#define SP_FLAG_END_OF_CANDIDATES		SHARED_FLAG_END_OF_CANDIDATES

/* struct packet_stream */
#define PS_FLAG_RTP				(1LL << 16)
#define PS_FLAG_RTCP				(1LL << 17)
#define PS_FLAG_IMPLICIT_RTCP			SHARED_FLAG_IMPLICIT_RTCP
#define PS_FLAG_FALLBACK_RTCP			(1LL << 18)
#define PS_FLAG_RECEIVED			(1LL << 19)
#define PS_FLAG_FILLED				(1LL << 20)
#define PS_FLAG_CONFIRMED			(1LL << 21)
#define PS_FLAG_KERNELIZED			(1LL << 22)
#define PS_FLAG_NO_KERNEL_SUPPORT		(1LL << 23)
#define PS_FLAG_UNUSED				(1LL << 24)
#define PS_FLAG_FINGERPRINT_VERIFIED		(1LL << 25)
#define PS_FLAG_STRICT_SOURCE			SHARED_FLAG_STRICT_SOURCE
#define PS_FLAG_MEDIA_HANDOVER			SHARED_FLAG_MEDIA_HANDOVER
#define PS_FLAG_ICE				SHARED_FLAG_ICE
#define PS_FLAG_ZERO_ADDR			(1LL << 26)
#define PS_FLAG_PIERCE_NAT			(1LL << 27)
#define PS_FLAG_NAT_WAIT			(1LL << 28)

/* struct call_media */
#define MEDIA_FLAG_INITIALIZED			(1LL << 16)
#define MEDIA_FLAG_ASYMMETRIC			SHARED_FLAG_ASYMMETRIC
#define MEDIA_FLAG_UNIDIRECTIONAL		SHARED_FLAG_UNIDIRECTIONAL
#define MEDIA_FLAG_SEND				SHARED_FLAG_SEND
#define MEDIA_FLAG_RECV				SHARED_FLAG_RECV
#define MEDIA_FLAG_RTCP_MUX			SHARED_FLAG_RTCP_MUX
#define MEDIA_FLAG_RTCP_MUX_OVERRIDE		(1LL << 17)
#define MEDIA_FLAG_DTLS				(1LL << 18)
#define MEDIA_FLAG_SDES				(1LL << 19)
#define MEDIA_FLAG_SETUP_ACTIVE			SHARED_FLAG_SETUP_ACTIVE
#define MEDIA_FLAG_SETUP_PASSIVE		SHARED_FLAG_SETUP_PASSIVE
#define MEDIA_FLAG_PASSTHRU			(1LL << 20)
#define MEDIA_FLAG_ICE				SHARED_FLAG_ICE
#define MEDIA_FLAG_TRICKLE_ICE			SHARED_FLAG_TRICKLE_ICE
#define MEDIA_FLAG_ICE_LITE_PEER		SHARED_FLAG_ICE_LITE_PEER
#define MEDIA_FLAG_ICE_CONTROLLING		(1LL << 21)
#define MEDIA_FLAG_LOOP_CHECK			(1LL << 22)
#define MEDIA_FLAG_REORDER_FORCED		(1LL << 23)
#define MEDIA_FLAG_PTIME_OVERRIDE		(1LL << 24)
#define MEDIA_FLAG_RTCP_FB			SHARED_FLAG_RTCP_FB
#define MEDIA_FLAG_GENERATOR			(1LL << 25)
#define MEDIA_FLAG_ICE_LITE_SELF		(1LL << 26)
#define MEDIA_FLAG_RTCP_GEN			(1LL << 27)
#define MEDIA_FLAG_ECHO				(1LL << 28)
#define MEDIA_FLAG_BLACKHOLE			(1LL << 29)
// 30 used by SHARED_FLAG_END_OF_CANDIDATES
#define MEDIA_FLAG_AUDIO_PLAYER			(1LL << 31)
#define MEDIA_FLAG_END_OF_CANDIDATES		SHARED_FLAG_END_OF_CANDIDATES
#define MEDIA_FLAG_LEGACY_OSRTP			SHARED_FLAG_LEGACY_OSRTP
#define MEDIA_FLAG_LEGACY_OSRTP_REV		SHARED_FLAG_LEGACY_OSRTP_REV
#define MEDIA_FLAG_TRANSCODING			(1LL << 32)
#define MEDIA_FLAG_BLOCK_EGRESS			(1LL << 33)
/* MoH sendrecv flag handling, if set then hold is on-going */
#define MEDIA_FLAG_FAKE_SENDRECV		(1LL << 34)
/* in common with previous, if set, then answer has to be recvonly,
 * if not set, then inactive.
 */
#define MEDIA_FLAG_REAL_SENDONLY		(1LL << 35)
#define MEDIA_FLAG_SELECT_PT			(1LL << 36)
#define MEDIA_FLAG_RECRYPT			(1LL << 37)
#define MEDIA_FLAG_PUBLIC			(1LL << 38)

/* struct call_monologue */
#define ML_FLAG_REC_FORWARDING			(1LL << 16)
#define ML_FLAG_INJECT_DTMF			(1LL << 17)
#define ML_FLAG_DTMF_INJECTION_ACTIVE		(1LL << 18)
#define ML_FLAG_DETECT_DTMF			(1LL << 19)
#define ML_FLAG_NO_RECORDING			(1LL << 20)
#define ML_FLAG_FINAL_RESPONSE			(1LL << 21)
#define ML_FLAG_BLOCK_SHORT			(1LL << 22)
#define ML_FLAG_BLOCK_MEDIA			(1LL << 23)
#define ML_FLAG_SILENCE_MEDIA			(1LL << 24)
#define ML_FLAG_MOH_SENDRECV			(1LL << 25)
#define ML_FLAG_MOH_ZEROCONN			(1LL << 26)
#define ML_FLAG_FORCE_TRANSCODING		(1LL << 27)

/* call_t */
#define CALL_FLAG_IPV4_OFFER			(1LL << 16)
#define CALL_FLAG_IPV6_OFFER			(1LL << 17)
#define CALL_FLAG_IPV4_ANSWER			(1LL << 18)
#define CALL_FLAG_IPV6_ANSWER			(1LL << 19)
#define CALL_FLAG_MEDIA_COUNTED			(1LL << 20)
#define CALL_FLAG_RECORDING_ON			(1LL << 21)
#define CALL_FLAG_REC_FORWARDING		(1LL << 22)
#define CALL_FLAG_DROP_TRAFFIC			(1LL << 23)
#define CALL_FLAG_FOREIGN			(1LL << 24) // created_via_redis_notify call
#define CALL_FLAG_FOREIGN_MEDIA			(1LL << 25) // for calls taken over, tracks whether we have media
#define CALL_FLAG_DISABLE_JB			(1LL << 26)
#define CALL_FLAG_DEBUG				(1LL << 27)
#define CALL_FLAG_BLOCK_MEDIA			(1LL << 28)
#define CALL_FLAG_SILENCE_MEDIA			(1LL << 29)
#define CALL_FLAG_NO_REC_DB			(1LL << 30)

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
#include "dtmf.h"
#include "arena.h"
#include "ssrc.h"


struct control_stream;
struct redis;
struct crypto_suite;
struct rtpengine_srtp;
struct local_interface;
struct call_monologue;
struct ice_agent;
struct codec_handler;
struct media_player;
struct send_timer;
struct transport_protocol;
struct jitter_buffer;
struct codec_tracker;
struct rtcp_timer;
struct mqtt_timer;
struct janus_session;
struct audio_player;
struct media_subscription;




TYPED_GHASHTABLE(codecs_ht, void, rtp_payload_type, g_direct_hash, g_direct_equal, NULL, NULL)
TYPED_GHASHTABLE(codec_names_ht, str, GQueue, str_case_hash, str_case_equal, str_free, g_queue_free)
TYPED_GHASHTABLE_LOOKUP_INSERT(codec_names_ht, str_free, g_queue_new)
TYPED_GQUEUE(subscription, struct media_subscription)
TYPED_DIRECT_FUNCS(media_direct_hash, media_direct_eq, struct call_media)
TYPED_GHASHTABLE(subscription_ht, struct call_media, subscription_list, media_direct_hash, media_direct_eq,
		NULL, NULL)
TYPED_GHASHTABLE(media_id_ht, str, struct call_media, str_hash, str_equal, NULL, NULL)

struct session_bandwidth {
	long as, rr, rs, ct, tias;
};

struct codec_store {
	codecs_ht		codecs; // int payload type -> rtp_payload_type
	codec_names_ht		codec_names; // codec name -> GQueue of int payload types; storage container
	rtp_pt_q		codec_prefs; // preference by order in SDP; storage container
	rtp_pt_list		*supp_link; // tracks location for codec_store_add_end
	struct codec_tracker	*tracker;
	struct call_media	*media;
	unsigned int		strip_all:1, // set by codec_store_strip
				strip_full:1; // set by codec_store_strip
};

TYPED_GQUEUE(endpoint_map, struct endpoint_map)

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
	sdes_q			sdes_params; // slice-alloc'd
	sdp_attr_q		generic_attributes;	/* just some other attributes */
	sdp_attr_q		all_attributes;		/* all attributes */
	str			direction[2];
	struct dtls_fingerprint fingerprint;
	atomic64		sp_flags;
	struct codec_store	codecs;
	candidate_q		ice_candidates; /* slice-alloc'd */
	str			ice_ufrag;
	str			ice_pwd;
	int			ptime, maxptime;
	str			media_id;
	struct t38_options	t38_options;
	str			tls_id;
	int			media_sdp_id;
	struct session_bandwidth media_session_bandiwdth;
	str			sdp_information;
	extmap_q		extmap;
};

struct endpoint_map {
	unsigned int		unique_id;
	struct endpoint		endpoint;
	unsigned int		num_ports;
	struct logical_intf	*logical_intf;
	sfd_intf_list_q		intf_sfds; /* list of struct sfd_intf_list - contains stream_fd list */
	unsigned int		wildcard:1;
};

struct loop_protector {
	unsigned int		len;
	unsigned char		buf[RTP_LOOP_PROTECT];
};


TYPED_GPTRARRAY(rtp_stats_arr, struct rtp_stats)
TYPED_GHASHTABLE_PROTO(rtp_stats_ht, void, struct rtp_stats)

/**
 * The packet_stream itself can be marked as:
 * - SRTP endpoint
 * - ICE endpoint
 * - send/receive-only
 * 
 * This is done through the various bit flags.
 */
struct packet_stream {
	/* Lock valid only with call->master_lock held in R.
	 * Preempted by call->master_lock held in W.
	 */
	mutex_t			lock;

	struct call_media	*media;		/* RO */
	call_t			*call;		/* RO */
	unsigned int		component;	/* RO, starts with 1 */
	unsigned int		unique_id;	/* RO */
	struct recording_stream recording;	/* LOCK: call->master_lock */

	stream_fd_q		sfds;		/* LOCK: call->master_lock */
	stream_fd 		*selected_sfd;	// LOCK: ps->lock
	endpoint_t		last_local_endpoint;
	struct dtls_connection	ice_dtls;	/* LOCK: ps->lock */
	sink_handler_q		rtp_sinks;	/* LOCK: call->master_lock, ps->lock for streamhandler */
	sink_handler_q		rtcp_sinks;	/* LOCK: call->master_lock, ps->lock for streamhandler */
	struct packet_stream	*rtcp_sibling;	/* LOCK: call->master_lock */
	sink_handler_q		rtp_mirrors;	/* LOCK: call->master_lock, ps->lock for streamhandler */
	struct endpoint		endpoint;	/* LOCK: ps->lock */
	struct endpoint		detected_endpoints[4];		/* LOCK: ps->lock */
	int64_t			ep_detect_signal;		/* LOCK: ps->lock */
	struct endpoint		advertised_endpoint;		/* RO */
	struct endpoint		learned_endpoint;		/* LOCK: ps->lock */
	struct crypto_context	crypto;				/* OUT direction, LOCK: ps->lock */
	struct send_timer	*send_timer;				/* RO */
	struct jitter_buffer	*jb;					/* RO */
	int64_t			kernel_time_us;

	struct stream_stats	*stats_in;
	struct stream_stats	*stats_out;
	atomic64		last_packet_us;				// userspace only
	rtp_stats_ht		rtp_stats;				/* LOCK: call->master_lock */
	struct rtp_stats	*rtp_stats_cache;
	enum endpoint_learning		el_flags;

#if RTP_LOOP_PROTECT
	/* LOCK: ps->lock: */
	unsigned int		lp_idx;
	struct loop_protector	lp_buf[RTP_LOOP_PACKETS];
	unsigned int		lp_count;
#endif

	X509			*dtls_cert;				/* LOCK: ps->lock */

	/* ps->lock must be held for SETTING these: */
	atomic64		ps_flags;
};

INLINE int64_t packet_stream_last_packet(const struct packet_stream *ps) {
	uint64_t lp1 = atomic64_get_na(&ps->last_packet_us);
	uint64_t lp2 = atomic64_get_na(&ps->stats_in->last_packet_us);
	return MAX(lp1, lp2);
}

/**
 * Protected by call->master_lock, except the RO elements.
 * 
 * call_media is not reference-counted and is completely owned by the call object.
 * Therefore call_media is released when the call is destroyed.
 */
struct call_media {
	struct call_monologue	*monologue;			/* RO */
	call_t		*call;				/* RO */

	unsigned int		index;				/* RO */
	unsigned int		unique_id;			/* RO */
	str			type;
	enum media_type		type_id;
	str			protocol_str;
	const struct transport_protocol *protocol;
	str			format_str;
	sockfamily_t		*desired_family;
	struct logical_intf	*logical_intf;

	struct ice_agent	*ice_agent;

	extmap_q		extmap; // container
	struct rtp_extension	*extmap_a[14]; // 1-14 -> [0..13]
	extmap_ht		extmap_ht;
	struct rtp_extension	*(*extmap_lookup)(struct call_media *, unsigned int);
	ext_name_ht		ext_name_ht;

	str			media_id;
	str			label;
	sdes_q			sdes_in, sdes_out;
	struct dtls_fingerprint fingerprint;			/* as received */
	const struct dtls_hash_func *fp_hash_func;		/* outgoing */
	str			tls_id;
	candidate_q		ice_candidates; 		/* slice-alloc'd, as received */
	unsigned int			media_rec_slot;

	packet_stream_q		streams;			/* normally RTP + RTCP */
	endpoint_map_q		endpoint_maps;
	struct ssrc_hash	ssrc_hash_in;
	struct ssrc_hash	ssrc_hash_out;

	struct codec_store	codecs;
	struct codec_store	offered_codecs;
	sdp_attr_q		generic_attributes;			/* sdp_attr_new() */
	sdp_attr_q		all_attributes;			/* sdp_attr_new() */
	sdp_media_attr_print_f	*sdp_attr_print;
	codec_handlers_ht	codec_handlers;			/* int payload type -> struct codec_handler
														XXX combine this with 'codecs' hash table? */
	codec_handlers_q	codec_handlers_store;		/* storage for struct codec_handler */
	struct codec_handler	*codec_handler_cache;
	struct rtcp_handler	*rtcp_handler;
	struct rtcp_timer	*rtcp_timer;			/* master lock for scheduling purposes */
	struct mqtt_timer	*mqtt_timer;			/* master lock for scheduling purposes */
	//struct codec_handler	*dtmf_injector;
	struct t38_gateway	*t38_gateway;
	struct audio_player	*audio_player;
	struct codec_handler	*t38_handler;

	unsigned int		buffer_delay;

	/* media subsriptions handling */
	subscription_ht		media_subscriptions_ht;		/* for quick lookup of our subsriptions */
	subscription_ht		media_subscribers_ht;		/* for quick lookup of medias subscribed to us */
	subscription_q		media_subscribers;		/* who is subscribed to this media (sinks) */
	subscription_q		media_subscriptions;		/* who am I subscribed to (sources) */

	mutex_t			dtmf_lock;
	unsigned long		dtmf_ts;			/* TS of last processed end event */
	unsigned int		dtmf_count;
	// lists are append-only
	dtmf_event_q		dtmf_recv;
	dtmf_event_q		dtmf_send;
	int					media_sdp_id;

	/* bandwidth */
	struct session_bandwidth sdp_media_bandwidth;

	str sdp_information;

#ifdef WITH_TRANSCODING
	encoder_callback_t	encoder_callback;
#endif

	int			ptime;				/* either from SDP or overridden */
	int			maxptime;			/* from SDP */

	atomic64		media_flags;
	unsigned int		update_iter;
};

TYPED_GPTRARRAY(medias_arr, struct call_media)
TYPED_GQUEUE(medias, struct call_media)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(medias_q, medias_q_clear)


struct media_subscription {
	struct call_media	* media;	/* media itself */
	struct call_monologue	* monologue;	/* whom media belongs to */
	struct sink_attrs	attrs;		/* attributes to passed to a sink */
	subscription_list	* link;		/* TODO: is this still really needed? */
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
	call_t		*call;			/* RO */
	unsigned int		unique_id;		/* RO */

	str			tag;
	str			viabranch;
	str_q			tag_aliases;
	enum tag_type		tagtype;
	str			label;
	int64_t			created_us;		/* RO */
	int64_t			deleted_us;
	int64_t			started;		/* for CDR */
	int64_t			terminated;		/* for CDR */
	enum termination_reason	term_reason;
	sockfamily_t		*desired_family;
	struct logical_intf	*logical_intf;
	GHashTable 		*associated_tags;
	GHashTable		*subscribers_ht;	/* for quick lookup */
	medias_arr		*medias;
	media_id_ht		media_ids;
	struct media_player	*player;
	struct media_player	*rec_player;
	struct session_bandwidth sdp_session_bandwidth;
	sdp_streams_q		last_in_sdp_streams;	/* last parsed `stream_params` */
	GString			*last_out_sdp;

	sdp_origin * session_sdp_orig;	/* actual origin belonging to this monologue */
	sdp_origin * session_last_sdp_orig;	/* previously used origin by other other side */

	str			sdp_session_name;
	str			sdp_session_timing;
	str			sdp_session_group;	/* a=group: e.g. BUNDLE */
	str			sdp_session_information;
	str			sdp_session_uri;
	str			sdp_session_phone;
	str			sdp_session_email;
	str			metadata;
	struct janus_session	*janus_session;

	// DTMF triggers, MUST be set via dtmf_trigger_set() only
	struct dtmf_trigger_state dtmf_trigger_state[__NUM_DTMF_TRIGGERS];
	uint8_t			dtmf_trigger_index[__NUM_DTMF_TRIGGERS];
	unsigned int		num_dtmf_triggers;
	unsigned int		dtmf_delay;

	// DTMF blocking/replacement stuff:
	enum block_dtmf_mode	block_dtmf; // current block mode
	GArray			*tone_freqs;
	unsigned int		tone_vol;
	char			dtmf_digit; // replacement digit
	enum block_dtmf_mode	block_dtmf_trigger; // to enable when trigger detected
	int			dtmf_trigger_digits; // unblock after this many digits
	enum block_dtmf_mode	block_dtmf_trigger_end; // to enable when trigger detected
	unsigned int		block_dtmf_trigger_end_ms; // unblock after this many ms

	/* carry `sdp_session` attributes into resulting call monologue SDP */
	sdp_attr_q		generic_attributes;
	sdp_attr_q		all_attributes;
	sdp_monologue_attr_print_f *sdp_attr_print;

	long long moh_db_id;
	str moh_blob;
	str moh_file;

	atomic64		ml_flags;
};

TYPED_GQUEUE(monologues, struct call_monologue)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(monologues_q, monologues_q_clear)
TYPED_GHASHTABLE(tags_ht, str, struct call_monologue, str_hash, str_equal, NULL, NULL)

struct sdp_fragment;
TYPED_GQUEUE(fragment, struct sdp_fragment)
TYPED_GHASHTABLE(fragments_ht, str, fragment_q, str_hash, str_equal, NULL, NULL)


struct call_iterator_list {
	call_list *first;
	mutex_t lock; // protects .first and every entry's .data
};
struct call_iterator_entry {
	call_list link; // .data is protected by the list's main lock
	mutex_t next_lock; // held while the link is in use, protects link.data and link.next
	mutex_t prev_lock; // held while the link is in use, protects link.prev
};

#define ITERATE_CALL_LIST_START(which, varname) \
	do { \
		int __which = (which); \
		mutex_lock(&rtpe_call_iterators[__which].lock); \
		\
		__auto_type __l = rtpe_call_iterators[__which].first; \
		bool __has_lock = true; \
		call_t *next_ ## varname = NULL; \
		while (__l) { \
			call_t *varname = NULL; \
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
			__auto_type __next = varname->iterator[__which].link.next; \
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


TYPED_GHASHTABLE(labels_ht, str, struct call_monologue, str_hash, str_equal, NULL, NULL)

/**
 * call_t is the main parent structure of all call-related objects.
 * 
 * The logical object hierarchy under the 'struct call':
 * call > call_monologue > call_media > packet_stream > stream_fd
 * 
 * call_t usually has multiple call_monologue objects.
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

	memory_arena_t		buffer;

	// use a single poller for all sockets within the call
	struct poller		*poller;

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
	monologues_q		monologues;	/* call_monologue */
	medias_q		medias;		/* call_media */
	tags_ht			tags;
	tags_ht			viabranches;
	labels_ht		labels;
	fragments_ht		sdp_fragments;
	packet_stream_q		streams;
	stream_fd_q		stream_fds;	/* stream_fd */
	endpoint_map_q		endpoint_maps;
	struct dtls_cert	*dtls_cert;	/* for outgoing */
	struct mqtt_timer	*mqtt_timer;

	str			callid;
	str_q			callid_aliases;
	int64_t			created;
	int64_t			destroyed;
	int64_t			last_signal_us;
	int64_t			deleted_us;
	int64_t			ml_deleted_us;
	unsigned char		tos;
	str			created_from;
	str			xmlrpc_callback;
	endpoint_t		dtmf_log_dest;

	int			redis_hosted_db;
	atomic64		last_redis_update_us;

	struct recording 	*recording;
	str			metadata;
	str			recording_meta_prefix;
	str			recording_file;
	str			recording_random_tag;
	str			recording_path;
	str			recording_pattern;

	struct call_iterator_entry iterator[NUM_CALL_ITERATORS];
	int			cpu_affinity;
	enum block_dtmf_mode	block_dtmf;

	atomic64		call_flags;
	unsigned int		update_iter;
	unsigned int media_rec_slots;
};


/**
 * The main entry point into call objects for signalling events is the call-ID:
 * Therefore the main entry point is the global hash table rtpe_callhash (protected by rtpe_callhash_lock),
 * which uses call-IDs as keys and call objects as values,
 * while holding a reference to each contained call.
 */
TYPED_GHASHTABLE(rtpe_calls_ht, str, struct call, str_hash, str_equal, NULL, NULL)

extern rwlock_t rtpe_callhash_lock;
extern rtpe_calls_ht rtpe_callhash;
extern struct call_iterator_list rtpe_call_iterators[NUM_CALL_ITERATORS];
extern __thread call_t *call_memory_arena;



int call_init(void);
void call_free(void);

struct call_monologue *__monologue_create(call_t *call);
void __monologue_free(struct call_monologue *m);
void __monologue_tag(struct call_monologue *ml, const str *tag);
void __monologue_viabranch(struct call_monologue *ml, const str *viabranch);
struct packet_stream *__packet_stream_new(call_t *call);
__attribute__((nonnull(1, 2)))
struct media_subscription *__add_media_subscription(struct call_media * which, struct call_media * to,
		const struct sink_attrs *attrs);
bool __unsubscribe_media(struct call_media * which, struct call_media * from);
struct media_subscription *call_ml_get_top_ms(struct call_monologue *ml);
bool call_ml_sendonly_inactive(struct call_monologue *ml);
struct media_subscription *call_media_get_top_ms(struct call_media * cm);
struct media_subscription *call_get_media_subscription(subscription_ht ht, struct call_media * cm);
struct call_monologue * ml_medias_subscribed_to_single_ml(struct call_monologue *ml);

void free_sink_handler(struct sink_handler *);
void __add_sink_handler(sink_handler_q *, struct packet_stream *, const struct sink_attrs *);

void media_subscription_free(struct media_subscription *);
void media_subscriptions_clear(subscription_q *q);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(subscription_q, media_subscriptions_clear)

call_t *call_get_or_create(const str *callid, bool exclusive);
call_t *call_get_opmode(const str *callid, enum ng_opmode opmode);
void call_make_own_foreign(call_t *c, bool foreign);
int call_get_mono_dialogue(struct call_monologue *monologues[2], call_t *call,
		const str *fromtag,
		const str *totag,
		const str *viabranch,
		sdp_ng_flags *);
struct call_monologue *call_get_monologue(call_t *call, const str *fromtag);
struct call_monologue *call_get_or_create_monologue(call_t *call, const str *fromtag);
__attribute__((nonnull(1, 2, 4, 5, 6)))
struct call_media *call_make_transform_media(struct call_monologue *ml, const str *type, enum media_type type_id,
		const str *media_id, const endpoint_t *remote, const str *interface);
__attribute__((nonnull(1)))
call_t *call_get(const str *callid);
typedef enum { CG2_OK, CG2_NF1, CG2_NF2, CG2_SAME } call_get2_ret_t;
__attribute__((nonnull(1, 2, 3, 4)))
call_get2_ret_t call_get2(call_t **, call_t **, const str *, const str *);
__attribute__((nonnull(1, 2)))
bool call_merge(call_t *, call_t **);
__attribute__((nonnull(2, 3)))
int monologue_offer_answer(struct call_monologue *monologues[2], sdp_streams_q *streams, sdp_ng_flags *flags);
__attribute__((nonnull(1, 2, 3, 4)))
void codecs_offer_answer(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, sdp_ng_flags *flags);
int monologue_publish(struct call_monologue *ml, sdp_streams_q *streams, sdp_ng_flags *flags);
int monologue_subscribe_request(const subscription_q *srms, struct call_monologue *dst, sdp_ng_flags *flags);
int monologue_subscribe_answer(struct call_monologue *dst, sdp_ng_flags *flags,
		sdp_streams_q *streams);
int monologue_unsubscribe(struct call_monologue *dst, sdp_ng_flags *);
void dialogue_connect(struct call_monologue *, struct call_monologue *, sdp_ng_flags *);
bool monologue_transform(struct call_monologue *, sdp_ng_flags *, medias_q *);
void monologue_destroy(struct call_monologue *ml);
int call_delete_branch_by_id(const str *callid, const str *branch,
	const str *fromtag, const str *totag, ng_command_ctx_t *, int64_t delete_delay);
int call_delete_branch(call_t *, const str *branch,
	const str *fromtag, const str *totag, ng_command_ctx_t *, int64_t delete_delay);
void call_destroy(call_t *);
struct call_media *call_media_new(call_t *call);
void call_media_free(struct call_media **mdp);
enum call_stream_state call_stream_state_machine(struct packet_stream *);
void call_media_state_machine(struct call_media *m);
void call_media_unkernelize(struct call_media *media, const char *reason);
void dialogue_unconfirm(struct call_monologue *ml, const char *);
void __monologue_unconfirm(struct call_monologue *monologue, const char *);
void __media_unconfirm(struct call_media *media, const char *);
__attribute__((nonnull(1)))
void update_init_monologue_subscribers(struct call_monologue *ml, enum ng_opmode opmode);

int call_stream_address(GString *, struct packet_stream *ps, enum stream_address_format format,
		const struct local_intf *ifa, bool keep_unspec);

void add_total_calls_duration_in_interval(int64_t interval_tv);
enum thread_looper_action call_timer(void);

void __rtp_stats_update(rtp_stats_ht dst, struct codec_store *);
bool __init_stream(struct packet_stream *ps);

const rtp_payload_type *__rtp_stats_codec(struct call_media *m);

#include "str.h"
#include "rtp.h"

#define call_malloc memory_arena_alloc
#define call_dup memory_arena_dup
#define call_ref memory_arena_ref

#define call_strdup memory_arena_strdup
#define call_strdup_str memory_arena_strdup_str
#define call_str_cpy_len memory_arena_str_cpy_len
#define call_str_cpy memory_arena_str_cpy
#define call_str_cpy_c memory_arena_str_cpy_c
#define call_str_dup memory_arena_str_dup

INLINE void __call_unkernelize(call_t *call, const char *reason) {
	for (__auto_type l = call->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		__monologue_unconfirm(ml, reason);
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

INLINE void call_memory_arena_release(void) {
	if (!call_memory_arena)
		return;
	obj_put(call_memory_arena);
	call_memory_arena = NULL;
	memory_arena = &rtpe_arena;
}
INLINE void call_memory_arena_set(call_t *c) {
	call_memory_arena_release();
	call_memory_arena = obj_get(c);
	memory_arena = &c->buffer;
}

#endif
