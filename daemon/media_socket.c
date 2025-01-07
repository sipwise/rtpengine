#include "media_socket.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <errno.h>
#include <netinet/in.h>

#include "str.h"
#include "ice.h"
#include "socket.h"
#include "redis.h"
#include "rtp.h"
#include "ice.h"
#include "stun.h"
#include "kernel.h"
#include "rtcp.h"
#include "sdp.h"
#include "helpers.h"
#include "log_funcs.h"
#include "poller.h"
#include "recording.h"
#include "rtplib.h"
#include "rtcplib.h"
#include "ssrc.h"
#include "iptables.h"
#include "main.h"
#include "codec.h"
#include "media_player.h"
#include "jitter_buffer.h"
#include "dtmf.h"
#include "mqtt.h"
#include "janus.h"
#include "bufferpool.h"

#include "xt_RTPENGINE.h"

#ifndef PORT_RANDOM_MIN
#define PORT_RANDOM_MIN 6
#define PORT_RANDOM_MAX 20
#endif


#ifndef MAX_RECV_LOOP_STRIKES
#define MAX_RECV_LOOP_STRIKES 5
#endif


struct intf_key {
	str name;
	sockfamily_t *preferred_family;
};
struct intf_rr {
	struct intf_key hash_key;
	mutex_t lock;
	GQueue logical_intfs;
	struct logical_intf *singular; // set iff only one is present in the list - no lock needed
};
struct packet_handler_ctx {
	// inputs:
	str s; // raw input packet
	bool kernel_handled; // parse and read contents but do not forward

	sink_handler_q *sinks; // where to send output packets to (forward destination)
	rewrite_func decrypt_func, encrypt_func; // handlers for decrypt/encrypt
	rtcp_filter_func *rtcp_filter;
	struct packet_stream *in_srtp, *out_srtp; // SRTP contexts for decrypt/encrypt (relevant for muxed RTCP)
	int payload_type; // -1 if unknown or not RTP
	bool rtcp; // true if this is an RTCP packet
	GQueue rtcp_list;

	// verdicts:
	bool update; // true if Redis info needs to be updated
	const char *unkernelize; // non-null if stream ought to be removed from kernel
	bool unconfirm; // forget learned peer address
	bool unkernelize_subscriptions; // if our peer address changed
	bool kernelize; // true if stream can be kernelized
	bool rtcp_discard; // do not forward RTCP

	// output:
	struct media_packet mp; // passed to handlers
};
struct late_port_release {
	socket_t socket;
	struct intf_spec *spec;
};
struct interface_stats_interval {
	struct interface_stats_block stats;
	struct timeval last_run;
};


TYPED_GQUEUE(ports_release, struct late_port_release)

/* thread scope (local) queue for sockets to be released, only appending here */
static __thread ports_release_q ports_to_release = TYPED_GQUEUE_INIT;
/* global queue for sockets to be released, releasing by `sockets_releaser()` is done using that */
static ports_release_q ports_to_release_glob = TYPED_GQUEUE_INIT;
static mutex_t ports_to_release_glob_lock = MUTEX_STATIC_INIT;

static const struct streamhandler *__determine_handler(struct packet_stream *in, struct sink_handler *);

static int __k_null(struct rtpengine_srtp *s, struct packet_stream *);
static int __k_srtp_encrypt(struct rtpengine_srtp *s, struct packet_stream *);
static int __k_srtp_decrypt(struct rtpengine_srtp *s, struct packet_stream *);

static int call_avp2savp_rtp(str *s, struct packet_stream *, struct ssrc_ctx *);
static int call_savp2avp_rtp(str *s, struct packet_stream *, struct ssrc_ctx *);
static int call_avp2savp_rtcp(str *s, struct packet_stream *, struct ssrc_ctx *);
static int call_savp2avp_rtcp(str *s, struct packet_stream *, struct ssrc_ctx *);


static struct logical_intf *__get_logical_interface(const str *name, sockfamily_t *fam);




/* ********** */

const struct transport_protocol transport_protocols[] = {
	[PROTO_RTP_AVP] = {
		.index		= PROTO_RTP_AVP,
		.name		= "RTP/AVP",
		.avpf_proto	= PROTO_RTP_AVPF,
		.osrtp_proto	= PROTO_RTP_SAVP_OSRTP,
		.rtp		= 1,
		.srtp		= 0,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_SAVP] = {
		.index		= PROTO_RTP_SAVP,
		.name		= "RTP/SAVP",
		.avpf_proto	= PROTO_RTP_SAVPF,
		.rtp		= 1,
		.srtp		= 1,
		.rtp_proto	= PROTO_RTP_AVP,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_AVPF] = {
		.index		= PROTO_RTP_AVPF,
		.name		= "RTP/AVPF",
		.osrtp_proto	= PROTO_RTP_SAVPF_OSRTP,
		.rtp		= 1,
		.srtp		= 0,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_RTP_SAVPF] = {
		.index		= PROTO_RTP_SAVPF,
		.name		= "RTP/SAVPF",
		.rtp		= 1,
		.srtp		= 1,
		.rtp_proto	= PROTO_RTP_AVPF,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_UDP_TLS_RTP_SAVP] = {
		.index		= PROTO_UDP_TLS_RTP_SAVP,
		.name		= "UDP/TLS/RTP/SAVP",
		.avpf_proto	= PROTO_UDP_TLS_RTP_SAVPF,
		.rtp		= 1,
		.srtp		= 1,
		.rtp_proto	= PROTO_RTP_AVP,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_UDP_TLS_RTP_SAVPF] = {
		.index		= PROTO_UDP_TLS_RTP_SAVPF,
		.name		= "UDP/TLS/RTP/SAVPF",
		.rtp		= 1,
		.srtp		= 1,
		.rtp_proto	= PROTO_RTP_AVPF,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_UDPTL] = {
		.index		= PROTO_UDPTL,
		.name		= "udptl",
		.rtp		= 0,
		.srtp		= 0,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_SAVP_OSRTP] = {
		.index		= PROTO_RTP_SAVP_OSRTP,
		.name		= "RTP/AVP",
		.avpf_proto	= PROTO_RTP_SAVPF_OSRTP,
		.rtp		= 1,
		.srtp		= 1,
		.rtp_proto	= PROTO_RTP_AVP,
		.osrtp		= 1,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_SAVPF_OSRTP] = {
		.index		= PROTO_RTP_SAVPF_OSRTP,
		.name		= "RTP/AVPF",
		.rtp		= 1,
		.srtp		= 1,
		.rtp_proto	= PROTO_RTP_AVPF,
		.osrtp		= 1,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_UNKNOWN] = {
		.index		= PROTO_UNKNOWN,
		.name		= "unknown (legacy)",
		.rtp		= 0,
		.srtp		= 0,
		.avpf		= 0,
		.tcp		= 0,
	},
};
const int num_transport_protocols = G_N_ELEMENTS(transport_protocols);


/* ********** */

static const struct streamhandler_io __shio_noop = { // non-RTP protocols
	.kernel		= __k_null,
};
static const struct streamhandler_io __shio_noop_rtp = {
	.kernel		= __k_null,
};
static const struct streamhandler_io __shio_decrypt = {
	.kernel		= __k_srtp_decrypt,
	.rtp_crypt	= call_savp2avp_rtp,
	.rtcp_crypt	= call_savp2avp_rtcp,
};
static const struct streamhandler_io __shio_encrypt = {
	.kernel		= __k_srtp_encrypt,
	.rtp_crypt	= call_avp2savp_rtp,
	.rtcp_crypt	= call_avp2savp_rtcp,
};
static const struct streamhandler_io __shio_decrypt_rtcp_only = {
	.kernel		= __k_null,
	.rtcp_crypt	= call_savp2avp_rtcp,
};
static const struct streamhandler_io __shio_encrypt_rtcp_only = {
	.kernel		= __k_null,
	.rtcp_crypt	= call_avp2savp_rtcp,
};
static const struct streamhandler_io __shio_avpf_strip = {
	.kernel		= __k_null,
	.rtcp_filter	= rtcp_avpf2avp_filter,
};
static const struct streamhandler_io __shio_decrypt_avpf_strip = {
	.kernel		= __k_srtp_decrypt,
	.rtp_crypt	= call_savp2avp_rtp,
	.rtcp_crypt	= call_savp2avp_rtcp,
	.rtcp_filter	= rtcp_avpf2avp_filter,
};

/* ********** */

static const struct streamhandler __sh_noop = { // non-RTP protocols
	.in		= &__shio_noop,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_noop_rtp = {
	.in		= &__shio_noop_rtp,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_savp2avp = {
	.in		= &__shio_decrypt,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_avp2savp = {
	.in		= &__shio_noop_rtp,
	.out		= &__shio_encrypt,
};
static const struct streamhandler __sh_avpf2avp = {
	.in		= &__shio_avpf_strip,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_avpf2savp = {
	.in		= &__shio_avpf_strip,
	.out		= &__shio_encrypt,
};
static const struct streamhandler __sh_savpf2avp = {
	.in		= &__shio_decrypt_avpf_strip,
	.out		= &__shio_noop,
};
static const struct streamhandler __sh_savp2savp = {
	.in		= &__shio_decrypt,
	.out		= &__shio_encrypt,
};
static const struct streamhandler __sh_savp2savp_rtcp_only = {
	.in		= &__shio_decrypt_rtcp_only,
	.out		= &__shio_encrypt_rtcp_only,
};
static const struct streamhandler __sh_savpf2savp = {
	.in		= &__shio_decrypt_avpf_strip,
	.out		= &__shio_encrypt,
};

/* ********** */

static const struct streamhandler * const __sh_matrix_in_rtp_avp[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_noop_rtp,
	[PROTO_RTP_AVPF]		= &__sh_noop_rtp,
	[PROTO_RTP_SAVP]		= &__sh_avp2savp,
	[PROTO_RTP_SAVPF]		= &__sh_avp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_avp2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_avp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_avp2savp,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_avp2savp,
};
static const struct streamhandler * const __sh_matrix_in_rtp_avpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_avpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_noop_rtp,
	[PROTO_RTP_SAVP]		= &__sh_avpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_avp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_avpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_avp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_avpf2savp,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_avp2savp,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savp[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savp2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savp2savp_rtcp_only,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp_rtcp_only,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savp2savp_rtcp_only,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp_rtcp_only,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_savp2savp_rtcp_only,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_savp2savp_rtcp_only,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp_rtcp_only,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp_rtcp_only,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_savp2savp_rtcp_only,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savp_recrypt[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savp2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savp2savp,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savp2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_savp2savp,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_savp2savp,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savpf_recrypt[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_savp2savp,
};
static const struct streamhandler * const __sh_matrix_noop[__PROTO_LAST] = { // non-RTP protocols
	[PROTO_RTP_AVP]			= &__sh_noop,
	[PROTO_RTP_AVPF]		= &__sh_noop,
	[PROTO_RTP_SAVP]		= &__sh_noop,
	[PROTO_RTP_SAVPF]		= &__sh_noop,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_noop,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_noop,
	[PROTO_UDPTL]			= &__sh_noop,
	[PROTO_RTP_SAVP_OSRTP]		= &__sh_noop,
	[PROTO_RTP_SAVPF_OSRTP]		= &__sh_noop,
	[PROTO_UNKNOWN]			= &__sh_noop,
};

/* ********** */

static const struct streamhandler * const * const __sh_matrix[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= __sh_matrix_in_rtp_avp,
	[PROTO_RTP_AVPF]		= __sh_matrix_in_rtp_avpf,
	[PROTO_RTP_SAVP]		= __sh_matrix_in_rtp_savp,
	[PROTO_RTP_SAVPF]		= __sh_matrix_in_rtp_savpf,
	[PROTO_UDP_TLS_RTP_SAVP]	= __sh_matrix_in_rtp_savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= __sh_matrix_in_rtp_savpf,
	[PROTO_UDPTL]			= __sh_matrix_noop,
	[PROTO_RTP_SAVP_OSRTP]		= __sh_matrix_in_rtp_savp,
	[PROTO_RTP_SAVPF_OSRTP]		= __sh_matrix_in_rtp_savpf,
	[PROTO_UNKNOWN]			= __sh_matrix_noop,
};
/* special case for DTLS as we can't pass through SRTP<>SRTP */
static const struct streamhandler * const * const __sh_matrix_recrypt[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= __sh_matrix_in_rtp_avp,
	[PROTO_RTP_AVPF]		= __sh_matrix_in_rtp_avpf,
	[PROTO_RTP_SAVP]		= __sh_matrix_in_rtp_savp_recrypt,
	[PROTO_RTP_SAVPF]		= __sh_matrix_in_rtp_savpf_recrypt,
	[PROTO_UDP_TLS_RTP_SAVP]	= __sh_matrix_in_rtp_savp_recrypt,
	[PROTO_UDP_TLS_RTP_SAVPF]	= __sh_matrix_in_rtp_savpf_recrypt,
	[PROTO_UDPTL]			= __sh_matrix_noop,
	[PROTO_RTP_SAVP_OSRTP]		= __sh_matrix_in_rtp_savp_recrypt,
	[PROTO_RTP_SAVPF_OSRTP]		= __sh_matrix_in_rtp_savpf_recrypt,
	[PROTO_UNKNOWN]			= __sh_matrix_noop,
};

/* ********** */

static const struct rtpengine_srtp __res_null = {
	.cipher			= REC_NULL,
	.hmac			= REH_NULL,
};




static GQueue *__interface_list_for_family(sockfamily_t *fam);


static unsigned int __name_family_hash(const struct intf_key *p);
static int __name_family_eq(const struct intf_key *a, const struct intf_key *b);

TYPED_GHASHTABLE(intf_lookup, struct intf_key, struct logical_intf, __name_family_hash, __name_family_eq,
		g_free, NULL)
TYPED_GHASHTABLE(intf_rr_lookup, struct intf_key, struct intf_rr, __name_family_hash, __name_family_eq,
		NULL, NULL)

static intf_lookup __logical_intf_name_family_hash; // name + family -> struct logical_intf
static intf_rr_lookup __logical_intf_name_family_rr_hash; // name + family -> struct intf_rr
static GHashTable *__intf_spec_addr_type_hash; // addr + type -> struct intf_spec
static GHashTable *__local_intf_addr_type_hash; // addr + type -> GList of struct local_intf
static GQueue __preferred_lists_for_family[__SF_LAST];

GQueue all_local_interfaces = G_QUEUE_INIT;

TYPED_GHASHTABLE(local_sockets_ht, endpoint_t, stream_fd, endpoint_hash, endpoint_eq, NULL, stream_fd_put)
static rwlock_t local_media_socket_endpoints_lock = RWLOCK_STATIC_INIT;
static local_sockets_ht local_media_socket_endpoints;

__thread struct bufferpool *media_bufferpool;


/* checks for free no_ports on a local interface */
static int has_free_ports_loc(struct local_intf *loc, unsigned int num_ports) {
	if (loc == NULL) {
		ilog(LOG_ERR, "has_free_ports_loc - NULL local interface");
		return 0;
	}

	if (num_ports > g_hash_table_size(loc->spec->port_pool.free_ports_ht)) {
		ilog(LOG_ERR, "Didn't find %d ports available for " STR_FORMAT "/%s",
			num_ports, STR_FMT(&loc->logical->name),
			sockaddr_print_buf(&loc->spec->local_address.addr));
		return 0;
	}

	__C_DBG("Found %d ports available for " STR_FORMAT "/%s from total of %d free ports",
		num_ports, STR_FMT(&loc->logical->name),
		sockaddr_print_buf(&loc->spec->local_address.addr),
		g_hash_table_size(loc->spec->port_pool.free_ports_ht));

	return 1;
}

#if 0
/* checks for free num_ports on at least one local interface of a logical interface */
static int has_free_ports_log_any(struct logical_intf *log, unsigned int num_ports) {
	if (log == NULL) {
		ilog(LOG_ERR, "has_free_ports_log_any - NULL logical interface");
		return 0;
	}

	struct local_intf *loc;
	GList *l;

	for (l = log->list.head; l; l = l->next) {
		loc = l->data;

		if (has_free_ports_loc(loc, num_ports)) {
			return 1;
		}
	}

	return 0;
}
#endif

/* checks for free num_ports on all local interfaces of a logical interface */
static int has_free_ports_log_all(struct logical_intf *log, unsigned int num_ports) {
	if (log == NULL) {
		ilog(LOG_ERR, "has_free_ports_log_all - NULL logical interface");
		return 0;
	}

	struct local_intf *loc;
	GList *l;

	for (l = log->list.head; l; l = l->next) {
		loc = l->data;

		if (!has_free_ports_loc(loc, num_ports)) {
			return 0;
		}
	}

	return 1;
}

/* run round-robin-calls algorithm */
static struct logical_intf* run_round_robin_calls(struct intf_rr *rr, unsigned int num_ports) {
	struct logical_intf *log = NULL;

	mutex_lock(&rr->lock);

	unsigned int max_tries = rr->logical_intfs.length;
	unsigned int num_tries = 0;

	while (num_tries++ < max_tries) {
		log = g_queue_pop_head(&rr->logical_intfs);
		g_queue_push_tail(&rr->logical_intfs, log);

		mutex_unlock(&rr->lock);

		__C_DBG("Trying %d ports on logical interface " STR_FORMAT, num_ports, STR_FMT(&log->name));

		if (has_free_ports_log_all(log, num_ports))
			goto done;
		log = NULL;

		mutex_lock(&rr->lock);
	}

	mutex_unlock(&rr->lock);

done:
	if (!log) {
		ilog(LOG_ERR, "No logical interface with free ports found; fallback to default behaviour");
		return NULL;
	}
	__C_DBG("Round Robin Calls algorithm found logical " STR_FORMAT, STR_FMT(&log->name));
	return log;
}

// 'fam' may only be NULL if 'name' is also NULL
struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam, int num_ports) {
	struct logical_intf *log = NULL;
	int rr_use_default_intf = 0;

	__C_DBG("Get logical interface for %d ports", num_ports);

	if (G_UNLIKELY(!name || !name->s)) {
		// trivial case: no interface given. just pick one suitable for the address family.
		// always used for legacy TCP and UDP protocols.
		GQueue *q = NULL;
		if (fam)
			q = __interface_list_for_family(fam);
		if (!q) {
			for (int i = 0; i < __SF_LAST; i++) {
				q = &__preferred_lists_for_family[i];
				if (q->length)
					goto got_some;
			}
			abort();
got_some:
			;
		}
		if (!q->head)
			return NULL;

		log = q->head->data;
		// if interface is in the form foo:bar then use round-robin
		if (!fam || log->name.len == log->name_base.len)
			return log;
		else
			rr_use_default_intf = 1;
	}

	// check if round-robin is desired
	struct intf_key key;

	if (rr_use_default_intf)
		key.name = log->name_base;
	else
		key.name = *name;
	key.preferred_family = fam;

	struct intf_rr *rr = t_hash_table_lookup(__logical_intf_name_family_rr_hash, &key);
	if (!rr) {
		// try other socket families
		for (int i = 0; i < __SF_LAST; i++) {
			key.preferred_family = get_socket_family_enum(i);
			rr = t_hash_table_lookup(__logical_intf_name_family_rr_hash, &key);
			if (rr)
				break;
		}
	}
	if (!rr)
		return name ? __get_logical_interface(name, fam) : log;
	if (rr->singular) {
		__C_DBG("Returning non-RR logical interface '" STR_FORMAT "' based on direction '" \
					STR_FORMAT "'",
				STR_FMT(&rr->singular->name),
				STR_FMT(name));
		return rr->singular;
	}

	__C_DBG("Running RR interface selection for direction '" STR_FORMAT "'",
			STR_FMT(name));

	log = run_round_robin_calls(rr, num_ports);
	if (log)
		return log;
	if (!name)
		return NULL;
	return __get_logical_interface(name, fam);
}
static struct logical_intf *__get_logical_interface(const str *name, sockfamily_t *fam) {
	struct intf_key d;
	struct logical_intf *log = NULL;

	d.name = *name;
	d.preferred_family = fam;

	log = t_hash_table_lookup(__logical_intf_name_family_hash, &d);
	if (log) {
		__C_DBG("Choose logical interface " STR_FORMAT " because of direction " STR_FORMAT,
			STR_FMT(&log->name),
			STR_FMT(name));
	} else {
		__C_DBG("Choose logical interface NULL because of direction " STR_FORMAT,
			STR_FMT(name));
	}

	return log;
}

static unsigned int __name_family_hash(const struct intf_key *lif) {
	return str_hash(&lif->name) ^ g_direct_hash(lif->preferred_family);
}
static int __name_family_eq(const struct intf_key *A, const struct intf_key *B) {
	return str_equal(&A->name, &B->name) && A->preferred_family == B->preferred_family;
}

static unsigned int __addr_type_hash(const void *p) {
	const struct intf_address *addr = p;
	return sockaddr_hash(&addr->addr) ^ g_direct_hash(addr->type);
}
static int __addr_type_eq(const void *a, const void *b) {
	const struct intf_address *A = a, *B = b;
	return sockaddr_eq(&A->addr, &B->addr) && A->type == B->type;
}

static void __insert_local_intf_addr_type(const struct intf_address *addr, const struct local_intf *intf) {
	GList *l;

	l = g_hash_table_lookup(__local_intf_addr_type_hash, addr);
	l = g_list_prepend(l, (void *) intf);
	g_hash_table_replace(__local_intf_addr_type_hash, (void *) addr, l);
}
int is_local_endpoint(const struct intf_address *addr, unsigned int port) {
	GList *l;
	const struct local_intf *intf;
	const struct intf_spec *spec;

	l = g_hash_table_lookup(__local_intf_addr_type_hash, addr);
	if (!l)
		return 0;
	while (l) {
		intf = l->data;
		spec = intf->spec;
		if (spec->port_pool.min <= port && spec->port_pool.max >= port)
			return 1;
		l = l->next;
	}
	return 0;
}

/**
 * This function just (globally) reserves a port number, it doesn't provide any binding/unbinding.
 */
static void reserve_port(GQueue * free_ports_q, GHashTable * free_ports_ht,
		GList * value_looked_up, unsigned int port) {

		g_queue_delete_link(free_ports_q, value_looked_up);
		g_hash_table_remove(free_ports_ht, GUINT_TO_POINTER(port));
}
/**
 * This function just releases reserved port number, it doesn't provide any binding/unbinding.
 */
static void release_reserved_port(GQueue * free_ports_q, GHashTable * free_ports_ht,
		unsigned int port) {

		g_queue_push_tail(free_ports_q, GUINT_TO_POINTER(port));
		GList * l = free_ports_q->tail;
		g_hash_table_replace(free_ports_ht, GUINT_TO_POINTER(port), l);
}
/* Append a list of free ports within the min-max range */
static void __append_free_ports_to_int(struct intf_spec *spec) {
	unsigned int ports_amount, count;

	GQueue * free_ports_q = &spec->port_pool.free_ports_q;
	GHashTable ** free_ports_ht = &spec->port_pool.free_ports_ht;

	if (!*free_ports_ht)
		*free_ports_ht = g_hash_table_new(g_direct_hash, g_direct_equal);

	if (spec->port_pool.max < spec->port_pool.min) {
		ilog(LOG_WARNING, "Ports range: max value cannot be less than min");
		return;
	}

	/* range of possible ports */
	ports_amount = spec->port_pool.max - spec->port_pool.min + 1;
	count = ports_amount;

	if (ports_amount == 0) {
		ilog(LOG_WARNING, "Ports range: there must be at least 1 port in the range");
		return;
	}

	int port_values[ports_amount];

	/* create an array to store the initial values within the range */
	for (int i = 0; i < ports_amount; i++)
		port_values[i] = spec->port_pool.min + i;

	/* generate N random numbers within the given range without duplicates,
	 * using the rolling dice algorithm */
	for (int i = 0; i < ports_amount; i++)
	{
		int j = ssl_random() % count;
		int value = port_values[j];

		mutex_lock(&spec->port_pool.free_list_lock);
		g_queue_push_tail(free_ports_q, GUINT_TO_POINTER(value));
		/* store this new GList as value into the hash table */
		GList * l = free_ports_q->tail;
		/* The value retrieved from the hash table would then point
		 * into the queue for quick removal */
		g_hash_table_replace(*free_ports_ht, GUINT_TO_POINTER(value), l);
		mutex_unlock(&spec->port_pool.free_list_lock);

		port_values[j] = port_values[count - 1];
		count--;
	}
}
// called during single-threaded startup only
static void __add_intf_rr_1(struct logical_intf *lif, str *name_base, sockfamily_t *fam) {
	struct intf_key key = {0,};
	key.name = *name_base;
	key.preferred_family = fam;
	struct intf_rr *rr = t_hash_table_lookup(__logical_intf_name_family_rr_hash, &key);
	if (!rr) {
		rr = g_slice_alloc0(sizeof(*rr));
		rr->hash_key = key;
		mutex_init(&rr->lock);
		t_hash_table_insert(__logical_intf_name_family_rr_hash, &rr->hash_key, rr);
	}
	g_queue_push_tail(&rr->logical_intfs, lif);
	rr->singular = (rr->logical_intfs.length == 1) ? lif : NULL;
	g_hash_table_insert(lif->rr_specs, &rr->hash_key.name, lif);
}
static void __add_intf_rr(struct logical_intf *lif, str *name_base, sockfamily_t *fam) {
	__add_intf_rr_1(lif, name_base, fam);
	static str legacy_rr_str = STR_CONST("round-robin-calls");
	__add_intf_rr_1(lif, &legacy_rr_str, fam);
}
static GQueue *__interface_list_for_family(sockfamily_t *fam) {
	return &__preferred_lists_for_family[fam->idx];
}
// called during single-threaded startup only
static void __interface_append(struct intf_config *ifa, sockfamily_t *fam, bool create) {
	struct logical_intf *lif;
	GQueue *q;
	struct local_intf *ifc;
	struct intf_spec *spec;

	lif = __get_logical_interface(&ifa->name, fam);

	if (!lif) {
		if (!create) {
			// alias?
			if (!ifa->alias.len)
				return;

			struct logical_intf *alias = __get_logical_interface(&ifa->alias, fam);
			if (!alias)
				return;

			struct intf_key *key = g_new0(__typeof(*key), 1);
			key->name = ifa->name;
			key->preferred_family = fam;

			t_hash_table_insert(__logical_intf_name_family_hash, key, alias);

			return;
		}

		if (ifa->alias.len) // handled in second run
			return;

		lif = g_slice_alloc0(sizeof(*lif));
		g_queue_init(&lif->list);
		lif->name = ifa->name;
		lif->name_base = ifa->name_base;
		lif->preferred_family = fam;
		lif->rr_specs = g_hash_table_new((GHashFunc) str_hash, (GEqualFunc) str_equal);

		struct intf_key *key = g_new0(__typeof(*key), 1);
		key->name = ifa->name;
		key->preferred_family = fam;

		t_hash_table_insert(__logical_intf_name_family_hash, key, lif);
		if (ifa->local_address.addr.family == fam) {
			q = __interface_list_for_family(fam);
			g_queue_push_tail(q, lif);
			__add_intf_rr(lif, &ifa->name_base, fam);
		}
	}

	spec = g_hash_table_lookup(__intf_spec_addr_type_hash, &ifa->local_address);

	if (!spec) {
		spec = g_slice_alloc0(sizeof(*spec));
		spec->local_address = ifa->local_address;
		spec->port_pool.min = ifa->port_min;
		spec->port_pool.max = ifa->port_max;

		mutex_init(&spec->port_pool.free_list_lock);

		/* pre-fill the range of used ports */
		__append_free_ports_to_int(spec);

		g_hash_table_insert(__intf_spec_addr_type_hash, &spec->local_address, spec);
	}

	ifc = uid_slice_alloc0(ifc, &lif->list);
	ice_foundation(&ifc->ice_foundation);
	ifc->advertised_address = ifa->advertised_address;
	ifc->spec = spec;
	ifc->logical = lif;
	ifc->stats = bufferpool_alloc0(shm_bufferpool, sizeof(*ifc->stats));

	g_queue_push_tail(&all_local_interfaces, ifc);

	__insert_local_intf_addr_type(&spec->local_address, ifc);
	__insert_local_intf_addr_type(&ifc->advertised_address, ifc);
}

// called during single-threaded startup only
void interfaces_init(intf_config_q *interfaces) {
	int i;
	struct intf_config *ifa;
	sockfamily_t *fam;

	/* init everything */
	__logical_intf_name_family_hash = intf_lookup_new();
	__logical_intf_name_family_rr_hash = intf_rr_lookup_new();
	__intf_spec_addr_type_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);
	__local_intf_addr_type_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);

	for (i = 0; i < G_N_ELEMENTS(__preferred_lists_for_family); i++)
		g_queue_init(&__preferred_lists_for_family[i]);

	/* build primary lists first */
	for (__auto_type l = interfaces->head; l; l = l->next) {
		ifa = l->data;
		__interface_append(ifa, ifa->local_address.addr.family, true);
	}

	/* then append to each other as lower-preference alternatives */
	for (i = 0; i < __SF_LAST; i++) {
		fam = get_socket_family_enum(i);
		for (__auto_type l = interfaces->head; l; l = l->next) {
			ifa = l->data;
			if (ifa->local_address.addr.family == fam)
				continue;
			__interface_append(ifa, fam, false);
		}
	}

	local_media_socket_endpoints = local_sockets_ht_new();
}

void interfaces_exclude_port(unsigned int port) {
	GList *vals, *l, *ll;
	struct intf_spec *spec;

	struct port_pool *pp;
	GQueue * free_ports_q;
	GHashTable * free_ports_ht;

	vals = g_hash_table_get_values(__intf_spec_addr_type_hash);

	for (l = vals; l; l = l->next) {
		spec = l->data;

		pp = &spec->port_pool;
		free_ports_q = &pp->free_ports_q;
		free_ports_ht = pp->free_ports_ht;

		mutex_lock(&pp->free_list_lock);
		ll = g_hash_table_lookup(free_ports_ht, GUINT_TO_POINTER(port));
		if (ll)
			reserve_port(free_ports_q, free_ports_ht, ll, port);
		mutex_unlock(&pp->free_list_lock);
	}

	g_list_free(vals);
}

struct local_intf *get_interface_address(const struct logical_intf *lif, sockfamily_t *fam) {
	const GQueue *q;

	if (!fam)
		return NULL;
	q = &lif->list;
	if (!q->head)
		return NULL;
	return q->head->data;
}

/* safety fallback */
struct local_intf *get_any_interface_address(const struct logical_intf *lif, sockfamily_t *fam) {
	struct local_intf *ifa;

	ifa = get_interface_address(lif, fam);
	if (ifa)
		return ifa;
	ifa = get_interface_address(lif, get_socket_family_enum(SF_IP4));
	if (ifa)
		return ifa;
	return get_interface_address(lif, get_socket_family_enum(SF_IP6));
}

/**
 * Opens a socket for a given port value and edits the iptables accordingly.
 * It doesn't provide a port selection logic.
 */
static int add_socket(socket_t *r, unsigned int port, struct intf_spec *spec, const str *label) {
	__C_DBG("An attempt to open a socket for the port: '%u'", port);

	if (open_socket(r, SOCK_DGRAM, port, &spec->local_address.addr)) {
		__C_DBG("Can't open a socket for the port: '%d'", port);
		return -1;
	}
	iptables_add_rule(r, label);
	socket_timestamping(r);
	__C_DBG("A socket is successfully bound for the port: '%u'", port);
	return 0;
}
/**
 * Pushing ports into the `ports_to_release` queue.
 */
static void release_port_push(void *p) {
	struct late_port_release *lpr = p;
	__C_DBG("Adding the port '%u' to late-release list", lpr->socket.local.port);
	t_queue_push_tail(&ports_to_release, lpr);
}
static void release_port_poller(socket_t *r, struct intf_spec *spec, struct poller *poller) {
	if (!r->local.port || r->fd == -1)
		return;
	struct late_port_release *lpr = g_slice_alloc(sizeof(*lpr));
	move_socket(&lpr->socket, r);
	lpr->spec = spec;
	if (!poller)
		release_port_push(lpr);
	else {
		__C_DBG("Adding late-release callback for port '%u'", lpr->socket.local.port);
		rtpe_poller_del_item_callback(poller, lpr->socket.fd, release_port_push, lpr);
	}
}
static void release_port(socket_t *r, struct intf_spec *spec) {
	release_port_poller(r, spec, NULL);
}
static void free_port(socket_t *r, struct intf_spec *spec) {
	release_port(r, spec);
	g_slice_free1(sizeof(*r), r);
}
/**
 * Logic responsible for devastating the `ports_to_release` queue.
 * It's being called by main poller.
 */
static void release_port_now(socket_t *r, struct intf_spec *spec) {
	unsigned int port = r->local.port;
	struct port_pool *pp = &spec->port_pool;

	GQueue * free_ports_q = &pp->free_ports_q;
	GHashTable * free_ports_ht = pp->free_ports_ht;

	__C_DBG("Trying to release the port '%u'", port);

	if (close_socket(r) == 0) {
		__C_DBG("A socket for the '%u' has been closed", port);

		iptables_del_rule(r);

		/* first return the engaged port back */
		mutex_lock(&pp->free_list_lock);
		release_reserved_port(free_ports_q, free_ports_ht, port);
		mutex_unlock(&pp->free_list_lock);
	} else {
		ilog(LOG_WARNING, "Unable to close the socket for port '%u'", port);
	}
}
/**
 * Sockets releaser.
 */
enum thread_looper_action release_closed_sockets(void) {
	struct late_port_release * lpr;

	/* for the separate releaser thread (one working with `sockets_releaser()`)
	 * it does no job. But only for those threads related to calls processing.
	 */
	if (ports_to_release.head)
		append_thread_lpr_to_glob_lpr();

	if (ports_to_release_glob.head) {
		mutex_lock(&ports_to_release_glob_lock);
		ports_release_q ports_left = ports_to_release_glob;
		t_queue_init(&ports_to_release_glob);
		mutex_unlock(&ports_to_release_glob_lock);

		while ((lpr = t_queue_pop_head(&ports_left))) {
			release_port_now(&lpr->socket, lpr->spec);
			g_slice_free1(sizeof(*lpr), lpr);
		}
	}

	return TLA_CONTINUE;
}
/**
 * Appends thread scope (local) sockets to the global releasing list.
 */
void append_thread_lpr_to_glob_lpr(void) {
	mutex_lock(&ports_to_release_glob_lock);
	t_queue_move(&ports_to_release_glob, &ports_to_release); /* dst, src */
	mutex_unlock(&ports_to_release_glob_lock);
}

/**
 * Puts a list of `socket_t` objects into the `out`.
 *
 * @param num_ports, number of ports we have to engage (1 - rtcp-mux / 2 - one RTP and one RTCP)
 * @param wanted_start_port, a pre-defined port (if given), if not given must be 0
 * @param spec, interface specifications
 * @param out, a list of sockets for this particular session (not a global list)
 */
int __get_consecutive_ports(socket_q *out, unsigned int num_ports, unsigned int wanted_start_port,
		struct intf_spec *spec, const str *label)
{
	unsigned int allocation_attempts = 0, available_ports = 0, additional_port = 0, port = 0;
	socket_t * sk;
	GQueue ports_to_engage = G_QUEUE_INIT;		/* usually it's only one RTCP port, theoretically can be more */

	struct port_pool * pp = &spec->port_pool;	/* port pool for a given local interface */
	GQueue * free_ports_q;
	GHashTable * free_ports_ht;

	if (num_ports == 0) {
		ilog(LOG_ERR, "Number of ports to be engaged is '%d', can't handle it like that",
				num_ports);
		goto fail;
	}

	/* for the wanted port, only one port can be engaged */
	if (num_ports > 1 && wanted_start_port > 0) {
		ilog(LOG_ERR, "A specific port value is requested, but ports to be engaged > 1");
		goto fail;
	}

	free_ports_q = &pp->free_ports_q;
	free_ports_ht = pp->free_ports_ht;

	/* a presence of free lists data is critical for us */
	if (!(free_ports_q && free_ports_q->head) || !free_ports_ht) {
		ilog(LOG_ERR, "Failure while trying to get a list of free ports");
		goto fail;
	}

	/* specifically requested port */
	if (wanted_start_port > 0) {
		ilog(LOG_DEBUG, "A specific port value is requested, wanted_start_port: '%d'", wanted_start_port);
		mutex_lock(&pp->free_list_lock);
		GList *l = g_hash_table_lookup(free_ports_ht, GUINT_TO_POINTER(wanted_start_port));
		if (!l) {
			/* if engaged already, just select any other (so default logic) */
			ilog(LOG_WARN, "This requested port has been already engaged, can't take it.");
			wanted_start_port = 0; /* take what is proposed by FIFO instead */
		} else {
			/* we got the port, and we are sure it wasn't engaged */
			reserve_port(free_ports_q, free_ports_ht, l, wanted_start_port);
			port = wanted_start_port;
		}
		mutex_unlock(&pp->free_list_lock);
	}

	/* make sure we have ports to be used */
	mutex_lock(&pp->free_list_lock);
	available_ports = g_queue_get_length(free_ports_q);
	mutex_unlock(&pp->free_list_lock);

	if (!available_ports && wanted_start_port == 0) {
		ilog(LOG_ERR, "Empty ports queue, no more ports left to use");
		goto fail;
	}

	/* if there is only 1 port left, and it's not rtcp-mux, then
	 * it makes no sence to conitnue - ran out ports */
	if (num_ports > 1 && wanted_start_port == 0 && available_ports == 1) {
		ilog(LOG_ERR, "Ran out of ports, can't engage an additional port (for RTCP)");
		goto fail;
	}

	/* Here we try to bind a port to a socket being opened.
	 *
	 * cycling here unless:
	 * - for non rtcp-mux: we engage two sequential ports, where RTP port is even
	 *                and the socket for both ports can be opened (get_port())
	 * - for rtcp-mux: we get a socket opened for it (get_port())
	 * - theoretically more than 2 ports can be requested, but usually not a case.
	 */
	while (1)
	{
new_cycle:
		if (++allocation_attempts > available_ports) {
			ilog(LOG_ERR, "Failure while trying to bind a port to the socket");
			goto fail;
		}

		if (!wanted_start_port) {
			/* For cases with no rtcp-mux: RTP must be an even port,
			 * and RTCP port is always the next one to that.
			 */

			/* Now only get first possible port for RTP.
			 * Then additionally make sure that the RTCP port can also be engaged, if needed.
			 */
			mutex_lock(&pp->free_list_lock);
			port = GPOINTER_TO_UINT(g_queue_pop_head(free_ports_q)); /* RTP */

			if (!port) {
				mutex_unlock(&pp->free_list_lock);
				ilog(LOG_ERR, "Failure while trying to get a port from the list");
				goto fail;
			}
			g_hash_table_remove(free_ports_ht, GUINT_TO_POINTER(port)); /* RTP */
			mutex_unlock(&pp->free_list_lock);

			/* ports for RTP must be even, if there is an additional port for RTCP */
			if (num_ports > 1 && (port & 1)) {
				/* return port for RTP back and try again */
				mutex_lock(&pp->free_list_lock);
				release_reserved_port(free_ports_q, free_ports_ht, port);
				mutex_unlock(&pp->free_list_lock);
				goto new_cycle;
			}

			/* find additional ports, usually it's only RTCP */
			additional_port = port;
			for (int i = 1; i < num_ports; i++)
			{
				additional_port++;

				mutex_lock(&pp->free_list_lock);
				GList *l = g_hash_table_lookup(free_ports_ht, GUINT_TO_POINTER(additional_port));

				if (!l) {
					/* return port for RTP back and try again */
					release_reserved_port(free_ports_q, free_ports_ht, port);
					mutex_unlock(&pp->free_list_lock);

					/* check if we managed to enagage anything in previous for-cycles */
					while ((additional_port = GPOINTER_TO_UINT(g_queue_pop_head(&ports_to_engage))))
					{
						mutex_lock(&pp->free_list_lock);
						/* return additional ports back */
						release_reserved_port(free_ports_q, free_ports_ht, additional_port);
						mutex_unlock(&pp->free_list_lock);
					}
					goto new_cycle;

				} else {
					/* engage this port right away */
					reserve_port(free_ports_q, free_ports_ht, l, additional_port);
					mutex_unlock(&pp->free_list_lock);

					/* track for which additional ports, we have to open sockets */
					g_queue_push_tail(&ports_to_engage, GUINT_TO_POINTER(additional_port));
				}
			}
		}

		ilog(LOG_DEBUG, "Trying to bind the socket for RTP/RTCP ports (allocation attempt = '%d')",
				allocation_attempts);

		/* at this point we consider all things before as successfull. Now just add the RTP port */
		g_queue_push_head(&ports_to_engage, GUINT_TO_POINTER(port));

		while ((port = GPOINTER_TO_UINT(g_queue_pop_head(&ports_to_engage))))
		{
			ilog(LOG_DEBUG, "Trying to bind the socket for port = '%d'", port);
			sk = g_slice_alloc0(sizeof(*sk));
			sk->fd = -1;
			t_queue_push_tail(out, sk);

			/* if not possible to engage this socket, try to reallocate it again */
			if (add_socket(sk, port, spec, label)) {
				/* if something has been left in the `ports_to_engage` queue, release it right away */
				while ((port = GPOINTER_TO_UINT(g_queue_pop_head(&ports_to_engage))))
				{
					mutex_lock(&pp->free_list_lock);
					release_reserved_port(free_ports_q, free_ports_ht, port);
					mutex_unlock(&pp->free_list_lock);
				}
				/* ports which are already bound to a socket, will be freed by `free_port()` */
				goto release_restart;
			}
		}

		/* success */
		break;

release_restart:
		/* release all previously engaged sockets */
		while ((sk = t_queue_pop_head(out)))
			free_port(sk, spec); /* engaged ports will be released here */

		/* do not re-try for specifically wanted ports */
		if (wanted_start_port > 0)
			goto fail;

		ilog(LOG_DEBUG, "Something already keeps this port, trying to take another port(s)");
	}

	/* success */
	ilog(LOG_DEBUG, "Opened a socket on port '%u' (on interface '%s') for a media relay",
		((socket_t *) out->head->data)->local.port, sockaddr_print_buf(&spec->local_address.addr));
	return 0;

fail:
	ilog(LOG_ERR, "Failed to get %u consecutive ports on interface %s for media relay (last error: %s)",
			num_ports, sockaddr_print_buf(&spec->local_address.addr), strerror(errno));
	return -1;
}

/* puts a list of "struct intf_list" into "out", containing socket_t list */
int get_consecutive_ports(socket_intf_list_q *out, unsigned int num_ports, unsigned int num_intfs, struct call_media *media)
{
	GList *l;
	struct socket_intf_list *il;
	struct local_intf *loc;
	const struct logical_intf *log = media->logical_intf;
	const str *label = &media->call->callid; /* call's callid */

	/*
	// debug locals of logical incerface
	char ip[100];
	for (l = log->list.head; l; l = l->next) {
		loc = l->data;
		inet_ntop(loc->spec->local_address.addr.family->af, &loc->spec->local_address.addr.u, ip, sizeof(ip));
		ilog(LOG_DEBUG, "XXXXXXXXXX IP: %s", ip);
	}
	ilog(LOG_DEBUG, "");
	*/

	for (l = log->list.head; l; l = l->next) {
		if (out->length >= num_intfs)
			break;

		loc = l->data;

		il = g_slice_alloc0(sizeof(*il));
		il->local_intf = loc;
		t_queue_push_tail(out, il);
		if (G_LIKELY(!__get_consecutive_ports(&il->list, num_ports, 0, loc->spec, label))) {
			// success - found available ports on local interfaces, so far
			continue;
		} else {
			// fail - did not found available ports on at least one local interface
			goto error_ports;
		}
	}

	return 0;

error_ports:
	ilog(LOG_ERR, "Failed to get %d consecutive ports on all locals of logical '"STR_FORMAT"'",
		num_ports, STR_FMT(&log->name));

	// free all ports alloc'ed so far for the previous local interfaces
	while ((il = t_queue_pop_head(out))) {
		free_socket_intf_list(il);
	}

	return -1;

}
void free_socket_intf_list(struct socket_intf_list *il) {
	socket_t *sock;

	while ((sock = t_queue_pop_head(&il->list)))
		free_port(sock, il->local_intf->spec);
	g_slice_free1(sizeof(*il), il);
}
void free_sfd_intf_list(struct sfd_intf_list *il) {
	t_queue_clear(&il->list);
	g_slice_free1(sizeof(*il), il);
}
void free_release_sfd_intf_list(struct sfd_intf_list *il) {
	t_queue_clear_full(&il->list, stream_fd_release);
	g_slice_free1(sizeof(*il), il);
}



/* called lock-free */
static void stream_fd_closed(int fd, void *p) {
	stream_fd *sfd = p;
	call_t *c;
	int i;
	socklen_t j;

	c = sfd->call;
	if (!c)
		return;

	rwlock_lock_r(&c->master_lock);
	if (fd == sfd->socket.fd) {
		j = sizeof(i);
		i = 0;
		// coverity[check_return : FALSE]
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &i, &j);
		ilog(LOG_WARNING, "Read error on media socket: %i (%s) -- closing call", i, strerror(i));
	}
	rwlock_unlock_r(&c->master_lock);

	call_destroy(c);
}



/* returns: 0 = not a muxed stream, 1 = muxed, RTP, 2 = muxed, RTCP */
static int rtcp_demux(const str *s, struct call_media *media) {
	if (!MEDIA_ISSET(media, RTCP_MUX))
		return 0;
	return rtcp_demux_is_rtcp(s) ? 2 : 1;
}

static int call_avp2savp_rtp(str *s, struct packet_stream *stream, struct ssrc_ctx *ssrc_ctx)
{
	return rtp_avp2savp(s, &stream->crypto, ssrc_ctx);
}
static int call_avp2savp_rtcp(str *s, struct packet_stream *stream, struct ssrc_ctx *ssrc_ctx)
{
	return rtcp_avp2savp(s, &stream->crypto, ssrc_ctx);
}
static int call_savp2avp_rtp(str *s, struct packet_stream *stream, struct ssrc_ctx *ssrc_ctx)
{
	return rtp_savp2avp(s, &stream->selected_sfd->crypto, ssrc_ctx);
}
static int call_savp2avp_rtcp(str *s, struct packet_stream *stream, struct ssrc_ctx *ssrc_ctx)
{
	return rtcp_savp2avp(s, &stream->selected_sfd->crypto, ssrc_ctx);
}


static int __k_null(struct rtpengine_srtp *s, struct packet_stream *stream) {
	*s = __res_null;
	return 0;
}
static int __k_srtp_crypt(struct rtpengine_srtp *s, struct crypto_context *c,
		struct ssrc_ctx *ssrc_ctx[RTPE_NUM_SSRC_TRACKING])
{
	if (!c->params.crypto_suite)
		return -1;

	*s = (struct rtpengine_srtp) {
		.cipher		= c->params.crypto_suite->kernel_cipher,
		.hmac		= c->params.crypto_suite->kernel_hmac,
		.mki_len	= c->params.mki_len,
		.rtp_auth_tag_len= c->params.crypto_suite->srtp_auth_tag,
		.rtcp_auth_tag_len= c->params.crypto_suite->srtcp_auth_tag,
	};
	if (c->params.mki_len)
		memcpy(s->mki, c->params.mki, c->params.mki_len);
	memcpy(s->master_key, c->params.master_key, c->params.crypto_suite->master_key_len);
	s->master_key_len = c->params.crypto_suite->master_key_len;
	s->session_key_len = c->params.crypto_suite->session_key_len;
	memcpy(s->master_salt, c->params.master_salt, c->params.crypto_suite->master_salt_len);
	s->master_salt_len = c->params.crypto_suite->master_salt_len;
	s->session_salt_len = c->params.crypto_suite->session_salt_len;

	if (c->params.session_params.unencrypted_srtp)
		s->cipher = REC_NULL;
	if (c->params.session_params.unauthenticated_srtp)
		s->rtp_auth_tag_len = 0;

	return 0;
}
static int __k_srtp_encrypt(struct rtpengine_srtp *s, struct packet_stream *stream) {
	return __k_srtp_crypt(s, &stream->crypto, stream->ssrc_out);
}
static int __k_srtp_decrypt(struct rtpengine_srtp *s, struct packet_stream *stream) {
	return __k_srtp_crypt(s, &stream->selected_sfd->crypto, stream->ssrc_in);
}

INLINE void __re_address_translate_ep(struct re_address *o, const endpoint_t *ep) {
	ep->address.family->endpoint2kernel(o, ep);
}

static int __rtp_stats_pt_sort(const void *ap, const void *bp) {
	const struct rtp_stats *a = ap, *b = bp;

	if (a->payload_type < b->payload_type)
		return -1;
	if (a->payload_type > b->payload_type)
		return 1;
	return 0;
}


/**
 * The linkage between userspace and kernel module is in the kernelize_one().
 * 
 * Called with in_lock held.
 * sink_handler can be NULL.
 */
static const char *kernelize_one(struct rtpengine_target_info *reti, GQueue *outputs,
		struct packet_stream *stream, struct sink_handler *sink_handler, sink_handler_q *sinks,
		GList **payload_types)
{
	struct rtpengine_destination_info *redi = NULL;
	call_t *call = stream->call;
	struct call_media *media = stream->media;
	struct packet_stream *sink = sink_handler ? sink_handler->sink : NULL;
	bool non_forwarding = false;
	bool blackhole = false;

	if (sink_handler) {
		if (MEDIA_ISSET(sink->media, BLOCK_EGRESS))
			return NULL;
		sink_handler->kernel_output_idx = -1;
	}

	if (MEDIA_ISSET(media, BLACKHOLE))
		blackhole = true;
	else if (!sink_handler)
		blackhole = true;

	if (blackhole)
		non_forwarding = true;

	if (sink && !sink->endpoint.address.family)
		return NULL;

	if (sink && sink->selected_sfd)
		ilog(LOG_INFO, "Kernelizing media stream: %s%s%s -> %s | %s -> %s%s%s",
				FMT_M(endpoint_print_buf(&stream->endpoint)),
				endpoint_print_buf(&stream->selected_sfd->socket.local),
				endpoint_print_buf(&sink->selected_sfd->socket.local),
				FMT_M(endpoint_print_buf(&sink->endpoint)));
	else
		ilog(LOG_INFO, "Kernelizing media stream: %s%s%s -> %s -> void",
				FMT_M(endpoint_print_buf(&stream->endpoint)),
				endpoint_print_buf(&stream->selected_sfd->socket.local));

	const struct streamhandler *handler = __determine_handler(stream, sink_handler);

	if (!handler->in->kernel || !handler->out->kernel)
		return "protocol not supported by kernel module";

	// fill input if needed

	if (reti->local.family)
		goto output;

	if (PS_ISSET2(stream, STRICT_SOURCE, MEDIA_HANDOVER)) {
		mutex_lock(&stream->out_lock);
		__re_address_translate_ep(&reti->expected_src, MEDIA_ISSET(media, ASYMMETRIC) ? &stream->learned_endpoint : &stream->endpoint);
		mutex_unlock(&stream->out_lock);
		if (PS_ISSET(stream, STRICT_SOURCE))
			reti->src_mismatch = MSM_DROP;
		else if (PS_ISSET(stream, MEDIA_HANDOVER))
			reti->src_mismatch = MSM_PROPAGATE;
	}

	__re_address_translate_ep(&reti->local, &stream->selected_sfd->socket.local);
	reti->iface_stats = stream->selected_sfd->local_intf->stats;
	reti->stats = stream->stats_in;
	reti->rtcp_mux = MEDIA_ISSET(media, RTCP_MUX);
	reti->rtcp = PS_ISSET(stream, RTCP);
	reti->dtls = MEDIA_ISSET(media, DTLS);
	reti->stun = media->ice_agent ? 1 : 0;
	reti->non_forwarding = non_forwarding ? 1 : 0;
	reti->blackhole = blackhole ? 1 : 0;
	reti->rtp_stats = (rtpe_config.measure_rtp
			|| MEDIA_ISSET(media, RTCP_GEN) || (mqtt_publish_scope() != MPS_NONE)) ? 1 : 0;

	handler->in->kernel(&reti->decrypt, stream);
	if (!reti->decrypt.cipher || !reti->decrypt.hmac)
		return "decryption cipher or HMAC not supported by kernel module";

	reti->track_ssrc = 1;
	for (unsigned int u = 0; u < G_N_ELEMENTS(stream->ssrc_in); u++) {
		if (stream->ssrc_in[u]) {
			reti->ssrc[u] = htonl(stream->ssrc_in[u]->parent->h.ssrc);
			reti->ssrc_stats[u] = stream->ssrc_in[u]->stats;
		}
	}

	if (proto_is_rtp(media->protocol)) {
		reti->rtp = 1;
		reti->ssrc_req = 1;
		if (!MEDIA_ISSET(media, TRANSCODING)) {
			reti->rtcp_fw = 1;
			if (media->protocol->avpf)
				reti->rtcp_fb_fw = 1;
		}
	}

	if (reti->rtp && sinks && sinks->length && payload_types) {
		GList *l;
		struct rtp_stats *rs;

		// this code is execute only once: list therefore must be empty
		assert(*payload_types == NULL);
		*payload_types = g_hash_table_get_values(stream->rtp_stats);
		*payload_types = g_list_sort(*payload_types, __rtp_stats_pt_sort);
		for (l = *payload_types; l; ) {
			if (reti->num_payload_types >= G_N_ELEMENTS(reti->pt_stats)) {
				ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Too many RTP payload types for kernel module");
				break;
			}
			rs = l->data;
			// only add payload types that are passthrough for all sinks
			bool can_kernelize = true;
			for (__auto_type k = sinks->head; k; k = k->next) {
				struct sink_handler *ksh = k->data;
				struct packet_stream *ksink = ksh->sink;
				struct codec_handler *ch = codec_handler_get(media, rs->payload_type,
						ksink->media, ksh);
				if (ch->kernelize)
					continue;
				can_kernelize = false;
				break;
			}
			if (!can_kernelize) {
				reti->pt_filter = 1;
				// ensure that the final list in *payload_types reflects the payload
				// types populated in reti->payload_types
				GList *next = l->next;
				*payload_types = g_list_delete_link(*payload_types, l);
				l = next;
				continue;
			}

			reti->pt_stats[reti->num_payload_types] = rs;
			reti->num_payload_types++;

			l = l->next;
		}
	}
	else {
		if (sink_handler && sink_handler->attrs.transcoding)
			return NULL;
	}

	recording_stream_kernel_info(stream, reti);

output:
	// output section: any output at all?
	if (non_forwarding || !sink || !sink->selected_sfd)
		return NULL; // no output
	if (!PS_ISSET(sink, FILLED))
		return NULL;

	// fill output struct
	redi = g_slice_alloc0(sizeof(*redi));
	redi->local = reti->local;
	redi->output.tos = call->tos;

	// PT manipulations
	bool silenced = CALL_ISSET(call, SILENCE_MEDIA) || ML_ISSET(media->monologue, SILENCE_MEDIA)
			|| sink_handler->attrs.silence_media;
	bool manipulate_pt = silenced || ML_ISSET(media->monologue, BLOCK_SHORT);
	if (manipulate_pt && payload_types) {
		int i = 0;
		for (GList *l = *payload_types; l; l = l->next) {
			struct rtp_stats *rs = l->data;
			struct rtpengine_pt_output *rpt = &redi->output.pt_output[i++];
			struct codec_handler *ch = codec_handler_get(media, rs->payload_type,
					sink->media, sink_handler);

			str replace_pattern = STR_NULL;
			if (silenced && ch->source_pt.codec_def)
				replace_pattern = ch->source_pt.codec_def->silence_pattern;
			if (replace_pattern.len > sizeof(rpt->replace_pattern))
				ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Payload replacement pattern too long (%zu)",
						replace_pattern.len);
			else {
				rpt->replace_pattern_len = replace_pattern.len;
				memcpy(rpt->replace_pattern, replace_pattern.s, replace_pattern.len);
			}

			if (ML_ISSET(media->monologue, BLOCK_SHORT) && ch->payload_len)
				rpt->min_payload_len = ch->payload_len;
		}

	}

	if (MEDIA_ISSET(media, ECHO))
		redi->output.ssrc_subst = 1;

	if (sink_handler->attrs.transcoding) {
		redi->output.ssrc_subst = 1;
		reti->pt_filter = 1;
	}

	mutex_lock(&sink->out_lock);

	__re_address_translate_ep(&redi->output.dst_addr, &sink->endpoint);
	__re_address_translate_ep(&redi->output.src_addr, &sink->selected_sfd->socket.local);
	redi->output.iface_stats = sink->selected_sfd->local_intf->stats;
	redi->output.stats = sink->stats_out;

	if (reti->track_ssrc) {
		for (unsigned int u = 0; u < G_N_ELEMENTS(stream->ssrc_in); u++) {
			if (sink->ssrc_out[u]) {
				// XXX order can be different from ingress?
				redi->output.seq_offset[u] = sink->ssrc_out[u]->parent->seq_diff;
				redi->output.ssrc_stats[u] = sink->ssrc_out[u]->stats;
			}

			if (redi->output.ssrc_subst && stream->ssrc_in[u])
				redi->output.ssrc_out[u] = htonl(stream->ssrc_in[u]->ssrc_map_out);
		}
	}

	handler->out->kernel(&redi->output.encrypt, sink);

	mutex_unlock(&sink->out_lock);

	if (!redi->output.encrypt.cipher || !redi->output.encrypt.hmac) {
		g_slice_free1(sizeof(*redi), redi);
		return "encryption cipher or HMAC not supported by kernel module";
	}

	// got a new output
	redi->num = reti->num_destinations;
	reti->num_destinations++;
	sink_handler->kernel_output_idx = redi->num;
	g_queue_push_tail(outputs, redi);
	assert(outputs->length == reti->num_destinations);

	return NULL;
}
// helper function for kernelize()
static void kernelize_one_sink_handler(struct rtpengine_target_info *reti, GQueue *outputs,
		struct packet_stream *stream, struct sink_handler *sink_handler, sink_handler_q *sinks,
		GList **payload_types)
{
	struct packet_stream *sink = sink_handler->sink;
	if (PS_ISSET(sink, NAT_WAIT) && !PS_ISSET(sink, RECEIVED))
		return;
	const char *err = kernelize_one(reti, outputs, stream, sink_handler, &stream->rtp_sinks,
			payload_types);
	if (err)
		ilog(LOG_WARNING, "No support for kernel packet forwarding available (%s)", err);
}
/* called with in_lock held */
void kernelize(struct packet_stream *stream) {
	call_t *call = stream->call;
	const char *nk_warn_msg;
	struct call_media *media = stream->media;

	if (PS_ISSET(stream, KERNELIZED))
		return;

	if (call->recording != NULL && !selected_recording_method->kernel_support)
		goto no_kernel;
	if (!kernel.is_wanted)
		goto no_kernel;
	nk_warn_msg = "interface to kernel module not open";
	if (!kernel.is_open)
		goto no_kernel_warn;
	if (MEDIA_ISSET(media, GENERATOR))
		goto no_kernel;
	if (!stream->selected_sfd)
		goto no_kernel;
	if (ML_ISSET(media->monologue, BLOCK_MEDIA) || CALL_ISSET(call, BLOCK_MEDIA))
		goto no_kernel;
	if (!stream->endpoint.address.family)
		goto no_kernel;

	struct rtpengine_target_info reti;
	ZERO(reti); // reti.local.family determines if anything can be done
	GQueue outputs = G_QUEUE_INIT;
	GList *payload_types = NULL;

	unsigned int num_sinks = stream->rtp_sinks.length + stream->rtcp_sinks.length;

	if (num_sinks == 0) {
		// add blackhole kernel rule
		const char *err = kernelize_one(&reti, &outputs, stream, NULL, NULL, &payload_types);
		if (err)
			ilog(LOG_WARNING, "No support for kernel packet forwarding available (%s)", err);
	}
	else {
		for (__auto_type l = stream->rtp_sinks.head; l; l = l->next) {
			struct sink_handler *sh = l->data;
			if (sh->attrs.block_media)
				continue;
			kernelize_one_sink_handler(&reti, &outputs, stream, sh, &stream->rtp_sinks,
					&payload_types);
		}
		for (__auto_type l = stream->rtp_mirrors.head; l; l = l->next) {
			struct sink_handler *sh = l->data;
			kernelize_one_sink_handler(&reti, &outputs, stream, sh, &stream->rtp_sinks,
					&payload_types);
		}
		// record number of RTP destinations
		unsigned int num_rtp_dests = reti.num_destinations;
		for (__auto_type l = stream->rtcp_sinks.head; l; l = l->next) {
			struct sink_handler *sh = l->data;
			kernelize_one_sink_handler(&reti, &outputs, stream, sh, &stream->rtp_sinks, NULL);
		}
		reti.num_rtcp_destinations = reti.num_destinations - num_rtp_dests;
	}

	g_list_free(payload_types);

	if (!reti.local.family)
		goto no_kernel;

	if (!outputs.length && !reti.non_forwarding) {
		reti.non_forwarding = 1;
		ilog(LOG_NOTICE | LOG_FLAG_LIMIT, "Setting 'non-forwarding' flag for kernel stream due to "
				"lack of sinks");
	}

	kernel_add_stream(&reti);
	struct rtpengine_destination_info *redi;
	while ((redi = g_queue_pop_head(&outputs))) {
		kernel_add_destination(redi);
		g_slice_free1(sizeof(*redi), redi);
	}

	stream->kernel_time = rtpe_now.tv_sec;
	PS_SET(stream, KERNELIZED);
	return;

no_kernel_warn:
	ilog(LOG_WARNING, "No support for kernel packet forwarding available (%s)", nk_warn_msg);
no_kernel:
	PS_SET(stream, KERNELIZED);
	stream->kernel_time = rtpe_now.tv_sec;
	PS_SET(stream, NO_KERNEL_SUPPORT);
}

// must be called with appropriate locks (master lock and/or in/out_lock)
int __hunt_ssrc_ctx_idx(uint32_t ssrc, struct ssrc_ctx *list[RTPE_NUM_SSRC_TRACKING],
		unsigned int start_idx)
{
	for (unsigned int v = 0; v < RTPE_NUM_SSRC_TRACKING; v++) {
		// starting point is the same offset as `u`
		unsigned int idx = (start_idx + v) % RTPE_NUM_SSRC_TRACKING;
		if (!list[idx])
			continue;
		if (list[idx]->parent->h.ssrc != ssrc)
			continue;
		return idx;
	}
	return -1;
}
// must be called with appropriate locks (master lock and/or in/out_lock)
struct ssrc_ctx *__hunt_ssrc_ctx(uint32_t ssrc, struct ssrc_ctx *list[RTPE_NUM_SSRC_TRACKING],
		unsigned int start_idx)
{
	int idx = __hunt_ssrc_ctx_idx(ssrc, list, start_idx);
	if (idx == -1)
		return NULL;
	return list[idx];
}


/* must be called with in_lock held or call->master_lock held in W */
void __unkernelize(struct packet_stream *p, const char *reason) {
	if (!p->selected_sfd)
		return;

	if (!PS_ISSET(p, KERNELIZED))
		return;

	if (kernel.is_open && !PS_ISSET(p, NO_KERNEL_SUPPORT)) {
		ilog(LOG_INFO, "Removing media stream from kernel: local %s (%s)",
				endpoint_print_buf(&p->selected_sfd->socket.local),
				reason);
		struct rtpengine_command_del_target cmd = {0};
		__re_address_translate_ep(&cmd.local, &p->selected_sfd->socket.local);
		kernel_del_stream(&cmd);
	}

	PS_CLEAR(p, KERNELIZED);
	PS_CLEAR(p, NO_KERNEL_SUPPORT);
}


void __reset_sink_handlers(struct packet_stream *ps) {
	for (__auto_type l = ps->rtp_sinks.head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		sh->handler = NULL;
	}
	for (__auto_type l = ps->rtcp_sinks.head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		sh->handler = NULL;
	}
}
void __stream_unconfirm(struct packet_stream *ps, const char *reason) {
	__unkernelize(ps, reason);
	if (!MEDIA_ISSET(ps->media, ASYMMETRIC)) {
		if (ps->selected_sfd)
			ilog(LOG_DEBUG | LOG_FLAG_LIMIT, "Unconfirming peer address for local %s (%s)",
					endpoint_print_buf(&ps->selected_sfd->socket.local),
					reason);
		PS_CLEAR(ps, CONFIRMED);
	}
	__reset_sink_handlers(ps);
}
static void stream_unconfirm(struct packet_stream *ps, const char *reason) {
	if (!ps)
		return;
	mutex_lock(&ps->in_lock);
	__stream_unconfirm(ps, reason);
	mutex_unlock(&ps->in_lock);
}
static void unconfirm_sinks(sink_handler_q *q, const char *reason) {
	for (__auto_type l = q->head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		stream_unconfirm(sh->sink, reason);
	}
}
void unkernelize(struct packet_stream *ps, const char *reason) {
	if (!ps)
		return;
	mutex_lock(&ps->in_lock);
	__unkernelize(ps, reason);
	mutex_unlock(&ps->in_lock);
}


// `out_media` can be NULL
const struct streamhandler *determine_handler(const struct transport_protocol *in_proto,
		struct call_media *out_media, bool must_recrypt)
{
	const struct transport_protocol *out_proto = out_media ? out_media->protocol : NULL;
	const struct streamhandler * const *sh_pp, *sh;
	const struct streamhandler * const * const *matrix;

	matrix = __sh_matrix;
	if (must_recrypt)
		matrix = __sh_matrix_recrypt;

	sh_pp = matrix[in_proto->index];
	if (!sh_pp)
		goto err;

	// special handling for RTP/AVP with advertised a=rtcp-fb
	int out_proto_idx = out_proto ? out_proto->index : in_proto->index;
	if (out_media && MEDIA_ISSET(out_media, RTCP_FB) && out_proto) {
		if (!out_proto->avpf && out_proto->avpf_proto)
			out_proto_idx = out_proto->avpf_proto;
	}
	sh = sh_pp[out_proto_idx];

	if (!sh)
		goto err;
	return sh;

err:
	ilog(LOG_WARNING, "Unknown transport protocol encountered");
	return &__sh_noop;
}

/* must be called with call->master_lock held in R, and in->in_lock held */
// `sh` can be null
static const struct streamhandler *__determine_handler(struct packet_stream *in, struct sink_handler *sh) {
	const struct transport_protocol *in_proto, *out_proto;
	bool must_recrypt = false;
	struct packet_stream *out = sh ? sh->sink : NULL;
	const struct streamhandler *ret = NULL;

	if (sh && sh->handler)
		return sh->handler;
	if (MEDIA_ISSET(in->media, PASSTHRU))
		goto noop;

	in_proto = in->media->protocol;
	out_proto = out ? out->media->protocol : NULL;

	if (!in_proto)
		goto err;

	if (!sh)
		must_recrypt = true;
	else if (dtmf_do_logging(in->call, false))
		must_recrypt = true;
	else if (MEDIA_ISSET(in->media, DTLS) || (out && MEDIA_ISSET(out->media, DTLS)))
		must_recrypt = true;
	else if (ML_ISSET(in->media->monologue, INJECT_DTMF) || (out && ML_ISSET(out->media->monologue, INJECT_DTMF)))
		must_recrypt = true;
	else if (sh->attrs.transcoding)
		must_recrypt = true;
	else if (in->call->recording)
		must_recrypt = true;
	else if (in->rtp_sinks.length > 1 || in->rtcp_sinks.length > 1) // need a proper decrypter?
		must_recrypt = true;
	else if (in_proto->srtp && out_proto && out_proto->srtp
			&& in->selected_sfd && out && out->selected_sfd
			&& (crypto_params_cmp(&in->crypto.params, &out->selected_sfd->crypto.params)
				|| crypto_params_cmp(&out->crypto.params, &in->selected_sfd->crypto.params)))
		must_recrypt = true;

	ret = determine_handler(in_proto, out ? out->media : NULL, must_recrypt);
	if (sh)
		sh->handler = ret;
	return ret;

err:
	ilog(LOG_WARNING, "Unknown transport protocol encountered");
noop:
	ret = &__sh_noop;
	if (sh)
		sh->handler = ret;
	return ret;
}


// returns non-null with reason string if stream should be removed from kernel
static const char *__stream_ssrc_inout(struct packet_stream *ps, uint32_t ssrc, mutex_t *lock,
		struct ssrc_ctx *list[RTPE_NUM_SSRC_TRACKING], unsigned int *ctx_idx_p,
		uint32_t output_ssrc,
		struct ssrc_ctx **output, struct ssrc_hash *ssrc_hash, enum ssrc_dir dir, const char *label)
{
	const char *ret = NULL;

	mutex_lock(lock);

	int ctx_idx = __hunt_ssrc_ctx_idx(ssrc, list, 0);
	if (ctx_idx == -1) {
		// SSRC mismatch - get the new entry:
		ctx_idx = *ctx_idx_p;
		// move to next slot
		*ctx_idx_p = (*ctx_idx_p + 1) % RTPE_NUM_SSRC_TRACKING;
		// eject old entry if present
		if (list[ctx_idx])
			ssrc_ctx_put(&list[ctx_idx]);
		// get new entry
		list[ctx_idx] =
			get_ssrc_ctx(ssrc, ssrc_hash, dir, ps->media->monologue);

		ret = "SSRC changed";
		ilog(LOG_DEBUG, "New %s SSRC for: %s%s:%d SSRC: %x%s", label,
                        FMT_M(sockaddr_print_buf(&ps->endpoint.address), ps->endpoint.port, ssrc));
	}
	if (ctx_idx != 0) {
		// move most recent entry to front of the list
		struct ssrc_ctx *tmp = list[0];
		list[0] = list[ctx_idx];
		list[ctx_idx] = tmp;
		ctx_idx = 0;
	}

	// extract and hold entry
	if (*output)
		ssrc_ctx_put(output);
	*output = list[ctx_idx];
	ssrc_ctx_hold(*output);

	// reverse SSRC mapping
	if (!output_ssrc)
		(*output)->ssrc_map_out = ssrc;
	else
		(*output)->ssrc_map_out = output_ssrc;

	mutex_unlock(lock);
	return ret;
}
// check and update input SSRC pointers
// returns non-null with reason string if stream should be removed from kernel
static const char *__stream_ssrc_in(struct packet_stream *in_srtp, uint32_t ssrc_bs,
		struct ssrc_ctx **ssrc_in_p, struct ssrc_hash *ssrc_hash)
{
	return __stream_ssrc_inout(in_srtp, ntohl(ssrc_bs), &in_srtp->in_lock, in_srtp->ssrc_in,
			&in_srtp->ssrc_in_idx, 0, ssrc_in_p, ssrc_hash, SSRC_DIR_INPUT, "ingress");
}
// check and update output SSRC pointers
// returns non-null with reason string if stream should be removed from kernel
static const char *__stream_ssrc_out(struct packet_stream *out_srtp, uint32_t ssrc_bs,
		struct ssrc_ctx *ssrc_in, struct ssrc_ctx **ssrc_out_p, struct ssrc_hash *ssrc_hash,
		bool ssrc_change)
{
	if (ssrc_change)
		return __stream_ssrc_inout(out_srtp, ssrc_in->ssrc_map_out, &out_srtp->out_lock,
				out_srtp->ssrc_out,
				&out_srtp->ssrc_out_idx, ntohl(ssrc_bs), ssrc_out_p, ssrc_hash, SSRC_DIR_OUTPUT,
				"egress (mapped)");

	return __stream_ssrc_inout(out_srtp, ntohl(ssrc_bs), &out_srtp->out_lock,
			out_srtp->ssrc_out,
			&out_srtp->ssrc_out_idx, 0, ssrc_out_p, ssrc_hash, SSRC_DIR_OUTPUT,
			"egress (direct)");
}


// returns: 0 = packet processed by other protocol handler;
// -1 = packet not handled, proceed;
// 1 = same as 0, but stream can be kernelized
static int media_demux_protocols(struct packet_handler_ctx *phc) {
	if (MEDIA_ISSET(phc->mp.media, DTLS) && is_dtls(&phc->s)) {
		// verify DTLS packet against ICE checks if present
		if (MEDIA_ISSET(phc->mp.media, ICE) && phc->mp.media->ice_agent) {
			if (!ice_peer_address_known(phc->mp.media->ice_agent, &phc->mp.fsin, phc->mp.stream,
						phc->mp.sfd->local_intf))
			{
				ilog(LOG_DEBUG, "Ignoring DTLS packet from %s%s%s to %s as no matching valid "
					"ICE candidate pair exists",
						FMT_M(endpoint_print_buf(&phc->mp.fsin)),
						endpoint_print_buf(&phc->mp.sfd->socket.local));
				return 0;
			}
		}

		mutex_lock(&phc->mp.stream->in_lock);
		int ret = dtls(phc->mp.sfd, &phc->s, &phc->mp.fsin);
		if (ret == 1) {
			phc->unkernelize = "DTLS connected";
			phc->unkernelize_subscriptions = true;
			ret = 0;
		}
		mutex_unlock(&phc->mp.stream->in_lock);
		if (!ret)
			return 0;
	}

	if (phc->mp.media->ice_agent && is_stun(&phc->s)) {
		int stun_ret = stun(&phc->s, phc->mp.sfd, &phc->mp.fsin);
		if (!stun_ret)
			return 0;
		if (stun_ret == 1) {
			call_media_state_machine(phc->mp.media);
			return 1;
		}
		else {
			/* not an stun packet */
		}
	}
	return -1;
}



#if RTP_LOOP_PROTECT
// returns: 0 = ok, proceed; -1 = duplicate detected, drop packet
static int media_loop_detect(struct packet_handler_ctx *phc) {
	mutex_lock(&phc->mp.stream->in_lock);

	for (int i = 0; i < RTP_LOOP_PACKETS; i++) {
		if (phc->mp.stream->lp_buf[i].len != phc->s.len)
			continue;
		if (memcmp(phc->mp.stream->lp_buf[i].buf, phc->s.s, MIN(phc->s.len, RTP_LOOP_PROTECT)))
			continue;

		__C_DBG("packet dupe");
		if (phc->mp.stream->lp_count >= RTP_LOOP_MAX_COUNT) {
			ilog(LOG_WARNING, "More than %d duplicate packets detected, dropping packet from %s%s%s"
					"to avoid potential loop",
					RTP_LOOP_MAX_COUNT,
					FMT_M(endpoint_print_buf(&phc->mp.fsin)));
			mutex_unlock(&phc->mp.stream->in_lock);
			return -1;
		}

		phc->mp.stream->lp_count++;
		goto loop_ok;
	}

	/* not a dupe */
	phc->mp.stream->lp_count = 0;
	phc->mp.stream->lp_buf[phc->mp.stream->lp_idx].len = phc->s.len;
	memcpy(phc->mp.stream->lp_buf[phc->mp.stream->lp_idx].buf, phc->s.s, MIN(phc->s.len, RTP_LOOP_PROTECT));
	phc->mp.stream->lp_idx = (phc->mp.stream->lp_idx + 1) % RTP_LOOP_PACKETS;
loop_ok:
	mutex_unlock(&phc->mp.stream->in_lock);

	return 0;
}
#endif



// in_srtp is set to point to the SRTP context to use
// sinks is set to where to forward the packet to
static void media_packet_rtcp_demux(struct packet_handler_ctx *phc)
{
	phc->in_srtp = phc->mp.stream;
	phc->sinks = &phc->mp.stream->rtp_sinks;
	// is this RTCP?
	if (PS_ISSET(phc->mp.stream, RTCP)) {
		int is_rtcp = 1;
		// plain RTCP or are we muxing?
		if (MEDIA_ISSET(phc->mp.media, RTCP_MUX)) {
			is_rtcp = 0;
			int muxed_rtcp = rtcp_demux(&phc->s, phc->mp.media);
			if (muxed_rtcp == 2) {
				is_rtcp = 1;
				if (phc->mp.stream->rtcp_sibling)
					phc->in_srtp = phc->mp.stream->rtcp_sibling; // use RTCP SRTP context
			}
		}
		if (is_rtcp) {
			phc->sinks = &phc->mp.stream->rtcp_sinks;
			phc->rtcp = true;
		}
	}
}
// out_srtp is set to point to the SRTP context to use
static void media_packet_rtcp_mux(struct packet_handler_ctx *phc, struct sink_handler *sh)
{
	phc->out_srtp = sh->sink;
	if (phc->rtcp && sh->sink->rtcp_sibling)
		phc->out_srtp = sh->sink->rtcp_sibling; // use RTCP SRTP context

	phc->mp.media_out = sh->sink->media;
	phc->mp.sink = *sh;
}


static void media_packet_rtp_in(struct packet_handler_ctx *phc)
{
	phc->payload_type = -1;

	if (G_UNLIKELY(!phc->mp.media))
		return;
	if (G_UNLIKELY(!proto_is_rtp(phc->mp.media->protocol)))
		return;

	const char *unkern = NULL;

	if (G_LIKELY(!phc->rtcp && !rtp_payload(&phc->mp.rtp, &phc->mp.payload, &phc->s))) {
		unkern = __stream_ssrc_in(phc->in_srtp, phc->mp.rtp->ssrc, &phc->mp.ssrc_in,
				phc->mp.media->monologue->ssrc_hash);

		// check the payload type
		// XXX redundant between SSRC handling and codec_handler stuff -> combine
		phc->payload_type = (phc->mp.rtp->m_pt & 0x7f);
		if (G_LIKELY(phc->mp.ssrc_in))
			payload_tracker_add(&phc->mp.ssrc_in->tracker, phc->payload_type);

		// XXX yet another hash table per payload type -> combine
		struct rtp_stats *rtp_s = g_atomic_pointer_get(&phc->mp.stream->rtp_stats_cache);
		if (G_UNLIKELY(!rtp_s) || G_UNLIKELY(rtp_s->payload_type != phc->payload_type))
			rtp_s = g_hash_table_lookup(phc->mp.stream->rtp_stats,
					GUINT_TO_POINTER(phc->payload_type));
		if (!rtp_s) {
			ilog(LOG_WARNING | LOG_FLAG_LIMIT,
					"RTP packet with unknown payload type %u received from %s%s%s",
					phc->payload_type,
					FMT_M(endpoint_print_buf(&phc->mp.fsin)));
			atomic64_inc_na(&phc->mp.stream->stats_in->errors);
			atomic64_inc_na(&phc->mp.sfd->local_intf->stats->in.errors);
			RTPE_STATS_INC(errors_user);
		}
		else {
			atomic64_inc(&rtp_s->packets);
			atomic64_add(&rtp_s->bytes, phc->s.len);
			g_atomic_pointer_set(&phc->mp.stream->rtp_stats_cache, rtp_s);
		}
	}
	else if (phc->rtcp && !rtcp_payload(&phc->mp.rtcp, NULL, &phc->s)) {
		unkern = __stream_ssrc_in(phc->in_srtp, phc->mp.rtcp->ssrc, &phc->mp.ssrc_in,
				phc->mp.media->monologue->ssrc_hash);
	}

	if (unkern)
		phc->unkernelize = unkern;
}
static void media_packet_rtp_out(struct packet_handler_ctx *phc, struct sink_handler *sh)
{
	if (G_UNLIKELY(!proto_is_rtp(phc->mp.media->protocol)))
		return;

	const char *unkern = NULL;

	if (G_LIKELY(!phc->rtcp && phc->mp.rtp)) {
		unkern = __stream_ssrc_out(phc->out_srtp, phc->mp.rtp->ssrc, phc->mp.ssrc_in,
				&phc->mp.ssrc_out, phc->mp.media_out->monologue->ssrc_hash,
				sh->attrs.transcoding ? true : false);
	}
	else if (phc->rtcp && phc->mp.rtcp) {
		unkern = __stream_ssrc_out(phc->out_srtp, phc->mp.rtcp->ssrc, phc->mp.ssrc_in,
				&phc->mp.ssrc_out, phc->mp.media_out->monologue->ssrc_hash,
				sh->attrs.transcoding ? true : false);
	}

	if (unkern)
		phc->unkernelize = unkern;
}


static int media_packet_decrypt(struct packet_handler_ctx *phc)
{
	mutex_lock(&phc->in_srtp->in_lock);
	struct sink_handler *first_sh = phc->sinks->length ? phc->sinks->head->data : NULL;
	const struct streamhandler *sh = __determine_handler(phc->in_srtp, first_sh);

	// XXX use an array with index instead of if/else
	if (G_LIKELY(!phc->rtcp))
		phc->decrypt_func = sh->in->rtp_crypt;
	else
		phc->decrypt_func = sh->in->rtcp_crypt;

	/* return values are: 0 = forward packet, -1 = error/don't forward,
	 * 1 = forward and push update to redis */
	int ret = 0;
	if (phc->decrypt_func) {
		str ori_s = phc->s;
		ret = phc->decrypt_func(&phc->s, phc->in_srtp, phc->mp.ssrc_in);
		// XXX for stripped auth tag and duplicate invocations of rtp_payload
		// XXX transcoder uses phc->mp.payload
		phc->mp.payload.len -= ori_s.len - phc->s.len;
	}

	mutex_unlock(&phc->in_srtp->in_lock);

	if (ret == 1) {
		phc->update = true;
		ret = 0;
	}
	return ret;
}
static void media_packet_set_encrypt(struct packet_handler_ctx *phc, struct sink_handler *sh)
{
	mutex_lock(&phc->in_srtp->in_lock);
	__determine_handler(phc->in_srtp, sh);

	// XXX use an array with index instead of if/else
	if (G_LIKELY(!phc->rtcp))
		phc->encrypt_func = sh->handler->out->rtp_crypt;
	else {
		phc->encrypt_func = sh->handler->out->rtcp_crypt;
		phc->rtcp_filter = sh->handler->in->rtcp_filter;
	}
	mutex_unlock(&phc->in_srtp->in_lock);
}

int media_packet_encrypt(rewrite_func encrypt_func, struct packet_stream *out, struct media_packet *mp) {
	int ret = 0x00; // 0x01 = error, 0x02 = update

	if (!encrypt_func)
		return 0x00;

	mutex_lock(&out->out_lock);

	for (__auto_type l = mp->packets_out.head; l; l = l->next) {
		struct codec_packet *p = l->data;
		if (mp->call->recording && rtpe_config.rec_egress) {
			p->plain = STR_LEN(bufferpool_alloc(media_bufferpool, p->s.len), p->s.len);
			memcpy(p->plain.s, p->s.s, p->s.len);
			p->plain_free_func = bufferpool_unref;
		}
		int encret = encrypt_func(&p->s, out, mp->ssrc_out);
		if (encret == 1)
			ret |= 0x02;
		else if (encret != 0)
			ret |= 0x01;
	}

	mutex_unlock(&out->out_lock);

	return ret;
}

// return: -1 = error, 0 = ok
static int __media_packet_encrypt(struct packet_handler_ctx *phc, struct sink_handler *sh) {
	int ret = media_packet_encrypt(phc->encrypt_func, phc->out_srtp, &phc->mp);
	if (ret & 0x02)
		phc->update = true;
	return (ret & 0x01) ? -1 : 0;
}



// returns: drop packet true/false
static bool media_packet_address_check(struct packet_handler_ctx *phc)
{
	struct endpoint endpoint;
	bool ret = false;

	mutex_lock(&phc->mp.stream->in_lock);

	/* we're OK to (potentially) use the source address of this packet as destination
	 * in the other direction. */
	/* if the other side hasn't been signalled yet, just forward the packet */
	if (!PS_ISSET(phc->mp.stream, FILLED)) {
		__C_DBG("stream %s:%d not FILLED", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		goto out;
	}

	// GH #697 - apparent Asterisk bug where it sends stray RTCP to the RTP port.
	// work around this by detecting this situation and ignoring the packet for
	// confirmation purposes when needed. This is regardless of whether rtcp-mux
	// is enabled or not.
	if (!PS_ISSET(phc->mp.stream, CONFIRMED) && PS_ISSET(phc->mp.stream, RTP)) {
		if (rtcp_demux_is_rtcp(&phc->s)) {
			ilog(LOG_DEBUG | LOG_FLAG_LIMIT, "Ignoring stray RTCP packet from %s%s%s for "
					"peer address confirmation purposes",
					FMT_M(endpoint_print_buf(&phc->mp.fsin)));
			goto out;
		}
	}

	PS_SET(phc->mp.stream, RECEIVED);

	/* do not pay attention to source addresses of incoming packets for asymmetric streams */
	if (MEDIA_ISSET(phc->mp.media, ASYMMETRIC) || phc->mp.stream->el_flags == EL_OFF) {
		PS_SET(phc->mp.stream, CONFIRMED);
		mutex_lock(&phc->mp.stream->out_lock);
		if (MEDIA_ISSET(phc->mp.media, ASYMMETRIC) && !phc->mp.stream->learned_endpoint.address.family)
			phc->mp.stream->learned_endpoint = phc->mp.fsin;
		mutex_unlock(&phc->mp.stream->out_lock);
	}

	/* confirm sinks for unidirectional streams in order to kernelize */
	if (MEDIA_ISSET(phc->mp.media, UNIDIRECTIONAL)) {
		for (__auto_type l = phc->sinks->head; l; l = l->next) {
			struct sink_handler *sh = l->data;
			PS_SET(sh->sink, CONFIRMED);
		}
	}

	/* if we have already updated the endpoint in the past ... */
	if (PS_ISSET(phc->mp.stream, CONFIRMED)) {
		/* see if we need to compare the source address with the known endpoint */
		if (PS_ISSET2(phc->mp.stream, STRICT_SOURCE, MEDIA_HANDOVER)) {
			endpoint = phc->mp.fsin;
			mutex_lock(&phc->mp.stream->out_lock);

			struct endpoint *ps_endpoint = MEDIA_ISSET(phc->mp.media, ASYMMETRIC) ?
							&phc->mp.stream->learned_endpoint : &phc->mp.stream->endpoint;
			int tmp = memcmp(&endpoint, ps_endpoint, sizeof(endpoint));
			if (tmp && PS_ISSET(phc->mp.stream, MEDIA_HANDOVER)) {
				/* out_lock remains locked */
				ilog(LOG_INFO | LOG_FLAG_LIMIT, "Peer address changed to %s%s%s",
						FMT_M(endpoint_print_buf(&phc->mp.fsin)));
				phc->unkernelize = "peer address changed (media handover)";
				phc->unconfirm = true;
				phc->update = true;
				*ps_endpoint = phc->mp.fsin;
				goto update_addr;
			}

			mutex_unlock(&phc->mp.stream->out_lock);

			if (tmp && PS_ISSET(phc->mp.stream, STRICT_SOURCE)) {
				ilog(LOG_INFO | LOG_FLAG_LIMIT, "Drop due to strict-source attribute; "
						"got %s%s:%d%s, "
						"expected %s%s:%d%s",
					FMT_M(sockaddr_print_buf(&endpoint.address), endpoint.port),
					FMT_M(sockaddr_print_buf(&ps_endpoint->address),
					ps_endpoint->port));
				atomic64_inc_na(&phc->mp.stream->stats_in->errors);
				atomic64_inc_na(&phc->mp.sfd->local_intf->stats->in.errors);
				ret = true;
			}
		}
		phc->kernelize = true;
		goto out;
	}

	/* wait at least 3 seconds after last signal before committing to a particular
	 * endpoint address */
	bool wait_time = false;
	if (!phc->mp.call->last_signal || rtpe_now.tv_sec <= phc->mp.call->last_signal + 3)
		wait_time = true;

	const struct endpoint *use_endpoint_confirm = &phc->mp.fsin;

	if (phc->mp.stream->el_flags == EL_IMMEDIATE)
		goto confirm_now;

	if (phc->mp.stream->el_flags == EL_HEURISTIC
			&& phc->mp.stream->advertised_endpoint.address.family
			&& phc->mp.stream->advertised_endpoint.port)
	{
		// check if we need to reset our learned endpoints
		if (memcmp(&rtpe_now, &phc->mp.stream->ep_detect_signal, sizeof(rtpe_now))) {
			memset(&phc->mp.stream->detected_endpoints, 0, sizeof(phc->mp.stream->detected_endpoints));
			phc->mp.stream->ep_detect_signal = rtpe_now;
		}

		// possible endpoints that can be detected in order of preference:
		// 0: endpoint that matches the address advertised in the SDP
		// 1: endpoint with the same address but different port
		// 2: endpoint with the same port but different address
		// 3: endpoint with both different port and different address
		unsigned int idx = 0;
		if (phc->mp.fsin.port != phc->mp.stream->advertised_endpoint.port)
			idx |= 1;
		if (memcmp(&phc->mp.fsin.address, &phc->mp.stream->advertised_endpoint.address,
					sizeof(sockaddr_t)))
			idx |= 2;

		// fill appropriate slot
		phc->mp.stream->detected_endpoints[idx] = phc->mp.fsin;

		// now grab the best matched endpoint
		for (idx = 0; idx < 4; idx++) {
			use_endpoint_confirm = &phc->mp.stream->detected_endpoints[idx];
			if (use_endpoint_confirm->address.family)
				break;
		}
	}

	if (wait_time)
		goto update_peerinfo;

confirm_now:
	phc->kernelize = true;
	phc->update = true;

	ilog(LOG_INFO, "Confirmed peer address as %s%s%s", FMT_M(endpoint_print_buf(use_endpoint_confirm)));

	PS_SET(phc->mp.stream, CONFIRMED);

update_peerinfo:
	mutex_lock(&phc->mp.stream->out_lock);
	// if we're during the wait time, check the received address against the previously
	// learned address. if they're the same, ignore this packet for learning purposes
	if (!wait_time || !phc->mp.stream->learned_endpoint.address.family ||
			memcmp(use_endpoint_confirm, &phc->mp.stream->learned_endpoint, sizeof(endpoint)))
	{
		endpoint = phc->mp.stream->endpoint;
		phc->mp.stream->endpoint = *use_endpoint_confirm;
		phc->mp.stream->learned_endpoint = *use_endpoint_confirm;
		if (memcmp(&endpoint, &phc->mp.stream->endpoint, sizeof(endpoint))) {
			ilog(LOG_DEBUG | LOG_FLAG_LIMIT, "Peer address changed from %s%s%s to %s%s%s",
					FMT_M(endpoint_print_buf(&endpoint)),
					FMT_M(endpoint_print_buf(use_endpoint_confirm)));
			phc->unkernelize = "peer address changed";
			phc->update = true;
			phc->unkernelize_subscriptions = true;
		}
	}
update_addr:
	mutex_unlock(&phc->mp.stream->out_lock);

	/* check the destination address of the received packet against what we think our
	 * local interface to use is */
	if (phc->mp.stream->selected_sfd && phc->mp.sfd != phc->mp.stream->selected_sfd) {
		// make sure the new interface/socket is actually one from the list of sockets
		// that we intend to use, and not an old one from a previous negotiation
		__auto_type contains = t_queue_find(&phc->mp.stream->sfds, phc->mp.sfd);
		if (!contains)
			ilog(LOG_INFO | LOG_FLAG_LIMIT, "Not switching from local socket %s to %s (not in list)",
					endpoint_print_buf(&phc->mp.stream->selected_sfd->socket.local),
					endpoint_print_buf(&phc->mp.sfd->socket.local));
		else {
			ilog(LOG_INFO | LOG_FLAG_LIMIT, "Switching local socket from %s to %s",
					endpoint_print_buf(&phc->mp.stream->selected_sfd->socket.local),
					endpoint_print_buf(&phc->mp.sfd->socket.local));
			phc->mp.stream->selected_sfd = phc->mp.sfd;
			phc->unkernelize = "local socket switched";
			phc->update = true;
			phc->unkernelize_subscriptions = true;
		}
	}

out:
	mutex_unlock(&phc->mp.stream->in_lock);

	return ret;
}


static void media_packet_kernel_check(struct packet_handler_ctx *phc) {
	if (PS_ISSET(phc->mp.stream, NO_KERNEL_SUPPORT)) {
		__C_DBG("stream %s%s%s NO_KERNEL_SUPPORT", FMT_M(endpoint_print_buf(&phc->mp.stream->endpoint)));
		return;
	}

	if (!PS_ISSET(phc->mp.stream, CONFIRMED)) {
		__C_DBG("stream %s%s%s not CONFIRMED", FMT_M(endpoint_print_buf(&phc->mp.stream->endpoint)));
		return;
	}

	if (ML_ISSET(phc->mp.media->monologue, DTMF_INJECTION_ACTIVE))
		return;

	mutex_lock(&phc->mp.stream->in_lock);
	kernelize(phc->mp.stream);
	mutex_unlock(&phc->mp.stream->in_lock);
}


static int do_rtcp_parse(struct packet_handler_ctx *phc) {
	int rtcp_ret = rtcp_parse(&phc->rtcp_list, &phc->mp);
	if (rtcp_ret < 0)
		return -1;
	if (rtcp_ret == 1)
		phc->rtcp_discard = true;
	return 0;
}
static int do_rtcp_output(struct packet_handler_ctx *phc) {
	if (phc->rtcp_discard)
		return 0;
	if (phc->kernel_handled)
		return 0;

	if (phc->rtcp_filter)
		if (phc->rtcp_filter(&phc->mp, &phc->rtcp_list))
			return -1;

	// queue for output
	codec_add_raw_packet(&phc->mp, 0);
	return 0;
}


// appropriate locks must be held
// only frees the output queue if no `sink` is given
int media_socket_dequeue(struct media_packet *mp, struct packet_stream *sink) {
	struct codec_packet *p;
	while ((p = t_queue_pop_head(&mp->packets_out))) {
		if (sink && sink->send_timer)
			send_timer_push(sink->send_timer, p);
		else
			codec_packet_free(p);
	}
	return 0;
}

void media_packet_copy(struct media_packet *dst, const struct media_packet *src) {
	*dst = *src;
	t_queue_init(&dst->packets_out);
	if (dst->sfd)
		obj_hold(dst->sfd);
	if (dst->ssrc_in)
		obj_hold(&dst->ssrc_in->parent->h);
	if (dst->ssrc_out)
		obj_hold(&dst->ssrc_out->parent->h);
	dst->rtp = __g_memdup(src->rtp, sizeof(*src->rtp));
	dst->rtcp = __g_memdup(src->rtcp, sizeof(*src->rtcp));
	dst->payload = STR_NULL;
	dst->raw = STR_NULL;
}
void media_packet_release(struct media_packet *mp) {
	if (mp->sfd)
		obj_put(mp->sfd);
	if (mp->ssrc_in)
		obj_put(&mp->ssrc_in->parent->h);
	if (mp->ssrc_out)
		obj_put(&mp->ssrc_out->parent->h);
	media_socket_dequeue(mp, NULL);
	g_free(mp->rtp);
	g_free(mp->rtcp);
	ZERO(*mp);
}


static int media_packet_queue_dup(codec_packet_q *q) {
	for (__auto_type l = q->head; l; l = l->next) {
		struct codec_packet *p = l->data;
		if (p->free_func) // nothing to do, already private
			continue;
		if (!codec_packet_copy(p))
			return -1;
	}
	return 0;
}

/**
 * Packet handling starts in stream_packet().
 * 
 * This operates on the originating stream_fd (fd which received the packet)
 * and on its linked packet_stream.
 *
 * Eventually proceeds to going through the list of sinks,
 * either rtp_sinks or rtcp_sinks (egress handling).
 *
 * called lock-free.
 */
static int stream_packet(struct packet_handler_ctx *phc) {
/**
 * Incoming packets (ingress):
 * - phc->mp.sfd->socket.local: the local IP/port on which the packet arrived
 * - phc->mp.sfd->stream->endpoint: adjusted/learned IP/port from where the packet
 *   was sent
 * - phc->mp.sfd->stream->advertised_endpoint: the unadjusted IP/port from where the
 *   packet was sent. These are the values present in the SDP
 *
 * Outgoing packets (egress):
 * - sh_link = phc->sinks->head (ptr to Gqueue with sinks), then
 *   sh = sh_link->data (ptr to handler, implicit cast), then
 *   sh->sink->endpoint: the destination IP/port
 * - sh->sink->selected_sfd->socket.local: the local source IP/port for the
 *   outgoing packet (same way it gets sinks from phc->sinks)
 *
 * If rtpengine runs behind a NAT and local addresses are configured with
 * different advertised endpoints, the SDP would not contain the address from
 * `...->socket.local.address`, but rather from `...->local_intf->advertised_address.addr`
 * (of type `sockaddr_t`). The port will be the same.
 *
 * TODO: move the above comments to the data structure definitions, if the above
 * always holds true */
	int ret = 0, handler_ret = 0;
	GQueue free_list = G_QUEUE_INIT;

	phc->mp.call = phc->mp.sfd->call;

	rwlock_lock_r(&phc->mp.call->master_lock);

	phc->mp.stream = phc->mp.sfd->stream;
	if (G_UNLIKELY(!phc->mp.stream))
		goto out;
	__C_DBG("Handling packet on: %s", endpoint_print_buf(&phc->mp.stream->endpoint));


	phc->mp.media = phc->mp.stream->media;

	///////////////// INGRESS HANDLING

	if (!phc->mp.stream->selected_sfd)
		goto out;

	CALL_CLEAR(phc->mp.call, FOREIGN_MEDIA);

	if (CALL_ISSET(phc->mp.call, DROP_TRAFFIC))
		goto drop;

	int stun_ret = media_demux_protocols(phc);
	if (stun_ret == 0) // packet processed
		goto out;
	if (stun_ret == 1) {
		media_packet_kernel_check(phc);
		goto drop;
	}


#if RTP_LOOP_PROTECT
	if (MEDIA_ISSET(phc->mp.media, LOOP_CHECK)) {
		if (media_loop_detect(phc))
			goto out;
	}
#endif

	// this sets rtcp, in_srtp, and sinks
	media_packet_rtcp_demux(phc);

	if (media_packet_address_check(phc))
		goto drop;

	if (rtpe_config.active_switchover && IS_FOREIGN_CALL(phc->mp.call))
		call_make_own_foreign(phc->mp.call, false);

	bool is_blackhole = MEDIA_ISSET(phc->mp.media, BLACKHOLE);
	if (!is_blackhole)
		is_blackhole = !phc->rtcp && !MEDIA_ISSET(phc->mp.media, RECV);

	// this set payload_type, ssrc_in, and mp payloads
	media_packet_rtp_in(phc);

	if (phc->mp.rtp)
		ilog(LOG_DEBUG, "Handling packet: remote %s%s%s (expected: %s%s%s) -> local %s "
				"(RTP seq %u TS %u SSRC %s%x%s)",
				FMT_M(endpoint_print_buf(&phc->mp.fsin)),
				FMT_M(endpoint_print_buf(&phc->mp.stream->endpoint)),
				endpoint_print_buf(&phc->mp.sfd->socket.local),
				ntohs(phc->mp.rtp->seq_num),
				ntohl(phc->mp.rtp->timestamp),
				FMT_M(ntohl(phc->mp.rtp->ssrc)));
	else
		ilog(LOG_DEBUG, "Handling packet: remote %s%s%s (expected: %s%s%s) -> local %s",
				FMT_M(endpoint_print_buf(&phc->mp.fsin)),
				FMT_M(endpoint_print_buf(&phc->mp.stream->endpoint)),
				endpoint_print_buf(&phc->mp.sfd->socket.local));

	// SSRC receive stats
	if (phc->mp.ssrc_in && phc->mp.rtp) {
		atomic64_inc_na(&phc->mp.ssrc_in->stats->packets);
		atomic64_add_na(&phc->mp.ssrc_in->stats->bytes, phc->s.len);
		// no real sequencing, so this is rudimentary
		unsigned int old_seq = atomic_get_na(&phc->mp.ssrc_in->stats->ext_seq);
		unsigned int new_seq = ntohs(phc->mp.rtp->seq_num) | (old_seq & 0xffff0000UL);
		// XXX combine this with similar code elsewhere
		int seq_diff = new_seq - old_seq;
		while (seq_diff < -60000) {
			new_seq += 0x10000;
			seq_diff += 0x10000;
		}
		if (seq_diff > 0 || seq_diff < -10) {
			atomic_set_na(&phc->mp.ssrc_in->stats->ext_seq, new_seq);
			atomic_set_na(&phc->mp.ssrc_in->stats->timestamp, ntohl(phc->mp.rtp->timestamp));
		}
	}

	// decrypt in place
	// XXX check handler_ret along the paths
	handler_ret = media_packet_decrypt(phc);
	if (handler_ret < 0)
		goto out; // receive error

	rtp_padding(phc->mp.rtp, &phc->mp.payload);

	// If recording pcap dumper is set, then we record the call.
	if (phc->mp.call->recording && !rtpe_config.rec_egress)
		dump_packet(&phc->mp, &phc->s);

	phc->mp.raw = phc->s;

	if (atomic64_inc_na(&phc->mp.stream->stats_in->packets) == 0) {
		if (phc->mp.stream->component == 1) {
			if (phc->mp.media->index == 1)
				janus_rtc_up(phc->mp.media->monologue);
			janus_media_up(phc->mp.media);
		}
	}
	atomic64_add_na(&phc->mp.stream->stats_in->bytes, phc->s.len);
	atomic64_inc_na(&phc->mp.sfd->local_intf->stats->in.packets);
	atomic64_add_na(&phc->mp.sfd->local_intf->stats->in.bytes, phc->s.len);
	atomic64_set(&phc->mp.stream->last_packet, rtpe_now.tv_sec);
	RTPE_STATS_INC(packets_user);
	RTPE_STATS_ADD(bytes_user, phc->s.len);

	///////////////// EGRESS HANDLING

	str orig_raw = STR_NULL;

	for (__auto_type sh_link = phc->sinks->head; sh_link; sh_link = sh_link->next) {
		struct sink_handler *sh = sh_link->data;
		struct packet_stream *sink = sh->sink;

		// this sets rtcp, in_srtp, out_srtp, media_out, and sink
		media_packet_rtcp_mux(phc, sh);

		// this set ssrc_out
		media_packet_rtp_out(phc, sh);

		rtcp_list_free(&phc->rtcp_list);

		if (phc->rtcp) {
			phc->rtcp_discard = false;
			handler_ret = -1;
			// these functions may do in-place rewriting, but we may have multiple
			// outputs - make a copy if this isn't the last sink
			if (sh_link->next) {
				if (!orig_raw.s)
					orig_raw = phc->mp.raw;
				char *buf = bufferpool_alloc(media_bufferpool, orig_raw.len + RTP_BUFFER_TAIL_ROOM);
				memcpy(buf, orig_raw.s, orig_raw.len);
				phc->mp.raw.s = buf;
				g_queue_push_tail(&free_list, buf);
			}
			if (do_rtcp_parse(phc))
				goto out;
			if (phc->rtcp_discard)
				goto next;
		}
		else {
			if (sh->attrs.rtcp_only)
				goto next;
		}

		if (PS_ISSET(sink, NAT_WAIT) && !PS_ISSET(sink, RECEIVED)) {
			ilog(LOG_DEBUG | LOG_FLAG_LIMIT,
					"Media packet from %s%s%s discarded due to `NAT-wait` flag",
					FMT_M(endpoint_print_buf(&phc->mp.fsin)));
			goto next;
		}

		if (G_UNLIKELY(!sink->selected_sfd || !phc->out_srtp
					|| !phc->out_srtp->selected_sfd || !phc->in_srtp->selected_sfd))
		{
			errno = ENOENT;
			ilog(LOG_WARNING | LOG_FLAG_LIMIT,
					"Media packet from %s%s%s discarded due to lack of sink",
					FMT_M(endpoint_print_buf(&phc->mp.fsin)));
			goto err_next;
		}

		media_packet_set_encrypt(phc, sh);

		if (phc->rtcp) {
			if (do_rtcp_output(phc))
				goto err_next;
		}
		else {
			struct codec_handler *transcoder = codec_handler_get(phc->mp.media, phc->payload_type,
					phc->mp.media_out, sh);
			// this transfers the packet from 's' to 'packets_out'
			if (transcoder->handler_func(transcoder, &phc->mp))
				goto err_next;
		}

		// if this is not the last sink, duplicate the output queue packets if necessary
		if (sh_link->next) {
			ret = media_packet_queue_dup(&phc->mp.packets_out);
			errno = ENOMEM;
			if (ret)
				goto err_next;
		}

		// egress mirroring

		if (!phc->rtcp) {
			for (__auto_type mirror_link = phc->mp.stream->rtp_mirrors.head; mirror_link;
					mirror_link = mirror_link->next)
			{
				struct packet_handler_ctx mirror_phc = *phc;
				mirror_phc.mp.ssrc_out = NULL;
				t_queue_init(&mirror_phc.mp.packets_out);

				struct sink_handler *mirror_sh = mirror_link->data;
				struct packet_stream *mirror_sink = mirror_sh->sink;

				media_packet_rtcp_mux(&mirror_phc, mirror_sh);
				media_packet_rtp_out(&mirror_phc, mirror_sh);
				media_packet_set_encrypt(&mirror_phc, mirror_sh);

				for (__auto_type pack = phc->mp.packets_out.head; pack; pack = pack->next) {
					struct codec_packet *p = pack->data;
					t_queue_push_tail(&mirror_phc.mp.packets_out, codec_packet_dup(p));
				}

				ret = __media_packet_encrypt(&mirror_phc, mirror_sh);
				if (ret)
					goto next_mirror;

				mutex_lock(&mirror_sink->out_lock);

				if (!mirror_sink->advertised_endpoint.port
						|| (is_addr_unspecified(&mirror_sink->advertised_endpoint.address)
							&& !is_trickle_ice_address(&mirror_sink->advertised_endpoint)))
				{
					mutex_unlock(&mirror_sink->out_lock);
					goto next_mirror;
				}

				media_socket_dequeue(&mirror_phc.mp, mirror_sink);

				mutex_unlock(&mirror_sink->out_lock);

next_mirror:
				media_socket_dequeue(&mirror_phc.mp, NULL); // just free if anything left
				ssrc_ctx_put(&mirror_phc.mp.ssrc_out);
			}
		}

		ret = __media_packet_encrypt(phc, sh);
		errno = ENOTTY;
		if (ret == -1)
			goto err_next;

		mutex_lock(&sink->out_lock);

		if (!sink->advertised_endpoint.port
				|| (is_addr_unspecified(&sink->advertised_endpoint.address)
					&& !is_trickle_ice_address(&sink->advertised_endpoint)))
		{
			mutex_unlock(&sink->out_lock);
			goto next;
		}

		if (!is_blackhole)
			ret = media_socket_dequeue(&phc->mp, sink);
		else
			ret = media_socket_dequeue(&phc->mp, NULL);

		mutex_unlock(&sink->out_lock);

		if (ret == 0)
			goto next;

err_next:
		ilog(LOG_DEBUG | LOG_FLAG_LIMIT ,"Error when sending message. Error: %s", strerror(errno));
		atomic64_inc_na(&sink->stats_in->errors);
		if (sink->selected_sfd)
			atomic64_inc_na(&sink->selected_sfd->local_intf->stats->out.errors);
		RTPE_STATS_INC(errors_user);
		goto next;

next:
		media_socket_dequeue(&phc->mp, NULL); // just free if anything left
		ssrc_ctx_put(&phc->mp.ssrc_out);
	}

	///////////////// INGRESS POST-PROCESSING HANDLING

	if (phc->unkernelize) // for RTCP packet index updates
		unkernelize(phc->mp.stream, phc->unkernelize);
	if (phc->kernelize)
		media_packet_kernel_check(phc);

drop:
	ret = 0;
	handler_ret = 0;

out:
	if (phc->unconfirm) {
		stream_unconfirm(phc->mp.stream, "peer address unconfirmed");
		unconfirm_sinks(&phc->mp.stream->rtp_sinks, "peer address unconfirmed");
		unconfirm_sinks(&phc->mp.stream->rtcp_sinks, "peer address unconfirmed");
	}
	if (phc->unkernelize_subscriptions) {
		g_auto(GQueue) mls = G_QUEUE_INIT; /* to avoid duplications */
		for (__auto_type sub = phc->mp.media->media_subscriptions.head; sub; sub = sub->next)
		{
			struct media_subscription * ms = sub->data;

			if (!g_queue_find(&mls, ms->monologue)) {
				for (unsigned int k = 0; k < ms->monologue->medias->len; k++)
				{
					struct call_media *sub_media = ms->monologue->medias->pdata[k];
					if (!sub_media)
						continue;

					for (__auto_type m = sub_media->streams.head; m; m = m->next) {
						struct packet_stream *sub_ps = m->data;
						__unkernelize(sub_ps, "subscriptions modified");
					}
				}
				g_queue_push_tail(&mls, ms->monologue);
			}
		}
	}

	if (handler_ret < 0) {
		atomic64_inc_na(&phc->mp.stream->stats_in->errors);
		atomic64_inc_na(&phc->mp.sfd->local_intf->stats->in.errors);
		RTPE_STATS_INC(errors_user);
	}

	rwlock_unlock_r(&phc->mp.call->master_lock);

	media_socket_dequeue(&phc->mp, NULL); // just free
	ssrc_ctx_put(&phc->mp.ssrc_out);

	ssrc_ctx_put(&phc->mp.ssrc_in);
	rtcp_list_free(&phc->rtcp_list);
	g_queue_clear_full(&free_list, bufferpool_unref);

	return ret;
}


static void __stream_fd_readable(struct packet_handler_ctx *phc) {
	struct stream_fd *sfd = phc->mp.sfd;

	if (phc->mp.tv.tv_sec < 0) {
		// kernel-handled RTCP
		phc->kernel_handled = true;
		// restore original actual timestamp
		if (G_UNLIKELY(phc->mp.tv.tv_usec == 0))
			phc->mp.tv.tv_sec = -phc->mp.tv.tv_sec;
		else {
			phc->mp.tv.tv_sec = -phc->mp.tv.tv_sec - 1;
			phc->mp.tv.tv_usec = 1000000 - phc->mp.tv.tv_usec;
		}
	}

	int ret;
	if (sfd->stream && sfd->stream->jb) {
		ret = buffer_packet(&phc->mp, &phc->s);
		if (ret == 1)
			ret = stream_packet(phc);
	}
	else
		ret = stream_packet(phc);

	if (G_UNLIKELY(ret < 0))
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Write error on media socket: %s", strerror(-ret));
}

static void stream_fd_readable(int fd, void *p) {
	stream_fd *sfd = p;
	int ret, iters;
	bool update = false;
	call_t *ca;

	if (sfd->socket.fd != fd)
		return;

	// +1 to active read events. If it was zero then we handle it. If it was non-zero,
	// another thread is already handling this socket and will process our event.
	if (g_atomic_int_add(&sfd->active_read_events, 1) != 0)
		return;

	ca = sfd->call ? : NULL;

	log_info_stream_fd(sfd);
	int strikes = g_atomic_int_get(&sfd->error_strikes);

	if (strikes >= MAX_RECV_LOOP_STRIKES) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "UDP receive queue exceeded %i times: "
				"discarding packet", strikes);
		// Polling is edge-triggered so we won't immediately get here again.
		// We could remove ourselves from the poller though. Maybe call stream_fd_closed?
		return;
	}

restart:

	for (iters = 0; ; iters++) {
#if MAX_RECV_ITERS
		if (iters >= rtpe_config.max_recv_iters) {
			ilog(LOG_WARN | LOG_FLAG_LIMIT, "Too many packets in UDP receive queue (more than %d), "
					"aborting loop. Dropped packets possible", iters);
			g_atomic_int_inc(&sfd->error_strikes);
			g_atomic_int_set(&sfd->active_read_events,0);
			goto strike;
		}
#endif

		struct packet_handler_ctx phc;
		ZERO(phc);
		phc.mp.sfd = sfd;

		if (ca) {
			rwlock_lock_r(&ca->master_lock);
			if (sfd->socket.fd != fd) {
				rwlock_unlock_r(&ca->master_lock);
				goto done;
			}
		}

		g_autoptr(bp_char) buf = bufferpool_alloc(media_bufferpool, RTP_BUFFER_SIZE);

		ret = socket_recvfrom_ts(&sfd->socket, buf + RTP_BUFFER_HEAD_ROOM, MAX_RTP_PACKET_SIZE,
				&phc.mp.fsin, &phc.mp.tv);
		if (ca)
			rwlock_unlock_r(&ca->master_lock);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			stream_fd_closed(fd, sfd);
			goto done;
		}
		if (ret >= MAX_RTP_PACKET_SIZE)
			ilog(LOG_WARNING | LOG_FLAG_LIMIT, "UDP packet possibly truncated");

		phc.s = STR_LEN(buf + RTP_BUFFER_HEAD_ROOM, ret);

		__stream_fd_readable(&phc);

		update += phc.update;
	}

	// -1 active read events. If it's non-zero, another thread has received a read event,
	// and we must handle it here.
	if (!g_atomic_int_dec_and_test(&sfd->active_read_events))
		goto restart;

	// no strike
	if (strikes > 0)
		g_atomic_int_compare_and_exchange(&sfd->error_strikes, strikes, strikes - 1);

strike:

	if (ca && update) {
		redis_update_onekey(ca, rtpe_redis_write);
	}
done:
	log_info_pop();
}

static void stream_fd_recv(struct obj *obj, char *buf, size_t len, struct sockaddr *sa, struct timeval *tv) {
	struct stream_fd *sfd = (struct stream_fd *) obj;
	call_t *ca = sfd->call;
	if (!ca)
		goto out;

	rwlock_lock_r(&ca->master_lock);

	if (sfd->socket.fd == -1) {
		rwlock_unlock_r(&ca->master_lock);
		goto out;
	}

	log_info_stream_fd(sfd);

	rwlock_unlock_r(&ca->master_lock);

	struct packet_handler_ctx phc;
	ZERO(phc);
	phc.mp.sfd = sfd;
	sfd->socket.family->sockaddr2endpoint(&phc.mp.fsin, sa);
	phc.s = STR_LEN(buf, len);

	__stream_fd_readable(&phc);

	if (phc.update)
		redis_update_onekey(ca, rtpe_redis_write);

out:
	log_info_pop();
	bufferpool_unref(buf);
}



static void stream_fd_free(stream_fd *f) {
	release_port(&f->socket, f->local_intf->spec);
	crypto_cleanup(&f->crypto);
	dtls_connection_cleanup(&f->dtls);

	obj_put(f->call);
}

stream_fd *stream_fd_new(socket_t *fd, call_t *call, struct local_intf *lif) {
	stream_fd *sfd;
	struct poller_item pi;

	sfd = obj_alloc0(stream_fd, stream_fd_free);
	sfd->unique_id = t_queue_get_length(&call->stream_fds);
	sfd->socket = *fd;
	sfd->call = obj_get(call);
	sfd->local_intf = lif;
	t_queue_push_tail(&call->stream_fds, sfd); /* hand over ref */
	g_slice_free1(sizeof(*fd), fd); /* moved into sfd, thus free */

	__C_DBG("stream_fd_new localport=%d", sfd->socket.local.port);

	ZERO(pi);
	pi.fd = sfd->socket.fd;
	pi.obj = &sfd->obj;
	pi.readable = stream_fd_readable;
	pi.recv = stream_fd_recv;
	pi.closed = stream_fd_closed;

	if (sfd->socket.fd != -1) {
		struct poller *p = call->poller;
		if (!rtpe_poller_add_item(p, &pi))
			ilog(LOG_ERR, "Failed to add stream_fd to poller");
		else
			sfd->poller = p;

		RWLOCK_W(&local_media_socket_endpoints_lock);
		t_hash_table_replace(local_media_socket_endpoints, &sfd->socket.local, obj_get(sfd));
	}

	return sfd;
}

stream_fd *stream_fd_lookup(const endpoint_t *ep) {
	RWLOCK_R(&local_media_socket_endpoints_lock);
	stream_fd *ret = t_hash_table_lookup(local_media_socket_endpoints, ep);
	if (!ret)
		return NULL;
	obj_hold(ret);
	return ret;
}

void stream_fd_release(stream_fd *sfd) {
	if (!sfd)
		return;
	if (sfd->socket.fd == -1)
		return;

	{
		RWLOCK_W(&local_media_socket_endpoints_lock);
		stream_fd *ent = t_hash_table_lookup(local_media_socket_endpoints, &sfd->socket.local);
		if (ent == sfd)
			t_hash_table_remove(local_media_socket_endpoints,
					&sfd->socket.local); // releases reference
	}

	release_port_poller(&sfd->socket, sfd->local_intf->spec, sfd->poller);
}



const struct transport_protocol *transport_protocol(const str *s) {
	int i;

	if (!s || !s->s)
		goto out;

	for (i = 0; i < num_transport_protocols; i++) {
		if (strlen(transport_protocols[i].name) != s->len)
			continue;
		if (strncasecmp(transport_protocols[i].name, s->s, s->len))
			continue;
		return &transport_protocols[i];
	}

out:
	return NULL;
}

void play_buffered(struct jb_packet *cp) {
	struct packet_handler_ctx phc;
	ZERO(phc);
	phc.mp = cp->mp;
	phc.s = cp->mp.raw;
	//phc.buffered_packet = buffered;
	stream_packet(&phc);
	jb_packet_free(&cp);
}

void interfaces_free(void) {
	struct local_intf *ifc;
	GList *ll;

	while ((ifc = g_queue_pop_head(&all_local_interfaces))) {
		free(ifc->ice_foundation.s);
		bufferpool_unref(ifc->stats);
		g_slice_free1(sizeof(*ifc), ifc);
	}

	t_hash_table_destroy(__logical_intf_name_family_hash);

	ll = g_hash_table_get_values(__local_intf_addr_type_hash);
	for (GList *l = ll; l; l = l->next) {
		GList *k = l->data;
		g_list_free(k);
	}
	g_list_free(ll);
	g_hash_table_destroy(__local_intf_addr_type_hash);

	ll = g_hash_table_get_values(__intf_spec_addr_type_hash);
	for (GList *l = ll; l; l = l->next) {
		struct intf_spec *spec = l->data;
		struct port_pool *pp = &spec->port_pool;
		if (pp->free_ports_ht) {
			g_hash_table_destroy(pp->free_ports_ht);
		}
		g_queue_clear(&pp->free_ports_q);
		mutex_destroy(&pp->free_list_lock);
		g_slice_free1(sizeof(*spec), spec);
	}
	g_list_free(ll);
	g_hash_table_destroy(__intf_spec_addr_type_hash);

	intf_rr_lookup_iter r_iter;
	t_hash_table_iter_init(&r_iter, __logical_intf_name_family_rr_hash);
	struct intf_rr *rr;
	while (t_hash_table_iter_next(&r_iter, NULL, &rr)) {
		g_queue_clear(&rr->logical_intfs);
		g_slice_free1(sizeof(*rr), rr);
	}
	t_hash_table_destroy(__logical_intf_name_family_rr_hash);

	for (int i = 0; i < G_N_ELEMENTS(__preferred_lists_for_family); i++) {
		GQueue *q = &__preferred_lists_for_family[i];
		struct logical_intf *lif;
		while ((lif = g_queue_pop_head(q))) {
			g_hash_table_destroy(lif->rr_specs);
			g_queue_clear(&lif->list);
			g_slice_free1(sizeof(*lif), lif);
		}
	}

	t_hash_table_destroy(local_media_socket_endpoints);
	local_media_socket_endpoints = local_sockets_ht_null();
}



static void interface_stats_block_free(void *p) {
	g_slice_free1(sizeof(struct interface_stats_interval), p);
}
void interface_sampled_rate_stats_init(struct interface_sampled_rate_stats *s) {
	s->ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			interface_stats_block_free);
}
void interface_sampled_rate_stats_destroy(struct interface_sampled_rate_stats *s) {
	g_hash_table_destroy(s->ht);
}
struct interface_stats_block *interface_sampled_rate_stats_get(struct interface_sampled_rate_stats *s,
		struct local_intf *lif, long long *time_diff_us)
{
	if (!s)
		return NULL;
	struct interface_stats_interval *ret = g_hash_table_lookup(s->ht, lif);
	if (!ret) {
		ret = g_slice_alloc0(sizeof(*ret));
		g_hash_table_insert(s->ht, lif, ret);
	}
	if (ret->last_run.tv_sec)
		*time_diff_us = timeval_diff(&rtpe_now, &ret->last_run);
	else
		*time_diff_us = 0;
	ret->last_run = rtpe_now;
	return &ret->stats;
}
