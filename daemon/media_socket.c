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
#include "xt_RTPENGINE.h"
#include "rtcp.h"
#include "sdp.h"
#include "aux.h"
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


#ifndef PORT_RANDOM_MIN
#define PORT_RANDOM_MIN 6
#define PORT_RANDOM_MAX 20
#endif

#ifndef MAX_RECV_ITERS
#define MAX_RECV_ITERS 50
#endif



struct intf_rr {
	struct logical_intf hash_key;
	mutex_t lock;
	GQueue logical_intfs;
	struct logical_intf *singular; // set iff only one is present in the list - no lock needed
};
struct packet_handler_ctx {
	// inputs:
	str s; // raw input packet

	struct packet_stream *sink; // where to send output packets to (forward destination)
	rewrite_func decrypt_func, encrypt_func; // handlers for decrypt/encrypt
	rtcp_filter_func *rtcp_filter;
	struct packet_stream *in_srtp, *out_srtp; // SRTP contexts for decrypt/encrypt (relevant for muxed RTCP)
	int payload_type; // -1 if unknown or not RTP
	int rtcp; // true if this is an RTCP packet

	// verdicts:
	int update; // true if Redis info needs to be updated
	int unkernelize; // true if stream ought to be removed from kernel
	int kernelize; // true if stream can be kernelized

	// output:
	struct media_packet mp; // passed to handlers
};


static void __determine_handler(struct packet_stream *in, const struct packet_stream *out);

static int __k_null(struct rtpengine_srtp *s, struct packet_stream *);
static int __k_srtp_encrypt(struct rtpengine_srtp *s, struct packet_stream *);
static int __k_srtp_decrypt(struct rtpengine_srtp *s, struct packet_stream *);

static int call_avp2savp_rtp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_savp2avp_rtp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_avp2savp_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_savp2avp_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);


static struct logical_intf *__get_logical_interface(const str *name, sockfamily_t *fam);




/* ********** */

const struct transport_protocol transport_protocols[] = {
	[PROTO_RTP_AVP] = {
		.index		= PROTO_RTP_AVP,
		.name		= "RTP/AVP",
		.avpf_proto	= PROTO_RTP_AVPF,
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
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_AVPF] = {
		.index		= PROTO_RTP_AVPF,
		.name		= "RTP/AVPF",
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
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_UDP_TLS_RTP_SAVP] = {
		.index		= PROTO_UDP_TLS_RTP_SAVP,
		.name		= "UDP/TLS/RTP/SAVP",
		.avpf_proto	= PROTO_UDP_TLS_RTP_SAVPF,
		.rtp		= 1,
		.srtp		= 1,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_UDP_TLS_RTP_SAVPF] = {
		.index		= PROTO_UDP_TLS_RTP_SAVPF,
		.name		= "UDP/TLS/RTP/SAVPF",
		.rtp		= 1,
		.srtp		= 1,
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
};
static const struct streamhandler * const __sh_matrix_in_rtp_avpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_avpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_noop_rtp,
	[PROTO_RTP_SAVP]		= &__sh_avpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_avp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_avpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_avp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savp[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savp2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savp2savp_rtcp_only,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp_rtcp_only,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savp2savp_rtcp_only,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp_rtcp_only,
	[PROTO_UDPTL]			= &__sh_noop,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp_rtcp_only,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp_rtcp_only,
	[PROTO_UDPTL]			= &__sh_noop,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savp_recrypt[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savp2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savp2savp,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savp2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savpf_recrypt[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_savp2savp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_savp2savp,
	[PROTO_UDPTL]			= &__sh_noop,
};
static const struct streamhandler * const __sh_matrix_noop[__PROTO_LAST] = { // non-RTP protocols
	[PROTO_RTP_AVP]			= &__sh_noop,
	[PROTO_RTP_AVPF]		= &__sh_noop,
	[PROTO_RTP_SAVP]		= &__sh_noop,
	[PROTO_RTP_SAVPF]		= &__sh_noop,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_noop,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_noop,
	[PROTO_UDPTL]			= &__sh_noop,
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
};

/* ********** */

static const struct rtpengine_srtp __res_null = {
	.cipher			= REC_NULL,
	.hmac			= REH_NULL,
};




static GQueue *__interface_list_for_family(sockfamily_t *fam);


static GHashTable *__logical_intf_name_family_hash; // name + family -> struct logical_intf
static GHashTable *__logical_intf_name_family_rr_hash; // name + family -> struct intf_rr
static GHashTable *__intf_spec_addr_type_hash; // addr + type -> struct intf_spec
static GHashTable *__local_intf_addr_type_hash; // addr + type -> GList of struct local_intf
static GQueue __preferred_lists_for_family[__SF_LAST];

GQueue all_local_interfaces = G_QUEUE_INIT;



/* checks for free no_ports on a local interface */
static int has_free_ports_loc(struct local_intf *loc, unsigned int num_ports) {
	if (loc == NULL) {
		ilog(LOG_ERR, "has_free_ports_loc - NULL local interface");
		return 0;
	}

	if (num_ports > g_atomic_int_get(&loc->spec->port_pool.free_ports)) {
		ilog(LOG_ERR, "Didn't find %d ports available for " STR_FORMAT "/%s",
			num_ports, STR_FMT(&loc->logical->name),
			sockaddr_print_buf(&loc->spec->local_address.addr));
		return 0;
	}

	__C_DBG("Found %d ports available for " STR_FORMAT "/%s from total of %d free ports",
		num_ports, STR_FMT(&loc->logical->name),
		sockaddr_print_buf(&loc->spec->local_address.addr),
		loc->spec->port_pool.free_ports);

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
		GQueue *q;
		if (fam)
			q = __interface_list_for_family(fam);
		else {
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
	struct logical_intf key;

	if (rr_use_default_intf)
		key.name = log->name_base;
	else
		key.name = *name;
	key.preferred_family = fam;

	struct intf_rr *rr = g_hash_table_lookup(__logical_intf_name_family_rr_hash, &key);
	if (!rr)
		return __get_logical_interface(name, fam);
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
	return __get_logical_interface(name, fam);
}
static struct logical_intf *__get_logical_interface(const str *name, sockfamily_t *fam) {
	struct logical_intf d, *log = NULL;

	d.name = *name;
	d.preferred_family = fam;

	log = g_hash_table_lookup(__logical_intf_name_family_hash, &d);
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

static unsigned int __name_family_hash(const void *p) {
	const struct logical_intf *lif = p;
	return str_hash(&lif->name) ^ g_direct_hash(lif->preferred_family);
}
static int __name_family_eq(const void *a, const void *b) {
	const struct logical_intf *A = a, *B = b;
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


// called during single-threaded startup only
static void __add_intf_rr_1(struct logical_intf *lif, str *name_base, sockfamily_t *fam) {
	struct logical_intf key;
	key.name = *name_base;
	key.preferred_family = fam;
	struct intf_rr *rr = g_hash_table_lookup(__logical_intf_name_family_rr_hash, &key);
	if (!rr) {
		rr = g_slice_alloc0(sizeof(*rr));
		rr->hash_key = key;
		mutex_init(&rr->lock);
		g_hash_table_insert(__logical_intf_name_family_rr_hash, &rr->hash_key, rr);
	}
	g_queue_push_tail(&rr->logical_intfs, lif);
	rr->singular = (rr->logical_intfs.length == 1) ? lif : NULL;
	g_hash_table_insert(lif->rr_specs, &rr->hash_key.name, lif);
}
static void __add_intf_rr(struct logical_intf *lif, str *name_base, sockfamily_t *fam) {
	__add_intf_rr_1(lif, name_base, fam);
	static str legacy_rr_str = STR_CONST_INIT("round-robin-calls");
	__add_intf_rr_1(lif, &legacy_rr_str, fam);
}
static GQueue *__interface_list_for_family(sockfamily_t *fam) {
	return &__preferred_lists_for_family[fam->idx];
}
// called during single-threaded startup only
static void __interface_append(struct intf_config *ifa, sockfamily_t *fam) {
	struct logical_intf *lif;
	GQueue *q;
	struct local_intf *ifc;
	struct intf_spec *spec;

	lif = __get_logical_interface(&ifa->name, fam);

	if (!lif) {
		lif = g_slice_alloc0(sizeof(*lif));
		g_queue_init(&lif->list);
		lif->name = ifa->name;
		lif->name_base = ifa->name_base;
		lif->preferred_family = fam;
		lif->addr_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);
		lif->rr_specs = g_hash_table_new(str_hash, str_equal);
		g_hash_table_insert(__logical_intf_name_family_hash, lif, lif);
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
		spec->port_pool.free_ports = spec->port_pool.max - spec->port_pool.min + 1;
		mutex_init(&spec->port_pool.free_list_lock);
		g_hash_table_insert(__intf_spec_addr_type_hash, &spec->local_address, spec);
	}

	ifc = uid_slice_alloc(ifc, &lif->list);
	ice_foundation(&ifc->ice_foundation);
	ifc->advertised_address = ifa->advertised_address;
	ifc->spec = spec;
	ifc->logical = lif;

	g_hash_table_insert(lif->addr_hash, &spec->local_address, ifc);
	g_queue_push_tail(&all_local_interfaces, ifc);

	__insert_local_intf_addr_type(&spec->local_address, ifc);
	__insert_local_intf_addr_type(&ifc->advertised_address, ifc);
}

// called during single-threaded startup only
void interfaces_init(GQueue *interfaces) {
	int i;
	GList *l;
	struct intf_config *ifa;
	sockfamily_t *fam;

	/* init everything */
	__logical_intf_name_family_hash = g_hash_table_new(__name_family_hash, __name_family_eq);
	__logical_intf_name_family_rr_hash = g_hash_table_new(__name_family_hash, __name_family_eq);
	__intf_spec_addr_type_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);
	__local_intf_addr_type_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);

	for (i = 0; i < G_N_ELEMENTS(__preferred_lists_for_family); i++)
		g_queue_init(&__preferred_lists_for_family[i]);

	/* build primary lists first */
	for (l = interfaces->head; l; l = l->next) {
		ifa = l->data;
		__interface_append(ifa, ifa->local_address.addr.family);
	}

	/* then append to each other as lower-preference alternatives */
	for (i = 0; i < __SF_LAST; i++) {
		fam = get_socket_family_enum(i);
		for (l = interfaces->head; l; l = l->next) {
			ifa = l->data;
			if (ifa->local_address.addr.family == fam)
				continue;
			__interface_append(ifa, fam);
		}
	}
}

void interfaces_exclude_port(unsigned int port) {
	GList *vals, *l;
	struct intf_spec *spec;

	vals = g_hash_table_get_values(__intf_spec_addr_type_hash);

	for (l = vals; l; l = l->next) {
		spec = l->data;
		bit_array_set(spec->port_pool.ports_used, port);
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
	ifa = get_interface_address(lif, __get_socket_family_enum(SF_IP4));
	if (ifa)
		return ifa;
	return get_interface_address(lif, __get_socket_family_enum(SF_IP6));
}



static int get_port(socket_t *r, unsigned int port, struct intf_spec *spec, const str *label) {
	struct port_pool *pp;

	__C_DBG("attempting to open port %u", port);

	pp = &spec->port_pool;

	if (bit_array_set(pp->ports_used, port)) {
		__C_DBG("port %d in use", port);
		return -1;
	}
	__C_DBG("port %d locked", port);

	if (open_socket(r, SOCK_DGRAM, port, &spec->local_address.addr)) {
		__C_DBG("couldn't open port %d", port);
		bit_array_clear(pp->ports_used, port);
		return -1;
	}

	iptables_add_rule(r, label);
	socket_timestamping(r);

	g_atomic_int_dec_and_test(&pp->free_ports);
	__C_DBG("%d free ports remaining on interface %s", pp->free_ports,
			sockaddr_print_buf(&spec->local_address.addr));

	return 0;
}

static void release_port(socket_t *r, struct intf_spec *spec) {
	unsigned int port = r->local.port;
	struct port_pool *pp = &spec->port_pool;

	__C_DBG("trying to release port %u", port);

	iptables_del_rule(r);

	if (r->is_foreign) {
		__C_DBG("port %u is foreign so release is not needed");
	} else if (close_socket(r) == 0) {
		__C_DBG("port %u is released", port);
		bit_array_clear(pp->ports_used, port);
		g_atomic_int_inc(&pp->free_ports);
		if ((port & 1) == 0) {
			mutex_lock(&pp->free_list_lock);
			g_queue_push_tail(&pp->free_list, GUINT_TO_POINTER(port));
			mutex_unlock(&pp->free_list_lock);
		}
	} else {
		__C_DBG("port %u is NOT released", port);
	}
}
static void free_port(socket_t *r, struct intf_spec *spec) {
	release_port(r, spec);
	g_slice_free1(sizeof(*r), r);
}



/* puts list of socket_t into "out" */
int __get_consecutive_ports(GQueue *out, unsigned int num_ports, unsigned int wanted_start_port,
		struct intf_spec *spec, const str *label)
{
	int i, cycle = 0;
	socket_t *sk;
	int port;
	struct port_pool *pp;

	if (num_ports == 0)
		return 0;

	pp = &spec->port_pool;

	__C_DBG("wanted_start_port=%d", wanted_start_port);

	if (wanted_start_port > 0) {
		port = wanted_start_port;
		__C_DBG("port=%d", port);
	} else {
		port = g_atomic_int_get(&pp->last_used);
		__C_DBG("before randomization port=%d", port);
#if PORT_RANDOM_MIN && PORT_RANDOM_MAX
		port += PORT_RANDOM_MIN + (ssl_random() % (PORT_RANDOM_MAX - PORT_RANDOM_MIN));
#endif
		__C_DBG("after  randomization port=%d", port);
	}

	// debug msg if port is in the given interval
	if (bit_array_isset(pp->ports_used, port)) {
		__C_DBG("port %d is USED in port pool", port);
		mutex_lock(&pp->free_list_lock);
		unsigned int fport = GPOINTER_TO_UINT(g_queue_pop_head(&pp->free_list));
		mutex_unlock(&pp->free_list_lock);
		if (fport) {
			port = fport;
			__C_DBG("Picked port %u from free list", port);
		}
	} else {
		__C_DBG("port %d is NOT USED in port pool", port);
	}

	while (1) {
		__C_DBG("cycle=%d, port=%d", cycle, port);
		if (!wanted_start_port) {
			if (port < pp->min)
				port = pp->min;
			if ((port & 1))
				port++;
		}

		for (i = 0; i < num_ports; i++) {
			sk = g_slice_alloc0(sizeof(*sk));
			// fd=0 is a valid file descriptor that may be closed
			// accidentally by free_port if previously bounded
			sk->fd = -1;
			g_queue_push_tail(out, sk);

			if (!wanted_start_port && port > pp->max) {
				port = 0;
				cycle++;
				goto release_restart;
			}

			if (get_port(sk, port++, spec, label))
				goto release_restart;
		}
		break;

release_restart:
		while ((sk = g_queue_pop_head(out)))
			free_port(sk, spec);

		if (cycle >= 2 || wanted_start_port > 0)
			goto fail;
	}

	/* success */
	g_atomic_int_set(&pp->last_used, port);

	__C_DBG("Opened ports %u.. on interface %s for media relay",
		((socket_t *) out->head->data)->local.port, sockaddr_print_buf(&spec->local_address.addr));
	return 0;

fail:
	ilog(LOG_ERR, "Failed to get %u consecutive ports on interface %s for media relay (last error: %s)",
			num_ports, sockaddr_print_buf(&spec->local_address.addr), strerror(errno));
	return -1;
}

/* puts a list of "struct intf_list" into "out", containing socket_t list */
int get_consecutive_ports(GQueue *out, unsigned int num_ports, const struct logical_intf *log,
		const str *label)
{
	GList *l;
	struct intf_list *il;
	const struct local_intf *loc;

	for (l = log->list.head; l; l = l->next) {
		loc = l->data;

		il = g_slice_alloc0(sizeof(*il));
		il->local_intf = loc;
		g_queue_push_tail(out, il);
		if (G_LIKELY(!__get_consecutive_ports(&il->list, num_ports, 0, loc->spec, label))) {
			// success - found available ports on local interfaces, so far
			continue;
		}

		// error - found at least one local interface with no ports available
		goto error_ports;
	}

	return 0;

error_ports:
	ilog(LOG_ERR, "Failed to get %d consecutive ports on all locals of logical '"STR_FORMAT"'",
		num_ports, STR_FMT(&log->name));

	// free all ports alloc'ed so far for the previous local interfaces
	while ((il = g_queue_pop_head(out))) {
		free_socket_intf_list(il);
	}

	return -1;
}
void free_socket_intf_list(struct intf_list *il) {
	socket_t *sock;

	while ((sock = g_queue_pop_head(&il->list)))
		free_port(sock, il->local_intf->spec);
	g_slice_free1(sizeof(*il), il);
}
void free_intf_list(struct intf_list *il) {
	g_queue_clear(&il->list);
	g_slice_free1(sizeof(*il), il);
}



/* called lock-free */
static void stream_fd_closed(int fd, void *p, uintptr_t u) {
	struct stream_fd *sfd = p;
	struct call *c;
	int i;
	socklen_t j;

	assert(sfd->socket.fd == fd);
	c = sfd->call;
	if (!c)
		return;

	j = sizeof(i);
	i = 0;
	// coverity[check_return : FALSE]
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &i, &j);
	ilog(LOG_WARNING, "Read error on media socket: %i (%s) -- closing call", i, strerror(i));

	call_destroy(c);
}



/* returns: 0 = not a muxed stream, 1 = muxed, RTP, 2 = muxed, RTCP */
static int rtcp_demux(const str *s, struct call_media *media) {
	if (!MEDIA_ISSET(media, RTCP_MUX))
		return 0;
	return rtcp_demux_is_rtcp(s) ? 2 : 1;
}

static int call_avp2savp_rtp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	return rtp_avp2savp(s, &stream->crypto, ssrc_ctx);
}
static int call_avp2savp_rtcp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	return rtcp_avp2savp(s, &stream->crypto, ssrc_ctx);
}
static int call_savp2avp_rtp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	return rtp_savp2avp(s, &stream->selected_sfd->crypto, ssrc_ctx);
}
static int call_savp2avp_rtcp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	return rtcp_savp2avp(s, &stream->selected_sfd->crypto, ssrc_ctx);
}


static int __k_null(struct rtpengine_srtp *s, struct packet_stream *stream) {
	*s = __res_null;
	return 0;
}
static int __k_srtp_crypt(struct rtpengine_srtp *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	if (!c->params.crypto_suite)
		return -1;

	*s = (struct rtpengine_srtp) {
		.cipher		= c->params.crypto_suite->kernel_cipher,
		.hmac		= c->params.crypto_suite->kernel_hmac,
		.mki_len	= c->params.mki_len,
		.last_index	= ssrc_ctx ? ssrc_ctx->srtp_index : 0,
		.auth_tag_len	= c->params.crypto_suite->srtp_auth_tag,
	};
	if (c->params.mki_len)
		memcpy(s->mki, c->params.mki, c->params.mki_len);
	memcpy(s->master_key, c->params.master_key, c->params.crypto_suite->master_key_len);
	s->master_key_len = c->params.crypto_suite->master_key_len;
	s->session_key_len = c->params.crypto_suite->session_key_len;
	memcpy(s->master_salt, c->params.master_salt, c->params.crypto_suite->master_salt_len);

	if (c->params.session_params.unencrypted_srtp)
		s->cipher = REC_NULL;
	if (c->params.session_params.unauthenticated_srtp)
		s->auth_tag_len = 0;

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


/* called with in_lock held */
void kernelize(struct packet_stream *stream) {
	struct rtpengine_target_info reti;
	struct call *call = stream->call;
	struct packet_stream *sink = NULL;
	const char *nk_warn_msg;
	int non_forwarding = 0;

	if (PS_ISSET(stream, KERNELIZED))
		return;
	if (call->recording != NULL && !selected_recording_method->kernel_support)
		goto no_kernel;
	if (!kernel.is_wanted)
		goto no_kernel;
	nk_warn_msg = "interface to kernel module not open";
	if (!kernel.is_open)
		goto no_kernel_warn;
	if (!PS_ISSET(stream, RTP)) {
		if (PS_ISSET(stream, RTCP) && PS_ISSET(stream, STRICT_SOURCE))
			non_forwarding = 1; // use the kernel's source checking capability
		else
			goto no_kernel;
	}
	if (!stream->selected_sfd)
		goto no_kernel;
	if (stream->media->monologue->block_media || call->block_media)
		goto no_kernel;

        ilog(LOG_INFO, "Kernelizing media stream: %s%s:%d%s",
			FMT_M(sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port));

	sink = packet_stream_sink(stream);
	if (!sink) {
		ilog(LOG_WARNING, "Attempt to kernelize stream without sink");
		goto no_kernel;
	}

	__determine_handler(stream, sink);

	if (is_addr_unspecified(&sink->advertised_endpoint.address)
			|| !sink->advertised_endpoint.port)
		goto no_kernel;
	nk_warn_msg = "protocol not supported by kernel module";
	if (!stream->handler->in->kernel
			|| !stream->handler->out->kernel)
		goto no_kernel_warn;

	ZERO(reti);

	if (PS_ISSET2(stream, STRICT_SOURCE, MEDIA_HANDOVER)) {
		mutex_lock(&stream->out_lock);
		__re_address_translate_ep(&reti.expected_src, &stream->endpoint);
		mutex_unlock(&stream->out_lock);
		if (PS_ISSET(stream, STRICT_SOURCE))
			reti.src_mismatch = MSM_DROP;
		else if (PS_ISSET(stream, MEDIA_HANDOVER))
			reti.src_mismatch = MSM_PROPAGATE;
	}

	mutex_lock(&sink->out_lock);

	__re_address_translate_ep(&reti.local, &stream->selected_sfd->socket.local);
	reti.tos = call->tos;
	reti.rtcp_mux = MEDIA_ISSET(stream->media, RTCP_MUX);
	reti.dtls = MEDIA_ISSET(stream->media, DTLS);
	reti.stun = stream->media->ice_agent ? 1 : 0;
	reti.non_forwarding = non_forwarding;

	__re_address_translate_ep(&reti.dst_addr, &sink->endpoint);
	__re_address_translate_ep(&reti.src_addr, &sink->selected_sfd->socket.local);
	if (stream->ssrc_in) {
		reti.ssrc = htonl(stream->ssrc_in->parent->h.ssrc);
		if (MEDIA_ISSET(stream->media, TRANSCODE)) {
			reti.ssrc_out = htonl(stream->ssrc_in->ssrc_map_out);
			reti.transcoding = 1;
		}
	}

	stream->handler->in->kernel(&reti.decrypt, stream);
	stream->handler->out->kernel(&reti.encrypt, sink);

	mutex_unlock(&sink->out_lock);

	nk_warn_msg = "encryption cipher or HMAC not supported by kernel module";
	if (!reti.encrypt.cipher || !reti.encrypt.hmac)
		goto no_kernel_warn;
	nk_warn_msg = "decryption cipher or HMAC not supported by kernel module";
	if (!reti.decrypt.cipher || !reti.decrypt.hmac)
		goto no_kernel_warn;

	ZERO(stream->kernel_stats);

	if (stream->media->protocol && stream->media->protocol->rtp) {
		GList *values, *l;
		struct rtp_stats *rs;

		reti.rtp = 1;
		values = g_hash_table_get_values(stream->rtp_stats);
		values = g_list_sort(values, __rtp_stats_pt_sort);
		for (l = values; l; l = l->next) {
			if (reti.num_payload_types >= G_N_ELEMENTS(reti.payload_types)) {
				ilog(LOG_WARNING, "Too many RTP payload types for kernel module");
				break;
			}
			rs = l->data;
			// only add payload types that are passthrough
			struct codec_handler *ch = codec_handler_get(stream->media, rs->payload_type);
			if (!ch->kernelize)
				continue;
			reti.payload_types[reti.num_payload_types++] = rs->payload_type;
		}
		g_list_free(values);
	}

	recording_stream_kernel_info(stream, &reti);

	kernel_add_stream(&reti, 0);
	PS_SET(stream, KERNELIZED);

	return;

no_kernel_warn:
	ilog(LOG_WARNING, "No support for kernel packet forwarding available (%s)", nk_warn_msg);
no_kernel:
	PS_SET(stream, KERNELIZED);
	PS_SET(stream, NO_KERNEL_SUPPORT);
}

/* must be called with in_lock held or call->master_lock held in W */
void __unkernelize(struct packet_stream *p) {
	struct re_address rea;

	if (!PS_ISSET(p, KERNELIZED))
		return;
	if (PS_ISSET(p, NO_KERNEL_SUPPORT))
		return;

	if (kernel.is_open) {
		__re_address_translate_ep(&rea, &p->selected_sfd->socket.local);
		kernel_del_stream(&rea);
	}

	PS_CLEAR(p, KERNELIZED);
}


void __stream_unconfirm(struct packet_stream *ps) {
	__unkernelize(ps);
	if (!MEDIA_ISSET(ps->media, ASYMMETRIC))
		PS_CLEAR(ps, CONFIRMED);
	ps->handler = NULL;
}
static void stream_unconfirm(struct packet_stream *ps) {
	if (!ps)
		return;
	mutex_lock(&ps->in_lock);
	__stream_unconfirm(ps);
	mutex_unlock(&ps->in_lock);
}
void unkernelize(struct packet_stream *ps) {
	if (!ps)
		return;
	mutex_lock(&ps->in_lock);
	__unkernelize(ps);
	mutex_unlock(&ps->in_lock);
}



const struct streamhandler *determine_handler(const struct transport_protocol *in_proto,
		struct call_media *out_media, int must_recrypt)
{
	const struct transport_protocol *out_proto = out_media->protocol;
	const struct streamhandler * const *sh_pp, *sh;
	const struct streamhandler * const * const *matrix;

	matrix = __sh_matrix;
	if (must_recrypt)
		matrix = __sh_matrix_recrypt;

	sh_pp = matrix[in_proto->index];
	if (!sh_pp)
		goto err;

	// special handling for RTP/AVP with advertised a=rtcp-fb
	int out_proto_idx = out_proto->index;
	if (out_media && MEDIA_ISSET(out_media, RTCP_FB)) {
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
static void __determine_handler(struct packet_stream *in, const struct packet_stream *out) {
	const struct transport_protocol *in_proto, *out_proto;
	int must_recrypt = 0;

	if (in->handler)
		return;
	if (MEDIA_ISSET(in->media, PASSTHRU))
		goto noop;

	in_proto = in->media->protocol;
	out_proto = out->media->protocol;

	if (!in_proto)
		goto err;
	if (!out_proto)
		goto err;

	if (MEDIA_ISSET(in->media, DTLS) || MEDIA_ISSET(out->media, DTLS))
		must_recrypt = 1;
	else if (in->call->recording)
		must_recrypt = 1;
	else if (in_proto->srtp && out_proto->srtp
			&& in->selected_sfd && out->selected_sfd
			&& (crypto_params_cmp(&in->crypto.params, &out->selected_sfd->crypto.params)
				|| crypto_params_cmp(&out->crypto.params, &in->selected_sfd->crypto.params)))
		must_recrypt = 1;

	in->handler = determine_handler(in_proto, out->media, must_recrypt);
	return;

err:
	ilog(LOG_WARNING, "Unknown transport protocol encountered");
noop:
	in->handler = &__sh_noop;
	return;
}


// check and update SSRC pointers
static void __stream_ssrc(struct packet_stream *in_srtp, struct packet_stream *out_srtp, u_int32_t ssrc_bs,
		struct ssrc_ctx **ssrc_in_p, struct ssrc_ctx **ssrc_out_p, struct ssrc_hash *ssrc_hash)
{
	u_int32_t in_ssrc = ntohl(ssrc_bs);
	u_int32_t out_ssrc;

	// input direction
	mutex_lock(&in_srtp->in_lock);

	(*ssrc_in_p) = in_srtp->ssrc_in;
	if (*ssrc_in_p)
		obj_hold(&(*ssrc_in_p)->parent->h);
	if (G_UNLIKELY(!(*ssrc_in_p) || (*ssrc_in_p)->parent->h.ssrc != in_ssrc)) {
		// SSRC mismatch - get the new entry
		if (*ssrc_in_p)
			obj_put(&(*ssrc_in_p)->parent->h);
		if (in_srtp->ssrc_in)
			obj_put(&in_srtp->ssrc_in->parent->h);
		(*ssrc_in_p) = in_srtp->ssrc_in =
			get_ssrc_ctx(in_ssrc, ssrc_hash, SSRC_DIR_INPUT);
		obj_hold(&in_srtp->ssrc_in->parent->h);

		// might have created a new entry, which would have a new random
		// ssrc_map_out. we don't need this if we're not transcoding
		if (!MEDIA_ISSET(in_srtp->media, TRANSCODE))
			(*ssrc_in_p)->ssrc_map_out = in_ssrc;
	}

	mutex_unlock(&in_srtp->in_lock);

	// out direction
	out_ssrc = (*ssrc_in_p)->ssrc_map_out;
	mutex_lock(&out_srtp->out_lock);

	(*ssrc_out_p) = out_srtp->ssrc_out;
	if (*ssrc_out_p)
		obj_hold(&(*ssrc_out_p)->parent->h);
	if (G_UNLIKELY(!(*ssrc_out_p) || (*ssrc_out_p)->parent->h.ssrc != out_ssrc)) {
		// SSRC mismatch - get the new entry
		if (*ssrc_out_p)
			obj_put(&(*ssrc_out_p)->parent->h);
		if (out_srtp->ssrc_out)
			obj_put(&out_srtp->ssrc_out->parent->h);
		(*ssrc_out_p) = out_srtp->ssrc_out =
			get_ssrc_ctx(out_ssrc, ssrc_hash, SSRC_DIR_OUTPUT);
		obj_hold(&out_srtp->ssrc_out->parent->h);

		// reverse SSRC mapping
		(*ssrc_out_p)->ssrc_map_out = in_ssrc;
	}

	mutex_unlock(&out_srtp->out_lock);
}


// returns: 0 = packet processed by other protocol hander; -1 = packet not handled, proceed;
// 1 = same as 0, but stream can be kernelized
static int media_demux_protocols(struct packet_handler_ctx *phc) {
	if (MEDIA_ISSET(phc->mp.media, DTLS) && is_dtls(&phc->s)) {
		mutex_lock(&phc->mp.stream->in_lock);
		int ret = dtls(phc->mp.sfd, &phc->s, &phc->mp.fsin);
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
		else /* not an stun packet */
			;
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
			ilog(LOG_WARNING, "More than %d duplicate packets detected, dropping packet "
					"to avoid potential loop", RTP_LOOP_MAX_COUNT);
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



// in_srtp and out_srtp are set to point to the SRTP contexts to use
// sink is set to where to forward the packet to
static void media_packet_rtcp_demux(struct packet_handler_ctx *phc)
{
	phc->in_srtp = phc->mp.stream;
	phc->sink = phc->mp.stream->rtp_sink;
	if (!phc->sink && PS_ISSET(phc->mp.stream, RTCP)) {
		phc->sink = phc->mp.stream->rtcp_sink;
		phc->rtcp = 1;
	}
	else if (phc->mp.stream->rtcp_sink) {
		int muxed_rtcp = rtcp_demux(&phc->s, phc->mp.media);
		if (muxed_rtcp == 2) {
			phc->sink = phc->mp.stream->rtcp_sink;
			phc->rtcp = 1;
			phc->in_srtp = phc->mp.stream->rtcp_sibling; // use RTCP SRTP context
		}
	}
	phc->out_srtp = phc->sink;
	if (phc->rtcp && phc->sink && phc->sink->rtcp_sibling)
		phc->out_srtp = phc->sink->rtcp_sibling; // use RTCP SRTP context
}


static void media_packet_rtp(struct packet_handler_ctx *phc)
{
	phc->payload_type = -1;

	if (G_UNLIKELY(!phc->mp.media->protocol))
		return;
	if (G_UNLIKELY(!phc->mp.media->protocol->rtp))
		return;

	if (G_LIKELY(!phc->rtcp && !rtp_payload(&phc->mp.rtp, &phc->mp.payload, &phc->s))) {
		rtp_padding(phc->mp.rtp, &phc->mp.payload);

		if (G_LIKELY(phc->out_srtp != NULL))
			__stream_ssrc(phc->in_srtp, phc->out_srtp, phc->mp.rtp->ssrc, &phc->mp.ssrc_in,
					&phc->mp.ssrc_out, phc->mp.call->ssrc_hash);

		// check the payload type
		// XXX redundant between SSRC handling and codec_handler stuff -> combine
		phc->payload_type = (phc->mp.rtp->m_pt & 0x7f);
		if (G_LIKELY(phc->mp.ssrc_in))
			payload_tracker_add(&phc->mp.ssrc_in->tracker, phc->payload_type);

		// XXX yet another hash table per payload type -> combine
		struct rtp_stats *rtp_s = g_atomic_pointer_get(&phc->mp.stream->rtp_stats_cache);
		if (G_UNLIKELY(!rtp_s) || G_UNLIKELY(rtp_s->payload_type != phc->payload_type))
			rtp_s = g_hash_table_lookup(phc->mp.stream->rtp_stats, &phc->payload_type);
		if (!rtp_s) {
			ilog(LOG_WARNING | LOG_FLAG_LIMIT,
					"RTP packet with unknown payload type %u received", phc->payload_type);
			atomic64_inc(&phc->mp.stream->stats.errors);
			atomic64_inc(&rtpe_statsps.errors);
		}
		else {
			atomic64_inc(&rtp_s->packets);
			atomic64_add(&rtp_s->bytes, phc->s.len);
			g_atomic_pointer_set(&phc->mp.stream->rtp_stats_cache, rtp_s);
		}
	}
	else if (phc->rtcp && !rtcp_payload(&phc->mp.rtcp, NULL, &phc->s)) {
		if (G_LIKELY(phc->out_srtp != NULL))
			__stream_ssrc(phc->in_srtp, phc->out_srtp, phc->mp.rtcp->ssrc, &phc->mp.ssrc_in,
					&phc->mp.ssrc_out, phc->mp.call->ssrc_hash);
	}
}


static int media_packet_decrypt(struct packet_handler_ctx *phc)
{
	mutex_lock(&phc->in_srtp->in_lock);
	__determine_handler(phc->in_srtp, phc->sink);

	// XXX use an array with index instead of if/else
	if (G_LIKELY(!phc->rtcp)) {
		phc->decrypt_func = phc->in_srtp->handler->in->rtp_crypt;
		phc->encrypt_func = phc->in_srtp->handler->out->rtp_crypt;
	}
	else {
		phc->decrypt_func = phc->in_srtp->handler->in->rtcp_crypt;
		phc->encrypt_func = phc->in_srtp->handler->out->rtcp_crypt;
		phc->rtcp_filter = phc->in_srtp->handler->in->rtcp_filter;
	}

	/* return values are: 0 = forward packet, -1 = error/dont forward,
	 * 1 = forward and push update to redis */
	int ret = 0;
	if (phc->decrypt_func) {
		str ori_s = phc->s;
		ret = phc->decrypt_func(&phc->s, phc->in_srtp, phc->mp.sfd, &phc->mp.fsin, &phc->mp.tv, phc->mp.ssrc_in);
		// XXX for stripped auth tag and duplicate invokations of rtp_payload
		// XXX transcoder uses phc->mp.payload
		phc->mp.payload.len -= ori_s.len - phc->s.len;
	}

	mutex_unlock(&phc->in_srtp->in_lock);

	if (ret == 1) {
		phc->update = 1;
		ret = 0;
	}
	return ret;
}

int media_packet_encrypt(rewrite_func encrypt_func, struct packet_stream *out, struct media_packet *mp) {
	int ret = 0x00; // 0x01 = error, 0x02 = update

	if (!encrypt_func)
		return 0x00;

	mutex_lock(&out->out_lock);

	for (GList *l = mp->packets_out.head; l; l = l->next) {
		struct codec_packet *p = l->data;
		int encret = encrypt_func(&p->s, out, NULL, NULL, NULL, mp->ssrc_out);
		if (encret == 1)
			ret |= 0x02;
		else if (encret != 0)
			ret |= 0x01;
	}

	mutex_unlock(&out->out_lock);

	return ret;
}

static int __media_packet_encrypt(struct packet_handler_ctx *phc) {
	int ret = media_packet_encrypt(phc->encrypt_func, phc->out_srtp, &phc->mp);
	if (ret & 0x02)
		phc->update = 1;
	return (ret & 0x01) ? -1 : 0;
}



// returns: 0 = OK, forward packet; -1 = drop packet
static int media_packet_address_check(struct packet_handler_ctx *phc)
{
	struct endpoint endpoint;
	int ret = 0;

	mutex_lock(&phc->mp.stream->in_lock);

	/* we're OK to (potentially) use the source address of this packet as destination
	 * in the other direction. */
	/* if the other side hasn't been signalled yet, just forward the packet */
	if (!PS_ISSET(phc->mp.stream, FILLED)) {
		__C_DBG("stream %s:%d not FILLED", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		goto out;
	}

	/* do not pay attention to source addresses of incoming packets for asymmetric streams */
	if (MEDIA_ISSET(phc->mp.media, ASYMMETRIC) || rtpe_config.endpoint_learning == EL_OFF)
		PS_SET(phc->mp.stream, CONFIRMED);

	/* confirm sink for unidirectional streams in order to kernelize */
	if (MEDIA_ISSET(phc->mp.media, UNIDIRECTIONAL))
		PS_SET(phc->sink, CONFIRMED);

	/* if we have already updated the endpoint in the past ... */
	if (PS_ISSET(phc->mp.stream, CONFIRMED)) {
		/* see if we need to compare the source address with the known endpoint */
		if (PS_ISSET2(phc->mp.stream, STRICT_SOURCE, MEDIA_HANDOVER)) {
			endpoint = phc->mp.fsin;
			mutex_lock(&phc->mp.stream->out_lock);

			int tmp = memcmp(&endpoint, &phc->mp.stream->endpoint, sizeof(endpoint));
			if (tmp && PS_ISSET(phc->mp.stream, MEDIA_HANDOVER)) {
				/* out_lock remains locked */
				ilog(LOG_INFO | LOG_FLAG_LIMIT, "Peer address changed to %s%s%s",
						FMT_M(endpoint_print_buf(&phc->mp.fsin)));
				phc->unkernelize = 1;
				phc->update = 1;
				phc->mp.stream->endpoint = phc->mp.fsin;
				goto update_addr;
			}

			mutex_unlock(&phc->mp.stream->out_lock);

			if (tmp && PS_ISSET(phc->mp.stream, STRICT_SOURCE)) {
				ilog(LOG_INFO | LOG_FLAG_LIMIT, "Drop due to strict-source attribute; "
						"got %s%s:%d%s, "
						"expected %s%s:%d%s",
					FMT_M(sockaddr_print_buf(&endpoint.address), endpoint.port),
					FMT_M(sockaddr_print_buf(&phc->mp.stream->endpoint.address),
					phc->mp.stream->endpoint.port));
				atomic64_inc(&phc->mp.stream->stats.errors);
				ret = -1;
			}
		}
		phc->kernelize = 1;
		goto out;
	}

	const struct endpoint *use_endpoint_confirm = &phc->mp.fsin;

	if (rtpe_config.endpoint_learning == EL_IMMEDIATE)
		goto confirm_now;

	if (rtpe_config.endpoint_learning == EL_HEURISTIC
			&& phc->mp.stream->advertised_endpoint.address.family
			&& phc->mp.stream->advertised_endpoint.port)
	{
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
			if (use_endpoint_confirm->address.family) {
				if (idx == 0) // doesn't get any better than this
					goto confirm_now;
				break;
			}
		}
	}

	/* wait at least 3 seconds after last signal before committing to a particular
	 * endpoint address */
	if (!phc->mp.call->last_signal || rtpe_now.tv_sec <= phc->mp.call->last_signal + 3)
		goto update_peerinfo;

confirm_now:
	phc->kernelize = 1;
	phc->update = 1;

	ilog(LOG_INFO, "Confirmed peer address as %s%s%s", FMT_M(endpoint_print_buf(use_endpoint_confirm)));

	PS_SET(phc->mp.stream, CONFIRMED);

update_peerinfo:
	mutex_lock(&phc->mp.stream->out_lock);
	endpoint = phc->mp.stream->endpoint;
	phc->mp.stream->endpoint = *use_endpoint_confirm;
	if (memcmp(&endpoint, &phc->mp.stream->endpoint, sizeof(endpoint))) {
		phc->unkernelize = 1;
		phc->update = 1;
	}
update_addr:
	mutex_unlock(&phc->mp.stream->out_lock);

	/* check the destination address of the received packet against what we think our
	 * local interface to use is */
	if (phc->mp.stream->selected_sfd && phc->mp.sfd != phc->mp.stream->selected_sfd) {
		ilog(LOG_INFO, "Switching local interface to %s", endpoint_print_buf(&phc->mp.sfd->socket.local));
		phc->mp.stream->selected_sfd = phc->mp.sfd;
		phc->unkernelize = 1;
		phc->update = 1;
	}

out:
	mutex_unlock(&phc->mp.stream->in_lock);

	return ret;
}


static void media_packet_kernel_check(struct packet_handler_ctx *phc) {
	if (PS_ISSET(phc->mp.stream, NO_KERNEL_SUPPORT)) {
		__C_DBG("stream %s:%d NO_KERNEL_SUPPORT", sockaddr_print_buf(&phc->mp.stream->endpoint.address), phc->mp.stream->endpoint.port);
		return;
	}

	if (!PS_ISSET(phc->mp.stream, CONFIRMED)) {
		__C_DBG("stream %s:%d not CONFIRMED", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		return;
	}

	if (!phc->sink) {
		__C_DBG("sink is NULL for stream %s:%d", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		return;
	}

	if (MEDIA_ISSET(phc->sink->media, ASYMMETRIC))
		PS_SET(phc->sink, CONFIRMED);

	if (!PS_ISSET(phc->sink, CONFIRMED)) {
		__C_DBG("sink not CONFIRMED for stream %s:%d",
				sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		return;
	}

	if (!PS_ISSET(phc->sink, FILLED)) {
		__C_DBG("sink not FILLED for stream %s:%d", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
				phc->mp.stream->endpoint.port);
		return;
	}

	mutex_lock(&phc->mp.stream->in_lock);
	kernelize(phc->mp.stream);
	mutex_unlock(&phc->mp.stream->in_lock);
}


static int do_rtcp(struct packet_handler_ctx *phc) {
	int ret = -1;

	GQueue rtcp_list = G_QUEUE_INIT;
	if (rtcp_parse(&rtcp_list, &phc->mp))
		goto out;
	if (phc->rtcp_filter)
		if (phc->rtcp_filter(&phc->mp, &rtcp_list))
			goto out;

	// queue for output
	codec_add_raw_packet(&phc->mp);
	ret = 0;

out:
	rtcp_list_free(&rtcp_list);
	return ret;
}


// appropriate locks must be held
int media_socket_dequeue(struct media_packet *mp, struct packet_stream *sink) {
	struct codec_packet *p;
	while ((p = g_queue_pop_head(&mp->packets_out)))
		send_timer_push(sink->send_timer, p);
	return 0;
}


/* called lock-free */
static int stream_packet(struct packet_handler_ctx *phc) {
/**
 * Incoming packets:
 * - sfd->socket.local: the local IP/port on which the packet arrived
 * - sfd->stream->endpoint: adjusted/learned IP/port from where the packet
 *   was sent
 * - sfd->stream->advertised_endpoint: the unadjusted IP/port from where the
 *   packet was sent. These are the values present in the SDP
 *
 * Outgoing packets:
 * - sfd->stream->rtp_sink->endpoint: the destination IP/port
 * - sfd->stream->selected_sfd->socket.local: the local source IP/port for the
 *   outgoing packet
 *
 * If the rtpengine runs behind a NAT and local addresses are configured with
 * different advertised endpoints, the SDP would not contain the address from
 * `...->socket.local`, but rather from `sfd->local_intf->spec->address.advertised`
 * (of type `sockaddr_t`). The port will be the same.
 */
/* TODO move the above comments to the data structure definitions, if the above
 * always holds true */
	int ret = 0, handler_ret = 0;

	phc->mp.call = phc->mp.sfd->call;

	rwlock_lock_r(&phc->mp.call->master_lock);

	phc->mp.stream = phc->mp.sfd->stream;
	if (G_UNLIKELY(!phc->mp.stream))
		goto out;
	__C_DBG("Handling packet on: %s:%d", sockaddr_print_buf(&phc->mp.stream->endpoint.address),
			phc->mp.stream->endpoint.port);


	phc->mp.media = phc->mp.stream->media;

	if (!phc->mp.stream->selected_sfd)
		goto out;


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


	// this sets rtcp, in_srtp, out_srtp, and sink
	media_packet_rtcp_demux(phc);

	// this set payload_type, ssrc_in, ssrc_out and mp
	media_packet_rtp(phc);


	/* do we have somewhere to forward it to? */

	if (G_UNLIKELY(!phc->sink || !phc->sink->selected_sfd || !phc->out_srtp
				|| !phc->out_srtp->selected_sfd || !phc->in_srtp->selected_sfd))
	{
		ilog(LOG_WARNING, "RTP packet from %s%s%s discarded", FMT_M(endpoint_print_buf(&phc->mp.fsin)));
		atomic64_inc(&phc->mp.stream->stats.errors);
		atomic64_inc(&rtpe_statsps.errors);
		goto out;
	}


	handler_ret = media_packet_decrypt(phc);

	// If recording pcap dumper is set, then we record the call.
	if (phc->mp.call->recording)
		dump_packet(&phc->mp, &phc->s);

	// ready to process

	phc->mp.raw = phc->s;

	if (phc->rtcp) {
		if (do_rtcp(phc))
			goto drop;
	}
	else {
		struct codec_handler *transcoder = codec_handler_get(phc->mp.media, phc->payload_type);
		// this transfers the packet from 's' to 'packets_out'
		if (transcoder->func(transcoder, &phc->mp))
			goto drop;
	}

	if (G_LIKELY(handler_ret >= 0))
		handler_ret = __media_packet_encrypt(phc);

	if (phc->unkernelize) // for RTCP packet index updates
		unkernelize(phc->mp.stream);


	int address_check = media_packet_address_check(phc);
	if (phc->kernelize)
		media_packet_kernel_check(phc);
	if (address_check)
		goto drop;

	mutex_lock(&phc->sink->out_lock);

	if (!phc->sink->advertised_endpoint.port
			|| (is_addr_unspecified(&phc->sink->advertised_endpoint.address)
				&& !is_trickle_ice_address(&phc->sink->advertised_endpoint))
			|| handler_ret < 0)
	{
		mutex_unlock(&phc->sink->out_lock);
		goto drop;
	}

	ret = media_socket_dequeue(&phc->mp, phc->sink);

	mutex_unlock(&phc->sink->out_lock);

	if (ret == -1) {
		ret = -errno;
                ilog(LOG_DEBUG,"Error when sending message. Error: %s",strerror(errno));
		atomic64_inc(&phc->mp.stream->stats.errors);
		atomic64_inc(&rtpe_statsps.errors);
		goto out;
	}

drop:
	ret = 0;
	// XXX separate stats for received/sent
	atomic64_inc(&phc->mp.stream->stats.packets);
	atomic64_add(&phc->mp.stream->stats.bytes, phc->s.len);
	atomic64_set(&phc->mp.stream->last_packet, rtpe_now.tv_sec);
	atomic64_inc(&rtpe_statsps.packets);
	atomic64_add(&rtpe_statsps.bytes, phc->s.len);

out:
	if (phc->unkernelize) {
		stream_unconfirm(phc->mp.stream);
		stream_unconfirm(phc->mp.stream->rtp_sink);
		stream_unconfirm(phc->mp.stream->rtcp_sink);
	}

	rwlock_unlock_r(&phc->mp.call->master_lock);

	g_queue_clear_full(&phc->mp.packets_out, codec_packet_free);

	if (phc->mp.ssrc_in) {
		obj_put(&phc->mp.ssrc_in->parent->h);
		phc->mp.ssrc_in = NULL;
	}
	if (phc->mp.ssrc_out) {
		obj_put(&phc->mp.ssrc_out->parent->h);
		phc->mp.ssrc_out = NULL;
	}

	return ret;
}


static void stream_fd_readable(int fd, void *p, uintptr_t u) {
	struct stream_fd *sfd = p;
	char buf[RTP_BUFFER_SIZE];
	int ret, iters;
	int update = 0;
	struct call *ca;

	if (sfd->socket.fd != fd)
		goto out;

	log_info_stream_fd(sfd);

	for (iters = 0; ; iters++) {
#if MAX_RECV_ITERS
		if (iters >= MAX_RECV_ITERS) {
			ilog(LOG_ERROR, "Too many packets in UDP receive queue (more than %d), "
					"aborting loop. Dropped packets possible", iters);
			break;
		}
#endif

		struct packet_handler_ctx phc;
		ZERO(phc);
		phc.mp.sfd = sfd;

		ret = socket_recvfrom_ts(&sfd->socket, buf + RTP_BUFFER_HEAD_ROOM, MAX_RTP_PACKET_SIZE,
				&phc.mp.fsin, &phc.mp.tv);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			stream_fd_closed(fd, sfd, 0);
			goto done;
		}
		if (ret >= MAX_RTP_PACKET_SIZE)
			ilog(LOG_WARNING, "UDP packet possibly truncated");

		str_init_len(&phc.s, buf + RTP_BUFFER_HEAD_ROOM, ret);
		ret = stream_packet(&phc);
		if (G_UNLIKELY(ret < 0))
			ilog(LOG_WARNING, "Write error on media socket: %s", strerror(-ret));
		else if (phc.update)
			update = 1;
	}

out:
	ca = sfd->call ? : NULL;

	if (ca && update) {
		redis_update_onekey(ca, rtpe_redis_write);
	}
done:
	log_info_clear();
}




static void stream_fd_free(void *p) {
	struct stream_fd *f = p;

	release_port(&f->socket, f->local_intf->spec);
	crypto_cleanup(&f->crypto);
	dtls_connection_cleanup(&f->dtls);

	obj_put(f->call);
}

struct stream_fd *stream_fd_new(socket_t *fd, struct call *call, const struct local_intf *lif) {
	struct stream_fd *sfd;
	struct poller_item pi;

	sfd = obj_alloc0("stream_fd", sizeof(*sfd), stream_fd_free);
	sfd->unique_id = g_queue_get_length(&call->stream_fds);
	sfd->socket = *fd;
	sfd->call = obj_get(call);
	sfd->local_intf = lif;
	g_queue_push_tail(&call->stream_fds, sfd); /* hand over ref */
	g_slice_free1(sizeof(*fd), fd); /* moved into sfd, thus free */

	__C_DBG("stream_fd_new localport=%d", sfd->socket.local.port);

	if (!sfd->socket.is_foreign) {
		ZERO(pi);
		pi.fd = sfd->socket.fd;
		pi.obj = &sfd->obj;
		pi.readable = stream_fd_readable;
		pi.closed = stream_fd_closed;

		if (poller_add_item(rtpe_poller, &pi))
			ilog(LOG_ERR, "Failed to add stream_fd to poller");
	}

	return sfd;
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
