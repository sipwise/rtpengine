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


#ifndef PORT_RANDOM_MIN
#define PORT_RANDOM_MIN 6
#define PORT_RANDOM_MAX 20
#endif

#ifndef MAX_RECV_ITERS
#define MAX_RECV_ITERS 50
#endif


typedef int (*rewrite_func)(str *, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);


struct streamhandler_io {
	rewrite_func	rtp;
	rewrite_func	rtcp;
	int		(*kernel)(struct rtpengine_srtp *, struct packet_stream *);
};
struct streamhandler {
	const struct streamhandler_io	*in;
	const struct streamhandler_io	*out;
};


static void determine_handler(struct packet_stream *in, const struct packet_stream *out);

static int __k_null(struct rtpengine_srtp *s, struct packet_stream *);
static int __k_srtp_encrypt(struct rtpengine_srtp *s, struct packet_stream *);
static int __k_srtp_decrypt(struct rtpengine_srtp *s, struct packet_stream *);

static int call_noop_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_avp2savp_rtp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_savp2avp_rtp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_avp2savp_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_savp2avp_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
static int call_avpf2avp_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
//static int call_avpf2savp_rtcp(str *s, struct packet_stream *);
static int call_savpf2avp_rtcp(str *s, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);
//static int call_savpf2savp_rtcp(str *s, struct packet_stream *);





static const struct streamhandler_io __shio_noop = {
	.kernel		= __k_null,
};
static const struct streamhandler_io __shio_noop_rtp = {
	.kernel		= __k_null,
	.rtcp		= call_noop_rtcp,
};
static const struct streamhandler_io __shio_decrypt = {
	.kernel		= __k_srtp_decrypt,
	.rtp		= call_savp2avp_rtp,
	.rtcp		= call_savp2avp_rtcp,
};
static const struct streamhandler_io __shio_encrypt = {
	.kernel		= __k_srtp_encrypt,
	.rtp		= call_avp2savp_rtp,
	.rtcp		= call_avp2savp_rtcp,
};
static const struct streamhandler_io __shio_avpf_strip = {
	.kernel		= __k_null,
	.rtcp		= call_avpf2avp_rtcp,
};
static const struct streamhandler_io __shio_decrypt_avpf_strip = {
	.kernel		= __k_srtp_decrypt,
	.rtp		= call_savp2avp_rtp,
	.rtcp		= call_savpf2avp_rtcp,
};

/* ********** */

static const struct streamhandler __sh_noop = {
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
	[PROTO_RTP_SAVP]		= &__sh_noop_rtp,
	[PROTO_RTP_SAVPF]		= &__sh_noop_rtp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_noop_rtp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_noop_rtp,
	[PROTO_UDPTL]			= &__sh_noop,
};
static const struct streamhandler * const __sh_matrix_in_rtp_savpf[__PROTO_LAST] = {
	[PROTO_RTP_AVP]			= &__sh_savpf2avp,
	[PROTO_RTP_AVPF]		= &__sh_savp2avp,
	[PROTO_RTP_SAVP]		= &__sh_savpf2savp,
	[PROTO_RTP_SAVPF]		= &__sh_noop_rtp,
	[PROTO_UDP_TLS_RTP_SAVP]	= &__sh_savpf2savp,
	[PROTO_UDP_TLS_RTP_SAVPF]	= &__sh_noop,
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
static const struct streamhandler * const __sh_matrix_noop[__PROTO_LAST] = {
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


static GHashTable *__logical_intf_name_family_hash;
static GHashTable *__intf_spec_addr_type_hash;
static GHashTable *__local_intf_addr_type_hash; // hash of lists
static GQueue __preferred_lists_for_family[__SF_LAST];

static __thread unsigned int selection_index = 0;
static __thread unsigned int selection_count = 0;


/* checks for free no_ports on a local interface */
static int has_free_ports_loc(struct local_intf *loc, unsigned int num_ports) {
	if (loc == NULL) {
		ilog(LOG_ERR, "has_free_ports_loc - NULL local interface");
		return 0;
	}

	if (num_ports > loc->spec->port_pool.free_ports) {
		ilog(LOG_ERR, "Didn't found %d ports available for %.*s/%s",
			num_ports, loc->logical->name.len, loc->logical->name.s,
			sockaddr_print_buf(&loc->spec->local_address.addr));
		return 0;
	}

	__C_DBG("Found %d ports available for %.*s/%s from total of %d free ports",
		num_ports, loc->logical->name.len, loc->logical->name.s,
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
static struct logical_intf* run_round_robin_calls(GQueue *q, unsigned int num_ports) {
	struct logical_intf *log = NULL;
	volatile unsigned int nr_tries = 0;
	unsigned int nr_logs = 0;

	nr_logs = g_queue_get_length(q);

select_log:
	// choose the next logical interface
	log = g_queue_peek_nth(q, selection_index);
	if (!log) {
		if (selection_index == 0)
			return NULL;
		selection_index = 0;
		goto select_log;
	}
	__C_DBG("Trying %d ports on logical interface %.*s", num_ports, log->name.len, log->name.s);

	// test for free ports for the logical interface
	if(!has_free_ports_log_all(log, num_ports)) {
		// count the logical interfaces tried
		nr_tries++;

		// the logical interface selected has no ports available, try another one
		selection_index ++;
		selection_index = selection_index % nr_logs;

		// all the logical interfaces have no ports available
		if (nr_tries == nr_logs) {
			ilog(LOG_ERR, "No logical interface with free ports found; fallback to default behaviour");
			return NULL;
		}

		goto select_log;
	}

	__C_DBG("Round Robin Calls algorithm found logical %.*s; count=%u index=%u", log->name.len, log->name.s, selection_count, selection_index);

	// 1 stream	=> 2 x get_logical_interface calls at offer
	// 2 streams	=> 4 x get_logical_interface calls at offer
	selection_count ++;
	if (selection_count % (num_ports / 2) == 0) {
		selection_count = 0;
		selection_index ++;
		selection_index = selection_index % nr_logs;
	}

	return log;
}

struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam, int num_ports) {
	struct logical_intf d, *log = NULL;

	__C_DBG("Get logical interface for %d ports", num_ports);

	if (G_UNLIKELY(!name || !name->s ||
	   str_cmp(name, ALGORITHM_ROUND_ROBIN_CALLS) == 0)) {

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

		// round-robin-calls behaviour - return next interface with free ports
		if (name && name->s && str_cmp(name, ALGORITHM_ROUND_ROBIN_CALLS) == 0 && num_ports > 0) {
			log = run_round_robin_calls(q, num_ports);
			if (log) {
				__C_DBG("Choose logical interface %.*s because of direction %.*s",
					log->name.len, log->name.s,
					name->len, name->s);
			} else {
				__C_DBG("Choose logical interface NULL because of direction %.*s",
					name->len, name->s);
			}
			return log;
		}

		// default behaviour - return first logical interface
		return q->head ? q->head->data : NULL;
	}

	d.name = *name;
	d.preferred_family = fam;

	log = g_hash_table_lookup(__logical_intf_name_family_hash, &d);
	if (log) {
		__C_DBG("Choose logical interface %.*s because of direction %.*s",
			log->name.len, log->name.s,
			name->len, name->s);
	} else {
		__C_DBG("Choose logical interface NULL because of direction %.*s",
			name->len, name->s);
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


static GQueue *__interface_list_for_family(sockfamily_t *fam) {
	return &__preferred_lists_for_family[fam->idx];
}
static void __interface_append(struct intf_config *ifa, sockfamily_t *fam) {
	struct logical_intf *lif;
	GQueue *q;
	struct local_intf *ifc;
	struct intf_spec *spec;

	lif = get_logical_interface(&ifa->name, fam, 0);

	if (!lif) {
		lif = g_slice_alloc0(sizeof(*lif));
		lif->name = ifa->name;
		lif->preferred_family = fam;
		lif->addr_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);
		g_hash_table_insert(__logical_intf_name_family_hash, lif, lif);
		if (ifa->local_address.addr.family == fam) {
			q = __interface_list_for_family(fam);
			g_queue_push_tail(q, lif);
		}
	}

	spec = g_hash_table_lookup(__intf_spec_addr_type_hash, &ifa->local_address);
	if (!spec) {
		spec = g_slice_alloc0(sizeof(*spec));
		spec->local_address = ifa->local_address;
		spec->port_pool.min = ifa->port_min;
		spec->port_pool.max = ifa->port_max;
		spec->port_pool.free_ports = spec->port_pool.max - spec->port_pool.min + 1;
		g_hash_table_insert(__intf_spec_addr_type_hash, &spec->local_address, spec);
	}

	ifc = uid_slice_alloc(ifc, &lif->list);
	ice_foundation(&ifc->ice_foundation);
	ifc->advertised_address = ifa->advertised_address;
	ifc->spec = spec;
	ifc->logical = lif;

	g_hash_table_insert(lif->addr_hash, &spec->local_address, ifc);

	__insert_local_intf_addr_type(&spec->local_address, ifc);
	__insert_local_intf_addr_type(&ifc->advertised_address, ifc);
}

void interfaces_init(GQueue *interfaces) {
	int i;
	GList *l;
	struct intf_config *ifa;
	sockfamily_t *fam;

	/* init everything */
	__logical_intf_name_family_hash = g_hash_table_new(__name_family_hash, __name_family_eq);
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



/* XXX family specific? unify? */
static int get_port6(socket_t *r, unsigned int port, struct intf_spec *spec) {
	if (open_socket(r, SOCK_DGRAM, port, &spec->local_address.addr))
		return -1;
	socket_timestamping(r);
	return 0;
}

static int get_port(socket_t *r, unsigned int port, struct intf_spec *spec) {
	int ret;
	struct port_pool *pp;

	__C_DBG("attempting to open port %u", port);

	pp = &spec->port_pool;

	if (bit_array_set(pp->ports_used, port)) {
		__C_DBG("port %d in use", port);
		return -1;
	}
	__C_DBG("port %d locked", port);

	ret = get_port6(r, port, spec);

	if (ret) {
		__C_DBG("couldn't open port %d", port);
		bit_array_clear(pp->ports_used, port);
		return ret;
	}

	g_atomic_int_dec_and_test(&pp->free_ports);
	__C_DBG("%d free ports remaining on interface %s", pp->free_ports,
			sockaddr_print_buf(&spec->local_address.addr));

	return 0;
}

static void release_port(socket_t *r, struct intf_spec *spec) {
	unsigned int port = r->local.port;

	__C_DBG("trying to release port %u", port);

	if (close_socket(r) == 0) {
		__C_DBG("port %u is released", port);
		bit_array_clear(spec->port_pool.ports_used, port);
		g_atomic_int_inc(&spec->port_pool.free_ports);
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
		struct intf_spec *spec)
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
	} else {
		__C_DBG("port %d is NOOT USED in port pool", port);
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

			if (get_port(sk, port++, spec))
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
int get_consecutive_ports(GQueue *out, unsigned int num_ports, const struct logical_intf *log) {
	GList *l;
	struct intf_list *il;
	const struct local_intf *loc;

	for (l = log->list.head; l; l = l->next) {
		loc = l->data;

		il = g_slice_alloc0(sizeof(*il));
		il->local_intf = loc;
		g_queue_push_tail(out, il);
		if (G_LIKELY(!__get_consecutive_ports(&il->list, num_ports, 0, loc->spec))) {
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
static int rtcp_demux(str *s, struct call_media *media) {
	if (!MEDIA_ISSET(media, RTCP_MUX))
		return 0;
	return rtcp_demux_is_rtcp(s) ? 2 : 1;
}

static int call_noop_rtcp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	rtcp_parse(s, sfd, src, tv);
	return 0;
}
static int call_avpf2avp_rtcp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	return rtcp_avpf2avp(s, sfd, src, tv); // also does rtcp_parse
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
	int ret = rtcp_savp2avp(s, &stream->selected_sfd->crypto, ssrc_ctx);
	if (ret < 0)
		return ret;
	rtcp_parse(s, sfd, src, tv);
	return ret;
}
static int call_savpf2avp_rtcp(str *s, struct packet_stream *stream, struct stream_fd *sfd, const endpoint_t *src,
		const struct timeval *tv, struct ssrc_ctx *ssrc_ctx)
{
	int ret;
	ret = rtcp_savp2avp(s, &stream->selected_sfd->crypto, ssrc_ctx);
	if (ret < 0)
		return ret;
	return rtcp_avpf2avp(s, sfd, src, tv);
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
		.last_index	= ssrc_ctx->srtp_index,
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

	if (PS_ISSET(stream, KERNELIZED))
		return;
	if (call->recording != NULL && !selected_recording_method->kernel_support)
		return;
	if (!kernel.is_wanted)
		goto no_kernel;
	nk_warn_msg = "interface to kernel module not open";
	if (!kernel.is_open)
		goto no_kernel_warn;
	if (!PS_ISSET(stream, RTP))
		goto no_kernel;
	if (!stream->selected_sfd)
		goto no_kernel;

        ilog(LOG_INFO, "Kernelizing media stream: %s:%d", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);

	sink = packet_stream_sink(stream);
	if (!sink) {
		ilog(LOG_WARNING, "Attempt to kernelize stream without sink");
		goto no_kernel;
	}

	determine_handler(stream, sink);

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

	__re_address_translate_ep(&reti.dst_addr, &sink->endpoint);
	__re_address_translate_ep(&reti.src_addr, &sink->selected_sfd->socket.local);
	reti.ssrc = stream->ssrc_in ? htonl(stream->ssrc_in->parent->ssrc) : 0;

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



/* must be called with call->master_lock held in R, and in->in_lock held */
static void determine_handler(struct packet_stream *in, const struct packet_stream *out) {
	const struct streamhandler * const *sh_pp, *sh;
	const struct streamhandler * const * const *matrix;

	if (in->handler)
		return;
	if (MEDIA_ISSET(in->media, PASSTHRU))
		goto noop;

	if (!in->media->protocol)
		goto err;
	if (!out->media->protocol)
		goto err;

	matrix = __sh_matrix;
	if (MEDIA_ISSET(in->media, DTLS) || MEDIA_ISSET(out->media, DTLS))
		matrix = __sh_matrix_recrypt;
	else if (in->call->recording)
		matrix = __sh_matrix_recrypt;
	else if (in->media->protocol->srtp && out->media->protocol->srtp
			&& in->selected_sfd && out->selected_sfd
			&& (crypto_params_cmp(&in->crypto.params, &out->selected_sfd->crypto.params)
				|| crypto_params_cmp(&out->crypto.params, &in->selected_sfd->crypto.params)))
		matrix = __sh_matrix_recrypt;


	sh_pp = matrix[in->media->protocol->index];
	if (!sh_pp)
		goto err;
	sh = sh_pp[out->media->protocol->index];
	if (!sh)
		goto err;
	in->handler = sh;

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
	u_int32_t ssrc = ntohl(ssrc_bs);

	// input direction
	mutex_lock(&in_srtp->in_lock);

	(*ssrc_in_p) = in_srtp->ssrc_in;
	if (G_UNLIKELY(!(*ssrc_in_p) || (*ssrc_in_p)->parent->ssrc != ssrc)) {
		// SSRC mismatch - get the new entry
		(*ssrc_in_p) = in_srtp->ssrc_in =
			get_ssrc_ctx(ssrc, ssrc_hash, SSRC_DIR_INPUT);
	}

	mutex_unlock(&in_srtp->in_lock);

	// out direction
	mutex_lock(&out_srtp->out_lock);

	(*ssrc_out_p) = out_srtp->ssrc_out;
	if (G_UNLIKELY(!(*ssrc_out_p) || (*ssrc_out_p)->parent->ssrc != ssrc)) {
		// SSRC mismatch - get the new entry
		(*ssrc_out_p) = out_srtp->ssrc_out =
			get_ssrc_ctx(ssrc, ssrc_hash, SSRC_DIR_OUTPUT);
	}

	mutex_unlock(&out_srtp->out_lock);
}


/* XXX split this function into pieces */
/* called lock-free */
static int stream_packet(struct stream_fd *sfd, str *s, const endpoint_t *fsin, const struct timeval *tv) {
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
	struct packet_stream *stream,
			     *sink = NULL,
			     *in_srtp, *out_srtp;
	struct call_media *media;
	int ret = 0, update = 0, stun_ret = 0, handler_ret = 0, muxed_rtcp = 0, rtcp = 0,
	    unk = 0;
	int i;
	struct call *call;
	struct callmaster *cm;
	/*unsigned char cc;*/
	struct endpoint endpoint;
	rewrite_func rwf_in, rwf_out;
	//struct local_intf *loc_addr;
	struct rtp_header *rtp_h;
	struct rtcp_packet *rtcp_h;
	struct rtp_stats *rtp_s;
	struct ssrc_ctx *ssrc_in = NULL, *ssrc_out = NULL;

	call = sfd->call;
	cm = call->callmaster;

	rwlock_lock_r(&call->master_lock);

	stream = sfd->stream;
	if (!stream)
		goto unlock_out;
	__C_DBG("Try to Kernelizing media stream: %s:%d", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);


	media = stream->media;

	if (!stream->selected_sfd)
		goto unlock_out;


	/* demux other protocols running on this port */

	if (MEDIA_ISSET(media, DTLS) && is_dtls(s)) {
		mutex_lock(&stream->in_lock);
		ret = dtls(stream, s, fsin);
		mutex_unlock(&stream->in_lock);
		if (!ret)
			goto unlock_out;
	}

	if (media->ice_agent && is_stun(s)) {
		stun_ret = stun(s, sfd, fsin);
		if (!stun_ret)
			goto unlock_out;
		if (stun_ret == 1) {
			call_media_state_machine(media);
			mutex_lock(&stream->in_lock); /* for the jump */
			goto kernel_check;
		}
		else /* not an stun packet */
			stun_ret = 0;
	}

#if RTP_LOOP_PROTECT
	if (MEDIA_ISSET(media, LOOP_CHECK)) {
		mutex_lock(&stream->in_lock);

		for (i = 0; i < RTP_LOOP_PACKETS; i++) {
			if (stream->lp_buf[i].len != s->len)
				continue;
			if (memcmp(stream->lp_buf[i].buf, s->s, MIN(s->len, RTP_LOOP_PROTECT)))
				continue;

			__C_DBG("packet dupe");
			if (stream->lp_count >= RTP_LOOP_MAX_COUNT) {
				ilog(LOG_WARNING, "More than %d duplicate packets detected, dropping packet "
						"to avoid potential loop", RTP_LOOP_MAX_COUNT);
				goto done;
			}

			stream->lp_count++;
			goto loop_ok;
		}

		/* not a dupe */
		stream->lp_count = 0;
		stream->lp_buf[stream->lp_idx].len = s->len;
		memcpy(stream->lp_buf[stream->lp_idx].buf, s->s, MIN(s->len, RTP_LOOP_PROTECT));
		stream->lp_idx = (stream->lp_idx + 1) % RTP_LOOP_PACKETS;
loop_ok:
		mutex_unlock(&stream->in_lock);
	}
#endif


	/* demux RTCP */

	in_srtp = stream;
	sink = stream->rtp_sink;
	if (!sink && PS_ISSET(stream, RTCP)) {
		sink = stream->rtcp_sink;
		rtcp = 1;
	}
	else if (stream->rtcp_sink) {
		muxed_rtcp = rtcp_demux(s, media);
		if (muxed_rtcp == 2) {
			sink = stream->rtcp_sink;
			rtcp = 1;
			in_srtp = stream->rtcp_sibling;
		}
	}
	out_srtp = sink;
	if (rtcp && sink && sink->rtcp_sibling)
		out_srtp = sink->rtcp_sibling;


	/* RTP/RTCP specifics */

	if (G_LIKELY(media->protocol && media->protocol->rtp)) {
		if (G_LIKELY(!rtcp && !rtp_payload(&rtp_h, NULL, s))) {
			__stream_ssrc(in_srtp, out_srtp, rtp_h->ssrc, &ssrc_in, &ssrc_out, call->ssrc_hash);

			// check the payload type
			i = (rtp_h->m_pt & 0x7f);
			if (G_LIKELY(ssrc_in))
				ssrc_in->parent->payload_type = i;

			// XXX convert to array? or keep last pointer?
			rtp_s = g_hash_table_lookup(stream->rtp_stats, &i);
			if (!rtp_s) {
				ilog(LOG_WARNING | LOG_FLAG_LIMIT,
						"RTP packet with unknown payload type %u received", i);
				atomic64_inc(&stream->stats.errors);
				atomic64_inc(&cm->statsps.errors);
			}

			else {
				atomic64_inc(&rtp_s->packets);
				atomic64_add(&rtp_s->bytes, s->len);
			}
		}
		else if (rtcp && !rtcp_payload(&rtcp_h, NULL, s)) {
			__stream_ssrc(in_srtp, out_srtp, rtcp_h->ssrc, &ssrc_in, &ssrc_out, call->ssrc_hash);
		}
	}

	/* do we have somewhere to forward it to? */

	if (G_UNLIKELY(!sink || !sink->selected_sfd || !out_srtp->selected_sfd || !in_srtp->selected_sfd)) {
		ilog(LOG_WARNING, "RTP packet from %s discarded", endpoint_print_buf(fsin));
		atomic64_inc(&stream->stats.errors);
		atomic64_inc(&cm->statsps.errors);
		goto unlock_out;
	}


	/* transcoding stuff, in and out */

	mutex_lock(&in_srtp->in_lock);

	determine_handler(in_srtp, sink);

	if (G_LIKELY(!rtcp)) {
		rwf_in = in_srtp->handler->in->rtp;
		rwf_out = in_srtp->handler->out->rtp;
	}
	else {
		rwf_in = in_srtp->handler->in->rtcp;
		rwf_out = in_srtp->handler->out->rtcp;
	}

	mutex_lock(&out_srtp->out_lock);

	/* return values are: 0 = forward packet, -1 = error/dont forward,
	 * 1 = forward and push update to redis */
	if (rwf_in) {
		handler_ret = rwf_in(s, in_srtp, sfd, fsin, tv, ssrc_in);
	}

	// If recording pcap dumper is set, then we record the call.
	if (call->recording) {
		dump_packet(call->recording, stream, s);
	}

	if (G_LIKELY(handler_ret >= 0)) {
		if (rwf_out)
			handler_ret += rwf_out(s, out_srtp, NULL, NULL, NULL, ssrc_out);
	}

	if (handler_ret > 0) {
		__unkernelize(stream);
		update = 1;
	}

	mutex_unlock(&out_srtp->out_lock);
	mutex_unlock(&in_srtp->in_lock);


	/* endpoint address handling */

	mutex_lock(&stream->in_lock);

	/* we're OK to (potentially) use the source address of this packet as destination
	 * in the other direction. */
	/* if the other side hasn't been signalled yet, just forward the packet */
	if (!PS_ISSET(stream, FILLED)) {
		__C_DBG("stream %s:%d not FILLED", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
		goto forward;
	}

	/* do not pay attention to source addresses of incoming packets for asymmetric streams */
	if (MEDIA_ISSET(media, ASYMMETRIC))
		PS_SET(stream, CONFIRMED);

	/* confirm sink for unidirectional streams in order to kernelize */
	if (MEDIA_ISSET(media, UNIDIRECTIONAL)) {
		PS_SET(sink, CONFIRMED);
	}

	/* if we have already updated the endpoint in the past ... */
	if (PS_ISSET(stream, CONFIRMED)) {
		/* see if we need to compare the source address with the known endpoint */
		if (PS_ISSET2(stream, STRICT_SOURCE, MEDIA_HANDOVER)) {
			endpoint = *fsin;
			mutex_lock(&stream->out_lock);

			int tmp = memcmp(&endpoint, &stream->endpoint, sizeof(endpoint));
			if (tmp && PS_ISSET(stream, MEDIA_HANDOVER)) {
				/* out_lock remains locked */
				ilog(LOG_INFO, "Peer address changed to %s", endpoint_print_buf(fsin));
				unk = 1;
				goto update_addr;
			}

			mutex_unlock(&stream->out_lock);

			if (tmp && PS_ISSET(stream, STRICT_SOURCE)) {
				ilog(LOG_INFO, "Drop due to strict-source attribute; got %s:%d, expected %s:%d",
					sockaddr_print_buf(&endpoint.address), endpoint.port,
					sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
				atomic64_inc(&stream->stats.errors);
				goto drop;
			}
		}
		goto kernel_check;
	}

	/* wait at least 3 seconds after last signal before committing to a particular
	 * endpoint address */
	if (!call->last_signal || poller_now <= call->last_signal + 3)
		goto update_peerinfo;

	ilog(LOG_INFO, "Confirmed peer address as %s", endpoint_print_buf(fsin));

	PS_SET(stream, CONFIRMED);
	update = 1;

update_peerinfo:
	mutex_lock(&stream->out_lock);
update_addr:
	endpoint = stream->endpoint;
	stream->endpoint = *fsin;
	if (memcmp(&endpoint, &stream->endpoint, sizeof(endpoint)))
		update = 1;
	mutex_unlock(&stream->out_lock);

	/* check the destination address of the received packet against what we think our
	 * local interface to use is */
	if (stream->selected_sfd && sfd != stream->selected_sfd) {
		ilog(LOG_INFO, "Switching local interface to %s", endpoint_print_buf(&sfd->socket.local));
		stream->selected_sfd = sfd;
		update = 1;
	}


kernel_check:
	if (PS_ISSET(stream, NO_KERNEL_SUPPORT)) {
		__C_DBG("stream %s:%d NO_KERNEL_SUPPORT", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
		goto forward;
	}

	if (!PS_ISSET(stream, CONFIRMED)) {
		__C_DBG("stream %s:%d not CONFIRMED", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
		goto forward;
	}

	if (!sink) {
		__C_DBG("sink is NULL for stream %s:%d", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
		goto forward;
	}

	if (!PS_ISSET(sink, CONFIRMED)) {
		__C_DBG("sink not CONFIRMED for stream %s:%d", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
		goto forward;
	}

	if (!PS_ISSET(sink, FILLED)) {
		__C_DBG("sink not FILLED for stream %s:%d", sockaddr_print_buf(&stream->endpoint.address), stream->endpoint.port);
		goto forward;
	}

	kernelize(stream);

forward:
	if (sink)
		mutex_lock(&sink->out_lock);

	if (!sink
			|| !sink->advertised_endpoint.port
			|| (is_addr_unspecified(&sink->advertised_endpoint.address)
				&& !is_trickle_ice_address(&sink->advertised_endpoint))
			|| stun_ret || handler_ret < 0)
		goto drop;

	// s is my packet?
	ret = socket_sendto(&sink->selected_sfd->socket, s->s, s->len, &sink->endpoint);
	__C_DBG("Forward to sink endpoint: %s:%d", sockaddr_print_buf(&sink->endpoint.address), sink->endpoint.port);

	mutex_unlock(&sink->out_lock);

	if (ret == -1) {
		ret = -errno;
                ilog(LOG_DEBUG,"Error when sending message. Error: %s",strerror(errno));
		atomic64_inc(&stream->stats.errors);
		atomic64_inc(&cm->statsps.errors);
		goto out;
	}

	sink = NULL;

drop:
	if (sink)
		mutex_unlock(&sink->out_lock);
	ret = 0;
	atomic64_inc(&stream->stats.packets);
	atomic64_add(&stream->stats.bytes, s->len);
	atomic64_set(&stream->last_packet, poller_now);
	atomic64_inc(&cm->statsps.packets);
	atomic64_add(&cm->statsps.bytes, s->len);

out:
	if (ret == 0 && update)
		ret = 1;

#if RTP_LOOP_PROTECT
done:
#endif
	if (unk)
		__stream_unconfirm(stream);
	mutex_unlock(&stream->in_lock);
	if (unk) {
		stream_unconfirm(stream->rtp_sink);
		stream_unconfirm(stream->rtcp_sink);
	}
unlock_out:
	rwlock_unlock_r(&call->master_lock);

	return ret;
}


static void stream_fd_readable(int fd, void *p, uintptr_t u) {
	struct stream_fd *sfd = p;
	char buf[RTP_BUFFER_SIZE];
	int ret, iters;
	int update = 0;
	struct call *ca;
	str s;
	endpoint_t ep;
	struct timeval tv;

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

		ret = socket_recvfrom_ts(&sfd->socket, buf + RTP_BUFFER_HEAD_ROOM, MAX_RTP_PACKET_SIZE,
				&ep, &tv);

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

		str_init_len(&s, buf + RTP_BUFFER_HEAD_ROOM, ret);
		ret = stream_packet(sfd, &s, &ep, &tv);
		if (G_UNLIKELY(ret < 0))
			ilog(LOG_WARNING, "Write error on media socket: %s", strerror(-ret));
		else if (ret == 1)
			update = 1;
	}

out:
	ca = sfd->call ? : NULL;

	if (ca && update) {
		redis_update_onekey(ca, ca->callmaster->conf.redis_write);
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
	struct poller *po = call->callmaster->poller;

	sfd = obj_alloc0("stream_fd", sizeof(*sfd), stream_fd_free);
	sfd->unique_id = g_queue_get_length(&call->stream_fds);
	sfd->socket = *fd;
	sfd->call = obj_get(call);
	sfd->local_intf = lif;
	g_queue_push_tail(&call->stream_fds, sfd); /* hand over ref */
	g_slice_free1(sizeof(*fd), fd); /* moved into sfd, thus free */

	__C_DBG("stream_fd_new localport=%d", sfd->socket.local.port);

	ZERO(pi);
	pi.fd = sfd->socket.fd;
	pi.obj = &sfd->obj;
	pi.readable = stream_fd_readable;
	pi.closed = stream_fd_closed;

	if (poller_add_item(po, &pi))
		ilog(LOG_ERR, "Failed to add stream_fd to poller");

	return sfd;
}
