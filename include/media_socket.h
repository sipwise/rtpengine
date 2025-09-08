#ifndef _MEDIA_SOCKET_H_
#define _MEDIA_SOCKET_H_

#include <glib.h>
#include <string.h>
#include <stdio.h>

#include "str.h"
#include "obj.h"
#include "helpers.h"
#include "dtls.h"
#include "crypto.h"
#include "socket.h"
#include "containers.h"
#include "types.h"

#include "xt_RTPENGINE.h"
#include "common_stats.h"

struct media_packet;
struct transport_protocol;
struct ssrc_entry_call;
struct rtpengine_srtp;
struct jb_packet;
struct poller;
struct media_player_cache_entry;

TYPED_GQUEUE(stream_fd, stream_fd)


typedef int rtcp_filter_func(struct media_packet *, GQueue *);

typedef union {
	const struct rtp_header *rtp;
	const struct rtcp_packet *rtcp;
} rewrite_arg __attribute__ ((__transparent_union__));
typedef int (*rewrite_func)(rewrite_arg header, str *packet, str *payload, struct packet_stream *,
		struct ssrc_entry_call *);


enum transport_protocol_index {
	PROTO_RTP_AVP = 0,
	PROTO_RTP_SAVP,
	PROTO_RTP_AVPF,
	PROTO_RTP_SAVPF,
	PROTO_UDP_TLS_RTP_SAVP,
	PROTO_UDP_TLS_RTP_SAVPF,
	PROTO_UDPTL,
	PROTO_RTP_SAVP_OSRTP,
	PROTO_RTP_SAVPF_OSRTP,
	PROTO_UNKNOWN,

	__PROTO_LAST,
};
struct transport_protocol {
	enum transport_protocol_index	index;
	const char			*name;
	enum transport_protocol_index	avpf_proto;
	enum transport_protocol_index	osrtp_proto;
	enum transport_protocol_index	rtp_proto;
	unsigned int			rtp:1; /* also set to 1 for SRTP */
	unsigned int			srtp:1;
	unsigned int			osrtp:1;
	unsigned int			avpf:1;
	unsigned int			tcp:1;
};
extern const struct transport_protocol transport_protocols[];


struct streamhandler_io {
	rewrite_func		rtp_crypt;
	rewrite_func		rtcp_crypt;
	rtcp_filter_func	*rtcp_filter;
	int			(*kernel)(struct rtpengine_srtp *, struct packet_stream *);
};
struct streamhandler {
	const struct streamhandler_io	*in;
	const struct streamhandler_io	*out;
};



TYPED_GQUEUE(local_intf, struct local_intf)
TYPED_GHASHTABLE(rr_specs_ht, str, struct logical_intf, str_hash, str_equal, NULL, NULL)

struct logical_intf {
	str				name;
	sockfamily_t			*preferred_family;
	local_intf_q			list;
	rr_specs_ht			rr_specs;
	str				name_base; // if name is "foo:bar", this is "foo"
};

typedef void port_t;
TYPED_GQUEUE(ports, port_t)

struct socket_port_link {
	socket_t			socket;
	ports_q				links;
	struct port_pool		*pp;
};

TYPED_GQUEUE(port_pool, struct port_pool)
struct port_pool {
	unsigned int			min, max;

	mutex_t				free_list_lock;

	ports_q				free_ports_q;		/* for getting the next free port */
	ports_list			**free_ports;		/* for a lookup if the port is used */

	port_pool_q			overlaps;
};
#define free_ports_link(pp, port) ((pp)->free_ports[port - (pp)->min])

struct intf_address {
	socktype_t			*type;
	sockaddr_t			addr;
};
struct intf_config {
	str				name; // full name (before the '/' separator in config)
	str				name_base; // if name is "foo:bar", this is "foo"
	str				name_rr_spec; // if name is "foo:bar", this is "bar"
	str				alias; // if interface is "foo=bar", this is "bar"
	struct intf_address		local_address;
	struct intf_address		advertised_address;
	unsigned int			port_min, port_max;
	GList				*exclude_ports;
};
struct intf_spec {
	struct intf_address		local_address;
	struct port_pool		port_pool;
};
struct interface_sampled_rate_stats {
	GHashTable *ht;
	struct interface_stats_block intv;
};
INLINE void interface_sampled_calc_diff(const struct interface_sampled_stats *stats,
		struct interface_sampled_stats *intv, struct interface_sampled_stats *diff)
{
#define F(x) STAT_SAMPLED_CALC_DIFF(x, stats, intv, diff)
#include "interface_sampled_stats_fields.inc"
#undef F
}
INLINE void interface_sampled_avg(struct interface_sampled_stats_avg *loc,
		const struct interface_sampled_stats *diff) {
#define F(x) STAT_SAMPLED_AVG_STDDEV(x, loc, diff)
#include "interface_sampled_stats_fields.inc"
#undef F
}
INLINE void interface_counter_calc_diff(const struct interface_counter_stats *stats,
		struct interface_counter_stats *intv, struct interface_counter_stats *diff) {
#define F(x) atomic64_calc_diff(&stats->x, &intv->x, &diff->x);
#include "interface_counter_stats_fields.inc"
#undef F
}
INLINE void interface_counter_calc_diff_dir(const struct interface_counter_stats_dir *stats,
		struct interface_counter_stats_dir *intv, struct interface_counter_stats_dir *diff) {
#define F(x) atomic64_calc_diff(&stats->x, &intv->x, &diff->x);
#include "interface_counter_stats_fields_dir.inc"
#undef F
}
INLINE void interface_counter_calc_rate_from_diff(int64_t run_diff_us,
		struct interface_counter_stats *diff, struct interface_counter_stats *rate) {
#define F(x) atomic64_calc_rate_from_diff(run_diff_us, atomic64_get(&diff->x), &rate->x);
#include "interface_counter_stats_fields.inc"
#undef F
}
INLINE void interface_counter_calc_rate_from_diff_dir(int64_t run_diff_us,
		struct interface_counter_stats_dir *diff, struct interface_counter_stats_dir *rate) {
#define F(x) atomic64_calc_rate_from_diff(run_diff_us, atomic64_get(&diff->x), &rate->x);
#include "interface_counter_stats_fields_dir.inc"
#undef F
}
void interface_sampled_rate_stats_init(struct interface_sampled_rate_stats *);
void interface_sampled_rate_stats_destroy(struct interface_sampled_rate_stats *);
struct interface_stats_block *interface_sampled_rate_stats_get(struct interface_sampled_rate_stats *s,
		struct local_intf *lif, int64_t *time_diff_us);

TYPED_GQUEUE(socket_port, struct socket_port_link)

struct local_intf {
	struct intf_spec		*spec;
	struct intf_address		advertised_address;
	unsigned int			unique_id; /* starting with 0 - serves as preference */
	struct logical_intf		*logical;
	str				ice_foundation;

	struct interface_stats_block	*stats;
};
struct socket_intf_list {
	struct local_intf		*local_intf;
	socket_port_q			list;
};
struct sfd_intf_list {
	struct local_intf		*local_intf;
	stream_fd_q			list;
};
TYPED_GQUEUE(socket_intf_list, struct socket_intf_list) /* RO */
TYPED_GQUEUE(sfd_intf_list, struct sfd_intf_list)

/**
 * stream_fd is an entry-point object for RTP packets handling,
 * because of that it's also reference-counted.
 * 
 * stream_fd object us only released, when it is removed from the poller
 * and also removed from the call object.
 * 
 * Contains an information required for media processing, such as media ports.
 */
struct stream_fd {

	/* struct obj member must always be the first member in a struct.
	 *
	 * obj is created with a cleanup handler, see obj_alloc(),
	 * and this handler is executed whenever the reference count drops to zero.
	 * 
	 * References are acquired and released through obj_get() and obj_put()
	 * (plus some other wrapper functions).
	 */
	struct obj			obj;

	unsigned int			unique_id;	/* RO */
	union {
		socket_t			socket;		/* RO - alias */
		struct socket_port_link		spl;		/* RO */
	};
	struct local_intf		*local_intf;	/* RO */

	/* stream_fd object holds a reference to the call it belongs to.
	 * Which in turn holds references to all stream_fd objects it contains,
	 * what makes these references circular.
	 *
	 * The call is only released when it has been dissociated from all stream_fd objects,
	 * which happens during call teardown.
	 */
	call_t				*call;		/* RO */
	struct packet_stream		*stream;	/* LOCK: call->master_lock */
	struct crypto_context		crypto;		/* IN direction, LOCK: stream->in_lock */
	struct dtls_connection		dtls;		/* LOCK: stream->in_lock */
	int				error_strikes;
	int				active_read_events;
	struct poller			*poller;

	bool				kernelized:1,
					confirmed:1;
};

struct sink_attrs {
	// cannot be bit fields because G_STRUCT_OFFSET is used on them
	bool block_media;
	bool silence_media;

	bool offer_answer:1; // bidirectional, exclusive
	bool rtcp_only:1;
	bool transcoding:1;
	bool egress:1;
};

struct rtpext_printer {
	size_t (*length)(const struct media_packet *);
	size_t (*print)(struct rtp_header *, void *dst, const struct media_packet *);
	void (*kernel)(struct rtpengine_output_info *, struct call_media *, struct call_media *);
	bool may_copy;
};

/**
 * During actual packet handling and forwarding,
 * only the sink_handler objects (and the packet_stream objects they are related to) are used.
 */
struct sink_handler {
	struct packet_stream *sink;
	const struct streamhandler *handler;
	struct sink_attrs attrs;
	const struct rtpext_printer *rtpext;
};


extern const struct rtpext_printer rtpext_printer_copy; // also acts as a dummy printer


TYPED_GQUEUE(extmap_data, struct rtp_extension_data);

struct media_packet {
	str raw;

	endpoint_t fsin; // source address of received packet
	int64_t tv; // timestamp when packet was received
	stream_fd *sfd; // fd which received the packet
	call_t *call; // sfd->call
	struct packet_stream *stream; // sfd->stream
	struct call_media *media; // stream->media
	struct call_media *media_out; // output media
	struct sink_handler sink;
	struct media_player_cache_entry *cache_entry;

	struct rtp_header *rtp;
	struct rtcp_packet *rtcp;
	struct ssrc_entry_call *ssrc_in, *ssrc_out; // SSRC contexts from in_srtp and out_srtp
	str payload;
	str extensions;
	extmap_data_q extmap;

	codec_packet_q packets_out;
	int ptime; // returned from decoding
};

struct packet_handler_ctx;


struct rtp_extension;

typedef struct {
	void (*parse)(struct packet_handler_ctx *, const struct rtp_extension_data *);

	ssize_t (*len)(struct call_media *);
	ssize_t (*print)(void *dst, struct rtp_extension *, struct call_media *);

	enum {
		RTP_EXT_MID = 0,

		RTP_EXT_NUM,

		RTP_EXT_UNKNOWN,
	} id;
} rtp_ext_handler;

struct rtp_extension {
	unsigned int id;
	str name; // urn:ietf:params:rtp- hdrext:... or URI
	rtp_ext_handler handler;
	bool accepted:1;
};

struct rtp_extension_data {
	extmap_data_list link;
	struct rtp_extension *ext;
	str content;
};

static inline void rtp_extension_free(struct rtp_extension *r) {
	g_free(r);
}
static inline void rtp_ext_data_free(struct rtp_extension_data *r) {
	g_free(r);
}

TYPED_GQUEUE(extmap, struct rtp_extension);
TYPED_GHASHTABLE(extmap_ht, void, struct rtp_extension, g_direct_hash, g_direct_equal, NULL, NULL);
TYPED_GHASHTABLE(ext_name_ht, str, struct rtp_extension, str_hash, str_equal, NULL, NULL);

size_t extmap_length_short(const struct media_packet *);
void extmap_header_short(void *);
size_t extmap_print_short(void *, unsigned int, const str *);

size_t extmap_length_long(const struct media_packet *);
void extmap_header_long(void *);
size_t extmap_print_long(void *, unsigned int, const str *);


rtp_ext_handler rtp_extension_get_handler(const str *);


extern local_intf_q all_local_interfaces; // read-only during runtime

extern __thread struct bufferpool *media_bufferpool;


void interfaces_init(intf_config_q *interfaces);
void interfaces_free(void);

struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam, int num_ports);
struct local_intf *get_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
struct local_intf *get_any_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
void interfaces_exclude_port(endpoint_t *);
bool is_local_endpoint(const struct intf_address *addr, unsigned int port);

struct socket_port_link get_specific_port(unsigned int port,
		struct intf_spec *spec, const str *label);
bool get_consecutive_ports(socket_intf_list_q *out, unsigned int num_ports, unsigned int num_intfs,
		struct call_media *media);
stream_fd *stream_fd_new(struct socket_port_link *, call_t *call, struct local_intf *lif);
stream_fd *stream_fd_lookup(const endpoint_t *);
void stream_fd_release(stream_fd *);
enum thread_looper_action release_closed_sockets(void);
void append_thread_lpr_to_glob_lpr(void);

void free_sfd_intf_list(struct sfd_intf_list *il);
void free_release_sfd_intf_list(struct sfd_intf_list *il);
void free_socket_intf_list(struct socket_intf_list *il);

void __unkernelize(struct packet_stream *, const char *);
void unkernelize(struct packet_stream *, const char *);
void __stream_unconfirm(struct packet_stream *, const char *);
void __reset_sink_handlers(struct packet_stream *);

int __hunt_ssrc_ctx_idx(uint32_t ssrc, struct ssrc_entry_call *list[RTPE_NUM_SSRC_TRACKING],
		unsigned int start_idx);
struct ssrc_entry_call *__hunt_ssrc_ctx(uint32_t ssrc, struct ssrc_entry_call *list[RTPE_NUM_SSRC_TRACKING],
		unsigned int start_idx);

__attribute__((nonnull(1, 2)))
void media_packet_copy(struct media_packet *, const struct media_packet *);

__attribute__((nonnull(1)))
void media_packet_release(struct media_packet *);

__attribute__((nonnull(1)))
int media_socket_dequeue(struct media_packet *mp, struct packet_stream *sink);

__attribute__((nonnull(1)))
const struct streamhandler *determine_sink_handler(struct packet_stream *in, struct sink_handler *);

__attribute__((nonnull(1)))
const struct streamhandler *determine_handler(const struct transport_protocol *in_proto,
		struct call_media *out_media, bool must_recrypt);

__attribute__((nonnull(1)))
void sink_handler_set_generic(struct sink_handler *sh);

__attribute__((nonnull(2, 3)))
int media_packet_encrypt(rewrite_func encrypt_func, struct packet_stream *out, struct media_packet *mp);

const struct transport_protocol *transport_protocol(const str *s);

__attribute__((nonnull(1)))
void play_buffered(struct jb_packet *cp);

INLINE int proto_is_rtp(const struct transport_protocol *protocol) {
	// known to be RTP? therefore unknown is not RTP
	if (!protocol)
		return 0;
	return protocol->rtp ? 1 : 0;
}
INLINE int proto_is_not_rtp(const struct transport_protocol *protocol) {
	// known not to be RTP? therefore unknown might be RTP
	if (!protocol)
		return 0;
	return protocol->rtp ? 0 : 1;
}
INLINE int proto_is(const struct transport_protocol *protocol, enum transport_protocol_index idx) {
	if (!protocol)
		return 0;
	return (protocol->index == idx) ? 1 : 0;
}
INLINE void stream_fd_put(stream_fd *sp) {
	if (!sp)
		return;
	obj_put(sp);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(stream_fd, stream_fd_put)


#endif
