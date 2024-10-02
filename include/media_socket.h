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
struct ssrc_ctx;
struct rtpengine_srtp;
struct jb_packet;
struct poller;
struct media_player_cache_entry;

TYPED_GQUEUE(stream_fd, stream_fd)


typedef int rtcp_filter_func(struct media_packet *, GQueue *);
typedef int (*rewrite_func)(str *, struct packet_stream *, struct ssrc_ctx *);


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



struct logical_intf {
	str				name;
	sockfamily_t			*preferred_family;
	GQueue				list; /* struct local_intf */
	GHashTable			*rr_specs;
	str				name_base; // if name is "foo:bar", this is "foo"
};
struct port_pool {
	unsigned int			min, max;

	mutex_t				free_list_lock;

	GQueue				free_ports_q;		/* for getting the next free port */
	GHashTable			* free_ports_ht;	/* for a lookup, if the port is used */
};
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
INLINE void interface_counter_calc_rate_from_diff(long long run_diff_us,
		struct interface_counter_stats *diff, struct interface_counter_stats *rate) {
#define F(x) atomic64_calc_rate_from_diff(run_diff_us, atomic64_get(&diff->x), &rate->x);
#include "interface_counter_stats_fields.inc"
#undef F
}
INLINE void interface_counter_calc_rate_from_diff_dir(long long run_diff_us,
		struct interface_counter_stats_dir *diff, struct interface_counter_stats_dir *rate) {
#define F(x) atomic64_calc_rate_from_diff(run_diff_us, atomic64_get(&diff->x), &rate->x);
#include "interface_counter_stats_fields_dir.inc"
#undef F
}
void interface_sampled_rate_stats_init(struct interface_sampled_rate_stats *);
void interface_sampled_rate_stats_destroy(struct interface_sampled_rate_stats *);
struct interface_stats_block *interface_sampled_rate_stats_get(struct interface_sampled_rate_stats *s,
		struct local_intf *lif, long long *time_diff_us);

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
	socket_q			list;
};
struct sfd_intf_list {
	struct local_intf		*local_intf;
	stream_fd_q			list;
};
TYPED_GQUEUE(socket_intf_list, struct socket_intf_list)
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
	socket_t			socket;		/* RO */
	struct local_intf		*local_intf;	/* RO */

	/* stream_fd object holds a reference to the call it belongs to.
	 * Which in turn holds references to all stream_fd objects it contains,
	 * what makes these references circular.
	 *
	 * The call is only released when it has been dissociated from all stream_fd objects,
	 * which happens during call teardown.
	 */
	call_t			*call;		/* RO */
	struct packet_stream		*stream;	/* LOCK: call->master_lock */
	struct crypto_context		crypto;		/* IN direction, LOCK: stream->in_lock */
	struct dtls_connection		dtls;		/* LOCK: stream->in_lock */
	int				error_strikes;
	int				active_read_events;
	struct poller			*poller;
};

struct sink_attrs {
	bool block_media;
	bool silence_media;

	unsigned int offer_answer:1; // bidirectional, exclusive
	unsigned int rtcp_only:1;
	unsigned int transcoding:1;
	unsigned int egress:1;
};

/**
 * During actual packet handling and forwarding,
 * only the sink_handler objects (and the packet_stream objects they are related to) are used.
 */
struct sink_handler {
	struct packet_stream *sink;
	const struct streamhandler *handler;
	int kernel_output_idx;
	struct sink_attrs attrs;
};
struct media_packet {
	str raw;

	endpoint_t fsin; // source address of received packet
	struct timeval tv; // timestamp when packet was received
	stream_fd *sfd; // fd which received the packet
	call_t *call; // sfd->call
	struct packet_stream *stream; // sfd->stream
	struct call_media *media; // stream->media
	struct call_media *media_out; // output media
	struct sink_handler sink;
	struct media_player_cache_entry *cache_entry;

	struct rtp_header *rtp;
	struct rtcp_packet *rtcp;
	struct ssrc_ctx *ssrc_in, *ssrc_out; // SSRC contexts from in_srtp and out_srtp
	str payload;

	codec_packet_q packets_out;
	int ptime; // returned from decoding
};



extern GQueue all_local_interfaces; // read-only during runtime

extern __thread struct bufferpool *media_bufferpool;


void interfaces_init(intf_config_q *interfaces);
void interfaces_free(void);

struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam, int num_ports);
struct local_intf *get_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
struct local_intf *get_any_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
void interfaces_exclude_port(unsigned int port);
int is_local_endpoint(const struct intf_address *addr, unsigned int port);

//int get_port(socket_t *r, unsigned int port, const struct local_intf *lif, const call_t *c);
//void release_port(socket_t *r, const struct local_intf *);

int __get_consecutive_ports(socket_q *out, unsigned int num_ports, unsigned int wanted_start_port,
		struct intf_spec *spec, const str *);
int get_consecutive_ports(socket_intf_list_q *out, unsigned int num_ports, unsigned int num_intfs, struct call_media *media);
stream_fd *stream_fd_new(socket_t *fd, call_t *call, struct local_intf *lif);
stream_fd *stream_fd_lookup(const endpoint_t *);
void stream_fd_release(stream_fd *);
enum thread_looper_action release_closed_sockets(void);
void append_thread_lpr_to_glob_lpr(void);

void free_sfd_intf_list(struct sfd_intf_list *il);
void free_release_sfd_intf_list(struct sfd_intf_list *il);
void free_socket_intf_list(struct socket_intf_list *il);

INLINE int open_intf_socket(socket_t *r, unsigned int port, const struct local_intf *lif) {
	return open_socket(r, SOCK_DGRAM, port, &lif->spec->local_address.addr);
}

void kernelize(struct packet_stream *);
void __unkernelize(struct packet_stream *, const char *);
void unkernelize(struct packet_stream *, const char *);
void __stream_unconfirm(struct packet_stream *, const char *);
void __reset_sink_handlers(struct packet_stream *);

int __hunt_ssrc_ctx_idx(uint32_t ssrc, struct ssrc_ctx *list[RTPE_NUM_SSRC_TRACKING],
		unsigned int start_idx);
struct ssrc_ctx *__hunt_ssrc_ctx(uint32_t ssrc, struct ssrc_ctx *list[RTPE_NUM_SSRC_TRACKING],
		unsigned int start_idx);

void media_packet_copy(struct media_packet *, const struct media_packet *);
void media_packet_release(struct media_packet *);
int media_socket_dequeue(struct media_packet *mp, struct packet_stream *sink);
const struct streamhandler *determine_handler(const struct transport_protocol *in_proto,
		struct call_media *out_media, bool must_recrypt);
int media_packet_encrypt(rewrite_func encrypt_func, struct packet_stream *out, struct media_packet *mp);
const struct transport_protocol *transport_protocol(const str *s);
//void play_buffered(struct packet_stream *sink, struct codec_packet *cp, int buffered);
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
