#ifndef _MEDIA_SOCKET_H_
#define _MEDIA_SOCKET_H_


#include <glib.h>
#include <string.h>
#include <stdio.h>
#include "str.h"
#include "obj.h"
#include "aux.h"
#include "dtls.h"
#include "crypto.h"
#include "socket.h"




struct media_packet;
struct transport_protocol;
struct ssrc_ctx;
struct rtpengine_srtp;
struct jb_packet;

typedef int rtcp_filter_func(struct media_packet *, GQueue *);
typedef int (*rewrite_func)(str *, struct packet_stream *, struct stream_fd *, const endpoint_t *,
		const struct timeval *, struct ssrc_ctx *);


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
struct transport_protocol {
	enum transport_protocol_index	index;
	const char			*name;
	enum transport_protocol_index	avpf_proto;
	int				rtp:1; /* also set to 1 for SRTP */
	int				srtp:1;
	int				avpf:1;
	int				tcp:1;
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
	GHashTable			*addr_hash; // addr + type -> struct local_intf XXX obsolete?
	GHashTable			*rr_specs;
	str				name_base; // if name is "foo:bar", this is "foo"
};
struct port_pool {
	BIT_ARRAY_DECLARE(ports_used, 0x10000);
	volatile unsigned int		last_used;
	volatile unsigned int		free_ports;

	unsigned int			min, max;

	mutex_t				free_list_lock;
	GQueue				free_list;
	BIT_ARRAY_DECLARE(free_list_used, 0x10000);
};
struct intf_address {
	socktype_t			*type;
	sockaddr_t			addr;
};
struct intf_config {
	str				name; // full name (before the '/' separator in config)
	str				name_base; // if name is "foo:bar", this is "foo"
	str				name_rr_spec; // if name is "foo:bar", this is "bar"
	struct intf_address		local_address;
	struct intf_address		advertised_address;
	unsigned int			port_min, port_max;
};
struct intf_spec {
	struct intf_address		local_address;
	struct port_pool		port_pool;
};
struct local_intf {
	struct intf_spec		*spec;
	struct intf_address		advertised_address;
	unsigned int			unique_id; /* starting with 0 - serves as preference */
	const struct logical_intf	*logical;
	str				ice_foundation;
};
struct intf_list {
	const struct local_intf		*local_intf;
	GQueue				list;
};
struct stream_fd {
	struct obj			obj;
	unsigned int			unique_id;	/* RO */
	socket_t			socket;		/* RO */
	const struct local_intf		*local_intf;	/* RO */
	struct call			*call;		/* RO */
	struct packet_stream		*stream;	/* LOCK: call->master_lock */
	struct crypto_context		crypto;		/* IN direction, LOCK: stream->in_lock */
	struct dtls_connection		dtls;		/* LOCK: stream->in_lock */
};
struct media_packet {
	str raw;

	endpoint_t fsin; // source address of received packet
	struct timeval tv; // timestamp when packet was received
	struct stream_fd *sfd; // fd which received the packet
	struct call *call; // sfd->call
	struct packet_stream *stream; // sfd->stream
	struct call_media *media; // stream->media

	struct rtp_header *rtp;
	struct rtcp_packet *rtcp;
	struct ssrc_ctx *ssrc_in, *ssrc_out; // SSRC contexts from in_srtp and out_srtp
	str payload;

	GQueue packets_out;
};



extern GQueue all_local_interfaces; // read-only during runtime



void interfaces_init(GQueue *interfaces);

struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam, int num_ports);
struct local_intf *get_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
struct local_intf *get_any_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
void interfaces_exclude_port(unsigned int port);
int is_local_endpoint(const struct intf_address *addr, unsigned int port);

//int get_port(socket_t *r, unsigned int port, const struct local_intf *lif, const struct call *c);
//void release_port(socket_t *r, const struct local_intf *);

int __get_consecutive_ports(GQueue *out, unsigned int num_ports, unsigned int wanted_start_port,
		struct intf_spec *spec, const str *);
int get_consecutive_ports(GQueue *out, unsigned int num_ports, const struct logical_intf *log, const str *);
struct stream_fd *stream_fd_new(socket_t *fd, struct call *call, const struct local_intf *lif);

void free_intf_list(struct intf_list *il);
void free_socket_intf_list(struct intf_list *il);

INLINE int open_intf_socket(socket_t *r, unsigned int port, const struct local_intf *lif) {
	return open_socket(r, SOCK_DGRAM, port, &lif->spec->local_address.addr);
}

void kernelize(struct packet_stream *);
void __unkernelize(struct packet_stream *);
void unkernelize(struct packet_stream *);
void __stream_unconfirm(struct packet_stream *);

int media_socket_dequeue(struct media_packet *mp, struct packet_stream *sink);
const struct streamhandler *determine_handler(const struct transport_protocol *in_proto,
		struct call_media *out_media, int must_recrypt);
int media_packet_encrypt(rewrite_func encrypt_func, struct packet_stream *out, struct media_packet *mp);
const struct transport_protocol *transport_protocol(const str *s);
//void play_buffered(struct packet_stream *sink, struct codec_packet *cp, int buffered);
void play_buffered(struct jb_packet *cp);

/* XXX shouldn't be necessary */
/*
INLINE struct local_intf *get_interface_from_address(const struct logical_intf *lif,
		const sockaddr_t *addr, socktype_t *type)
{
	struct intf_address a;
	a.type = type;
	a.addr = *addr;
	return g_hash_table_lookup(lif->addr_hash, &a);
}
*/


#endif
