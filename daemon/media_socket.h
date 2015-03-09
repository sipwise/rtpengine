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






struct logical_intf {
	str				name;
	sockfamily_t			*preferred_family;
	GQueue				list; /* struct local_intf */
	GHashTable			*addr_hash;
};
struct port_pool {
	BIT_ARRAY_DECLARE(ports_used, 0x10000);
	volatile unsigned int		last_used;

	unsigned int			min, max;
};
struct intf_address {
	socktype_t			*type;
	sockaddr_t			addr;
	sockaddr_t			advertised;
};
struct intf_config {
	str				name;
	struct intf_address		address;
	unsigned int			port_min, port_max;
};
struct intf_spec {
	struct intf_address		address;
	str				ice_foundation;
	struct port_pool		port_pool;
};
struct local_intf {
	struct intf_spec		*spec;
	unsigned int			preference; /* starting with 0 */
	const struct logical_intf	*logical;
};
struct intf_list {
	const struct local_intf		*local_intf;
	GQueue				list;
};
struct stream_fd {
	struct obj			obj;
	socket_t			socket;		/* RO */
	const struct local_intf		*local_intf;	/* RO */
	struct call			*call;		/* RO */
	struct packet_stream		*stream;	/* LOCK: call->master_lock */
	struct crypto_context		crypto;		/* IN direction, LOCK: stream->in_lock */
	struct dtls_connection		dtls;		/* LOCK: stream->in_lock */
};



void interfaces_init(GQueue *interfaces);

struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam);
struct local_intf *get_interface_address(const struct logical_intf *lif, sockfamily_t *fam);
struct local_intf *get_any_interface_address(const struct logical_intf *lif, sockfamily_t *fam);

//int get_port(socket_t *r, unsigned int port, const struct local_intf *lif, const struct call *c);
//void release_port(socket_t *r, const struct local_intf *);
void set_tos(socket_t *, unsigned int tos);
int get_consecutive_ports(GQueue *out, unsigned int num_ports, const struct logical_intf *log);
struct stream_fd *stream_fd_new(socket_t *fd, struct call *call, const struct local_intf *lif);

void free_intf_list(struct intf_list *il);
void free_socket_intf_list(struct intf_list *il);

INLINE int open_intf_socket(socket_t *r, unsigned int port, const struct local_intf *lif) {
	return open_socket(r, SOCK_DGRAM, port, &lif->spec->address.addr);
}

void kernelize(struct packet_stream *);
void __unkernelize(struct packet_stream *);
void unkernelize(struct packet_stream *);
void __stream_unconfirm(struct packet_stream *);

/* XXX shouldnt be necessary */
INLINE struct local_intf *get_interface_from_address(const struct logical_intf *lif,
		const sockaddr_t *addr, socktype_t *type)
{
	struct intf_address a;
	a.type = type;
	a.addr = *addr;
	return g_hash_table_lookup(lif->addr_hash, &a);
}


#endif
