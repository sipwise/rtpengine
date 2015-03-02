#include "media_socket.h"
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "str.h"
#include "ice.h"
#include "socket.h"



static GQueue *__interface_list_for_family(sockfamily_t *fam);


static GHashTable *__logical_intf_name_family_hash;
static GHashTable *__intf_spec_addr_type_hash;
static GQueue __preferred_lists_for_family[__SF_LAST];





struct logical_intf *get_logical_interface(const str *name, sockfamily_t *fam) {
	struct logical_intf d, *lif;

	if (!name || !name->s) {
		GQueue *q;
		q = __interface_list_for_family(fam);
		return q->head ? q->head->data : NULL;
	}

	d.name = *name;
	d.preferred_family = fam;

	lif = g_hash_table_lookup(__logical_intf_name_family_hash, &d);
	return lif;
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

static GQueue *__interface_list_for_family(sockfamily_t *fam) {
	return &__preferred_lists_for_family[fam->idx];
}
static void __interface_append(struct intf_config *ifa, sockfamily_t *fam) {
	struct logical_intf *lif;
	GQueue *q;
	struct local_intf *ifc;
	struct intf_spec *spec;

	lif = get_logical_interface(&ifa->name, fam);

	if (!lif) {
		lif = g_slice_alloc0(sizeof(*lif));
		lif->name = ifa->name;
		lif->preferred_family = fam;
		lif->addr_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);
		g_hash_table_insert(__logical_intf_name_family_hash, lif, lif);
		if (ifa->address.addr.family == fam) {
			q = __interface_list_for_family(fam);
			g_queue_push_tail(q, lif);
		}
	}

	spec = g_hash_table_lookup(__intf_spec_addr_type_hash, &ifa->address);
	if (!spec) {
		spec = g_slice_alloc0(sizeof(*spec));
		spec->address = ifa->address;
		ice_foundation(&spec->ice_foundation);
		spec->port_pool.min = ifa->port_min;
		spec->port_pool.max = ifa->port_max;
		g_hash_table_insert(__intf_spec_addr_type_hash, &spec->address, spec);
	}

	ifc = g_slice_alloc(sizeof(*ifc));
	ifc->spec = spec;
	ifc->preference = lif->list.length;
	ifc->logical = lif;

	g_queue_push_tail(&lif->list, ifc);
	g_hash_table_insert(lif->addr_hash, (void *) &ifc->spec->address, ifc);
}

void interfaces_init(GQueue *interfaces) {
	int i;
	GList *l;
	struct intf_config *ifa;
	sockfamily_t *fam;

	/* init everything */
	__logical_intf_name_family_hash = g_hash_table_new(__name_family_hash, __name_family_eq);
	__intf_spec_addr_type_hash = g_hash_table_new(__addr_type_hash, __addr_type_eq);

	for (i = 0; i < G_N_ELEMENTS(__preferred_lists_for_family); i++)
		g_queue_init(&__preferred_lists_for_family[i]);

	/* build primary lists first */
	for (l = interfaces->head; l; l = l->next) {
		ifa = l->data;
		__interface_append(ifa, ifa->address.addr.family);
	}

	/* then append to each other as lower-preference alternatives */
	for (i = 0; i < __SF_LAST; i++) {
		fam = get_socket_family_enum(i);
		for (l = interfaces->head; l; l = l->next) {
			ifa = l->data;
			if (ifa->address.addr.family == fam)
				continue;
			__interface_append(ifa, fam);
		}
	}
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



/* XXX family specific */
void set_tos(int fd, unsigned int tos) {
	unsigned char ctos;

	ctos = tos;

	setsockopt(fd, IPPROTO_IP, IP_TOS, &ctos, sizeof(tos));
#ifdef IPV6_TCLASS
	setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
#else
#warning "Will not set IPv6 traffic class"
#endif
}


/* XXX family specific? unify? */
static int get_port6(socket_t *r, unsigned int port, const struct local_intf *lif, const struct call *c) {
	if (open_socket(r, SOCK_DGRAM, port, &lif->spec->address.addr))
		return -1;

	set_tos(r->fd, c->tos);

	return 0;
}

int get_port(socket_t *r, unsigned int port, const struct local_intf *lif, const struct call *c) {
	int ret;
	struct port_pool *pp;

	__C_DBG("attempting to open port %u", port);

	pp = &lif->spec->port_pool;

	if (bit_array_set(pp->ports_used, port)) {
		__C_DBG("port in use");
		return -1;
	}
	__C_DBG("port locked");

	ret = get_port6(r, port, lif, c);

	if (ret) {
		__C_DBG("couldn't open port");
		bit_array_clear(pp->ports_used, port);
		return ret;
	}

	return 0;
}

void release_port(socket_t *r, const struct local_intf *lif) {
	__C_DBG("releasing port %u", r->local.port);
	bit_array_clear(lif->spec->port_pool.ports_used, r->local.port);
	close_socket(r);
}
