#include "socket.h"
#include <glib.h>
#include <unistd.h>
#include <errno.h>
#include "str.h"
#include "media_socket.h"
#include "xt_RTPENGINE.h"

static int __ip4_addr_parse(sockaddr_t *dst, const char *src);
static int __ip6_addr_parse(sockaddr_t *dst, const char *src);
static int __ip4_addr_print(const sockaddr_t *a, char *buf, size_t len);
static int __ip6_addr_print(const sockaddr_t *a, char *buf, size_t len);
static int __ip6_addr_print_p(const sockaddr_t *a, char *buf, size_t len);
static unsigned int __ip4_hash(const sockaddr_t *a);
static unsigned int __ip6_hash(const sockaddr_t *a);
static int __ip4_eq(const sockaddr_t *a, const sockaddr_t *b);
static int __ip6_eq(const sockaddr_t *a, const sockaddr_t *b);
static int __ip4_is_specified(const sockaddr_t *a);
static int __ip6_is_specified(const sockaddr_t *a);
static int __ip_bind(socket_t *s, unsigned int, const sockaddr_t *);
static int __ip_connect(socket_t *s, const endpoint_t *);
static int __ip4_sockaddr2endpoint(endpoint_t *, const void *);
static int __ip6_sockaddr2endpoint(endpoint_t *, const void *);
static int __ip4_endpoint2sockaddr(void *, const endpoint_t *);
static int __ip6_endpoint2sockaddr(void *, const endpoint_t *);
static int __ip4_addrport2sockaddr(void *, const sockaddr_t *, unsigned int);
static int __ip6_addrport2sockaddr(void *, const sockaddr_t *, unsigned int);
static ssize_t __ip_recvfrom(socket_t *s, void *buf, size_t len, endpoint_t *ep);
static ssize_t __ip_sendmsg(socket_t *s, struct msghdr *mh, const endpoint_t *ep);
static ssize_t __ip_sendto(socket_t *s, const void *buf, size_t len, const endpoint_t *ep);
static int __ip4_tos(socket_t *, unsigned int);
static int __ip6_tos(socket_t *, unsigned int);
static void __ip4_endpoint2kernel(struct re_address *, const endpoint_t *);
static void __ip6_endpoint2kernel(struct re_address *, const endpoint_t *);
static void __ip4_kernel2endpoint(endpoint_t *ep, const struct re_address *ra);
static void __ip6_kernel2endpoint(endpoint_t *ep, const struct re_address *ra);



static socktype_t __socket_types[] = {
	{
		.name		= "udp",
		.name_uc	= "UDP",
	},
};

static struct socket_family __socket_families[__SF_LAST] = {
	[SF_IP4] = {
		.af			= AF_INET,
		.sockaddr_size		= sizeof(struct sockaddr_in),
		.name			= "IPv4",
		.rfc_name		= "IP4",
		.unspec_string		= "0.0.0.0",
		.hash			= __ip4_hash,
		.eq			= __ip4_eq,
		.addr_parse		= __ip4_addr_parse,
		.addr_print		= __ip4_addr_print,
		.addr_print_p		= __ip4_addr_print,
		.is_specified		= __ip4_is_specified,
		.sockaddr2endpoint	= __ip4_sockaddr2endpoint,
		.endpoint2sockaddr	= __ip4_endpoint2sockaddr,
		.addrport2sockaddr	= __ip4_addrport2sockaddr,
		.bind			= __ip_bind,
		.connect		= __ip_connect,
		.recvfrom		= __ip_recvfrom,
		.sendmsg		= __ip_sendmsg,
		.sendto			= __ip_sendto,
		.tos			= __ip4_tos,
		.endpoint2kernel	= __ip4_endpoint2kernel,
		.kernel2endpoint	= __ip4_kernel2endpoint,
	},
	[SF_IP6] = {
		.af			= AF_INET6,
		.sockaddr_size		= sizeof(struct sockaddr_in6),
		.name			= "IPv6",
		.rfc_name		= "IP6",
		.unspec_string		= "::",
		.hash			= __ip6_hash,
		.eq			= __ip6_eq,
		.addr_parse		= __ip6_addr_parse,
		.addr_print		= __ip6_addr_print,
		.addr_print_p		= __ip6_addr_print_p,
		.is_specified		= __ip6_is_specified,
		.sockaddr2endpoint	= __ip6_sockaddr2endpoint,
		.endpoint2sockaddr	= __ip6_endpoint2sockaddr,
		.addrport2sockaddr	= __ip6_addrport2sockaddr,
		.bind			= __ip_bind,
		.connect		= __ip_connect,
		.recvfrom		= __ip_recvfrom,
		.sendmsg		= __ip_sendmsg,
		.sendto			= __ip_sendto,
		.tos			= __ip6_tos,
		.endpoint2kernel	= __ip6_endpoint2kernel,
		.kernel2endpoint	= __ip6_kernel2endpoint,
	},
};


static int __ip4_addr_parse(sockaddr_t *dst, const char *src) {
	if (inet_pton(AF_INET, src, &dst->u.ipv4) == 1)
		return 0;
	return -1;
}
static int __ip6_addr_parse(sockaddr_t *dst, const char *src) {
	if (src[0] != '[') {
		if (inet_pton(AF_INET6, src, &dst->u.ipv6) == 1)
			return 0;
		return -1;
	}

	const char *ep;
	ep = strchr(src, ']');
	if (!ep)
		return -1;

	unsigned int len = ep - src - 1;
	char buf[64];
	memcpy(buf, src+1, len);
	buf[len] = '\0';

	if (inet_pton(AF_INET6, buf, &dst->u.ipv6) == 1)
		return 0;
	return -1;
}
static int __ip4_addr_print(const sockaddr_t *a, char *buf, size_t len) {
	buf[0] = '\0';
	if (!inet_ntop(AF_INET, &a->u.ipv4, buf, len))
		return -1;
	return 0;
}
static int __ip6_addr_print(const sockaddr_t *a, char *buf, size_t len) {
	buf[0] = '\0';
	if (!inet_ntop(AF_INET6, &a->u.ipv6, buf, len))
		return -1;
	return 0;
}
static int __ip6_addr_print_p(const sockaddr_t *a, char *buf, size_t len) {
	buf[0] = '\0';
	if (!inet_ntop(AF_INET6, &a->u.ipv6, buf+1, len-2))
		return -1;
	buf[0] = '[';
	strcpy(buf + strlen(buf), "]");
	return 0;
}
static unsigned int __ip4_hash(const sockaddr_t *a) {
	return a->u.ipv4.s_addr;
}
static unsigned int __ip6_hash(const sockaddr_t *a) {
	return in6_addr_hash(&a->u.ipv6);
}
static int __ip4_eq(const sockaddr_t *a, const sockaddr_t *b) {
	return !memcmp(&a->u.ipv4, &b->u.ipv4, sizeof(a->u.ipv4));
}
static int __ip6_eq(const sockaddr_t *a, const sockaddr_t *b) {
	return !memcmp(&a->u.ipv6, &b->u.ipv6, sizeof(a->u.ipv6));
}
static int __ip4_is_specified(const sockaddr_t *a) {
	return a->u.ipv4.s_addr != 0;
}
static int __ip6_is_specified(const sockaddr_t *a) {
	return a->u.ipv6.s6_addr32[0] != 0
		&& a->u.ipv6.s6_addr32[1] != 0
		&& a->u.ipv6.s6_addr32[2] != 0
		&& a->u.ipv6.s6_addr32[3] != 0;
}
static int __ip4_sockaddr2endpoint(endpoint_t *ep, const void *p) {
	const struct sockaddr_in *sin = p;
	if (sin->sin_family != AF_INET)
		return -1;
	ZERO(*ep);
	ep->address.family = &__socket_families[SF_IP4];
	ep->address.u.ipv4 = sin->sin_addr;
	ep->port = ntohs(sin->sin_port);
	return 0;
}
static int __ip6_sockaddr2endpoint(endpoint_t *ep, const void *p) {
	const struct sockaddr_in6 *sin = p;
	if (sin->sin6_family != AF_INET6)
		return -1;
	ZERO(*ep);
	ep->address.family = &__socket_families[SF_IP6];
	ep->address.u.ipv6 = sin->sin6_addr;
	ep->port = ntohs(sin->sin6_port);
	return 0;
}
static int __ip4_endpoint2sockaddr(void *p, const endpoint_t *ep) {
	return __ip4_addrport2sockaddr(p, &ep->address, ep->port);
}
static int __ip6_endpoint2sockaddr(void *p, const endpoint_t *ep) {
	return __ip6_addrport2sockaddr(p, &ep->address, ep->port);
}
static int __ip4_addrport2sockaddr(void *p, const sockaddr_t *sa, unsigned int port) {
	struct sockaddr_in *sin = p;
	ZERO(*sin);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	if (sa)
		sin->sin_addr = sa->u.ipv4;
	return 0;
}
static int __ip6_addrport2sockaddr(void *p, const sockaddr_t *sa, unsigned int port) {
	struct sockaddr_in6 *sin = p;
	ZERO(*sin);
	sin->sin6_family = AF_INET6;
	sin->sin6_port = htons(port);
	if (sa)
		sin->sin6_addr = sa->u.ipv6;
	return 0;
}
static int __ip_bind(socket_t *s, unsigned int port, const sockaddr_t *a) {
	struct sockaddr_storage sin;

	s->family->addrport2sockaddr(&sin, a, port);
	if (bind(s->fd, (struct sockaddr *) &sin, s->family->sockaddr_size))
		return -1;
	return 0;
}
static int __ip_connect(socket_t *s, const endpoint_t *ep) {
	struct sockaddr_storage sin;

	s->family->endpoint2sockaddr(&sin, ep);
	if (connect(s->fd, (struct sockaddr *) &sin, s->family->sockaddr_size))
		return -1;
	return 0;
}
static ssize_t __ip_recvfrom(socket_t *s, void *buf, size_t len, endpoint_t *ep) {
	ssize_t ret;
	struct sockaddr_storage sin;
	socklen_t sinlen;

	sinlen = s->family->sockaddr_size;
	ret = recvfrom(s->fd, buf, len, 0, (void *) &sin, &sinlen);
	if (ret < 0)
		return ret;
	s->family->sockaddr2endpoint(ep, &sin);
	return ret;
}
static ssize_t __ip_sendmsg(socket_t *s, struct msghdr *mh, const endpoint_t *ep) {
	struct sockaddr_storage sin;

	s->family->endpoint2sockaddr(&sin, ep);
	mh->msg_name = &sin;
	mh->msg_namelen = s->family->sockaddr_size;

	return sendmsg(s->fd, mh, 0);
}
static ssize_t __ip_sendto(socket_t *s, const void *buf, size_t len, const endpoint_t *ep) {
	struct sockaddr_storage sin;

	s->family->endpoint2sockaddr(&sin, ep);
	return sendto(s->fd, buf, len, 0, (void *) &sin, s->family->sockaddr_size);
}
static int __ip4_tos(socket_t *s, unsigned int tos) {
	unsigned char ctos;
	ctos = tos;
	setsockopt(s->fd, IPPROTO_IP, IP_TOS, &ctos, sizeof(ctos));
	return 0;
}
static int __ip6_tos(socket_t *s, unsigned int tos) {
	setsockopt(s->fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
	return 0;
}
static void __ip4_endpoint2kernel(struct re_address *ra, const endpoint_t *ep) {
	ZERO(*ra);
	ra->family = AF_INET;
	ra->u.ipv4 = ep->address.u.ipv4.s_addr;
	ra->port = ep->port;
}
static void __ip6_endpoint2kernel(struct re_address *ra, const endpoint_t *ep) {
	ZERO(*ra);
	ra->family = AF_INET6;
	memcpy(ra->u.ipv6, &ep->address.u.ipv6, sizeof(ra->u.ipv6));
	ra->port = ep->port;
}
void kernel2endpoint(endpoint_t *ep, const struct re_address *ra) {
	ZERO(*ep);
	if (ra->family == AF_INET)
		ep->address.family = __get_socket_family_enum(SF_IP4);
	else if (ra->family == AF_INET6)
		ep->address.family = __get_socket_family_enum(SF_IP6);
	else
		abort();
	ep->port = ra->port;
	ep->address.family->kernel2endpoint(ep, ra);
}
static void __ip4_kernel2endpoint(endpoint_t *ep, const struct re_address *ra) {
	ep->address.u.ipv4.s_addr = ra->u.ipv4;
}
static void __ip6_kernel2endpoint(endpoint_t *ep, const struct re_address *ra) {
	memcpy(&ep->address.u.ipv6, ra->u.ipv6, sizeof(ep->address.u.ipv6));
}



unsigned int sockaddr_hash(const sockaddr_t *a) {
	return a->family->hash(a) ^ g_direct_hash(a->family);
}
int sockaddr_eq(const sockaddr_t *a, const sockaddr_t *b) {
	return a->family == b->family && a->family->eq(a, b);
}
unsigned int g_sockaddr_hash(const void *a) {
	return sockaddr_hash(a);
}
int g_sockaddr_eq(const void *a, const void *b) {
	return sockaddr_eq(a, b);
}


unsigned int endpoint_hash(const endpoint_t *a) {
	return sockaddr_hash(&a->address) ^ a->port;
}
int endpoint_eq(const endpoint_t *a, const endpoint_t *b) {
	return sockaddr_eq(&a->address, &b->address) && a->port == b->port;
}
unsigned int g_endpoint_hash(const void *a) {
	return endpoint_hash(a);
}
int g_endpoint_eq(const void *a, const void *b) {
	return endpoint_eq(a, b);
}



int sockaddr_parse_any(sockaddr_t *dst, const char *src) {
	int i;
	sockfamily_t *fam;

	for (i = 0; i < __SF_LAST; i++) {
		fam = &__socket_families[i];
		if (!fam->addr_parse(dst, src)) {
			dst->family = fam;
			return 0;
		}
	}
	return -1;
}
int sockaddr_parse_any_str(sockaddr_t *dst, const str *src) {
	char buf[64];
	if (src->len >= sizeof(buf))
		return -1;
	sprintf(buf, STR_FORMAT, STR_FMT(src));
	return sockaddr_parse_any(dst, buf);
}
int sockaddr_parse_str(sockaddr_t *dst, sockfamily_t *fam, const str *src) {
	char buf[64];
	if (src->len >= sizeof(buf))
		return -1;
	if (!fam)
		return -1;
	sprintf(buf, STR_FORMAT, STR_FMT(src));
	dst->family = fam;
	return fam->addr_parse(dst, buf);
}
sockfamily_t *get_socket_family_rfc(const str *s) {
	int i;
	sockfamily_t *fam;

	for (i = 0; i < __SF_LAST; i++) {
		fam = &__socket_families[i];
		if (!str_cmp(s, fam->rfc_name))
			return fam;
	}
	return NULL;
}
sockfamily_t *__get_socket_family_enum(enum socket_families i) {
	return &__socket_families[i];
}
int endpoint_parse_any(endpoint_t *d, const char *s) {
	int i;
	sockfamily_t *fam;
	unsigned int len;
	const char *ep;
	char buf[64];

	ep = strrchr(s, ':');
	if (!ep) {
		if (strchr(s, '.'))
			return -1;
		/* just a port number */
		d->port = atoi(s);
		ZERO(d->address);
		d->address.family = __get_socket_family_enum(SF_IP4);
		return 0;
	}
	len = ep - s;
	if (len >= sizeof(buf))
		return -1;
	d->port = atoi(ep+1);
	if (d->port > 0xffff)
		return -1;
	sprintf(buf, "%.*s", len, s);

	for (i = 0; i < __SF_LAST; i++) {
		fam = &__socket_families[i];
		if (!fam->addr_parse(&d->address, buf)) {
			d->address.family = fam;
			return 0;
		}
	}
	return -1;
}

static int __socket(socket_t *r, int type, sockfamily_t *fam) {
	ZERO(*r);
	r->family = fam;
	r->fd = socket(fam->af, type, 0);
	if (r->fd == -1)
		return -1;

	return 0;
}

int open_socket(socket_t *r, int type, unsigned int port, const sockaddr_t *sa) {
	sockfamily_t *fam;

	fam = sa->family;

	if (__socket(r, type, fam))
		return -1;

	nonblock(r->fd);
	reuseaddr(r->fd);

	if (port > 0xffff)
		goto fail;

	if (fam->bind(r, port, sa))
		goto fail;

	r->local.port = port;
	r->local.address = *sa;

	return 0;

fail:
	close_socket(r);
	return -1;
}

int connect_socket(socket_t *r, int type, const endpoint_t *ep) {
	sockfamily_t *fam;

	fam = ep->address.family;

	if (__socket(r, type, fam))
		return -1;
	if (fam->connect(r, ep))
		goto fail;

	r->remote = *ep;

	return 0;

fail:
	close_socket(r);
	return -1;
}

int connect_socket_nb(socket_t *r, int type, const endpoint_t *ep) {
	sockfamily_t *fam;
	int ret = 0;

	fam = ep->address.family;

	if (__socket(r, type, fam))
		return -1;
	nonblock(r->fd);
	if (fam->connect(r, ep)) {
		if (errno != EINPROGRESS)
			goto fail;
		ret = 1;
	}

	r->remote = *ep;

	return ret;

fail:
	close_socket(r);
	return -1;
}

void close_socket(socket_t *r) {
	if (!r || r->fd == -1)
		return;
	close(r->fd);
	r->fd = -1;
	ZERO(r->local);
	ZERO(r->remote);
}




socktype_t *get_socket_type(const str *s) {
	int i;
	socktype_t *tp;

	for (i = 0; i < G_N_ELEMENTS(__socket_types); i++) {
		tp = &__socket_types[i];
		if (!str_cmp(s, tp->name))
			return tp;
		if (!str_cmp(s, tp->name_uc))
			return tp;
	}
	return NULL;
}




void socket_init(void) {
	int i;

	for (i = 0; i < __SF_LAST; i++)
		__socket_families[i].idx = i;
}
