#include "socket.h"
#include <glib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include "str.h"
#include "xt_RTPENGINE.h"
#include "log.h"

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
static int __ip_listen(socket_t *s, int backlog);
static int __ip_accept(socket_t *s, socket_t *new_sock);
static int __ip_timestamping(socket_t *s);
static int __ip4_sockaddr2endpoint(endpoint_t *, const void *);
static int __ip6_sockaddr2endpoint(endpoint_t *, const void *);
static int __ip4_endpoint2sockaddr(void *, const endpoint_t *);
static int __ip6_endpoint2sockaddr(void *, const endpoint_t *);
static int __ip4_addrport2sockaddr(void *, const sockaddr_t *, unsigned int);
static int __ip6_addrport2sockaddr(void *, const sockaddr_t *, unsigned int);
static ssize_t __ip_recvfrom(socket_t *s, void *buf, size_t len, endpoint_t *ep);
static ssize_t __ip_recvfrom_ts(socket_t *s, void *buf, size_t len, endpoint_t *ep, struct timeval *);
static ssize_t __ip_sendmsg(socket_t *s, struct msghdr *mh, const endpoint_t *ep);
static ssize_t __ip_sendto(socket_t *s, const void *buf, size_t len, const endpoint_t *ep);
static int __ip4_tos(socket_t *, unsigned int);
static int __ip6_tos(socket_t *, unsigned int);
static int __ip_error(socket_t *s);
static void __ip4_endpoint2kernel(struct re_address *, const endpoint_t *);
static void __ip6_endpoint2kernel(struct re_address *, const endpoint_t *);
static void __ip4_kernel2endpoint(endpoint_t *ep, const struct re_address *ra);
static void __ip6_kernel2endpoint(endpoint_t *ep, const struct re_address *ra);
static unsigned int __ip4_packet_header(unsigned char *, const endpoint_t *, const endpoint_t *,
		unsigned int);
static unsigned int __ip6_packet_header(unsigned char *, const endpoint_t *, const endpoint_t *,
		unsigned int);



static socktype_t __socket_types[] = {
	{
		.name		= "udp",
		.name_uc	= "UDP",
	},
};

static struct socket_family __socket_families[__SF_LAST] = {
	[SF_IP4] = {
		.af			= AF_INET,
		.ethertype		= 0x0800,
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
		.listen			= __ip_listen,
		.accept			= __ip_accept,
		.timestamping		= __ip_timestamping,
		.recvfrom		= __ip_recvfrom,
		.recvfrom_ts		= __ip_recvfrom_ts,
		.sendmsg		= __ip_sendmsg,
		.sendto			= __ip_sendto,
		.tos			= __ip4_tos,
		.error			= __ip_error,
		.endpoint2kernel	= __ip4_endpoint2kernel,
		.kernel2endpoint	= __ip4_kernel2endpoint,
		.packet_header		= __ip4_packet_header,
	},
	[SF_IP6] = {
		.af			= AF_INET6,
		.ethertype		= 0x86dd,
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
		.listen			= __ip_listen,
		.accept			= __ip_accept,
		.timestamping		= __ip_timestamping,
		.recvfrom		= __ip_recvfrom,
		.recvfrom_ts		= __ip_recvfrom_ts,
		.sendmsg		= __ip_sendmsg,
		.sendto			= __ip_sendto,
		.tos			= __ip6_tos,
		.error			= __ip_error,
		.endpoint2kernel	= __ip6_endpoint2kernel,
		.kernel2endpoint	= __ip6_kernel2endpoint,
		.packet_header		= __ip6_packet_header,
	},
};



socktype_t *socktype_udp;




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
		|| a->u.ipv6.s6_addr32[1] != 0
		|| a->u.ipv6.s6_addr32[2] != 0
		|| a->u.ipv6.s6_addr32[3] != 0;
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
	if (bind(s->fd, (struct sockaddr *) &sin, s->family->sockaddr_size)) {
		__C_DBG("bind fail, fd=%d, port=%d", s->fd, s->local.port);
		return -1;
	} else {
		__C_DBG("bind success, fd=%d, port=%d", s->fd, s->local.port);
	}

	return 0;
}
static int __ip_connect(socket_t *s, const endpoint_t *ep) {
	struct sockaddr_storage sin;

	s->family->endpoint2sockaddr(&sin, ep);
	if (connect(s->fd, (struct sockaddr *) &sin, s->family->sockaddr_size)) {
		__C_DBG("connect fail, fd=%d, port=%d", s->fd, s->local.port);
		return -1;
	} else {
		__C_DBG("connect success, fd=%d, port=%d", s->fd, s->local.port);
	}
	return 0;
}
static int __ip_listen(socket_t *s, int backlog) {
	return listen(s->fd, backlog);
}
static int __ip_accept(socket_t *s, socket_t *newsock) {
	int nfd;
	struct sockaddr_storage sin;
	socklen_t sinlen;

	ZERO(*newsock);

	sinlen = sizeof(sin);
	nfd = accept(s->fd, (struct sockaddr *) &sin, &sinlen);
	if (nfd == -1) {
		__C_DBG("accept fail, fd=%d, port=%d", s->fd, s->local.port);
		return -1;
	}

	newsock->fd = nfd;
	newsock->family = s->family;
	newsock->local = s->local;
	s->family->sockaddr2endpoint(&newsock->remote, &sin);

	return 0;
}
static ssize_t __ip_recvfrom_ts(socket_t *s, void *buf, size_t len, endpoint_t *ep, struct timeval *tv) {
	ssize_t ret;
	struct sockaddr_storage sin;
	struct msghdr msg;
	struct iovec iov;
	char ctrl[64];
	struct cmsghdr *cm;

	ZERO(msg);
	msg.msg_name = &sin;
	msg.msg_namelen = s->family->sockaddr_size;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof(ctrl);
	ZERO(iov);
	iov.iov_base = buf;
	iov.iov_len = len;

	ret = recvmsg(s->fd, &msg, 0);
	if (ret < 0)
		return ret;
	s->family->sockaddr2endpoint(ep, &sin);

	if (tv) {
		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
				*tv = *((struct timeval *) CMSG_DATA(cm));
				tv = NULL;
				break;
			}
		}
		if (G_UNLIKELY(tv)) {
			ilog(LOG_WARNING, "No receive timestamp received from kernel");
			ZERO(*tv);
		}
	}
	if (G_UNLIKELY((msg.msg_flags & MSG_TRUNC)))
		ilog(LOG_WARNING, "Kernel indicates that data was truncated");
	if (G_UNLIKELY((msg.msg_flags & MSG_CTRUNC)))
		ilog(LOG_WARNING, "Kernel indicates that ancillary data was truncated");

	return ret;
}
static ssize_t __ip_recvfrom(socket_t *s, void *buf, size_t len, endpoint_t *ep) {
	return __ip_recvfrom_ts(s, buf, len, ep, NULL);
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
	if (setsockopt(s->fd, IPPROTO_IP, IP_TOS, &ctos, sizeof(ctos)))
		ilog(LOG_ERR, "Failed to set TOS on IPv4 socket: %s", strerror(errno));
	return 0;
}
static int __ip6_tos(socket_t *s, unsigned int tos) {
	if (setsockopt(s->fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)))
		ilog(LOG_ERR, "Failed to set TOS on IPv6 socket: %s", strerror(errno));
	return 0;
}
static int __ip_error(socket_t *s) {
	int optval;
	socklen_t optlen = sizeof(optval);
	if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen))
		return -1;
	return optval;
}
static int __ip_timestamping(socket_t *s) {
	int one = 1;
	if (setsockopt(s->fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one)))
		return -1;
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
static unsigned int __udp_packet_header(unsigned char *out, unsigned int src, unsigned int dst,
		unsigned int payload_len)
{
	struct udphdr *udp = (void *) out;

	ZERO(*udp);
	udp->source = htons(src);
	udp->dest = htons(dst);
	udp->len = htons(sizeof(*udp) + payload_len);
	return sizeof(*udp);
}
static unsigned int __ip4_packet_header(unsigned char *out, const endpoint_t *src, const endpoint_t *dst,
		unsigned int payload_len)
{
	struct iphdr *iph = (void *) out;
	unsigned char *nxt = (void *) out + sizeof(*iph);

	unsigned int udp_len = __udp_packet_header(nxt, src->port, dst->port, payload_len);

	ZERO(*iph);
	iph->ihl = sizeof(*iph) >> 2; // normally 5 ~ 20 bytes
	iph->version = 4;
	iph->tot_len = htons(sizeof(*iph) + udp_len + payload_len);
	iph->ttl = 64;
	iph->protocol = 17; // UDP
	iph->saddr = src->address.u.ipv4.s_addr;
	iph->daddr = dst->address.u.ipv4.s_addr;

	return sizeof(*iph) + udp_len;
}
static unsigned int __ip6_packet_header(unsigned char *out, const endpoint_t *src, const endpoint_t *dst,
		unsigned int payload_len)
{
	struct ip6_hdr *iph = (void *) out;
	unsigned char *nxt = (void *) out + sizeof(*iph);

	unsigned int udp_len = __udp_packet_header(nxt, src->port, dst->port, payload_len);

	ZERO(*iph);
	iph->ip6_vfc = 0x60; // version 6;
	//iph->ip6_flow = htonl(0x60000000); // version 6
	iph->ip6_plen = htons(udp_len + payload_len);
	iph->ip6_nxt = 17; // UDP
	iph->ip6_hlim = 64;
	iph->ip6_src = src->address.u.ipv6;
	iph->ip6_dst = dst->address.u.ipv6;

	return sizeof(*iph) + udp_len;
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

int endpoint_parse_any_getaddrinfo(endpoint_t *d, const char *s) {
	unsigned int len;
	const char *ep;
	char buf[64];
	void *addr;
	struct addrinfo hints, *res;
	int status;

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

	/* original s was [IPv6]:port */
	if ((len > 2) && (s[0] == '[') && (s[len - 1] == ']')) {
		sprintf(buf, "%.*s", len - 2, s + 1);
	} else {
		sprintf(buf, "%.*s", len, s);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;

	if ((status = getaddrinfo(buf, NULL, &hints, &res)) != 0) {
		__C_DBG("getaddrinfo failed for %s, status is \"%s\"\n", s, gai_strerror(status));
		return -1;
	}

	if (res->ai_family == AF_INET) { // IPv4
		struct sockaddr_in *ipv4 = (struct sockaddr_in *) res->ai_addr;
		addr = &(ipv4->sin_addr);
		memcpy(&d->address.u, addr, sizeof(struct in_addr));
		d->address.family = &__socket_families[SF_IP4];
	} else { // IPv6
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) res->ai_addr;
		addr = &(ipv6->sin6_addr);
		memcpy(&d->address.u, addr, sizeof(struct in6_addr));
		d->address.family = &__socket_families[SF_IP6];
	}

	freeaddrinfo(res);
	return 0;
}

static int __socket(socket_t *r, int type, sockfamily_t *fam) {
	ZERO(*r);
	r->family = fam;
	r->fd = socket(fam->af, type, 0);
	if (r->fd == -1) {
		__C_DBG("socket() syscall fail, fd=%d", r->fd);
		return -1;
	} else {
		__C_DBG("socket() syscall success, fd=%d", r->fd);
	}

	return 0;
}

int open_socket(socket_t *r, int type, unsigned int port, const sockaddr_t *sa) {
	sockfamily_t *fam;

	fam = sa->family;

	if (__socket(r, type, fam)) {
		__C_DBG("open socket fail, fd=%d", r->fd);
		return -1;
	}

	nonblock(r->fd);
	reuseaddr(r->fd);
	if (r->family->af == AF_INET6)
		ipv6only(r->fd, 1);

	if (port > 0xffff) {
		__C_DBG("open socket fail, port=%d > 0xfffffd", port);
		goto fail;
	}

	if (fam->bind(r, port, sa)) {
		__C_DBG("open socket fail, fd=%d, port=%d", r->fd, port);
		goto fail;
	}

	r->local.port = port;
	r->local.address = *sa;

	__C_DBG("open socket success, fd=%d, port=%d", r->fd, port);

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

int connect_socket_retry(socket_t *r) {
	int ret = 0;

	if (r->family->connect(r, &r->remote)) {
		if (errno != EINPROGRESS && errno != EALREADY && errno != EISCONN)
			goto fail;
		if (errno != EISCONN)
			ret = 1;
	}

	return ret;

fail:
	close_socket(r);
	return -1;
}

int connect_socket_nb(socket_t *r, int type, const endpoint_t *ep) {
	sockfamily_t *fam;

	fam = ep->address.family;

	if (__socket(r, type, fam))
		return -1;
	nonblock(r->fd);
	r->remote = *ep;

	return connect_socket_retry(r);
}

int close_socket(socket_t *r) {
	if (!r) {
		__C_DBG("close() syscall not called, no socket");
		return -1;
	}
	if (r->fd == -1) {
		__C_DBG("close() syscall not called, fd=%d", r->fd);
		return -1;
	}

	if (close(r->fd) != 0) {
		__C_DBG("close() syscall fail, fd=%d", r->fd);
		return -1;
	}

	__C_DBG("close() syscall success, fd=%d", r->fd);

	r->fd = -1;
	ZERO(r->local);
	ZERO(r->remote);

	return 0;
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
socktype_t *get_socket_type_c(const char *s) {
	int i;
	socktype_t *tp;

	for (i = 0; i < G_N_ELEMENTS(__socket_types); i++) {
		tp = &__socket_types[i];
		if (!strcmp(s, tp->name))
			return tp;
		if (!strcmp(s, tp->name_uc))
			return tp;
	}
	return NULL;
}




void socket_init(void) {
	int i;

	for (i = 0; i < __SF_LAST; i++)
		__socket_families[i].idx = i;

	socktype_udp = get_socket_type_c("udp");
}
