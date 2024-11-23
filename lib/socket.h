#ifndef _SOCKET_H_
#define _SOCKET_H_


#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include "containers.h"



enum socket_families {
	SF_IP4 = 0,
	SF_IP6,
	__SF_LAST
};



struct socket_address;
struct socket_type;
struct socket_family;
struct endpoint;
struct socket;
struct re_address;

typedef struct socket_address sockaddr_t;
typedef struct endpoint endpoint_t;
typedef struct socket socket_t;
typedef const struct socket_type socktype_t;
typedef const struct socket_family sockfamily_t;

TYPED_GQUEUE(socket, socket_t)


#include "str.h"



#define MAX_PACKET_HEADER_LEN 48 // 40 bytes IPv6 + 8 bytes UDP



struct local_intf;


struct socket_type {
	const char			*name; /* lower case */
	const char			*name_uc; /* upper case */
};
struct socket_family {
	int				idx;
	int				af;
	unsigned int			ethertype;
	size_t				sockaddr_size;
	const char			*name; /* "IPv4" */
	const char			*rfc_name; /* "IP4" */
	const char			*unspec_string; /* 0.0.0.0 or :: */
	unsigned int			(*hash)(const sockaddr_t *);
	int				(*eq)(const sockaddr_t *, const sockaddr_t *);
	int				(*addr_parse)(sockaddr_t *, const char *);
	int				(*addr_print)(const sockaddr_t *, char *, size_t);
	int				(*addr_print_p)(const sockaddr_t *, char *, size_t);
	int				(*is_specified)(const sockaddr_t *);
	int				(*sockaddr2endpoint)(endpoint_t *, const void *);
	int				(*endpoint2sockaddr)(void *, const endpoint_t *);
	int				(*addrport2sockaddr)(void *, const sockaddr_t *, unsigned int);
	int				(*bind)(socket_t *, unsigned int, const sockaddr_t *);
	int				(*connect)(socket_t *, const endpoint_t *);
	int				(*listen)(socket_t *, int);
	int				(*accept)(socket_t *, socket_t *);
	int				(*timestamping)(socket_t *);
	int				(*pktinfo)(socket_t *);
	ssize_t				(*recvfrom)(socket_t *, void *, size_t, endpoint_t *);
	ssize_t				(*recvfrom_ts)(socket_t *, void *, size_t, endpoint_t *, struct timeval *);
	ssize_t				(*recvfrom_to)(socket_t *, void *, size_t, endpoint_t *, sockaddr_t *);
	ssize_t				(*sendmsg)(socket_t *, struct msghdr *, const endpoint_t *);
	ssize_t				(*sendto)(socket_t *, const void *, size_t, const endpoint_t *);
	int				(*tos)(socket_t *, unsigned int);
	void				(*pmtu_disc)(socket_t *, int);
	int				(*error)(socket_t *);
	void				(*endpoint2kernel)(struct re_address *, const endpoint_t *);
	void				(*kernel2endpoint)(endpoint_t *, const struct re_address *);
	unsigned int			(*packet_header)(unsigned char *, const endpoint_t *, const endpoint_t *,
						unsigned int);
	void				(*cmsg_pktinfo)(struct cmsghdr *, const sockaddr_t *);
};
struct socket_address {
	sockfamily_t			*family;
	union {
		struct in_addr			ipv4;
		struct in6_addr			ipv6;
	};
};
struct endpoint {
	sockaddr_t			address;
	unsigned int			port;
};
struct socket {
	int				fd;
	sockfamily_t			*family;
	endpoint_t			local;
	endpoint_t			remote;
};




extern socktype_t *socktype_udp;



#include "auxlib.h"


INLINE int sockaddr_print(const sockaddr_t *a, char *buf, size_t len) {
	if (!a->family) {
		buf[0] = '\0';
		return 0;
	}
	return a->family->addr_print(a, buf, len);
}
INLINE char *sockaddr_print_buf(const sockaddr_t *a) {
	char *buf = get_thread_buf();
	if (!a->family) {
		buf[0] = '\0';
		return buf;
	}
	sockaddr_print(a, buf, THREAD_BUF_SIZE);
	return buf;
}
INLINE int sockaddr_print_gstring(GString *s, const sockaddr_t *a) {
	if (!a->family)
		return 0;
	char buf[THREAD_BUF_SIZE];
	if (sockaddr_print(a, buf, THREAD_BUF_SIZE))
		return -1;
	g_string_append(s, buf);
	return 0;
}
INLINE int sockaddr_print_p(const sockaddr_t *a, char *buf, size_t len) {
	if (!a->family) {
		buf[0] = '\0';
		return 0;
	}
	return a->family->addr_print_p(a, buf, len);
}
INLINE char *sockaddr_print_p_buf(const sockaddr_t *a) {
	char *buf = get_thread_buf();
	sockaddr_print_p(a, buf, THREAD_BUF_SIZE);
	return buf;
}
INLINE int sockaddr_print_port(const sockaddr_t *a, unsigned int port, char *buf, size_t len) {
	if (!a->family) {
		buf[0] = '\0';
		return 0;
	}
	if (a->family->addr_print_p(a, buf, len-6))
		return -1;
	sprintf(buf + strlen(buf), ":%u", port);
	return 0;
}
INLINE char *sockaddr_print_port_buf(const sockaddr_t *a, unsigned int port) {
	char *buf = get_thread_buf();
	sockaddr_print_port(a, port, buf, THREAD_BUF_SIZE);
	return buf;
}
INLINE int sockaddr_print_port_gstring(GString *s, const sockaddr_t *a, unsigned int port) {
	char buf[THREAD_BUF_SIZE];
	if (sockaddr_print_port(a, port, buf, THREAD_BUF_SIZE))
		return -1;
	g_string_append(s, buf);
	return 0;

}
INLINE int endpoint_print(const endpoint_t *ep, char *buf, size_t len) {
	return sockaddr_print_port(&ep->address, ep->port, buf, len);
}
INLINE char *endpoint_print_buf(const endpoint_t *ep) {
	return sockaddr_print_port_buf(&ep->address, ep->port);
}
INLINE int endpoint_print_gstring(GString *s, const endpoint_t *ep) {
	return sockaddr_print_port_gstring(s, &ep->address, ep->port);
}
INLINE int is_addr_unspecified(const sockaddr_t *a) {
	if (!a || !a->family)
		return 1;
	return !a->family->is_specified(a);
}
#define socket_recvfrom(s,a...) (s)->family->recvfrom((s), a)
#define socket_recvfrom_ts(s,a...) (s)->family->recvfrom_ts((s), a)
#define socket_recvfrom_to(s,a...) (s)->family->recvfrom_to((s), a)
#define socket_sendmsg(s,a...) (s)->family->sendmsg((s), a)
#define socket_sendto(s,a...) (s)->family->sendto((s), a)
#define socket_error(s) (s)->family->error((s))
#define socket_timestamping(s) (s)->family->timestamping((s))
#define socket_pktinfo(s) (s)->family->pktinfo((s))
INLINE ssize_t socket_sendiov(socket_t *s, const struct iovec *v, unsigned int len, const endpoint_t *dst,
		const sockaddr_t *src)
{
	struct msghdr mh = {0};
	char ctrl[64] = {0};

	mh.msg_iov = (void *) v;
	mh.msg_iovlen = len;

	if (src && src->family) {
		mh.msg_control = ctrl;
		mh.msg_controllen = sizeof(ctrl);

		struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);

		s->family->cmsg_pktinfo(cm, src);
		cm = CMSG_NXTHDR(&mh, cm);
		assert(cm != NULL);

		mh.msg_controllen = (char *) cm - ctrl;
	}

	return socket_sendmsg(s, &mh, dst);
}
INLINE ssize_t socket_sendto_from(socket_t *s, const void *b, size_t l, const endpoint_t *dst, sockaddr_t *src) {
	return socket_sendiov(s, &(struct iovec) { .iov_base = (void *) b, .iov_len = l }, l, dst, src);
}

#define socket_recvfrom_parse_cmsg(tv, to, parse_to, msgh, firsthdr, nexthdr) do { \
	if ((*tv) || (*to)) { \
		struct cmsghdr *cm; \
		for (cm = firsthdr; cm; cm = nexthdr) { \
			if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP && (*tv)) { \
				*(*tv) = *((struct timeval *) CMSG_DATA(cm)); \
				(*tv) = NULL; \
			} \
			if (parse && (*to) && parse_to(cm, (*to))) \
				(*to) = NULL; \
		} \
		if (G_UNLIKELY((*tv))) { \
			ilog(LOG_WARNING, "No receive timestamp received from kernel"); \
			ZERO(*(*tv)); \
		} \
		if (G_UNLIKELY((*to))) { \
			ilog(LOG_WARNING, "No local address received from kernel"); \
			ZERO(*(*to)); \
		} \
	} \
	if (G_UNLIKELY(((msgh)->msg_flags & MSG_TRUNC))) \
		ilog(LOG_WARNING, "Kernel indicates that data was truncated"); \
	if (G_UNLIKELY(((msgh)->msg_flags & MSG_CTRUNC))) \
		ilog(LOG_WARNING, "Kernel indicates that ancillary data was truncated"); \
} while (0)


/* XXX obsolete these? */
INLINE void usertimeout(int fd, unsigned int val) {
	// coverity[check_return : FALSE]
	setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &val, sizeof(val));
}
INLINE void nonblock(int fd) {
	// coverity[check_return : FALSE]
	fcntl(fd, F_SETFL, O_NONBLOCK);
}
INLINE void reuseaddr(int fd) {
	int one = 1;
	// coverity[check_return : FALSE]
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}
INLINE void ipv6only(int fd, int yn) {
	// coverity[check_return : FALSE]
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yn, sizeof(yn));
}
INLINE int socket_cpu_affinity(socket_t *s, int cpu) {
#ifndef SO_INCOMING_CPU
	errno = ENOTSUP;
	return -1;
#else
	return setsockopt(s->fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));
#endif
}



void socket_init(void);

int open_socket(socket_t *r, int type, unsigned int port, const sockaddr_t *);
int open_v46_socket(socket_t *r, int type);
int connect_socket(socket_t *r, int type, const endpoint_t *ep);
int connect_socket_nb(socket_t *r, int type, const endpoint_t *ep); // 1 == in progress
int connect_socket_retry(socket_t *r); // retries connect() while in progress
int close_socket(socket_t *r);
int reset_socket(socket_t *r);
void move_socket(socket_t *dst, socket_t *src);
void dummy_socket(socket_t *r, const sockaddr_t *);

sockfamily_t *get_socket_family_rfc(const str *s);
sockfamily_t *__get_socket_family_enum(enum socket_families);
int sockaddr_parse_any(sockaddr_t *dst, const char *src);
int sockaddr_parse_any_str(sockaddr_t *dst, const str *src);
int sockaddr_parse_str(sockaddr_t *dst, sockfamily_t *fam, const str *src);
int endpoint_parse_any(endpoint_t *, const char *); // address (ip) optional
int sockaddr_getaddrinfo_alt(sockaddr_t *a, sockaddr_t *a2, const char *s);
int endpoint_parse_any_getaddrinfo_alt(endpoint_t *d, endpoint_t *d2, const char *s); // address (ip or hostname) optional
INLINE int endpoint_parse_any_getaddrinfo(endpoint_t *d, const char *s);
void endpoint_parse_sockaddr_storage(endpoint_t *, struct sockaddr_storage *);
void kernel2endpoint(endpoint_t *ep, const struct re_address *ra);

unsigned int sockaddr_hash(const sockaddr_t *);
bool sockaddr_eq(const sockaddr_t *, const sockaddr_t *);
guint sockaddr_t_hash(gconstpointer); // for glib
gint sockaddr_t_eq(gconstpointer, gconstpointer); // true/false, for glib

unsigned int endpoint_hash(const endpoint_t *);
gboolean endpoint_eq(const endpoint_t *, const endpoint_t *); /* true/false */

INLINE sockfamily_t *get_socket_family_enum(enum socket_families i) {
	if (i >= __SF_LAST)
		return NULL;
	return __get_socket_family_enum(i);
}
INLINE int endpoint_parse_port_any(endpoint_t *e, const char *p, unsigned int port) {
	if (port > 0xffff)
		return -1;
	e->port = port;
	return sockaddr_parse_any(&e->address, p);
}
// address (ip) required
INLINE int endpoint_parse_any_full(endpoint_t *d, const char *s) {
	int ret;
	ret = endpoint_parse_any(d, s);
	if (ret)
		return ret;
	if (is_addr_unspecified(&d->address))
		return -1;
	return 0;
}
// address (ip or hostname) required
INLINE int endpoint_parse_any_getaddrinfo_full(endpoint_t *d, const char *s) {
	int ret;
	ret = endpoint_parse_any_getaddrinfo(d, s);
	if (ret)
		return ret;
	if (is_addr_unspecified(&d->address))
		return -1;
	return 0;
}
INLINE int sockaddr_getaddrinfo(sockaddr_t *a, const char *s) {
	return sockaddr_getaddrinfo_alt(a, NULL, s);
}
INLINE int endpoint_parse_any_getaddrinfo(endpoint_t *d, const char *s) {
	return endpoint_parse_any_getaddrinfo_alt(d, NULL, s);
}
INLINE int ipv46_any_convert(endpoint_t *ep) {
	if (ep->address.family->af != AF_INET)
		return 0;
	if (!is_addr_unspecified(&ep->address))
		return 0;
	ep->address.family = __get_socket_family_enum(SF_IP6);
	ZERO(ep->address.ipv6);
	return 1;
}
// needs a writeable str
INLINE int endpoint_parse_any_str(endpoint_t *d, str *s) {
	char tmp = s->s[s->len];
	s->s[s->len] = '\0';
	int ret = endpoint_parse_any(d, s->s);
	s->s[s->len] = tmp;
	return ret;
}

#define endpoint_packet_header(o, src, dst, len) (dst)->address.family->packet_header(o, src, dst, len)

INLINE void set_tos(socket_t *s, unsigned int tos) {
	s->family->tos(s, tos);
}
INLINE void set_pmtu_disc(socket_t *s, int opt) {
	if (s->family->pmtu_disc)
		s->family->pmtu_disc(s, opt);
}

socktype_t *get_socket_type(const str *s);
socktype_t *get_socket_type_c(const char *s);


#endif
