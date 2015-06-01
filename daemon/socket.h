#ifndef _SOCKET_H_
#define _SOCKET_H_


#include <arpa/inet.h>
#include <sys/types.h>




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

typedef struct socket_address sockaddr_t;
typedef struct endpoint endpoint_t;
typedef struct socket socket_t;
typedef const struct socket_type socktype_t;
typedef const struct socket_family sockfamily_t;


#include "str.h"



struct local_intf;


struct socket_type {
	const char			*name; /* lower case */
	const char			*name_uc; /* upper case */
};
struct socket_family {
	int				idx;
	int				af;
	size_t				sockaddr_size;
	const char			*name; /* "IPv4" */
	const char			*rfc_name; /* "IP4" */
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
	ssize_t				(*recvfrom)(socket_t *, void *, size_t, endpoint_t *);
	ssize_t				(*sendmsg)(socket_t *, struct msghdr *, const endpoint_t *);
	ssize_t				(*sendto)(socket_t *, const void *, size_t, const endpoint_t *);
	int				(*tos)(socket_t *, unsigned int);
};
struct socket_address {
	sockfamily_t			*family;
	union {
		struct in_addr			ipv4;
		struct in6_addr			ipv6;
	} u;
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



#include "aux.h"


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
		return 0;
	}
	sockaddr_print(a, buf, THREAD_BUF_SIZE);
	return buf;
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
INLINE int endpoint_print(const endpoint_t *ep, char *buf, size_t len) {
	return sockaddr_print_port(&ep->address, ep->port, buf, len);
}
INLINE char *endpoint_print_buf(const endpoint_t *ep) {
	return sockaddr_print_port_buf(&ep->address, ep->port);
}
INLINE int is_addr_unspecified(const sockaddr_t *a) {
	if (!a || !a->family)
		return 1;
	return !a->family->is_specified(a);
}
#define socket_recvfrom(s,a...) (s)->family->recvfrom((s), a)
#define socket_sendmsg(s,a...) (s)->family->sendmsg((s), a)
#define socket_sendto(s,a...) (s)->family->sendto((s), a)
INLINE ssize_t socket_sendiov(socket_t *s, const struct iovec *v, unsigned int len, const endpoint_t *dst) {
	struct msghdr mh;
	ZERO(mh);
	mh.msg_iov = (void *) v;
	mh.msg_iovlen = len;
	return socket_sendmsg(s, &mh, dst);
}



/* XXX obsolete these? */
INLINE void nonblock(int fd) {
	fcntl(fd, F_SETFL, O_NONBLOCK);
}
INLINE void reuseaddr(int fd) {
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}
INLINE void ipv6only(int fd, int yn) {
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yn, sizeof(yn));
}



void socket_init(void);

int open_socket(socket_t *r, int type, unsigned int port, const sockaddr_t *);
int connect_socket(socket_t *r, int type, const endpoint_t *ep);
int connect_socket_nb(socket_t *r, int type, const endpoint_t *ep);
void close_socket(socket_t *r);

sockfamily_t *get_socket_family_rfc(const str *s);
sockfamily_t *__get_socket_family_enum(enum socket_families);
int sockaddr_parse_any(sockaddr_t *dst, const char *src);
int sockaddr_parse_any_str(sockaddr_t *dst, const str *src);
int sockaddr_parse_str(sockaddr_t *dst, sockfamily_t *fam, const str *src);
int endpoint_parse_any(endpoint_t *, const char *);

unsigned int sockaddr_hash(const sockaddr_t *);
int sockaddr_eq(const sockaddr_t *, const sockaddr_t *); /* true/false */
unsigned int g_sockaddr_hash(const void *);
int g_sockaddr_eq(const void *, const void *); /* true/false */

unsigned int endpoint_hash(const endpoint_t *);
int endpoint_eq(const endpoint_t *, const endpoint_t *); /* true/false */
unsigned int g_endpoint_hash(const void *);
int g_endpoint_eq(const void *, const void *); /* true/false */

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
INLINE int ipv46_any_convert(endpoint_t *ep) {
	if (ep->address.family->af != AF_INET)
		return 0;
	if (!is_addr_unspecified(&ep->address))
		return 0;
	ep->address.family = __get_socket_family_enum(SF_IP6);
	ZERO(ep->address.u.ipv6);
	return 1;
}



socktype_t *get_socket_type(const str *s);


#endif
