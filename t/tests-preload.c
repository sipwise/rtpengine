#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>

typedef struct {
	int used_domain,
	    wanted_domain,
	    type,
	    used_protocol,
	    wanted_protocol;
	char unix_path[256];
	struct sockaddr_storage sockname,
				peername;
	unsigned int open:1,
	             bound:1,
		     connected:1;
} socket_t;

typedef struct {
	struct sockaddr_un path;
	struct sockaddr_storage address;
	socklen_t addrlen;
} peer_t;

#define MAX_SOCKETS 4096

static socket_t real_sockets[MAX_SOCKETS];
static unsigned int anon_sock_inc;

static peer_t remote_peers[MAX_SOCKETS];
static unsigned int anon_peer_inc;
static pthread_mutex_t remote_peers_lock = PTHREAD_MUTEX_INITIALIZER;

static void do_init(void) __attribute__((constructor));
static void do_exit(void) __attribute__((destructor));

static socklen_t anon_addr(int domain, struct sockaddr_storage *sst, unsigned int id, unsigned int id2);

static void do_init(void) {
	setenv("RTPE_PRELOAD_TEST_ACTIVE", "1", 1);
}
static void do_exit(void) {
	for (int i = 0; i < MAX_SOCKETS; i++) {
		socket_t *s = &real_sockets[i];
		if (!s->open)
			continue;
		if (s->used_domain != AF_UNIX)
			continue;
		if (s->wanted_domain == AF_UNIX)
			continue;
		unlink(s->unix_path);
	}
}

static const char *path_prefix(void) {
	char *ret = getenv("TEST_SOCKET_PATH");
	if (ret)
		return ret;
	return "/tmp";
}

int socket(int domain, int type, int protocol) {
	int use_domain = domain;
	int use_protocol = protocol;

	if (domain == AF_INET || domain == AF_INET6) {
		use_domain = AF_UNIX;
		use_protocol = 0;
	}

	int (*real_socket)(int, int, int) = dlsym(RTLD_NEXT, "socket");
	int fd = real_socket(use_domain, type, use_protocol);
	if (fd < 0 || fd >= MAX_SOCKETS) {
		fprintf(stderr, "preload socket(): fd out of bounds (fd %i)\n", fd);
		return fd;
	}
	real_sockets[fd] = (socket_t) {
		.used_domain = use_domain,
		.wanted_domain = domain,
		.type = type,
		.used_protocol = use_protocol,
		.wanted_protocol = protocol,
		.open = 1,
	};

	return fd;
}

static const char *addr_translate(struct sockaddr_un *sun, const struct sockaddr *addr,
		socklen_t addrlen,
		int allow_anon)
{
	const char *err;
	char sockname[64];
	const char *any_name;
	unsigned int port;

	switch (addr->sa_family) {
		case AF_INET:;
			struct sockaddr_in *sin = (void *) addr;
			err = "addrlen too short";
			if (addrlen < sizeof(*sin))
				goto err;
			err = "failed to print network address";
			if (!inet_ntop(addr->sa_family, &sin->sin_addr, sockname, sizeof(sockname)))
				goto err;
			any_name = "0.0.0.0";
			port = ntohs(sin->sin_port);
			break;
		case AF_INET6:;
			struct sockaddr_in6 *sin6 = (void *) addr;
			err = "addrlen too short";
			if (addrlen < sizeof(*sin6))
				goto err;
			err = "failed to print network address";
			if (!inet_ntop(addr->sa_family, &sin6->sin6_addr, sockname, sizeof(sockname)))
				goto err;
			any_name = "::";
			port = ntohs(sin6->sin6_port);
			break;
		default:
			goto skip;
	}

	int do_specific = 1;

	if (allow_anon) {
		err = "Unix socket path truncated";
		if (snprintf(sun->sun_path, sizeof(sun->sun_path), "%s/[%s]:%u", path_prefix(), any_name, port)
				>= sizeof(sun->sun_path))
			goto err;

		struct stat sb;
		int ret = stat(sun->sun_path, &sb);
		if (ret == 0 && sb.st_mode & S_IFSOCK)
			do_specific = 0;
	}

	if (do_specific) {
		err = "Unix socket path truncated";
		if (snprintf(sun->sun_path, sizeof(sun->sun_path), "%s/[%s]:%u", path_prefix(), sockname, port)
				>= sizeof(sun->sun_path))
			goto err;
	}

	sun->sun_family = AF_UNIX;
	return NULL;
skip:
	return ""; // special return value
err:
	return err;
}

void addr_translate_reverse(struct sockaddr_storage *sst, socklen_t *socklen, int wanted_domain,
		const struct sockaddr_un *sun)
{
	assert(sun->sun_family == AF_UNIX);
	const char *path = sun->sun_path;
	assert(strlen(path) > 0);
	const char *pref = path_prefix();
	if (strncmp(path, pref, strlen(pref))) {
		fprintf(stderr, "preload addr_translate_reverse(): received from unknown peer '%s'\n", path);
		return;
	}
	path += strlen(pref);
	if (path[0] != '/') {
		fprintf(stderr, "preload addr_translate_reverse(): received from unknown peer '%s'\n", path);
		return;
	}
	path++;

	struct sockaddr_in sin = {0,};
	struct sockaddr_in6 sin6 = {0,};
	socklen_t addrlen;
	struct sockaddr *sa = NULL;

	if (!strncmp(path, "ANON.", 5)) {
		pthread_mutex_lock(&remote_peers_lock);
		peer_t *p = NULL;
		for (unsigned int i = 0; i < anon_peer_inc; i++) {
			p = &remote_peers[i];
			if (!strcmp(p->path.sun_path, path))
				goto got_peer;
		}
		assert(anon_peer_inc < MAX_SOCKETS);
		// generate new fake remote response address
		p = &remote_peers[anon_peer_inc++];
		p->path = *sun;
		p->addrlen = anon_addr(wanted_domain, &p->address, anon_peer_inc, getpid());
got_peer:
		pthread_mutex_unlock(&remote_peers_lock);
		addrlen = p->addrlen;
		sa = (struct sockaddr *) &p->address;
	}
	else if (path[0] == '[') {
		path++;
		char *end = strchr(path, ']');
		assert(end != NULL);
		char addr[64];
		if (snprintf(addr, sizeof(addr), "%.*s", (int) (end - path), path) >= sizeof(addr))
			abort();
		end++;
		assert(*end == ':');
		end++;
		int port = atoi(end);
		assert(port != 0);

		if (inet_pton(AF_INET, addr, &sin.sin_addr)) {
			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
			sa = (struct sockaddr *) &sin;
			addrlen = sizeof(sin);
		}
		else if (inet_pton(AF_INET6, addr, &sin6.sin6_addr)) {
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = htons(port);
			sa = (struct sockaddr *) &sin6;
			addrlen = sizeof(sin6);
		}
		else
			abort();
	}
	else
		abort();

	assert(addrlen <= sizeof(*sst));
	memset(sst, 0, sizeof(*sst));
	memcpy(sst, sa, addrlen);
	*socklen = addrlen;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
	const char *err;
	int (*real_bind)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_bind_warn;
	socket_t *s = &real_sockets[fd];
	err = "fd not open";
	if (!s->open)
		goto do_bind_warn;

	assert(s->used_domain == AF_UNIX);
	assert(s->wanted_domain == addr->sa_family);

	struct sockaddr_un sun;
	err = addr_translate(&sun, addr, addrlen, 0);
	if (err) {
		if (!err[0])
			goto do_bind;
		goto do_bind_warn;
	}

	struct sockaddr_storage sst = {0,};
	if (addrlen > sizeof(sst))
		goto do_bind_warn;
	memcpy(&sst, addr, addrlen);

	addr = (void *) &sun;
	addrlen = sizeof(sun);

	if (s->unix_path[0])
		unlink(s->unix_path);

	assert(sizeof(s->unix_path) >= strlen(sun.sun_path));
	strcpy(s->unix_path, sun.sun_path);
	s->sockname = sst;
	s->bound = 1;

	goto do_bind;

do_bind_warn:
	fprintf(stderr, "preload bind(): %s (fd %i)\n", err, fd);
do_bind:
	return real_bind(fd, addr, addrlen);
}

static socklen_t anon_addr(int domain, struct sockaddr_storage *sst, unsigned int id, unsigned int id2) {
	memset(sst, 0, sizeof(*sst));
	socklen_t ret = -1;
	switch (domain) {
		case AF_INET:;
			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_port = htons(id);
			sin.sin_addr.s_addr = id2;
			memcpy(sst, &sin, sizeof(sin));
			ret = sizeof(sin);
			break;
		case AF_INET6:;
			struct sockaddr_in6 sin6;
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = htons(id);
			memset(&sin6.sin6_addr, -1, sizeof(sin6.sin6_addr));
			sin6.sin6_addr.s6_addr16[4] = id2;
			memcpy(sst, &sin6, sizeof(sin6));
			ret = sizeof(sin6);
			break;
	}
	return ret;
}

static void check_bind(int fd) {
	// to make inspecting the peer address on the receiving end possible, we must bind
	// to some unix path name

	if (fd < 0 || fd >= MAX_SOCKETS)
		return;
	socket_t *s = &real_sockets[fd];
	if (!s->open)
		return;
	if (s->bound)
		return;
	if (s->wanted_domain == AF_UNIX || s->used_domain != AF_UNIX)
		return;

	struct sockaddr_storage sst;
	unsigned int auto_inc = __sync_fetch_and_add(&anon_sock_inc, 1);
	anon_addr(s->wanted_domain, &sst, auto_inc, getpid());

	struct sockaddr_un sun;
	sun.sun_family = AF_UNIX;
	if (snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/ANON.%u.%u", path_prefix(), getpid(),
				auto_inc)
			>= sizeof(sun.sun_path))
		fprintf(stderr, "preload socket(): failed to print anon (fd %i)\n", fd);

	assert(sizeof(real_sockets[fd].unix_path) >= strlen(sun.sun_path));
	strcpy(real_sockets[fd].unix_path, sun.sun_path);

	int (*real_bind)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "bind");
	if (real_bind(fd, (struct sockaddr *) &sun, sizeof(sun)))
		fprintf(stderr, "preload socket(): failed to bind to anon (fd %i): %s\n",
				fd, strerror(errno));

	s->bound = 1;

}

int close(int fd) {
	const char *err;
	int (*real_close)(int) = dlsym(RTLD_NEXT, "close");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_close_warn;
	socket_t *s = &real_sockets[fd];
	if (!s->open)
		goto do_close;

	s->open = 0;
	s->connected = 0;
	if (s->used_domain == AF_UNIX && s->wanted_domain != AF_UNIX && s->unix_path[0])
		unlink(s->unix_path);
	goto do_close;

do_close_warn:
	fprintf(stderr, "preload close(): %s (fd %i)\n", err, fd);
do_close:
	return real_close(fd);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
	check_bind(fd);

	const char *err;
	int (*real_getsockname)(int, struct sockaddr *, socklen_t *) = dlsym(RTLD_NEXT, "getsockname");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_getsockname_warn;
	socket_t *s = &real_sockets[fd];
	if (!s->open)
		goto do_getsockname;
	if (s->used_domain != AF_UNIX || s->wanted_domain == AF_UNIX || !s->bound)
		goto do_getsockname;

	switch (s->wanted_domain) {
		case AF_INET:
			if (*addrlen < sizeof(struct sockaddr_in))
				memcpy(addr, &s->sockname, *addrlen);
			else
				memcpy(addr, &s->sockname, sizeof(struct sockaddr_in));
			*addrlen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			if (*addrlen < sizeof(struct sockaddr_in6))
				memcpy(addr, &s->sockname, *addrlen);
			else
				memcpy(addr, &s->sockname, sizeof(struct sockaddr_in6));
			*addrlen = sizeof(struct sockaddr_in6);
			break;
		default:
			goto do_getsockname;
	}

	return 0;

do_getsockname_warn:
	fprintf(stderr, "preload getsockname(): %s (fd %i)\n", err, fd);
do_getsockname:
	return real_getsockname(fd, addr, addrlen);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
	check_bind(fd);

	const char *err;
	int (*real_getpeername)(int, struct sockaddr *, socklen_t *) = dlsym(RTLD_NEXT, "getpeername");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_getpeername_warn;
	socket_t *s = &real_sockets[fd];
	if (!s->open)
		goto do_getpeername;
	if (s->used_domain != AF_UNIX || s->wanted_domain == AF_UNIX || !s->bound)
		goto do_getpeername;
	if (!s->connected)
		goto do_getpeername;

	switch (s->wanted_domain) {
		case AF_INET:
			if (*addrlen < sizeof(struct sockaddr_in))
				memcpy(addr, &s->peername, *addrlen);
			else
				memcpy(addr, &s->peername, sizeof(struct sockaddr_in));
			*addrlen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			if (*addrlen < sizeof(struct sockaddr_in6))
				memcpy(addr, &s->peername, *addrlen);
			else
				memcpy(addr, &s->peername, sizeof(struct sockaddr_in6));
			*addrlen = sizeof(struct sockaddr_in6);
			break;
		default:
			goto do_getpeername;
	}

	return 0;

do_getpeername_warn:
	fprintf(stderr, "preload getpeername(): %s (fd %i)\n", err, fd);
do_getpeername:
	return real_getpeername(fd, addr, addrlen);
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
	check_bind(fd);

	socket_t *s = NULL;
	const char *err;
	int (*real_connect)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_connect_warn;
	s = &real_sockets[fd];
	err = "fd not open";
	if (!s->open)
		goto do_connect_warn;

	assert(s->used_domain == AF_UNIX);
	assert(s->wanted_domain == addr->sa_family);

	struct sockaddr_un sun;
	err = addr_translate(&sun, addr, addrlen, 1);
	if (err) {
		if (!err[0])
			goto do_connect;
		goto do_connect_warn;
	}

	struct sockaddr_storage sst = {0,};
	if (addrlen > sizeof(sst))
		goto do_connect_warn;
	memcpy(&sst, addr, addrlen);
	s->peername = sst;

	addr = (void *) &sun;
	addrlen = sizeof(sun);

	goto do_connect;

do_connect_warn:
	fprintf(stderr, "preload connect(): %s (fd %i)\n", err, fd);
do_connect:;
	int ret = real_connect(fd, addr, addrlen);
	if (ret == 0 && s)
		s->connected = 1;
	return ret;
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
	const char *err;
	int (*real_accept)(int, struct sockaddr *, socklen_t *) = dlsym(RTLD_NEXT, "accept");

	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_accept_warn;
	socket_t *s = &real_sockets[fd];
	err = "fd not open";
	if (!s->open)
		goto do_accept_warn;

	assert(s->used_domain == AF_UNIX);

	goto do_accept;

do_accept_warn:
	fprintf(stderr, "preload accept(): %s (fd %i)\n", err, fd);
do_accept:;
	struct sockaddr_un sun;
	socklen_t sun_len = sizeof(sun);
	int new_fd = real_accept(fd, (struct sockaddr *) &sun, &sun_len);
	if (new_fd == -1)
		return -1;
	if (new_fd < 0 || new_fd >= MAX_SOCKETS || real_sockets[new_fd].open) {
		fprintf(stderr, "preload accept(): new_fd out of bounds (%i/%i)\n", fd, new_fd);
		return -1;
	}

	assert(sun.sun_family == AF_UNIX);
	socket_t *new_s = &real_sockets[new_fd];
	*new_s = *s;
	assert(sun_len < sizeof(new_s->sockname));
	assert(sizeof(new_s->unix_path) >= strlen(sun.sun_path));
	strcpy(new_s->unix_path, sun.sun_path);
	memset(&new_s->sockname, 0, sizeof(new_s->sockname));
	new_s->open = 1;
	new_s->connected = 1;

	struct sockaddr_storage sst;
	socklen_t socklen;
	addr_translate_reverse(&sst, &socklen, new_s->wanted_domain, &sun);
	assert(socklen <= *addrlen);
	memset(addr, 0, *addrlen);
	memcpy(addr, &sst, socklen);
	*addrlen = socklen;
	assert(s->wanted_domain == addr->sa_family);
	new_s->peername = sst;

	return new_fd;
}

int dup(int fd) {
	int (*real_dup)(int) = dlsym(RTLD_NEXT, "dup");
	int ret = real_dup(fd);
	if (fd < 0 || fd >= MAX_SOCKETS || ret < 0 || ret >= MAX_SOCKETS) {
		fprintf(stderr, "preload dup(): fd out of bounds (%i/%i)\n", fd, ret);
		return ret;
	}
	real_sockets[ret] = real_sockets[fd];
	return ret;
}

int dup2(int oldfd, int newfd) {
	int (*real_dup2)(int, int) = dlsym(RTLD_NEXT, "dup2");
	int ret = real_dup2(oldfd, newfd);
	if (ret != newfd || oldfd < 0 || oldfd >= MAX_SOCKETS || newfd < 0 || newfd >= MAX_SOCKETS) {
		fprintf(stderr, "preload dup(): fd out of bounds (%i/%i/%i)\n", oldfd, newfd, ret);
		return ret;
	}
	if (real_sockets[newfd].open) {
		if (real_sockets[newfd].used_domain == AF_UNIX && real_sockets[newfd].unix_path[0])
			unlink(real_sockets[newfd].unix_path);
	}
	real_sockets[newfd] = real_sockets[oldfd];
	return ret;
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
	const char *err;
	ssize_t (*real_recvmsg)(int, struct msghdr *, int) = dlsym(RTLD_NEXT, "recvmsg");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_recvmsg_warn;
	socket_t *s = &real_sockets[fd];
	err = "fd not open";
	if (!s->open)
		goto do_recvmsg_warn;
	if (s->used_domain != AF_UNIX || s->wanted_domain == AF_UNIX)
		goto do_recvmsg;

	struct sockaddr_un sun;
	struct sockaddr *sa_orig = NULL;
	socklen_t sa_len;
	if (msg->msg_name) {
		sa_orig = msg->msg_name;
		sa_len = msg->msg_namelen;
		msg->msg_name = &sun;
		msg->msg_namelen = sizeof(sun);
	}

	ssize_t ret = real_recvmsg(fd, msg, flags);

	if (ret <= 0)
		goto out;

	if (sa_orig && msg->msg_name) {
		struct sockaddr_storage sst;
		socklen_t addrlen;
		addr_translate_reverse(&sst, &addrlen, s->wanted_domain, &sun);
		assert(addrlen <= sa_len);
		memcpy(sa_orig, &sst, addrlen);

		msg->msg_name = sa_orig;
		msg->msg_namelen = sa_len;
	}

	goto out;

out:
	return ret;

do_recvmsg_warn:
	fprintf(stderr, "preload recvmsg(): %s (fd %i)\n", err, fd);
do_recvmsg:
	return real_recvmsg(fd, msg, flags);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
	check_bind(fd);
	ssize_t (*real_send)(int, const void *, size_t, int) = dlsym(RTLD_NEXT, "send");
	return real_send(fd, buf, len, flags);
}

static const struct sockaddr *addr_find(const struct sockaddr *addr, socklen_t *addrlen) {
	pthread_mutex_lock(&remote_peers_lock);
	for (unsigned int i = 0; i < anon_peer_inc; i++) {
		peer_t *p = &remote_peers[i];
		if (p->address.ss_family != addr->sa_family)
			continue;
		switch (p->address.ss_family) {
			case AF_INET:{
				struct sockaddr_in *a = (struct sockaddr_in *) addr,
						   *b = (struct sockaddr_in *) &p->address;
				if (a->sin_port != b->sin_port)
					continue;
				if (a->sin_addr.s_addr != b->sin_addr.s_addr)
					continue;
				break;
			     }

			case AF_INET6:{
				struct sockaddr_in6 *a = (struct sockaddr_in6 *) addr,
						    *b = (struct sockaddr_in6 *) &p->address;
				if (a->sin6_port != b->sin6_port)
					continue;
				if (memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)))
					continue;
				break;
			      }

			default:
				continue;
		}

		// match
		*addrlen = sizeof(p->path);
		pthread_mutex_unlock(&remote_peers_lock);
		return (struct sockaddr *) &p->path;
	}
	pthread_mutex_unlock(&remote_peers_lock);
	return NULL;
}

static const struct sockaddr *addr_send_translate(const struct sockaddr *addr, socklen_t *addrlen) {
	const struct sockaddr *ret = addr_find(addr, addrlen);
	if (ret)
		return ret;

	static __thread struct sockaddr_un sun;
	const char *err = addr_translate(&sun, addr, *addrlen, 0);
	if (!err) {
		*addrlen = sizeof(sun);
		return (void *) &sun;
	}

	if (err[0])
		fprintf(stderr, "preload addr_send_translate(): %s\n", err);

	return addr;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen) {
	check_bind(fd);
	ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t)
		= dlsym(RTLD_NEXT, "sendto");
	addr = addr_send_translate(addr, &addrlen);
	return real_sendto(fd, buf, len, flags, addr, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
	check_bind(fd);
	ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = dlsym(RTLD_NEXT, "sendmsg");
	struct msghdr msg2 = *msg;
	if (msg2.msg_name)
		msg2.msg_name = (void *) addr_send_translate(msg2.msg_name, &msg2.msg_namelen);
	return real_sendmsg(fd, &msg2, flags);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
	const char *err;
	int (*real_setsockopt)(int, int, int, const void *, socklen_t) = dlsym(RTLD_NEXT, "setsockopt");
	err = "fd out of bounds";
	if (fd < 0 || fd >= MAX_SOCKETS)
		goto do_set_warn;
	socket_t *s = &real_sockets[fd];
	err = "fd not open";
	if (!s->open)
		goto do_set_warn;

	assert(s->used_domain == AF_UNIX);

	switch (s->wanted_domain) {
		case AF_INET:
			if (level == SOL_IP && optname == IP_TOS)
				return 0;
			if (level == IPPROTO_TCP && optname == TCP_NODELAY)
				return 0;
			break;

		case AF_INET6:
			if (level == SOL_IPV6 && optname == IPV6_V6ONLY)
				return 0;
			if (level == SOL_IPV6 && optname == IPV6_TCLASS)
				return 0;
			if (level == IPPROTO_TCP && optname == TCP_NODELAY)
				return 0;
			break;
	}

	goto do_set;

do_set_warn:
	fprintf(stderr, "preload setsockopt(): %s (fd %i)\n", err, fd);
do_set:
	return real_setsockopt(fd, level, optname, optval, optlen);
}
