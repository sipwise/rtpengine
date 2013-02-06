#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <pcre.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <xmlrpc_client.h>
#include <sys/wait.h>

#include "call.h"
#include "poller.h"
#include "aux.h"
#include "log.h"
#include "kernel.h"
#include "control.h"
#include "streambuf.h"
#include "redis.h"
#include "xt_MEDIAPROXY.h"



#ifdef __DEBUG
#define DBG(x...) mylog(LOG_DEBUG, x)
#else
#define DBG(x...) ((void)0)
#endif

#define LOG_PREFIX_C "[%s] "
#define LOG_PREFIX_CI "[%s - %s] "
#define LOG_PARAMS_C(c) (c)->callid
#define LOG_PARAMS_CI(c) (c)->callid, log_info

#define xasprintf(a...) if (asprintf(a) == -1) abort()

static __thread const char *log_info;




struct iterator_helper {
	GSList			*del;
	struct streamrelay	*ports[0x10000];
};
struct xmlrpc_helper {
	GStringChunk		*c;
	char			*url;
	GSList			*tags;
};


struct callmaster {
	struct obj		obj;

	rwlock_t		hashlock;
	GHashTable		*callhash;

	mutex_t			portlock;
	u_int16_t		lastport;
	BIT_ARRAY_DECLARE(ports_used, 0x10000);

	mutex_t			statspslock;
	struct stats		statsps;	/* per second stats, running timer */
	mutex_t			statslock;
	struct stats		stats;		/* copied from statsps once a second */

	struct poller		*poller;
	pcre			*info_re;
	pcre_extra		*info_ree;
	pcre			*streams_re;
	pcre_extra		*streams_ree;

	struct callmaster_config conf;
};

static char *rtp_codecs[] = {
	[0]	= "G711u",
	[1]	= "1016",
	[2]	= "G721",
	[3]	= "GSM",
	[4]	= "G723",
	[5]	= "DVI4",
	[6]	= "DVI4",
	[7]	= "LPC",
	[8]	= "G711a",
	[9]	= "G722",
	[10]	= "L16",
	[11]	= "L16",
	[14]	= "MPA",
	[15]	= "G728",
	[18]	= "G729",
	[25]	= "CelB",
	[26]	= "JPEG",
	[28]	= "nv",
	[31]	= "H261",
	[32]	= "MPV",
	[33]	= "MP2T",
	[34]	= "H263",
};






static void call_destroy(struct call *);
static void unkernelize(struct peer *);




static void stream_closed(int fd, void *p, uintptr_t u) {
	struct callstream *cs = p;
	struct streamrelay *r;
	struct call *c;
	int i;
	socklen_t j;

	mutex_lock(&cs->lock);
	r = &cs->peers[u >> 1].rtps[u & 1];
	assert(r->fd == fd);
	mutex_unlock(&cs->lock);
	c = cs->call;

	j = sizeof(i);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &i, &j);
	mylog(LOG_WARNING, LOG_PREFIX_C "Read error on RTP socket: %i (%s) -- closing call", LOG_PARAMS_C(c), i, strerror(i));

	call_destroy(c);
}




/* called with callstream->lock held */
void kernelize(struct callstream *c) {
	int i, j;
	struct peer *p, *pp;
	struct streamrelay *r, *rp;
	struct kernel_stream ks;
	struct callmaster *cm = c->call->callmaster;

	if (cm->conf.kernelfd < 0 || cm->conf.kernelid == -1)
		return;

	mylog(LOG_DEBUG, LOG_PREFIX_C "Kernelizing RTP streams", LOG_PARAMS_C(c->call));

	ZERO(ks);

	for (i = 0; i < 2; i++) {
		p = &c->peers[i];
		pp = &c->peers[i ^ 1];

		if (p->kernelized)
			continue;

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];
			rp = &pp->rtps[j];

			if (is_addr_unspecified(&r->peer_advertised.ip46)
					|| !r->fd_family || !r->peer_advertised.port)
				continue;

			ks.local_port = r->localport;
			ks.tos = cm->conf.tos;
			ks.src.port = rp->localport;
			ks.dest.port = r->peer.port;

			if (IN6_IS_ADDR_V4MAPPED(&r->peer.ip46)) {
				ks.src.family = AF_INET;
				ks.src.ipv4 = cm->conf.ipv4;
				ks.dest.family = AF_INET;
				ks.dest.ipv4 = r->peer.ip46.s6_addr32[3];
			}
			else {
				ks.src.family = AF_INET6;
				ks.src.ipv6 = cm->conf.ipv6;
				ks.dest.family = AF_INET6;
				ks.dest.ipv6 = r->peer.ip46;
			}

			ZERO(r->kstats);

			kernel_add_stream(cm->conf.kernelfd, &ks, 0);
		}

		p->kernelized = 1;
	}
}




/* called with r->up (== cs) locked */
static int stream_packet(struct streamrelay *r, char *b, int l, struct sockaddr_in6 *fsin) {
	struct streamrelay *p, *p2;
	struct peer *pe, *pe2;
	struct callstream *cs;
	int ret, update = 0;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct msghdr mh;
	struct iovec iov;
	unsigned char buf[256];
	struct cmsghdr *ch;
	struct in_pktinfo *pi;
	struct in6_pktinfo *pi6;
	struct call *c;
	struct callmaster *m;
	unsigned char cc;
	char addr[64];

	pe = r->up;
	cs = pe->up;
	pe2 = &cs->peers[pe->idx ^ 1];
	p = &pe2->rtps[r->idx];
	c = cs->call;
	m = c->callmaster;
	smart_ntop_p(addr, &fsin->sin6_addr, sizeof(addr));

	if (p->fd == -1) {
		mylog(LOG_WARNING, LOG_PREFIX_C "RTP packet to port %u discarded from %s:%u", 
			LOG_PARAMS_C(c), r->localport, addr, ntohs(fsin->sin6_port));
		r->stats.errors++;
		mutex_lock(&m->statspslock);
		m->statsps.errors++;
		mutex_unlock(&m->statspslock);
		return 0;
	}

	if (pe->confirmed || !pe->filled || r->idx != 0)
		goto forward;

	if (!c->lookup_done || poller_now <= c->lookup_done + 3)
		goto peerinfo;

	mylog(LOG_DEBUG, LOG_PREFIX_C "Confirmed peer information for port %u - %s:%u", 
		LOG_PARAMS_C(c), r->localport, addr, ntohs(fsin->sin6_port));

	pe->confirmed = 1;

peerinfo:
	if (!pe->codec && l >= 2) {
		cc = b[1];
		cc &= 0x7f;
		if (cc < G_N_ELEMENTS(rtp_codecs))
			pe->codec = rtp_codecs[cc] ? : "unknown";
		else
			pe->codec = "unknown";
	}

	p2 = &p->up->rtps[p->idx ^ 1];
	p->peer.ip46 = fsin->sin6_addr;
	p->peer.port = ntohs(fsin->sin6_port);
	p2->peer.ip46 = p->peer.ip46;
	p2->peer.port = p->peer.port + ((int) (p2->idx * 2) - 1);

	if (pe->confirmed && pe2->confirmed && pe2->filled)
		kernelize(cs);

	update = 1;

forward:
	if (is_addr_unspecified(&r->peer_advertised.ip46)
			|| !r->peer_advertised.port || !r->fd_family)
		goto drop;

	ZERO(mh);
	mh.msg_control = buf;
	mh.msg_controllen = sizeof(buf);

	ch = CMSG_FIRSTHDR(&mh);
	ZERO(*ch);

	switch (r->fd_family) {
		case AF_INET:
			ZERO(sin);
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = r->peer.ip46.s6_addr32[3];
			sin.sin_port = htons(r->peer.port);
			mh.msg_name = &sin;
			mh.msg_namelen = sizeof(sin);

ipv4_src:
			ch->cmsg_len = CMSG_LEN(sizeof(*pi));
			ch->cmsg_level = IPPROTO_IP;
			ch->cmsg_type = IP_PKTINFO;

			pi = (void *) CMSG_DATA(ch);
			ZERO(*pi);
			pi->ipi_spec_dst.s_addr = m->conf.ipv4;

			mh.msg_controllen = CMSG_SPACE(sizeof(*pi));

			break;

		case AF_INET6:
			ZERO(sin6);
			sin6.sin6_family = AF_INET6;
			sin6.sin6_addr = r->peer.ip46;
			sin6.sin6_port = htons(r->peer.port);
			mh.msg_name = &sin6;
			mh.msg_namelen = sizeof(sin6);

			if (IN6_IS_ADDR_V4MAPPED(&sin6.sin6_addr))
				goto ipv4_src;

			ch->cmsg_len = CMSG_LEN(sizeof(*pi6));
			ch->cmsg_level = IPPROTO_IPV6;
			ch->cmsg_type = IPV6_PKTINFO;

			pi6 = (void *) CMSG_DATA(ch);
			ZERO(*pi6);
			pi6->ipi6_addr = m->conf.ipv6;

			mh.msg_controllen = CMSG_SPACE(sizeof(*pi6));

			break;

		default:
			abort();
	}

	ZERO(iov);
	iov.iov_base = b;
	iov.iov_len = l;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	ret = sendmsg(p->fd, &mh, 0);

	if (ret == -1) {
		r->stats.errors++;
		mutex_lock(&m->statspslock);
		m->statsps.errors++;
		mutex_unlock(&m->statspslock);
		goto out;
	}

drop:
	ret = 0;
	r->stats.packets++;
	r->stats.bytes += l;
	r->last = poller_now;
	mutex_lock(&m->statspslock);
	m->statsps.packets++;
	m->statsps.bytes += l;
	mutex_unlock(&m->statspslock);

out:
	if (ret == 0 && update)
		ret = 1;

	return ret;
}




static void stream_readable(int fd, void *p, uintptr_t u) {
	struct callstream *cs = p;
	struct streamrelay *r;
	char buf[8192];
	int ret;
	struct sockaddr_storage ss;
	struct sockaddr_in6 sin6;
	struct sockaddr_in *sin;
	unsigned int sinlen;
	void *sinp;
	int update = 0;
	struct call *ca;

	mutex_lock(&cs->lock);
	r = &cs->peers[u >> 1].rtps[u & 1];
	if (r->fd != fd)
		goto out;

	for (;;) {
		sinlen = sizeof(ss);
		ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &ss, &sinlen);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			mutex_unlock(&cs->lock);
			stream_closed(fd, r, 0);
			return;
		}
		if (ret >= sizeof(buf))
			mylog(LOG_WARNING, "UDP packet possibly truncated");

		if (ss.ss_family != r->fd_family)
			abort();

		sinp = &ss;
		if (ss.ss_family == AF_INET) {
			sin = sinp;
			sinp = &sin6;
			ZERO(sin6);
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = sin->sin_port;
			in4_to_6(&sin6.sin6_addr, sin->sin_addr.s_addr);
		}

		ret = stream_packet(r, buf, ret, sinp);
		if (ret == -1) {
			mylog(LOG_WARNING, "Write error on RTP socket");
			mutex_unlock(&cs->lock);
			call_destroy(cs->call);
			return;
		}
		if (ret == 1)
			update = 1;
	}

out:
	ca = cs->call;
	mutex_unlock(&cs->lock);

	if (update && redis_update)
		redis_update(ca, ca->callmaster->conf.redis);
}





static int info_parse_func(char **a, void **ret, void *p) {
	struct call *c = p;

	g_hash_table_replace(c->infohash, call_strdup(c, a[0]), call_strdup(c, a[1]));

	return -1;
}


static void info_parse(const char *s, struct call *c) {
	GQueue *q;
	struct callmaster *m = c->callmaster;

	q = pcre_multi_match(m->info_re, m->info_ree, s, 2, info_parse_func, c);
	g_queue_free(q);
}


static int streams_parse_func(char **a, void **ret, void *p) {
	struct stream *st;
	u_int32_t ip;
	int *i;

	i = p;
	st = g_slice_alloc0(sizeof(*st));

	ip = inet_addr(a[0]);
	if (ip == -1)
		goto fail;

	in4_to_6(&st->ip46, ip);
	st->port = atoi(a[1]);
	st->mediatype = strdup(a[2] ? : ""); /* XXX should use string chunks */
	st->num = ++(*i);

	if (!st->port && strcmp(a[1], "0"))
		goto fail;

	*ret = st;
	return 0;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s:%s", a[0], a[1]);
	free(st->mediatype);
	g_slice_free1(sizeof(*st), st);
	return -1;
}


static GQueue *streams_parse(const char *s, struct callmaster *m) {
	int i;
	i = 0;
	return pcre_multi_match(m->streams_re, m->streams_ree, s, 3, streams_parse_func, &i);
}

static void streams_free(GQueue *q) {
	struct stream *s;

	while (q->head) {
		s = g_queue_pop_head(q);
		free(s->mediatype);
		g_slice_free1(sizeof(*s), s);
	}

	g_queue_free(q);
}



/* called with callmaster->hashlock held */
static void call_timer_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct iterator_helper *hlp = ptr;
	GList *it;
	struct callstream *cs;
	int i, j;
	struct peer *p;
	struct callmaster *cm;
	unsigned int check;
	struct streamrelay *sr;
	int good = 0;

	mutex_lock(&c->lock);

	if (!c->callstreams->head)
		goto drop;

	cm = c->callmaster;

	for (it = c->callstreams->head; it; it = it->next) {
		cs = it->data;
		mutex_lock(&cs->lock);

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];
			for (j = 0; j < 2; j++) {
				sr = &p->rtps[j];
				if (!sr->localport)
					continue;
				if (hlp->ports[sr->localport])
					abort();
				hlp->ports[sr->localport] = sr;
				obj_hold(cs);

				if (good)
					continue;

				check = cm->conf.timeout;
				if (!sr->peer_advertised.port)
					check = cm->conf.silent_timeout;
				else if (is_addr_unspecified(&sr->peer_advertised.ip46))
					check = cm->conf.silent_timeout;

				if (poller_now - sr->last < check)
					good = 1;
			}
		}
		mutex_unlock(&cs->lock);
	}

	if (good)
		goto out;

	mylog(LOG_INFO, LOG_PREFIX_C "Closing call branch due to timeout", 
		LOG_PARAMS_C(c));

drop:
	mutex_unlock(&c->lock);
	hlp->del = g_slist_prepend(hlp->del, obj_get(c));
	return;

out:
	mutex_unlock(&c->lock);
}

void xmlrpc_kill_calls(void *p) {
	struct xmlrpc_helper *xh = p;
	xmlrpc_env e;
	xmlrpc_client *c;
	xmlrpc_value *r;
	pid_t pid;
	sigset_t ss;
	int i = 0;
	int status;

	while (xh->tags) {
		mylog(LOG_INFO, "Forking child to close call with tag %s via XMLRPC", (char *) xh->tags->data);
		pid = fork();

		if (pid) {
retry:
			pid = waitpid(pid, &status, 0);
			if ((pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) || i >= 3) {
				xh->tags = g_slist_delete_link(xh->tags, xh->tags);
				i = 0;
			}
			else {
				if (pid == -1 && errno == EINTR)
					goto retry;
				mylog(LOG_INFO, "XMLRPC child exited with status %i", status);
				i++;
			}
			continue;
		}

		/* child process */
		rlim(RLIMIT_CORE, 0);
		sigemptyset(&ss);
		sigprocmask(SIG_SETMASK, &ss, NULL);
		closelog();

		for (i = 0; i < 100; i++)
			close(i);

		openlog("mediaproxy-ng/child", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		mylog(LOG_INFO, "Initiating XMLRPC call for tag %s", (char *) xh->tags->data);

		alarm(5);

		xmlrpc_env_init(&e);
		xmlrpc_client_setup_global_const(&e);
		xmlrpc_client_create(&e, XMLRPC_CLIENT_NO_FLAGS, "ngcp-mediaproxy-ng", MEDIAPROXY_VERSION,
			NULL, 0, &c);
		if (e.fault_occurred)
			goto fault;

		r = NULL;
		xmlrpc_client_call2f(&e, c, xh->url, "di", &r, "(ssss)",
			"sbc", "postControlCmd", xh->tags->data, "teardown");
		if (r)
			xmlrpc_DECREF(r);
		if (e.fault_occurred)
			goto fault;

		xmlrpc_client_destroy(c);
		xh->tags = g_slist_delete_link(xh->tags, xh->tags);
		xmlrpc_env_clean(&e);

		_exit(0);

fault:
		mylog(LOG_WARNING, "XMLRPC fault occurred: %s", e.fault_string);
		_exit(1);
	}

	g_string_chunk_free(xh->c);
	g_slice_free1(sizeof(*xh), xh);
}

void kill_calls_timer(GSList *list, struct callmaster *m) {
	struct call *ca;
	GList *csl;
	struct callstream *cs;
	const char *url;
	struct xmlrpc_helper *xh = NULL;

	if (!list)
		return; /* shouldn't happen */

	ca = list->data;
	m = ca->callmaster; /* same callmaster for all of them */
	url = m->conf.b2b_url;
	if (url) {
		xh = g_slice_alloc(sizeof(*xh));
		xh->c = g_string_chunk_new(64);
		xh->url = g_string_chunk_insert(xh->c, url);
		xh->tags = NULL;
	}

	while (list) {
		ca = list->data;
		if (!url)
			goto destroy;

		mutex_lock(&ca->lock);

		for (csl = ca->callstreams->head; csl; csl = csl->next) {
			cs = csl->data;
			mutex_lock(&cs->lock);
			if (!cs->peers[1].tag || !*cs->peers[1].tag)
				goto next;
			xh->tags = g_slist_prepend(xh->tags, g_string_chunk_insert(xh->c, cs->peers[1].tag));
next:
			mutex_unlock(&cs->lock);
		}
		mutex_unlock(&ca->lock);

destroy:
		call_destroy(ca);
		obj_put(ca);
		list = g_slist_delete_link(list, list);
	}

	if (xh)
		thread_create_detach(xmlrpc_kill_calls, xh);
}


#define DS(x) do {							\
		mutex_lock(&cs->lock);					\
		if (ke->stats.x < sr->kstats.x)				\
			d = 0;						\
		else							\
			d = ke->stats.x - sr->kstats.x;			\
		sr->stats.x += d;					\
		mutex_unlock(&cs->lock);				\
		mutex_lock(&m->statspslock);				\
		m->statsps.x += d;					\
		mutex_unlock(&m->statspslock);				\
	} while (0)
static void callmaster_timer(void *ptr) {
	struct callmaster *m = ptr;
	struct iterator_helper hlp;
	GList *i;
	struct mediaproxy_list_entry *ke;
	struct streamrelay *sr;
	u_int64_t d;
	struct stats tmpstats;
	struct callstream *cs;
	int j;

	ZERO(hlp);

	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, call_timer_iterator, &hlp);
	rwlock_unlock_r(&m->hashlock);

	mutex_lock(&m->statspslock);
	memcpy(&tmpstats, &m->statsps, sizeof(tmpstats));
	ZERO(m->statsps);
	mutex_unlock(&m->statspslock);
	mutex_lock(&m->statslock);
	memcpy(&m->stats, &tmpstats, sizeof(m->stats));
	mutex_unlock(&m->statslock);

	i = (m->conf.kernelid != -1) ? kernel_list(m->conf.kernelid) : NULL;
	while (i) {
		ke = i->data;

		cs = NULL;
		sr = hlp.ports[ke->target.target_port];
		if (!sr)
			goto next;
		cs = sr->up->up;

		DS(packets);
		DS(bytes);
		DS(errors);

		mutex_lock(&cs->lock);
		if (ke->stats.packets != sr->kstats.packets)
			sr->last = poller_now;

		sr->kstats.packets = ke->stats.packets;
		sr->kstats.bytes = ke->stats.bytes;
		sr->kstats.errors = ke->stats.errors;
		mutex_unlock(&cs->lock);

next:
		hlp.ports[ke->target.target_port] = NULL;
		g_slice_free1(sizeof(*ke), ke);
		i = g_list_delete_link(i, i);
		if (cs)
			obj_put(cs);
	}

	for (j = 0; j < (sizeof(hlp.ports) / sizeof(*hlp.ports)); j++)
		if (hlp.ports[j])
			obj_put(hlp.ports[j]->up->up);

	if (!hlp.del)
		return;

	kill_calls_timer(hlp.del, m);
}
#undef DS


struct callmaster *callmaster_new(struct poller *p) {
	struct callmaster *c;
	const char *errptr;
	int erroff;

	c = obj_alloc0("callmaster", sizeof(*c), NULL);

	c->callhash = g_hash_table_new(g_str_hash, g_str_equal);
	if (!c->callhash)
		goto fail;
	c->poller = p;
	rwlock_init(&c->hashlock);

	c->info_re = pcre_compile("^([^:,]+)(?::(.*?))?(?:$|,)", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!c->info_re)
		goto fail;
	c->info_ree = pcre_study(c->info_re, 0, &errptr);

	c->streams_re = pcre_compile("^([\\d.]+):(\\d+)(?::(.*?))?(?:$|,)", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!c->streams_re)
		goto fail;
	c->streams_ree = pcre_study(c->streams_re, 0, &errptr);

	poller_add_timer(p, callmaster_timer, &c->obj);

	obj_put(c);
	return c;

fail:
	obj_put(c);
	return NULL;
}



static int get_port4(struct streamrelay *r, u_int16_t p) {
	int fd;
	struct sockaddr_in sin;
	struct callmaster *m = r->up->up->call->callmaster;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	nonblock(fd);
	reuseaddr(fd);
	if (m->conf.tos)
		setsockopt(fd, IPPROTO_IP, IP_TOS, &m->conf.tos, sizeof(m->conf.tos));

	ZERO(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(p);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	r->fd = fd;
	r->fd_family = AF_INET;

	return 0;

fail:
	close(fd);
	return -1;
}

static int get_port6(struct streamrelay *r, u_int16_t p) {
	int fd;
	struct sockaddr_in6 sin;
	struct callmaster *m = r->up->up->call->callmaster;
	int tos;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	nonblock(fd);
	reuseaddr(fd);
	tos = m->conf.tos;
#ifdef IPV6_TCLASS
	if (tos)
		setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
#else
#warning "Will not set IPv6 traffic class"
#endif
	ipv6only(fd, 0);

	ZERO(sin);
	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(p);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	r->fd = fd;
	r->fd_family = AF_INET6;

	return 0;

fail:
	close(fd);
	return -1;
}

static int get_port(struct streamrelay *r, u_int16_t p) {
	int ret;
	struct callmaster *m = r->up->up->call->callmaster;

	mutex_lock(&m->portlock);
	if (bit_array_isset(m->ports_used, p)) {
		mutex_unlock(&m->portlock);
		return -1;
	}
	bit_array_set(m->ports_used, p);
	mutex_unlock(&m->portlock);

	if (is_addr_unspecified(&m->conf.ipv6))
		ret = get_port4(r, p);
	else
		ret = get_port6(r, p);

	if (ret) {
		mutex_lock(&m->portlock);
		bit_array_clear(m->ports_used, p);
		mutex_unlock(&m->portlock);
		return ret;
	}

	r->localport = p;

	return 0;
}

static void release_port(struct streamrelay *r) {
	struct callmaster *m = r->up->up->call->callmaster;

	if (r->fd == -1 || !r->localport)
		return;
	mutex_lock(&m->portlock);
	bit_array_clear(m->ports_used, r->localport);
	mutex_unlock(&m->portlock);
	close(r->fd);
	r->fd = -1;
	r->localport = 0;
}

static void get_port_pair(struct peer *p, int wanted_port) {
	struct call *c;
	struct callmaster *m;
	struct streamrelay *a, *b;
	u_int16_t port, min, max;

	c = p->up->call;
	m = c->callmaster;
	a = &p->rtps[0];
	b = &p->rtps[1];

	assert(a->fd == -1 && b->fd == -1);

	if (wanted_port > 0) {
		if ((wanted_port & 1))
			goto fail;
		if (get_port(a, wanted_port))
			goto fail;
		if (get_port(b, wanted_port + 1))
			goto fail;
		goto done;
	}

	min = (m->conf.port_min > 0 && m->conf.port_min < 0xfff0) ? m->conf.port_min : 1024;
	max = (m->conf.port_max > 0 && m->conf.port_max > min && m->conf.port_max < 0xfff0) ? m->conf.port_max : 0;

	mutex_lock(&m->portlock);
	if (!m->lastport)
		m->lastport = max;
	port = m->lastport + 1;
	mutex_unlock(&m->portlock);

	for (;;) {
		if (port < min)
			port = min;
		else if (max && port > max)
			port = min;

		if (port == m->lastport)
			goto fail;

		if ((port & 1))
			goto next;

		if (get_port(a, port))
			goto next;

		port++;
		if (get_port(b, port))
			goto tryagain;

		break;

tryagain:
		release_port(a);
next:
		port++;
	}

	mutex_lock(&m->portlock);
	m->lastport = port;
	mutex_unlock(&m->portlock);

	mylog(LOG_DEBUG, LOG_PREFIX_CI "Opened ports %u/%u for RTP", 
		LOG_PARAMS_CI(c), a->localport, b->localport);

done:
	return;

fail:
	mylog(LOG_ERR, LOG_PREFIX_CI "Failed to get RTP port pair", LOG_PARAMS_CI(c));
	release_port(a);
	release_port(b);
}

/* caller is responsible for appropriate locking */
static int setup_peer(struct peer *p, struct stream *s, const char *tag) {
	struct streamrelay *a, *b;
	struct callstream *cs;
	struct call *ca;
	int i;

	cs = p->up;
	ca = cs->call;
	a = &p->rtps[0];
	b = &p->rtps[1];

	if (a->peer_advertised.port != s->port || !IN6_ARE_ADDR_EQUAL(&a->peer_advertised.ip46, &s->ip46)) {
		cs->peers[0].confirmed = 0;
		unkernelize(&cs->peers[0]);
		cs->peers[1].confirmed = 0;
		unkernelize(&cs->peers[1]);
	}

	a->peer.ip46 = s->ip46;
	b->peer.ip46 = s->ip46;
	a->peer.port = b->peer.port = s->port;
	if (b->peer.port)
		b->peer.port++;
	a->peer_advertised = a->peer;
	b->peer_advertised = b->peer;

	for (i = 0; i < 2; i++) {
		switch (s->direction[i]) {
			case DIR_INTERNAL:
				cs->peers[i ^ p->idx].desired_family = AF_INET;
				break;
			case DIR_EXTERNAL:
				cs->peers[i ^ p->idx].desired_family = AF_INET6;
				break;
			default:
				break;
		}
	}

	p->mediatype = call_strdup(ca, s->mediatype);
	p->tag = call_strdup(ca, tag);
	p->filled = 1;

	return 0;
}

/* caller is responsible for appropriate locking */
static void steal_peer(struct peer *dest, struct peer *src) {
	struct streamrelay *r;
	int i;
	struct poller_item pi;
	struct streamrelay *sr, *srs;
	struct call *c;
	struct callmaster *m;
	struct poller *po;

	ZERO(pi);
	r = &src->rtps[0];
	c = src->up->call;
	m = c->callmaster;
	po = m->poller;

	mylog(LOG_DEBUG, LOG_PREFIX_CI "Re-using existing open RTP port %u", 
		LOG_PARAMS_CI(c), r->localport);

	dest->confirmed = 0;
	unkernelize(dest);
	src->confirmed = 0;
	unkernelize(src);

	dest->filled = 1;
	dest->mediatype = src->mediatype;
	dest->tag = src->tag;
	src->mediatype = "";
	src->tag = "";
	//dest->kernelized = src->kernelized;
	//src->kernelized = 0;
	dest->desired_family = src->desired_family;

	for (i = 0; i < 2; i++) {
		sr = &dest->rtps[i];
		srs = &src->rtps[i];

		if (sr->fd != -1) {
			mylog(LOG_DEBUG, LOG_PREFIX_CI "Closing port %u in favor of re-use", 
				LOG_PARAMS_CI(c), sr->localport);
			poller_del_item(po, sr->fd);
			release_port(sr);
		}

		sr->fd = srs->fd;
		sr->fd_family = srs->fd_family;

		sr->peer.ip46 = srs->peer.ip46;
		sr->peer.port = srs->peer.port;
		sr->peer_advertised.ip46 = srs->peer_advertised.ip46;
		sr->peer_advertised.port = srs->peer_advertised.port;

		sr->localport = srs->localport;


		srs->fd = -1;
		srs->fd_family = 0;
		ZERO(srs->peer.ip46);
		srs->peer.port = 0;
		srs->localport = 0;
		ZERO(srs->peer_advertised.ip46);
		srs->peer_advertised.port = 0;

		pi.fd = sr->fd;
		pi.obj = &sr->up->up->obj;
		pi.uintp = i | (dest->idx << 1);
		pi.readable = stream_readable;
		pi.closed = stream_closed;

		poller_update_item(po, &pi);
	}
}


void callstream_init(struct callstream *s, int port1, int port2) {
	int i, j, tport;
	struct peer *p;
	struct streamrelay *r;
	struct poller_item pi;
	struct poller *po;

	po = s->call->callmaster->poller;
	ZERO(pi);

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];

		p->idx = i;
		p->up = s;
		p->tag = "";
		p->mediatype = "";

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];

			r->fd = -1;
			r->idx = j;
			r->up = p;
			r->last = poller_now;
		}

		tport = (i == 0) ? port1 : port2;

		if (tport >= 0) {
			get_port_pair(p, tport);

			for (j = 0; j < 2; j++) {
				r = &p->rtps[j];

				pi.fd = r->fd;
				pi.obj = &s->obj;
				pi.uintp = (i << 1) | j;
				pi.readable = stream_readable;
				pi.closed = stream_closed;

				poller_add_item(po, &pi);
			}
		}
	}
}



static void callstream_free(void *ptr) {
	struct callstream *s = ptr;
	int i, j;       
	struct peer *p;
	struct streamrelay *r;

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];
			release_port(r);
		}
	}
	mutex_destroy(&s->lock);
	obj_put(s->call);
}

/* called with call->lock held */
static int call_streams(struct call *c, GQueue *s, const char *tag, int opmode) {
	GQueue *q;
	GList *i, *l;
	struct stream *t;
	int x;
	struct streamrelay *r;
	struct callstream *cs, *cs_o;
	struct peer *p, *p2;
	int ret = 1;

	q = g_queue_new();	/* new callstreams list */

	if (!tag)
		tag = "";

	for (i = s->head; i; i = i->next) {
		t = i->data;

		p = NULL;

		/* look for an existing call stream with identical parameters */
		for (l = c->callstreams->head; l; l = l->next) {
			cs_o = l->data;
			mutex_lock(&cs_o->lock);
			for (x = 0; x < 2; x++) {
				r = &cs_o->peers[x].rtps[0];
				DBG("comparing new ["IP6F"]:%u/%s to old ["IP6F"]:%u/%s",
					IP6P(&t->ip46), t->port, tag,
					IP6P(&r->peer_advertised.ip46), r->peer_advertised.port, cs_o->peers[x].tag);

				if (!IN6_ARE_ADDR_EQUAL(&r->peer_advertised.ip46, &t->ip46))
					continue;
				if (r->peer_advertised.port != t->port)
					continue;
				if (strcmp(cs_o->peers[x].tag, tag))
					continue;
				DBG("found existing call stream to steal");
				goto found;
			}
			mutex_unlock(&cs_o->lock);
		}

		/* not found */
		r = NULL;
		cs_o = NULL;
		l = NULL;

found:
		/* cs_o remains locked if set */
		if (!opmode) {	/* request */
			DBG("creating new callstream");

			cs = callstream_new(c, t->num);
			mutex_lock(&cs->lock);

			if (!r) {
				/* nothing found to re-use, open new ports */
				callstream_init(cs, 0, 0);
				p = &cs->peers[0];
				setup_peer(p, t, tag);
			}
			else {
				/* re-use, so don't open new ports */
				callstream_init(cs, -1, -1);
				if (r->up->idx == 0) {
					/* request/lookup came in the same order as before */
					steal_peer(&cs->peers[0], &cs_o->peers[0]);
					steal_peer(&cs->peers[1], &cs_o->peers[1]);
				}
				else {
					/* reversed request/lookup */
					steal_peer(&cs->peers[0], &cs_o->peers[1]);
					steal_peer(&cs->peers[1], &cs_o->peers[0]);
				}
				mutex_unlock(&cs_o->lock);
			}

			mutex_unlock(&cs->lock);
			g_queue_push_tail(q, cs); /* hand over the ref of new cs */
			ZERO(c->lookup_done);
			continue;
		}

		/* lookup */
		for (l = c->callstreams->head; l; l = l->next) {
			cs = l->data;
			if (cs != cs_o)
				mutex_lock(&cs->lock);
			DBG("hunting for callstream, %i <> %i", cs->num, t->num);
			if (cs->num == t->num)
				goto got_cs;
			if (cs != cs_o)
				mutex_unlock(&cs->lock);
		}

		mylog(LOG_WARNING, LOG_PREFIX_CI "Got LOOKUP, but no usable callstreams found", 
			LOG_PARAMS_CI(c));
		if (cs_o)
			mutex_unlock(&cs_o->lock);
		break;

got_cs:
		/* cs and cs_o remain locked, and maybe cs == cs_o */
		/* r == peer[x].rtp[0] of cs_o */
		g_queue_delete_link(c->callstreams, l); /* steal cs ref */
		p = &cs->peers[1];
		p2 = &cs->peers[0];

		if (c->lookup_done && r) {
			/* duplicate/stray lookup. don't do anything except replying with something
			   we already have. check whether the direction is reversed or not and return
			   the appropriate details. if no matching stream was found, results are
			   undefined. */
			DBG("double lookup");
			if (p == r->up)
				goto skip;
			if (p2 == r->up) {
				ret = -1;
				goto skip;
			}
		}


		if (r && p == r->up) {
			/* best case, nothing to do */
			DBG("case 1");
			;
		}
		else if (r && cs_o != cs) {
			/* found something, but it's linked to a different stream */
			DBG("case 2");
			steal_peer(p, r->up);
		}
		else if (!r && !p->filled) {
			/* nothing found to steal, but this end is open */
			DBG("case 3");
			setup_peer(p, t, tag);
		}
		else {
			/* nothing found to steal and this end is used */
			/* need a new call stream after all */
			DBG("case 4");
			if (cs_o && cs_o != cs)
				mutex_unlock(&cs_o->lock);
			cs_o = cs;
			cs = callstream_new(c, t->num);
			mutex_lock(&cs->lock);
			callstream_init(cs, 0, 0);
			steal_peer(&cs->peers[0], &cs_o->peers[0]);
			p = &cs->peers[1];
			setup_peer(p, t, tag);
			g_queue_push_tail(c->callstreams, cs_o); /* hand over ref to original cs */
		}

		time(&c->lookup_done);

skip:
		g_queue_push_tail(q, p->up); /* hand over ref to cs */
		mutex_unlock(&cs->lock);
		if (cs_o && cs_o != cs)
			mutex_unlock(&cs_o->lock);
	}

	ret = ret * q->length;

	if (!q->head)
		g_queue_free(q);
	else {
		if (c->callstreams->head) {
			q->tail->next = c->callstreams->head;
			c->callstreams->head->prev = q->tail;
			q->tail = c->callstreams->tail;
			q->length += c->callstreams->length;
			c->callstreams->head = c->callstreams->tail = NULL;
			c->callstreams->length = 0;
		}
		g_queue_free(c->callstreams);
		c->callstreams = q;
	}

	return ret;
}




static void unkernelize(struct peer *p) {
	struct streamrelay *r;
	int i;

	if (!p->kernelized)
		return;

	for (i = 0; i < 2; i++) {
		r = &p->rtps[i];

		kernel_del_stream(p->up->call->callmaster->conf.kernelfd, r->localport);

	}

	p->kernelized = 0;
}


/* called with callstream->lock held */
static void kill_callstream(struct callstream *s) {
	int i, j;
	struct peer *p;
	struct streamrelay *r;

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];

		unkernelize(p);

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];

			if (r->fd != -1)
				poller_del_item(s->call->callmaster->poller, r->fd);
		}
	}
}

static void call_destroy(struct call *c) {
	struct callmaster *m = c->callmaster;
	struct callstream *s;
	int ret;

	rwlock_lock_w(&m->hashlock);
	ret = g_hash_table_remove(m->callhash, c->callid);
	rwlock_unlock_w(&m->hashlock);

	if (!ret)
		return;

	obj_put(c);

	if (redis_delete)
		redis_delete(c, m->conf.redis);

	mutex_lock(&c->lock);
	/* at this point, no more callstreams can be added */
	mylog(LOG_INFO, LOG_PREFIX_C "Final packet stats:", c->callid);
	while (c->callstreams->head) {
		s = g_queue_pop_head(c->callstreams);
		mutex_unlock(&c->lock);
		mutex_lock(&s->lock);
		mylog(LOG_INFO, LOG_PREFIX_C
			"--- "
			"side A: "
			"RTP[%u] %lu p, %lu b, %lu e; "
			"RTCP[%u] %lu p, %lu b, %lu e; "
			"side B: "
			"RTP[%u] %lu p, %lu b, %lu e; "
			"RTCP[%u] %lu p, %lu b, %lu e",
			c->callid,
			s->peers[0].rtps[0].localport, s->peers[0].rtps[0].stats.packets,
			s->peers[0].rtps[0].stats.bytes, s->peers[0].rtps[0].stats.errors,
			s->peers[0].rtps[1].localport, s->peers[0].rtps[1].stats.packets,
			s->peers[0].rtps[1].stats.bytes, s->peers[0].rtps[1].stats.errors,
			s->peers[1].rtps[0].localport, s->peers[1].rtps[0].stats.packets,
			s->peers[1].rtps[0].stats.bytes, s->peers[1].rtps[0].stats.errors,
			s->peers[1].rtps[1].localport, s->peers[1].rtps[1].stats.packets,
			s->peers[1].rtps[1].stats.bytes, s->peers[1].rtps[1].stats.errors);
		kill_callstream(s);
		mutex_unlock(&s->lock);
		obj_put(s);
		mutex_lock(&c->lock);
	}
	mutex_unlock(&c->lock);
}



static char *streams_print(GQueue *s, unsigned int num, unsigned int off, const char *prefix, int format) {
	GString *o;
	int i;
	GList *l;
	struct callstream *t;
	struct streamrelay *x;
	char ips[64];
	u_int32_t ip4;
	int other_off;
	char af;

	o = g_string_new("");
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	if (!s->head)
		goto out;

	t = s->head->data;
	other_off = (off == 0) ? 1 : 0;

	if (t->peers[other_off].desired_family == AF_INET
			|| (t->peers[other_off].desired_family == 0
				&& is_addr_unspecified(&t->peers[other_off].rtps[0].peer.ip46))
			|| is_addr_unspecified(&t->call->callmaster->conf.ipv6)) {
		ip4 = t->peers[off].rtps[0].peer_advertised.ip46.s6_addr32[3];
		if (!ip4)
			strcpy(ips, "0.0.0.0");
		else if (t->call->callmaster->conf.adv_ipv4)
			sprintf(ips, IPF, IPP(t->call->callmaster->conf.adv_ipv4));
		else
			sprintf(ips, IPF, IPP(t->call->callmaster->conf.ipv4));

		af = '4';
	}
	else {
		if (is_addr_unspecified(&t->peers[off].rtps[0].peer_advertised.ip46))
			strcpy(ips, "::");
		else if (!is_addr_unspecified(&t->call->callmaster->conf.adv_ipv6))
			inet_ntop(AF_INET6, &t->call->callmaster->conf.adv_ipv6, ips, sizeof(ips));
		else
			inet_ntop(AF_INET6, &t->call->callmaster->conf.ipv6, ips, sizeof(ips));

		af = '6';
	}

	if (format == 0)
		g_string_append(o, ips);

	for (i = 0, l = s->head; i < num && l; i++, l = l->next) {
		t = l->data;
		x = &t->peers[off].rtps[0];
		g_string_append_printf(o, (format == 1) ? "%u " : " %u", x->localport);
	}

	if (format == 1)
		g_string_append_printf(o, "%s %c", ips, af);

out:
	g_string_append(o, "\n");

	return g_string_free(o, FALSE);
}

static gboolean g_str_equal0(gconstpointer a, gconstpointer b) {
	if (!a) {
		if (!b)
			return TRUE;
		return FALSE;
	}
	if (!b)
		return FALSE;
	return g_str_equal(a, b);
}

static guint g_str_hash0(gconstpointer v) {
	if (!v)
		return 0;
	return g_str_hash(v);
}

static void call_free(void *p) {
	struct call *c = p;

	g_hash_table_destroy(c->infohash);
	g_hash_table_destroy(c->branches);
	g_queue_free(c->callstreams);
	mutex_destroy(&c->lock);
	mutex_destroy(&c->chunk_lock);
	g_string_chunk_free(c->chunk);
}

static struct call *call_create(const char *callid, struct callmaster *m) {
	struct call *c;

	mylog(LOG_NOTICE, LOG_PREFIX_C "Creating new call",
		callid);	/* XXX will spam syslog on recovery from DB */
	c = obj_alloc0("call", sizeof(*c), call_free);
	c->callmaster = m;
	c->chunk = g_string_chunk_new(256);
	mutex_init(&c->chunk_lock);
	c->callid = call_strdup(c, callid);
	c->callstreams = g_queue_new();
	c->created = poller_now;
	c->infohash = g_hash_table_new(g_str_hash, g_str_equal);
	c->branches = g_hash_table_new(g_str_hash0, g_str_equal0);
	mutex_init(&c->lock);
	return c;
}

/* returns call with lock held */
struct call *call_get_or_create(const char *callid, const char *viabranch, struct callmaster *m) {
	struct call *c;

restart:
	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, callid);
	if (!c) {
		rwlock_unlock_r(&m->hashlock);
		/* completely new call-id, create call */
		c = call_create(callid, m);
		rwlock_lock_w(&m->hashlock);
		if (g_hash_table_lookup(m->callhash, callid)) {
			/* preempted */
			rwlock_unlock_w(&m->hashlock);
			obj_put(c);
			goto restart;
		}
		g_hash_table_insert(m->callhash, c->callid, obj_get(c));
		mutex_lock(&c->lock);
		rwlock_unlock_w(&m->hashlock);
	}
	else {
		obj_hold(c);
		mutex_lock(&c->lock);
		rwlock_unlock_r(&m->hashlock);
	}

	if (viabranch && *viabranch && !g_hash_table_lookup(c->branches, viabranch))
		g_hash_table_insert(c->branches, call_strdup(c, viabranch),
		(void *) 0x1);

	return c;
}

static int addr_parse_udp(struct stream *st, const char **out) {
	u_int32_t ip4;
	const char *cp;
	char c;
	int i;

	ZERO(*st);
	if (out[RE_UDP_UL_ADDR4] && *out[RE_UDP_UL_ADDR4]) {
		ip4 = inet_addr(out[RE_UDP_UL_ADDR4]);
		if (ip4 == -1)
			goto fail;
		in4_to_6(&st->ip46, ip4);
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (inet_pton(AF_INET6, out[RE_UDP_UL_ADDR6], &st->ip46) != 1)
			goto fail;
	}
	else
		goto fail;

	st->port = atoi(out[RE_UDP_UL_PORT]);
	st->mediatype = "unknown";
	if (!st->port && strcmp(out[RE_UDP_UL_PORT], "0"))
		goto fail;

	if (out[RE_UDP_UL_FLAGS] && *out[RE_UDP_UL_FLAGS]) {
		i = 0;
		for (cp =out[RE_UDP_UL_FLAGS]; *cp && i < 2; cp++) {
			c = chrtoupper(*cp);
			if (c == 'E')
				st->direction[i++] = DIR_EXTERNAL;
			else if (c == 'I')
				st->direction[i++] = DIR_INTERNAL;
		}
	}

	if (out[RE_UDP_UL_NUM] && *out[RE_UDP_UL_NUM])
		st->num = atoi(out[RE_UDP_UL_NUM]);
	if (!st->num)
		st->num = 1;

	return 0;
fail:
	return -1;
}

char *call_update_udp(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;
	char *ret;

	c = call_get_or_create(out[RE_UDP_UL_CALLID], out[RE_UDP_UL_VIABRANCH], m);
	log_info = out[RE_UDP_UL_VIABRANCH];
	c->calling_agent = "UNKNOWN(udp)";

	if (addr_parse_udp(&st, out))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, out[RE_UDP_UL_FROMTAG], 0);
	g_queue_clear(&q);

	ret = streams_print(c->callstreams, 1, (num >= 0) ? 0 : 1, out[RE_UDP_COOKIE], 1);
	mutex_unlock(&c->lock);

	if (redis_update)
		redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	log_info = NULL;
	obj_put(c);
	return ret;

fail:
	mutex_unlock(&c->lock);
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	xasprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	log_info = NULL;
	obj_put(c);
	return ret;
}

char *call_lookup_udp(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;
	char *ret;
	const char *branch;

	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, out[RE_UDP_UL_CALLID]);
	if (c)
		mutex_lock(&c->lock);
	else {
		rwlock_unlock_r(&m->hashlock);
		mylog(LOG_WARNING, LOG_PREFIX_CI "Got UDP LOOKUP for unknown call-id or unknown via-branch",
			out[RE_UDP_UL_CALLID], out[RE_UDP_UL_VIABRANCH]);
		xasprintf(&ret, "%s 0 " IPF "\n", out[RE_UDP_COOKIE], IPP(m->conf.ipv4));
		return ret;
	}

	obj_hold(c);
	rwlock_unlock_r(&m->hashlock);

	branch = out[RE_UDP_UL_VIABRANCH];
	if (branch && *branch && !g_hash_table_lookup(c->branches, branch))
		g_hash_table_insert(c->branches, call_strdup(c, branch),
		(void *) 0x1);

	log_info = branch;
	c->called_agent = "UNKNOWN(udp)";

	if (addr_parse_udp(&st, out))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, out[RE_UDP_UL_TOTAG], 1);
	g_queue_clear(&q);

	ret = streams_print(c->callstreams, 1, (num >= 0) ? 1 : 0, out[RE_UDP_COOKIE], 1);
	mutex_unlock(&c->lock);

	if (redis_update)
		redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	log_info = NULL;
	obj_put(c);
	return ret;

fail:
	mutex_unlock(&c->lock);
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	xasprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	log_info = NULL;
	obj_put(c);
	return ret;
}

char *call_request(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	int num;
	char *ret;

	c = call_get_or_create(out[RE_TCP_RL_CALLID], NULL, m);

	c->calling_agent = (out[RE_TCP_RL_AGENT] && *out[RE_TCP_RL_AGENT])
		? call_strdup(c, out[RE_TCP_RL_AGENT]) : "UNKNOWN";
	info_parse(out[RE_TCP_RL_INFO], c);
	s = streams_parse(out[RE_TCP_RL_STREAMS], m);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "fromtag"), 0);
	streams_free(s);
	ret = streams_print(c->callstreams, abs(num), (num >= 0) ? 0 : 1, NULL, 0);
	mutex_unlock(&c->lock);

	if (redis_update)
		redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	obj_put(c);
	return ret;
}

char *call_lookup(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	int num;
	char *ret;

	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, out[RE_TCP_RL_CALLID]);
	if (!c) {
		rwlock_unlock_r(&m->hashlock);
		mylog(LOG_WARNING, LOG_PREFIX_C "Got LOOKUP for unknown call-id", out[RE_TCP_RL_CALLID]);
		return NULL;
	}
	obj_hold(c);
	mutex_lock(&c->lock);
	rwlock_unlock_r(&m->hashlock);

	c->called_agent = (out[RE_TCP_RL_AGENT] && *out[RE_TCP_RL_AGENT])
		? call_strdup(c, out[RE_TCP_RL_AGENT]) : "UNKNOWN";
	info_parse(out[RE_TCP_RL_INFO], c);
	s = streams_parse(out[RE_TCP_RL_STREAMS], m);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "totag"), 1);
	streams_free(s);
	ret = streams_print(c->callstreams, abs(num), (num >= 0) ? 1 : 0, NULL, 0);
	mutex_unlock(&c->lock);

	if (redis_update)
		redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	obj_put(c);
	return ret;
}

char *call_delete_udp(const char **out, struct callmaster *m) {
	struct call *c;
	char *ret;
	struct callstream *cs;
	GList *l;
	int i;
	struct peer *p, *px;

	DBG("got delete for callid '%s' and viabranch '%s'", 
		out[RE_UDP_DQ_CALLID], out[RE_UDP_DQ_VIABRANCH]);

	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, out[RE_UDP_DQ_CALLID]);
	if (!c) {
		rwlock_unlock_r(&m->hashlock);
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to delete not found", out[RE_UDP_DQ_CALLID]);
		goto err;
	}
	obj_hold(c);
	mutex_lock(&c->lock);
	rwlock_unlock_r(&m->hashlock);

	log_info = out[RE_UDP_DQ_VIABRANCH];

	if (out[RE_UDP_DQ_FROMTAG] && *out[RE_UDP_DQ_FROMTAG]) {
		for (l = c->callstreams->head; l; l = l->next) {
			cs = l->data;
			mutex_lock(&cs->lock);

			for (i = 0; i < 2; i++) {
				p = &cs->peers[i];
				if (!p->tag)
					continue;
				if (strcmp(p->tag, out[RE_UDP_DQ_FROMTAG]))
					continue;
				if (!out[RE_UDP_DQ_TOTAG] || !*out[RE_UDP_DQ_TOTAG])
					goto tag_match;

				px = &cs->peers[i ^ 1];
				if (!px->tag)
					continue;
				if (strcmp(px->tag, out[RE_UDP_DQ_TOTAG]))
					continue;

				goto tag_match;
			}

			mutex_unlock(&cs->lock);
		}
	}

	mylog(LOG_INFO, LOG_PREFIX_C "Tags didn't match for delete message, ignoring", c->callid);
	goto err;

tag_match:
	mutex_unlock(&cs->lock);

	if (out[RE_UDP_DQ_VIABRANCH] && *out[RE_UDP_DQ_VIABRANCH]) {
		if (!g_hash_table_remove(c->branches, out[RE_UDP_DQ_VIABRANCH])) {
			mylog(LOG_INFO, LOG_PREFIX_CI "Branch to delete doesn't exist", c->callid, out[RE_UDP_DQ_VIABRANCH]);
			goto err;
		}

		mylog(LOG_INFO, LOG_PREFIX_CI "Branch deleted", LOG_PARAMS_CI(c));
		if (g_hash_table_size(c->branches))
			goto success_unlock;
		else
			DBG("no branches left, deleting full call");
	}

	mutex_unlock(&c->lock);
	mylog(LOG_INFO, LOG_PREFIX_C "Deleting full call", c->callid);
	call_destroy(c);
	goto success;

success_unlock:
	mutex_unlock(&c->lock);
success:
	xasprintf(&ret, "%s 0\n", out[RE_UDP_COOKIE]);
	goto out;

err:
	if (c)
		mutex_unlock(&c->lock);
	xasprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	log_info = NULL;
	if (c)
		obj_put(c);
	return ret;
}

char *call_query_udp(const char **out, struct callmaster *m) {
	struct call *c;
	char *ret;
	struct callstream *cs;
	long long unsigned int pcs[4] = {0,0,0,0};
	time_t newest = 0;
	int i;
	GList *l;
	struct peer *p, *px;

	DBG("got query for callid '%s'", out[RE_UDP_DQ_CALLID]);

	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, out[RE_UDP_DQ_CALLID]);
	if (!c) {
		rwlock_unlock_r(&m->hashlock);
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to query not found", out[RE_UDP_DQ_CALLID]);
		goto err;
	}
	obj_hold(c);
	mutex_lock(&c->lock);
	rwlock_unlock_r(&m->hashlock);

	for (l = c->callstreams->head; l; l = l->next) {
		cs = l->data;
		mutex_lock(&cs->lock);

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];
			px = &cs->peers[i ^ 1];

			if (p->rtps[0].last > newest)
				newest = p->rtps[0].last;
			if (p->rtps[1].last > newest)
				newest = p->rtps[1].last;

			if (!out[RE_UDP_DQ_FROMTAG] || !*out[RE_UDP_DQ_FROMTAG])
				goto tag_match;

			if (!p->tag)
				continue;
			if (strcmp(p->tag, out[RE_UDP_DQ_FROMTAG]))
				continue;
			if (!out[RE_UDP_DQ_TOTAG] || !*out[RE_UDP_DQ_TOTAG])
				goto tag_match;

			if (!px->tag)
				continue;
			if (strcmp(px->tag, out[RE_UDP_DQ_TOTAG]))
				continue;

tag_match:
			pcs[0] += p->rtps[0].stats.packets;
			pcs[1] += px->rtps[0].stats.packets;
			pcs[2] += p->rtps[1].stats.packets;
			pcs[3] += px->rtps[1].stats.packets;
		}

		mutex_unlock(&cs->lock);
	}

	mutex_unlock(&c->lock);

	xasprintf(&ret, "%s %lld %llu %llu %llu %llu\n", out[RE_UDP_COOKIE],
		(long long int) m->conf.silent_timeout - (poller_now - newest),
		pcs[0], pcs[1], pcs[2], pcs[3]);
	goto out;

err:
	if (c)
		mutex_unlock(&c->lock);
	xasprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	if (c)
		obj_put(c);
	return ret;
}

void call_delete(const char **out, struct callmaster *m) {
	struct call *c;

	rwlock_lock_r(&m->hashlock);
	c = g_hash_table_lookup(m->callhash, out[RE_TCP_D_CALLID]);
	if (!c) {
		rwlock_unlock_r(&m->hashlock);
		return;
	}
	obj_hold(c);
	rwlock_unlock_r(&m->hashlock);

	/* delete whole list, as we don't have branches in tcp controller */
	call_destroy(c);
	obj_put(c);
}



static void call_status_iterator(struct call *c, struct control_stream *s) {
	GList *l;
	struct callstream *cs;
	struct peer *p;
	struct streamrelay *r1, *r2;
	struct streamrelay *rx1, *rx2;
	struct callmaster *m;
	char addr1[64], addr2[64], addr3[64];

	m = c->callmaster;
	mutex_lock(&c->lock);

	control_stream_printf(s, "session %s %s %s %s %s %i\n",
		c->callid,
		(char *) g_hash_table_lookup(c->infohash, "from"),
		(char *) g_hash_table_lookup(c->infohash, "to"),
		c->calling_agent, c->called_agent,
		(int) (poller_now - c->created));

	for (l = c->callstreams->head; l; l = l->next) {
		cs = l->data;
		mutex_lock(&cs->lock);

		p = &cs->peers[0];
		r1 = &p->rtps[0];
		r2 = &cs->peers[1].rtps[0];
		rx1 = &p->rtps[1];
		rx2 = &cs->peers[1].rtps[1];

		if (r1->fd == -1 || r2->fd == -1)
			goto next;

		smart_ntop_p(addr1, &r1->peer.ip46, sizeof(addr1));
		smart_ntop_p(addr2, &r2->peer.ip46, sizeof(addr2));
		if (IN6_IS_ADDR_V4MAPPED(&r1->peer.ip46))
			inet_ntop(AF_INET, &m->conf.ipv4, addr3, sizeof(addr3));
		else
			smart_ntop_p(addr3, &m->conf.ipv6, sizeof(addr3));

		control_stream_printf(s, "stream %s:%u %s:%u %s:%u %llu/%llu/%llu %s %s %s %i\n",
			addr1, r1->peer.port,
			addr2, r2->peer.port,
			addr3, r1->localport,
			(long long unsigned int) r1->stats.bytes + rx1->stats.bytes,
			(long long unsigned int) r2->stats.bytes + rx2->stats.bytes,
			(long long unsigned int) r1->stats.bytes + rx1->stats.bytes + r2->stats.bytes + rx2->stats.bytes,
			"active",
			p->codec ? : "unknown",
			p->mediatype, (int) (poller_now - r1->last));
next:
		mutex_unlock(&cs->lock);
	}
	mutex_unlock(&c->lock);
}

static void callmaster_get_all_calls_interator(void *key, void *val, void *ptr) {
	GQueue *q = ptr;
	g_queue_push_tail(q, obj_get(val));
}

void calls_status(struct callmaster *m, struct control_stream *s) {
	struct stats st;
	GQueue q = G_QUEUE_INIT;
	struct call *c;

	mutex_lock(&m->statslock);
	st = m->stats;
	mutex_unlock(&m->statslock);

	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, callmaster_get_all_calls_interator, &q);
	rwlock_unlock_r(&m->hashlock);

	control_stream_printf(s, "proxy %u %llu/%llu/%llu\n",
		g_queue_get_length(&q),
		(long long unsigned int) st.bytes,
		(long long unsigned int) st.bytes - st.errors,
		(long long unsigned int) st.bytes * 2 - st.errors);

	while (q.head) {
		c = g_queue_pop_head(&q);
		call_status_iterator(c, s);
		obj_put(c);
	}
}




static void calls_dump_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct callmaster *m = c->callmaster;

	if (redis_update)
		redis_update(c, m->conf.redis);
}

void calls_dump_redis(struct callmaster *m) {
	if (!m->conf.redis)
		return;

	mylog(LOG_DEBUG, "Start dumping all call data to Redis...\n");
	redis_wipe(m->conf.redis);
	g_hash_table_foreach(m->callhash, calls_dump_iterator, NULL);
	mylog(LOG_DEBUG, "Finished dumping all call data to Redis\n");
}

void callmaster_config(struct callmaster *m, struct callmaster_config *c) {
	m->conf = *c;
}

struct callstream *callstream_new(struct call *ca, int num) {
	struct callstream *s;

	s = obj_alloc0("callstream", sizeof(*s), callstream_free);
	s->call = obj_get(ca);
	s->num = num;
	mutex_init(&s->lock);

	return s;
}
