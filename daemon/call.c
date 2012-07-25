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
#define LOG_PARAMS_CI(c) (c)->callid, (c)->log_info



static pcre		*info_re;
static pcre_extra	*info_ree;
static pcre		*streams_re;
static pcre_extra	*streams_ree;

static BIT_ARRAY_DECLARE(ports_used, 0x10000);




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




static void stream_closed(int fd, void *p) {
	struct streamrelay *r = p;
	struct call *c;
	int i;
	socklen_t j;

	c = r->up->up->call;

	j = sizeof(i);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &i, &j);
	mylog(LOG_WARNING, LOG_PREFIX_C "Read error on RTP socket: %i (%s) -- closing call", LOG_PARAMS_C(c), i, strerror(i));

	call_destroy(c);
}




void kernelize(struct callstream *c) {
	int i, j;
	struct peer *p, *pp;
	struct streamrelay *r, *rp;
	struct kernel_stream ks;
	struct callmaster *cm = c->call->callmaster;

	if (cm->kernelfd < 0 || cm->kernelid == -1)
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

			if (IN6_IS_ADDR_UNSPECIFIED(&r->peer.ip46) || !r->fd_family || !r->peer.port)
				continue;

			ks.local_port = r->localport;
			ks.tos = cm->tos;
			ks.src.port = rp->localport;
			ks.dest.port = r->peer.port;

			if (IN6_IS_ADDR_V4MAPPED(&r->peer.ip46)) {
				ks.src.family = AF_INET;
				ks.src.ipv4 = cm->ipv4;
				ks.dest.family = AF_INET;
				ks.dest.ipv4 = r->peer.ip46.s6_addr32[3];
			}
			else {
				ks.src.family = AF_INET6;
				ks.src.ipv6 = cm->ipv6;
				ks.dest.family = AF_INET6;
				ks.dest.ipv6 = r->peer.ip46;
			}

			ZERO(r->kstats);

			kernel_add_stream(cm->kernelfd, &ks, 0);
		}

		p->kernelized = 1;
	}
}




static int stream_packet(struct streamrelay *r, char *b, int l, struct sockaddr_in6 *fsin) {
	struct streamrelay *p, *p2;
	struct peer *pe, *pe2;
	struct callstream *cs;
	int ret;
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
		m->statsps.errors++;
		return 0;
	}

	if (pe->confirmed || !pe->filled || r->idx != 0)
		goto forward;

	if (!c->lookup_done || m->poller->now <= c->lookup_done + 3)
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

	if (redis_update)
		redis_update(c);

forward:
	if (IN6_IS_ADDR_UNSPECIFIED(&r->peer.ip46) || !r->peer.port || !r->fd_family)
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

			ch->cmsg_len = CMSG_LEN(sizeof(*pi));
			ch->cmsg_level = IPPROTO_IP;
			ch->cmsg_type = IP_PKTINFO;

			pi = (void *) CMSG_DATA(ch);
			ZERO(*pi);
			pi->ipi_spec_dst.s_addr = m->ipv4;

			mh.msg_controllen = CMSG_SPACE(sizeof(*pi));

			break;

		case AF_INET6:
			ZERO(sin6);
			sin6.sin6_family = AF_INET6;
			sin6.sin6_addr = r->peer.ip46;
			sin6.sin6_port = htons(r->peer.port);
			mh.msg_name = &sin6;
			mh.msg_namelen = sizeof(sin6);

			ch->cmsg_len = CMSG_LEN(sizeof(*pi6));
			ch->cmsg_level = IPPROTO_IPV6;
			ch->cmsg_type = IPV6_PKTINFO;

			pi6 = (void *) CMSG_DATA(ch);
			ZERO(*pi6);
			pi6->ipi6_addr = m->ipv6;

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

	if (ret == -1 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
		r->stats.errors++;
		m->statsps.errors++;
		return -1;
	}

drop:
	r->stats.packets++;
	r->stats.bytes += l;
	m->statsps.packets++;
	m->statsps.bytes += l;
	r->last = m->poller->now;

	return 0;
}




static void stream_readable(int fd, void *p) {
	struct streamrelay *r = p;
	char buf[8192];
	int ret;
	struct sockaddr_storage ss;
	struct sockaddr_in6 sin6;
	struct sockaddr_in *sin;
	unsigned int sinlen;
	void *sinp;

	for (;;) {
		sinlen = sizeof(ss);
		ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &ss, &sinlen);

		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			stream_closed(fd, r);
			break;
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

		if (stream_packet(r, buf, ret, sinp)) {
			mylog(LOG_WARNING, "Write error on RTP socket");
			call_destroy(r->up->up->call);
			return;
		}
	}
}





static int info_parse_func(char **a, void **ret, void *p) {
	GHashTable *h = p;

	g_hash_table_replace(h, strdup(a[0]), a[1] ? strdup(a[1]) : NULL);

	return -1;
}


static GHashTable *info_parse(const char *s, GHashTable **h) {
	GQueue *q;

	q = pcre_multi_match(&info_re, &info_ree, "^([^:,]+)(?::(.*?))?(?:$|,)", s, 2, info_parse_func, *h);
	g_queue_free(q);

	return *h;
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
	st->mediatype = strdup(a[2] ? : "");
	st->num = ++(*i);

	if (!st->port)
		goto fail;

	*ret = st;
	return 0;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s:%s", a[0], a[1]);
	free(st->mediatype);
	g_slice_free1(sizeof(*st), st);
	return -1;
}


static GQueue *streams_parse(const char *s) {
	int i;
	i = 0;
	return pcre_multi_match(&streams_re, &streams_ree, "^([\\d.]+):(\\d+)(?::(.*?))?(?:$|,)", s, 3, streams_parse_func, &i);
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



struct iterator_helper {
	GList			*del;
	struct streamrelay	*ports[0x10000];
};


static void call_timer_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct iterator_helper *hlp = ptr;
	GList *it;
	struct callstream *cs;
	int i, j;
	struct peer *p;
	struct poller *po;
	struct callmaster *cm;
	unsigned int check;
	struct streamrelay *sr;

	if (!c->callstreams->head)
		goto drop;

	cm = c->callmaster;
	po = cm->poller;

	for (it = c->callstreams->head; it; it = it->next) {
		cs = it->data;

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];
			for (j = 0; j < 2; j++) {
				sr = &p->rtps[j];
				hlp->ports[sr->localport] = sr;

				check = cm->timeout;
				if (!sr->peer.port)
					check = cm->silent_timeout;
				else if (IN6_IS_ADDR_UNSPECIFIED(&sr->peer.ip46))
					check = cm->silent_timeout;

				if (po->now - sr->last < check)
					goto good;
			}
		}
	}

	mylog(LOG_INFO, LOG_PREFIX_C "Closing call branch due to timeout", 
		LOG_PARAMS_C(c));

drop:
	hlp->del = g_list_prepend(hlp->del, c);
	return;

good:
	;
}

static void xmlrpc_kill_calls(GList *list, const char *url) {
	pid_t parent;
	int i;
	xmlrpc_env e;
	xmlrpc_client *c;
	xmlrpc_value *r;
	struct call *ca;
	GList *csl;
	struct callstream *cs;

	parent = fork();
	if (parent)
		return;
	parent = fork();
	if (parent)
		_exit(0);

	for (i = 0; i < 8192; i++)
		close(i);

	xmlrpc_env_init(&e);
	xmlrpc_client_setup_global_const(&e);
	xmlrpc_client_create(&e, XMLRPC_CLIENT_NO_FLAGS, "ngcp-mediaproxy-ng", MEDIAPROXY_VERSION, NULL, 0, &c);

	while (list) {
		ca = list->data;

		for (csl = ca->callstreams->head; csl; csl = csl->next) {
			cs = csl->data;
			if (!cs->peers[1].tag || !*cs->peers[1].tag)
				continue;
			alarm(2);
			xmlrpc_client_call2f(&e, c, url, "di", &r, "(ssss)",
				"sbc", "postControlCmd", cs->peers[1].tag, "teardown");
			xmlrpc_DECREF(r);
			alarm(0);
		}

		list = list->next;
	}

	_exit(0);
}


#define DS(x) do {							\
		if (ke->stats.x < sr->kstats.x)				\
			d = 0;						\
		else							\
			d = ke->stats.x - sr->kstats.x;			\
		sr->stats.x += d;					\
		m->statsps.x += d;					\
	} while (0)
static void callmaster_timer(void *ptr) {
	struct callmaster *m = ptr;
	struct iterator_helper hlp;
	GList *i, *n;
	struct call *c;
	struct mediaproxy_list_entry *ke;
	struct streamrelay *sr;
	struct poller *po;
	u_int64_t d;

	ZERO(hlp);
	po = m->poller;

	g_hash_table_foreach(m->callhash, call_timer_iterator, &hlp);

	memcpy(&m->stats, &m->statsps, sizeof(m->stats));
	ZERO(m->statsps);

	i = (m->kernelid != -1) ? kernel_list(m->kernelid) : NULL;
	while (i) {
		ke = i->data;

		sr = hlp.ports[ke->target.target_port];
		if (!sr)
			goto next;

		DS(packets);
		DS(bytes);
		DS(errors);

		if (ke->stats.packets != sr->kstats.packets)
			sr->last = po->now;

		sr->kstats.packets = ke->stats.packets;
		sr->kstats.bytes = ke->stats.bytes;
		sr->kstats.errors = ke->stats.errors;

next:
		g_slice_free1(sizeof(*ke), ke);
		i = g_list_delete_link(i, i);
	}

	if (m->b2b_url)
		xmlrpc_kill_calls(hlp.del, m->b2b_url);

	for (i = hlp.del; i; i = n) {
		n = i->next;
		c = i->data;
		call_destroy(c);
		g_list_free_1(i);
	}
}
#undef DS


struct callmaster *callmaster_new(struct poller *p) {
	struct callmaster *c;

	c = g_slice_alloc0(sizeof(*c));

	c->callhash = g_hash_table_new(g_str_hash, g_str_equal);
	if (!c->callhash)
		goto fail;
	c->poller = p;

	poller_timer(p, callmaster_timer, c);

	return c;

fail:
	g_slice_free1(sizeof(*c), c);
	return NULL;
}



static int get_port4(struct streamrelay *r, u_int16_t p) {
	int fd;
	struct sockaddr_in sin;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	nonblock(fd);
	reuseaddr(fd);
	setsockopt(fd, IPPROTO_IP, IP_TOS, &r->up->up->call->callmaster->tos, sizeof(r->up->up->call->callmaster->tos));

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

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	nonblock(fd);
	reuseaddr(fd);
#ifdef IPV6_TCLASS
	setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &r->up->up->call->callmaster->tos, sizeof(r->up->up->call->callmaster->tos));
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

	if (bit_array_isset(ports_used, p))
		return -1;

	if (IN6_IS_ADDR_UNSPECIFIED(&r->up->up->call->callmaster->ipv6))
		ret = get_port4(r, p);
	else
		ret = get_port6(r, p);

	if (ret)
		return ret;

	r->localport = p;

	return 0;
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
		goto reserve;
	}

	min = (m->port_min > 0 && m->port_min < 0xfff0) ? m->port_min : 1024;
	max = (m->port_max > 0 && m->port_max > min && m->port_max < 0xfff0) ? m->port_max : 0;

	if (!m->lastport)
		m->lastport = max;
	port = m->lastport + 1;

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
		close(a->fd);
next:
		port++;
	}

	m->lastport = port;
	mylog(LOG_DEBUG, LOG_PREFIX_CI "Opened ports %u/%u for RTP", 
		LOG_PARAMS_CI(c), a->localport, b->localport);

reserve:
	bit_array_set(ports_used, a->localport);
	bit_array_set(ports_used, b->localport);

	return;

fail:
	mylog(LOG_ERR, LOG_PREFIX_CI "Failed to get RTP port pair", LOG_PARAMS_CI(c));
	if (a->fd != -1)
		close(a->fd);
	if (b->fd != -1)
		close(b->fd);
	a->fd = b->fd = -1;
}



static int setup_peer(struct peer *p, struct stream *s, const char *tag) {
	struct streamrelay *a, *b;
	struct callstream *cs;
	int i;

	cs = p->up;
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

	strdupfree(&p->mediatype, s->mediatype);
	strdupfree(&p->tag, tag);
	p->filled = 1;

	return 0;
}

static void steal_peer(struct peer *dest, struct peer *src) {
	struct streamrelay *r;
	int i;
	struct poller_item pi;
	struct streamrelay *sr, *srs;
	struct call *c;
	struct poller *po;

	ZERO(pi);
	r = &src->rtps[0];
	c = src->up->call;
	po = c->callmaster->poller;

	mylog(LOG_DEBUG, LOG_PREFIX_CI "Re-using existing open RTP port %u", 
		LOG_PARAMS_CI(c), r->localport);

	dest->confirmed = 0;
	unkernelize(dest);
	src->confirmed = 0;
	unkernelize(src);

	dest->filled = 1;
	strmove(&dest->mediatype, &src->mediatype);
	strmove(&dest->tag, &src->tag);
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
			close(sr->fd);
			bit_array_clear(ports_used, sr->localport);
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
		pi.ptr = sr;
		pi.readable = stream_readable;
		pi.closed = stream_closed;

		poller_update_item(po, &pi);
	}
}


void callstream_init(struct callstream *s, struct call *ca, int port1, int port2, int num) {
	int i, j, tport;
	struct peer *p;
	struct streamrelay *r;
	struct poller_item pi;
	struct poller *po;

	po = ca->callmaster->poller;

	ZERO(*s);
	ZERO(pi);

	s->call = ca;
	DBG("setting new callstream num to %i", num);
	s->num = num;

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];

		p->idx = i;
		p->up = s;
		p->tag = strdup("");
		p->mediatype = strdup("");

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];

			r->fd = -1;
			r->idx = j;
			r->up = p;
			r->last = po->now;
		}

		tport = (i == 0) ? port1 : port2;

		if (tport >= 0) {
			get_port_pair(p, tport);

			for (j = 0; j < 2; j++) {
				r = &p->rtps[j];

				pi.fd = r->fd;
				pi.ptr = r;
				pi.readable = stream_readable;
				pi.closed = stream_closed;

				poller_add_item(po, &pi);
			}
		}
	}
}



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
		}

		/* not found */
		r = NULL;
		cs_o = NULL;
		l = NULL;

found:

		if (!opmode) {	/* request */
			DBG("creating new callstream");

			cs = g_slice_alloc(sizeof(*cs));

			if (!r) {
				/* nothing found to re-use, open new ports */
				callstream_init(cs, c, 0, 0, t->num);
				p = &cs->peers[0];
				setup_peer(p, t, tag);
			}
			else {
				/* re-use, so don't open new ports */
				callstream_init(cs, c, -1, -1, t->num);
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
			}

			g_queue_push_tail(q, cs);
			ZERO(c->lookup_done);
			continue;
		}

		/* lookup */
		for (l = c->callstreams->head; l; l = l->next) {
			cs = l->data;
			DBG("hunting for callstream, %i <> %i", cs->num, t->num);
			if (cs->num != t->num)
				continue;
			goto got_cs;
		}

		mylog(LOG_WARNING, LOG_PREFIX_CI "Got LOOKUP, but no usable callstreams found", 
			LOG_PARAMS_CI(c));
		break;

got_cs:
		g_queue_delete_link(c->callstreams, l);
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
			cs_o = cs;
			cs = g_slice_alloc(sizeof(*cs));
			callstream_init(cs, c, 0, 0, t->num);
			steal_peer(&cs->peers[0], &cs_o->peers[0]);
			p = &cs->peers[1];
			setup_peer(p, t, tag);
			g_queue_push_tail(c->callstreams, cs_o);
		}

		time(&c->lookup_done);

skip:
		g_queue_push_tail(q, p->up);
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

		kernel_del_stream(p->up->call->callmaster->kernelfd, r->localport);

	}

	p->kernelized = 0;
}



static void kill_callstream(struct callstream *s) {
	int i, j;
	struct peer *p;
	struct streamrelay *r;

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];

		unkernelize(p);

		free(p->tag);
		free(p->mediatype);

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];

			if (r->fd != -1) {
				poller_del_item(s->call->callmaster->poller, r->fd);
				close(r->fd);
				bit_array_clear(ports_used, r->localport);
			}
		}
	}

	g_slice_free1(sizeof(*s), s);
}

static void call_destroy(struct call *c) {
	struct callmaster *m = c->callmaster;
	struct callstream *s;

	g_hash_table_remove(m->callhash, c->callid);

	if (redis_delete)
		redis_delete(c);

	g_hash_table_destroy(c->infohash);
	g_hash_table_destroy(c->branches);
	if (c->calling_agent)
		free(c->calling_agent);
	if (c->called_agent)
		free(c->called_agent);

	mylog(LOG_INFO, LOG_PREFIX_C "Final packet stats:", c->callid);
	while (c->callstreams->head) {
		s = g_queue_pop_head(c->callstreams);
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
	}
	g_queue_free(c->callstreams);
	free(c->callid);

	g_slice_free1(sizeof(*c), c);
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
				&& IN6_IS_ADDR_V4MAPPED(&t->peers[other_off].rtps[0].peer.ip46))
			|| IN6_IS_ADDR_UNSPECIFIED(&t->call->callmaster->ipv6)) {
		ip4 = t->peers[off].rtps[0].peer.ip46.s6_addr32[3];
		if (!ip4)
			strcpy(ips, "0.0.0.0");
		else if (t->call->callmaster->adv_ipv4)
			sprintf(ips, IPF, IPP(t->call->callmaster->adv_ipv4));
		else
			sprintf(ips, IPF, IPP(t->call->callmaster->ipv4));

		af = '4';
	}
	else {
		if (IN6_IS_ADDR_UNSPECIFIED(&t->peers[off].rtps[0].peer.ip46))
			strcpy(ips, "::");
		else if (!IN6_IS_ADDR_UNSPECIFIED(&t->call->callmaster->adv_ipv6))
			inet_ntop(AF_INET6, &t->call->callmaster->adv_ipv6, ips, sizeof(ips));
		else
			inet_ntop(AF_INET6, &t->call->callmaster->ipv6, ips, sizeof(ips));

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

static struct call *call_create(const char *callid, struct callmaster *m) {
	struct call *c;

	mylog(LOG_NOTICE, LOG_PREFIX_C "Creating new call",
		callid);	/* XXX will spam syslog on recovery from DB */
	c = g_slice_alloc0(sizeof(*c));
	c->callmaster = m;
	c->callid = strdup(callid);
	c->callstreams = g_queue_new();
	c->created = m->poller->now;
	c->infohash = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
	c->branches = g_hash_table_new_full(g_str_hash0, g_str_equal0, free, NULL);
	return c;
}

struct call *call_get_or_create(const char *callid, const char *viabranch, struct callmaster *m) {
	struct call *c;

	c = g_hash_table_lookup(m->callhash, callid);
	if (!c) {
		/* completely new call-id, create call */
		c = call_create(callid, m);
		g_hash_table_insert(m->callhash, c->callid, c);
	}

	if (viabranch && !g_hash_table_lookup(c->branches, viabranch))
		g_hash_table_insert(c->branches, strdup(viabranch), (void *) 0x1);

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
	c->log_info = out[RE_UDP_UL_VIABRANCH];
	strdupfree(&c->calling_agent, "UNKNOWN(udp)");

	if (addr_parse_udp(&st, out))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, out[RE_UDP_UL_FROMTAG], 0);

	g_queue_clear(&q);

	if (redis_update)
		redis_update(c);

	ret = streams_print(c->callstreams, 1, (num >= 0) ? 0 : 1, out[RE_UDP_COOKIE], 1);
	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	c->log_info = NULL;
	return ret;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	asprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	c->log_info = NULL;
	return ret;
}

char *call_lookup_udp(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;
	char *ret;

	c = g_hash_table_lookup(m->callhash, out[RE_UDP_UL_CALLID]);
	if (!c || !g_hash_table_lookup(c->branches, out[RE_UDP_UL_VIABRANCH])) {
		mylog(LOG_WARNING, LOG_PREFIX_CI "Got UDP LOOKUP for unknown call-id or unknown via-branch",
			out[RE_UDP_UL_CALLID], out[RE_UDP_UL_VIABRANCH]);
		asprintf(&ret, "%s 0 " IPF "\n", out[RE_UDP_COOKIE], IPP(m->ipv4));
		return ret;
	}

	c->log_info = out[RE_UDP_UL_CALLID];
	strdupfree(&c->called_agent, "UNKNOWN(udp)");

	if (addr_parse_udp(&st, out))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, out[RE_UDP_UL_TOTAG], 1);

	g_queue_clear(&q);

	if (redis_update)
		redis_update(c);

	ret = streams_print(c->callstreams, 1, (num >= 0) ? 1 : 0, out[RE_UDP_COOKIE], 1);
	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	c->log_info = NULL;
	return ret;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	asprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	c->log_info = NULL;
	return ret;
}

char *call_request(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	int num;
	char *ret;

	c = call_get_or_create(out[RE_TCP_RL_CALLID], NULL, m);

	strdupfree(&c->calling_agent, (out[RE_TCP_RL_AGENT] && *out[RE_TCP_RL_AGENT]) ? out[RE_TCP_RL_AGENT] : "UNKNOWN");
	info_parse(out[RE_TCP_RL_INFO], &c->infohash);
	s = streams_parse(out[RE_TCP_RL_STREAMS]);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "fromtag"), 0);
	streams_free(s);

	if (redis_update)
		redis_update(c);

	ret = streams_print(c->callstreams, abs(num), (num >= 0) ? 0 : 1, NULL, 0);
	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
	return ret;
}

char *call_lookup(const char **out, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	int num;
	char *ret;

	c = g_hash_table_lookup(m->callhash, out[RE_TCP_RL_CALLID]);
	if (!c) {
		mylog(LOG_WARNING, LOG_PREFIX_C "Got LOOKUP for unknown call-id", out[RE_TCP_RL_CALLID]);
		return NULL;
	}

	strdupfree(&c->called_agent, out[RE_TCP_RL_AGENT] ? : "UNKNOWN");
	info_parse(out[RE_TCP_RL_INFO], &c->infohash);
	s = streams_parse(out[RE_TCP_RL_STREAMS]);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "totag"), 1);
	streams_free(s);

	if (redis_update)
		redis_update(c);

	ret = streams_print(c->callstreams, abs(num), (num >= 0) ? 1 : 0, NULL, 0);
	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %s", LOG_PARAMS_CI(c), ret);
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
		out[RE_UDP_D_CALLID], out[RE_UDP_D_VIABRANCH]);

	c = g_hash_table_lookup(m->callhash, out[RE_UDP_D_CALLID]);
	if (!c) {
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to delete not found", out[RE_UDP_D_CALLID]);
		goto err;
	}
	c->log_info = out[RE_UDP_D_VIABRANCH];

	if (out[RE_UDP_D_FROMTAG] && *out[RE_UDP_D_FROMTAG]) {
		for (l = c->callstreams->head; l; l = l->next) {
			cs = l->data;
			for (i = 0; i < 2; i++) {
				p = &cs->peers[i];
				if (!p->tag)
					continue;
				if (strcmp(p->tag, out[RE_UDP_D_FROMTAG]))
					continue;
				if (!out[RE_UDP_D_TOTAG] || !*out[RE_UDP_D_TOTAG])
					goto tag_match;

				px = &cs->peers[i ^ 1];
				if (!px->tag)
					continue;
				if (strcmp(px->tag, out[RE_UDP_D_TOTAG]))
					continue;

				goto tag_match;
			}
		}
	}

	mylog(LOG_INFO, LOG_PREFIX_C "Tags didn't match for delete message, ignoring", c->callid);
	goto err;

tag_match:
	if (out[RE_UDP_D_VIABRANCH] && *out[RE_UDP_D_VIABRANCH]) {
		if (!g_hash_table_remove(c->branches, out[RE_UDP_D_VIABRANCH])) {
			mylog(LOG_INFO, LOG_PREFIX_CI "Branch to delete doesn't exist", c->callid, out[RE_UDP_D_VIABRANCH]);
			goto err;
		}

		mylog(LOG_INFO, LOG_PREFIX_CI "Branch deleted", LOG_PARAMS_CI(c));
		if (g_hash_table_size(c->branches))
			goto success;
		else
			DBG("no branches left, deleting full call");
	}

	mylog(LOG_INFO, LOG_PREFIX_C "Deleting full call", c->callid);
	call_destroy(c);


success:
	asprintf(&ret, "%s 0\n", out[RE_UDP_COOKIE]);
	goto out;

err:

	asprintf(&ret, "%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	if (c)
		c->log_info = NULL;
	return ret;
}

void call_delete(const char **out, struct callmaster *m) {
	struct call *c;

	c = g_hash_table_lookup(m->callhash, out[RE_TCP_D_CALLID]);
	if (!c)
		return;

	/* delete whole list, as we don't have branches in tcp controller */
	call_destroy(c);
}



static void call_status_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct control_stream *s = ptr;
	GList *l;
	struct callstream *cs;
	struct peer *p;
	struct streamrelay *r1, *r2;
	struct streamrelay *rx1, *rx2;
	struct callmaster *m;
	char addr1[64], addr2[64], addr3[64];

	m = c->callmaster;

	/* TODO: only called for tcp controller, so no linked list of calls? */

	streambuf_printf(s->outbuf, "session %s %s %s %s %s %i\n",
		c->callid,
		(char *) g_hash_table_lookup(c->infohash, "from"),
		(char *) g_hash_table_lookup(c->infohash, "to"),
		c->calling_agent, c->called_agent,
		(int) (m->poller->now - c->created));

	for (l = c->callstreams->head; l; l = l->next) {
		cs = l->data;

		p = &cs->peers[0];
		r1 = &p->rtps[0];
		r2 = &cs->peers[1].rtps[0];
		rx1 = &p->rtps[1];
		rx2 = &cs->peers[1].rtps[1];

		if (r1->fd == -1 || r2->fd == -1)
			continue;

		smart_ntop_p(addr1, &r1->peer.ip46, sizeof(addr1));
		smart_ntop_p(addr2, &r2->peer.ip46, sizeof(addr2));
		if (IN6_IS_ADDR_V4MAPPED(&r1->peer.ip46))
			inet_ntop(AF_INET, &m->ipv4, addr3, sizeof(addr3));
		else
			smart_ntop_p(addr3, &m->ipv6, sizeof(addr3));

		streambuf_printf(s->outbuf, "stream %s:%u %s:%u %s:%u %llu/%llu/%llu %s %s %s %i\n",
			addr1, r1->peer.port,
			addr2, r2->peer.port,
			addr3, r1->localport,
			(long long unsigned int) r1->stats.bytes + rx1->stats.bytes,
			(long long unsigned int) r2->stats.bytes + rx2->stats.bytes,
			(long long unsigned int) r1->stats.bytes + rx1->stats.bytes + r2->stats.bytes + rx2->stats.bytes,
			"active",
			p->codec ? : "unknown",
			p->mediatype, (int) (m->poller->now - r1->last));
	}

}

void calls_status(struct callmaster *m, struct control_stream *s) {
	streambuf_printf(s->outbuf, "proxy %u %llu/%llu/%llu\n",
		g_hash_table_size(m->callhash),
		(long long unsigned int) m->stats.bytes,
		(long long unsigned int) m->stats.bytes - m->stats.errors,
		(long long unsigned int) m->stats.bytes * 2 - m->stats.errors);

	g_hash_table_foreach(m->callhash, call_status_iterator, s);
}




static void calls_dump_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;

	if (redis_update)
		redis_update(c);
}

void calls_dump_redis(struct callmaster *m) {
	if (!m->redis)
		return;

	mylog(LOG_DEBUG, "Start dumping all call data to Redis...\n");
	redis_wipe(m);
	g_hash_table_foreach(m->callhash, calls_dump_iterator, NULL);
	mylog(LOG_DEBUG, "Finished dumping all call data to Redis\n");
}
