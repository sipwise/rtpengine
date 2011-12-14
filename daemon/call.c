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
#ifndef NO_REDIS
#include <hiredis.h>
#endif
#include <stdlib.h>
#include <time.h>

#include "call.h"
#include "poller.h"
#include "aux.h"
#include "log.h"
#include "kernel.h"
#include "control.h"
#include "streambuf.h"
#ifndef NO_REDIS
#include "redis.h"
#endif



#ifdef __DEBUG
#define DBG(x...) mylog(LOG_DEBUG, x)
#else
#define DBG(x...) ((void)0)
#endif



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

	c = r->up->up->call;

	mylog(LOG_WARNING, "[%s] Read error on RTP socket", c->callid);

	call_destroy(c);
}




static void kernelize(struct callstream *c) {
	int i, j;
	struct peer *p, *pp;
	struct streamrelay *r, *rp;
	struct kernel_stream ks;

	mylog(LOG_DEBUG, "[%s] Kernelizing RTP streams", c->call->callid);

	ZERO(ks);

	for (i = 0; i < 2; i++) {
		p = &c->peers[i];
		pp = &c->peers[i ^ 1];

		if (p->kernelized)
			continue;

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];
			rp = &pp->rtps[j];

			if (!r->peer.family || !r->peer.port)
				continue;

			ks.local_port = r->localport;
			ks.tos = c->call->callmaster->tos;
			ks.src.family = ks.dest.family = r->peer.family;
			ks.src.port = rp->localport;
			ks.dest.port = r->peer.port;

			switch (r->peer.family) {
				case AF_INET:
					ks.src.ipv4 = c->call->callmaster->ipv4;
					ks.dest.ipv4 = r->peer.ipv4;
					break;
				case AF_INET6:
					memcpy(ks.src.ipv6, c->call->callmaster->ipv6, 16);
					memcpy(ks.dest.ipv6, r->peer.ipv6, 16);
					break;
				default:
					/* XXX panic */
					break;
			}

			ZERO(r->kstats);

			kernel_add_stream(c->call->callmaster->kernelfd, &ks, 0);
		}

		p->kernelized = 1;
	}
}




static int stream_packet(struct streamrelay *r, char *b, int l, struct sockaddr_storage *xsin) {
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
	struct call *c;
	struct callmaster *m;
	unsigned char cc;
	struct sockaddr_in *fsin;
	struct sockaddr_in6 *fsin6;

	fsin = (void *) xsin;
	fsin6 = (void *) xsin;

	pe = r->up;
	cs = pe->up;
	pe2 = &cs->peers[pe->idx ^ 1];
	p = &pe2->rtps[r->idx];
	c = cs->call;
	m = c->callmaster;

	if (p->fd == -1) {
		switch (xsin->ss_family) {
			case AF_INET:
				mylog(LOG_WARNING, "[%s] RTP packet to port %u discarded from " DF, c->callid, r->localport, DP(*fsin));
				break;
			case AF_INET6:
				mylog(LOG_WARNING, "[%s] RTP packet to port %u discarded from " D6F, c->callid, r->localport, D6P(*fsin6));
				break;
			default:
				/* XXX panic */
				;
		}
		r->stats.errors++;
		m->statsps.errors++;
		return 0;
	}

	if (!pe->confirmed && pe->filled && r->idx == 0) {
		if (l < 2)
			goto skip;

		if (c->lookup_done && m->poller->now > (c->lookup_done + 3)) {
			if (!pe->codec) {
				cc = b[1];
				cc &= 0x7f;
				if (cc < G_N_ELEMENTS(rtp_codecs))
					pe->codec = rtp_codecs[cc] ? : "unknown";
				else
					pe->codec = "unknown";
			}

			switch (xsin->ss_family) {
				case AF_INET:
					mylog(LOG_DEBUG, "[%s] Confirmed peer information for port %u - " DF, c->callid, r->localport, DP(*fsin));
					break;
				case AF_INET6:
					mylog(LOG_DEBUG, "[%s] Confirmed peer information for port %u - " D6F, c->callid, r->localport, D6P(*fsin6));
					break;
				default:
					/* XXX panic */
					;
			}

			pe->confirmed = 1;
		}

		p2 = &p->up->rtps[p->idx ^ 1];
		switch (xsin->ss_family) {
			case AF_INET:
				p->peer.ipv4 = fsin->sin_addr.s_addr;
				p->peer.port = ntohs(fsin->sin_port);
				p2->peer.ipv4 = fsin->sin_addr.s_addr;
				p2->peer.port = p->peer.port + ((int) (p2->idx * 2) - 1);
				break;
			case AF_INET6:
				memcpy(p->peer.ipv6, fsin6->sin6_addr.s6_addr, sizeof(p->peer.ipv6));
				p->peer.port = ntohs(fsin6->sin6_port);
				memcpy(p2->peer.ipv6, fsin6->sin6_addr.s6_addr, sizeof(p2->peer.ipv6));
				p2->peer.port = p->peer.port + ((int) (p2->idx * 2) - 1);
				break;
			default:
				/* XXX panic */
				;
		}



		if (pe->confirmed && pe2->confirmed && pe2->filled)
			kernelize(cs);

#ifndef NO_REDIS
		redis_update(c);
#endif
	}

skip:
	if (!r->peer.family || !r->peer.port)
		goto drop;

	ZERO(mh);

	switch (r->peer.family) {
		case AF_INET:
			ZERO(sin);
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = r->peer.ipv4;
			sin.sin_port = htons(r->peer.port);
			mh.msg_name = &sin;
			mh.msg_namelen = sizeof(sin);
			break;

		case AF_INET6:
			ZERO(sin6);
			sin6.sin6_family = AF_INET6;
			memcpy(sin6.sin6_addr.s6_addr, r->peer.ipv6, sizeof(sin6.sin6_addr.s6_addr));
			sin6.sin6_port = htons(r->peer.port);
			mh.msg_name = &sin6;
			mh.msg_namelen = sizeof(sin6);
			break;

		default:
			/* XXX panic */
			;
	}

	ZERO(iov);
	iov.iov_base = b;
	iov.iov_len = l;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	if (r->peer.family == AF_INET) {
		mh.msg_control = buf;
		mh.msg_controllen = sizeof(buf);

		ch = CMSG_FIRSTHDR(&mh);
		ZERO(*ch);
		ch->cmsg_len = CMSG_LEN(sizeof(*pi));
		ch->cmsg_level = IPPROTO_IP;
		ch->cmsg_type = IP_PKTINFO;

		pi = (void *) CMSG_DATA(ch);
		ZERO(*pi);
		pi->ipi_spec_dst.s_addr = m->ipv4;

		mh.msg_controllen = CMSG_SPACE(sizeof(*pi));
	}

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
	char buf[1024];
	int ret;
	struct sockaddr_storage sin;
	unsigned int sinlen;

	for (;;) {
		sinlen = sizeof(sin);
		ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &sin, &sinlen);

		if (ret == 0)
			goto err;
		else if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				break;
err:
			stream_closed(fd, r);
			break;
		}

		if (stream_packet(r, buf, ret, &sin)) {
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

	st = g_slice_alloc0(sizeof(*st));

	st->family = AF_INET;
	st->ipv4 = inet_addr(a[0]);
	st->port = atoi(a[1]);
	st->mediatype = strdup(a[2] ? : "");

	if (st->ipv4 == -1)
		goto fail;
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
	return pcre_multi_match(&streams_re, &streams_ree, "^([\\d.]+):(\\d+)(?::(.*?))?(?:$|,)", s, 3, streams_parse_func, NULL);
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
	int i;
	struct peer *p;
	struct poller *po;
	struct callmaster *cm;
	unsigned int check;

	if (!c->callstreams->head)
		goto drop;

	cm = c->callmaster;
	po = cm->poller;

	for (it = c->callstreams->head; it; it = it->next) {
		cs = it->data;

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];

			hlp->ports[p->rtps[0].localport] = &p->rtps[0];
			hlp->ports[p->rtps[1].localport] = &p->rtps[1];

			check = cm->timeout;
			if (!p->rtps[0].peer.port)
				check = cm->silent_timeout;
			else if (p->rtps[0].peer.family == AF_INET && !p->rtps[0].peer.ipv4)
				check = cm->silent_timeout;
			else if (p->rtps[0].peer.family == AF_INET6 && !memcmp(p->rtps[0].peer.ipv6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16))
				check = cm->silent_timeout;

			if (po->now - p->rtps[0].last < check)
				goto good;
		}
	}

	mylog(LOG_INFO, "[%s] Closing call due to timeout", c->callid);

drop:
	hlp->del = g_list_prepend(hlp->del, c);
	return;

good:
	;
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

	i = kernel_list(m->kernelid);
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

		memcpy(&sr->kstats, &ke->stats, sizeof(sr->kstats));

next:
		g_slice_free1(sizeof(*ke), ke);
		i = g_list_delete_link(i, i);
	}

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

	NONBLOCK(fd);
	REUSEADDR(fd);
	setsockopt(fd, IPPROTO_IP, IP_TOS, &r->up->up->call->callmaster->tos, sizeof(r->up->up->call->callmaster->tos));

	ZERO(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(p);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	r->fd = fd;

	return 0;

fail:
	close(fd);
	return -1;
}

static int get_port6(struct streamrelay *r, u_int16_t p) {
	int fd;
	struct sockaddr_in6 sin;
	int i;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	NONBLOCK(fd);
	REUSEADDR(fd);
	setsockopt(fd, IPPROTO_IP, IP_TOS, &r->up->up->call->callmaster->tos, sizeof(r->up->up->call->callmaster->tos));
	i = 1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &i, sizeof(i));

	ZERO(sin);
	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(p);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	r->fd = fd;

	return 0;

fail:
	close(fd);
	return -1;
}

static int get_port(struct streamrelay *r, u_int16_t p, int family) {
	int ret;

	if (BIT_ARRAY_ISSET(ports_used, p))
		return -1;

	switch (family) {
		case AF_INET:
			ret = get_port4(r, p);
			break;
		case AF_INET6:
			ret = get_port6(r, p);
			break;
		default:
			/* panic XXX */
			return -1;
	}

	if (ret)
		return ret;

	r->localport = p;
	r->peer.family = family;
	r->peer_advertised.family = family;

	return 0;
}


static void get_port_pair(struct peer *p, int wanted_port, int family) {
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
		if (get_port(a, wanted_port, family))
			goto fail;
		if (get_port(b, wanted_port + 1, family))
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

		if (get_port(a, port, family))
			goto next;

		port++;
		if (get_port(b, port, family))
			goto tryagain;

		break;

tryagain:
		close(a->fd);
next:
		port++;
	}

	m->lastport = port;
	mylog(LOG_DEBUG, "[%s] Opened ports %u/%u for RTP", c->callid, a->localport, b->localport);

reserve:
	BIT_ARRAY_SET(ports_used, a->localport);
	BIT_ARRAY_SET(ports_used, b->localport);

	return;

fail:
	mylog(LOG_ERR, "[%s] Failed to get RTP port pair", c->callid);
	if (a->fd != -1)
		close(a->fd);
	if (b->fd != -1)
		close(b->fd);
	a->fd = b->fd = -1;
}



static int setup_peer(struct peer *p, struct stream *s, const char *tag) {
	struct streamrelay *a, *b;
	struct callstream *cs;

	cs = p->up;
	a = &p->rtps[0];
	b = &p->rtps[1];

	if (a->peer_advertised.port != s->port
			|| (s->family == AF_INET && a->peer_advertised.ipv4 != s->ipv4)
			|| (s->family == AF_INET6 && memcmp(a->peer_advertised.ipv6, s->ipv6, 16))) {
		cs->peers[0].confirmed = 0;
		unkernelize(&cs->peers[0]);
		cs->peers[1].confirmed = 0;
		unkernelize(&cs->peers[1]);
	}

	memcpy(a->peer.all, s->all, sizeof(a->peer.all));
	memcpy(b->peer.all, s->all, sizeof(b->peer.all));
	a->peer.port = b->peer.port = s->port;
	if (b->peer.port)
		b->peer.port++;
	a->peer_advertised = a->peer;
	b->peer_advertised = b->peer;

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

	mylog(LOG_DEBUG, "[%s] Re-using existing open RTP port %u", c->callid, r->localport);

	dest->confirmed = 0;
	unkernelize(dest);
	src->confirmed = 0;
	unkernelize(src);

	dest->filled = 1;
	strmove(&dest->mediatype, &src->mediatype);
	strmove(&dest->tag, &src->tag);
	//dest->kernelized = src->kernelized;
	//src->kernelized = 0;

	for (i = 0; i < 2; i++) {
		sr = &dest->rtps[i];
		srs = &src->rtps[i];

		if (sr->fd != -1) {
			mylog(LOG_DEBUG, "[%s] Closing port %u in favor of re-use", c->callid, sr->localport);
			close(sr->fd);
			BIT_ARRAY_CLEAR(ports_used, sr->localport);
			poller_del_item(po, sr->fd);
		}

		sr->fd = srs->fd;

		sr->peer.family = srs->peer.family;
		memcpy(sr->peer.all, srs->peer.all, sizeof(sr->peer.all));
		sr->peer.port = srs->peer.port;
		sr->peer_advertised.family = srs->peer_advertised.family;
		memcpy(sr->peer_advertised.all, srs->peer_advertised.all, sizeof(sr->peer_advertised.all));
		sr->peer_advertised.port = srs->peer_advertised.port;

		sr->localport = srs->localport;


		srs->fd = -1;
		srs->peer.family = 0;
		ZERO(srs->peer.all);
		srs->peer.port = 0;
		srs->localport = 0;
		srs->peer_advertised.family = 0;
		ZERO(srs->peer_advertised.all);
		srs->peer_advertised.port = 0;

		pi.fd = sr->fd;
		pi.ptr = sr;
		pi.readable = stream_readable;
		pi.closed = stream_closed;

		poller_update_item(po, &pi);
	}
}


static void callstream_init(struct callstream *s, struct call *ca, int port1, int port2, int family) {
	int i, j, tport;
	struct peer *p;
	struct streamrelay *r;
	struct poller_item pi;
	struct poller *po;

	po = ca->callmaster->poller;

	ZERO(*s);
	ZERO(pi);

	s->call = ca;

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
			get_port_pair(p, tport, family);

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
				DBG("comparing new %i:"IPF6":%u/%s to old %i:"IPF6":%u/%s",
					IPP(t->ipv6), t->port, tag,
					IPP(r->peer_advertised.ipv6), r->peer_advertised.port, cs_o->peers[x].tag);
				if (r->peer_advertised.family != t->family)
					continue;
				switch (t->family) {
					case AF_INET:
						if (r->peer_advertised.ipv4 != t->ipv4)
							continue;
						break;
					case AF_INET6:
						if (memcmp(r->peer_advertised.ipv6, t->ipv6, 16))
							continue;
						break;
					default:
						/* XXX panic */
						;
				}
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
				callstream_init(cs, c, 0, 0, t->family);
				p = &cs->peers[0];
				setup_peer(p, t, tag);
			}
			else {
				/* re-use, so don't open new ports */
				callstream_init(cs, c, -1, -1, t->family);
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
		l = c->callstreams->head;
		if (!l) {
			mylog(LOG_WARNING, "[%s] Got LOOKUP, but no callstreams found", c->callid);
			break;
		}
		cs = l->data;
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
			callstream_init(cs, c, 0, 0, t->family);
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
				close(r->fd);
				BIT_ARRAY_CLEAR(ports_used, r->localport);
			}
			poller_del_item(s->call->callmaster->poller, r->fd);
		}
	}

	g_slice_free1(sizeof(*s), s);
}



static void call_destroy(struct call *c) {
	struct callmaster *m = c->callmaster;
	struct callstream *s;

	g_hash_table_remove(m->callhash, c->callid);
#ifndef NO_REDIS
	redis_delete(c);
#endif

	free(c->callid);
	g_hash_table_destroy(c->infohash);
	if (c->calling_agent)
		free(c->calling_agent);
	if (c->called_agent)
		free(c->called_agent);

	while (c->callstreams->head) {
		s = g_queue_pop_head(c->callstreams);
		kill_callstream(s);
	}
	g_queue_free(c->callstreams);

	g_slice_free1(sizeof(*c), c);
}



static char *streams_print(GQueue *s, unsigned int num, unsigned int off, const char *prefix, int swap) {
	GString *o;
	int i;
	GList *l;
	struct callstream *t;
	struct streamrelay *x;
	char ips[64];

	o = g_string_new("");
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	if (!s->head)
		goto out;

	t = s->head->data;

	switch (t->peers[off].rtps[0].peer.family) {
		case AF_INET:
			if (!t->peers[off].rtps[0].peer.ipv4)
				strcpy(ips, "0.0.0.0");
			else if (t->call->callmaster->adv_ipv4)
				sprintf(ips, IPF, IPP(t->call->callmaster->adv_ipv4));
			else
				sprintf(ips, IPF, IPP(t->peers[off].rtps[0].peer.ipv4));
			break;

		case AF_INET6:
			if (!memcmp(t->peers[off].rtps[0].peer.ipv6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16))
				strcpy(ips, "::");
			else if (!memcmp(t->call->callmaster->adv_ipv6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16))
				inet_ntop(AF_INET6, t->call->callmaster->adv_ipv6, ips, sizeof(ips));
			else
				inet_ntop(AF_INET6, t->peers[off].rtps[0].peer.ipv6, ips, sizeof(ips));
			break;
		default:
			/* XXX panic */
			;
	}

	t = s->head->data;

	if (!swap)
		g_string_append(o, ips);

	for (i = 0, l = s->head; i < num && l; i++, l = l->next) {
		t = l->data;
		x = &t->peers[off].rtps[0];
		g_string_append_printf(o, swap ? "%u " : " %u", x->localport);
	}

	if (swap)
		g_string_append(o, ips);

out:
	g_string_append(o, "\n");

	return g_string_free(o, FALSE);
}



static struct call *call_get_or_create(const char *callid, struct callmaster *m) {
	struct call *c;

	c = g_hash_table_lookup(m->callhash, callid);
	if (!c) {
		mylog(LOG_NOTICE, "[%s] Creating new call", callid);	/* XXX will spam syslog on recovery from DB */
		c = g_slice_alloc0(sizeof(*c));
		c->callmaster = m;
		c->callid = strdup(callid);
		c->callstreams = g_queue_new();
		c->created = m->poller->now;
		c->infohash = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
		g_hash_table_insert(m->callhash, c->callid, c);
	}

	return c;
}

static int addr_parse_udp(struct stream *st, const char **o) {
	ZERO(st);
	if (o[5] && *o[5]) {
		st->family = AF_INET;
		st->ipv4 = inet_addr(o[5]);
		if (st->ipv4 == -1)
			goto fail;
	}
	else if (o[6] && *o[6]) {
		st->family = AF_INET6;
		if (inet_pton(AF_INET6, o[6], st->ipv6) != 1)
			goto fail;
	}
	else
		goto fail;

	st->port = atoi(o[7]);
	st->mediatype = "unknown";
	if (!st->port && strcmp(o[7], "0"))
		goto fail;

	return 0;
fail:
	return -1;
}

char *call_update_udp(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;
	char *ret;

	c = call_get_or_create(o[4], m);
	strdupfree(&c->calling_agent, "UNKNOWN(udp)");

	if (addr_parse_udp(&st, o))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, o[8], 0);

	g_queue_clear(&q);

#ifndef NO_REDIS
	redis_update(c);
#endif

	ret = streams_print(c->callstreams, 1, (num >= 0) ? 0 : 1, o[1], 1);
	mylog(LOG_INFO, "[%s] Returning to SIP proxy: %s", c->callid, ret);
	return ret;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", o[5], o[6], o[7]);
	asprintf(&ret, "%s E8\n", o[1]);
	return ret;
}

char *call_lookup_udp(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;
	char *ret;

	c = g_hash_table_lookup(m->callhash, o[4]);
	if (!c) {
		mylog(LOG_WARNING, "[%s] Got UDP LOOKUP for unknown call-id", o[4]);
		asprintf(&ret, "%s 0 " IPF "\n", o[1], IPP(m->ipv4));
		return ret;
	}

	strdupfree(&c->called_agent, "UNKNOWN(udp)");

	if (addr_parse_udp(&st, o))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, o[9], 1);

	g_queue_clear(&q);

#ifndef NO_REDIS
	redis_update(c);
#endif

	ret = streams_print(c->callstreams, 1, (num >= 0) ? 1 : 0, o[1], 1);
	mylog(LOG_INFO, "[%s] Returning to SIP proxy: %s", c->callid, ret);
	return ret;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", o[5], o[6], o[7]);
	asprintf(&ret, "%s E8\n", o[1]);
	return ret;
}

char *call_request(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	int num;
	char *ret;

	c = call_get_or_create(o[2], m);

	strdupfree(&c->calling_agent, o[9] ? : "UNKNOWN");
	info_parse(o[10], &c->infohash);
	s = streams_parse(o[3]);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "fromtag"), 0);
	streams_free(s);

#ifndef NO_REDIS
	redis_update(c);
#endif

	ret = streams_print(c->callstreams, abs(num), (num >= 0) ? 0 : 1, NULL, 0);
	mylog(LOG_INFO, "[%s] Returning to SIP proxy: %s", c->callid, ret);
	return ret;
}

char *call_lookup(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	int num;
	char *ret;

	c = g_hash_table_lookup(m->callhash, o[2]);
	if (!c) {
		mylog(LOG_WARNING, "[%s] Got LOOKUP for unknown call-id", o[2]);
		return NULL;
	}

	strdupfree(&c->called_agent, o[9] ? : "UNKNOWN");
	info_parse(o[10], &c->infohash);
	s = streams_parse(o[3]);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "totag"), 1);
	streams_free(s);

#ifndef NO_REDIS
	redis_update(c);
#endif

	ret = streams_print(c->callstreams, abs(num), (num >= 0) ? 1 : 0, NULL, 0);
	mylog(LOG_INFO, "[%s] Returning to SIP proxy: %s", c->callid, ret);
	return ret;
}

char *call_delete_udp(const char **o, struct callmaster *m) {
	struct call *c;
	char *ret;

	c = g_hash_table_lookup(m->callhash, o[11]);
	if (!c)
		goto err;

	call_destroy(c);

	asprintf(&ret, "%s 0\n", o[1]);
	goto out;

err:
	asprintf(&ret, "%s E8\n", o[1]);
	goto out;

out:
	return ret;
}

void call_delete(const char **o, struct callmaster *m) {
	struct call *c;

	c = g_hash_table_lookup(m->callhash, o[12]);
	if (!c)
		return;

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

	m = c->callmaster;

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

		streambuf_printf(s->outbuf, "stream ");
		switch (r1->peer.family) {
			case AF_INET:
				streambuf_printf(s->outbuf, IPF, IPP(r1->peer.ipv4));
				break;
			case AF_INET6:
				streambuf_printf(s->outbuf, IP6F, IP6P(r1->peer.ipv6));
				break;
			default:
				/* XXX Panic */
				;
		}
		streambuf_printf(s->outbuf, ":%u ", r1->peer.port);
		switch (r2->peer.family) {
			case AF_INET:
				streambuf_printf(s->outbuf, IPF, IPP(r2->peer.ipv4));
				break;
			case AF_INET6:
				streambuf_printf(s->outbuf, IP6F, IP6P(r2->peer.ipv6));
				break;
			default:
				/* XXX Panic */
				;
		}
		streambuf_printf(s->outbuf, ":%u ", r2->peer.port);
		switch (r1->peer.family) {
			case AF_INET:
				streambuf_printf(s->outbuf, IPF, IPP(m->ipv4));
				break;
			case AF_INET6:
				streambuf_printf(s->outbuf, IP6F, IP6P(m->ipv6));
				break;
			default:
				/* XXX Panic */
				;
		}
		streambuf_printf(s->outbuf, ":%u %llu/%llu/%llu %s %s %s %i\n",
			r1->localport,
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




#ifndef NO_REDIS
void call_restore(struct callmaster *m, char *uuid, redisReply **hash, GList *streams) {
	struct call *c;
	struct callstream *cs;
	redisReply *rps[2], *rp;
	int i, kernel;
	struct peer *p;

	c = call_get_or_create(hash[0]->str, m);
	strcpy(c->redis_uuid, uuid);
	c->created = strtoll(hash[1]->str, NULL, 10);
	strdupfree(&c->calling_agent, "UNKNOWN(recovered)");
	strdupfree(&c->called_agent, "UNKNOWN(recovered)");

	for (; streams; streams = streams->next) {
		rps[0] = streams->data;
		streams = streams->next;
		rps[1] = streams->data;

		cs = g_slice_alloc(sizeof(*cs));
		callstream_init(cs, c, atoi(rps[0]->element[2]->str), atoi(rps[1]->element[2]->str));
		kernel = 0;

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];
			rp = rps[i];

			p->rtps[1].peer.ip = p->rtps[0].peer.ip = inet_addr(rp->element[0]->str);
			p->rtps[0].peer.port = atoi(rp->element[1]->str);
			p->rtps[1].peer.port = p->rtps[0].peer.port + 1;
			strdupfree(&p->tag, rp->element[6]->str);
			kernel = atoi(rp->element[3]->str);
			p->filled = atoi(rp->element[4]->str);
			p->confirmed = atoi(rp->element[5]->str);
		}

		g_queue_push_tail(c->callstreams, cs);

		if (kernel)
			kernelize(cs);
	}
}





static void calls_dump_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;

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
#endif
