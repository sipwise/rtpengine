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
#include <hiredis.h>
#include <stdlib.h>

#include "call.h"
#include "poller.h"
#include "aux.h"
#include "log.h"
#include "kernel.h"
#include "control.h"
#include "streambuf.h"
#include "redis.h"



#if 0
#define DBG(x...) mylog(LOG_DEBUG, x)
#else
#define DBG(x...) ((void)0)
#endif



static pcre		*info_re;
static pcre_extra	*info_ree;
static pcre		*streams_re;
static pcre_extra	*streams_ree;

static BIT_ARRAY_DECLARE(ports_used, 0x1000);




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

			if (!r->peer.ip || !r->peer.port)
				continue;

			ZERO(r->kstats);

			ks.local_port = r->localport;
			ks.src.ip = c->call->callmaster->ip;
			ks.src.port = rp->localport;
			ks.dest.ip = r->peer.ip;
			ks.dest.port = r->peer.port;
			ks.tos = c->call->callmaster->tos;

			kernel_add_stream(c->call->callmaster->kernelfd, &ks, 0);
		}

		p->kernelized = 1;
	}
}




static int stream_packet(struct streamrelay *r, char *b, int l, struct sockaddr_in *fsin) {
	struct streamrelay *p, *p2;
	struct peer *pe, *pe2;
	struct callstream *cs;
	int ret;
	struct sockaddr_in sin;
	struct msghdr mh;
	struct iovec iov;
	unsigned char buf[256];
	struct cmsghdr *ch;
	struct in_pktinfo *pi;
	struct call *c;
	struct callmaster *m;
	unsigned char cc;

	pe = r->up;
	cs = pe->up;
	pe2 = &cs->peers[pe->idx ^ 1];
	p = &pe2->rtps[r->idx];
	c = cs->call;
	m = c->callmaster;

	if (p->fd == -1) {
		mylog(LOG_WARNING, "[%s] RTP packet discarded from " DF, c->callid, DP(*fsin));
		r->stats.errors++;
		m->statsps.errors++;
		return 0;
	}

	if (!pe->confirmed && pe->filled && r->idx == 0) {
		if (l < 2)
			goto skip;

		if (!pe->codec) {
			cc = b[1];
			cc &= 0x7f;
			if (cc < G_N_ELEMENTS(rtp_codecs))
				pe->codec = rtp_codecs[cc] ? : "unknown";
			else
				pe->codec = "unknown";
		}

		mylog(LOG_DEBUG, "[%s] Confirmed peer information - " DF, c->callid, DP(*fsin));

		p->peer.ip = fsin->sin_addr.s_addr;
		p->peer.port = ntohs(fsin->sin_port);

		p2 = &p->up->rtps[p->idx ^ 1];
		p2->peer.ip = fsin->sin_addr.s_addr;
		p2->peer.port = p->peer.port + ((int) (p2->idx * 2) - 1);

		pe->confirmed = 1;


		if (pe2->confirmed && pe2->filled)
			kernelize(cs);

		redis_update(c);
	}

skip:
	if (!r->peer.ip || !r->peer.port)
		goto drop;

	ZERO(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = r->peer.ip;
	sin.sin_port = htons(r->peer.port);

	ZERO(iov);
	iov.iov_base = b;
	iov.iov_len = l;

	ZERO(mh);
	mh.msg_name = &sin;
	mh.msg_namelen = sizeof(sin);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = buf;
	mh.msg_controllen = sizeof(buf);

	ch = CMSG_FIRSTHDR(&mh);
	ZERO(*ch);
	ch->cmsg_len = CMSG_LEN(sizeof(*pi));
	ch->cmsg_level = IPPROTO_IP;
	ch->cmsg_type = IP_PKTINFO;

	pi = (void *) CMSG_DATA(ch);
	ZERO(*pi);
	pi->ipi_spec_dst.s_addr = m->ip;

	mh.msg_controllen = CMSG_SPACE(sizeof(*pi));

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
	struct sockaddr_in sin;
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

	st->ip = inet_addr(a[0]);
	st->port = atoi(a[1]);
	st->mediatype = strdup(a[2] ? : "");

	if (st->ip == -1)
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
			if (!p->rtps[0].peer.ip || !p->rtps[0].peer.port)
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
	GList *i;
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

	for (i = hlp.del; i; i = i->next) {
		c = i->data;
		call_destroy(c);
	}

	g_list_free(i);
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



static int get_port(struct streamrelay *r, u_int16_t p) {
	int fd;
	struct sockaddr_in sin;

	if (BIT_ARRAY_ISSET(ports_used, p))
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	NONBLOCK(fd);
	REUSEADDR(fd);
	setsockopt(fd, SOL_IP, IP_TOS, &r->up->up->call->callmaster->tos, sizeof(r->up->up->call->callmaster->tos));

	ZERO(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(p);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	r->fd = fd;
	r->localport = p;

	return 0;

fail:
	close(fd);
	return -1;
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

	if (a->peer.ip != s->ip || a->peer.port != b->peer.port) {
		cs->peers[0].confirmed = 0;
		unkernelize(&cs->peers[0]);
		cs->peers[1].confirmed = 0;
		unkernelize(&cs->peers[1]);
	}

	a->peer.ip = b->peer.ip = s->ip;
	a->peer.port = b->peer.port = s->port;
	if (b->peer.port)
		b->peer.port++;

	strdupfree(&p->mediatype, s->mediatype);
	strdupfree(&p->tag, tag);
	p->filled = 1;

	return 0;
}

static void steal_peer(struct peer *p, struct streamrelay *r) {
	struct peer *s = r->up;
	int i;
	struct poller_item pi;
	struct streamrelay *sr, *srs;
	struct call *c;
	struct poller *po;

	ZERO(pi);
	c = s->up->call;
	po = c->callmaster->poller;

	mylog(LOG_DEBUG, "[%s] Re-using existing open RTP ports", c->callid);

	p->confirmed = 0;
	unkernelize(p);
	s->confirmed = 0;
	unkernelize(s);

	p->filled = 1;
	strmove(&p->mediatype, &s->mediatype);
	strmove(&p->tag, &s->tag);
	//p->kernelized = s->kernelized;
	//s->kernelized = 0;

	for (i = 0; i < 2; i++) {
		sr = &p->rtps[i];
		srs = &s->rtps[i];

		if (sr->fd != -1) {
			close(sr->fd);
			BIT_ARRAY_CLEAR(ports_used, sr->localport);
			poller_del_item(po, sr->fd);
		}

		sr->fd = srs->fd;

		sr->peer.ip = srs->peer.ip;
		sr->peer.port = srs->peer.port;

		sr->localport = srs->localport;


		srs->fd = -1;
		srs->peer.ip = 0;
		srs->peer.port = 0;
		srs->localport = 0;

		pi.fd = sr->fd;
		pi.ptr = sr;
		pi.readable = stream_readable;
		pi.closed = stream_closed;

		poller_update_item(po, &pi);
	}
}


static void callstream_init(struct callstream *s, struct call *ca, int port1, int port2) {
	int i, j;
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

		get_port_pair(p, (i == 0) ? port1 : port2);

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



static unsigned int call_streams(struct call *c, GQueue *s, const char *tag, int opmode) {
	GQueue *q;
	GList *i, *l;
	struct stream *t;
	int x;
	struct streamrelay *r;
	struct callstream *cs;
	struct peer *p;
	unsigned int ret;

	q = g_queue_new();	/* new callstreams list */

	if (!tag)
		tag = "";

	for (i = s->head; i; i = i->next) {
		t = i->data;

		p = NULL;

		if (!opmode) {
			DBG("creating new callstream");
			cs = g_slice_alloc(sizeof(*cs));
			callstream_init(cs, c, 0, 0);
			p = &cs->peers[0];
		}
		else {
			l = c->callstreams->head;
			if (!l) {
				mylog(LOG_WARNING, "[%s] Got LOOKUP, but no callstreams found", c->callid);
				break;
			}
			cs = l->data;
			g_queue_delete_link(c->callstreams, l);
			p = &cs->peers[1];
		}


		for (l = c->callstreams->head; l; l = l->next) {
			cs = l->data;
			for (x = 0; x < 2; x++) {
				r = &cs->peers[x].rtps[0];
				if (r->peer.ip != t->ip)
					continue;
				if (r->peer.port != t->port)
					continue;
				if (strcmp(cs->peers[x].tag, tag))
					continue;
				DBG("found existing call stream to steal");
				goto found;
			}
		}

		/* not found */
		setup_peer(p, t, tag);
		g_queue_push_tail(q, p->up);
		continue;

found:
		steal_peer(p, r);
		g_queue_push_tail(q, p->up);
	}

	ret = q->length;

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
	redis_delete(c);

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
	u_int32_t ip;

	o = g_string_new("");
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	if (!s->head)
		goto out;

	t = s->head->data;
	ip = t->call->callmaster->ip;
	if (t->call->callmaster->adv_ip)
		ip = t->call->callmaster->adv_ip;
	if (!swap)
		g_string_append_printf(o, IPF, IPP(ip));

	for (i = 0, l = s->head; i < num && l; i++, l = l->next) {
		t = l->data;
		x = &t->peers[off].rtps[0];
		g_string_append_printf(o, swap ? "%u " : " %u", x->localport);
	}

	if (swap)
		g_string_append_printf(o, IPF, IPP(ip));

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

char *call_update_udp(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;

	c = call_get_or_create(o[4], m);
	strdupfree(&c->calling_agent, "UNKNOWN(udp)");

	ZERO(st);
	st.ip = inet_addr(o[5]);
	st.port = atoi(o[6]);
	st.mediatype = "unknown";
	if (st.ip == -1)
		goto fail;
	if (!st.port && strcmp(o[6], "0"))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, o[7], 0);

	g_queue_clear(&q);

	redis_update(c);

	return streams_print(c->callstreams, 1, 0, o[1], 1);

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s:%s", o[5], o[6]);
	return NULL;
}

char *call_lookup_udp(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream st;
	int num;

	c = g_hash_table_lookup(m->callhash, o[4]);
	if (!c) {
		mylog(LOG_WARNING, "[%s] Got UDP LOOKUP for unknown call-id", o[4]);
		return NULL;
	}

	strdupfree(&c->called_agent, "UNKNOWN(udp)");

	ZERO(st);
	st.ip = inet_addr(o[5]);
	st.port = atoi(o[6]);
	st.mediatype = "unknown";
	if (st.ip == -1)
		goto fail;
	if (!st.port && strcmp(o[6], "0"))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, o[8], 1);

	g_queue_clear(&q);

	redis_update(c);

	return streams_print(c->callstreams, 1, 1, o[1], 1);

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s:%s", o[5], o[6]);
	return NULL;
}

char *call_request(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	unsigned int num;

	c = call_get_or_create(o[2], m);

	strdupfree(&c->calling_agent, o[9] ? : "UNKNOWN");
	info_parse(o[10], &c->infohash);
	s = streams_parse(o[3]);
	num = call_streams(c, s, g_hash_table_lookup(c->infohash, "fromtag"), 0);
	streams_free(s);

	redis_update(c);

	return streams_print(c->callstreams, num, 0, NULL, 0);
}

char *call_lookup(const char **o, struct callmaster *m) {
	struct call *c;
	GQueue *s;
	unsigned int num;

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

	redis_update(c);

	return streams_print(c->callstreams, num, 1, NULL, 0);
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

		streambuf_printf(s->outbuf, "stream " IPF ":%u " IPF ":%u " IPF ":%u %llu/%llu/%llu %s %s %s %i\n",
			IPP(r1->peer.ip), r1->peer.port,
			IPP(r2->peer.ip), r2->peer.port,
			IPP(m->ip), r1->localport,
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

		if (kernel)
			kernelize(cs);
	}
}
