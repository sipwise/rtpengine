#include "call.h"

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

#include "poller.h"
#include "aux.h"
#include "log.h"
#include "kernel.h"
#include "control_tcp.h"
#include "streambuf.h"
#include "redis.h"
#include "xt_MEDIAPROXY.h"
#include "bencode.h"
#include "sdp.h"
#include "str.h"
#include "stun.h"
#include "rtcp.h"



#ifdef __DEBUG
#define DBG(x...) mylog(LOG_DEBUG, x)
#else
#define DBG(x...) ((void)0)
#endif

#define LOG_PREFIX_C "[%.*s] "
#define LOG_PREFIX_CI "[%.*s - %.*s] "
#define LOG_PARAMS_C(c) STR_FMT(&(c)->callid)
#define LOG_PARAMS_CI(c) STR_FMT(&(c)->callid), STR_FMT0(log_info)

static __thread const str *log_info;




/* also serves as array index for callstream->peers[] */
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

struct call_stats {
	time_t		newest;
	struct stats	totals[4]; /* rtp in, rtcp in, rtp out, rtcp out */
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
const char *transport_protocol_strings[__PROTO_RTP_LAST] = {
	[PROTO_RTP_AVP]		= "RTP/AVP",
	[PROTO_RTP_SAVP]	= "RTP/SAVP",
	[PROTO_RTP_AVPF]	= "RTP/AVPF",
	[PROTO_RTP_SAVPF]	= "RTP/SAVPF",
};






static void call_destroy(struct call *);
static void unkernelize(struct peer *);
static void relays_cache_port_used(struct relays_cache *c);
static void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output);




static void stream_closed(int fd, void *p, uintptr_t u) {
	struct callstream *cs = p;
	struct streamrelay *r;
	struct call *c;
	int i;
	socklen_t j;

	mutex_lock(&cs->lock);
	r = &cs->peers[u >> 1].rtps[u & 1];
	assert(r->fd.fd == fd);
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
					|| !r->fd.fd_family || !r->peer_advertised.port)
				continue;

			ks.local_port = r->fd.localport;
			ks.tos = cm->conf.tos;
			ks.src.port = rp->fd.localport;
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




int __dummy_stream_handler(str *s) {
	abort();
	return 0;
}

static stream_handler determine_handler(struct streamrelay *in) {
	if (in->peer.protocol == in->peer_advertised.protocol)
		goto dummy;
	if (in->peer.protocol == PROTO_UNKNOWN)
		goto dummy;
	if (in->peer_advertised.protocol == PROTO_UNKNOWN)
		goto dummy;

	if (in->peer.protocol == PROTO_RTP_AVPF && in->peer_advertised.protocol == PROTO_RTP_AVP) {
		if (!in->rtcp)
			goto dummy;
		return rtcp_avpf2avp;
	}
	if (in->peer.protocol == PROTO_RTP_AVP && in->peer_advertised.protocol == PROTO_RTP_AVPF)
		goto dummy;

	/* XXX warn? */

dummy:
	return __dummy_stream_handler;
}

/* called with r->up (== cs) locked */
static int stream_packet(struct streamrelay *sr_incoming, str *s, struct sockaddr_in6 *fsin) {
	struct streamrelay *sr_outgoing, *sr_out_rtcp;
	struct peer *p_incoming, *p_outgoing;
	struct callstream *cs_incoming;
	int ret, update = 0, stun_ret = 0, handler_ret = 0;
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

	p_incoming = sr_incoming->up;
	cs_incoming = p_incoming->up;
	p_outgoing = p_incoming->other;
	sr_outgoing = sr_incoming->other;
	c = cs_incoming->call;
	m = c->callmaster;
	smart_ntop_port(addr, fsin, sizeof(addr));

	if (sr_incoming->stun && is_stun(s)) {
		stun_ret = stun(s, sr_incoming, fsin);
		if (!stun_ret)
			return 0;
		if (stun_ret == 1) /* use candidate */
			goto use_cand;
		else /* not an stun packet */
			stun_ret = 0;
	}

	if (sr_outgoing->fd.fd == -1) {
		mylog(LOG_WARNING, LOG_PREFIX_C "RTP packet to port %u discarded from %s", 
			LOG_PARAMS_C(c), sr_incoming->fd.localport, addr);
		sr_incoming->stats.errors++;
		mutex_lock(&m->statspslock);
		m->statsps.errors++;
		mutex_unlock(&m->statspslock);
		return 0;
	}

	if (!sr_incoming->handler)
		sr_incoming->handler = determine_handler(sr_incoming);
	if (sr_incoming->handler != __dummy_stream_handler)
		handler_ret = sr_incoming->handler(s);

use_cand:
	if (p_incoming->confirmed || !p_incoming->filled || sr_incoming->idx != 0)
		goto forward;

	if (!c->lookup_done || poller_now <= c->lookup_done + 3)
		goto peerinfo;

	mylog(LOG_DEBUG, LOG_PREFIX_C "Confirmed peer information for port %u - %s", 
		LOG_PARAMS_C(c), sr_incoming->fd.localport, addr);

	p_incoming->confirmed = 1;

peerinfo:
	if (!stun_ret && !p_incoming->codec && s->len >= 2) {
		cc = s->s[1];
		cc &= 0x7f;
		if (cc < G_N_ELEMENTS(rtp_codecs))
			p_incoming->codec = rtp_codecs[cc] ? : "unknown";
		else
			p_incoming->codec = "unknown";
	}

	sr_out_rtcp = &p_outgoing->rtps[1]; /* sr_incoming->idx == 0 */
	sr_outgoing->peer.ip46 = fsin->sin6_addr;
	sr_outgoing->peer.port = ntohs(fsin->sin6_port);
	sr_out_rtcp->peer.ip46 = sr_outgoing->peer.ip46;
	sr_out_rtcp->peer.port = sr_outgoing->peer.port + 1; /* sr_out_rtcp->idx == 1 */

	update = 1;

	if (sr_incoming->handler != __dummy_stream_handler)
		goto forward;

	if (p_incoming->confirmed && p_outgoing->confirmed && p_outgoing->filled)
		kernelize(cs_incoming);

forward:
	if (is_addr_unspecified(&sr_incoming->peer_advertised.ip46)
			|| !sr_incoming->peer_advertised.port || !sr_incoming->fd.fd_family
			|| stun_ret || handler_ret)
		goto drop;

	ZERO(mh);
	mh.msg_control = buf;
	mh.msg_controllen = sizeof(buf);

	ch = CMSG_FIRSTHDR(&mh);
	ZERO(*ch);

	switch (sr_incoming->fd.fd_family) {
		case AF_INET:
			ZERO(sin);
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = sr_incoming->peer.ip46.s6_addr32[3];
			sin.sin_port = htons(sr_incoming->peer.port);
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
			sin6.sin6_addr = sr_incoming->peer.ip46;
			sin6.sin6_port = htons(sr_incoming->peer.port);
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
	iov.iov_base = s->s;
	iov.iov_len = s->len;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	ret = sendmsg(sr_outgoing->fd.fd, &mh, 0);

	if (ret == -1) {
		sr_incoming->stats.errors++;
		mutex_lock(&m->statspslock);
		m->statsps.errors++;
		mutex_unlock(&m->statspslock);
		goto out;
	}

drop:
	ret = 0;
	sr_incoming->stats.packets++;
	sr_incoming->stats.bytes += s->len;
	sr_incoming->last = poller_now;
	mutex_lock(&m->statspslock);
	m->statsps.packets++;
	m->statsps.bytes += s->len;
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
	str s;

	mutex_lock(&cs->lock);
	r = &cs->peers[u >> 1].rtps[u & 1];
	if (r->fd.fd != fd)
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

		if (ss.ss_family != r->fd.fd_family)
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

		s.s = buf;
		s.len = ret;
		ret = stream_packet(r, &s, sinp);
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
	GHashTable *ih = p;

	g_hash_table_replace(ih, a[0], a[1]);

	return -1;
}


static void info_parse(const char *s, GHashTable *ih, struct callmaster *m) {
	pcre_multi_match(m->info_re, m->info_ree, s, 2, info_parse_func, ih, NULL);
}


static int streams_parse_func(char **a, void **ret, void *p) {
	struct stream_input *st;
	u_int32_t ip;
	int *i;

	i = p;
	st = g_slice_alloc0(sizeof(*st));

	ip = inet_addr(a[0]);
	if (ip == -1)
		goto fail;

	in4_to_6(&st->stream.ip46, ip);
	st->stream.port = atoi(a[1]);
	st->stream.num = ++(*i);
	st->consecutive_num = 1;

	if (!st->stream.port && strcmp(a[1], "0"))
		goto fail;

	*ret = st;
	return 0;

fail:
	mylog(LOG_WARNING, "Failed to parse a media stream: %s:%s", a[0], a[1]);
	g_slice_free1(sizeof(*st), st);
	return -1;
}


static void streams_parse(const char *s, struct callmaster *m, GQueue *q) {
	int i;
	i = 0;
	pcre_multi_match(m->streams_re, m->streams_ree, s, 3, streams_parse_func, &i, q);
}

static void streams_free(GQueue *q) {
	struct stream_input *s;

	while ((s = g_queue_pop_head(q)))
		g_slice_free1(sizeof(*s), s);
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
				if (!sr->fd.localport)
					continue;
				if (hlp->ports[sr->fd.localport])
					abort();
				hlp->ports[sr->fd.localport] = sr;
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
	str *tag;

	while (xh->tags) {
		tag = xh->tags->data;

		mylog(LOG_INFO, "Forking child to close call with tag %.*s via XMLRPC", STR_FMT(tag));
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
		alarm(1); /* syslog functions contain a lock, which may be locked at
			     this point and can't be unlocked */
		rlim(RLIMIT_CORE, 0);
		sigemptyset(&ss);
		sigprocmask(SIG_SETMASK, &ss, NULL);
		closelog();

		for (i = 0; i < 100; i++)
			close(i);

		openlog("mediaproxy-ng/child", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		mylog(LOG_INFO, "Initiating XMLRPC call for tag %.*s", STR_FMT(tag));

		alarm(5);

		xmlrpc_env_init(&e);
		xmlrpc_client_setup_global_const(&e);
		xmlrpc_client_create(&e, XMLRPC_CLIENT_NO_FLAGS, "ngcp-mediaproxy-ng", MEDIAPROXY_VERSION,
			NULL, 0, &c);
		if (e.fault_occurred)
			goto fault;

		r = NULL;
		xmlrpc_client_call2f(&e, c, xh->url, "di", &r, "(ssss)",
			"sbc", "postControlCmd", tag->s, "teardown");
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
			if (!cs->peers[1].tag.s || !cs->peers[1].tag.len)
				goto next;
			xh->tags = g_slist_prepend(xh->tags, str_chunk_insert(xh->c, &cs->peers[1].tag));
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

	c->callhash = g_hash_table_new(str_hash, str_equal);
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



static int get_port4(struct udp_fd *r, u_int16_t p, struct callmaster *m) {
	int fd;
	struct sockaddr_in sin;

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

static int get_port6(struct udp_fd *r, u_int16_t p, struct callmaster *m) {
	int fd;
	struct sockaddr_in6 sin;
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

static int get_port(struct udp_fd *r, u_int16_t p, struct callmaster *m) {
	int ret;

	assert(r->fd == -1);

	mutex_lock(&m->portlock);
	if (bit_array_isset(m->ports_used, p)) {
		mutex_unlock(&m->portlock);
		return -1;
	}
	bit_array_set(m->ports_used, p);
	mutex_unlock(&m->portlock);

	if (is_addr_unspecified(&m->conf.ipv6))
		ret = get_port4(r, p, m);
	else
		ret = get_port6(r, p, m);

	if (ret) {
		mutex_lock(&m->portlock);
		bit_array_clear(m->ports_used, p);
		mutex_unlock(&m->portlock);
		return ret;
	}

	r->localport = p;

	return 0;
}

static void release_port(struct udp_fd *r, struct callmaster *m) {
	if (r->fd == -1 || !r->localport)
		return;
	mutex_lock(&m->portlock);
	bit_array_clear(m->ports_used, r->localport);
	mutex_unlock(&m->portlock);
	close(r->fd);
	r->fd = -1;
	r->localport = 0;
}

static int get_consecutive_ports(struct udp_fd *array, int array_len, int wanted_start_port, struct call *c) {
	int i, j, cycle = 0;
	struct udp_fd *it;
	u_int16_t port;
	struct callmaster *m = c->callmaster;

	if (wanted_start_port > 0)
		port = wanted_start_port;
	else {
		mutex_lock(&m->portlock);
		port = m->lastport;
		mutex_unlock(&m->portlock);
	}

	while (1) {
		if (!wanted_start_port) {
			if (port < m->conf.port_min)
				port = m->conf.port_min;
			if ((port & 1))
				port++;
		}

		for (i = 0; i < array_len; i++) {
			it = &array[i];

			if (!wanted_start_port && port > m->conf.port_max) {
				port = 0;
				cycle++;
				goto release_restart;
			}

			if (get_port(it, port++, m))
				goto release_restart;
		}
		break;

release_restart:
		for (j = 0; j < i; j++)
			release_port(&array[j], m);

		if (cycle >= 2 || wanted_start_port > 0)
			goto fail;
	}

	/* success */
	mutex_lock(&m->portlock);
	m->lastport = port;
	mutex_unlock(&m->portlock);

	mylog(LOG_DEBUG, LOG_PREFIX_CI "Opened ports %u..%u for RTP", 
		LOG_PARAMS_CI(c), array[0].localport, array[array_len - 1].localport);
	return 0;

fail:
	mylog(LOG_ERR, LOG_PREFIX_CI "Failed to get RTP port pair", LOG_PARAMS_CI(c));
	return -1;
}

/* caller is responsible for appropriate locking */
static int setup_peer(struct peer *p, struct stream_input *s, const str *tag) {
	struct streamrelay *a, *b;
	struct callstream *cs;
	struct call *ca;
	int i;

	cs = p->up;
	ca = cs->call;
	a = &p->rtps[0];
	b = &p->rtps[1];

	if (a->peer_advertised.port != s->stream.port
			|| !IN6_ARE_ADDR_EQUAL(&a->peer_advertised.ip46, &s->stream.ip46)) {
		cs->peers[0].confirmed = 0;
		unkernelize(&cs->peers[0]);
		cs->peers[1].confirmed = 0;
		unkernelize(&cs->peers[1]);
	}

	a->peer.ip46 = s->stream.ip46;
	b->peer.ip46 = s->stream.ip46;
	a->peer.port = b->peer.port = s->stream.port;
	if (b->peer.port)
		b->peer.port++;
	a->peer.protocol = b->peer.protocol = s->stream.protocol;
	a->peer_advertised = a->peer;
	b->peer_advertised = b->peer;
	a->rtcp = s->is_rtcp;
	b->rtcp = 1;

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

	call_str_cpy(ca, &p->tag, tag);
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
		LOG_PARAMS_CI(c), r->fd.localport);

	dest->confirmed = 0;
	unkernelize(dest);
	src->confirmed = 0;
	unkernelize(src);

	dest->filled = 1;
	dest->tag = src->tag;
	src->tag = STR_NULL;
	dest->desired_family = src->desired_family;
	dest->ice_ufrag = src->ice_ufrag;
	dest->ice_pwd = src->ice_pwd;

	for (i = 0; i < 2; i++) {
		sr = &dest->rtps[i];
		srs = &src->rtps[i];

		if (sr->fd.fd != -1) {
			mylog(LOG_DEBUG, LOG_PREFIX_CI "Closing port %u in favor of re-use", 
				LOG_PARAMS_CI(c), sr->fd.localport);
			poller_del_item(po, sr->fd.fd);
			release_port(&sr->fd, m);
		}

		sr->fd = srs->fd;
		sr->peer = srs->peer;
		sr->peer_advertised = srs->peer_advertised;
		sr->stun = srs->stun;
		sr->rtcp = srs->rtcp;


		srs->fd.fd = -1;
		srs->fd.fd_family = 0;
		srs->fd.localport = 0;
		ZERO(srs->peer);
		ZERO(srs->peer_advertised);

		pi.fd = sr->fd.fd;
		pi.obj = &sr->up->up->obj;
		pi.uintp = i | (dest->idx << 1);
		pi.readable = stream_readable;
		pi.closed = stream_closed;

		poller_update_item(po, &pi);
	}
}


void callstream_init(struct callstream *s, struct relays_cache *rc) {
	int i, j;
	struct peer *p;
	struct streamrelay *r;
	struct udp_fd *relay_AB;
	struct poller_item pi;
	struct call *c = s->call;
	struct poller *po = c->callmaster->poller;

	ZERO(pi);

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];
		relay_AB = rc ? rc->array_ptrs[i] : NULL;

		p->idx = i;
		p->up = s;
		p->other = &s->peers[i ^ 1];
		p->tag = STR_NULL;

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];

			r->fd.fd = -1;
			r->idx = j;
			r->up = p;
			r->other = &p->other->rtps[j];
			r->last = poller_now;

			if (relay_AB && relay_AB[j].fd != -1) {
				r->fd = relay_AB[j];

				pi.fd = r->fd.fd;
				pi.obj = &s->obj;
				pi.uintp = (i << 1) | j;
				pi.readable = stream_readable;
				pi.closed = stream_closed;

				poller_add_item(po, &pi);

				relay_AB[j].fd = -1;
			}
		}
	}

	if (rc)
		relays_cache_port_used(rc);
}



static void callstream_free(void *ptr) {
	struct callstream *s = ptr;
	struct callmaster *m = s->call->callmaster;
	int i, j;       
	struct peer *p;
	struct streamrelay *r;

	for (i = 0; i < 2; i++) {
		p = &s->peers[i];

		for (j = 0; j < 2; j++) {
			r = &p->rtps[j];
			release_port(&r->fd, m);
		}
	}
	mutex_destroy(&s->lock);
	obj_put(s->call);
}

void relays_cache_init(struct relays_cache *c) {
	memset(c, -1, sizeof(*c));
	c->relays_open = 0;
	c->array_ptrs[0] = c->relays_A;
	c->array_ptrs[1] = c->relays_B;
}

int relays_cache_want_ports(struct relays_cache *c, int portA, int portB, struct call *call) {
	if (c->relays_open + 2 > ARRAYSIZE(c->relays_A))
		return -1;
	if (get_consecutive_ports(&c->relays_A[c->relays_open], 2, portA, call))
		return -1;
	if (get_consecutive_ports(&c->relays_B[c->relays_open], 2, portB, call))
		return -1;
	c->relays_open += 2;
	return 0;
}

static int relays_cache_get_ports(struct relays_cache *c, int num, struct call *call) {
	num *= 2;
	if (c->relays_open >= num)
		return 0;

	if (c->relays_open + num > ARRAYSIZE(c->relays_A))
		return -1;
	if (get_consecutive_ports(&c->relays_A[c->relays_open], num, 0, call))
		return -1;
	if (get_consecutive_ports(&c->relays_B[c->relays_open], num, 0, call))
		return -1;
	c->relays_open += num;
	return 0;
}

static void relays_cache_port_used(struct relays_cache *c) {
	if (c->relays_open < 2)
		return;

	c->relays_open -= 2;
	if (c->relays_open) {
		memmove(&c->relays_A[0], &c->relays_A[2], c->relays_open * sizeof(*c->relays_A));
		memmove(&c->relays_B[0], &c->relays_B[2], c->relays_open * sizeof(*c->relays_B));
	}
	c->relays_A[c->relays_open].fd = -1;
	c->relays_B[c->relays_open].fd = -1;
	c->relays_A[c->relays_open + 1].fd = -1;
	c->relays_B[c->relays_open + 1].fd = -1;
}

void relays_cache_cleanup(struct relays_cache *c, struct callmaster *m) {
	int i;

	for (i = 0; i < ARRAYSIZE(c->relays_A); i++) {
		if (c->relays_A[i].fd == -1)
			break;
		release_port(&c->relays_A[i], m);
	}
	for (i = 0; i < ARRAYSIZE(c->relays_B); i++) {
		if (c->relays_B[i].fd == -1)
			break;
		release_port(&c->relays_B[i], m);
	}
}

/* called with call->lock held */
static int call_streams(struct call *c, GQueue *s, const str *tag, enum call_opmode opmode) {
	GQueue *q;
	GList *i, *l;
	struct stream_input *t;
	int x;
	struct streamrelay *matched_relay;
	struct callstream *cs, *cs_o;
	struct peer *p, *p2;
	int ret = 1;
	struct relays_cache relays_cache;

	q = g_queue_new();	/* new callstreams list */
	relays_cache_init(&relays_cache);

	for (i = s->head; i; i = i->next) {
		t = i->data;

		p = NULL;

		/* look for an existing call stream with identical parameters */
		for (l = c->callstreams->head; l; l = l->next) {
			cs_o = l->data;
			mutex_lock(&cs_o->lock);
			for (x = 0; x < 2; x++) {
				matched_relay = &cs_o->peers[x].rtps[0];
				DBG("comparing new ["IP6F"]:%u/%.*s to old ["IP6F"]:%u/%.*s",
					IP6P(&t->stream.ip46), t->stream.port, STR_FMT(tag),
					IP6P(&matched_relay->peer_advertised.ip46),
					matched_relay->peer_advertised.port, STR_FMT(&cs_o->peers[x].tag));

				if (!IN6_ARE_ADDR_EQUAL(&matched_relay->peer_advertised.ip46, &t->stream.ip46)
						&& !is_addr_unspecified(&matched_relay->peer_advertised.ip46)
						&& !is_addr_unspecified(&t->stream.ip46))
					continue;
				if (matched_relay->peer_advertised.port != t->stream.port
						&& matched_relay->peer_advertised.port
						&& t->stream.port)
					continue;
				if (str_cmp_str0(&cs_o->peers[x].tag, tag))
					continue;
				DBG("found existing call stream to steal");
				goto found;
			}
			mutex_unlock(&cs_o->lock);
		}

		/* not found */
		matched_relay = NULL;
		cs_o = NULL;
		l = NULL;

found:
		/* cs_o remains locked if set */
		if (opmode == OP_OFFER) {
			DBG("creating new callstream");

			cs = callstream_new(c, t->stream.num);
			mutex_lock(&cs->lock);

			if (!matched_relay) {
				/* nothing found to re-use, use new ports */
				relays_cache_get_ports(&relays_cache, t->consecutive_num, c);
				callstream_init(cs, &relays_cache);
				p = &cs->peers[0];
				setup_peer(p, t, tag);
			}
			else {
				/* re-use, so don't use new ports */
				callstream_init(cs, NULL);
				if (matched_relay->up->idx == 0) {
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
			DBG("hunting for callstream, %i <> %i", cs->num, t->stream.num);
			if (cs->num == t->stream.num)
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
		/* matched_relay == peer[x].rtp[0] of cs_o */
		g_queue_delete_link(c->callstreams, l); /* steal cs ref */
		p = &cs->peers[1];
		p2 = &cs->peers[0];

		if (c->lookup_done && matched_relay) {
			/* duplicate/stray lookup. don't do anything except replying with something
			   we already have. check whether the direction is reversed or not and return
			   the appropriate details. if no matching stream was found, results are
			   undefined. */
			DBG("double lookup");
			if (p == matched_relay->up)
				goto skip;
			if (p2 == matched_relay->up) {
				ret = -1;
				goto skip;
			}
		}


		if (matched_relay && p == matched_relay->up) {
			/* best case, nothing to do */
			DBG("case 1");
			/* ... unless we (un)silenced the stream, in which case
			   we need to copy the new information */
			if (!IN6_ARE_ADDR_EQUAL(&matched_relay->peer_advertised.ip46, &t->stream.ip46)
					|| matched_relay->peer_advertised.port != t->stream.port)
				setup_peer(p, t, tag);
		}
		else if (matched_relay && cs_o != cs) {
			/* found something, but it's linked to a different stream */
			DBG("case 2");
			steal_peer(p, matched_relay->up);
		}
		else if (!matched_relay && !p->filled) {
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
			cs = callstream_new(c, t->stream.num);
			mutex_lock(&cs->lock);
			relays_cache_get_ports(&relays_cache, t->consecutive_num, c);
			callstream_init(cs, &relays_cache);
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

	relays_cache_cleanup(&relays_cache, c->callmaster);
	return ret;
}




static void unkernelize(struct peer *p) {
	struct streamrelay *r;
	int i;

	if (!p->kernelized)
		return;

	for (i = 0; i < 2; i++) {
		r = &p->rtps[i];
		kernel_del_stream(p->up->call->callmaster->conf.kernelfd, r->fd.localport);
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

			if (r->fd.fd != -1)
				poller_del_item(s->call->callmaster->poller, r->fd.fd);
		}
	}
}

static void call_destroy(struct call *c) {
	struct callmaster *m = c->callmaster;
	struct callstream *s;
	int ret;

	rwlock_lock_w(&m->hashlock);
	ret = g_hash_table_remove(m->callhash, &c->callid);
	rwlock_unlock_w(&m->hashlock);

	if (!ret)
		return;

	obj_put(c);

	if (redis_delete)
		redis_delete(c, m->conf.redis);

	mutex_lock(&c->lock);
	/* at this point, no more callstreams can be added */
	mylog(LOG_INFO, LOG_PREFIX_C "Final packet stats:", LOG_PARAMS_C(c));
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
			LOG_PARAMS_C(c),
			s->peers[0].rtps[0].fd.localport, s->peers[0].rtps[0].stats.packets,
			s->peers[0].rtps[0].stats.bytes, s->peers[0].rtps[0].stats.errors,
			s->peers[0].rtps[1].fd.localport, s->peers[0].rtps[1].stats.packets,
			s->peers[0].rtps[1].stats.bytes, s->peers[0].rtps[1].stats.errors,
			s->peers[1].rtps[0].fd.localport, s->peers[1].rtps[0].stats.packets,
			s->peers[1].rtps[0].stats.bytes, s->peers[1].rtps[0].stats.errors,
			s->peers[1].rtps[1].fd.localport, s->peers[1].rtps[1].stats.packets,
			s->peers[1].rtps[1].stats.bytes, s->peers[1].rtps[1].stats.errors);
		kill_callstream(s);
		mutex_unlock(&s->lock);
		obj_put(s);
		mutex_lock(&c->lock);
	}
	mutex_unlock(&c->lock);
}



typedef int (*csa_func)(char *o, struct peer *p, enum stream_address_format format, int *len);

static int call_stream_address4(char *o, struct peer *p, enum stream_address_format format, int *len) {
	struct callstream *cs = p->up;
	u_int32_t ip4;
	struct callmaster *m = cs->call->callmaster;
	int l = 0;

	if (format == SAF_NG) {
		strcpy(o + l, "IP4 ");
		l = 4;
	}

	ip4 = p->rtps[0].peer_advertised.ip46.s6_addr32[3];
	if (!ip4) {
		strcpy(o + l, "0.0.0.0");
		l += 7;
	}
	else if (m->conf.adv_ipv4)
		l += sprintf(o + l, IPF, IPP(m->conf.adv_ipv4));
	else
		l += sprintf(o + l, IPF, IPP(m->conf.ipv4));

	*len = l;
	return AF_INET;
}

static int call_stream_address6(char *o, struct peer *p, enum stream_address_format format, int *len) {
	struct callmaster *m = p->up->call->callmaster;
	int l = 0;

	if (format == SAF_NG) {
		strcpy(o + l, "IP6 ");
		l += 4;
	}

	if (is_addr_unspecified(&p->rtps[0].peer_advertised.ip46)) {
		strcpy(o + l, "::");
		l += 2;
	}
	else {
		if (!is_addr_unspecified(&m->conf.adv_ipv6))
			inet_ntop(AF_INET6, &m->conf.adv_ipv6, o + l, 45); /* lies... */
		else
			inet_ntop(AF_INET6, &m->conf.ipv6, o + l, 45);
		l += strlen(o + l);
	}

	*len = l;
	return AF_INET6;
}

static csa_func __call_stream_address(struct peer *p, int variant) {
	struct callmaster *m;
	struct peer *other;
	csa_func variants[2];

	assert(variant >= 0);
	assert(variant < ARRAYSIZE(variants));

	m = p->up->call->callmaster;
	other = p->other;

	variants[0] = call_stream_address4;
	variants[1] = call_stream_address6;

	if (is_addr_unspecified(&m->conf.ipv6)) {
		variants[1] = NULL;
		goto done;
	}
	if (other->desired_family == AF_INET)
		goto done;
	if (other->desired_family == 0 && IN6_IS_ADDR_V4MAPPED(&other->rtps[0].peer.ip46))
		goto done;
	if (other->desired_family == 0 && is_addr_unspecified(&other->rtps[0].peer_advertised.ip46))
		goto done;

	variants[0] = call_stream_address6;
	variants[1] = call_stream_address4;
	goto done;

done:
	return variants[variant];
}

int call_stream_address(char *o, struct peer *p, enum stream_address_format format, int *len) {
	csa_func f;

	f = __call_stream_address(p, 0);
	return f(o, p, format, len);
}

int call_stream_address_alt(char *o, struct peer *p, enum stream_address_format format, int *len) {
	csa_func f;

	f = __call_stream_address(p, 1);
	return f ? f(o, p, format, len) : -1;
}

int callmaster_has_ipv6(struct callmaster *m) {
	return is_addr_unspecified(&m->conf.ipv6) ? 0 : 1;
}

static int call_stream_address_gstring(GString *o, struct peer *p, enum stream_address_format format) {
	int len, ret;
	char buf[64]; /* 64 bytes ought to be enough for anybody */

	ret = call_stream_address(buf, p, format, &len);
	g_string_append_len(o, buf, len);
	return ret;
}



static str *streams_print(GQueue *s, int num, enum call_opmode opmode, const char *prefix, enum stream_address_format format) {
	GString *o;
	int i, off;
	GList *l;
	struct callstream *t;
	struct streamrelay *x;
	int af;

	off = opmode; /* 0 or 1 */
	if (num < 0)
		off ^= 1; /* 1 or 0 */
	num = abs(num);

	o = g_string_new_str();
	if (prefix)
		g_string_append_printf(o, "%s ", prefix);

	if (!s->head)
		goto out;

	t = s->head->data;
	mutex_lock(&t->lock);

	if (format == SAF_TCP)
		call_stream_address_gstring(o, &t->peers[off], format);

	for (i = 0, l = s->head; i < num && l; i++, l = l->next) {
		t = l->data;
		x = &t->peers[off].rtps[0];
		g_string_append_printf(o, (format == 1) ? "%u " : " %u", x->fd.localport);
	}

	if (format == SAF_UDP) {
		af = call_stream_address_gstring(o, &t->peers[off], format);
		g_string_append_printf(o, " %c", (af == AF_INET) ? '4' : '6');
	}

	mutex_unlock(&t->lock);

out:
	g_string_append(o, "\n");

	return g_string_free_str(o);
}

static void call_free(void *p) {
	struct call *c = p;

	g_hash_table_destroy(c->branches);
	g_queue_free(c->callstreams);
	mutex_destroy(&c->lock);
	mutex_destroy(&c->chunk_lock);
	g_string_chunk_free(c->chunk);
}

static struct call *call_create(const str *callid, struct callmaster *m) {
	struct call *c;

	mylog(LOG_NOTICE, LOG_PREFIX_C "Creating new call",
		STR_FMT(callid));	/* XXX will spam syslog on recovery from DB */
	c = obj_alloc0("call", sizeof(*c), call_free);
	c->callmaster = m;
	c->chunk = g_string_chunk_new(256);
	mutex_init(&c->chunk_lock);
	call_str_cpy(c, &c->callid, callid);
	c->callstreams = g_queue_new();
	c->created = poller_now;
	c->branches = g_hash_table_new(str_hash, str_equal);
	mutex_init(&c->lock);
	return c;
}

/* returns call with lock held */
struct call *call_get_or_create(const str *callid, const str *viabranch, struct callmaster *m) {
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
		g_hash_table_insert(m->callhash, &c->callid, obj_get(c));
		mutex_lock(&c->lock);
		rwlock_unlock_w(&m->hashlock);
	}
	else {
		obj_hold(c);
		mutex_lock(&c->lock);
		rwlock_unlock_r(&m->hashlock);
	}

	if (viabranch && viabranch->s && viabranch->len
			&& !g_hash_table_lookup(c->branches, viabranch))
		g_hash_table_insert(c->branches, call_str_dup(c, viabranch),
		(void *) 0x1);

	return c;
}

/* returns call with lock held, or NULL if not found */
static struct call *call_get(const str *callid, const str *viabranch, struct callmaster *m) {
	struct call *ret;

	rwlock_lock_r(&m->hashlock);
	ret = g_hash_table_lookup(m->callhash, callid);
	if (!ret) {
		rwlock_unlock_r(&m->hashlock);
		return NULL;
	}

	mutex_lock(&ret->lock);
	obj_hold(ret);
	rwlock_unlock_r(&m->hashlock);

	if (viabranch && viabranch->s && viabranch->len) {
		if (!g_hash_table_lookup(ret->branches, viabranch))
			g_hash_table_insert(ret->branches, call_str_dup(ret, viabranch), (void *) 0x1);
	}

	return ret;
}

/* returns call with lock held, or possibly NULL iff opmode == OP_ANSWER */
static struct call *call_get_opmode(const str *callid, const str *viabranch, struct callmaster *m, enum call_opmode opmode) {
	if (opmode == OP_OFFER)
		return call_get_or_create(callid, viabranch, m);
	return call_get(callid, viabranch, m);
}

static int addr_parse_udp(struct stream_input *st, char **out) {
	u_int32_t ip4;
	const char *cp;
	char c;
	int i;

	ZERO(*st);
	if (out[RE_UDP_UL_ADDR4] && *out[RE_UDP_UL_ADDR4]) {
		ip4 = inet_addr(out[RE_UDP_UL_ADDR4]);
		if (ip4 == -1)
			goto fail;
		in4_to_6(&st->stream.ip46, ip4);
	}
	else if (out[RE_UDP_UL_ADDR6] && *out[RE_UDP_UL_ADDR6]) {
		if (inet_pton(AF_INET6, out[RE_UDP_UL_ADDR6], &st->stream.ip46) != 1)
			goto fail;
	}
	else
		goto fail;

	st->stream.port = atoi(out[RE_UDP_UL_PORT]);
	if (!st->stream.port && strcmp(out[RE_UDP_UL_PORT], "0"))
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
		st->stream.num = atoi(out[RE_UDP_UL_NUM]);
	if (!st->stream.num)
		st->stream.num = 1;
	st->consecutive_num = 1;

	return 0;
fail:
	return -1;
}

static str *call_update_lookup_udp(char **out, struct callmaster *m, enum call_opmode opmode, int tagidx) {
	struct call *c;
	GQueue q = G_QUEUE_INIT;
	struct stream_input st;
	int num;
	str *ret, callid, viabranch, tag;

	str_init(&callid, out[RE_UDP_UL_CALLID]);
	str_init(&viabranch, out[RE_UDP_UL_VIABRANCH]);
	str_init(&tag, out[tagidx]);

	c = call_get_opmode(&callid, &viabranch, m, opmode);
	if (!c) {
		mylog(LOG_WARNING, LOG_PREFIX_CI "Got UDP LOOKUP for unknown call-id",
			STR_FMT(&callid), STR_FMT(&viabranch));
		return str_sprintf("%s 0 " IPF "\n", out[RE_UDP_COOKIE], IPP(m->conf.ipv4));
	}
	log_info = &viabranch;

	if (addr_parse_udp(&st, out))
		goto fail;

	g_queue_push_tail(&q, &st);
	num = call_streams(c, &q, &tag, opmode);
	g_queue_clear(&q);

	ret = streams_print(c->callstreams, num, opmode, out[RE_UDP_COOKIE], SAF_UDP);
	mutex_unlock(&c->lock);

	if (redis_update)
		redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %.*s", LOG_PARAMS_CI(c), STR_FMT(ret));
	goto out;

fail:
	mutex_unlock(&c->lock);
	mylog(LOG_WARNING, "Failed to parse a media stream: %s/%s:%s", out[RE_UDP_UL_ADDR4], out[RE_UDP_UL_ADDR6], out[RE_UDP_UL_PORT]);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
out:
	log_info = NULL;
	obj_put(c);
	return ret;
}

str *call_update_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_OFFER, RE_UDP_UL_FROMTAG);
}
str *call_lookup_udp(char **out, struct callmaster *m) {
	return call_update_lookup_udp(out, m, OP_ANSWER, RE_UDP_UL_TOTAG);
}

static str *call_request_lookup_tcp(char **out, struct callmaster *m, enum call_opmode opmode, const char *tagstr) {
	struct call *c;
	GQueue s = G_QUEUE_INIT;
	int num;
	str *ret = NULL, callid, tag;
	GHashTable *infohash;

	str_init(&callid, out[RE_TCP_RL_CALLID]);
	infohash = g_hash_table_new(g_str_hash, g_str_equal);
	c = call_get_opmode(&callid, NULL, m, opmode);
	if (!c) {
		mylog(LOG_WARNING, LOG_PREFIX_C "Got LOOKUP for unknown call-id", STR_FMT(&callid));
		goto out;
	}

	info_parse(out[RE_TCP_RL_INFO], infohash, m);
	streams_parse(out[RE_TCP_RL_STREAMS], m, &s);
	str_init(&tag, g_hash_table_lookup(infohash, tagstr));
	num = call_streams(c, &s, &tag, opmode);

	ret = streams_print(c->callstreams, num, opmode, NULL, SAF_TCP);
	mutex_unlock(&c->lock);

	streams_free(&s);

	if (redis_update)
		redis_update(c, m->conf.redis);

	mylog(LOG_INFO, LOG_PREFIX_CI "Returning to SIP proxy: %.*s", LOG_PARAMS_CI(c), STR_FMT(ret));
	obj_put(c);

out:
	g_hash_table_destroy(infohash);
	return ret;
}

str *call_request_tcp(char **out, struct callmaster *m) {
	return call_request_lookup_tcp(out, m, OP_OFFER, "fromtag");
}
str *call_lookup_tcp(char **out, struct callmaster *m) {
	return call_request_lookup_tcp(out, m, OP_ANSWER, "totag");
}

static int tags_match(const struct peer *p, const struct peer *px, const str *fromtag, const str *totag) {
	if (!fromtag || !fromtag->len)
		return 1;
	if (str_cmp_str(&p->tag, fromtag))
		return 0;
	if (!totag || !totag->len)
		return 1;
	if (str_cmp_str(&px->tag, totag))
		return 0;
	return 1;
}

/* cs must be unlocked */
static int tags_match_cs(struct callstream *cs, const str *fromtag, const str *totag) {
	int i;

	mutex_lock(&cs->lock);

	for (i = 0; i < 2; i++) {
		if (tags_match(&cs->peers[i], &cs->peers[i ^ 1], fromtag, totag)) {
			mutex_unlock(&cs->lock);
			return 1;
		}
	}

	mutex_unlock(&cs->lock);
	return 0;
}

static int call_delete_branch(struct callmaster *m, const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output)
{
	struct call *c;
	GList *l;
	int ret;

	c = call_get(callid, NULL, m);
	if (!c) {
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to delete not found", STR_FMT(callid));
		goto err;
	}

	log_info = branch;

	for (l = c->callstreams->head; l; l = l->next) {
		if (tags_match_cs(l->data, fromtag, totag))
			goto tag_match;
	}

	mylog(LOG_INFO, LOG_PREFIX_C "Tags didn't match for delete message, ignoring", LOG_PARAMS_C(c));
	goto err;

tag_match:
	if (output)
		ng_call_stats(c, fromtag, totag, output);

	if (branch && branch->len) {
		if (!g_hash_table_remove(c->branches, branch)) {
			mylog(LOG_INFO, LOG_PREFIX_CI "Branch to delete doesn't exist", STR_FMT(&c->callid), STR_FMT(branch));
			goto err;
		}

		mylog(LOG_INFO, LOG_PREFIX_CI "Branch deleted", LOG_PARAMS_CI(c));
		if (g_hash_table_size(c->branches))
			goto success_unlock;
		else
			DBG("no branches left, deleting full call");
	}

	mutex_unlock(&c->lock);
	mylog(LOG_INFO, LOG_PREFIX_C "Deleting full call", LOG_PARAMS_C(c));
	call_destroy(c);
	goto success;

success_unlock:
	mutex_unlock(&c->lock);
success:
	ret = 0;
	goto out;

err:
	if (c)
		mutex_unlock(&c->lock);
	ret = -1;
	goto out;

out:
	log_info = NULL;
	if (c)
		obj_put(c);
	return ret;
}

str *call_delete_udp(char **out, struct callmaster *m) {
	str callid, branch, fromtag, totag;

	DBG("got delete for callid '%s' and viabranch '%s'", 
		out[RE_UDP_DQ_CALLID], out[RE_UDP_DQ_VIABRANCH]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&branch, out[RE_UDP_DQ_VIABRANCH]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	if (call_delete_branch(m, &callid, &branch, &fromtag, &totag, NULL))
		return str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);

	return str_sprintf("%s 0\n", out[RE_UDP_COOKIE]);
}

#define SSUM(x) \
	stats->totals[0].x += p->rtps[0].stats.x; \
	stats->totals[1].x += p->rtps[1].stats.x; \
	stats->totals[2].x += px->rtps[0].stats.x; \
	stats->totals[3].x += px->rtps[1].stats.x
/* call must be locked */
static void stats_query(struct call *call, const str *fromtag, const str *totag, struct call_stats *stats,
	void (*cb)(struct peer *, struct peer *, void *), void *arg)
{
	GList *l;
	struct callstream *cs;
	int i;
	struct peer *p, *px;

	ZERO(*stats);

	for (l = call->callstreams->head; l; l = l->next) {
		cs = l->data;
		mutex_lock(&cs->lock);

		for (i = 0; i < 2; i++) {
			p = &cs->peers[i];
			px = &cs->peers[i ^ 1];

			if (p->rtps[0].last > stats->newest)
				stats->newest = p->rtps[0].last;
			if (p->rtps[1].last > stats->newest)
				stats->newest = p->rtps[1].last;

			if (!tags_match(p, px, fromtag, totag))
				continue;

			if (cb)
				cb(p, px, arg);

			SSUM(packets);
			SSUM(bytes);
			SSUM(errors);

			break;
		}

		mutex_unlock(&cs->lock);
	}
}

str *call_query_udp(char **out, struct callmaster *m) {
	struct call *c;
	str *ret, callid, fromtag, totag;
	struct call_stats stats;

	DBG("got query for callid '%s'", out[RE_UDP_DQ_CALLID]);

	str_init(&callid, out[RE_UDP_DQ_CALLID]);
	str_init(&fromtag, out[RE_UDP_DQ_FROMTAG]);
	str_init(&totag, out[RE_UDP_DQ_TOTAG]);

	c = call_get_opmode(&callid, NULL, m, OP_OTHER);
	if (!c) {
		mylog(LOG_INFO, LOG_PREFIX_C "Call-ID to query not found", STR_FMT(&callid));
		goto err;
	}

	stats_query(c, &fromtag, &totag, &stats, NULL, NULL);

	mutex_unlock(&c->lock);

	ret = str_sprintf("%s %lld "UINT64F" "UINT64F" "UINT64F" "UINT64F"\n", out[RE_UDP_COOKIE],
		(long long int) m->conf.silent_timeout - (poller_now - stats.newest),
		stats.totals[0].packets, stats.totals[1].packets,
		stats.totals[2].packets, stats.totals[3].packets);
	goto out;

err:
	if (c)
		mutex_unlock(&c->lock);
	ret = str_sprintf("%s E8\n", out[RE_UDP_COOKIE]);
	goto out;

out:
	if (c)
		obj_put(c);
	return ret;
}

void call_delete_tcp(char **out, struct callmaster *m) {
	str callid;

	str_init(&callid, out[RE_TCP_D_CALLID]);
	call_delete_branch(m, &callid, NULL, NULL, NULL, NULL);
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

	control_stream_printf(s, "session %.*s - - - - %i\n",
		STR_FMT(&c->callid),
		(int) (poller_now - c->created));

	for (l = c->callstreams->head; l; l = l->next) {
		cs = l->data;
		mutex_lock(&cs->lock);

		p = &cs->peers[0];
		r1 = &p->rtps[0];
		r2 = &cs->peers[1].rtps[0];
		rx1 = &p->rtps[1];
		rx2 = &cs->peers[1].rtps[1];

		if (r1->fd.fd == -1 || r2->fd.fd == -1)
			goto next;

		smart_ntop_p(addr1, &r1->peer.ip46, sizeof(addr1));
		smart_ntop_p(addr2, &r2->peer.ip46, sizeof(addr2));
		if (IN6_IS_ADDR_V4MAPPED(&r1->peer.ip46))
			inet_ntop(AF_INET, &m->conf.ipv4, addr3, sizeof(addr3));
		else
			smart_ntop_p(addr3, &m->conf.ipv6, sizeof(addr3));

		control_stream_printf(s, "stream %s:%u %s:%u %s:%u "UINT64F"/"UINT64F"/"UINT64F" %s %s - %i\n",
			addr1, r1->peer.port,
			addr2, r2->peer.port,
			addr3, r1->fd.localport,
			r1->stats.bytes + rx1->stats.bytes, r2->stats.bytes + rx2->stats.bytes,
			r1->stats.bytes + rx1->stats.bytes + r2->stats.bytes + rx2->stats.bytes,
			"active",
			p->codec ? : "unknown",
			(int) (poller_now - r1->last));
next:
		mutex_unlock(&cs->lock);
	}
	mutex_unlock(&c->lock);
}

static void callmaster_get_all_calls_interator(void *key, void *val, void *ptr) {
	GQueue *q = ptr;
	g_queue_push_tail(q, obj_get(val));
}

void calls_status_tcp(struct callmaster *m, struct control_stream *s) {
	struct stats st;
	GQueue q = G_QUEUE_INIT;
	struct call *c;

	mutex_lock(&m->statslock);
	st = m->stats;
	mutex_unlock(&m->statslock);

	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, callmaster_get_all_calls_interator, &q);
	rwlock_unlock_r(&m->hashlock);

	control_stream_printf(s, "proxy %u "UINT64F"/"UINT64F"/"UINT64F"\n",
		g_queue_get_length(&q),
		st.bytes, st.bytes - st.errors,
		st.bytes * 2 - st.errors);

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


static void call_ng_process_flags(struct sdp_ng_flags *out, GQueue *streams, bencode_item_t *input) {
	bencode_item_t *list, *it;
	struct stream_input *si;
	int diridx;
	enum stream_direction dirs[2];
	GList *gl;
	str s;

	ZERO(*out);
	ZERO(dirs);

	if ((list = bencode_dictionary_get_expect(input, "flags", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "trust-address"))
				out->trust_address = 1;
			else if (!bencode_strcmp(it, "symmetric"))
				out->symmetric = 1;
			else if (!bencode_strcmp(it, "asymmetric"))
				out->asymmetric = 1;
		}
	}

	if ((list = bencode_dictionary_get_expect(input, "replace", BENCODE_LIST))) {
		for (it = list->child; it; it = it->sibling) {
			if (!bencode_strcmp(it, "origin"))
				out->replace_origin = 1;
			else if (!bencode_strcmp(it, "session-connection"))
				out->replace_sess_conn = 1;
		}
	}

	/* XXX convert to a "desired-family" kinda thing instead */
	diridx = 0;
	if ((list = bencode_dictionary_get_expect(input, "direction", BENCODE_LIST))) {
		for (it = list->child; it && diridx < 2; it = it->sibling) {
			if (!bencode_strcmp(it, "internal"))
				dirs[diridx++] = DIR_INTERNAL;
			else if (!bencode_strcmp(it, "external"))
				dirs[diridx++] = DIR_EXTERNAL;
		}

		for (gl = streams->head; gl; gl = gl->next) {
			si = gl->data;
			si->direction[0] = dirs[0];
			si->direction[1] = dirs[1];
		}
	}

	list = bencode_dictionary_get_expect(input, "received-from", BENCODE_LIST);
	if (list && (it = list->child)) {
		bencode_get_str(it, &out->received_from_family);
		bencode_get_str(it->sibling, &out->received_from_address);
	}

	if (bencode_dictionary_get_str(input, "ICE", &s)) {
		if (!str_cmp(&s, "remove"))
			out->ice_remove = 1;
		else if (!str_cmp(&s, "force"))
			out->ice_force = 1;
	}

	bencode_dictionary_get_str(input, "transport-protocol", &out->transport_protocol);
}

static unsigned int stream_hash(struct stream_input *s) {
	unsigned int ret, *p;

	ret = s->stream.port;
	p = (void *) &s->stream.ip46;
	while (((void *) p) < (((void *) &s->stream.ip46) + sizeof(s->stream.ip46))) {
		ret ^= *p;
		p++;
	}
	return ret;
}

static int stream_equal(struct stream_input *a, struct stream_input *b) {
	if (a->stream.port != b->stream.port)
		return 0;
	if (memcmp(&a->stream.ip46, &b->stream.ip46, sizeof(a->stream.ip46)))
		return 0;
	return 1;
}

static const char *call_offer_answer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output, enum call_opmode opmode, const char *tagname) {
	str sdp, fromtag, viabranch, callid;
	char *errstr;
	GQueue parsed = G_QUEUE_INIT;
	GQueue streams = G_QUEUE_INIT;
	struct call *call;
	int ret, num;
	struct sdp_ng_flags flags;
	struct sdp_chopper *chopper;
	GHashTable *streamhash;

	if (!bencode_dictionary_get_str(input, "sdp", &sdp))
		return "No SDP body in message";
	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	if (!bencode_dictionary_get_str(input, tagname, &fromtag))
		return "No from-tag in message";
	bencode_dictionary_get_str(input, "via-branch", &viabranch);
	log_info = &viabranch;

	if (sdp_parse(&sdp, &parsed))
		return "Failed to parse SDP";

	call_ng_process_flags(&flags, &streams, input);

	streamhash = g_hash_table_new((GHashFunc) stream_hash, (GEqualFunc) stream_equal);
	errstr = "Incomplete SDP specification";
	if (sdp_streams(&parsed, &streams, streamhash, &flags))
		goto out;

	call = call_get_opmode(&callid, &viabranch, m, opmode);
	errstr = "Unknown call-id";
	if (!call)
		goto out;
	log_info = &viabranch;

	chopper = sdp_chopper_new(&sdp);
	bencode_buffer_destroy_add(output->buffer, (free_func_t) sdp_chopper_destroy, chopper);
	num = call_streams(call, &streams, &fromtag, opmode);
	ret = sdp_replace(chopper, &parsed, call, (num >= 0) ? opmode : (opmode ^ 1), &flags, streamhash);

	mutex_unlock(&call->lock);
	obj_put(call);

	errstr = "Error rewriting SDP";
	if (ret)
		goto out;

	bencode_dictionary_add_iovec(output, "sdp", &g_array_index(chopper->iov, struct iovec, 0),
		chopper->iov_num, chopper->str_len);
	bencode_dictionary_add_string(output, "result", "ok");

	errstr = NULL;
out:
	sdp_free(&parsed);
	streams_free(&streams);
	g_hash_table_destroy(streamhash);
	log_info = NULL;

	return errstr;
}

const char *call_offer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_OFFER, "from-tag");
}

const char *call_answer_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	return call_offer_answer_ng(input, m, output, OP_ANSWER, "to-tag");
}

const char *call_delete_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str fromtag, totag, viabranch, callid;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	if (!bencode_dictionary_get_str(input, "from-tag", &fromtag))
		return "No from-tag in message";
	bencode_dictionary_get_str(input, "to-tag", &totag);
	bencode_dictionary_get_str(input, "via-branch", &viabranch);

	if (call_delete_branch(m, &callid, &viabranch, &fromtag, &totag, output))
		return "Call-ID not found or tags didn't match";

	bencode_dictionary_add_string(output, "result", "ok");
	return NULL;
}

void callmaster_exclude_port(struct callmaster *m, u_int16_t p) {
	mutex_lock(&m->portlock);
	bit_array_set(m->ports_used, p);
	mutex_unlock(&m->portlock);
}

static bencode_item_t *peer_address(bencode_buffer_t *b, struct stream *s) {
	bencode_item_t *d;
	char buf[64];

	d = bencode_dictionary(b);
	if (IN6_IS_ADDR_V4MAPPED(&s->ip46)) {
		bencode_dictionary_add_string(d, "family", "IPv4");
		inet_ntop(AF_INET, &(s->ip46.s6_addr32[3]), buf, sizeof(buf));
	}
	else {
		bencode_dictionary_add_string(d, "family", "IPv6");
		inet_ntop(AF_INET6, &s->ip46, buf, sizeof(buf));
	}
	bencode_dictionary_add_string_dup(d, "address", buf);
	bencode_dictionary_add_integer(d, "port", s->port);

	return d;
}

static bencode_item_t *stats_encode(bencode_buffer_t *b, struct stats *s) {
	bencode_item_t *d;

	d = bencode_dictionary(b);
	bencode_dictionary_add_integer(d, "packets", s->packets);
	bencode_dictionary_add_integer(d, "bytes", s->bytes);
	bencode_dictionary_add_integer(d, "errors", s->errors);
	return d;
}

static bencode_item_t *streamrelay_stats(bencode_buffer_t *b, struct streamrelay *r) {
	bencode_item_t *d;

	d = bencode_dictionary(b);

	bencode_dictionary_add(d, "counters", stats_encode(b, &r->stats));
	bencode_dictionary_add(d, "peer address", peer_address(b, &r->peer));
	bencode_dictionary_add(d, "advertised peer address", peer_address(b, &r->peer_advertised));

	bencode_dictionary_add_integer(d, "local port", r->fd.localport);

	return d;
}

static bencode_item_t *rtp_rtcp_stats(bencode_buffer_t *b, struct stats *rtp, struct stats *rtcp) {
	bencode_item_t *s;
	s = bencode_dictionary(b);
	bencode_dictionary_add(s, "rtp", stats_encode(b, rtp));
	bencode_dictionary_add(s, "rtcp", stats_encode(b, rtcp));
	return s;
}

static bencode_item_t *peer_stats(bencode_buffer_t *b, struct peer *p) {
	bencode_item_t *d, *s;

	d = bencode_dictionary(b);

	bencode_dictionary_add_str_dup(d, "tag", &p->tag);
	if (p->codec)
		bencode_dictionary_add_string(d, "codec", p->codec);
	if (p->kernelized)
		bencode_dictionary_add_string(d, "status", "in kernel");
	else if (p->confirmed)
		bencode_dictionary_add_string(d, "status", "confirmed peer address");
	else if (p->filled)
		bencode_dictionary_add_string(d, "status", "known but unconfirmed peer address");
	else
		bencode_dictionary_add_string(d, "status", "unknown peer address");

	s = bencode_dictionary_add_dictionary(d, "stats");
	bencode_dictionary_add(s, "rtp", streamrelay_stats(b, &p->rtps[0]));
	bencode_dictionary_add(s, "rtcp", streamrelay_stats(b, &p->rtps[1]));

	return d;
}

static void ng_stats_cb(struct peer *p, struct peer *px, void *streams) {
	bencode_item_t *stream;

	stream = bencode_list_add_list(streams);
	bencode_list_add(stream, peer_stats(stream->buffer, p));
	bencode_list_add(stream, peer_stats(stream->buffer, px));
}

/* call must be locked */
static void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output) {
	bencode_item_t *streams, *dict;
	struct call_stats stats;

	bencode_dictionary_add_integer(output, "created", call->created);

	streams = bencode_dictionary_add_list(output, "streams");
	stats_query(call, fromtag, totag, &stats, ng_stats_cb, streams);

	dict = bencode_dictionary_add_dictionary(output, "totals");
	bencode_dictionary_add(dict, "input", rtp_rtcp_stats(output->buffer, &stats.totals[0], &stats.totals[1]));
	bencode_dictionary_add(dict, "output", rtp_rtcp_stats(output->buffer, &stats.totals[2], &stats.totals[3]));
}

const char *call_query_ng(bencode_item_t *input, struct callmaster *m, bencode_item_t *output) {
	str callid, fromtag, totag;
	struct call *call;

	if (!bencode_dictionary_get_str(input, "call-id", &callid))
		return "No call-id in message";
	call = call_get_opmode(&callid, NULL, m, OP_OTHER);
	if (!call)
		return "Unknown call-id";
	bencode_dictionary_get_str(input, "from-tag", &fromtag);
	bencode_dictionary_get_str(input, "to-tag", &totag);

	bencode_dictionary_add_string(output, "result", "ok");
	ng_call_stats(call, &fromtag, &totag, output);
	mutex_unlock(&call->lock);

	return NULL;
}
