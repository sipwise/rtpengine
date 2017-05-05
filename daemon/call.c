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
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

#include "poller.h"
#include "aux.h"
#include "log.h"
#include "kernel.h"
#include "control_tcp.h"
#include "streambuf.h"
#include "redis.h"
#include "xt_RTPENGINE.h"
#include "bencode.h"
#include "sdp.h"
#include "str.h"
#include "stun.h"
#include "rtcp.h"
#include "rtp.h"
#include "call_interfaces.h"
#include "ice.h"
#include "rtpengine_config.h"
#include "log_funcs.h"
#include "recording.h"
#include "rtplib.h"
#include "cdr.h"
#include "statistics.h"
#include "ssrc.h"


/* also serves as array index for callstream->peers[] */
struct iterator_helper {
	GSList			*del_timeout;
	GSList			*del_scheduled;
	GHashTable		*addr_sfd;
};
struct xmlrpc_helper {
	enum xmlrpc_format fmt;
	GStringChunk		*c;
	GSList			*tags_urls;
};

const struct transport_protocol transport_protocols[] = {
	[PROTO_RTP_AVP] = {
		.index		= PROTO_RTP_AVP,
		.name		= "RTP/AVP",
		.rtp		= 1,
		.srtp		= 0,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_SAVP] = {
		.index		= PROTO_RTP_SAVP,
		.name		= "RTP/SAVP",
		.rtp		= 1,
		.srtp		= 1,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_RTP_AVPF] = {
		.index		= PROTO_RTP_AVPF,
		.name		= "RTP/AVPF",
		.rtp		= 1,
		.srtp		= 0,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_RTP_SAVPF] = {
		.index		= PROTO_RTP_SAVPF,
		.name		= "RTP/SAVPF",
		.rtp		= 1,
		.srtp		= 1,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_UDP_TLS_RTP_SAVP] = {
		.index		= PROTO_UDP_TLS_RTP_SAVP,
		.name		= "UDP/TLS/RTP/SAVP",
		.rtp		= 1,
		.srtp		= 1,
		.avpf		= 0,
		.tcp		= 0,
	},
	[PROTO_UDP_TLS_RTP_SAVPF] = {
		.index		= PROTO_UDP_TLS_RTP_SAVPF,
		.name		= "UDP/TLS/RTP/SAVPF",
		.rtp		= 1,
		.srtp		= 1,
		.avpf		= 1,
		.tcp		= 0,
	},
	[PROTO_UDPTL] = {
		.index		= PROTO_UDPTL,
		.name		= "udptl",
		.rtp		= 0,
		.srtp		= 0,
		.avpf		= 0,
		.tcp		= 0,
	},
};
const int num_transport_protocols = G_N_ELEMENTS(transport_protocols);

/* ********** */

static void __monologue_destroy(struct call_monologue *monologue);
static int monologue_destroy(struct call_monologue *ml);
static struct timeval add_ongoing_calls_dur_in_interval(struct callmaster *m,
		struct timeval *interval_start, struct timeval *interval_duration);

/* called with call->master_lock held in R */
static int call_timer_delete_monologues(struct call *c) {
	GList *i;
	struct call_monologue *ml;
	int ret = 0;
	time_t min_deleted = 0;

	/* we need a write lock here */
	rwlock_unlock_r(&c->master_lock);
	rwlock_lock_w(&c->master_lock);

	for (i = c->monologues.head; i; i = i->next) {
		ml = i->data;

		if (!ml->deleted)
			continue;
		if (ml->deleted > poller_now) {
			if (!min_deleted || ml->deleted < min_deleted)
				min_deleted = ml->deleted;
			continue;
		}

		if (monologue_destroy(ml)) {
			ret = 1; /* destroy call */
			goto out;
		}
	}

out:
	c->ml_deleted = min_deleted;

	rwlock_unlock_w(&c->master_lock);
	rwlock_lock_r(&c->master_lock);

	// coverity[missing_unlock : FALSE]
	return ret;
}



/* called with callmaster->hashlock held */
static void call_timer_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct iterator_helper *hlp = ptr;
	GList *it;
	struct callmaster *cm;
	unsigned int check;
	int good = 0;
	struct packet_stream *ps;
	struct stream_fd *sfd;
	int tmp_t_reason = UNKNOWN;
	struct call_monologue *ml;
	enum call_stream_state css;
	atomic64 *timestamp;

	rwlock_lock_r(&c->master_lock);
	log_info_call(c);

	cm = c->callmaster;
	rwlock_lock_r(&cm->conf.config_lock);

	// final timeout applicable to all calls (own and foreign)
	if (cm->conf.final_timeout && poller_now >= (c->created.tv_sec + cm->conf.final_timeout)) {
		ilog(LOG_INFO, "Closing call due to final timeout");
		tmp_t_reason = FINAL_TIMEOUT;
		for (it = c->monologues.head; it; it = it->next) {
			ml = it->data;
			gettimeofday(&(ml->terminated),NULL);
			ml->term_reason = tmp_t_reason;
		}

		goto delete;
	}

	// other timeouts not applicable to foreign calls
	if (IS_FOREIGN_CALL(c)) {
		goto out;
	}

	if (c->deleted && poller_now >= c->deleted
			&& c->last_signal <= c->deleted)
		goto delete;

	if (c->ml_deleted && poller_now >= c->ml_deleted) {
		if (call_timer_delete_monologues(c))
			goto delete;
	}

	if (!c->streams.head)
		goto drop;

	for (it = c->streams.head; it; it = it->next) {
		ps = it->data;

		timestamp = &ps->last_packet;

		if (!ps->media)
			goto next;
		sfd = ps->selected_sfd;
		if (!sfd)
			goto no_sfd;

		/* valid stream */

		css = call_stream_state_machine(ps);

		if (css == CSS_ICE)
			timestamp = &ps->media->ice_agent->last_activity;

		if (g_hash_table_contains(hlp->addr_sfd, &sfd->socket.local))
			goto next;
		g_hash_table_insert(hlp->addr_sfd, &sfd->socket.local, obj_get(sfd));

no_sfd:
		if (good)
			goto next;

		check = cm->conf.timeout;
		tmp_t_reason = TIMEOUT;
		if (!MEDIA_ISSET(ps->media, RECV) || !sfd || !PS_ISSET(ps, FILLED)) {
			check = cm->conf.silent_timeout;
			tmp_t_reason = SILENT_TIMEOUT;
		}

		if (poller_now - atomic64_get(timestamp) < check)
			good = 1;

next:
		;
	}

	if (good || IS_FOREIGN_CALL(c)) {
		goto out;
	}

	if (c->ml_deleted)
		goto out;

	for (it = c->monologues.head; it; it = it->next) {
		ml = it->data;
		gettimeofday(&(ml->terminated),NULL);
		ml->term_reason = tmp_t_reason;
	}

	ilog(LOG_INFO, "Closing call due to timeout");

drop:
	hlp->del_timeout = g_slist_prepend(hlp->del_timeout, obj_get(c));
	goto out;

delete:
	hlp->del_scheduled = g_slist_prepend(hlp->del_scheduled, obj_get(c));
	goto out;

out:
	rwlock_unlock_r(&cm->conf.config_lock);
	rwlock_unlock_r(&c->master_lock);
	log_info_clear();
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
	const char *url;

	while (xh->tags_urls && xh->tags_urls->next) {
		tag = xh->tags_urls->data;
		url = xh->tags_urls->next->data;

		ilog(LOG_INFO, "Forking child to close call with tag "STR_FORMAT" via XMLRPC call to %s",
				STR_FMT(tag), url);
		pid = fork();

		if (pid) {
retry:
			pid = waitpid(pid, &status, 0);
			if ((pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) || i >= 3) {
				xh->tags_urls = g_slist_delete_link(xh->tags_urls, xh->tags_urls);
				xh->tags_urls = g_slist_delete_link(xh->tags_urls, xh->tags_urls);
				i = 0;
			}
			else {
				if (pid == -1 && errno == EINTR)
					goto retry;
				ilog(LOG_INFO, "XMLRPC child exited with status %i", status);
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

		if (!ilog_stderr) {
			openlog("rtpengine/child", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		}
		ilog(LOG_INFO, "Initiating XMLRPC call for tag "STR_FORMAT"", STR_FMT(tag));

		alarm(5);

		xmlrpc_env_init(&e);
		xmlrpc_client_setup_global_const(&e);
		xmlrpc_client_create(&e, XMLRPC_CLIENT_NO_FLAGS, "ngcp-rtpengine", RTPENGINE_VERSION,
			NULL, 0, &c);
		if (e.fault_occurred)
			goto fault;

		r = NULL;
		switch (xh->fmt) {
		case XF_SEMS:
			xmlrpc_client_call2f(&e, c, url, "di", &r, "(ssss)",
						"sbc", "postControlCmd", tag->s, "teardown");
			break;
		case XF_CALLID:
			xmlrpc_client_call2f(&e, c, url, "teardown", &r, "(s)", tag->s);
			break;
		}

		if (r)
			xmlrpc_DECREF(r);
		if (e.fault_occurred)
			goto fault;

		xmlrpc_client_destroy(c);
		xh->tags_urls = g_slist_delete_link(xh->tags_urls, xh->tags_urls);
		xh->tags_urls = g_slist_delete_link(xh->tags_urls, xh->tags_urls);
		xmlrpc_env_clean(&e);

		_exit(0);

fault:
		ilog(LOG_WARNING, "XMLRPC fault occurred: %s", e.fault_string);
		_exit(1);
	}

	g_string_chunk_free(xh->c);
	g_slice_free1(sizeof(*xh), xh);
}

void kill_calls_timer(GSList *list, struct callmaster *m) {
	struct call *ca;
	GList *csl;
	struct call_monologue *cm;
	const char *url, *url_prefix, *url_suffix;
	struct xmlrpc_helper *xh = NULL;
	char url_buf[128];

	if (!list)
		return;

	/* if m is NULL, it's the scheduled deletions, otherwise it's the timeouts */
	url = m ? m->conf.b2b_url : NULL;
	if (url) {
		xh = g_slice_alloc(sizeof(*xh));
		xh->c = g_string_chunk_new(64);
		url_prefix = NULL;
		url_suffix = strstr(url, "%%");
		if (url_suffix) {
			url_prefix = g_string_chunk_insert_len(xh->c, url, url_suffix - url);
			url_suffix = g_string_chunk_insert(xh->c, url_suffix + 2);
		}
		else
			url_suffix = g_string_chunk_insert(xh->c, url);
		xh->tags_urls = NULL;
		xh->fmt = m->conf.fmt;
	}

	while (list) {
		ca = list->data;
		log_info_call(ca);
		if (!url)
			goto destroy;

		rwlock_lock_r(&ca->master_lock);

		if (url_prefix) {
			snprintf(url_buf, sizeof(url_buf), "%s%s%s",
					url_prefix, sockaddr_print_buf(&ca->created_from_addr),
					url_suffix);
		}
		else
			snprintf(url_buf, sizeof(url_buf), "%s", url_suffix);

		switch (m->conf.fmt) {
		case XF_SEMS:
			for (csl = ca->monologues.head; csl; csl = csl->next) {
				cm = csl->data;
				if (cm->tag.s && cm->tag.len) {
					xh->tags_urls = g_slist_prepend(xh->tags_urls, g_string_chunk_insert(xh->c, url_buf));
					xh->tags_urls = g_slist_prepend(xh->tags_urls, str_chunk_insert(xh->c, &cm->tag));
				}
			}
			break;
		case XF_CALLID:
			xh->tags_urls = g_slist_prepend(xh->tags_urls, g_string_chunk_insert(xh->c, url_buf));
			xh->tags_urls = g_slist_prepend(xh->tags_urls, str_chunk_insert(xh->c, &ca->callid));
			break;
		}

		rwlock_unlock_r(&ca->master_lock);

destroy:
		call_destroy(ca);
		obj_put(ca);
		list = g_slist_delete_link(list, list);
		log_info_clear();
	}

	if (xh)
		thread_create_detach(xmlrpc_kill_calls, xh);
}


#define DS(x) do {							\
		u_int64_t ks_val, d;					\
		ks_val = atomic64_get(&ps->kernel_stats.x);	\
		if (ke->stats.x < ks_val)				\
			d = 0;						\
		else							\
			d = ke->stats.x - ks_val;			\
		atomic64_add(&ps->stats.x, d);			\
		atomic64_add(&m->statsps.x, d);			\
	} while (0)
static void callmaster_timer(void *ptr) {
	struct callmaster *m = ptr;
	struct iterator_helper hlp;
	GList *i, *l;
	struct rtpengine_list_entry *ke;
	struct packet_stream *ps, *sink;
	struct stats tmpstats;
	int j, update;
	struct stream_fd *sfd;
	struct rtp_stats *rs;
	unsigned int pt;
	endpoint_t ep;

	ZERO(hlp);
	hlp.addr_sfd = g_hash_table_new(g_endpoint_hash, g_endpoint_eq);

	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, call_timer_iterator, &hlp);
	rwlock_unlock_r(&m->hashlock);

	atomic64_local_copy_zero_struct(&tmpstats, &m->statsps, bytes);
	atomic64_local_copy_zero_struct(&tmpstats, &m->statsps, packets);
	atomic64_local_copy_zero_struct(&tmpstats, &m->statsps, errors);

	atomic64_set(&m->stats.bytes, atomic64_get_na(&tmpstats.bytes));
	atomic64_set(&m->stats.packets, atomic64_get_na(&tmpstats.packets));
	atomic64_set(&m->stats.errors, atomic64_get_na(&tmpstats.errors));

	i = kernel_list();
	while (i) {
		ke = i->data;

		kernel2endpoint(&ep, &ke->target.local);
		sfd = g_hash_table_lookup(hlp.addr_sfd, &ep);
		if (!sfd)
			goto next;

		rwlock_lock_r(&sfd->call->master_lock);

		ps = sfd->stream;
		if (!ps || ps->selected_sfd != sfd) {
			rwlock_unlock_r(&sfd->call->master_lock);
			goto next;
		}

		DS(packets);
		DS(bytes);
		DS(errors);


		if (ke->stats.packets != atomic64_get(&ps->kernel_stats.packets))
			atomic64_set(&ps->last_packet, poller_now);

		ps->stats.in_tos_tclass = ke->stats.in_tos;

#if (RE_HAS_MEASUREDELAY)
		/* XXX fix atomicity */
		ps->stats.delay_min = ke->stats.delay_min;
		ps->stats.delay_avg = ke->stats.delay_avg;
		ps->stats.delay_max = ke->stats.delay_max;
#endif

		atomic64_set(&ps->kernel_stats.bytes, ke->stats.bytes);
		atomic64_set(&ps->kernel_stats.packets, ke->stats.packets);
		atomic64_set(&ps->kernel_stats.errors, ke->stats.errors);

		for (j = 0; j < ke->target.num_payload_types; j++) {
			pt = ke->target.payload_types[j];
			rs = g_hash_table_lookup(ps->rtp_stats, &pt);
			if (!rs)
				continue;
			if (ke->rtp_stats[j].packets > atomic64_get(&rs->packets))
				atomic64_add(&rs->packets,
						ke->rtp_stats[j].packets - atomic64_get(&rs->packets));
			if (ke->rtp_stats[j].bytes > atomic64_get(&rs->bytes))
				atomic64_add(&rs->bytes,
						ke->rtp_stats[j].bytes - atomic64_get(&rs->bytes));
			atomic64_set(&rs->kernel_packets, ke->rtp_stats[j].packets);
			atomic64_set(&rs->kernel_bytes, ke->rtp_stats[j].bytes);
		}

		update = 0;

		sink = packet_stream_sink(ps);

		/* XXX this only works if the kernel module actually gets to see the packets. */
		if (sink) {
			mutex_lock(&sink->out_lock);
			if (sink->crypto.params.crypto_suite && sink->ssrc_out
					&& ke->target.ssrc == sink->ssrc_out->parent->ssrc
					&& ke->target.encrypt.last_index - sink->ssrc_out->srtp_index > 0x4000)
			{
				sink->ssrc_out->srtp_index = ke->target.encrypt.last_index;
				update = 1;
			}
			mutex_unlock(&sink->out_lock);
		}

		mutex_lock(&ps->in_lock);
		if (sfd->crypto.params.crypto_suite && ps->ssrc_in
				&& ke->target.ssrc == ps->ssrc_in->parent->ssrc
				&& ke->target.decrypt.last_index - ps->ssrc_in->srtp_index > 0x4000)
		{
			ps->ssrc_in->srtp_index = ke->target.decrypt.last_index;
			update = 1;
		}
		mutex_unlock(&ps->in_lock);

		rwlock_unlock_r(&sfd->call->master_lock);

		if (update) {
				redis_update_onekey(ps->call, m->conf.redis_write);
		}

next:
		g_hash_table_remove(hlp.addr_sfd, &ep);
		g_slice_free1(sizeof(*ke), ke);
		i = g_list_delete_link(i, i);
		if (sfd)
			obj_put(sfd);
	}

	l = g_hash_table_get_values(hlp.addr_sfd);
	for (i = l; i; i = i->next)
		obj_put((struct stream_fd *) i->data);
	g_list_free(l);
	g_hash_table_destroy(hlp.addr_sfd);

	kill_calls_timer(hlp.del_scheduled, NULL);
	kill_calls_timer(hlp.del_timeout, m);
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

	mutex_init(&c->totalstats.total_average_lock);
	mutex_init(&c->totalstats_interval.total_average_lock);
	mutex_init(&c->totalstats_interval.managed_sess_lock);
	mutex_init(&c->totalstats_interval.total_calls_duration_lock);

	c->totalstats.started = poller_now;
	//c->totalstats_interval.managed_sess_min = 0; // already zeroed
	//c->totalstats_interval.managed_sess_max = 0;

	mutex_init(&c->totalstats_lastinterval_lock);
	mutex_init(&c->cngs_lock);
	c->cngs_hash = g_hash_table_new(g_sockaddr_hash, g_sockaddr_eq);

	return c;

fail:
	obj_put(c);
	return NULL;
}



void __payload_type_free(void *p) {
	g_slice_free1(sizeof(struct rtp_payload_type), p);
}

static struct call_media *__get_media(struct call_monologue *ml, GList **it, const struct stream_params *sp) {
	struct call_media *med;
	struct call *call;

	/* iterator points to last seen element, or NULL if uninitialized */
	if (!*it)
		*it = ml->medias.head;
	else
		*it = (*it)->next;

	/* possible incremental update, hunt for correct media struct */
	while (*it) {
		med = (*it)->data;
		if (med->index == sp->index) {
			__C_DBG("found existing call_media for stream #%u", sp->index);
			return med;
		}
		*it = (*it)->next;
	}

	__C_DBG("allocating new call_media for stream #%u", sp->index);
	call = ml->call;
	med = uid_slice_alloc0(med, &call->medias);
	med->monologue = ml;
	med->call = ml->call;
	med->index = sp->index;
	call_str_cpy(ml->call, &med->type, &sp->type);
	med->rtp_payload_types = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, __payload_type_free);

	g_queue_push_tail(&ml->medias, med);

	*it = ml->medias.tail;

	return med;
}

static struct endpoint_map *__get_endpoint_map(struct call_media *media, unsigned int num_ports,
		const struct endpoint *ep, const struct sdp_ng_flags *flags)
{
	GList *l;
	struct endpoint_map *em;
	struct stream_fd *sfd;
	GQueue intf_sockets = G_QUEUE_INIT;
	socket_t *sock;
	struct intf_list *il, *em_il;

	for (l = media->endpoint_maps.tail; l; l = l->prev) {
		em = l->data;
		if (em->logical_intf != media->logical_intf)
			continue;
		if (em->wildcard && em->num_ports >= num_ports) {
			__C_DBG("found a wildcard endpoint map%s", ep ? " and filling it in" : "");
			if (ep) {
				em->endpoint = *ep;
				em->wildcard = 0;
			}
			return em;
		}
		if (!ep) /* creating wildcard map */
			break;

		if (flags && flags->port_latching)
			/* do nothing - ignore endpoint addresses */ ;
		else if (is_addr_unspecified(&ep->address) || is_addr_unspecified(&em->endpoint.address)) {
			/* handle zero endpoint address: only compare ports */
			if (ep->port != em->endpoint.port)
				continue;
		}
		else if (memcmp(&em->endpoint, ep, sizeof(*ep)))
			continue;

		if (em->num_ports >= num_ports) {
			if (is_addr_unspecified(&em->endpoint.address))
				em->endpoint.address = ep->address;
			return em;
		}
		/* endpoint matches, but not enough ports. flush existing ports
		 * and allocate a new set. */
		__C_DBG("endpoint matches, doesn't have enough ports");
		g_queue_clear_full(&em->intf_sfds, (void *) free_intf_list);
		goto alloc;
	}

	__C_DBG("allocating new %sendpoint map", ep ? "" : "wildcard ");
	em = uid_slice_alloc0(em, &media->call->endpoint_maps);
	if (ep)
		em->endpoint = *ep;
	else
		em->wildcard = 1;
	em->logical_intf = media->logical_intf;
	em->num_ports = num_ports;
	g_queue_init(&em->intf_sfds);
	g_queue_push_tail(&media->endpoint_maps, em);

alloc:
	if (num_ports > 16)
		return NULL;
	if (get_consecutive_ports(&intf_sockets, num_ports, media->logical_intf))
		return NULL;

	__C_DBG("allocating stream_fds for %u ports", num_ports);

	while ((il = g_queue_pop_head(&intf_sockets))) {
		if (il->list.length != num_ports)
			goto next_il;

		em_il = g_slice_alloc0(sizeof(*em_il));
		em_il->local_intf = il->local_intf;
		g_queue_push_tail(&em->intf_sfds, em_il);

		while ((sock = g_queue_pop_head(&il->list))) {
			set_tos(sock, media->call->tos);
			sfd = stream_fd_new(sock, media->call, il->local_intf);
			g_queue_push_tail(&em_il->list, sfd); /* not referenced */
		}

next_il:
		free_socket_intf_list(il);
	}

	return em;
}

static void __assign_stream_fds(struct call_media *media, GQueue *intf_sfds) {
	GList *l, *k;
	struct packet_stream *ps;
	struct stream_fd *sfd, *intf_sfd;
	struct intf_list *il;
	int sfd_found;

	for (k = media->streams.head; k; k = k->next) {
		ps = k->data;

		g_queue_clear(&ps->sfds);
		sfd_found = 0;
		intf_sfd = NULL;

		for (l = intf_sfds->head; l; l = l->next) {
			il = l->data;

			sfd = g_queue_peek_nth(&il->list, ps->component - 1);
			if (!sfd) return ;

			sfd->stream = ps;
			g_queue_push_tail(&ps->sfds, sfd);

			if (ps->selected_sfd == sfd)
				sfd_found = 1;
			if (ps->selected_sfd && sfd->local_intf == ps->selected_sfd->local_intf)
				intf_sfd = sfd;
		}

		if (!ps->selected_sfd || !sfd_found) {
			if (intf_sfd)
				ps->selected_sfd = intf_sfd;
			else
				ps->selected_sfd = g_queue_peek_nth(&ps->sfds, 0);
		}

		/* XXX:
		 * handle crypto/dtls resets by moving contexts into sfd struct.
		 * handle ice resets too.
		 */
	}
}

static int __wildcard_endpoint_map(struct call_media *media, unsigned int num_ports) {
	struct endpoint_map *em;

	em = __get_endpoint_map(media, num_ports, NULL, NULL);
	if (!em)
		return -1;

	__assign_stream_fds(media, &em->intf_sfds);

	return 0;
}

static void __rtp_stats_free(void *p) {
	g_slice_free1(sizeof(struct rtp_stats), p);
}

struct packet_stream *__packet_stream_new(struct call *call) {
	struct packet_stream *stream;

	stream = uid_slice_alloc0(stream, &call->streams);
	mutex_init(&stream->in_lock);
	mutex_init(&stream->out_lock);
	stream->call = call;
	atomic64_set_na(&stream->last_packet, poller_now);
	stream->rtp_stats = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, __rtp_stats_free);
	recording_init_stream(stream);

	return stream;
}

static int __num_media_streams(struct call_media *media, unsigned int num_ports) {
	struct packet_stream *stream;
	struct call *call = media->call;
	int ret = 0;

	__C_DBG("allocating %i new packet_streams", num_ports - media->streams.length);
	while (media->streams.length < num_ports) {
		stream = __packet_stream_new(call);
		stream->media = media;
		g_queue_push_tail(&media->streams, stream);
		stream->component = media->streams.length;
		ret++;
	}

	g_queue_truncate(&media->streams, num_ports);

	return ret;
}

static void __fill_stream(struct packet_stream *ps, const struct endpoint *epp, unsigned int port_off,
		const struct stream_params *sp)
{
	struct endpoint ep;
	struct call_media *media = ps->media;

	ep = *epp;
	ep.port += port_off;

	/* if the endpoint hasn't changed, we do nothing */
	if (PS_ISSET(ps, FILLED) && !memcmp(&ps->advertised_endpoint, &ep, sizeof(ep)))
		return;

	ps->advertised_endpoint = ep;

	/* ignore endpoint changes if we're ICE-enabled and ICE data hasn't changed */
	if (PS_ISSET(ps, FILLED) && MEDIA_ISSET(media, ICE) && media->ice_agent && sp
			&& !ice_ufrag_cmp(media->ice_agent, &sp->ice_ufrag))
		return;

	ps->endpoint = ep;

	if (PS_ISSET(ps, FILLED)) {
		/* we reset crypto params whenever the endpoint changes */
		// XXX fix WRT SSRC handling
		crypto_reset(&ps->crypto);
		dtls_shutdown(ps);
	}

	ilog(LOG_DEBUG, "set FILLED flag for stream %s:%d", sockaddr_print_buf(&ps->endpoint.address), ps->endpoint.port);
	PS_SET(ps, FILLED);
	/* XXX reset/repair ICE */
}

/* called with call locked in R or W, but ps not locked */
enum call_stream_state call_stream_state_machine(struct packet_stream *ps) {
	struct call_media *media = ps->media;

	if (!ps->selected_sfd || !ps->sfds.length)
		return CSS_SHUTDOWN;

	if (MEDIA_ISSET(media, PASSTHRU))
		return CSS_RUNNING;

	if (MEDIA_ISSET(media, ICE) && !ice_has_finished(media))
		return CSS_ICE; /* handled by ICE timer */

	if (MEDIA_ISSET(media, DTLS)) {
		mutex_lock(&ps->in_lock);
		if (ps->selected_sfd->dtls.init && !ps->selected_sfd->dtls.connected) {
			dtls(ps, NULL, NULL);
			mutex_unlock(&ps->in_lock);
			return CSS_DTLS;
		}
		mutex_unlock(&ps->in_lock);
	}

	return CSS_RUNNING;
}

void call_media_state_machine(struct call_media *m) {
	GList *l;

	for (l = m->streams.head; l; l = l->next)
		call_stream_state_machine(l->data);
}

static int __init_stream(struct packet_stream *ps) {
	struct call_media *media = ps->media;
	struct call *call = ps->call;
	int active;

	if (ps->selected_sfd) {
		// XXX apply SDES parms to all sfds?
		if (MEDIA_ISSET(media, SDES))
			crypto_init(&ps->selected_sfd->crypto, &media->sdes_in.params);

		if (MEDIA_ISSET(media, DTLS) && !PS_ISSET(ps, FALLBACK_RTCP)) {
			active = dtls_is_active(&ps->selected_sfd->dtls);
			// we try to retain our role if possible, but must handle a role switch
			if ((active && !MEDIA_ISSET(media, SETUP_ACTIVE))
					|| (!active && !MEDIA_ISSET(media, SETUP_PASSIVE)))
				active = -1;
			if (active == -1)
				active = (PS_ISSET(ps, FILLED) && MEDIA_ISSET(media, SETUP_ACTIVE));
			dtls_connection_init(ps, active, call->dtls_cert);

			if (!PS_ISSET(ps, FINGERPRINT_VERIFIED) && media->fingerprint.hash_func
					&& ps->dtls_cert)
			{
				if (dtls_verify_cert(ps))
					return -1;
			}

			call_stream_state_machine(ps);
		}
	}

	if (MEDIA_ISSET(media, SDES))
		crypto_init(&ps->crypto, &media->sdes_out.params);

	return 0;
}

void __rtp_stats_update(GHashTable *dst, GHashTable *src) {
	struct rtp_stats *rs;
	struct rtp_payload_type *pt;
	GList *values, *l;

	/* "src" is a call_media->rtp_payload_types table, while "dst" is a
	 * packet_stream->rtp_stats table */

	values = g_hash_table_get_values(src);

	for (l = values; l; l = l->next) {
		pt = l->data;
		rs = g_hash_table_lookup(dst, &pt->payload_type);
		if (rs)
			continue;

		rs = g_slice_alloc0(sizeof(*rs));
		rs->payload_type = pt->payload_type;
		g_hash_table_insert(dst, &rs->payload_type, rs);
	}

	g_list_free(values);

	/* we leave previously added but now removed payload types in place */
}

static int __init_streams(struct call_media *A, struct call_media *B, const struct stream_params *sp) {
	GList *la, *lb;
	struct packet_stream *a, *ax, *b;
	unsigned int port_off = 0;

	la = A->streams.head;
	lb = B->streams.head;

	while (la) {
		assert(lb != NULL);
		a = la->data;
		b = lb->data;

		/* RTP */
		a->rtp_sink = b;
		PS_SET(a, RTP); /* XXX technically not correct, could be udptl too */

		__rtp_stats_update(a->rtp_stats, A->rtp_payload_types);

		if (sp) {
			__fill_stream(a, &sp->rtp_endpoint, port_off, sp);
			bf_copy_same(&a->ps_flags, &sp->sp_flags,
					SHARED_FLAG_STRICT_SOURCE | SHARED_FLAG_MEDIA_HANDOVER);
		}
		bf_copy_same(&a->ps_flags, &A->media_flags, SHARED_FLAG_ICE);

		if (__init_stream(a))
			return -1;

		/* RTCP */
		if (!MEDIA_ISSET(B, RTCP_MUX)) {
			lb = lb->next;
			assert(lb != NULL);
			b = lb->data;
		}

		if (!MEDIA_ISSET(A, RTCP_MUX)) {
			a->rtcp_sink = NULL;
			PS_CLEAR(a, RTCP);
		}
		else {
			a->rtcp_sink = b;
			PS_SET(a, RTCP);
			PS_CLEAR(a, IMPLICIT_RTCP);
		}

		ax = a;

		/* if muxing, this is the fallback RTCP port. it also contains the RTCP
		 * crypto context */
		la = la->next;
		assert(la != NULL);
		a = la->data;

		a->rtp_sink = NULL;
		a->rtcp_sink = b;
		PS_CLEAR(a, RTP);
		PS_SET(a, RTCP);
		a->rtcp_sibling = NULL;
		bf_copy(&a->ps_flags, PS_FLAG_FALLBACK_RTCP, &ax->ps_flags, PS_FLAG_RTCP);

		ax->rtcp_sibling = a;

		if (sp) {
			if (!SP_ISSET(sp, IMPLICIT_RTCP)) {
				__fill_stream(a, &sp->rtcp_endpoint, port_off, sp);
				PS_CLEAR(a, IMPLICIT_RTCP);
			}
			else {
				__fill_stream(a, &sp->rtp_endpoint, port_off + 1, sp);
				PS_SET(a, IMPLICIT_RTCP);
			}
			bf_copy_same(&a->ps_flags, &sp->sp_flags,
					SHARED_FLAG_STRICT_SOURCE | SHARED_FLAG_MEDIA_HANDOVER);
		}
		bf_copy_same(&a->ps_flags, &A->media_flags, SHARED_FLAG_ICE);

		if (__init_stream(a))
			return -1;

		recording_setup_stream(ax); // RTP
		recording_setup_stream(a); // RTCP

		la = la->next;
		lb = lb->next;

		port_off += 2;
	}

	return 0;
}

static void __ice_offer(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other)
{
	if (!flags)
		return;

	/* we offer ICE by default */
	if (!MEDIA_ISSET(this, INITIALIZED))
		MEDIA_SET(this, ICE);
	if (flags->ice_remove)
		MEDIA_CLEAR(this, ICE);

	/* special case: if doing ICE on both sides and ice_force is not set, we cannot
	 * be sure that media will pass through us, so we have to disable certain features */
	if (MEDIA_ISSET(this, ICE) && MEDIA_ISSET(other, ICE) && !flags->ice_force) {
		ilog(LOG_DEBUG, "enabling passthrough mode");
		MEDIA_SET(this, PASSTHRU);
		MEDIA_SET(other, PASSTHRU);
		return;
	}

	/* determine roles (even if we don't actually do ICE) */
	/* this = receiver, other = sender */
	/* ICE_CONTROLLING is from our POV, the other ICE flags are from peer's POV */
	if (MEDIA_ISSET(this, ICE_LITE))
		MEDIA_SET(this, ICE_CONTROLLING);
	else if (!MEDIA_ISSET(this, INITIALIZED)) {
		if (flags->opmode == OP_OFFER)
			MEDIA_SET(this, ICE_CONTROLLING);
		else
			MEDIA_CLEAR(this, ICE_CONTROLLING);
	}

	/* roles are reversed for the other side */
	if (MEDIA_ISSET(other, ICE_LITE))
		MEDIA_SET(other, ICE_CONTROLLING);
	else if (!MEDIA_ISSET(other, INITIALIZED)) {
		if (flags->opmode == OP_OFFER)
			MEDIA_CLEAR(other, ICE_CONTROLLING);
		else
			MEDIA_SET(other, ICE_CONTROLLING);
	}
}

/* generates SDES parametes for outgoing SDP, which is our media "out" direction */
static void __generate_crypto(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other)
{
	struct crypto_params *cp = &this->sdes_out.params,
			     *cp_in = &this->sdes_in.params;

	if (!flags)
		return;

	if (!this->protocol || !this->protocol->srtp || MEDIA_ISSET(this, PASSTHRU)) {
		cp->crypto_suite = NULL;
		/* clear crypto for the this leg b/c we are in passthrough mode */
		MEDIA_CLEAR(this, DTLS);
		MEDIA_CLEAR(this, SDES);
		MEDIA_CLEAR(this, SETUP_PASSIVE);
		MEDIA_CLEAR(this, SETUP_ACTIVE);

		if (MEDIA_ISSET(this, PASSTHRU)) {
			/* clear crypto for the other leg as well b/c passthrough only
			 * works if it is done for both legs */
			MEDIA_CLEAR(other, DTLS);
			MEDIA_CLEAR(other, SDES);
			MEDIA_CLEAR(other, SETUP_PASSIVE);
			MEDIA_CLEAR(other, SETUP_ACTIVE);
		}

		return;
	}

	if (flags->opmode == OP_OFFER) {
		/* we always must offer actpass */
		MEDIA_SET(this, SETUP_PASSIVE);
		MEDIA_SET(this, SETUP_ACTIVE);
	}
	else {
		if (flags->dtls_passive && MEDIA_ISSET(this, SETUP_PASSIVE))
			MEDIA_CLEAR(this, SETUP_ACTIVE);
		/* if we can be active, we will, otherwise we'll be passive */
		if (MEDIA_ISSET(this, SETUP_ACTIVE))
			MEDIA_CLEAR(this, SETUP_PASSIVE);
	}

	if (!MEDIA_ISSET(this, INITIALIZED)) {
		/* we offer both DTLS and SDES by default */
		/* unless this is overridden by flags */
		if (!flags->dtls_off)
			MEDIA_SET(this, DTLS);
		if (!flags->sdes_off)
			MEDIA_SET(this, SDES);
		else
			goto skip_sdes;
	}
	else {
		/* if both SDES and DTLS are supported, we may use the flags to select one
		 * over the other */
		if (MEDIA_ARESET2(this, DTLS, SDES) && flags->dtls_off)
			MEDIA_CLEAR(this, DTLS);
		/* flags->sdes_off is ignored as we prefer DTLS by default */

		/* if we're talking to someone understanding DTLS, then skip the SDES stuff */
		if (MEDIA_ISSET(this, DTLS)) {
			MEDIA_CLEAR(this, SDES);
			goto skip_sdes;
		}
	}

	/* SDES parameters below */

	/* for answer case, otherwise we default to one */
	this->sdes_out.tag = cp_in->crypto_suite ? this->sdes_in.tag : 1;

	if (other->sdes_in.params.crypto_suite) {
		/* SRTP <> SRTP case, copy from other stream */
		cp->session_params = cp_in->session_params;
		crypto_params_copy(cp, &other->sdes_in.params, (flags->opmode == OP_OFFER) ? 1 : 0);
	}

	if (cp->crypto_suite)
		goto apply_sdes_flags;

	cp->crypto_suite = cp_in->crypto_suite;
	if (!cp->crypto_suite)
		cp->crypto_suite = &crypto_suites[0];
	random_string((unsigned char *) cp->master_key,
			cp->crypto_suite->master_key_len);
	random_string((unsigned char *) cp->master_salt,
			cp->crypto_suite->master_salt_len);
	/* mki = mki_len = 0 */
	cp->session_params.unencrypted_srtp = cp_in->session_params.unencrypted_srtp;
	cp->session_params.unencrypted_srtcp = cp_in->session_params.unencrypted_srtcp;
	cp->session_params.unauthenticated_srtp = cp_in->session_params.unauthenticated_srtp;

apply_sdes_flags:
	if (flags->sdes_unencrypted_srtp && flags->opmode == OP_OFFER)
		cp_in->session_params.unencrypted_srtp = cp->session_params.unencrypted_srtp = 1;
	else if (flags->sdes_encrypted_srtp)
		cp_in->session_params.unencrypted_srtp = cp->session_params.unencrypted_srtp = 0;
	if (flags->sdes_unencrypted_srtcp && flags->opmode == OP_OFFER)
		cp_in->session_params.unencrypted_srtcp = cp->session_params.unencrypted_srtcp = 1;
	else if (flags->sdes_encrypted_srtcp)
		cp_in->session_params.unencrypted_srtcp = cp->session_params.unencrypted_srtcp = 0;
	if (flags->sdes_unauthenticated_srtp && flags->opmode == OP_OFFER)
		cp_in->session_params.unauthenticated_srtp = cp->session_params.unauthenticated_srtp = 1;
	else if (flags->sdes_authenticated_srtp)
		cp_in->session_params.unauthenticated_srtp = cp->session_params.unauthenticated_srtp = 0;

skip_sdes:
	;
}


static void __disable_streams(struct call_media *media, unsigned int num_ports) {
	GList *l;
	struct packet_stream *ps;

	__num_media_streams(media, num_ports);

	for (l = media->streams.head; l; l = l->next) {
		ps = l->data;
		g_queue_clear(&ps->sfds);
		ps->selected_sfd = NULL;
	}
}

static void __rtcp_mux_logic(const struct sdp_ng_flags *flags, struct call_media *media,
		struct call_media *other_media)
{
	if (!flags)
		return;

	if (flags->opmode == OP_ANSWER) {
		/* default is to go with the client's choice, unless we were instructed not
		 * to do that in the offer (see below) */
		if (!MEDIA_ISSET(media, RTCP_MUX_OVERRIDE))
			bf_copy_same(&media->media_flags, &other_media->media_flags, MEDIA_FLAG_RTCP_MUX);

		return;
	}

	if (flags->opmode != OP_OFFER)
		return;


	/* default is to pass through the client's choice, unless our peer is already
	 * talking rtcp-mux, then we stick to that */
	if (!MEDIA_ISSET(media, RTCP_MUX))
		bf_copy_same(&media->media_flags, &other_media->media_flags, MEDIA_FLAG_RTCP_MUX);
	/* in our offer, we can override the client's choice */
	if (flags->rtcp_mux_offer)
		MEDIA_SET(media, RTCP_MUX);
	else if (flags->rtcp_mux_demux)
		MEDIA_CLEAR(media, RTCP_MUX);

	/* we can also control what's going to happen in the answer. it
	 * depends on what was offered, but by default we go with the other
	 * client's choice */
	MEDIA_CLEAR(other_media, RTCP_MUX_OVERRIDE);
	if (MEDIA_ISSET(other_media, RTCP_MUX)) {
		if (!MEDIA_ISSET(media, RTCP_MUX)) {
			/* rtcp-mux was offered, but we don't offer it ourselves.
			 * the answer will not accept rtcp-mux (wasn't offered).
			 * the default is to accept the offer, unless we want to
			 * explicitly reject it. */
			MEDIA_SET(other_media, RTCP_MUX_OVERRIDE);
			if (flags->rtcp_mux_reject)
				MEDIA_CLEAR(other_media, RTCP_MUX);
		}
		else {
			/* rtcp-mux was offered and we offer it too. default is
			 * to go with the other client's choice, unless we want to
			 * either explicitly accept it (possibly demux) or reject
			 * it (possible reverse demux). */
			if (flags->rtcp_mux_accept)
				MEDIA_SET(other_media, RTCP_MUX_OVERRIDE);
			else if (flags->rtcp_mux_reject) {
				MEDIA_SET(other_media, RTCP_MUX_OVERRIDE);
				MEDIA_CLEAR(other_media, RTCP_MUX);
			}
		}
	}
	else {
		/* rtcp-mux was not offered. we may offer it, but since it wasn't
		 * offered to us, we must not accept it. */
		MEDIA_SET(other_media, RTCP_MUX_OVERRIDE);
	}
}

static void __fingerprint_changed(struct call_media *m) {
	GList *l;
	struct packet_stream *ps;

	if (!m->fingerprint.hash_func)
		return;

	ilog(LOG_INFO, "DTLS fingerprint changed, restarting DTLS");

	for (l = m->streams.head; l; l = l->next) {
		ps = l->data;
		PS_CLEAR(ps, FINGERPRINT_VERIFIED);
		dtls_shutdown(ps);
	}
}

static void __set_all_tos(struct call *c) {
	GList *l;
	struct stream_fd *sfd;

	for (l = c->stream_fds.head; l; l = l->next) {
		sfd = l->data;
		set_tos(&sfd->socket, c->tos);
	}
}

static void __tos_change(struct call *call, const struct sdp_ng_flags *flags) {
	unsigned char new_tos;

	/* Handle TOS= parameter. Negative value = no change, not present or too large =
	 * revert to default, otherwise set specified value. We only do it in an offer, but
	 * then for both directions. */
	if (flags && (flags->opmode != OP_OFFER || flags->tos < 0))
		return;

	if (!flags || flags->tos > 255)
		new_tos = call->callmaster->conf.default_tos;
	else
		new_tos = flags->tos;

	if (new_tos == call->tos)
		return;

	call->tos = new_tos;
	__set_all_tos(call);
}

static void __init_interface(struct call_media *media, const str *ifname, int num_ports) {
	/* we're holding master_lock in W mode here, so we can safely ignore the
	 * atomic ops */

	if (!media->logical_intf)
		goto get;
	if (media->logical_intf->preferred_family != media->desired_family)
		goto get;
	if (!ifname || !ifname->s)
		return;
	if (!str_cmp_str(&media->logical_intf->name, ifname) || !str_cmp(ifname, ALGORITHM_ROUND_ROBIN_CALLS))
		return;
get:
	media->logical_intf = get_logical_interface(ifname, media->desired_family, num_ports);
	if (G_UNLIKELY(!media->logical_intf)) {
		/* legacy support */
		if (!str_cmp(ifname, "internal"))
			media->desired_family = __get_socket_family_enum(SF_IP4);
		else if (!str_cmp(ifname, "external"))
			media->desired_family = __get_socket_family_enum(SF_IP6);
		else
			ilog(LOG_WARNING, "Interface '"STR_FORMAT"' not found, using default", STR_FMT(ifname));
		media->logical_intf = get_logical_interface(NULL, media->desired_family, num_ports);
		if (!media->logical_intf) {
			ilog(LOG_WARNING, "Requested address family (%s) not supported",
					media->desired_family->name);
			media->logical_intf = get_logical_interface(NULL, NULL, 0);
		}
	}
//	media->local_intf = ifa = get_interface_address(media->logical_intf, media->desired_family);
//	if (!ifa) {
//		ilog(LOG_WARNING, "No usable address in interface '"STR_FORMAT"' found, using default",
//				STR_FMT(ifname));
//		media->local_intf = ifa = get_any_interface_address(media->logical_intf, media->desired_family);
//		media->desired_family = ifa->spec->address.addr.family;
//	}
}


// process received a=setup and related attributes
static void __dtls_logic(const struct sdp_ng_flags *flags,
		struct call_media *other_media, struct stream_params *sp)
{
	unsigned int tmp;

	/* active and passive are from our POV */
	tmp = other_media->media_flags;
	bf_copy(&other_media->media_flags, MEDIA_FLAG_SETUP_PASSIVE,
			&sp->sp_flags, SP_FLAG_SETUP_ACTIVE);
	bf_copy(&other_media->media_flags, MEDIA_FLAG_SETUP_ACTIVE,
			&sp->sp_flags, SP_FLAG_SETUP_PASSIVE);

	if (flags) {
		/* Special case: if this is an offer and actpass is being offered (as it should),
		 * we would normally choose to be active. However, if this is a reinvite and we
		 * were passive previously, we should retain this role. */
		if (flags && flags->opmode == OP_OFFER && MEDIA_ARESET2(other_media, SETUP_ACTIVE, SETUP_PASSIVE)
				&& (tmp & (MEDIA_FLAG_SETUP_ACTIVE | MEDIA_FLAG_SETUP_PASSIVE))
				== MEDIA_FLAG_SETUP_PASSIVE)
			MEDIA_CLEAR(other_media, SETUP_ACTIVE);
		/* if passive mode is requested, honour it if we can */
		if (flags && flags->dtls_passive && MEDIA_ISSET(other_media, SETUP_PASSIVE))
			MEDIA_CLEAR(other_media, SETUP_ACTIVE);
	}

	if (memcmp(&other_media->fingerprint, &sp->fingerprint, sizeof(sp->fingerprint))) {
		__fingerprint_changed(other_media);
		other_media->fingerprint = sp->fingerprint;
	}
	MEDIA_CLEAR(other_media, DTLS);
	if (MEDIA_ISSET2(other_media, SETUP_PASSIVE, SETUP_ACTIVE)
			&& other_media->fingerprint.hash_func)
		MEDIA_SET(other_media, DTLS);
}

static void __rtp_payload_types(struct call_media *media, GQueue *types) {
	struct rtp_payload_type *pt;
	struct call *call = media->call;

	/* we steal the entire list to avoid duplicate allocs */
	while ((pt = g_queue_pop_head(types))) {
		/* but we must duplicate the contents */
		call_str_cpy(call, &pt->encoding_with_params, &pt->encoding_with_params);
		call_str_cpy(call, &pt->encoding, &pt->encoding);
		call_str_cpy(call, &pt->encoding_parameters, &pt->encoding_parameters);
		g_hash_table_replace(media->rtp_payload_types, &pt->payload_type, pt);
	}
}

static void __ice_start(struct call_media *media) {
	if (MEDIA_ISSET(media, PASSTHRU)) {
		ice_shutdown(&media->ice_agent);
		return;
	}
	if (!MEDIA_ISSET(media, ICE)) /* don't init new ICE agent but leave it running if there is one */
		return;

	ice_agent_init(&media->ice_agent, media);
}

static int get_algorithm_num_ports(GQueue *streams, char *algorithm) {
	unsigned int algorithm_ports = 0;
	struct stream_params *sp;
	GList *media_iter;

	if (algorithm == NULL) {
		return 0;
	}

	for (media_iter = streams->head; media_iter; media_iter = media_iter->next) {
		sp = media_iter->data;

		if (!str_cmp(&sp->direction[0], algorithm)) {
			algorithm_ports += sp->consecutive_ports;
		}

		if (!str_cmp(&sp->direction[1], algorithm)) {
			algorithm_ports += sp->consecutive_ports;
		}
	}

	// XXX only do *=2 for RTP streams?
	algorithm_ports *= 2;

	return algorithm_ports;
}

static void __endpoint_loop_protect(struct stream_params *sp, struct call_media *media) {
	struct intf_address intf_addr;

	/* check if the advertised endpoint is one of our own addresses. this can
	 * happen by mistake, or it's expected when ICE is in use and passthrough
	 * mode is enabled (in particular when using ICE=force-relay). we still
	 * accept such an endpoint, but flag it for potential loop, which we will
	 * check for later.
	 * */

	intf_addr.type = socktype_udp;
//	if (other_media->protocol && other_media->protocol->tcp)
//		intf_addr.type = socktype_tcp;
	intf_addr.addr = sp->rtp_endpoint.address;
	if (!is_local_endpoint(&intf_addr, sp->rtp_endpoint.port))
		return;

	ilog(LOG_DEBUG, "Detected local endpoint advertised by remote client, "
			"enabling loop checking");

	MEDIA_SET(media, LOOP_CHECK);
}

/* called with call->master_lock held in W */
int monologue_offer_answer(struct call_monologue *other_ml, GQueue *streams,
		const struct sdp_ng_flags *flags)
{
	struct stream_params *sp;
	GList *media_iter, *ml_media, *other_ml_media;
	struct call_media *media, *other_media;
	unsigned int num_ports;
	unsigned int rr_calls_ports;
	struct call_monologue *monologue;
	struct endpoint_map *em;
	struct call *call;

	/* we must have a complete dialogue, even though the to-tag (monologue->tag)
	 * may not be known yet */
	if (!other_ml) {
		ilog(LOG_ERROR, "Incomplete dialogue association");
		return -1;
	}

	monologue = other_ml->active_dialogue;
	call = monologue->call;

	call->last_signal = poller_now;
	call->deleted = 0;

	// get the total number of ports needed for ALGORITHM_ROUND_ROBIN_CALLS algorithm
	rr_calls_ports = get_algorithm_num_ports(streams, ALGORITHM_ROUND_ROBIN_CALLS);

	__C_DBG("this="STR_FORMAT" other="STR_FORMAT, STR_FMT(&monologue->tag), STR_FMT(&other_ml->tag));

	__tos_change(call, flags);

	ml_media = other_ml_media = NULL;

	for (media_iter = streams->head; media_iter; media_iter = media_iter->next) {
		sp = media_iter->data;
		__C_DBG("processing media stream #%u", sp->index);
		__C_DBG("free ports needed for round-robin-calls, left for this call %u", rr_calls_ports);

		/* first, check for existance of call_media struct on both sides of
		 * the dialogue */
		media = __get_media(monologue, &ml_media, sp);
		other_media = __get_media(other_ml, &other_ml_media, sp);
		/* OTHER is the side which has sent the message. SDP parameters in
		 * "sp" are as advertised by OTHER side. The message will be sent to
		 * THIS side. Parameters sent to THIS side may be overridden by
		 * what's in "flags". If this is an answer, or if we have talked to
		 * THIS side (recipient) before, then the structs will be populated with
		 * details already. */

		if (flags && flags->opmode == OP_OFFER && flags->reset) {
			MEDIA_CLEAR(media, INITIALIZED);
			MEDIA_CLEAR(other_media, INITIALIZED);
			if (media->ice_agent)
				ice_restart(media->ice_agent);
			if (other_media->ice_agent)
				ice_restart(other_media->ice_agent);
		}

		/* deduct protocol from stream parameters received */
		if (other_media->protocol != sp->protocol) {
			other_media->protocol = sp->protocol;
			/* if the endpoint changes the protocol, we reset the other side's
			 * protocol as well. this lets us remember our previous overrides,
			 * but also lets endpoints re-negotiate. */
			media->protocol = NULL;
		}
		/* default is to leave the protocol unchanged */
		if (!media->protocol)
			media->protocol = other_media->protocol;
		/* allow override of outgoing protocol even if we know it already */
		/* but only if this is an RTP-based protocol */
		if (flags && flags->transport_protocol
				&& other_media->protocol && other_media->protocol->rtp)
			media->protocol = flags->transport_protocol;

		__endpoint_loop_protect(sp, other_media);

		if (sp->rtp_endpoint.port) {
			/* copy parameters advertised by the sender of this message */
			bf_copy_same(&other_media->media_flags, &sp->sp_flags,
					SHARED_FLAG_RTCP_MUX | SHARED_FLAG_ASYMMETRIC | SHARED_FLAG_UNIDIRECTIONAL |
					SHARED_FLAG_ICE | SHARED_FLAG_TRICKLE_ICE | SHARED_FLAG_ICE_LITE);

			crypto_params_copy(&other_media->sdes_in.params, &sp->crypto, 1);
			other_media->sdes_in.tag = sp->sdes_tag;
			if (other_media->sdes_in.params.crypto_suite)
				MEDIA_SET(other_media, SDES);
		}

		__rtp_payload_types(media, &sp->rtp_payload_types);

		/* send and recv are from our POV */
		bf_copy_same(&media->media_flags, &sp->sp_flags,
				SP_FLAG_SEND | SP_FLAG_RECV);
		bf_copy(&other_media->media_flags, MEDIA_FLAG_RECV, &sp->sp_flags, SP_FLAG_SEND);
		bf_copy(&other_media->media_flags, MEDIA_FLAG_SEND, &sp->sp_flags, SP_FLAG_RECV);

		if (sp->rtp_endpoint.port) {
			/* DTLS stuff */
			__dtls_logic(flags, other_media, sp);

			/* control rtcp-mux */
			__rtcp_mux_logic(flags, media, other_media);

			/* SDES and DTLS */
			__generate_crypto(flags, media, other_media);

			/* deduct address family from stream parameters received */
			other_media->desired_family = sp->rtp_endpoint.address.family;
			/* for outgoing SDP, use "direction"/DF or default to what was offered */
			if (!media->desired_family)
				media->desired_family = other_media->desired_family;
			if (sp->desired_family)
				media->desired_family = sp->desired_family;
		}

		/* local interface selection */
		__init_interface(media, &sp->direction[1], rr_calls_ports);
		__init_interface(other_media, &sp->direction[0], rr_calls_ports);

		if (media->logical_intf == NULL || other_media->logical_intf == NULL) {
			goto error_intf;
		}

		/* ICE stuff - must come after interface and address family selection */
		__ice_offer(flags, media, other_media);
		__ice_start(other_media);
		__ice_start(media);



		/* we now know what's being advertised by the other side */
		MEDIA_SET(other_media, INITIALIZED);


		/* determine number of consecutive ports needed locally.
		 * XXX only do *=2 for RTP streams? */
		num_ports = sp->consecutive_ports;
		num_ports *= 2;


		if (!sp->rtp_endpoint.port) {
			/* Zero port: stream has been rejected.
			 * RFC 3264, chapter 6:
			 * If a stream is rejected, the offerer and answerer MUST NOT
			 * generate media (or RTCP packets) for that stream. */
			__disable_streams(media, num_ports);
			__disable_streams(other_media, num_ports);
			goto init;
		}
		if (is_addr_unspecified(&sp->rtp_endpoint.address) && !is_trickle_ice_address(&sp->rtp_endpoint)) {
			/* Zero endpoint address, equivalent to setting the media stream
			 * to sendonly or inactive */
			MEDIA_CLEAR(media, RECV);
			MEDIA_CLEAR(other_media, SEND);
		}


		/* get that many ports for each side, and one packet stream for each port, then
		 * assign the ports to the streams */
		em = __get_endpoint_map(media, num_ports, &sp->rtp_endpoint, flags);
		if (!em) {
			goto error_ports;
		} else {
			// update the ports needed for ALGORITHM_ROUND_ROBIN_CALLS algorithm
			if (str_cmp(&sp->direction[1], ALGORITHM_ROUND_ROBIN_CALLS) == 0) {
				rr_calls_ports -= num_ports;
			}
		}

		__num_media_streams(media, num_ports);
		__assign_stream_fds(media, &em->intf_sfds);

		if (__num_media_streams(other_media, num_ports)) {
			/* new streams created on OTHER side. normally only happens in
			 * initial offer. create a wildcard endpoint_map to be filled in
			 * when the answer comes. */
			if (__wildcard_endpoint_map(other_media, num_ports))
				goto error_ports;

			// update the ports needed for ALGORITHM_ROUND_ROBIN_CALLS algorithm
			if (str_cmp(&sp->direction[0], ALGORITHM_ROUND_ROBIN_CALLS) == 0) {
				rr_calls_ports -= num_ports;
			}
		}

init:
		if (__init_streams(media, other_media, NULL))
			return -1;
		if (__init_streams(other_media, media, sp))
			return -1;

		/* we are now ready to fire up ICE if so desired and requested */
		ice_update(other_media->ice_agent, sp);
		ice_update(media->ice_agent, NULL); /* this is in case rtcp-mux has changed */

		recording_setup_media(other_media);
	}

	return 0;

error_ports:
	ilog(LOG_ERR, "Error allocating media ports");
	return ERROR_NO_FREE_PORTS;

error_intf:
	ilog(LOG_ERR, "Error finding logical interface with free ports");
	return ERROR_NO_FREE_LOGS;
}


static int __rtp_stats_sort(const void *ap, const void *bp) {
	const struct rtp_stats *a = ap, *b = bp;

	/* descending order */
	if (atomic64_get(&a->packets) > atomic64_get(&b->packets))
		return -1;
	if (atomic64_get(&a->packets) < atomic64_get(&b->packets))
		return 1;
	return 0;
}

const struct rtp_payload_type *__rtp_stats_codec(struct call_media *m) {
	struct packet_stream *ps;
	GList *values;
	struct rtp_stats *rtp_s;
	const struct rtp_payload_type *rtp_pt = NULL;

	/* we only use the primary packet stream for the time being */
	if (!m->streams.head)
		return NULL;

	ps = m->streams.head->data;

	values = g_hash_table_get_values(ps->rtp_stats);
	if (!values)
		return NULL;

	values = g_list_sort(values, __rtp_stats_sort);

	/* payload type with the most packets */
	rtp_s = values->data;
	if (atomic64_get(&rtp_s->packets) == 0)
		goto out;

	rtp_pt = rtp_payload_type(rtp_s->payload_type, m->rtp_payload_types);

out:
	g_list_free(values);
	return rtp_pt; /* may be NULL */
}

void add_total_calls_duration_in_interval(struct callmaster *cm,
		struct timeval *interval_tv) {
	struct timeval ongoing_calls_dur = add_ongoing_calls_dur_in_interval(cm,
			&cm->latest_graphite_interval_start, interval_tv);

	mutex_lock(&cm->totalstats_interval.total_calls_duration_lock);
	timeval_add(&cm->totalstats_interval.total_calls_duration_interval,
			&cm->totalstats_interval.total_calls_duration_interval,
			&ongoing_calls_dur);
	mutex_unlock(&cm->totalstats_interval.total_calls_duration_lock);
}

static struct timeval add_ongoing_calls_dur_in_interval(struct callmaster *m,
		struct timeval *interval_start, struct timeval *interval_duration) {
	GHashTableIter iter;
	gpointer key, value;
	struct timeval call_duration, res = {0};
	struct call *call;
	struct call_monologue *ml;

	rwlock_lock_r(&m->hashlock);
	g_hash_table_iter_init(&iter, m->callhash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		call = (struct call*) value;
		if (!call->monologues.head || IS_FOREIGN_CALL(call))
			continue;
		ml = call->monologues.head->data;
		if (timercmp(interval_start, &ml->started, >)) {
			timeval_add(&res, &res, interval_duration);
		} else {
			timeval_subtract(&call_duration, &g_now, &ml->started);
			timeval_add(&res, &res, &call_duration);
		}
	}
	rwlock_unlock_r(&m->hashlock);
	return res;
}

/* called lock-free, but must hold a reference to the call */
void call_destroy(struct call *c) {
	struct callmaster *m;
	struct packet_stream *ps=0;
	struct stream_fd *sfd;
	struct poller *p;
	GList *l;
	int ret;
	struct call_monologue *ml;
	struct call_media *md;
	GList *k, *o;
	const struct rtp_payload_type *rtp_pt;

	if (!c) {
		return;
	}

	m = c->callmaster;
	p = m->poller;

	rwlock_lock_w(&m->hashlock);
	ret = (g_hash_table_lookup(m->callhash, &c->callid) == c);
	if (ret)
		g_hash_table_remove(m->callhash, &c->callid);
	rwlock_unlock_w(&m->hashlock);

	// if call not found in callhash => previously deleted
	if (!ret)
		return;

	obj_put(c);


	statistics_update_foreignown_dec(c);

	if (IS_OWN_CALL(c)) {
		redis_delete(c, m->conf.redis_write);
	}

	rwlock_lock_w(&c->master_lock);
	/* at this point, no more packet streams can be added */

	if (!IS_OWN_CALL(c))
		goto no_stats_output;

	ilog(LOG_INFO, "Final packet stats:");

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;

		ilog(LOG_INFO, "--- Tag '"STR_FORMAT"'%s"STR_FORMAT"%s, created "
				"%u:%02u ago for branch '"STR_FORMAT"', in dialogue with '"STR_FORMAT"'",
				STR_FMT(&ml->tag),
				ml->label.s ? " (label '" : "",
				STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
				ml->label.s ? "')" : "",
				(unsigned int) (poller_now - ml->created) / 60,
				(unsigned int) (poller_now - ml->created) % 60,
				STR_FMT(&ml->viabranch),
				ml->active_dialogue ? ml->active_dialogue->tag.len : 6,
				ml->active_dialogue ? ml->active_dialogue->tag.s : "(none)");

		for (k = ml->medias.head; k; k = k->next) {
			md = k->data;

			rtp_pt = __rtp_stats_codec(md);
#define MLL_PREFIX "------ Media #%u ("STR_FORMAT" over %s) using " /* media log line prefix */
#define MLL_COMMON /* common args */						\
				md->index,				\
				STR_FMT(&md->type),			\
				md->protocol ? md->protocol->name : "(unknown)"
			if (!rtp_pt)
				ilog(LOG_INFO, MLL_PREFIX "unknown codec", MLL_COMMON);
			else
				ilog(LOG_INFO, MLL_PREFIX STR_FORMAT, MLL_COMMON,
						STR_FMT(&rtp_pt->encoding_with_params));

			for (o = md->streams.head; o; o = o->next) {
				ps = o->data;

				if (PS_ISSET(ps, FALLBACK_RTCP))
					continue;

				char *addr = sockaddr_print_buf(&ps->endpoint.address);
				char *local_addr = ps->selected_sfd ? sockaddr_print_buf(&ps->selected_sfd->socket.local.address) : "0.0.0.0";

				ilog(LOG_INFO, "--------- Port %15s:%-5u <> %15s:%-5u%s, SSRC %" PRIu32 ", "
						""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" ts",
						local_addr,
						(unsigned int) (ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
						addr, ps->endpoint.port,
						(!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
						ps->ssrc_in ? ps->ssrc_in->parent->ssrc : 0,
						atomic64_get(&ps->stats.packets),
						atomic64_get(&ps->stats.bytes),
						atomic64_get(&ps->stats.errors),
						g_now.tv_sec - atomic64_get(&ps->last_packet));

				statistics_update_totals(m,ps);

			}

			ice_shutdown(&md->ice_agent);
		}
	}

	k = g_hash_table_get_values(c->ssrc_hash->ht);
	for (l = k; l; l = l->next) {
		struct ssrc_entry *se = l->data;

		if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
			continue;

		ilog(LOG_INFO, "--- SSRC %" PRIu32 "", se->ssrc);
		ilog(LOG_INFO, "------ Average MOS %" PRIu64 ".%" PRIu64 ", "
				"lowest MOS %" PRIu64 ".%" PRIu64 " (at %u:%02u), "
				"highest MOS %" PRIu64 ".%" PRIu64 " (at %u:%02u)",
			se->average_mos.mos / se->stats_blocks.length / 10,
			se->average_mos.mos / se->stats_blocks.length % 10,
			se->lowest_mos->mos / 10,
			se->lowest_mos->mos % 10,
			(unsigned int) (timeval_diff(&se->lowest_mos->reported, &c->created) / 1000000) / 60,
			(unsigned int) (timeval_diff(&se->lowest_mos->reported, &c->created) / 1000000) % 60,
			se->highest_mos->mos / 10,
			se->highest_mos->mos % 10,
			(unsigned int) (timeval_diff(&se->highest_mos->reported, &c->created) / 1000000) / 60,
			(unsigned int) (timeval_diff(&se->highest_mos->reported, &c->created) / 1000000) % 60);
	}
	g_list_free(k);

no_stats_output:
	statistics_update_oneway(c);

	cdr_update_entry(c);

	for (l = c->streams.head; l; l = l->next) {
		ps = l->data;

		__unkernelize(ps);
		dtls_shutdown(ps);
		ps->selected_sfd = NULL;
		g_queue_clear(&ps->sfds);
		crypto_cleanup(&ps->crypto);

		ps->rtp_sink = NULL;
		ps->rtcp_sink = NULL;
	}

	while (c->stream_fds.head) {
		sfd = g_queue_pop_head(&c->stream_fds);
		poller_del_item(p, sfd->socket.fd);
		obj_put(sfd);
	}

	recording_finish(c);

	rwlock_unlock_w(&c->master_lock);
}


/* XXX move these */
int call_stream_address46(char *o, struct packet_stream *ps, enum stream_address_format format,
		int *len, const struct local_intf *ifa)
{
	struct packet_stream *sink;
	int l = 0;
	const struct intf_address *ifa_addr;

	if (!ifa) {
		if (ps->selected_sfd)
			ifa = ps->selected_sfd->local_intf;
		else
			ifa = get_any_interface_address(ps->media->logical_intf, ps->media->desired_family);
	}
	ifa_addr = &ifa->spec->local_address;

	sink = packet_stream_sink(ps);

	if (format == SAF_NG)
		l += sprintf(o + l, "%s ", ifa_addr->addr.family->rfc_name);

	if (is_addr_unspecified(&sink->advertised_endpoint.address)
			&& !is_trickle_ice_address(&sink->advertised_endpoint))
		l += sprintf(o + l, "%s", ifa_addr->addr.family->unspec_string);
	else
		l += sprintf(o + l, "%s", sockaddr_print_buf(&ifa->advertised_address.addr));

	*len = l;
	return ifa_addr->addr.family->af;
}


static void __call_free(void *p) {
	struct call *c = p;
	struct call_monologue *m;
	struct call_media *md;
	struct packet_stream *ps;
	struct endpoint_map *em;

	__C_DBG("freeing call struct");

	call_buffer_free(&c->buffer);
	mutex_destroy(&c->buffer_lock);
	rwlock_destroy(&c->master_lock);
	obj_put(c->dtls_cert);

	while (c->monologues.head) {
		m = g_queue_pop_head(&c->monologues);

		g_queue_clear(&m->medias);
		g_hash_table_destroy(m->other_tags);
		g_slice_free1(sizeof(*m), m);
	}

	while (c->medias.head) {
		md = g_queue_pop_head(&c->medias);

		crypto_params_cleanup(&md->sdes_in.params);
		crypto_params_cleanup(&md->sdes_out.params);
		g_queue_clear(&md->streams);
		g_queue_clear(&md->endpoint_maps);
		g_hash_table_destroy(md->rtp_payload_types);
		g_slice_free1(sizeof(*md), md);
	}

	while (c->endpoint_maps.head) {
		em = g_queue_pop_head(&c->endpoint_maps);

		g_queue_clear_full(&em->intf_sfds, (void *) free_intf_list);
		g_slice_free1(sizeof(*em), em);
	}

	g_hash_table_destroy(c->tags);
	g_hash_table_destroy(c->viabranches);
	free_ssrc_hash(&c->ssrc_hash);

	while (c->streams.head) {
		ps = g_queue_pop_head(&c->streams);
		crypto_cleanup(&ps->crypto);
		g_queue_clear(&ps->sfds);
		g_hash_table_destroy(ps->rtp_stats);
		g_slice_free1(sizeof(*ps), ps);
	}

	assert(c->stream_fds.head == NULL);
}

static struct call *call_create(const str *callid, struct callmaster *m) {
	struct call *c;

	ilog(LOG_NOTICE, "Creating new call");
	c = obj_alloc0("call", sizeof(*c), __call_free);
	c->callmaster = m;
	mutex_init(&c->buffer_lock);
	call_buffer_init(&c->buffer);
	rwlock_init(&c->master_lock);
	c->tags = g_hash_table_new(str_hash, str_equal);
	c->viabranches = g_hash_table_new(str_hash, str_equal);
	call_str_cpy(c, &c->callid, callid);
	c->created = g_now;
	c->dtls_cert = dtls_cert();
	c->tos = m->conf.default_tos;
	c->ssrc_hash = create_ssrc_hash();

	return c;
}

/* returns call with master_lock held in W */
struct call *call_get_or_create(const str *callid, struct callmaster *m, enum call_type type) {
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

		if (type == CT_FOREIGN_CALL)  /* foreign call*/
					c->foreign_call = 1;

		statistics_update_foreignown_inc(m,c);

		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_w(&m->hashlock);
	}
	else {
		obj_hold(c);
		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_r(&m->hashlock);
	}

	log_info_call(c);
	return c;
}

/* returns call with master_lock held in W, or NULL if not found */
struct call *call_get(const str *callid, struct callmaster *m) {
	struct call *ret;

	rwlock_lock_r(&m->hashlock);
	ret = g_hash_table_lookup(m->callhash, callid);
	if (!ret) {
		rwlock_unlock_r(&m->hashlock);
		return NULL;
	}

	rwlock_lock_w(&ret->master_lock);
	obj_hold(ret);
	rwlock_unlock_r(&m->hashlock);

	log_info_call(ret);
	return ret;
}

/* returns call with master_lock held in W, or possibly NULL iff opmode == OP_ANSWER */
struct call *call_get_opmode(const str *callid, struct callmaster *m, enum call_opmode opmode) {
	if (opmode == OP_OFFER)
		return call_get_or_create(callid, m, CT_OWN_CALL);
	return call_get(callid, m);
}

/* must be called with call->master_lock held in W */
struct call_monologue *__monologue_create(struct call *call) {
	struct call_monologue *ret;

	__C_DBG("creating new monologue");
	ret = uid_slice_alloc0(ret, &call->monologues);

	ret->call = call;
	ret->created = poller_now;
	ret->other_tags = g_hash_table_new(str_hash, str_equal);

	g_queue_init(&ret->medias);
	gettimeofday(&ret->started, NULL);

	return ret;
}

/* must be called with call->master_lock held in W */
void __monologue_tag(struct call_monologue *ml, const str *tag) {
	struct call *call = ml->call;

	__C_DBG("tagging monologue with '"STR_FORMAT"'", STR_FMT(tag));
	call_str_cpy(call, &ml->tag, tag);
	g_hash_table_insert(call->tags, &ml->tag, ml);
}
void __monologue_viabranch(struct call_monologue *ml, const str *viabranch) {
	struct call *call = ml->call;

	if (!viabranch)
		return;

	__C_DBG("tagging monologue with viabranch '"STR_FORMAT"'", STR_FMT(viabranch));
	if (ml->viabranch.s)
		g_hash_table_remove(call->viabranches, &ml->viabranch);
	call_str_cpy(call, &ml->viabranch, viabranch);
	g_hash_table_insert(call->viabranches, &ml->viabranch, ml);
}

/* must be called with call->master_lock held in W */
static void __monologue_unkernelize(struct call_monologue *monologue) {
	GList *l, *m;
	struct call_media *media;
	struct packet_stream *stream;

	if (!monologue)
		return;

	monologue->deleted = 0; /* not really related, but indicates activity, so cancel
				   any pending deletion */

	for (l = monologue->medias.head; l; l = l->next) {
		media = l->data;

		for (m = media->streams.head; m; m = m->next) {
			stream = m->data;
			__stream_unconfirm(stream);
			if (stream->rtp_sink)
				__stream_unconfirm(stream->rtp_sink);
			if (stream->rtcp_sink)
				__stream_unconfirm(stream->rtcp_sink);
		}
	}
}

/* call locked in R */
void call_media_unkernelize(struct call_media *media) {
	GList *m;
	struct packet_stream *stream;

	for (m = media->streams.head; m; m = m->next) {
		stream = m->data;
		unkernelize(stream);
		unkernelize(stream->rtp_sink);
		unkernelize(stream->rtcp_sink);
	}
}

/* must be called with call->master_lock held in W */
static void __monologue_destroy(struct call_monologue *monologue) {
	struct call *call;
	struct call_monologue *dialogue;
	GList *l;

	call = monologue->call;

	g_hash_table_remove(call->tags, &monologue->tag);

	l = g_hash_table_get_values(monologue->other_tags);

	while (l) {
		dialogue = l->data;
		l = g_list_delete_link(l, l);
		g_hash_table_remove(dialogue->other_tags, &monologue->tag);
		if (!g_hash_table_size(dialogue->other_tags))
			__monologue_destroy(dialogue);
	}

	monologue->deleted = 0;
}

/* must be called with call->master_lock held in W */
static int monologue_destroy(struct call_monologue *ml) {
	struct call *c = ml->call;

	__monologue_destroy(ml);

	if (!g_hash_table_size(c->tags)) {
		ilog(LOG_INFO, "Call branch '"STR_FORMAT"' (%s"STR_FORMAT"%svia-branch '"STR_FORMAT"') "
				"deleted, no more branches remaining",
				STR_FMT(&ml->tag),
				ml->label.s ? "label '" : "",
				STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
				ml->label.s ? "', " : "",
				STR_FMT0(&ml->viabranch));
		return 1; /* destroy call */
	}

	ilog(LOG_INFO, "Call branch '"STR_FORMAT"' (%s"STR_FORMAT"%svia-branch '"STR_FORMAT"') deleted",
			STR_FMT(&ml->tag),
			ml->label.s ? "label '" : "",
			STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
			ml->label.s ? "', " : "",
			STR_FMT0(&ml->viabranch));
	return 0;
}

/* must be called with call->master_lock held in W */
static void __fix_other_tags(struct call_monologue *one) {
	struct call_monologue *two;

	if (!one || !one->tag.len)
		return;
	two = one->active_dialogue;
	if (!two || !two->tag.len)
		return;

	g_hash_table_insert(one->other_tags, &two->tag, two);
	g_hash_table_insert(two->other_tags, &one->tag, one);
}

/* must be called with call->master_lock held in W */
static struct call_monologue *call_get_monologue(struct call *call, const str *fromtag, const str *totag,
		const str *viabranch)
{
	struct call_monologue *ret, *os;

	__C_DBG("getting monologue for tag '"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(&call->callid));
	ret = g_hash_table_lookup(call->tags, fromtag);
	if (!ret) {
		ret = __monologue_create(call);
		__monologue_tag(ret, fromtag);
		goto new_branch;
	}

	__C_DBG("found existing monologue");
	__monologue_unkernelize(ret);
	__monologue_unkernelize(ret->active_dialogue);

	if (!viabranch)
		goto ok_check_tag;

	/* check the viabranch. if it's not known, then this is a branched offer and we need
	 * to create a new "other side" for this branch. */
	if (!ret->active_dialogue->viabranch.s) {
		/* previous "other side" hasn't been tagged with the via-branch, so we'll just
		 * use this one and tag it */
		__monologue_viabranch(ret->active_dialogue, viabranch);
		goto ok_check_tag;
	}
	if (!str_cmp_str(&ret->active_dialogue->viabranch, viabranch))
		goto ok_check_tag; /* dialogue still intact */
	os = g_hash_table_lookup(call->viabranches, viabranch);
	if (os) {
		/* previously seen branch. use it */
		__monologue_unkernelize(os);
		os->active_dialogue = ret;
		ret->active_dialogue = os;
		goto ok_check_tag;
	}

	/* we need both sides of the dialogue even in the initial offer, so create
	 * another monologue without to-tag (to be filled in later) */
new_branch:
	__C_DBG("create new \"other side\" monologue for viabranch "STR_FORMAT, STR_FMT0(viabranch));
	os = __monologue_create(call);
	ret->active_dialogue = os;
	os->active_dialogue = ret;
	__monologue_viabranch(os, viabranch);

ok_check_tag:
	os = ret->active_dialogue;
	if (totag && totag->s && !os->tag.s) {
		__monologue_tag(os, totag);
		__fix_other_tags(ret);
	}
	return ret;
}

/* must be called with call->master_lock held in W */
static struct call_monologue *call_get_dialogue(struct call *call, const str *fromtag, const str *totag,
		const str *viabranch)
{
	struct call_monologue *ft, *tt;

	__C_DBG("getting dialogue for tags '"STR_FORMAT"'<>'"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(totag), STR_FMT(&call->callid));

	/* we start with the to-tag. if it's not known, we treat it as a branched offer */
	tt = g_hash_table_lookup(call->tags, totag);
	if (!tt)
		return call_get_monologue(call, fromtag, totag, viabranch);

	/* if the from-tag is known already, return that */
	ft = g_hash_table_lookup(call->tags, fromtag);
	if (ft) {
		__C_DBG("found existing dialogue");

		/* make sure that the dialogue is actually intact */
		/* fastpath for a common case */
		if (!str_cmp_str(totag, &ft->active_dialogue->tag))
			goto done;
	}
	else {
		/* perhaps we can determine the monologue from the viabranch */
		if (viabranch)
			ft = g_hash_table_lookup(call->viabranches, viabranch);
	}

	if (!ft) {
		/* if we don't have a fromtag monologue yet, we can use a half-complete dialogue
		 * from the totag if there is one. otherwise we have to create a new one. */
		ft = tt->active_dialogue;
		if (ft->tag.s)
			ft = __monologue_create(call);
	}

	/* the fromtag monologue may be newly created, or half-complete from the totag, or
	 * derived from the viabranch. */
	if (!ft->tag.s)
		__monologue_tag(ft, fromtag);

	__monologue_unkernelize(ft->active_dialogue);
	__monologue_unkernelize(tt->active_dialogue);
	ft->active_dialogue = tt;
	tt->active_dialogue = ft;
	__fix_other_tags(ft);

done:
	__monologue_unkernelize(ft);
	__monologue_unkernelize(ft->active_dialogue);
	return ft;
}

/* fromtag and totag strictly correspond to the directionality of the message, not to the actual
 * SIP headers. IOW, the fromtag corresponds to the monologue sending this message, even if the
 * tag is actually from the TO header of the SIP message (as it would be in a 200 OK) */
struct call_monologue *call_get_mono_dialogue(struct call *call, const str *fromtag, const str *totag,
		const str *viabranch)
{
	if (!totag || !totag->s) /* initial offer */
		return call_get_monologue(call, fromtag, NULL, viabranch);
	return call_get_dialogue(call, fromtag, totag, viabranch);
}


int call_delete_branch(struct callmaster *m, const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay)
{
	struct call *c;
	struct call_monologue *ml;
	int ret;
	const str *match_tag;
	GList *i;

	if (delete_delay < 0)
		delete_delay = m->conf.delete_delay;

	c = call_get(callid, m);
	if (!c) {
		ilog(LOG_INFO, "Call-ID to delete not found");
		goto err;
	}

	for (i = c->monologues.head; i; i = i->next) {
		ml = i->data;
		gettimeofday(&(ml->terminated), NULL);
		ml->term_reason = REGULAR;
	}

	if (!fromtag || !fromtag->len)
		goto del_all;

	if ((!totag || !totag->len) && branch && branch->len) {
		// try a via-branch match
		ml = g_hash_table_lookup(c->viabranches, branch);
		if (ml)
			goto do_delete;
	}

	match_tag = (totag && totag->len) ? totag : fromtag;

	ml = g_hash_table_lookup(c->tags, match_tag);
	if (!ml) {
		if (branch && branch->len) {
			// also try a via-branch match here
			ml = g_hash_table_lookup(c->viabranches, branch);
			if (ml)
				goto do_delete;
		}

		// last resort: try the from-tag if we tried the to-tag before and see
		// if the associated dialogue has an empty tag (unknown)
		if (match_tag == totag) {
			ml = g_hash_table_lookup(c->tags, fromtag);
			if (ml && ml->active_dialogue && ml->active_dialogue->tag.len == 0)
				goto do_delete;
		}

		ilog(LOG_INFO, "Tag '"STR_FORMAT"' in delete message not found, ignoring",
				STR_FMT(match_tag));
		goto err;
	}

do_delete:
	if (output)
		ng_call_stats(c, fromtag, totag, output, NULL);

	if (delete_delay > 0) {
		ilog(LOG_INFO, "Scheduling deletion of call branch '"STR_FORMAT"' "
				"(via-branch '"STR_FORMAT"') in %d seconds",
				STR_FMT(&ml->tag), STR_FMT0(branch), delete_delay);
		ml->deleted = poller_now + delete_delay;
		if (!c->ml_deleted || c->ml_deleted > ml->deleted)
			c->ml_deleted = ml->deleted;
	}
	else {
		ilog(LOG_INFO, "Deleting call branch '"STR_FORMAT"' (via-branch '"STR_FORMAT"')",
				STR_FMT(&ml->tag), STR_FMT0(branch));
		if (monologue_destroy(ml))
			goto del_all;
	}
	goto success_unlock;

del_all:
	if (delete_delay > 0) {
		ilog(LOG_INFO, "Scheduling deletion of entire call in %d seconds", delete_delay);
		c->deleted = poller_now + delete_delay;
		rwlock_unlock_w(&c->master_lock);
	}
	else {
		ilog(LOG_INFO, "Deleting entire call");
		rwlock_unlock_w(&c->master_lock);
		call_destroy(c);
	}
	goto success;

success_unlock:
	rwlock_unlock_w(&c->master_lock);
success:
	ret = 0;
	goto out;

err:
	if (c)
		rwlock_unlock_w(&c->master_lock);
	ret = -1;
	goto out;

out:
	if (c)
		obj_put(c);
	return ret;
}


static void callmaster_get_all_calls_interator(void *key, void *val, void *ptr) {
	GQueue *q = ptr;
	g_queue_push_tail(q, obj_get_o(val));
}

void callmaster_get_all_calls(struct callmaster *m, GQueue *q) {
	rwlock_lock_r(&m->hashlock);
	g_hash_table_foreach(m->callhash, callmaster_get_all_calls_interator, q);
	rwlock_unlock_r(&m->hashlock);

}


#if 0
// unused
// simplifty redis_write <> redis if put back into use
static void calls_dump_iterator(void *key, void *val, void *ptr) {
	struct call *c = val;
	struct callmaster *m = c->callmaster;

	if (m->conf.redis_write) {
		redis_update(c, m->conf.redis_write);
	} else if (m->conf.redis) {
		redis_update(c, m->conf.redis);
	}
}

void calls_dump_redis(struct callmaster *m) {
	if (!m->conf.redis)
		return;

	ilog(LOG_DEBUG, "Start dumping all call data to Redis...\n");
	redis_wipe(m->conf.redis);
	g_hash_table_foreach(m->callhash, calls_dump_iterator, NULL);
	ilog(LOG_DEBUG, "Finished dumping all call data to Redis\n");
}

void calls_dump_redis_read(struct callmaster *m) {
	if (!m->conf.redis_read)
		return;

	ilog(LOG_DEBUG, "Start dumping all call data to read Redis...\n");
	redis_wipe(m->conf.redis_read);
	g_hash_table_foreach(m->callhash, calls_dump_iterator, NULL);
	ilog(LOG_DEBUG, "Finished dumping all call data to read Redis\n");
}

void calls_dump_redis_write(struct callmaster *m) {
	if (!m->conf.redis_write)
		return;

	ilog(LOG_DEBUG, "Start dumping all call data to write Redis...\n");
	redis_wipe(m->conf.redis_write);
	g_hash_table_foreach(m->callhash, calls_dump_iterator, NULL);
	ilog(LOG_DEBUG, "Finished dumping all call data to write Redis\n");
}
#endif

const struct transport_protocol *transport_protocol(const str *s) {
	int i;

	if (!s || !s->s)
		goto out;

	for (i = 0; i < num_transport_protocols; i++) {
		if (strlen(transport_protocols[i].name) != s->len)
			continue;
		if (strncasecmp(transport_protocols[i].name, s->s, s->len))
			continue;
		return &transport_protocols[i];
	}

out:
	return NULL;
}
