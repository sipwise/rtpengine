#include "call.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <xmlrpc_client.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

#include "poller.h"
#include "helpers.h"
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
#include "main.h"
#include "graphite.h"
#include "codec.h"
#include "media_player.h"
#include "jitter_buffer.h"
#include "t38.h"
#include "mqtt.h"
#include "janus.h"
#include "dtmf.h"
#include "audio_player.h"


struct iterator_helper {
	uint64_t		count;
	GSList			*del_timeout;
	GSList			*del_scheduled;
	uint64_t		transcoded_media;
};
struct xmlrpc_helper {
	enum xmlrpc_format fmt;
	GQueue			strings;
};

rwlock_t rtpe_callhash_lock;
GHashTable *rtpe_callhash;
struct call_iterator_list rtpe_call_iterators[NUM_CALL_ITERATORS];
static struct mqtt_timer *global_mqtt_timer;

unsigned int call_socket_cpu_affinity = 0;

/**
 * locally needed static declarations
 */
static struct timeval add_ongoing_calls_dur_in_interval(struct timeval *interval_start,
		struct timeval *interval_duration);
static void __call_free(void *p);
static void __call_cleanup(struct call *c);
static void __monologue_stop(struct call_monologue *ml);
static void media_stop(struct call_media *m);
static void __subscribe_medias_both_ways(struct call_media * a, struct call_media * b);

/* called with call->master_lock held in R */
static int call_timer_delete_monologues(struct call *c) {
	GList *i;
	struct call_monologue *ml;
	int ret = 0;
	time_t min_deleted = 0;
	bool update = false;

	/* we need a write lock here */
	rwlock_unlock_r(&c->master_lock);
	rwlock_lock_w(&c->master_lock);

	for (i = c->monologues.head; i; i = i->next) {
		ml = i->data;

		if (!ml->deleted)
			continue;
		if (ml->deleted > rtpe_now.tv_sec) {
			if (!min_deleted || ml->deleted < min_deleted)
				min_deleted = ml->deleted;
			continue;
		}

		monologue_destroy(ml);
		update = true;
	}

	c->ml_deleted = min_deleted;

	rwlock_unlock_w(&c->master_lock);
	if (update)
		redis_update_onekey(c, rtpe_redis_write);
	rwlock_lock_r(&c->master_lock);

	// coverity[missing_unlock : FALSE]
	return ret;
}



void call_make_own_foreign(struct call *c, bool foreign) {
	statistics_update_foreignown_dec(c);
	c->foreign_call = foreign ? 1 : 0;
	statistics_update_foreignown_inc(c);
}



/* called with hashlock held */
static void call_timer_iterator(struct call *c, struct iterator_helper *hlp) {
	GList *it;
	unsigned int check;
	bool good = false;
	struct packet_stream *ps;
	struct stream_fd *sfd;
	int tmp_t_reason = UNKNOWN;
	struct call_monologue *ml;
	enum call_stream_state css;
	atomic64 *timestamp;

	hlp->count++;

	rwlock_lock_r(&c->master_lock);
	log_info_call(c);

	rwlock_lock_r(&rtpe_config.config_lock);

	// final timeout applicable to all calls (own and foreign)
	if (rtpe_config.final_timeout && rtpe_now.tv_sec >= (c->created.tv_sec + rtpe_config.final_timeout)) {
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

	if (c->deleted && rtpe_now.tv_sec >= c->deleted
			&& c->last_signal <= c->deleted)
		goto delete;

	if (c->ml_deleted && rtpe_now.tv_sec >= c->ml_deleted) {
		if (call_timer_delete_monologues(c))
			goto delete;
	}

	// conference: call can be created without participants added
	if (!c->streams.head)
		goto out;

	// ignore media timeout if call was recently taken over
	if (c->foreign_media && rtpe_now.tv_sec - c->last_signal <= rtpe_config.timeout)
		goto out;

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

no_sfd:
		if (good)
			goto next;

		check = rtpe_config.timeout;
		tmp_t_reason = TIMEOUT;
		if (!MEDIA_ISSET(ps->media, RECV) || !sfd) {
			check = rtpe_config.silent_timeout;
			tmp_t_reason = SILENT_TIMEOUT;
		}
		else if (!PS_ISSET(ps, FILLED)) {
			check = rtpe_config.offer_timeout;
			tmp_t_reason = OFFER_TIMEOUT;
		}

		if (rtpe_now.tv_sec - atomic64_get(timestamp) < check)
			good = true;

next:
		;
	}

	for (it = c->medias.head; it; it = it->next) {
		struct call_media *media = it->data;
		if (rtpe_config.measure_rtp) {
			media_update_stats(media);
			ssrc_collect_metrics(media);
		}
		if (media->monologue->transcoding)
			hlp->transcoded_media++;
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

	hlp->del_timeout = g_slist_prepend(hlp->del_timeout, obj_get(c));
	goto out;

delete:
	hlp->del_scheduled = g_slist_prepend(hlp->del_scheduled, obj_get(c));
	goto out;

out:
	rwlock_unlock_r(&rtpe_config.config_lock);
	rwlock_unlock_r(&c->master_lock);
	log_info_pop();
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
	str *tag, *tag2 = NULL, *tag3 = NULL;
	const char *url;

	int els_per_ent = 2;
	if (xh->fmt == XF_KAMAILIO)
		els_per_ent = 4;

	while (xh->strings.length >= els_per_ent) {
		usleep(10000);

		url = xh->strings.head->data;
		tag = xh->strings.head->next->data;
		if (xh->fmt == XF_KAMAILIO) {
			tag2 = xh->strings.head->next->next->data;
			tag3 = xh->strings.head->next->next->next->data;
		}

		ilog(LOG_INFO, "Forking child to close call with tag " STR_FORMAT_M " via XMLRPC call to %s",
				STR_FMT_M(tag), url);
		pid = fork();

		if (pid) {
retry:
			pid = waitpid(pid, &status, 0);
			if ((pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) || i >= 3) {
				for (int j = 0; j < els_per_ent; j++)
					free(g_queue_pop_head(&xh->strings));
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

		for (i = 0; i < 100; i++) {
			if (i == 2 && rtpe_config.common.log_stderr)
				continue;
			close(i);
		}

		if (!rtpe_config.common.log_stderr) {
			openlog("rtpengine/child", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		}
		ilog(LOG_INFO, "Initiating XMLRPC call for tag " STR_FORMAT_M "", STR_FMT_M(tag));

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
		case XF_KAMAILIO:
			xmlrpc_client_call2f(&e, c, url, "dlg.terminate_dlg", &r, "(sss)",
					tag->s, tag2->s, tag3->s);
			break;
		}

		if (r)
			xmlrpc_DECREF(r);
		if (e.fault_occurred) {
			if (strcasestr(e.fault_string, "dialog not found"))
				;
			else
				goto fault;
		}

		xmlrpc_client_destroy(c);
		for (int j = 0; j < els_per_ent; j++)
			free(g_queue_pop_head(&xh->strings));
		xmlrpc_env_clean(&e);

		_exit(0);

fault:
		ilog(LOG_WARNING, "XMLRPC fault occurred: %s", e.fault_string);
		_exit(1);
	}

	g_slice_free1(sizeof(*xh), xh);
}

void kill_calls_timer(GSList *list, const char *url) {
	struct call *ca;
	GList *csl;
	struct call_monologue *cm;
	char *url_prefix = NULL, *url_suffix = NULL;
	struct xmlrpc_helper *xh = NULL;
	char url_buf[128];

	if (!list)
		return;

	/* if url is NULL, it's the scheduled deletions, otherwise it's the timeouts */
	if (url) {
		xh = g_slice_alloc(sizeof(*xh));
		url_prefix = NULL;
		url_suffix = strstr(url, "%%");
		if (url_suffix) {
			url_prefix = strndup(url, url_suffix - url);
			url_suffix = strdup(url_suffix + 2);
		}
		else
			url_suffix = strdup(url);
		g_queue_init(&xh->strings);
		xh->fmt = rtpe_config.fmt;
	}

	while (list) {
		GHashTable *dup_tags = NULL;

		ca = list->data;
		log_info_call(ca);
		if (!url)
			goto destroy;

		if (rtpe_config.fmt == XF_KAMAILIO)
			dup_tags = g_hash_table_new(str_hash, str_equal);

		rwlock_lock_r(&ca->master_lock);

		const sockaddr_t *cb_addr;
		if (ca->xmlrpc_callback.family)
			cb_addr = &ca->xmlrpc_callback;
		else
			cb_addr = &ca->created_from_addr;

		if (url_prefix) {
			snprintf(url_buf, sizeof(url_buf), "%s%s%s",
					url_prefix, sockaddr_print_buf(cb_addr),
					url_suffix);
		}
		else
			snprintf(url_buf, sizeof(url_buf), "%s", url_suffix);

		switch (rtpe_config.fmt) {
		case XF_SEMS:
			for (csl = ca->monologues.head; csl; csl = csl->next) {
				cm = csl->data;
				if (!cm->tag.s || !cm->tag.len)
					continue;
				g_queue_push_tail(&xh->strings, strdup(url_buf));
				g_queue_push_tail(&xh->strings, str_dup(&cm->tag));
			}
			break;
		case XF_CALLID:
			g_queue_push_tail(&xh->strings, strdup(url_buf));
			g_queue_push_tail(&xh->strings, str_dup(&ca->callid));
			break;
		case XF_KAMAILIO:
			for (csl = ca->monologues.head; csl; csl = csl->next) {
				cm = csl->data;
				if (!cm->tag.s || !cm->tag.len)
					continue;

				for (GList *sub = cm->subscribers.head; sub; sub = sub->next) {
					struct call_subscription *cs = sub->data;
					struct call_monologue *cd = cs->monologue;

					if (!cd->tag.s || !cd->tag.len)
						continue;

					str *from_tag = g_hash_table_lookup(dup_tags, &cd->tag);
					if (from_tag && !str_cmp_str(from_tag, &cm->tag))
						continue;

					from_tag = str_dup(&cm->tag);
					str *to_tag = str_dup(&cd->tag);

					g_queue_push_tail(&xh->strings,
							strdup(url_buf));
					g_queue_push_tail(&xh->strings,
							str_dup(&ca->callid));
					g_queue_push_tail(&xh->strings, from_tag);
					g_queue_push_tail(&xh->strings, to_tag);

					g_hash_table_insert(dup_tags, from_tag, to_tag);
				}
			}
			break;
		}

		rwlock_unlock_r(&ca->master_lock);

destroy:
		call_destroy(ca);
		obj_put(ca);
		list = g_slist_delete_link(list, list);
		log_info_pop();

		if (dup_tags)
			g_hash_table_destroy(dup_tags);
	}

	if (xh)
		thread_create_detach_prio(xmlrpc_kill_calls, xh, rtpe_config.idle_scheduling,
				rtpe_config.idle_priority, "XMLRPC");
	if (url_prefix)
		free(url_prefix);
	if (url_suffix)
		free(url_suffix);
}

enum thread_looper_action call_timer() {
	struct iterator_helper hlp;
	ZERO(hlp);

	ITERATE_CALL_LIST_START(CALL_ITERATOR_TIMER, c);
		call_timer_iterator(c, &hlp);
	ITERATE_CALL_LIST_NEXT_END(c);

	/* stats derived while iterating calls */
	RTPE_GAUGE_SET(transcoded_media, hlp.transcoded_media); /* TODO: move out from here? */

	kill_calls_timer(hlp.del_scheduled, NULL);
	kill_calls_timer(hlp.del_timeout, rtpe_config.b2b_url);

	/* add thread scope (local) sockets to the global list, in order to release them later */
	append_thread_lpr_to_glob_lpr();

	return TLA_CONTINUE;
}
#undef DS


int call_init() {
	rtpe_callhash = g_hash_table_new(str_hash, str_equal);
	if (!rtpe_callhash)
		return -1;
	rwlock_init(&rtpe_callhash_lock);

	for (int i = 0; i < NUM_CALL_ITERATORS; i++)
		mutex_init(&rtpe_call_iterators[i].lock);

	if (mqtt_publish_scope() != MPS_NONE)
		mqtt_timer_start(&global_mqtt_timer, NULL, NULL);

	return 0;
}

static void __call_iterator_remove(struct call *c) {
	for (unsigned int i = 0; i < NUM_CALL_ITERATORS; i++) {
		struct call *prev_call, *next_call;
		while (1) {
			mutex_lock(&rtpe_call_iterators[i].lock);
			// lock this entry
			mutex_lock(&c->iterator[i].next_lock);
			mutex_lock(&c->iterator[i].prev_lock);
			// try lock adjacent entries
			prev_call = c->iterator[i].link.prev ? c->iterator[i].link.prev->data : NULL;
			next_call = c->iterator[i].link.next ? c->iterator[i].link.next->data : NULL;
			if (prev_call) {
				if (mutex_trylock(&prev_call->iterator[i].next_lock)) {
					mutex_unlock(&c->iterator[i].next_lock);
					mutex_unlock(&c->iterator[i].prev_lock);
					mutex_unlock(&rtpe_call_iterators[i].lock);
					continue; // try again
				}
			}
			if (next_call) {
				if (mutex_trylock(&next_call->iterator[i].prev_lock)) {
					if (prev_call)
						mutex_unlock(&prev_call->iterator[i].next_lock);
					mutex_unlock(&c->iterator[i].next_lock);
					mutex_unlock(&c->iterator[i].prev_lock);
					mutex_unlock(&rtpe_call_iterators[i].lock);
					continue; // try again
				}
			}
			break; // we can remove now
		}
		if (c->iterator[i].link.data)
			obj_put_o(c->iterator[i].link.data);
		rtpe_call_iterators[i].first = g_list_remove_link(rtpe_call_iterators[i].first,
				&c->iterator[i].link);
		ZERO(c->iterator[i].link);
		if (prev_call)
			mutex_unlock(&prev_call->iterator[i].next_lock);
		if (next_call)
			mutex_unlock(&next_call->iterator[i].prev_lock);
		mutex_unlock(&c->iterator[i].next_lock);
		mutex_unlock(&c->iterator[i].prev_lock);
		mutex_unlock(&rtpe_call_iterators[i].lock);
	}

}
void call_free(void) {
	mqtt_timer_stop(&global_mqtt_timer);
	GList *ll = g_hash_table_get_values(rtpe_callhash);
	for (GList *l = ll; l; l = l->next) {
		struct call *c = l->data;
		__call_iterator_remove(c);
		__call_cleanup(c);
		obj_put(c);
	}
	g_list_free(ll);
	g_hash_table_destroy(rtpe_callhash);
}



struct call_media *call_media_new(struct call *call) {
	struct call_media *med;
	med = uid_slice_alloc0(med, &call->medias);
	med->call = call;
	codec_store_init(&med->codecs, med);
	med->media_subscribers_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	med->media_subscriptions_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	mutex_init(&med->dtmf_lock);
	return med;
}

static struct call_media *__get_media(struct call_monologue *ml, const struct stream_params *sp,
		const struct sdp_ng_flags *flags, unsigned int index)
{
	struct call_media *med;
	struct call *call;

	// check for trickle ICE SDP fragment
	if (flags && flags->fragment && sp->media_id.len) {
		// in this case, the media sections are out of order and the media ID
		// string is used to determine which media section to operate on. this
		// info must be present and valid.
		med = g_hash_table_lookup(ml->media_ids, &sp->media_id);
		if (med)
			return med;
		ilogs(ice, LOG_ERR, "Received trickle ICE SDP fragment with unknown media ID '"
				STR_FORMAT "'",
				STR_FMT(&sp->media_id));
	}

	unsigned int want_index = index;
	if (want_index == 0)
		want_index = sp->index;
	assert(want_index > 0);
	unsigned int arr_index = want_index - 1;

	// check if we have an existing media struct. resize array if needed
	if (arr_index >= ml->medias->len)
		g_ptr_array_set_size(ml->medias, want_index);

	if (ml->medias->pdata[arr_index]) {
		__C_DBG("found existing call_media for stream #%u", want_index);
		return ml->medias->pdata[arr_index];
	}

	__C_DBG("allocating new call_media for stream #%u", want_index);
	call = ml->call;
	med = call_media_new(call);
	med->monologue = ml;
	med->index = want_index;
	call_str_cpy(ml->call, &med->type, &sp->type);
	med->type_id = sp->type_id;

	ml->medias->pdata[arr_index] = med;

	return med;
}



static int __media_want_interfaces(struct call_media *media) {
	unsigned int want_interfaces = media->logical_intf->list.length;
	if (rtpe_config.save_interface_ports || !MEDIA_ISSET(media, ICE))
		want_interfaces = 1;
	return want_interfaces;
}
static void __endpoint_map_truncate(struct endpoint_map *em, unsigned int num_intfs) {
	while (em->intf_sfds.length > num_intfs) {
		struct intf_list *il = g_queue_pop_tail(&em->intf_sfds);
		free_release_intf_list(il);
	}
}
static struct endpoint_map *__hunt_endpoint_map(struct call_media *media, unsigned int num_ports,
		const struct endpoint *ep, const struct sdp_ng_flags *flags, bool always_reuse,
		unsigned int want_interfaces)
{
	for (GList *l = media->endpoint_maps.tail; l; l = l->prev) {
		struct endpoint_map *em = l->data;
		if (em->logical_intf != media->logical_intf)
			continue;

		// any of our sockets shut down?
		for (GList *k = em->intf_sfds.head; k; k = k->next) {
			struct intf_list *il = k->data;
			for (GList *j = il->list.head; j; j = j->next) {
				struct stream_fd *sfd = j->data;
				if (sfd->socket.fd == -1)
					return NULL;
			}
		}

		if ((em->wildcard || always_reuse) && em->num_ports >= num_ports
				&& em->intf_sfds.length >= want_interfaces)
		{
			__C_DBG("found a wildcard endpoint map%s", ep ? " and filling it in" : "");
			if (ep) {
				em->endpoint = *ep;
				em->wildcard = 0;
			}
			__endpoint_map_truncate(em, want_interfaces);
			return em;
		}
		if (!ep) /* creating wildcard map */
			break;

		if (is_addr_unspecified(&ep->address) || is_addr_unspecified(&em->endpoint.address)) {
			/* handle zero endpoint address: only compare ports */
			if (ep->port != em->endpoint.port)
				continue;
		}
		else if (memcmp(&em->endpoint, ep, sizeof(*ep)))
			continue;

		if (em->num_ports >= num_ports && em->intf_sfds.length >= want_interfaces) {
			if (is_addr_unspecified(&em->endpoint.address))
				em->endpoint.address = ep->address;
			__endpoint_map_truncate(em, want_interfaces);
			return em;
		}
		/* endpoint matches, but not enough ports. flush existing ports
		 * and allocate a new set. */
		__C_DBG("endpoint matches, doesn't have enough ports");
		g_queue_clear_full(&em->intf_sfds, (void *) free_intf_list);
		return em;
	}

	return NULL;
}
static struct endpoint_map *__latch_endpoint_map(struct call_media *media)
{
	// simply look for the endpoint map matching the current port
	if (!media->streams.length)
		return NULL;
	struct packet_stream *first_ps = media->streams.head->data;
	if (!first_ps->sfds.length)
		return NULL;
	struct stream_fd *matcher = first_ps->sfds.head->data;

	for (GList *l = media->endpoint_maps.tail; l; l = l->prev) {
		struct endpoint_map *em = l->data;
		if (!em->intf_sfds.length)
			continue;
		struct intf_list *em_il = em->intf_sfds.head->data;
		if (!em_il->list.length)
			continue;
		struct stream_fd *first = em_il->list.head->data;
		if (first == matcher)
			return em;
	}
	return NULL;
}
static struct endpoint_map *__get_endpoint_map(struct call_media *media, unsigned int num_ports,
		const struct endpoint *ep, const struct sdp_ng_flags *flags, bool always_reuse)
{
	struct stream_fd *sfd;
	GQueue intf_sockets = G_QUEUE_INIT;
	unsigned int want_interfaces = __media_want_interfaces(media);

	bool port_latching = false;
	if (flags && flags->port_latching)
		port_latching = true;
	else if (MEDIA_ISSET(media, ICE) && (!flags || !flags->no_port_latching))
		port_latching = true;
	else if (!MEDIA_ISSET(media, RECV) && (!flags || !flags->no_port_latching))
		port_latching = true;

	struct endpoint_map *em = NULL;
	if (port_latching)
		em = __latch_endpoint_map(media);
	if (!em)
		em = __hunt_endpoint_map(media, num_ports, ep, flags, always_reuse, want_interfaces);

	if (em) {
		if (em->intf_sfds.length)
			return em;
		// fall through
	}
	else {
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
	}

	if (num_ports > 16)
		return NULL;
	if (get_consecutive_ports(&intf_sockets, num_ports, want_interfaces, media))
		return NULL;

	__C_DBG("allocating stream_fds for %u ports", num_ports);

	struct intf_list *il;
	while ((il = g_queue_pop_head(&intf_sockets))) {
		if (il->list.length != num_ports)
			goto next_il;

		struct intf_list *em_il = g_slice_alloc0(sizeof(*em_il));
		em_il->local_intf = il->local_intf;
		g_queue_push_tail(&em->intf_sfds, em_il);

		socket_t *sock;
		while ((sock = g_queue_pop_head(&il->list))) {
			set_tos(sock, media->call->tos);
			if (media->call->cpu_affinity >= 0) {
				if (socket_cpu_affinity(sock, media->call->cpu_affinity))
					ilog(LOG_ERR | LOG_FLAG_LIMIT, "Failed to set socket CPU "
							"affinity: %s", strerror(errno));
			}
			sfd = stream_fd_new(sock, media->call, il->local_intf);
			g_queue_push_tail(&em_il->list, sfd); // not referenced
		}

next_il:
		free_socket_intf_list(il);
	}

	return em;
}

static void __assign_stream_fds(struct call_media *media, GQueue *intf_sfds) {
	int reset_ice = 0;

	for (GList *k = media->streams.head; k; k = k->next) {
		struct packet_stream *ps = k->data;

		// use opaque pointer to detect changes
		void *old_selected_sfd = ps->selected_sfd;

		g_queue_clear(&ps->sfds);
		bool sfd_found = false;
		struct stream_fd *intf_sfd = NULL;

		for (GList *l = intf_sfds->head; l; l = l->next) {
			struct intf_list *il = l->data;

			struct stream_fd *sfd = g_queue_peek_nth(&il->list, ps->component - 1);
			if (!sfd)
				sfd = ps->selected_sfd;
			if (!sfd) {
				// create a dummy sfd. needed to hold RTCP crypto context when
				// RTCP-mux is in use
				socket_t *sock = g_slice_alloc(sizeof(*sock));
				dummy_socket(sock, &il->local_intf->spec->local_address.addr);
				sfd = stream_fd_new(sock, media->call, il->local_intf);
			}

			sfd->stream = ps;
			g_queue_push_tail(&ps->sfds, sfd);

			if (ps->selected_sfd == sfd)
				sfd_found = true;
			if (ps->selected_sfd && sfd->local_intf == ps->selected_sfd->local_intf)
				intf_sfd = sfd;
		}

		if (!ps->selected_sfd || !sfd_found) {
			if (intf_sfd)
				ps->selected_sfd = intf_sfd;
			else
				ps->selected_sfd = g_queue_peek_nth(&ps->sfds, 0);
		}

		if (old_selected_sfd && ps->selected_sfd && old_selected_sfd != ps->selected_sfd)
			reset_ice = 1;
	}

	if (reset_ice && media->ice_agent)
		ice_restart(media->ice_agent);
}

static int __wildcard_endpoint_map(struct call_media *media, unsigned int num_ports) {
	struct endpoint_map *em;

	em = __get_endpoint_map(media, num_ports, NULL, NULL, false);
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
	atomic64_set_na(&stream->last_packet, rtpe_now.tv_sec);
	stream->rtp_stats = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, __rtp_stats_free);
	recording_init_stream(stream);
	stream->send_timer = send_timer_new(stream);

	if (rtpe_config.jb_length && !call->disable_jb)
		stream->jb = jitter_buffer_new(call);

	return stream;
}

static int __num_media_streams(struct call_media *media, unsigned int num_ports) {
	struct packet_stream *stream;
	struct call *call = media->call;
	int ret = 0;

	// we need at least two, one for RTP and one for RTCP as they hold the crypto context
	if (num_ports < 2)
		num_ports = 2;

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
		const struct stream_params *sp, const struct sdp_ng_flags *flags)
{
	struct endpoint ep;
	struct call_media *media = ps->media;

	atomic64_set_na(&ps->last_packet, rtpe_now.tv_sec);

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

	if (!MEDIA_ISSET(media, ICE)) {
		if (PS_ISSET(ps, FILLED) && ps->selected_sfd
				&& ep.address.family != ps->selected_sfd->socket.family)
		{
			if (ep.address.family && !is_trickle_ice_address(&ep))
				ilog(LOG_WARN, "Ignoring updated remote endpoint %s%s%s as the local "
						"socket is %s", FMT_M(endpoint_print_buf(&ep)),
						ps->selected_sfd->socket.family->name);
			return;
		}

		ps->endpoint = ep;

		if (PS_ISSET(ps, FILLED) && !MEDIA_ISSET(media, DTLS)) {
			/* we reset crypto params whenever the endpoint changes */
			call_stream_crypto_reset(ps);
			dtls_shutdown(ps);
		}
	}
	else {
		// ICE
		if (!PS_ISSET(ps, FILLED))
			ps->endpoint = ep;
	}

	/* endpont-learning setup */
	if (flags)
		ps->el_flags = flags->el_option;

	if (ps->selected_sfd)
		ilog(LOG_DEBUG, "set FILLED flag for stream, local %s remote %s%s%s",
				endpoint_print_buf(&ps->selected_sfd->socket.local),
				FMT_M(endpoint_print_buf(&ps->endpoint)));
	else
		ilog(LOG_DEBUG, "set FILLED flag for stream, remote %s%s%s",
				FMT_M(endpoint_print_buf(&ps->endpoint)));
	PS_SET(ps, FILLED);

	if (flags && flags->pierce_nat)
		PS_SET(ps, PIERCE_NAT);
	if (flags && flags->nat_wait)
		PS_SET(ps, NAT_WAIT);
}

void call_stream_crypto_reset(struct packet_stream *ps) {
	ilog(LOG_DEBUG, "Resetting crypto context");

	crypto_reset(&ps->crypto);

	if (PS_ISSET(ps, RTP)) {
		mutex_lock(&ps->in_lock);
		for (unsigned int u = 0; u < G_N_ELEMENTS(ps->ssrc_in); u++) {
			if (!ps->ssrc_in[u]) // end of list
				break;
			ps->ssrc_in[u]->srtp_index = 0;
		}
		mutex_unlock(&ps->in_lock);

		mutex_lock(&ps->out_lock);
		for (unsigned int u = 0; u < G_N_ELEMENTS(ps->ssrc_out); u++) {
			if (!ps->ssrc_out[u]) // end of list
				break;
			ps->ssrc_out[u]->srtp_index = 0;
		}
		mutex_unlock(&ps->out_lock);
	}
}

/* called with call locked in R or W, but ps not locked */
enum call_stream_state call_stream_state_machine(struct packet_stream *ps) {
	struct call_media *media = ps->media;

	if (!ps->selected_sfd || !ps->sfds.length)
		return CSS_SHUTDOWN;

	if (MEDIA_ISSET(media, PASSTHRU))
		return CSS_RUNNING;

	enum call_stream_state ret = CSS_RUNNING;

	if (MEDIA_ISSET(media, ICE) && !ice_has_finished(media)) {
		if (!MEDIA_ISSET(media, DTLS))
			return CSS_ICE; /* handled by ICE timer */
		if (!ice_is_usable(media))
			return CSS_ICE; /* handled by ICE timer */
		// special case: ICE was able to communicate and DTLS is in use.
		// we can now start DTLS if necessary.
		ret = CSS_ICE;
	}

	if (MEDIA_ISSET(media, DTLS)) {
		mutex_lock(&ps->in_lock);
		struct dtls_connection *d = dtls_ptr(ps->selected_sfd);
		if (d && d->init && !d->connected) {
			dtls(ps->selected_sfd, NULL, NULL);
			mutex_unlock(&ps->in_lock);
			return CSS_DTLS;
		}
		mutex_unlock(&ps->in_lock);
	}

	if (PS_ISSET(ps, PIERCE_NAT) && PS_ISSET(ps, FILLED) && !PS_ISSET(ps, CONFIRMED)) {
		for (GList *l = ps->sfds.head; l; l = l->next) {
			static const str fake_rtp = STR_CONST_INIT("\x80\x7f\xff\xff\x00\x00\x00\x00"
					"\x00\x00\x00\x00");
			struct stream_fd *sfd = l->data;
			if (sfd->socket.fd == -1 || ps->endpoint.address.family == NULL)
				continue;
			socket_sendto(&sfd->socket, fake_rtp.s, fake_rtp.len, &ps->endpoint);
			atomic64_inc(&ps->stats_out.packets);
			atomic64_add(&ps->stats_out.bytes, fake_rtp.len);
		}
		ret = CSS_PIERCE_NAT;
	}

	return ret;
}

void call_media_state_machine(struct call_media *m) {
	GList *l;

	for (l = m->streams.head; l; l = l->next)
		call_stream_state_machine(l->data);
}

int __init_stream(struct packet_stream *ps) {
	struct call_media *media = ps->media;
	struct call *call = ps->call;
	int dtls_active = -1;
	AUTO_CLEANUP_GBUF(paramsbuf);
	struct dtls_connection *dtls_conn = NULL;

	if (MEDIA_ISSET(media, DTLS)) {
		dtls_conn = dtls_ptr(ps->selected_sfd);
		if (dtls_conn)
			dtls_active = dtls_is_active(dtls_conn);
	}
	else
		dtls_shutdown(ps);

	if (MEDIA_ISSET(media, SDES) && dtls_active == -1) {
		for (GList *l = ps->sfds.head; l; l = l->next) {
			struct stream_fd *sfd = l->data;
			struct crypto_params_sdes *cps = media->sdes_in.head
				? media->sdes_in.head->data : NULL;
			crypto_init(&sfd->crypto, cps ? &cps->params : NULL);
			ilogs(crypto, LOG_DEBUG, "[%s] Initialized incoming SRTP with SDES crypto params: %s%s%s",
					endpoint_print_buf(&sfd->socket.local),
					FMT_M(crypto_params_sdes_dump(cps, &paramsbuf)));
		}
		struct crypto_params_sdes *cps = media->sdes_out.head
			? media->sdes_out.head->data : NULL;
		crypto_init(&ps->crypto, cps ? &cps->params : NULL);
		ilogs(crypto, LOG_DEBUG, "[%i] Initialized outgoing SRTP with SDES crypto params: %s%s%s",
				ps->component,
				FMT_M(crypto_params_sdes_dump(cps, &paramsbuf)));
	}

	if (MEDIA_ISSET(media, DTLS) && !PS_ISSET(ps, FALLBACK_RTCP)) {
		// we try to retain our role if possible, but must handle a role switch
		if ((dtls_active && !MEDIA_ISSET(media, SETUP_ACTIVE))
				|| (!dtls_active && !MEDIA_ISSET(media, SETUP_PASSIVE)))
			dtls_active = -1;
		if (dtls_active == -1)
			dtls_active = (PS_ISSET(ps, FILLED) && MEDIA_ISSET(media, SETUP_ACTIVE));
		dtls_connection_init(&ps->ice_dtls, ps, dtls_active, call->dtls_cert);
		for (GList *l = ps->sfds.head; l; l = l->next) {
			struct stream_fd *sfd = l->data;
			dtls_connection_init(&sfd->dtls, ps, dtls_active, call->dtls_cert);
		}

		if (!PS_ISSET(ps, FINGERPRINT_VERIFIED) && media->fingerprint.hash_func
				&& media->fingerprint.digest_len && ps->dtls_cert)
		{
			if (dtls_verify_cert(ps))
				return -1;
		}

		call_stream_state_machine(ps);
	}

	return 0;
}

void __rtp_stats_update(GHashTable *dst, struct codec_store *cs) {
	struct rtp_stats *rs;
	struct rtp_payload_type *pt;
	GList *values, *l;
	GHashTable *src = cs->codecs;

	/* "src" is a call_media->codecs table, while "dst" is a
	 * packet_stream->rtp_stats table */

	values = g_hash_table_get_values(src);

	for (l = values; l; l = l->next) {
		pt = l->data;
		rs = g_hash_table_lookup(dst, GINT_TO_POINTER(pt->payload_type));
		if (rs)
			continue;

		rs = g_slice_alloc0(sizeof(*rs));
		rs->payload_type = pt->payload_type;
		g_hash_table_insert(dst, GINT_TO_POINTER(rs->payload_type), rs);
	}

	g_list_free(values);

	/* we leave previously added but now removed payload types in place */
}

void free_sink_handler(void *p) {
	struct sink_handler *sh = p;
	g_slice_free1(sizeof(*sh), sh);
}

/**
 * A transfer of flags from the subscription (call_subscription) to the sink handlers (sink_handler) is done
 * using the __init_streams() through __add_sink_handler().
 */
void __add_sink_handler(GQueue *q, struct packet_stream *sink, const struct sink_attrs *attrs) {
	struct sink_handler *sh = g_slice_alloc0(sizeof(*sh));
	sh->sink = sink;
	sh->kernel_output_idx = -1;
	if (attrs)
		sh->attrs = *attrs;
	g_queue_push_tail(q, sh);
}

// called once before calling __init_streams once for each sink
static void __reset_streams(struct call_media *media) {
	for (GList *l = media->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;
		g_queue_clear_full(&ps->rtp_sinks, free_sink_handler);
		g_queue_clear_full(&ps->rtcp_sinks, free_sink_handler);
		g_queue_clear_full(&ps->rtp_mirrors, free_sink_handler);
	}
}

/** Called once on media A for each sink media B.
 * B can be NULL.
 * attrs can be NULL.
 * TODO: this function seems to do two things - stream init (with B NULL) and sink init - split up?
 */
static int __init_streams(struct call_media *A, struct call_media *B, const struct stream_params *sp,
		const struct sdp_ng_flags *flags, const struct sink_attrs *attrs) {
	GList *la, *lb;
	struct packet_stream *a, *ax, *b;
	unsigned int port_off = 0;

	la = A->streams.head;
	lb = B ? B->streams.head : NULL;

	if (B)
		__C_DBG("Sink init media %u -> %u", A->index, B->index);
	else
		__C_DBG("Stream init media %u", A->index);

	while (la) {
		a = la->data;
		b = lb ? lb->data : NULL;

		/* RTP */
		// reflect media - pretend reflection also for blackhole, as otherwise
		// we get SSRC flip-flops on the opposite side
		// XXX still necessary for blackhole?
		if (attrs && attrs->egress && b)
			__add_sink_handler(&a->rtp_mirrors, b, attrs);
		else if (MEDIA_ISSET(A, ECHO) || MEDIA_ISSET(A, BLACKHOLE))
			__add_sink_handler(&a->rtp_sinks, a, attrs);
		else if (b && MEDIA_ISSET(B, SEND))
			__add_sink_handler(&a->rtp_sinks, b, attrs);
		PS_SET(a, RTP); /* XXX technically not correct, could be udptl too */

		__rtp_stats_update(a->rtp_stats, &A->codecs);

		if (sp) {
			__fill_stream(a, &sp->rtp_endpoint, port_off, sp, flags);
			bf_copy_same(&a->ps_flags, &sp->sp_flags,
					SHARED_FLAG_STRICT_SOURCE | SHARED_FLAG_MEDIA_HANDOVER);
		}
		bf_copy_same(&a->ps_flags, &A->media_flags, SHARED_FLAG_ICE);

		if (b) {
			PS_CLEAR(b, ZERO_ADDR);
			if (is_addr_unspecified(&a->advertised_endpoint.address)
					&& !(is_trickle_ice_address(&a->advertised_endpoint)
						&& MEDIA_ISSET(A, TRICKLE_ICE))
					&& !(flags && flags->replace_zero_address))
				PS_SET(b, ZERO_ADDR);
		}

		if (__init_stream(a))
			return -1;

		/* RTCP */
		if (B && lb && b && !MEDIA_ISSET(B, RTCP_MUX)) {
			lb = lb->next;
			assert(lb != NULL);
			b = lb->data;
		}

		if (!MEDIA_ISSET(A, RTCP_MUX))
			PS_CLEAR(a, RTCP);
		else {
			if (MEDIA_ISSET(A, ECHO) || MEDIA_ISSET(A, BLACKHOLE))
			{ /* RTCP sink handler added below */ }
			else if (b)
				__add_sink_handler(&a->rtcp_sinks, b, attrs);
			PS_SET(a, RTCP);
			PS_CLEAR(a, IMPLICIT_RTCP);
		}

		ax = a;

		/* if muxing, this is the fallback RTCP port. it also contains the RTCP
		 * crypto context */
		la = la->next;
		assert(la != NULL);
		a = la->data;

		if (attrs && attrs->egress)
			goto no_rtcp;

		if (MEDIA_ISSET(A, ECHO) || MEDIA_ISSET(A, BLACKHOLE)) {
			__add_sink_handler(&a->rtcp_sinks, a, attrs);
			if (MEDIA_ISSET(A, RTCP_MUX))
				__add_sink_handler(&ax->rtcp_sinks, a, attrs);
		}
		else if (b)
			__add_sink_handler(&a->rtcp_sinks, b, attrs);
		PS_CLEAR(a, RTP);
		PS_SET(a, RTCP);
		a->rtcp_sibling = NULL;
		bf_copy(&a->ps_flags, PS_FLAG_FALLBACK_RTCP, &ax->ps_flags, PS_FLAG_RTCP);

		ax->rtcp_sibling = a;

		if (sp) {
			if (!SP_ISSET(sp, IMPLICIT_RTCP)) {
				__fill_stream(a, &sp->rtcp_endpoint, port_off, sp, flags);
				PS_CLEAR(a, IMPLICIT_RTCP);
			}
			else {
				__fill_stream(a, &sp->rtp_endpoint, port_off + 1, sp, flags);
				PS_SET(a, IMPLICIT_RTCP);
			}
			bf_copy_same(&a->ps_flags, &sp->sp_flags,
					SHARED_FLAG_STRICT_SOURCE | SHARED_FLAG_MEDIA_HANDOVER);
		}
		bf_copy_same(&a->ps_flags, &A->media_flags, SHARED_FLAG_ICE);

		PS_CLEAR(a, ZERO_ADDR);
		if (b) {
			if (is_addr_unspecified(&b->advertised_endpoint.address)
					&& !(is_trickle_ice_address(&b->advertised_endpoint)
						&& MEDIA_ISSET(B, TRICKLE_ICE))
					&& !(flags && flags->replace_zero_address))
				PS_SET(a, ZERO_ADDR);
		}

		if (__init_stream(a))
			return -1;

no_rtcp:
		recording_setup_stream(ax); // RTP
		recording_setup_stream(a); // RTCP

		la = la->next;
		lb = lb ? lb->next : NULL;

		port_off += 2;
	}

	return 0;
}

static void __ice_offer(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other, bool ice_restart)
{
	if (!flags)
		return;

	// the default is to pass through the offering client's choice
	if (!MEDIA_ISSET(this, INITIALIZED))
		bf_copy_same(&this->media_flags, &other->media_flags, MEDIA_FLAG_ICE);
	// unless instructed not to
	if (flags->ice_option == ICE_REMOVE)
		MEDIA_CLEAR(this, ICE);
	else if (flags->ice_option != ICE_DEFAULT)
		MEDIA_SET(this, ICE);

	if (flags->ice_reject)
		MEDIA_CLEAR(other, ICE);

	if (flags->passthrough_on) {
		ilog(LOG_DEBUG, "enabling passthrough mode");
		MEDIA_SET(this, PASSTHRU);
		MEDIA_SET(other, PASSTHRU);
		return;
	}
	if (flags->passthrough_off) {
		ilog(LOG_DEBUG, "disabling passthrough mode");
		MEDIA_CLEAR(this, PASSTHRU);
		MEDIA_CLEAR(other, PASSTHRU);
		return;
	}

	if (flags->ice_option != ICE_FORCE && flags->ice_option != ICE_DEFAULT) {
		/* special case: if doing ICE on both sides and ice_force is not set, we cannot
		 * be sure that media will pass through us, so we have to disable certain features */
		if (MEDIA_ISSET(this, ICE) && MEDIA_ISSET(other, ICE)) {
			ilog(LOG_DEBUG, "enabling passthrough mode");
			MEDIA_SET(this, PASSTHRU);
			MEDIA_SET(other, PASSTHRU);
			return;
		}
		// if this is an answer, may see our ICE offer being rejected. if the original offer
		// wasn't forcing ICE, then we're only acting as a passthrough and so we must disable
		// ICE on the remote side as well. we can use the presence of an ICE agent as a test
		// to see whether ICE was originally forced or not.
		if (flags->opmode == OP_ANSWER && !MEDIA_ISSET(other, ICE) && !this->ice_agent) {
			MEDIA_CLEAR(this, ICE);
			return;
		}
	}

	if (flags->opmode == OP_OFFER) {
		switch (flags->ice_lite_option) {
			case ICE_LITE_OFF:
				MEDIA_CLEAR(this, ICE_LITE_SELF);
				MEDIA_CLEAR(other, ICE_LITE_SELF);
				break;
			case ICE_LITE_FWD:
				MEDIA_SET(this, ICE_LITE_SELF);
				MEDIA_CLEAR(other, ICE_LITE_SELF);
				break;
			case ICE_LITE_BKW:
				MEDIA_CLEAR(this, ICE_LITE_SELF);
				MEDIA_SET(other, ICE_LITE_SELF);
				break;
			case ICE_LITE_BOTH:
				MEDIA_SET(this, ICE_LITE_SELF);
				MEDIA_SET(other, ICE_LITE_SELF);
				break;
			default:
				break;
		}

		if (flags->trickle_ice)
			MEDIA_SET(this, TRICKLE_ICE);
	}
	else if (flags->opmode == OP_REQUEST) {
		// leave source media (`other`) alone
		switch (flags->ice_lite_option) {
			case ICE_LITE_OFF:
			case ICE_LITE_BKW:
				MEDIA_CLEAR(this, ICE_LITE_SELF);
				break;
			case ICE_LITE_FWD:
			case ICE_LITE_BOTH:
				MEDIA_SET(this, ICE_LITE_SELF);
				break;
			default:
				break;
		}

		if (flags->trickle_ice)
			MEDIA_SET(this, TRICKLE_ICE);
	}

	/* determine roles (even if we don't actually do ICE) */
	/* this = receiver, other = sender */
	/* ICE_CONTROLLING is from our POV, the other ICE flags are from peer's POV */
	if (MEDIA_ISSET(this, ICE_LITE_PEER) && !MEDIA_ISSET(this, ICE_LITE_SELF))
		MEDIA_SET(this, ICE_CONTROLLING);
	else if (!MEDIA_ISSET(this, INITIALIZED) || ice_restart) {
		if (MEDIA_ISSET(this, ICE_LITE_SELF))
			MEDIA_CLEAR(this, ICE_CONTROLLING);
		else if (flags->opmode == OP_OFFER || flags->opmode == OP_REQUEST)
			MEDIA_SET(this, ICE_CONTROLLING);
		else
			MEDIA_CLEAR(this, ICE_CONTROLLING);
	}

	if (flags->opmode == OP_OFFER) {
		/* roles are reversed for the other side */
		if (MEDIA_ISSET(other, ICE_LITE_PEER) && !MEDIA_ISSET(other, ICE_LITE_SELF))
			MEDIA_SET(other, ICE_CONTROLLING);
		else if (!MEDIA_ISSET(other, INITIALIZED) || ice_restart) {
			if (MEDIA_ISSET(other, ICE_LITE_SELF))
				MEDIA_CLEAR(other, ICE_CONTROLLING);
			else if (flags->opmode == OP_OFFER)
				MEDIA_CLEAR(other, ICE_CONTROLLING);
			else
				MEDIA_SET(other, ICE_CONTROLLING);
		}
	}
}


static void __sdes_flags(struct crypto_params_sdes *cps, const struct sdp_ng_flags *flags) {
	if (!cps)
		return;

	if (flags->sdes_unencrypted_srtp && flags->opmode == OP_OFFER)
		cps->params.session_params.unencrypted_srtp = 1;
	else if (flags->sdes_encrypted_srtp)
		cps->params.session_params.unencrypted_srtp = 0;
	if (flags->sdes_unencrypted_srtcp && flags->opmode == OP_OFFER)
		cps->params.session_params.unencrypted_srtcp = 1;
	else if (flags->sdes_encrypted_srtcp)
		cps->params.session_params.unencrypted_srtcp = 0;
	if (flags->sdes_unauthenticated_srtp && flags->opmode == OP_OFFER)
		cps->params.session_params.unauthenticated_srtp = 1;
	else if (flags->sdes_authenticated_srtp)
		cps->params.session_params.unauthenticated_srtp = 0;
}

/**
 *  Only generates SDES parameters for outgoing SDP, which is our media "out" direction.
 * `other` can be NULL.
 */
static void __generate_crypto(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other)
{
	/* SDES options, which will be present in the outgoing offer */
	GQueue *cpq = &this->sdes_out;
	/* SDES options coming to us for processing */
	GQueue *cpq_in = &this->sdes_in;

	GQueue *offered_cpq = other ? &other->sdes_in : NULL;
	if (!flags)
		return;

	/* requested order of crypto suites - generated offer */
	const GQueue *cpq_order = &flags->sdes_order;
	/* preferred crypto suites for the offerer - generated answer */
	const GQueue *offered_order = &flags->sdes_offerer_pref;

	bool is_offer = (flags->opmode == OP_OFFER || flags->opmode == OP_REQUEST);

	if (!this->protocol || !this->protocol->srtp || MEDIA_ISSET(this, PASSTHRU)) {
		crypto_params_sdes_queue_clear(cpq);
		/* clear crypto for the this leg b/c we are in passthrough mode */
		MEDIA_CLEAR(this, DTLS);
		MEDIA_CLEAR(this, SDES);
		MEDIA_CLEAR(this, SETUP_PASSIVE);
		MEDIA_CLEAR(this, SETUP_ACTIVE);

		if (other && (MEDIA_ISSET(this, PASSTHRU) || !other->protocol)) {
			/* clear crypto for the other leg as well b/c passthrough only
			 * works if it is done for both legs */
			MEDIA_CLEAR(other, DTLS);
			MEDIA_CLEAR(other, SDES);
			MEDIA_CLEAR(other, SETUP_PASSIVE);
			MEDIA_CLEAR(other, SETUP_ACTIVE);
		}

		return;
	}

	if (is_offer) {
		/* we always must offer actpass */
		MEDIA_SET(this, SETUP_PASSIVE);
		MEDIA_SET(this, SETUP_ACTIVE);
	}
	else {
		if (flags && flags->dtls_passive && MEDIA_ISSET(this, SETUP_PASSIVE))
			MEDIA_CLEAR(this, SETUP_ACTIVE);
		/* if we can be active, we will, otherwise we'll be passive */
		if (MEDIA_ISSET(this, SETUP_ACTIVE))
			MEDIA_CLEAR(this, SETUP_PASSIVE);
	}

	if (is_offer) {
		// if neither is enabled yet...
		if (!MEDIA_ISSET2(this, DTLS, SDES)) {
			/* we offer both DTLS and SDES by default */
			/* unless this is overridden by flags */
			if (!flags->dtls_off)
				MEDIA_SET(this, DTLS);
			if (!flags->sdes_off)
				MEDIA_SET(this, SDES);
			else
				goto skip_sdes;
		}
	}
	else {
		/* if both SDES and DTLS are supported, we may use the flags to select one
		 * over the other */
		if (MEDIA_ARESET2(this, DTLS, SDES) && flags->dtls_off) {
			MEDIA_CLEAR(this, DTLS);
			this->fingerprint.hash_func = NULL;
		}
		/* flags->sdes_off is ignored as we prefer DTLS by default */

		/* if we're talking to someone understanding DTLS, then skip the SDES stuff */
		if (MEDIA_ISSET(this, DTLS)) {
			MEDIA_CLEAR(this, SDES);
			goto skip_sdes;
		}
	}

	/* SDES parameters below */

	/* OP_OFFER */
	if (is_offer) {

		/* generate full set of params
		 * re-create the entire list - steal for later flushing */
		GQueue cpq_orig = *cpq;

		/* re-initialize it, in order to fill it out later, taking into account
		 * all the provided SDES flags and parameters */
		g_queue_init(cpq);

		/* if we were offered some crypto suites, copy those first into our offer */

		unsigned int c_tag = 1; /* tag for next crypto suite generated by us */
		unsigned long types_offered = 0;

		/* make sure our bit field is large enough */
		assert(num_crypto_suites <= sizeof(types_offered) * 8);

		/* always consider by default that offerer doesn't need re-ordering */
		MEDIA_CLEAR(other, REORDER_FORCED);

		/* add offered crypto parameters */
		for (GList *l = offered_cpq ? offered_cpq->head : NULL; l; l = l->next) {
			struct crypto_params_sdes *offered_cps = l->data;

			if (!flags->sdes_nonew &&
				crypto_params_sdes_check_limitations(flags->sdes_only, flags->sdes_no,
				offered_cps->params.crypto_suite))
			{
				ilogs(crypto, LOG_DEBUG, "Not offering crypto suite '%s'",
					offered_cps->params.crypto_suite->name);
				continue;
			}

			struct crypto_params_sdes *cps = g_slice_alloc0(sizeof(*cps));
			g_queue_push_tail(cpq, cps);

			cps->tag = offered_cps->tag;
			/* our own offered tags will be higher than the ones we received */
			if (cps->tag >= c_tag)
				c_tag = cps->tag + 1;
			crypto_params_copy(&cps->params, &offered_cps->params, 1);

			/* we use a bit field to keep track of which types we've seen here */
			types_offered |= 1 << cps->params.crypto_suite->idx;

			__sdes_flags(cps, flags);
		}

		/* if we had any suites added before, re-add those that aren't there yet */
		struct crypto_params_sdes *cps_orig;
		while ((cps_orig = g_queue_pop_head(&cpq_orig))) {
			if ((types_offered & (1 << cps_orig->params.crypto_suite->idx))) {
				crypto_params_sdes_free(cps_orig);
				continue;
			}

			/* make sure our tag is higher than what we've seen */
			if (cps_orig->tag < c_tag)
				cps_orig->tag = c_tag;
			if (cps_orig->tag >= c_tag)
				c_tag = cps_orig->tag + 1;

			g_queue_push_tail(cpq, cps_orig);

			types_offered |= 1 << cps_orig->params.crypto_suite->idx;
		}

		/* don't add any new crypto suites into the outgoing offer, if `SDES-nonew` is set */
		if (!flags->sdes_nonew) {

			/* generate crypto suite offers for any types that we haven't seen above.
			 * IMPORTANT: for re-invites, this always creates new crypto keys for suites
			 * that weren't accepted before, instead of re-using the same keys (and
			 * suites) that were previously offered but not accepted */
			for (unsigned int i = 0; i < num_crypto_suites; i++) {

				if ((types_offered & (1 << i)))
					continue;

				if (crypto_params_sdes_check_limitations(flags->sdes_only,
						flags->sdes_no, &crypto_suites[i]))
				{
					ilogs(crypto, LOG_DEBUG, "Not offering crypto suite '%s'",
						crypto_suites[i].name);
					continue;
				}

				struct crypto_params_sdes *cps = g_slice_alloc0(sizeof(*cps));
				g_queue_push_tail(cpq, cps);

				cps->tag = c_tag++;
				cps->params.crypto_suite = &crypto_suites[i];
				random_string((unsigned char *) cps->params.master_key,
						cps->params.crypto_suite->master_key_len);
				random_string((unsigned char *) cps->params.master_salt,
						cps->params.crypto_suite->master_salt_len);
				/* mki = mki_len = 0 */

				__sdes_flags(cps, flags);
			}
		}

		/* order the crypto suites list before to send out, if needed */
		if (cpq_order && cpq_order->head) {
			ilog(LOG_DEBUG, "The crypto suites in the outbound SDP will be re-ordered.");

			GQueue cpq_orig_list = *cpq;
			g_queue_init(cpq); /* re-initialize sdes_out */

			/* first add those mentioned in the order list,
			 * but only, if they were previously generated/added to the sdes_out */
			for (GList *l = cpq_order->head; l; l = l->next)
			{
				str * cs_name = l->data;
				struct crypto_params_sdes * cps_order;

				GList * elem = g_queue_find_custom(&cpq_orig_list, cs_name, crypto_params_sdes_cmp);

				if (!elem)
					continue;

				cps_order = elem->data;

				ilog(LOG_DEBUG, "New suites order, adding: %s (cps tag: %d)",
					cps_order->params.crypto_suite->name, cps_order->tag);

				g_queue_push_tail(cpq, cps_order);
				g_queue_delete_link(&cpq_orig_list, elem);
			}

			/* now add the rest */
			while ((cps_orig = g_queue_pop_head(&cpq_orig_list)))
			{
				ilog(LOG_DEBUG, "New suites order, adding: %s (cps tag: %d)",
				cps_orig->params.crypto_suite->name, cps_orig->tag);

				g_queue_push_tail(cpq, cps_orig);
			}
		}

		/* set preferences list of crypto suites for the offerer, if given */
		if ((offered_order && offered_order->head) && (offered_cpq && offered_cpq->head)) {
			ilog(LOG_DEBUG, "The crypto suites for the offerer will be re-ordered.");

			struct crypto_params_sdes * cps_found;
			GQueue offered_cpq_orig_list = *offered_cpq;

			g_queue_init(offered_cpq); /* re-initialize offered crypto suites */

			for (GList *l = offered_order->head; l; l = l->next)
			{
				str * cs_name = l->data;
				GList * elem = g_queue_find_custom(&offered_cpq_orig_list, cs_name, crypto_params_sdes_cmp);

				if (!elem)
					continue;

				cps_found = elem->data;

				/* check sdes_only limitations */
				if (crypto_params_sdes_check_limitations(flags->sdes_only,
						flags->sdes_no, cps_found->params.crypto_suite)) {
					g_queue_delete_link(&offered_cpq_orig_list, elem);
					crypto_params_sdes_free(cps_found);
					continue;
				}

				ilog(LOG_DEBUG, "Reordering suites for offerer, adding: %s (cps tag: %d)",
					cps_found->params.crypto_suite->name, cps_found->tag);

				/* affects a proper handling of crypto suites ordering,
				 * when sending processed answer to the media session originator */
				MEDIA_SET(other, REORDER_FORCED);

				g_queue_push_tail(offered_cpq, cps_found);
				g_queue_delete_link(&offered_cpq_orig_list, elem);
			}

			/* now add the rest */
			while ((cps_found = g_queue_pop_head(&offered_cpq_orig_list)))
			{
				ilog(LOG_DEBUG, "Reordering suites for offerer, adding: %s (cps tag: %d)",
						cps_found->params.crypto_suite->name, cps_found->tag);

				/* check sdes_only limitations */
				if (crypto_params_sdes_check_limitations(flags->sdes_only,
						flags->sdes_no, cps_found->params.crypto_suite)) {
					crypto_params_sdes_free(cps_found);
					continue;
				}

				g_queue_push_tail(offered_cpq, cps_found);
			}

			/* clear older data we are poiting using a copy now */
			crypto_params_sdes_queue_clear(&offered_cpq_orig_list);
		}
	}

	/* OP_ANSWER */
	else
	{
		/* we pick the first supported crypto suite */
		struct crypto_params_sdes *cps = cpq->head ? cpq->head->data : NULL;
		struct crypto_params_sdes *cps_in = cpq_in->head ? cpq_in->head->data : NULL;
		struct crypto_params_sdes *offered_cps = (offered_cpq && offered_cpq->head)
			? offered_cpq->head->data : NULL;

		if (flags && flags->sdes_static && cps) {
			/* reverse logic: instead of looking for a matching crypto suite to put in
			 * our answer, we want to leave what we already had. however, this is only
			 * valid if the currently present crypto suite matches the offer */
			for (GList *l = cpq_in->head; l; l = l->next) {
				struct crypto_params_sdes *check_cps = l->data;
				if (check_cps->params.crypto_suite == cps->params.crypto_suite
						&& check_cps->tag == cps->tag) {
					ilogs(crypto, LOG_DEBUG, "Found matching existing crypto suite %u:%s",
							check_cps->tag,
							check_cps->params.crypto_suite->name);
					goto cps_match;
				}
			}
		}

		/* don't try to match, if the offerer requested some suite preferences */
		if (offered_cps && !MEDIA_ISSET(this, REORDER_FORCED) ) {
			ilogs(crypto, LOG_DEBUG, "Looking for matching crypto suite to offered %u:%s", offered_cps->tag,
					offered_cps->params.crypto_suite->name);
			/* check if we can do SRTP<>SRTP passthrough. the crypto suite that was accepted
			 * must have been present in what was offered to us */
			for (GList *l = cpq_in->head; l; l = l->next) {
				struct crypto_params_sdes *check_cps = l->data;
				if (check_cps->params.crypto_suite == offered_cps->params.crypto_suite) {
					ilogs(crypto, LOG_DEBUG, "Found matching crypto suite %u:%s", check_cps->tag,
							check_cps->params.crypto_suite->name);
					cps_in = check_cps;
					break;
				}
			}
		}
cps_match:
		if (cps_in && (!cps || cps->params.crypto_suite != cps_in->params.crypto_suite)) {
			crypto_params_sdes_queue_clear(cpq);
			cps = g_slice_alloc0(sizeof(*cps));
			g_queue_push_tail(cpq, cps);

			cps->tag = cps_in->tag;
			cps->params.crypto_suite = cps_in->params.crypto_suite;
			if (offered_cps && offered_cps->params.crypto_suite == cps->params.crypto_suite) {
				// SRTP<>SRTP passthrough
				cps->params.session_params = cps_in->params.session_params; // XXX verify
				crypto_params_copy(&cps->params, &offered_cps->params, 1);
				ilogs(crypto, LOG_DEBUG, "Copied crypto params from %i:%s for SRTP passthrough",
						cps_in->tag, cps_in->params.crypto_suite->name);
			}
			else {
				random_string((unsigned char *) cps->params.master_key,
						cps->params.crypto_suite->master_key_len);
				random_string((unsigned char *) cps->params.master_salt,
						cps->params.crypto_suite->master_salt_len);
				/* mki = mki_len = 0 */
				cps->params.session_params = cps_in->params.session_params;
				ilogs(crypto, LOG_DEBUG, "Creating new SRTP crypto params for %i:%s",
						cps->tag, cps->params.crypto_suite->name);
			}

			// flush out crypto suites we ended up not using - leave only one
			if (!g_queue_remove(cpq_in, cps_in))
				ilogs(crypto, LOG_ERR, "BUG: incoming crypto suite not found in queue");
			crypto_params_sdes_queue_clear(cpq_in);
			g_queue_push_tail(cpq_in, cps_in);

			__sdes_flags(cps, flags);
			__sdes_flags(cps_in, flags);
		}
	}

skip_sdes:
	if (is_offer) {
		if (MEDIA_ISSET(this, DTLS) && !this->fp_hash_func && flags->dtls_fingerprint.len)
			this->fp_hash_func = dtls_find_hash_func(&flags->dtls_fingerprint);
	}
}
/**
 * Only accepts or declines proposed crypto suites. Does not generate.
 *
 * For an answer, uses the incoming received list of SDES crypto suites to prune
 * the list of (generated) outgoing crypto suites to contain only the one that was
 * accepted.
 */
static void __sdes_accept(struct call_media *media, const struct sdp_ng_flags *flags) {
	if (!media->sdes_in.length)
		return;

	/* if 'flags->sdes_nonew' is set, don't prune anything, just pass all coming.
	 * 'flags->sdes_nonew' takes precedence over 'sdes_only' and 'sdes_no'. */
	if (flags && (flags->sdes_only || flags->sdes_no) && !flags->sdes_nonew) {
		GList *l = media->sdes_in.tail;
		while (l) {
			struct crypto_params_sdes *offered_cps = l->data;

			if (!crypto_params_sdes_check_limitations(flags->sdes_only,
					flags->sdes_no, offered_cps->params.crypto_suite))
			{
				l = l->prev;
				continue;
			}

			/* stop the iteration intentionally, if only one suite is left
			 * this helps with a case, when the offerer left with no suites,
			 * which can be allowed, but we need to still have at least something */
			if (g_list_length(l) == 1) {
				l = l->prev;
				break;
			}

			ilogs(crypto, LOG_DEBUG, "Dropping offered crypto suite '%s' from offer due to %s",
				offered_cps->params.crypto_suite->name,
				flags->sdes_only ? "not being in SDES-only" : "SDES-no");

			GList *prev = l->prev;
			g_queue_delete_link(&media->sdes_in, l);
			crypto_params_sdes_free(offered_cps);
			l = prev;
		}
	}

	if (media->sdes_in.head == NULL)
		return;

	/* now prune those suites, which weren't accepted */

	/* currently incoming suites */
	struct crypto_params_sdes *cps_in = media->sdes_in.head->data;
	/* outgoing suites */
	GList *l = media->sdes_out.head;

	while (l) {
		struct crypto_params_sdes *cps_out = l->data;
		if (cps_out->params.crypto_suite != cps_in->params.crypto_suite)
			goto del_next;
		if (cps_out->tag != cps_in->tag)
			goto del_next;

		/* this one's good */
		l = l->next;
		continue;
del_next:
		/* mismatch, prune this one out */
		crypto_params_sdes_free(cps_out);
		GList *next = l->next;
		g_queue_delete_link(&media->sdes_out, l);
		l = next;
	}
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

static void __rtcp_mux_set(const struct sdp_ng_flags *flags, struct call_media *media) {
	if (flags->rtcp_mux_offer || flags->rtcp_mux_require)
		MEDIA_SET(media, RTCP_MUX);
	else if (flags->rtcp_mux_demux)
		MEDIA_CLEAR(media, RTCP_MUX);
}

static void __rtcp_mux_logic(struct sdp_ng_flags *flags, struct call_media *media,
		struct call_media *other_media)
{
	if (!flags)
		return;

	if (flags->opmode == OP_ANSWER) {
		/* default is to go with the client's choice, unless we were instructed not
		 * to do that in the offer (see below) */
		if (!MEDIA_ISSET(other_media, RTCP_MUX_OVERRIDE))
			bf_copy_same(&media->media_flags, &other_media->media_flags, MEDIA_FLAG_RTCP_MUX);

		return;
	}

	if (flags->opmode != OP_OFFER)
		return;

	/* default is to pass through the client's choice, unless our peer is already
	 * talking rtcp-mux, then we stick to that */
	if (!MEDIA_ISSET(media, RTCP_MUX))
		bf_copy_same(&media->media_flags, &other_media->media_flags, MEDIA_FLAG_RTCP_MUX);
	else {
		// mux already in use - unless we were instructed to do something else,
		// keep using it and don't offer a fallback choice: this is needed as the
		// fallback port might already be closed
		flags->rtcp_mux_require = 1;
	}
	/* in our offer, we can override the client's choice */
	__rtcp_mux_set(flags, media);

	/* we can also control what's going to happen in the answer. it
	 * depends on what was offered, but by default we go with the other
	 * client's choice */
	MEDIA_CLEAR(media, RTCP_MUX_OVERRIDE);
	if (MEDIA_ISSET(other_media, RTCP_MUX)) {
		if (!MEDIA_ISSET(media, RTCP_MUX)) {
			/* rtcp-mux was offered, but we don't offer it ourselves.
			 * the answer will not accept rtcp-mux (wasn't offered).
			 * the default is to accept the offer, unless we want to
			 * explicitly reject it. */
			MEDIA_SET(media, RTCP_MUX_OVERRIDE);
			if (flags->rtcp_mux_reject)
				MEDIA_CLEAR(other_media, RTCP_MUX);
		}
		else {
			/* rtcp-mux was offered and we offer it too. default is
			 * to go with the other client's choice, unless we want to
			 * either explicitly accept it (possibly demux) or reject
			 * it (possible reverse demux). */
			if (flags->rtcp_mux_accept)
				MEDIA_SET(media, RTCP_MUX_OVERRIDE);
			else if (flags->rtcp_mux_reject) {
				MEDIA_SET(media, RTCP_MUX_OVERRIDE);
				MEDIA_CLEAR(other_media, RTCP_MUX);
			}
		}
	}
	else {
		/* rtcp-mux was not offered. we may offer it, but since it wasn't
		 * offered to us, we must not accept it. */
		MEDIA_SET(media, RTCP_MUX_OVERRIDE);
	}
}

static void __dtls_restart(struct call_media *m) {
	GList *l;
	struct packet_stream *ps;

	for (l = m->streams.head; l; l = l->next) {
		ps = l->data;
		PS_CLEAR(ps, FINGERPRINT_VERIFIED);
		dtls_shutdown(ps);
		__init_stream(ps);
	}
}

static void __fingerprint_changed(struct call_media *m) {
	if (!m->fingerprint.hash_func || !m->fingerprint.digest_len)
		return;

	ilogs(crypto, LOG_INFO, "DTLS fingerprint changed, restarting DTLS");
	__dtls_restart(m);
}

static void __set_all_tos(struct call *c) {
	GList *l;
	struct stream_fd *sfd;

	for (l = c->stream_fds.head; l; l = l->next) {
		sfd = l->data;
		if (sfd->socket.fd == -1)
			continue;
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
		new_tos = rtpe_config.default_tos;
	else
		new_tos = flags->tos;

	if (new_tos == call->tos)
		return;

	call->tos = new_tos;
	__set_all_tos(call);
}

static void __init_interface(struct call_media *media, const str *ifname, int num_ports) {
	if (!media->logical_intf && media->monologue)
		media->logical_intf = media->monologue->logical_intf;
	if (!media->logical_intf)
		goto get;
	if (media->logical_intf->preferred_family != media->desired_family)
		goto get;
	if (!ifname || !ifname->s)
		return;
	if (!str_cmp_str(&media->logical_intf->name, ifname))
		return;
	if (g_hash_table_lookup(media->logical_intf->rr_specs, ifname))
		return;
get:
	media->logical_intf = get_logical_interface(ifname, media->desired_family, num_ports);
	if (G_UNLIKELY(!media->logical_intf)) {
		/* legacy support */
		if (!str_cmp(ifname, "internal"))
			media->desired_family = get_socket_family_enum(SF_IP4);
		else if (!str_cmp(ifname, "external"))
			media->desired_family = get_socket_family_enum(SF_IP6);
		else
			ilog(LOG_WARNING, "Interface '"STR_FORMAT"' not found, using default", STR_FMT(ifname));
		media->logical_intf = get_logical_interface(NULL, media->desired_family, num_ports);
		if (!media->logical_intf) {
			ilog(LOG_WARNING, "Requested address family (%s) not supported",
					media->desired_family->name);
			media->logical_intf = get_logical_interface(NULL, NULL, 0);
		}
	}
	if (media->monologue)
		media->monologue->logical_intf = media->logical_intf;
}


// process received a=setup and related attributes
static void __dtls_logic(const struct sdp_ng_flags *flags,
		struct call_media *other_media, struct stream_params *sp)
{
	unsigned int tmp;
	struct call *call = other_media->call;

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
		if ((flags->opmode == OP_OFFER || flags->opmode == OP_PUBLISH)
				&& MEDIA_ARESET2(other_media, SETUP_ACTIVE, SETUP_PASSIVE)
				&& (tmp & (MEDIA_FLAG_SETUP_ACTIVE | MEDIA_FLAG_SETUP_PASSIVE))
				== MEDIA_FLAG_SETUP_PASSIVE)
			MEDIA_CLEAR(other_media, SETUP_ACTIVE);
		/* if passive mode is requested, honour it if we can */
		if (flags->dtls_reverse_passive && MEDIA_ISSET(other_media, SETUP_PASSIVE))
			MEDIA_CLEAR(other_media, SETUP_ACTIVE);
	}

	// restart DTLS?
	if (memcmp(&other_media->fingerprint, &sp->fingerprint, sizeof(sp->fingerprint))) {
		__fingerprint_changed(other_media);
		other_media->fingerprint = sp->fingerprint;
	}
	else if (other_media->tls_id.len && (sp->tls_id.len || str_cmp_str(&other_media->tls_id, &sp->tls_id))) {
		// previously seen tls-id and new tls-id is different or not present
		ilogs(crypto, LOG_INFO, "TLS-ID changed, restarting DTLS");
		__dtls_restart(other_media);
	}
	else if (ice_is_restart(other_media->ice_agent, sp) && !other_media->tls_id.len && !sp->tls_id.len) {
		ilogs(crypto, LOG_INFO, "ICE restart without TLS-ID, restarting DTLS");
		__dtls_restart(other_media);
	}

	call_str_cpy(call, &other_media->tls_id, &sp->tls_id);

	MEDIA_CLEAR(other_media, DTLS);
	if (MEDIA_ISSET2(other_media, SETUP_PASSIVE, SETUP_ACTIVE)
			&& other_media->fingerprint.hash_func)
		MEDIA_SET(other_media, DTLS);
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
	if (!intf_addr.addr.family) // dummy/empty address
		return;
	if (!is_local_endpoint(&intf_addr, sp->rtp_endpoint.port))
		return;

	ilog(LOG_DEBUG, "Detected local endpoint advertised by remote client, "
			"enabling loop checking");

	MEDIA_SET(media, LOOP_CHECK);
}

static void __update_media_id(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, const struct sdp_ng_flags *flags)
{
	if (!flags)
		return;

	struct call *call = other_media->call;
	struct call_monologue *ml = media ? media->monologue : NULL;
	struct call_monologue *other_ml = other_media->monologue;

	if (flags->opmode == OP_OFFER || flags->opmode == OP_OTHER || flags->opmode == OP_PUBLISH
			|| flags->opmode == OP_REQUEST)
	{
		if (!other_media->media_id.s) {
			// incoming side: we copy what we received
			if (sp->media_id.s)
				call_str_cpy(call, &other_media->media_id, &sp->media_id);
			if (other_media->media_id.s)
				g_hash_table_insert(other_ml->media_ids, &other_media->media_id,
						other_media);
		}
		else {
			// RFC 5888 allows changing the media ID in a re-invite
			// (section 9.1), so handle this here.
			if (sp->media_id.s) {
				if (str_cmp_str(&other_media->media_id, &sp->media_id)) {
					// mismatch - update
					g_hash_table_remove(other_ml->media_ids, &other_media->media_id);
					call_str_cpy(call, &other_media->media_id, &sp->media_id);
					g_hash_table_insert(other_ml->media_ids, &other_media->media_id,
							other_media);
				}
			}
			else {
				// we already have a media ID, but re-invite offer did not specify
				// one. we keep what we already have.
				;
			}
		}
		if (media && !media->media_id.s) {
			// outgoing side: we copy from the other side
			if (other_media->media_id.s)
				call_str_cpy(call, &media->media_id, &other_media->media_id);
			else if (flags->generate_mid) {
				// or generate one
				char buf[64];
				snprintf(buf, sizeof(buf), "%u", other_media->index);
				call_str_cpy_c(call, &media->media_id, buf);
			}
			if (media->media_id.s)
				g_hash_table_insert(ml->media_ids, &media->media_id, media);
		}
		else {
			// we already have a media ID. keep what we have and ignore what's
			// happening on the other side.
			;
		}
	}
	else if (flags->opmode == OP_ANSWER) {
		// in normal cases, if the answer contains a media ID, it must match
		// the media ID previously sent in the offer, as the order of the media
		// sections must remain intact (RFC 5888 section 9.1). check this.
		if (sp->media_id.s) {
			if (!other_media->media_id.s)
				ilog(LOG_INFO, "Received answer SDP with media ID ('"
						STR_FORMAT "') when no media ID was offered",
					STR_FMT(&sp->media_id));
			else if (str_cmp_str(&other_media->media_id, &sp->media_id))
				ilog(LOG_WARN, "Received answer SDP with mismatched media ID ('"
						STR_FORMAT "') when the offered media ID was '"
						STR_FORMAT "'",
					STR_FMT(&sp->media_id), STR_FMT(&other_media->media_id));
		}
	}
}

static void __t38_reset(struct call_media *media, struct call_media *other_media) {
	ilog(LOG_DEBUG, "Stopping T.38 gateway and resetting %s/" STR_FORMAT " to %s/" STR_FORMAT,
			media->protocol->name,
			STR_FMT(&media->format_str),
			other_media->protocol->name,
			STR_FMT(&other_media->format_str));

	media->protocol = other_media->protocol;
	media->type_id = other_media->type_id;
	call_str_cpy(media->call, &media->type, &other_media->type);
	call_str_cpy(media->call, &media->format_str, &other_media->format_str);
}

static void __update_media_protocol(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, struct sdp_ng_flags *flags)
{
	// is the media type still the same?
	if (str_cmp_str(&other_media->type, &sp->type)) {
		ilog(LOG_DEBUG, "Updating media type from '" STR_FORMAT "' to '" STR_FORMAT "'",
				STR_FMT(&other_media->type), STR_FMT(&sp->type));
		call_str_cpy(other_media->call, &other_media->type, &sp->type);
		other_media->type_id = codec_get_type(&other_media->type);
		if (media) {
			call_str_cpy(media->call, &media->type, &sp->type);
			media->type_id = other_media->type_id;
		}
	}

	/* deduct protocol from stream parameters received */
	call_str_cpy(other_media->call, &other_media->protocol_str, &sp->protocol_str);

	if (other_media->protocol != sp->protocol) {
		other_media->protocol = sp->protocol;
		/* If the endpoint changes the protocol, we reset the other side's
		 * protocol as well. this lets us remember our previous overrides,
		 * but also lets endpoints re-negotiate.
		 * Answers are a special case: handle OSRTP answer/accept, but otherwise
		 * answer with the same protocol that was offered, unless we're instructed
		 * not to. */
		if (media) {
			if (flags && flags->opmode == OP_ANSWER) {
				// OSRTP?
				if (other_media->protocol && other_media->protocol->rtp
						&& !other_media->protocol->srtp
						&& media->protocol && media->protocol->osrtp)
				{
					// accept it?
					if (flags->osrtp_accept_rfc)
						;
					else
						media->protocol = NULL; // reject
				}
				// pass through any other protocol change?
				else if (!flags->protocol_accept)
					;
				else
					media->protocol = NULL;
			}
			else
				media->protocol = NULL;
		}
	}
	/* default is to leave the protocol unchanged */
	if (media && !media->protocol)
		media->protocol = other_media->protocol;

	// handler overrides requested by the user
	if (!flags)
		return;

	/* allow override of outgoing protocol even if we know it already */
	/* but only if this is an RTP-based protocol */
	if (media && flags->transport_protocol
			&& proto_is_rtp(other_media->protocol))
		media->protocol = flags->transport_protocol;

	// OSRTP offer requested?
	if (media && media->protocol && media->protocol->rtp && !media->protocol->srtp
			&& media->protocol->osrtp_proto && flags->osrtp_offer && flags->opmode == OP_OFFER)
	{
		media->protocol = &transport_protocols[media->protocol->osrtp_proto];
	}

	// T.38 decoder?
	if (media && other_media->type_id == MT_IMAGE && proto_is(other_media->protocol, PROTO_UDPTL)
			&& flags->t38_decode)
	{
		media->protocol = flags->transport_protocol;
		if (!media->protocol)
			media->protocol = &transport_protocols[PROTO_RTP_AVP];
		media->type_id = MT_AUDIO;
		call_str_cpy_c(media->call, &media->type, "audio");
		return;
	}

	// T.38 encoder?
	if (media && other_media->type_id == MT_AUDIO && proto_is_rtp(other_media->protocol)
			&& flags->t38_force)
	{
		media->protocol = &transport_protocols[PROTO_UDPTL];
		media->type_id = MT_IMAGE;
		call_str_cpy_c(media->call, &media->type, "image");
		call_str_cpy_c(media->call, &media->format_str, "t38");
		return;
	}

	// previous T.38 gateway but now stopping?
	if (media && flags->t38_stop) {
		if (other_media->type_id == MT_AUDIO && proto_is_rtp(other_media->protocol)
				&& media->type_id == MT_IMAGE
				&& proto_is(media->protocol, PROTO_UDPTL))
			__t38_reset(media, other_media);
		else if (media->type_id == MT_AUDIO && proto_is_rtp(media->protocol)
				&& other_media->type_id == MT_IMAGE
				&& proto_is(other_media->protocol, PROTO_UDPTL))
			__t38_reset(media, other_media);
		// drop through for protocol override
	}
}

static struct call_subscription *find_subscription(struct call_monologue *ml, struct call_monologue *sub) {
	return call_get_call_subscription(ml->subscribers_ht, sub);
}


__attribute__((nonnull(1, 2, 3)))
static void codecs_offer(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, struct sdp_ng_flags *flags)
{
	ilogs(codec, LOG_DEBUG, "Updating codecs for offerer " STR_FORMAT " #%u",
			STR_FMT(&other_media->monologue->tag),
			other_media->index);
	if (flags) {
		if (flags->reuse_codec)
			codec_store_populate_reuse(&other_media->codecs, &sp->codecs,
					.codec_set = flags->codec_set);
		else
			codec_store_populate(&other_media->codecs, &sp->codecs,
					.codec_set = flags->codec_set,
					.allow_asymmetric = !!flags->allow_asymmetric_codecs);
		codec_store_strip(&other_media->codecs, &flags->codec_strip, flags->codec_except);
		codec_store_offer(&other_media->codecs, &flags->codec_offer, &sp->codecs);
		if (!other_media->codecs.strip_full)
			codec_store_offer(&other_media->codecs, &flags->codec_transcode, &sp->codecs);
		codec_store_check_empty(&other_media->codecs, &sp->codecs);
		codec_store_accept(&other_media->codecs, &flags->codec_accept, NULL);
		codec_store_accept(&other_media->codecs, &flags->codec_consume, &sp->codecs);
		codec_store_track(&other_media->codecs, &flags->codec_mask);
	} else
		codec_store_populate(&other_media->codecs, &sp->codecs);

	// we don't update the answerer side if the offer is not RTP but is going
	// to RTP (i.e. T.38 transcoding) - instead we leave the existing codec list
	// intact
	bool update_answerer = true;
	if (proto_is_rtp(media->protocol) && !proto_is_rtp(other_media->protocol))
		update_answerer = false;

	if (update_answerer) {
		// update/create answer/receiver side
		ilogs(codec, LOG_DEBUG, "Updating codecs for answerer " STR_FORMAT " #%u",
				STR_FMT(&media->monologue->tag),
				media->index);
		if (flags && flags->reuse_codec)
			codec_store_populate_reuse(&media->codecs, &sp->codecs);
		else
			codec_store_populate(&media->codecs, &sp->codecs,
					.allow_asymmetric = !!(flags && flags->allow_asymmetric_codecs));
	}
	if (flags) {
		codec_store_strip(&media->codecs, &flags->codec_strip, flags->codec_except);
		codec_store_strip(&media->codecs, &flags->codec_consume, flags->codec_except);
		codec_store_strip(&media->codecs, &flags->codec_mask, flags->codec_except);
		codec_store_offer(&media->codecs, &flags->codec_offer, &sp->codecs);
		codec_store_transcode(&media->codecs, &flags->codec_transcode, &sp->codecs);
		codec_store_check_empty(&media->codecs, &sp->codecs);
	}
	codec_store_synthesise(&media->codecs, &other_media->codecs);

	// update supp codecs based on actions so far
	codec_tracker_update(&media->codecs);

	// set up handlers
	codec_handlers_update(media, other_media, .flags = flags, .sp = sp,
			.allow_asymmetric = !!(flags && flags->allow_asymmetric_codecs));

	// updating the handlers may have removed some codecs, so run update the supp codecs again
	codec_tracker_update(&media->codecs);

	// finally set up handlers again based on final results

	codec_handlers_update(media, other_media, .flags = flags, .sp = sp, 
			.allow_asymmetric = !!(flags && flags->allow_asymmetric_codecs),
			.reset_transcoding = true);
}

__attribute__((nonnull(1, 2, 3, 4)))
static void codecs_answer(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, struct sdp_ng_flags *flags)
{
	ilogs(codec, LOG_DEBUG, "Updating codecs for answerer " STR_FORMAT " #%u",
			STR_FMT(&other_media->monologue->tag),
			other_media->index);

	bool codec_answer_only = true;
	// don't do codec answer for a rejected media section
	if (other_media->streams.length == 0)
		codec_answer_only = false;
	else if (sp->rtp_endpoint.port == 0)
		codec_answer_only = false;

	if (flags->reuse_codec)
		codec_store_populate_reuse(&other_media->codecs, &sp->codecs,
				.codec_set = flags->codec_set,
				.answer_only = codec_answer_only);
	else
		codec_store_populate(&other_media->codecs, &sp->codecs,
				.codec_set = flags->codec_set,
				.answer_only = codec_answer_only,
				.allow_asymmetric = !!flags->allow_asymmetric_codecs);
	codec_store_strip(&other_media->codecs, &flags->codec_strip, flags->codec_except);
	codec_store_offer(&other_media->codecs, &flags->codec_offer, &sp->codecs);
	codec_store_check_empty(&other_media->codecs, &sp->codecs);

	// update callee side codec handlers again (second pass after the offer) as we
	// might need to update some handlers, e.g. when supplemental codecs have been
	// rejected
	codec_handlers_update(other_media, media, .allow_asymmetric = !!flags->allow_asymmetric_codecs);

	// finally set up our caller side codecs
	ilogs(codec, LOG_DEBUG, "Codec answer for " STR_FORMAT " #%u",
			STR_FMT(&other_media->monologue->tag),
			other_media->index);
	codec_store_answer(&media->codecs, &other_media->codecs, flags);

	// set up handlers
	codec_handlers_update(media, other_media, .flags = flags, .sp = sp,
			.allow_asymmetric = !!flags->allow_asymmetric_codecs);

	// updating the handlers may have removed some codecs, so run update the supp codecs again
	codec_tracker_update(&media->codecs);
	codec_tracker_update(&other_media->codecs);

	// finally set up handlers again based on final results

	codec_handlers_update(media, other_media, .flags = flags, .sp = sp,
			.allow_asymmetric = !!flags->allow_asymmetric_codecs,
			.reset_transcoding = true);
	codec_handlers_update(other_media, media,
			.allow_asymmetric = !!flags->allow_asymmetric_codecs,
			.reset_transcoding = true);

	// activate audio player if needed (not done by codec_handlers_update without `flags`)
	audio_player_activate(media);
}

void codecs_offer_answer(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp,
		struct sdp_ng_flags *flags)
{
	if (!flags || flags->opmode != OP_ANSWER)
		codecs_offer(media, other_media, sp, flags);
	else
		codecs_answer(media, other_media, sp, flags);
}


/* called with call->master_lock held in W */
static void __update_init_subscribers(struct call_monologue *ml, GQueue *streams, struct sdp_ng_flags *flags,
		enum call_opmode opmode)
{
	GList *sl = streams ? streams->head : NULL;

	recording_setup_monologue(ml);

	if (flags && flags->block_short)
		ml->block_short = 1;

	for (unsigned int j = 0; j < ml->medias->len; j++)
	{
		struct call_media *media = ml->medias->pdata[j];

		if (!media)
			continue;

		struct stream_params *sp = NULL;
		if (sl) {
			sp = sl->data;
			sl = sl->next;
		}

		__ice_start(media);

		/* update all subscribers */
		__reset_streams(media);

		for (GList *l = media->media_subscribers.head; l; l = l->next)
		{
			struct media_subscription * ms = l->data;
			struct call_media * sub_media = ms->media;
			if (!sub_media)
				continue;
			if (__init_streams(media, sub_media, sp, flags, &ms->attrs))
				ilog(LOG_WARN, "Error initialising streams");
		}

		/* we are now ready to fire up ICE if so desired and requested */
		ice_update(media->ice_agent, sp, opmode == OP_OFFER); /* sp == NULL: update in case rtcp-mux changed */

		recording_setup_media(media);
		t38_gateway_start(media->t38_gateway);
		audio_player_start(media);

		if (mqtt_publish_scope() == MPS_MEDIA)
			mqtt_timer_start(&media->mqtt_timer, media->call, media);
	}
}

/* called with call->master_lock held in W */
void update_init_subscribers(struct call_monologue *ml, enum call_opmode opmode) {
	__update_init_subscribers(ml, NULL, NULL, opmode);
}


static void __call_monologue_init_from_flags(struct call_monologue *ml, struct sdp_ng_flags *flags) {
	struct call *call = ml->call;

	call->last_signal = rtpe_now.tv_sec;
	call->deleted = 0;

	// reset offer ipv4/ipv6/mixed media stats
	if (flags && flags->opmode == OP_OFFER) {
		statistics_update_ip46_inc_dec(call, CMC_DECREMENT);
		call->is_ipv4_media_offer = 0;
		call->is_ipv6_media_offer = 0;

	// reset answer ipv4/ipv6/mixed media stats
	} else if (flags && flags->opmode == OP_ANSWER) {
		statistics_update_ip46_inc_dec(call, CMC_DECREMENT);
		call->is_ipv4_media_answer = 0;
		call->is_ipv6_media_answer = 0;
	}

	__tos_change(call, flags);

	if (flags && flags->label.s) {
		call_str_cpy(call, &ml->label, &flags->label);
		g_hash_table_replace(call->labels, &ml->label, ml);
	}

}

static void __update_media_label(struct call_media *media, struct call_media *other_media,
		struct sdp_ng_flags *flags)
{
	if (!media)
		return;
	if (!flags)
		return;

	struct call *call = media->call;

	if (flags->siprec && flags->opmode == OP_REQUEST) {
		if (!media->label.len) {
			char buf[64];
			snprintf(buf, sizeof(buf), "%u", other_media->unique_id);
			call_str_cpy_c(call, &media->label, buf);
		}
		// put same label on both sides
		if (!other_media->label.len)
			other_media->label = media->label;
	}
}

// `media` can be NULL
static void __media_init_from_flags(struct call_media *other_media, struct call_media *media,
		struct stream_params *sp, struct sdp_ng_flags *flags)
{
	struct call *call = other_media->call;

	if (flags && flags->opmode == OP_OFFER && flags->reset) {
		if (media)
			MEDIA_CLEAR(media, INITIALIZED);
		MEDIA_CLEAR(other_media, INITIALIZED);
		if (media && media->ice_agent)
			ice_restart(media->ice_agent);
		if (other_media->ice_agent)
			ice_restart(other_media->ice_agent);
	}

	if (flags && flags->generate_rtcp) {
		if (media)
			MEDIA_SET(media, RTCP_GEN);
		MEDIA_SET(other_media, RTCP_GEN);
	}
	else if (flags && flags->generate_rtcp_off) {
		if (media)
			MEDIA_CLEAR(media, RTCP_GEN);
		MEDIA_CLEAR(other_media, RTCP_GEN);
	}

	if (flags) {
		switch (flags->media_echo) {
			case MEO_FWD:
				MEDIA_SET(media, ECHO);
				MEDIA_SET(other_media, BLACKHOLE);
				MEDIA_CLEAR(media, BLACKHOLE);
				MEDIA_CLEAR(other_media, ECHO);
				break;
			case MEO_BKW:
				MEDIA_SET(media, BLACKHOLE);
				MEDIA_SET(other_media, ECHO);
				MEDIA_CLEAR(media, ECHO);
				MEDIA_CLEAR(other_media, BLACKHOLE);
				break;
			case MEO_BOTH:
				MEDIA_SET(media, ECHO);
				MEDIA_SET(other_media, ECHO);
				MEDIA_CLEAR(media, BLACKHOLE);
				MEDIA_CLEAR(other_media, BLACKHOLE);
				break;
			case MEO_BLACKHOLE:
				MEDIA_SET(media, BLACKHOLE);
				MEDIA_SET(other_media, BLACKHOLE);
				MEDIA_CLEAR(media, ECHO);
				MEDIA_CLEAR(other_media, ECHO);
			case MEO_DEFAULT:
				break;
		}
	}

	__update_media_label(media, other_media, flags);
	__update_media_protocol(media, other_media, sp, flags);
	__update_media_id(media, other_media, sp, flags);
	__endpoint_loop_protect(sp, other_media);

	if (sp->rtp_endpoint.port) {
		/* copy parameters advertised by the sender of this message */
		bf_copy_same(&other_media->media_flags, &sp->sp_flags,
				SHARED_FLAG_RTCP_MUX | SHARED_FLAG_ASYMMETRIC | SHARED_FLAG_UNIDIRECTIONAL |
				SHARED_FLAG_ICE | SHARED_FLAG_TRICKLE_ICE | SHARED_FLAG_ICE_LITE_PEER |
				SHARED_FLAG_RTCP_FB | SHARED_FLAG_LEGACY_OSRTP | SHARED_FLAG_LEGACY_OSRTP_REV);

		// duplicate the entire queue of offered crypto params
		crypto_params_sdes_queue_clear(&other_media->sdes_in);
		crypto_params_sdes_queue_copy(&other_media->sdes_in, &sp->sdes_params);

		if (other_media->sdes_in.length) {
			MEDIA_SET(other_media, SDES);
			__sdes_accept(other_media, flags);
		}
	}

	// codec and RTP payload types handling
	if (sp->ptime > 0) {
		if (media && !MEDIA_ISSET(media, PTIME_OVERRIDE))
			media->ptime = sp->ptime;
		if (!MEDIA_ISSET(other_media, PTIME_OVERRIDE))
			other_media->ptime = sp->ptime;
	}
	if (media && flags && flags->ptime > 0) {
		media->ptime = flags->ptime;
		MEDIA_SET(media, PTIME_OVERRIDE);
		MEDIA_SET(other_media, PTIME_OVERRIDE);
	}
	if (flags && flags->rev_ptime > 0) {
		other_media->ptime = flags->rev_ptime;
		if (media)
			MEDIA_SET(media, PTIME_OVERRIDE);
		MEDIA_SET(other_media, PTIME_OVERRIDE);
	}
	if (str_cmp_str(&other_media->format_str, &sp->format_str))
		call_str_cpy(call, &other_media->format_str, &sp->format_str);
	if (media && str_cmp_str(&media->format_str, &sp->format_str)) {
		// update opposite side format string only if protocols match
		if (media->protocol == other_media->protocol)
			call_str_cpy(call, &media->format_str, &sp->format_str);
	}

	/* deduct address family from stream parameters received */
	if (!other_media->desired_family || !MEDIA_ISSET(other_media, ICE))
		other_media->desired_family = sp->rtp_endpoint.address.family;
	/* for outgoing SDP, use "direction"/DF or default to what was offered */
	if (media && (!media->desired_family || !MEDIA_ISSET(media, ICE))) {
		if (!media->desired_family)
			media->desired_family = other_media->desired_family;
		if (sp->desired_family)
			media->desired_family = sp->desired_family;
	}
}

unsigned int proto_num_ports(unsigned int sp_ports, struct call_media *media, struct sdp_ng_flags *flags,
		bool allow_offer_split)
{
	if (sp_ports == 0)
		return 2;
	if (sp_ports != 2)
		return sp_ports;
	if (!proto_is_rtp(media->protocol))
		return sp_ports;
	if (!MEDIA_ISSET(media, RTCP_MUX))
		return sp_ports;
	if (!flags)
		return sp_ports;
	if (flags->opmode == OP_ANSWER || flags->opmode == OP_PUBLISH)
		return sp_ports / 2;
	if (flags->opmode == OP_OFFER) {
		if (allow_offer_split)
			return sp_ports / 2;
		return sp_ports;
	}
	return sp_ports;
}


static int __sub_is_transcoding(gconstpointer p, gconstpointer dummy) {
	const struct call_subscription *cs = p;
	return cs->attrs.transcoding ? 0 : 1;
}
// set transcoding flag if any media flows are transcoding, otherwise unset it
static void set_monologue_flags_per_subscribers(struct call_monologue *ml) {
	ml->transcoding = 0;

	if (g_queue_find_custom(&ml->subscribers, NULL, __sub_is_transcoding))
		ml->transcoding = 1;
}

/* called with call->master_lock held in W */
int monologue_offer_answer(struct call_monologue *monologues[2], GQueue *streams,
		struct sdp_ng_flags *flags)
{
	struct call_media *media, *other_media;
	struct endpoint_map *em;
	struct call_monologue *other_ml = monologues[0];
	struct call_monologue *monologue = monologues[1];
	unsigned int num_ports_this, num_ports_other;

	/* we must have a complete dialogue, even though the to-tag (monologue->tag)
	 * may not be known yet */
	if (!other_ml) {
		ilog(LOG_ERROR, "Incomplete dialogue association");
		return -1;
	}

	/* required for updating the transcoding attrs of subscriber */
	struct call_subscription * cs = find_subscription(monologue, other_ml);

	__call_monologue_init_from_flags(other_ml, flags);

	if (flags && flags->exclude_recording) {
		monologue->no_recording = 1;
		other_ml->no_recording = 1;
	}

	__C_DBG("this="STR_FORMAT" other="STR_FORMAT, STR_FMT(&monologue->tag), STR_FMT(&other_ml->tag));

	if (cs)
		cs->attrs.transcoding = 0;

	for (GList *sp_iter = streams->head; sp_iter; sp_iter = sp_iter->next) {
		struct stream_params *sp = sp_iter->data;
		__C_DBG("processing media stream #%u", sp->index);
		assert(sp->index > 0);

		/* first, check for existence of call_media struct on both sides of
		 * the dialogue */
		media = __get_media(monologue, sp, flags, 0);
		other_media = __get_media(other_ml, sp, flags, 0);
		/* OTHER is the side which has sent the message. SDP parameters in
		 * "sp" are as advertised by OTHER side. The message will be sent to
		 * THIS side. Parameters sent to THIS side may be overridden by
		 * what's in "flags". If this is an answer, or if we have talked to
		 * THIS side (recipient) before, then the structs will be populated with
		 * details already. */

		/* if medias still not subscribed to each other, do it now */
		if (!call_get_media_subscription(media->media_subscribers_ht, other_media) &&
			!call_get_media_subscription(other_media->media_subscribers_ht, media))
		{
			__subscribe_medias_both_ways(media, other_media);
		}

		__media_init_from_flags(other_media, media, sp, flags);

		codecs_offer_answer(media, other_media, sp, flags);

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
		}

		if (media->desired_family->af == AF_INET) {
			if (flags && flags->opmode == OP_OFFER) {
				media->call->is_ipv4_media_offer = 1;
			} else if (flags && flags->opmode == OP_ANSWER) {
				media->call->is_ipv4_media_answer = 1;
			}
		} else if (media->desired_family->af == AF_INET6) {
			if (flags && flags->opmode == OP_OFFER) {
				media->call->is_ipv6_media_offer = 1;
			} else if (flags && flags->opmode == OP_ANSWER) {
				media->call->is_ipv6_media_answer = 1;
			}
		}

		num_ports_this = proto_num_ports(sp->num_ports, media, flags,
				flags && flags->rtcp_mux_require ? true : false);
		num_ports_other = proto_num_ports(sp->num_ports, other_media, flags,
				flags && (flags->rtcp_mux_demux || flags->rtcp_mux_accept) ? true : false);

		/* local interface selection */
		__init_interface(media, &sp->direction[1], num_ports_this);
		__init_interface(other_media, &sp->direction[0], num_ports_other);

		if (media->logical_intf == NULL || other_media->logical_intf == NULL) {
			goto error_intf;
		}

		/* ICE stuff - must come after interface and address family selection */
		__ice_offer(flags, media, other_media, ice_is_restart(other_media->ice_agent, sp));


		/* we now know what's being advertised by the other side */
		MEDIA_SET(other_media, INITIALIZED);


		if (!sp->rtp_endpoint.port) {
			/* Zero port: stream has been rejected.
			 * RFC 3264, chapter 6:
			 * If a stream is rejected, the offerer and answerer MUST NOT
			 * generate media (or RTCP packets) for that stream. */
			__disable_streams(media, num_ports_this);
			__disable_streams(other_media, num_ports_other);
			continue;
		}
		if (is_addr_unspecified(&sp->rtp_endpoint.address) && !MEDIA_ISSET(other_media, TRICKLE_ICE)) {
			/* Zero endpoint address, equivalent to setting the media stream
			 * to sendonly or inactive */
			MEDIA_CLEAR(media, RECV);
			MEDIA_CLEAR(other_media, SEND);
		}


		/* get that many ports for each side, and one packet stream for each port, then
		 * assign the ports to the streams */
		em = __get_endpoint_map(media, num_ports_this, &sp->rtp_endpoint, flags, false);
		if (!em) {
			goto error_ports;
		}

		if (flags && flags->disable_jb && media->call)
			media->call->disable_jb=1;

		__num_media_streams(media, num_ports_this);
		__assign_stream_fds(media, &em->intf_sfds);

		if (__num_media_streams(other_media, num_ports_other)) {
			/* new streams created on OTHER side. normally only happens in
			 * initial offer. create a wildcard endpoint_map to be filled in
			 * when the answer comes. */
			if (__wildcard_endpoint_map(other_media, num_ports_other))
				goto error_ports;
		}
	}

	set_monologue_flags_per_subscribers(monologue);
	set_monologue_flags_per_subscribers(other_ml);

	__update_init_subscribers(other_ml, streams, flags, flags ? flags->opmode : OP_OFFER);
	__update_init_subscribers(monologue, NULL, NULL, flags ? flags->opmode : OP_OFFER);

	// set ipv4/ipv6/mixed media stats
	if (flags && (flags->opmode == OP_OFFER || flags->opmode == OP_ANSWER)) {
		statistics_update_ip46_inc_dec(monologue->call, CMC_INCREMENT);
	}

	return 0;

error_ports:
	ilog(LOG_ERR, "Error allocating media ports");
	return ERROR_NO_FREE_PORTS;

error_intf:
	ilog(LOG_ERR, "Error finding logical interface with free ports");
	return ERROR_NO_FREE_LOGS;
}


void call_subscriptions_clear(GQueue *q) {
	g_queue_clear_full(q, call_subscription_free);
}

static void __unsubscribe_media_link(struct call_media * which, GList * which_cm_link)
{
	struct media_subscription * ms = which_cm_link->data;
	struct media_subscription * rev_ms = ms->link->data;
	struct call_media * from = ms->media;

	ilog(LOG_DEBUG, "Unsubscribing media with monologue tag '" STR_FORMAT_M "' (index: %d)"
			"from media with monologue tag '" STR_FORMAT_M "' (index: %d)",
			STR_FMT_M(&which->monologue->tag), which->index,
			STR_FMT_M(&from->monologue->tag), from->index);

	g_queue_delete_link(&from->media_subscribers, ms->link);
	g_queue_delete_link(&which->media_subscriptions, which_cm_link);

	g_hash_table_remove(which->media_subscriptions_ht, ms->media);
	g_hash_table_remove(from->media_subscribers_ht, rev_ms->media);

	g_slice_free1(sizeof(*ms), ms);
	g_slice_free1(sizeof(*rev_ms), rev_ms);
}
static void __unsubscribe_one_link(struct call_monologue *which, GList *which_cs_link) {
	struct call_subscription *cs = which_cs_link->data;
	struct call_subscription *rev_cs = cs->link->data;
	struct call_monologue *from = cs->monologue;
	ilog(LOG_DEBUG, "Unsubscribing '" STR_FORMAT_M "' from '" STR_FORMAT_M "'",
			STR_FMT_M(&which->tag),
			STR_FMT_M(&from->tag));
	g_queue_delete_link(&from->subscribers, cs->link);
	g_queue_delete_link(&which->subscriptions, which_cs_link);
	g_hash_table_remove(which->subscriptions_ht, cs->monologue);
	g_hash_table_remove(from->subscribers_ht, rev_cs->monologue);
	g_slice_free1(sizeof(*cs), cs);
	g_slice_free1(sizeof(*rev_cs), rev_cs);
}
/**
 * Unsubscribe one particular media subscriber from this call media.
 */
static bool __unsubscribe_media(struct call_media * which, struct call_media * from)
{
	GList * l = g_hash_table_lookup(which->media_subscriptions_ht, from);

	if (!l) {
		ilog(LOG_DEBUG, "Media with monologue tag '" STR_FORMAT_M "' (index: %d) "
				"is not subscribed to media with monologue tag '" STR_FORMAT_M "' "
				"(index: %d). Cannot remove this media subscriber.",
				STR_FMT_M(&which->monologue->tag), which->index,
				STR_FMT_M(&from->monologue->tag), from->index);

		return false;
	}

	__unsubscribe_media_link(which, l);
	return true;
}
static bool __unsubscribe_one(struct call_monologue *which, struct call_monologue *from) {
	GList *l = g_hash_table_lookup(which->subscriptions_ht, from);
	if (!l) {
		ilog(LOG_DEBUG, "Tag '" STR_FORMAT_M "' is not subscribed to '" STR_FORMAT_M "'",
				STR_FMT_M(&which->tag),
				STR_FMT_M(&from->tag));
		return false;
	}
	__unsubscribe_one_link(which, l);
	return true;
}
static void __unsubscribe_all_offer_answer_subscribers(struct call_monologue *ml) {
	for (GList *l = ml->subscribers.head; l; ) {
		struct call_subscription *cs = l->data;
		if (!cs->attrs.offer_answer) {
			l = l->next;
			continue;
		}
		GList *next = l->next;
		struct call_monologue *other_ml = cs->monologue;
		__unsubscribe_one(other_ml, ml);
		__unsubscribe_one(ml, other_ml);
		l = next;
	}
}
/**
 * Deletes all offer/answer media subscriptions.
 */
static void __unsubscribe_all_offer_answer_medias(struct call_media * cm) {
	for (GList *l = cm->media_subscribers.head; l; )
	{
		struct media_subscription * ms = l->data;

		if (!ms->attrs.offer_answer) {
			l = l->next;
			continue;
		}

		GList * next = l->next;
		struct call_media * other_cm = ms->media;

		__unsubscribe_media(other_cm, cm);
		__unsubscribe_media(cm, other_cm);
		l = next;
	}
}
static void __unsubscribe_from_all(struct call_monologue *ml) {
	for (GList *l = ml->subscriptions.head; l; ) {
		GList *next = l->next;
		__unsubscribe_one_link(ml, l);
		l = next;
	}
}
static void __unsubscribe_medias_from_all(struct call_monologue *ml) {
	for (int i = 0; i < ml->medias->len; i++)
	{
		struct call_media * media = ml->medias->pdata[i];
		if (!media)
			continue;

		for (GList * subcription = media->media_subscriptions.head; subcription; )
		{
			GList *next = subcription->next;
			__unsubscribe_media_link(media, subcription);
			subcription = next;
		}
	}
}
static void __add_media_subscription(struct call_media * which, struct call_media * to,
		const struct sink_attrs *attrs)
{
	if (g_hash_table_lookup(which->media_subscriptions_ht, to)) {
		ilog(LOG_DEBUG, "Media with monologue tag '" STR_FORMAT_M "' (index: %d) is already subscribed"
				" to media with monologue tag '" STR_FORMAT_M "' (index: %d)",
				STR_FMT_M(&which->monologue->tag), which->index,
				STR_FMT_M(&to->monologue->tag), to->index);
		return;
	}

	ilog(LOG_DEBUG, "Subscribing media with monologue tag '" STR_FORMAT_M "' (index: %d) "
			"to media with monologue tag '" STR_FORMAT_M "' (index: %d)",
			STR_FMT_M(&which->monologue->tag), which->index,
			STR_FMT_M(&to->monologue->tag), to->index);

	struct media_subscription *which_ms = g_slice_alloc0(sizeof(*which_ms));
	struct media_subscription *to_rev_ms = g_slice_alloc0(sizeof(*to_rev_ms));

	which_ms->media = to;
	to_rev_ms->media = which;

	which_ms->monologue = to->monologue;
	to_rev_ms->monologue = which->monologue;

	/* preserve attributes if they were present previously */
	if (attrs) {
		which_ms->attrs = * attrs;
		to_rev_ms->attrs = * attrs;
	}

	/* keep offer-answer subscriptions first in the list */
	if (!attrs || !attrs->offer_answer) {
		g_queue_push_tail(&which->media_subscriptions, which_ms);
		g_queue_push_tail(&to->media_subscribers, to_rev_ms);
		which_ms->link = to->media_subscribers.tail;
		to_rev_ms->link = which->media_subscriptions.tail;
	} else {
		g_queue_push_head(&which->media_subscriptions, which_ms);
		g_queue_push_head(&to->media_subscribers, to_rev_ms);
		which_ms->link = to->media_subscribers.head;
		to_rev_ms->link = which->media_subscriptions.head;
	}

	g_hash_table_insert(which->media_subscriptions_ht, to, to_rev_ms->link);
	g_hash_table_insert(to->media_subscribers_ht, which, which_ms->link);
}
void __add_subscription(struct call_monologue *which, struct call_monologue *to,
		unsigned int offset, const struct sink_attrs *attrs)
{
	if (g_hash_table_lookup(which->subscriptions_ht, to)) {
		ilog(LOG_DEBUG, "Tag '" STR_FORMAT_M "' is already subscribed to '" STR_FORMAT_M "'",
				STR_FMT_M(&which->tag),
				STR_FMT_M(&to->tag));
		return;
	}
	ilog(LOG_DEBUG, "Subscribing '" STR_FORMAT_M "' to '" STR_FORMAT_M "'",
			STR_FMT_M(&which->tag),
			STR_FMT_M(&to->tag));
	struct call_subscription *which_cs = g_slice_alloc0(sizeof(*which_cs));
	struct call_subscription *to_rev_cs = g_slice_alloc0(sizeof(*to_rev_cs));
	which_cs->monologue = to;
	to_rev_cs->monologue = which;
	which_cs->media_offset = offset;
	to_rev_cs->media_offset = offset;
	// preserve attributes if they were present previously
	if (attrs) {
		which_cs->attrs = *attrs;
		to_rev_cs->attrs = *attrs;
	}
	// keep offer-answer subscriptions first in the list
	if (!attrs || !attrs->offer_answer) {
		g_queue_push_tail(&which->subscriptions, which_cs);
		g_queue_push_tail(&to->subscribers, to_rev_cs);
		which_cs->link = to->subscribers.tail;
		to_rev_cs->link = which->subscriptions.tail;
	}
	else {
		g_queue_push_head(&which->subscriptions, which_cs);
		g_queue_push_head(&to->subscribers, to_rev_cs);
		which_cs->link = to->subscribers.head;
		to_rev_cs->link = which->subscriptions.head;
	}
	g_hash_table_insert(which->subscriptions_ht, to, to_rev_cs->link);
	g_hash_table_insert(to->subscribers_ht, which, which_cs->link);
}
/**
 * Subscribe medias to each other.
 */
static void __subscribe_medias_both_ways(struct call_media * a, struct call_media * b)
{
	if (!a || !b)
		return;

	/* retrieve previous subscriptions to retain attributes */
	struct media_subscription *a_ms = call_get_media_subscription(a->media_subscriptions_ht, b);
	struct media_subscription *b_ms = call_get_media_subscription(b->media_subscriptions_ht, a);

	/* copy out attributes */
	struct sink_attrs a_attrs = {0,};
	struct sink_attrs b_attrs = {0,};

	if (a_ms)
		a_attrs = a_ms->attrs;
	if (b_ms)
		b_attrs = b_ms->attrs;

	/* override/reset some attributes */
	a_attrs.offer_answer = b_attrs.offer_answer = true;
	a_attrs.egress = b_attrs.egress = false;
	a_attrs.rtcp_only = b_attrs.rtcp_only = false;

	/* release existing subscriptions both ways */
	__unsubscribe_all_offer_answer_medias(a);
	__unsubscribe_all_offer_answer_medias(b);

	/* (re)create, preserving existing attributes if there have been any */
	__add_media_subscription(a, b, &a_attrs);
	__add_media_subscription(b, a, &b_attrs);
}
static void __subscribe_offer_answer_both_ways(struct call_monologue *a, struct call_monologue *b) {
	// retrieve previous subscriptions to retain attributes
	struct call_subscription *a_cs = call_get_call_subscription(a->subscriptions_ht, b);
	struct call_subscription *b_cs = call_get_call_subscription(b->subscriptions_ht, a);
	// copy out attributes
	struct sink_attrs a_attrs = {0,};
	struct sink_attrs b_attrs = {0,};
	if (a_cs)
		a_attrs = a_cs->attrs;
	if (b_cs)
		b_attrs = b_cs->attrs;
	// override/reset some attributes
	a_attrs.offer_answer = b_attrs.offer_answer = true;
	a_attrs.egress = b_attrs.egress = false;
	a_attrs.rtcp_only = b_attrs.rtcp_only = false;
	// delete existing subscriptions
	__unsubscribe_all_offer_answer_subscribers(a);
	__unsubscribe_all_offer_answer_subscribers(b);
	// (re)create, preserving existing attributes if there were any
	__add_subscription(a, b, 0, &a_attrs);
	__add_subscription(b, a, 0, &b_attrs);
}

/**
 * Subscribe media lines to each other respecting the given order in the SDP offer/answer.
 * If there are `media_id` (mid) presented, then use a mid ordering instead.
 */
static void __subscribe_matched_medias(struct call_monologue * a_ml, struct call_monologue * b_ml)
{
	GPtrArray * a_medias = a_ml->medias;
	GPtrArray * b_medias = b_ml->medias;

	/* A properly formed answer SDP has the same number of m= lines as the offer SDP,
	 * and in the same order. Media types must match up. */
	if (a_medias->len != b_medias->len) {
		ilog(LOG_WARN, "Non-matching amount of media sections in monologues, cannot subscribe them!");
		return;
	}

	for (int i = 0; i < a_medias->len; i++)
	{
		struct call_media * a_media = a_medias->pdata[i];
		struct call_media * b_media;

		if (!a_media)
			continue;

		/* first try matching based on media_id */
		if (a_media->media_id.s) {
			b_media = g_hash_table_lookup(b_ml->media_ids, &a_media->media_id);
			if (b_media) {
				__subscribe_medias_both_ways(a_media, b_media);
				continue; /* we found a matched one, go ahead to another one */
			}
		}

		/* then a matching based on usual ordering */
		b_media = b_medias->pdata[i];
		if (!b_media)
			continue;

		if (a_media->type_id != b_media->type_id) {
			ilog(LOG_WARN, "Wrong ordering of media sections in monologues, skip the '%d' media section.", i);
			continue;
		}
		__subscribe_medias_both_ways(a_media, b_media);
	}
}

/**
 * Retrieve exsisting media subscriptions for a call monologue.
 */
struct media_subscription *call_get_media_subscription(GHashTable *ht, struct call_media * cm) {
	GList * l = g_hash_table_lookup(ht, cm);
	if (!l)
		return NULL;
	return l->data;
}
struct call_subscription *call_get_call_subscription(GHashTable *ht, struct call_monologue *ml) {
	GList *l = g_hash_table_lookup(ht, ml);
	if (!l)
		return NULL;
	return l->data;
}

/* called with call->master_lock held in W */
__attribute__((nonnull(1, 2, 3)))
int monologue_publish(struct call_monologue *ml, GQueue *streams, struct sdp_ng_flags *flags) {
	__call_monologue_init_from_flags(ml, flags);

	if (flags->exclude_recording)
		ml->no_recording = 1;

	for (GList *l = streams->head; l; l = l->next) {
		struct stream_params *sp = l->data;
		struct call_media *media = __get_media(ml, sp, flags, 0);

		__media_init_from_flags(media, NULL, sp, flags);

		codec_store_populate(&media->codecs, &sp->codecs,
				.allow_asymmetric = !!flags->allow_asymmetric_codecs);
		if (codec_store_accept_one(&media->codecs, &flags->codec_accept, !!flags->accept_any))
			return -1;

		// the most we can do is receive
		bf_copy(&media->media_flags, MEDIA_FLAG_RECV, &sp->sp_flags, SP_FLAG_SEND);

		if (sp->rtp_endpoint.port) {
			__dtls_logic(flags, media, sp);
			__generate_crypto(flags, media, NULL);
		}

		unsigned int num_ports = proto_num_ports(sp->num_ports, media, flags, true);

		/* local interface selection */
		__init_interface(media, &flags->interface, num_ports);

		if (media->logical_intf == NULL)
			return -1; // XXX return error code

		/* ICE stuff - must come after interface and address family selection */
		__ice_offer(flags, media, media, ice_is_restart(media->ice_agent, sp));

		MEDIA_SET(media, INITIALIZED);

		if (!sp->rtp_endpoint.port) {
			/* Zero port: stream has been rejected.
			 * RFC 3264, chapter 6:
			 * If a stream is rejected, the offerer and answerer MUST NOT
			 * generate media (or RTCP packets) for that stream. */
			__disable_streams(media, num_ports);
			continue;
		}

		struct endpoint_map *em = __get_endpoint_map(media, num_ports, NULL, flags, true);
		if (!em)
			return -1; // XXX error - no ports

		__num_media_streams(media, num_ports);
		__assign_stream_fds(media, &em->intf_sfds);

		// XXX this should be covered by __update_init_subscribers ?
		if (__init_streams(media, NULL, sp, flags, NULL))
			return -1;
		__ice_start(media);
		ice_update(media->ice_agent, sp, false);
	}

	return 0;
}

/* called with call->master_lock held in W */
__attribute__((nonnull(1, 2, 3, 4)))
static int monologue_subscribe_request1(struct call_monologue *src_ml, struct call_monologue *dst_ml,
		struct sdp_ng_flags *flags, unsigned int *index)
{
	unsigned int idx_diff = 0, rev_idx_diff = 0;

	for (GList *l = src_ml->last_in_sdp_streams.head; l; l = l->next) {
		struct stream_params *sp = l->data;

		struct call_media *dst_media = __get_media(dst_ml, sp, flags, (*index)++);
		struct call_media *src_media = __get_media(src_ml, sp, flags, 0);

		/* subscribe dst_ml (subscriber) to src_ml, don't forget to carry the egress flag, if required */
		__add_media_subscription(dst_media, src_media, &(struct sink_attrs) { .egress = !!flags->egress });
		/* mirroring, so vice-versa: src_media gets subscribed to dst_media (subscriber) */
		if (flags->rtcp_mirror)
			__add_media_subscription(src_media, dst_media,
				&(struct sink_attrs) { .egress = !!flags->egress, .rtcp_only = true });

		// track media index difference if one ml is subscribed to multiple other mls
		if (idx_diff == 0 && dst_media->index > src_media->index)
			idx_diff = dst_media->index - src_media->index;
		if (rev_idx_diff == 0 && src_media->index > dst_media->index)
			rev_idx_diff = src_media->index - dst_media->index;

		__media_init_from_flags(src_media, dst_media, sp, flags);

		codec_store_populate(&dst_media->codecs, &src_media->codecs,
				.allow_asymmetric = !!flags->allow_asymmetric_codecs);
		codec_store_strip(&dst_media->codecs, &flags->codec_strip, flags->codec_except);
		codec_store_strip(&dst_media->codecs, &flags->codec_consume, flags->codec_except);
		codec_store_strip(&dst_media->codecs, &flags->codec_mask, flags->codec_except);
		codec_store_offer(&dst_media->codecs, &flags->codec_offer, &sp->codecs);
		codec_store_transcode(&dst_media->codecs, &flags->codec_transcode, &sp->codecs);
		codec_store_synthesise(&dst_media->codecs, &src_media->codecs);

		codec_handlers_update(dst_media, src_media, .flags = flags, .sp = sp,
				.allow_asymmetric = !!flags->allow_asymmetric_codecs);

		if (!flags->inactive)
			bf_copy(&dst_media->media_flags, MEDIA_FLAG_SEND, &src_media->media_flags, SP_FLAG_RECV);
		else
			MEDIA_CLEAR(dst_media, SEND);
		MEDIA_CLEAR(dst_media, RECV);

		__rtcp_mux_set(flags, dst_media);
		__generate_crypto(flags, dst_media, src_media);

		unsigned int num_ports = proto_num_ports(sp->num_ports, dst_media, flags, false);

		// interface selection
		__init_interface(dst_media, &flags->interface, num_ports);
		if (dst_media->logical_intf == NULL)
			return -1; // XXX return error code

		__ice_offer(flags, dst_media, src_media, ice_is_restart(src_media->ice_agent, sp));

		struct endpoint_map *em = __get_endpoint_map(dst_media, num_ports, NULL, flags, true);
		if (!em)
			return -1; // XXX error - no ports

		__num_media_streams(dst_media, num_ports);
		__assign_stream_fds(dst_media, &em->intf_sfds);

		if (__init_streams(dst_media, NULL, NULL, flags, NULL))
			return -1;
	}

	__add_subscription(dst_ml, src_ml, idx_diff, &(struct sink_attrs) { .egress = !!flags->egress });
	if (flags->rtcp_mirror)
		__add_subscription(src_ml, dst_ml, rev_idx_diff,
				&(struct sink_attrs) { .egress = !!flags->egress, .rtcp_only = true });

	__update_init_subscribers(src_ml, NULL, NULL, flags->opmode);
	__update_init_subscribers(dst_ml, NULL, NULL, flags->opmode);

	return 0;
}
/* called with call->master_lock held in W */
__attribute__((nonnull(1, 2, 3)))
int monologue_subscribe_request(const GQueue *srcs, struct call_monologue *dst_ml,
		struct sdp_ng_flags *flags)
{
	__unsubscribe_from_all(dst_ml);
	__unsubscribe_medias_from_all(dst_ml);	/* analogy for media subscriptions */

	__call_monologue_init_from_flags(dst_ml, flags);

	unsigned int index = 1; // running counter for output/dst medias

	for (GList *sl = srcs->head; sl; sl = sl->next) {
		struct call_subscription *cs = sl->data;
		struct call_monologue *src_ml = cs->monologue;

		int ret = monologue_subscribe_request1(src_ml, dst_ml, flags, &index);
		if (ret)
			return -1;
	}
	return 0;
}

/* called with call->master_lock held in W */
__attribute__((nonnull(1, 2, 3)))
int monologue_subscribe_answer(struct call_monologue *dst_ml, struct sdp_ng_flags *flags, GQueue *streams) {
	GList *src_ml_it = dst_ml->subscriptions.head;
	unsigned int index = 1; // running counter for input/src medias

	struct call_subscription *rev_cs = NULL;

	for (GList *l = streams->head; l; l = l->next) {
		if (!src_ml_it)
			return -1;

		struct stream_params *sp = l->data;

		struct call_subscription *cs = src_ml_it->data;
		struct call_monologue *src_ml = cs->monologue;

		// grab the matching source ml:
		// we need to move to the next one when we've reached the last media of
		// the current source ml
		if (index > src_ml->medias->len) {
			src_ml_it = src_ml_it->next;
			if (!src_ml_it)
				return -1;
			index = 1; // starts over at 1
			cs = src_ml_it->data;
			src_ml = cs->monologue;
			rev_cs = NULL;
		}

		if (!rev_cs) {
			rev_cs = find_subscription(src_ml, dst_ml);
			rev_cs->attrs.transcoding = 0;
		}

		struct call_media *dst_media = __get_media(dst_ml, sp, flags, 0);
		struct call_media *src_media = __get_media(src_ml, sp, flags, index++);

		__media_init_from_flags(dst_media, NULL, sp, flags);

		if (flags->allow_transcoding) {
			codec_store_populate(&dst_media->codecs, &sp->codecs,
					.codec_set = flags->codec_set,
					.answer_only = true,
					.allow_asymmetric = !!flags->allow_asymmetric_codecs);
			codec_store_strip(&dst_media->codecs, &flags->codec_strip, flags->codec_except);
			codec_store_offer(&dst_media->codecs, &flags->codec_offer, &sp->codecs);
		}
		else {
			codec_store_populate(&dst_media->codecs, &sp->codecs, .answer_only = true,
					.allow_asymmetric = !!flags->allow_asymmetric_codecs);
			if (!codec_store_is_full_answer(&src_media->codecs, &dst_media->codecs))
				return -1;
		}

		codec_handlers_update(src_media, dst_media, .flags = flags,
				.allow_asymmetric = !!flags->allow_asymmetric_codecs);
		codec_handlers_update(dst_media, src_media, .flags = flags, .sp = sp,
				.allow_asymmetric = !!flags->allow_asymmetric_codecs,
				.reset_transcoding = true);

		__dtls_logic(flags, dst_media, sp);

		if (__init_streams(dst_media, NULL, sp, flags, NULL))
			return -1;

		MEDIA_CLEAR(dst_media, RECV);
		bf_copy(&dst_media->media_flags, MEDIA_FLAG_SEND, &sp->sp_flags, SP_FLAG_RECV);

		// XXX check answer SDP parameters

		MEDIA_SET(dst_media, INITIALIZED);
	}

	__update_init_subscribers(dst_ml, streams, flags, flags->opmode);
	dialogue_unkernelize(dst_ml, "subscribe answer event");

	for (GList *l = dst_ml->subscriptions.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		struct call_monologue *src_ml = cs->monologue;
		set_monologue_flags_per_subscribers(src_ml);
		__update_init_subscribers(src_ml, NULL, NULL, flags->opmode);
		dialogue_unkernelize(src_ml, "subscribe answer event");
	}

	return 0;
}

/* called with call->master_lock held in W */
__attribute__((nonnull(1, 2)))
int monologue_unsubscribe(struct call_monologue *dst_ml, struct sdp_ng_flags *flags) {
	for (GList *l = dst_ml->subscriptions.head; l; ) {
		GList *next = l->next;
		struct call_subscription *cs = l->data;
		struct call_monologue *src_ml = cs->monologue;

		__unsubscribe_one_link(dst_ml, l);

		__update_init_subscribers(dst_ml, NULL, NULL, flags->opmode);
		__update_init_subscribers(src_ml, NULL, NULL, flags->opmode);

		dialogue_unkernelize(src_ml, "monologue unsubscribe");
		dialogue_unkernelize(dst_ml, "monologue unsubscribe");

		l = next;
	}

	return 0;
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

	rtp_pt = rtp_payload_type(rtp_s->payload_type, &m->codecs);

out:
	g_list_free(values);
	return rtp_pt; /* may be NULL */
}

void add_total_calls_duration_in_interval(struct timeval *interval_tv) {
	struct timeval ongoing_calls_dur = add_ongoing_calls_dur_in_interval(
			&rtpe_latest_graphite_interval_start, interval_tv);
	RTPE_STATS_ADD(total_calls_duration_intv, timeval_us(&ongoing_calls_dur));
}

static struct timeval add_ongoing_calls_dur_in_interval(struct timeval *interval_start,
		struct timeval *interval_duration)
{
	struct timeval call_duration, res = {0};
	struct call_monologue *ml;

	ITERATE_CALL_LIST_START(CALL_ITERATOR_GRAPHITE, call);

		if (!call->monologues.head || IS_FOREIGN_CALL(call))
			goto next;
		ml = call->monologues.head->data;
		if (timercmp(interval_start, &ml->started, >)) {
			timeval_add(&res, &res, interval_duration);
		} else {
			timeval_subtract(&call_duration, &rtpe_now, &ml->started);
			timeval_add(&res, &res, &call_duration);
		}
next:
		;
	ITERATE_CALL_LIST_NEXT_END(call);

	return res;
}

static void __call_cleanup(struct call *c) {
	for (GList *l = c->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;

		send_timer_put(&ps->send_timer);
		jb_put(&ps->jb);
		__unkernelize(ps, "final call cleanup");
		dtls_shutdown(ps);
		ps->selected_sfd = NULL;
		g_queue_clear(&ps->sfds);
		crypto_cleanup(&ps->crypto);

		g_queue_clear_full(&ps->rtp_sinks, free_sink_handler);
		g_queue_clear_full(&ps->rtcp_sinks, free_sink_handler);
		g_queue_clear_full(&ps->rtp_mirrors, free_sink_handler);
	}

	for (GList *l = c->medias.head; l; l = l->next) {
		struct call_media *md = l->data;
		ice_shutdown(&md->ice_agent);
		media_stop(md);
		t38_gateway_put(&md->t38_gateway);
		audio_player_free(md);
	}

	for (GList *l = c->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		__monologue_stop(ml);
		media_player_put(&ml->player);
		if (ml->tone_freqs)
			g_array_free(ml->tone_freqs, true);
		if (ml->janus_session)
			obj_put_o((void *) ml->janus_session);
		ml->janus_session = NULL;
	}

	while (c->stream_fds.head) {
		struct stream_fd *sfd = g_queue_pop_head(&c->stream_fds);
		stream_fd_release(sfd);
		obj_put(sfd);
	}

	recording_finish(c, false);
}

/* called lock-free, but must hold a reference to the call */
void call_destroy(struct call *c) {
	struct packet_stream *ps=0;
	GList *l;
	struct call_monologue *ml;
	struct call_media *md;
	GList *k, *o;
	const struct rtp_payload_type *rtp_pt;

	if (!c) {
		return;
	}

	rwlock_lock_w(&rtpe_callhash_lock);
	struct call *call_ht = NULL;
	g_hash_table_steal_extended(rtpe_callhash, &c->callid, NULL, (void **) &call_ht);
	if (call_ht) {
		if (call_ht != c) {
			g_hash_table_insert(rtpe_callhash, &call_ht->callid, call_ht);
			call_ht = NULL;
		}
		else
			RTPE_GAUGE_DEC(total_sessions);
	}
	rwlock_unlock_w(&rtpe_callhash_lock);

	// if call not found in callhash => previously deleted
	if (!call_ht)
		return;

	obj_put(c);


	statistics_update_ip46_inc_dec(c, CMC_DECREMENT);
	statistics_update_foreignown_dec(c);

	redis_delete(c, rtpe_redis_write);

	__call_iterator_remove(c);

	rwlock_lock_w(&c->master_lock);
	/* at this point, no more packet streams can be added */

	mqtt_timer_stop(&c->mqtt_timer);

	if (!IS_OWN_CALL(c))
		goto no_stats_output;

	///// stats output

	ilog(LOG_INFO, "Final packet stats:");

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;

		// stats output only - no cleanups

		ilog(LOG_INFO, "--- Tag '" STR_FORMAT_M "'%s"STR_FORMAT"%s, created "
				"%u:%02u ago for branch '" STR_FORMAT_M "'",
				STR_FMT_M(&ml->tag),
				ml->label.s ? " (label '" : "",
				STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
				ml->label.s ? "')" : "",
				(unsigned int) (rtpe_now.tv_sec - ml->created) / 60,
				(unsigned int) (rtpe_now.tv_sec - ml->created) % 60,
				STR_FMT_M(&ml->viabranch));

		for (GList *sub = ml->subscriptions.head; sub; sub = sub->next) {
			struct call_subscription *cs = sub->data;
			struct call_monologue *csm = cs->monologue;
			ilog(LOG_INFO, "---     subscribed to '" STR_FORMAT_M "'",
					STR_FMT_M(&csm->tag));
		}
		for (GList *sub = ml->subscribers.head; sub; sub = sub->next) {
			struct call_subscription *cs = sub->data;
			struct call_monologue *csm = cs->monologue;
			ilog(LOG_INFO, "---     subscription for '" STR_FORMAT_M "'",
					STR_FMT_M(&csm->tag));
		}

		for (unsigned int m = 0; m < ml->medias->len; m++) {
			md = ml->medias->pdata[m];
			if (!md)
				continue;

			// stats output only - no cleanups

#define MLL_PREFIX "------ Media #%u ("STR_FORMAT" over %s) using " /* media log line prefix */
#define MLL_COMMON /* common args */						\
				md->index,				\
				STR_FMT(&md->type),			\
				md->protocol ? md->protocol->name : "(unknown)"

			if (proto_is_rtp(md->protocol)) {
				rtp_pt = __rtp_stats_codec(md);
				if (!rtp_pt)
					ilog(LOG_INFO, MLL_PREFIX "unknown codec", MLL_COMMON);
				else
					ilog(LOG_INFO, MLL_PREFIX STR_FORMAT, MLL_COMMON,
							STR_FMT(&rtp_pt->encoding_with_params));
			}
			else {
				ilog(LOG_INFO, MLL_PREFIX STR_FORMAT, MLL_COMMON,
						STR_FMT(&md->format_str));
			}

			for (o = md->streams.head; o; o = o->next) {
				ps = o->data;

				// stats output only - no cleanups

				if (PS_ISSET(ps, FALLBACK_RTCP))
					continue;

				char *addr = sockaddr_print_buf(&ps->endpoint.address);
				endpoint_t *local_endpoint = packet_stream_local_addr(ps);
				char *local_addr = sockaddr_print_buf(&local_endpoint->address);

				ilog(LOG_INFO, "--------- Port %15s:%-5u <> %s%15s:%-5u%s%s, SSRC %s%" PRIx32 "%s, in "
						UINT64F " p, " UINT64F " b, " UINT64F " e, " UINT64F " ts, "
						"out " UINT64F " p, " UINT64F " b, " UINT64F " e",
						local_addr,
						(unsigned int) local_endpoint->port,
						FMT_M(addr, ps->endpoint.port),
						(!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
						FMT_M(ps->ssrc_in[0] ? ps->ssrc_in[0]->parent->h.ssrc : 0),
						atomic64_get(&ps->stats_in.packets),
						atomic64_get(&ps->stats_in.bytes),
						atomic64_get(&ps->stats_in.errors),
						rtpe_now.tv_sec - atomic64_get(&ps->last_packet),
						atomic64_get(&ps->stats_out.packets),
						atomic64_get(&ps->stats_out.bytes),
						atomic64_get(&ps->stats_out.errors));
			}
		}

		k = g_hash_table_get_values(ml->ssrc_hash->ht);
		while (k) {
			struct ssrc_entry_call *se = k->data;

			// stats output only - no cleanups

			if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
				goto next_k;
			int mos_samples = (se->stats_blocks.length - se->no_mos_count);
			if (mos_samples < 1) mos_samples = 1;

			ilog(LOG_INFO, "--- SSRC %s%" PRIx32 "%s", FMT_M(se->h.ssrc));
			ilog(LOG_INFO, "------ Average MOS %" PRIu64 ".%" PRIu64 ", "
					"lowest MOS %" PRIu64 ".%" PRIu64 " (at %u:%02u), "
					"highest MOS %" PRIu64 ".%" PRIu64 " (at %u:%02u) lost:%u",
				se->average_mos.mos / mos_samples / 10,
				se->average_mos.mos / mos_samples % 10,
				se->lowest_mos->mos / 10,
				se->lowest_mos->mos % 10,
				(unsigned int) (timeval_diff(&se->lowest_mos->reported, &c->created) / 1000000) / 60,
				(unsigned int) (timeval_diff(&se->lowest_mos->reported, &c->created) / 1000000) % 60,
				se->highest_mos->mos / 10,
				se->highest_mos->mos % 10,
				(unsigned int) (timeval_diff(&se->highest_mos->reported, &c->created) / 1000000) / 60,
				(unsigned int) (timeval_diff(&se->highest_mos->reported, &c->created) / 1000000) % 60,
				(unsigned int) se->packets_lost);
			ilog(LOG_INFO, "------ respective (avg/min/max) jitter %" PRIu64 "/%" PRIu64 "/%" PRIu64 " ms, "
					"RTT-e2e %" PRIu64 ".%" PRIu64 "/%" PRIu64 ".%" PRIu64
					"/%" PRIu64 ".%" PRIu64 " ms, "
					"RTT-dsct %" PRIu32 ".%" PRIu32 "/%" PRIu32 ".%" PRIu32
					"/%" PRIu32 ".%" PRIu32 " ms, "
					"packet loss %" PRIu64 "/%" PRIu64 "/%" PRIu64 "%%",
					se->average_mos.jitter / mos_samples,
					se->lowest_mos->jitter,
					se->highest_mos->jitter,
					se->average_mos.rtt / mos_samples / 1000,
					(se->average_mos.rtt / mos_samples / 100) % 10,
					se->lowest_mos->rtt / 1000,
					(se->lowest_mos->rtt / 100) % 10,
					se->highest_mos->rtt / 1000,
					(se->highest_mos->rtt / 100) % 10,
					se->average_mos.rtt_leg / mos_samples / 1000,
					(se->average_mos.rtt_leg / mos_samples / 100) % 10,
					se->lowest_mos->rtt_leg / 1000,
					(se->lowest_mos->rtt_leg / 100) % 10,
					se->highest_mos->rtt_leg / 1000,
					(se->highest_mos->rtt_leg / 100) % 10,
					se->average_mos.packetloss / mos_samples,
					se->lowest_mos->packetloss,
					se->highest_mos->packetloss);

next_k:
			k = g_list_delete_link(k, k);
		}
	}


no_stats_output:
	// cleanups

	statistics_update_oneway(c);

	cdr_update_entry(c);

	__call_cleanup(c);

	rwlock_unlock_w(&c->master_lock);
}


int call_stream_address46(char *o, struct packet_stream *ps, enum stream_address_format format,
		int *len, const struct local_intf *ifa, bool keep_unspec)
{
	int l = 0;
	const struct intf_address *ifa_addr;

	if (!ifa) {
		if (ps->selected_sfd)
			ifa = ps->selected_sfd->local_intf;
		else
			ifa = get_any_interface_address(ps->media->logical_intf, ps->media->desired_family);
	}
	ifa_addr = &ifa->spec->local_address;

	if (format == SAF_NG)
		l += sprintf(o + l, "%s ", ifa_addr->addr.family->rfc_name);

	if (PS_ISSET(ps, ZERO_ADDR) && keep_unspec)
		l += sprintf(o + l, "%s", ifa_addr->addr.family->unspec_string);
	else
		l += sprintf(o + l, "%s", sockaddr_print_buf(&ifa->advertised_address.addr));

	*len = l;
	return ifa_addr->addr.family->af;
}

void media_subscription_free(void *p) {
	g_slice_free1(sizeof(struct media_subscription), p);
}

void call_media_free(struct call_media **mdp) {
	struct call_media *md = *mdp;
	crypto_params_sdes_queue_clear(&md->sdes_in);
	crypto_params_sdes_queue_clear(&md->sdes_out);
	g_queue_clear(&md->streams);
	g_queue_clear(&md->endpoint_maps);
	codec_store_cleanup(&md->codecs);
	codec_handlers_free(md);
	codec_handler_free(&md->t38_handler);
	t38_gateway_put(&md->t38_gateway);
	g_queue_clear_full(&md->sdp_attributes, free);
	g_queue_clear_full(&md->dtmf_recv, dtmf_event_free);
	g_queue_clear_full(&md->dtmf_send, dtmf_event_free);
	g_hash_table_destroy(md->media_subscribers_ht);
	g_hash_table_destroy(md->media_subscriptions_ht);
	g_queue_clear_full(&md->media_subscribers, media_subscription_free);
	g_queue_clear_full(&md->media_subscriptions, media_subscription_free);
	mutex_destroy(&md->dtmf_lock);
	g_slice_free1(sizeof(*md), md);
	*mdp = NULL;
}

void call_subscription_free(void *p) {
	g_slice_free1(sizeof(struct call_subscription), p);
}

void __monologue_free(struct call_monologue *m) {
	g_ptr_array_free(m->medias, true);
	g_hash_table_destroy(m->associated_tags);
	g_hash_table_destroy(m->media_ids);
	free_ssrc_hash(&m->ssrc_hash);
	if (m->last_out_sdp)
		g_string_free(m->last_out_sdp, TRUE);
	str_free_dup(&m->last_in_sdp);
	sdp_free(&m->last_in_sdp_parsed);
	sdp_streams_free(&m->last_in_sdp_streams);
	g_hash_table_destroy(m->subscribers_ht);
	g_hash_table_destroy(m->subscriptions_ht);
	g_queue_clear_full(&m->subscribers, call_subscription_free);
	g_queue_clear_full(&m->subscriptions, call_subscription_free);
	g_slice_free1(sizeof(*m), m);
}

static void __call_free(void *p) {
	struct call *c = p;
	struct call_monologue *m;
	struct call_media *md;
	struct packet_stream *ps;
	struct endpoint_map *em;

	//ilog(LOG_DEBUG, "freeing main call struct");

	if (c->dtls_cert)
		obj_put(c->dtls_cert);
	mqtt_timer_stop(&c->mqtt_timer);

	while (c->monologues.head) {
		m = g_queue_pop_head(&c->monologues);
		__monologue_free(m);
	}

	while (c->medias.head) {
		md = g_queue_pop_head(&c->medias);
		call_media_free(&md);
	}

	while (c->endpoint_maps.head) {
		em = g_queue_pop_head(&c->endpoint_maps);

		g_queue_clear_full(&em->intf_sfds, (void *) free_intf_list);
		g_slice_free1(sizeof(*em), em);
	}

	g_hash_table_destroy(c->tags);
	g_hash_table_destroy(c->viabranches);
	g_hash_table_destroy(c->labels);

	while (c->streams.head) {
		ps = g_queue_pop_head(&c->streams);
		crypto_cleanup(&ps->crypto);
		g_queue_clear(&ps->sfds);
		g_hash_table_destroy(ps->rtp_stats);
		for (unsigned int u = 0; u < G_N_ELEMENTS(ps->ssrc_in); u++)
			ssrc_ctx_put(&ps->ssrc_in[u]);
		for (unsigned int u = 0; u < G_N_ELEMENTS(ps->ssrc_out); u++)
			ssrc_ctx_put(&ps->ssrc_out[u]);
		g_slice_free1(sizeof(*ps), ps);
	}

	call_buffer_free(&c->buffer);
	mutex_destroy(&c->buffer_lock);
	rwlock_destroy(&c->master_lock);

	assert(c->stream_fds.head == NULL);
}

static struct call *call_create(const str *callid) {
	struct call *c;

	ilog(LOG_NOTICE, "Creating new call");
	c = obj_alloc0("call", sizeof(*c), __call_free);
	mutex_init(&c->buffer_lock);
	call_buffer_init(&c->buffer);
	rwlock_init(&c->master_lock);
	c->tags = g_hash_table_new(str_hash, str_equal);
	c->viabranches = g_hash_table_new(str_hash, str_equal);
	c->labels = g_hash_table_new(str_hash, str_equal);
	call_str_cpy(c, &c->callid, callid);
	c->created = rtpe_now;
	c->dtls_cert = dtls_cert();
	c->tos = rtpe_config.default_tos;
	if (rtpe_config.cpu_affinity)
		c->cpu_affinity = call_socket_cpu_affinity++ % rtpe_config.cpu_affinity;
	else
		c->cpu_affinity = -1;

	for (int i = 0; i < NUM_CALL_ITERATORS; i++) {
		mutex_init(&c->iterator[i].next_lock);
		mutex_init(&c->iterator[i].prev_lock);
	}

	return c;
}

/* returns call with master_lock held in W */
struct call *call_get_or_create(const str *callid, bool foreign, bool exclusive) {
	struct call *c;

restart:
	rwlock_lock_r(&rtpe_callhash_lock);
	c = g_hash_table_lookup(rtpe_callhash, callid);
	if (!c) {
		rwlock_unlock_r(&rtpe_callhash_lock);
		/* completely new call-id, create call */
		c = call_create(callid);
		rwlock_lock_w(&rtpe_callhash_lock);
		if (g_hash_table_lookup(rtpe_callhash, callid)) {
			/* preempted */
			rwlock_unlock_w(&rtpe_callhash_lock);
			obj_put(c);
			goto restart;
		}
		g_hash_table_insert(rtpe_callhash, &c->callid, obj_get(c));
		RTPE_GAUGE_INC(total_sessions);

		c->foreign_call = foreign ? 1 : 0;

		statistics_update_foreignown_inc(c);

		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_w(&rtpe_callhash_lock);

		for (int i = 0; i < NUM_CALL_ITERATORS; i++) {
			c->iterator[i].link.data = obj_get(c);
			struct call *first_call;
			while (1) {
				// lock the list
				mutex_lock(&rtpe_call_iterators[i].lock);
				// if there is a first entry, lock that
				first_call = NULL;
				if (rtpe_call_iterators[i].first) {
					first_call = rtpe_call_iterators[i].first->data;
					// coverity[lock_order : FALSE]
					if (mutex_trylock(&first_call->iterator[i].prev_lock)) {
						mutex_unlock(&rtpe_call_iterators[i].lock);
						continue; // retry
					}
				}
				// we can insert now
				break;
			}
			rtpe_call_iterators[i].first
				= g_list_insert_before_link(rtpe_call_iterators[i].first,
					rtpe_call_iterators[i].first, &c->iterator[i].link);
			if (first_call)
				mutex_unlock(&first_call->iterator[i].prev_lock);
			mutex_unlock(&rtpe_call_iterators[i].lock);
		}

		if (mqtt_publish_scope() == MPS_CALL)
			mqtt_timer_start(&c->mqtt_timer, c, NULL);
	}
	else {
		if (exclusive)
			c = NULL;
		else {
			obj_hold(c);
			rwlock_lock_w(&c->master_lock);
		}
		rwlock_unlock_r(&rtpe_callhash_lock);
	}

	if (c)
		log_info_call(c);
	return c;
}

/** returns call with master_lock held in W, or NULL if not found
 * 
 * The lookup of a call is performed via its call-ID.
 * A reference to the call object is returned with
 * the reference-count increased by one.
 * 
 * Therefore the code must use obj_put() on the call after call_get()
 * and after it's done operating on the object.
 */
struct call *call_get(const str *callid) {
	struct call *ret;

	rwlock_lock_r(&rtpe_callhash_lock);
	ret = g_hash_table_lookup(rtpe_callhash, callid);
	if (!ret) {
		rwlock_unlock_r(&rtpe_callhash_lock);
		return NULL;
	}

	rwlock_lock_w(&ret->master_lock);
	obj_hold(ret);
	rwlock_unlock_r(&rtpe_callhash_lock);

	log_info_call(ret);
	return ret;
}

/* returns call with master_lock held in W, or possibly NULL iff opmode == OP_ANSWER */
struct call *call_get_opmode(const str *callid, enum call_opmode opmode) {
	if (opmode == OP_OFFER)
		return call_get_or_create(callid, false, false);
	return call_get(callid);
}

/**
 * Create a new monologue, without assigning a tag to that.
 * Allocate all required hash tables for it.
 *
 * Also give the non reference-counted ptr to the call it belongs to.
 *
 * Must be called with call->master_lock held in W.
 */
struct call_monologue *__monologue_create(struct call *call) {
	struct call_monologue *ret;

	__C_DBG("creating new monologue");
	ret = uid_slice_alloc0(ret, &call->monologues);

	ret->call = call;
	ret->created = rtpe_now.tv_sec;
	ret->associated_tags = g_hash_table_new(g_direct_hash, g_direct_equal);
	ret->medias = g_ptr_array_new();
	ret->media_ids = g_hash_table_new(str_hash, str_equal);
	ret->ssrc_hash = create_ssrc_hash_call();
	ret->subscribers_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	ret->subscriptions_ht = g_hash_table_new(g_direct_hash, g_direct_equal);

	gettimeofday(&ret->started, NULL);

	return ret;
}

/**
 * Assign a new tag to the given monologue.
 * Additionally, remove older monologue tag from the correlated call tags,
 * and add a newer one.
 *
 * Must be called with call->master_lock held in W.
 */
void __monologue_tag(struct call_monologue *ml, const str *tag) {
	struct call *call = ml->call;

	__C_DBG("tagging monologue with '"STR_FORMAT"'", STR_FMT(tag));
	if (ml->tag.s)
		g_hash_table_remove(call->tags, &ml->tag);	/* remove tag from tags of the call object */
	call_str_cpy(call, &ml->tag, tag);
	g_hash_table_insert(call->tags, &ml->tag, ml); 		/* and insert a new one */
}

void __monologue_viabranch(struct call_monologue *ml, const str *viabranch) {
	struct call *call = ml->call;

	if (!viabranch || !viabranch->len)
		return;

	__C_DBG("tagging monologue with viabranch '"STR_FORMAT"'", STR_FMT(viabranch));
	if (ml->viabranch.s)
		g_hash_table_remove(call->viabranches, &ml->viabranch);
	call_str_cpy(call, &ml->viabranch, viabranch);
	g_hash_table_insert(call->viabranches, &ml->viabranch, ml);
}

static void __unconfirm_sinks(GQueue *q, const char *reason) {
	for (GList *l = q->head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		__stream_unconfirm(sh->sink, reason);
	}
}
/* must be called with call->master_lock held in W */
void __monologue_unkernelize(struct call_monologue *monologue, const char *reason) {
	if (!monologue)
		return;

	for (unsigned int i = 0; i < monologue->medias->len; i++) {
		struct call_media *media = monologue->medias->pdata[i];
		if (!media)
			continue;

		for (GList *m = media->streams.head; m; m = m->next) {
			struct packet_stream *stream = m->data;
			__stream_unconfirm(stream, reason);
			__unconfirm_sinks(&stream->rtp_sinks, reason);
			__unconfirm_sinks(&stream->rtcp_sinks, reason);
		}
	}
}
/* must be called with call->master_lock held in W */
void __media_unconfirm(struct call_media *media, const char *reason) {
	if (!media)
		return;

	for (GList *m = media->streams.head; m; m = m->next) {
		struct packet_stream *stream = m->data;
		__stream_unconfirm(stream, reason);
		__unconfirm_sinks(&stream->rtp_sinks, reason);
		__unconfirm_sinks(&stream->rtcp_sinks, reason);
	}
}
void dialogue_unkernelize(struct call_monologue *ml, const char *reason) {
	__monologue_unkernelize(ml, reason);

	for (GList *sub = ml->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		__monologue_unkernelize(cs->monologue, reason);
	}
	for (GList *sub = ml->subscribers.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		__monologue_unkernelize(cs->monologue, reason);
	}
}

static void __unkernelize_sinks(GQueue *q, const char *reason) {
	for (GList *l = q->head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		unkernelize(sh->sink, reason);
	}
}
/* call locked in R */
void call_media_unkernelize(struct call_media *media, const char *reason) {
	if (!media)
		return;
	for (GList *m = media->streams.head; m; m = m->next) {
		struct packet_stream *stream = m->data;
		unkernelize(stream, reason);
		__unkernelize_sinks(&stream->rtp_sinks, reason);
		__unkernelize_sinks(&stream->rtcp_sinks, reason);
	}
}

/* must be called with call->master_lock held in W */
static void __tags_unassociate_all(struct call_monologue *a) {
	GHashTableIter iter;
	g_hash_table_iter_init(&iter, a->associated_tags);
	struct call_monologue *b;
	while (g_hash_table_iter_next(&iter, (void **) &b, NULL))
		g_hash_table_remove(b->associated_tags, a);
	g_hash_table_remove_all(a->associated_tags);
}

void monologue_destroy(struct call_monologue *monologue) {
	struct call *call;

	call = monologue->call;

	ilog(LOG_DEBUG, "Destroying monologue '" STR_FORMAT "' (" STR_FORMAT ")",
			STR_FMT(&monologue->tag),
			STR_FMT0(&monologue->viabranch));

	__monologue_unkernelize(monologue, "destroying monologue");
	__tags_unassociate_all(monologue);

	g_hash_table_remove(call->tags, &monologue->tag);
	if (monologue->viabranch.s)
		g_hash_table_remove(call->viabranches, &monologue->viabranch);

	// close sockets
	for (unsigned int i = 0; i < monologue->medias->len; i++) {
		struct call_media *m = monologue->medias->pdata[i];
		if (!m)
			continue;
		for (GList *k = m->streams.head; k; k = k->next) {
			struct packet_stream *ps = k->data;
			if (ps->selected_sfd && ps->selected_sfd->socket.local.port)
				ps->last_local_endpoint = ps->selected_sfd->socket.local;
			ps->selected_sfd = NULL;

			struct stream_fd *sfd;
			while ((sfd = g_queue_pop_head(&ps->sfds)))
				stream_fd_release(sfd);
		}
	}

	monologue->deleted = 0;
}

/* must be called with call->master_lock held in W */
static void __tags_unassociate(struct call_monologue *a, struct call_monologue *b) {
	g_hash_table_remove(a->associated_tags, b);
	g_hash_table_remove(b->associated_tags, a);
}

/**
 * Marks the monologue for destruction, or destroys it immediately.
 * It also iterates through the associated monologues and does the same for them.
 *
 * Returns `true`, if we need to update Redis.
 */
static bool monologue_delete_iter(struct call_monologue *a, int delete_delay) {
	struct call *call = a->call;
	if (!call)
		return 0;

	GList *associated = g_hash_table_get_values(a->associated_tags);
	bool update_redis = false;

	if (delete_delay > 0) {
		ilog(LOG_INFO, "Scheduling deletion of call branch '" STR_FORMAT_M "' "
				"(via-branch '" STR_FORMAT_M "') in %d seconds",
				STR_FMT_M(&a->tag), STR_FMT0_M(&a->viabranch), delete_delay);
		a->deleted = rtpe_now.tv_sec + delete_delay;
		if (!call->ml_deleted || call->ml_deleted > a->deleted)
			call->ml_deleted = a->deleted;
	}
	else {
		ilog(LOG_INFO, "Deleting call branch '" STR_FORMAT_M "' (via-branch '" STR_FORMAT_M "')",
				STR_FMT_M(&a->tag), STR_FMT0_M(&a->viabranch));
		monologue_destroy(a);
		update_redis = true;
	}

	/* Look into all associated monologues: cascade deletion to those,
	 * which have no other associations left */
	for (GList *l = associated; l; l = l->next)
	{
		struct call_monologue *b = l->data;
		__tags_unassociate(a, b);

		if (g_hash_table_size(b->associated_tags) == 0)
			monologue_delete_iter(b, delete_delay);	/* schedule deletion of B */
	}

	g_list_free(associated);
	return update_redis;
}

/**
 * Based on the tag lookup the monologue in the 'tags' GHashTable of the call.
 *
 * Must be called with call->master_lock held in W.
 */
struct call_monologue *call_get_monologue(struct call *call, const str *fromtag) {
	return g_hash_table_lookup(call->tags, fromtag);
}

/**
 * Based on the monologue tag, try to lookup the monologue in the 'tags' GHashTable.
 * If not found create a new one (call_monologue) and associate with a given tag.
 *
 * Must be called with call->master_lock held in W.
 */
struct call_monologue *call_get_or_create_monologue(struct call *call, const str *fromtag) {
	struct call_monologue *ret = call_get_monologue(call, fromtag);
	if (!ret) {
		ret = __monologue_create(call);
		__monologue_tag(ret, fromtag);
	}
	return ret;
}

/**
 * Must be called with call->master_lock held in W.
 *
 * Also cancel scheduled deletion during offer/answer:
 *
 * Unmark a monologue that has been scheduled for deletion when it's
 * associated with another one, which happens during offer/answer.
 */
static void __tags_associate(struct call_monologue *a, struct call_monologue *b) {
	a->deleted = 0;
	b->deleted = 0;
	g_hash_table_insert(a->associated_tags, b, b);
	g_hash_table_insert(b->associated_tags, a, a);
}

/**
 * Check whether the call object contains some other monologues, which can have own associations.
 */
static bool call_monologues_associations_left(struct call * c) {
	for (GList * l = c->monologues.head; l; l = l->next)
	{
		struct call_monologue * ml = l->data;
		if (g_hash_table_size(ml->associated_tags) > 0)
			return true;
	}
	return false;
}

/**
 * Check whether given totag is already subscribed to the given monologue medias.
 * Returns: true - subscribed, false - not subscribed.
 */
static bool call_totag_subscribed_to_monologue(const str * totag, const struct call_monologue * monologue)
{
	if (!totag && !totag->s)
		return false;

	for (int i = 0; i < monologue->medias->len; i++)
	{
		struct call_media * media = monologue->medias->pdata[i];
		if (!media)
			continue;

		for (GList * subscriber = media->media_subscribers.head;
			subscriber;
			subscriber = subscriber->next)
		{
			struct media_subscription * ms = subscriber->data;
			if (!ms->attrs.offer_answer)	/* is this really needed? */
				continue;

			struct call_monologue * subscriber_monologue = ms->monologue;
			if (!str_cmp_str(&subscriber_monologue->tag, totag))	/* subscriber found */
				return true;
		}
	}
	return false;
}
/**
 * Check whether given viabranch is intact with a monologue, which owns
 * existing media subscribriptions to it.
 *
 * It tags a monologue, media of which is subscribed to given monologue, using given viabranch,
 * in case previous other side hasn't been tagged with the via-branch
 *
 * Returns: true - intact, false - not intact.
 */
static bool call_viabranch_intact_monologue(const str * viabranch, struct call_monologue * monologue)
{
	for (int i = 0; i < monologue->medias->len; i++)
	{
		struct call_media * media = monologue->medias->pdata[i];
		if (!media)
			continue;

		for (GList * subscriber = media->media_subscribers.head;
			subscriber;
			subscriber = subscriber->next)
		{
			struct media_subscription * ms = subscriber->data;
			struct call_monologue * subscriber_monologue = ms->monologue;

			/* check the viabranch. if it's not known, then this is a branched offer and we need
			* to create a new "other side" for this branch. */
			if (!subscriber_monologue->viabranch.s) {
				/* previous "other side" hasn't been tagged with the via-branch, so we'll just
				* use this one and tag it */
				__monologue_viabranch(subscriber_monologue, viabranch);
				return true;
			}
			if (!str_cmp_str(&subscriber_monologue->viabranch, viabranch))
				return true; /* dialogue still intact */
		}
	}
	return false;
}

/**
 * Based on given From-tag create a new monologue for this dialog,
 * if given tag wasn't present in 'tags' of this call.
 *
 * In case this is an initial offer, create both dialog sides (monologues),
 * even though the tag will be empty for the monologue requiring the To-tag.
 *
 * Otherwise, try to lookup the 'other side' using via branch value, and tag it
 * using the given To-tag, if this associated monologue didn't have a tag before.
 *
 * Must be called with call->master_lock held in W.
 *
 * `dialogue` must be initialised to zero.
 */
static int call_get_monologue_new(struct call_monologue *monologues[2], struct call *call,
		const str *fromtag,
		const str *totag,
		const str *viabranch)
{
	struct call_monologue *ret, *os = NULL; /* ret - initial offer, os - other side */

	__C_DBG("getting monologue for tag '"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(&call->callid));

	ret = call_get_monologue(call, fromtag);

	if (!ret) {
		/* this is a brand new offer */
		ret = __monologue_create(call);
		__monologue_tag(ret, fromtag);
		goto new_branch;
	}

	__C_DBG("found existing monologue");
	/* unkernelize existing monologue medias, which are subscribed to something */
	__monologue_unkernelize(ret, "signalling on existing monologue");
	for (int i = 0; i < ret->medias->len; i++)
	{
		struct call_media * media = ret->medias->pdata[i];
		if (!media)
			continue;

		for (GList * subcription = media->media_subscriptions.head; subcription; subcription = subcription->next) {
			struct media_subscription * ms = subcription->data;
			__media_unconfirm(ms->media, "signalling on existing media");
		}
	}

	/* If to-tag is presented, confirm that media associations are intact.
	 * Create a new monologue for the other side, if the monologue with such Totag not found.
	 * If it does exist, but its medias aren't susbcribed to offerer's medias, do it now.
	 */
	if (totag && totag->s &&
		!call_totag_subscribed_to_monologue(totag, ret))
	{
		struct call_monologue * monologue = call_get_monologue(call, totag);
		/* if monologue doesn't exist, then nothing to subscribe yet */
		if (!monologue)
			goto new_branch;

		__subscribe_offer_answer_both_ways(ret, monologue); /* TODO: deprecate */

		/* susbcribe existing medias */
		__subscribe_matched_medias(ret, monologue);
	}

	/* TODO: it looks like we do a double work here, when first do checks based on totag
	 * and then, additionally do checks based on viabranch.
	 * If totag based checks succeed and monologue related to it is found, we don't have to double it
	 * check using viabranch?
	 */
	if (!viabranch || call_viabranch_intact_monologue(viabranch, ret)) {
		/* dialogue still intact */
		goto monologues_intact;
	} else {
		os = g_hash_table_lookup(call->viabranches, viabranch);
		if (os) {
			/* previously seen branch. use it */
			__monologue_unkernelize(os, "dialogue/branch association changed");
			__subscribe_offer_answer_both_ways(ret, os); /* TODO: deprecate */

			/* susbcribe medias to medias */
			__subscribe_matched_medias(ret, os);
			goto monologues_intact;
		}
	}

	/* we need both sides of the dialogue even in the initial offer, so create
	 * another monologue without to-tag (to be filled in later) */
new_branch:
	__C_DBG("create new \"other side\" monologue for viabranch "STR_FORMAT, STR_FMT0(viabranch));
	os = __monologue_create(call);
	__subscribe_offer_answer_both_ways(ret, os); /* TODO: deprecate */
	__monologue_viabranch(os, viabranch);

	/* susbcribe medias to medias */
	__subscribe_matched_medias(ret, os);

monologues_intact:
	for (GList *sub = ret->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		if (!cs->attrs.offer_answer)
			continue;
		struct call_monologue *csm = cs->monologue;
		if (!os)
			os = csm;
		if (totag && totag->s && !csm->tag.s)
			__monologue_tag(csm, totag);
		break; // there should only be one
		// XXX check if there's more than a one-to-one mapping here?
	}
	if (G_UNLIKELY(!os))
		return -1;
	__tags_associate(ret, os);
	monologues[0] = ret;
	monologues[1] = os;
	return 0;
}

/**
 * Using the From-tag / To-tag get call monologues (dialog). Where:
 * - dialogue[0] is a monologue associated with the From-tag
 * - dialogue[1] is a monologue associated with the To-tag
 *
 * The request will be treated as a brand new offer,
 * in case the To-tag is still not know for this call.
 *
 * The function must be called with call->master_lock held in W.
 *
 * `dialogue` must be initialised to zero.
 */
static int call_get_dialogue(struct call_monologue *monologues[2], struct call *call,
		const str *fromtag,
		const str *totag,
		const str *viabranch)
{
	struct call_monologue *ft, *tt;

	__C_DBG("getting dialogue for tags '"STR_FORMAT"'<>'"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(totag), STR_FMT(&call->callid));

	/* we start with the to-tag. if it's not known, we treat it as a branched offer */
	tt = call_get_monologue(call, totag);
	if (!tt)
		return call_get_monologue_new(monologues, call, fromtag, totag, viabranch);

	/* if the from-tag is known already, return that */
	ft = call_get_monologue(call, fromtag);
	if (ft) {
		__C_DBG("found existing dialogue");

		/* make sure that the dialogue is actually intact */
		if (ft->subscriptions.length != 1 || ft->subscribers.length != 1)
			goto tag_setup;
		if (tt->subscriptions.length != 1 || tt->subscribers.length != 1)
			goto tag_setup;

		struct call_subscription *cs = ft->subscriptions.head->data;
		if (cs->monologue != tt)
			goto tag_setup;
		cs = ft->subscribers.head->data;
		if (cs->monologue != tt)
			goto tag_setup;

		cs = tt->subscriptions.head->data;
		if (cs->monologue != ft)
			goto tag_setup;
		cs = tt->subscribers.head->data;
		if (cs->monologue != ft)
			goto tag_setup;

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
		if (tt->subscriptions.head) {
			struct call_subscription *cs = tt->subscriptions.head->data;
			ft = cs->monologue;
		}
		if (!ft || ft->tag.s)
			ft = __monologue_create(call);
	}

tag_setup:
	/* the fromtag monologue may be newly created, or half-complete from the totag, or
	 * derived from the viabranch. */
	if (!ft->tag.s || str_cmp_str(&ft->tag, fromtag))
		__monologue_tag(ft, fromtag);

	dialogue_unkernelize(ft, "dialogue signalling event");
	dialogue_unkernelize(tt, "dialogue signalling event");
	__subscribe_offer_answer_both_ways(ft, tt);

	/* susbcribe medias to medias */
	__subscribe_matched_medias(ft, tt);

done:
	__monologue_unkernelize(ft, "dialogue signalling event");
	dialogue_unkernelize(ft, "dialogue signalling event");
	__tags_associate(ft, tt);

	/* just provide gotten dialogs,
	 * which have all needed information about subscribers/subscriptions */
	monologues[0] = ft;
	monologues[1] = tt;

	return 0;
}

/* fromtag and totag strictly correspond to the directionality of the message, not to the actual
 * SIP headers. IOW, the fromtag corresponds to the monologue sending this message, even if the
 * tag is actually from the TO header of the SIP message (as it would be in a 200 OK) */
int call_get_mono_dialogue(struct call_monologue *monologues[2], struct call *call,
		const str *fromtag,
		const str *totag,
		const str *viabranch)
{
	/* initial offer */
	if (!totag || !totag->s)
		return call_get_monologue_new(monologues, call, fromtag, NULL, viabranch);

	return call_get_dialogue(monologues, call, fromtag, totag, viabranch);
}

static void media_stop(struct call_media *m) {
	if (!m)
		return;
	t38_gateway_stop(m->t38_gateway);
	audio_player_stop(m);
	codec_handlers_stop(&m->codec_handlers_store);
	rtcp_timer_stop(&m->rtcp_timer);
	mqtt_timer_stop(&m->mqtt_timer);
}
static void __monologue_stop(struct call_monologue *ml) {
	media_player_stop(ml->player);
}
static void monologue_stop(struct call_monologue *ml) {
	__monologue_stop(ml);
	for (unsigned int i = 0; i < ml->medias->len; i++)
		media_stop(ml->medias->pdata[i]);
}


// call must be locked in W.
// unlocks the call and releases the reference prior to returning, even on error.
int call_delete_branch(struct call *c, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay)
{
	struct call_monologue *ml;
	int ret;
	const str *match_tag;
	GList *i;
	bool update = false;

	if (delete_delay < 0)
		delete_delay = rtpe_config.delete_delay;

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

	ml = call_get_monologue(c, match_tag);
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
			ml = call_get_monologue(c, fromtag);
			if (ml && ml->subscriptions.length == 1) {
				struct call_subscription *cs = ml->subscriptions.head->data;
				if (cs->monologue->tag.len == 0)
					goto do_delete;
			}
		}

		ilog(LOG_INFO, "Tag '"STR_FORMAT"' in delete message not found, ignoring",
				STR_FMT(match_tag));
		goto err;
	}

do_delete:
	c->destroyed = rtpe_now;

	if (output)
		ng_call_stats(c, fromtag, totag, output, NULL);

	monologue_stop(ml);
	for (GList *l = ml->subscribers.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		monologue_stop(cs->monologue);
	}

	/* check, if we have some associated monologues left, which have own associations
	 * which means they need a media to flow */
	update = monologue_delete_iter(ml, delete_delay);

	/* if there are no associated dialogs, which still require media, then additionally
	 * ensure, whether we can afford to destroy the whole call now.
	 * Maybe some of them still need a media to flow */
	bool del_stop = false;
	del_stop = call_monologues_associations_left(c);

	if (!del_stop)
		goto del_all;

	goto success_unlock;

del_all:
	for (i = c->monologues.head; i; i = i->next) {
		ml = i->data;
		monologue_stop(ml);
	}

	c->destroyed = rtpe_now;

	if (delete_delay > 0) {
		ilog(LOG_INFO, "Scheduling deletion of entire call in %d seconds", delete_delay);
		c->deleted = rtpe_now.tv_sec + delete_delay;
		rwlock_unlock_w(&c->master_lock);
	}
	else {
		ilog(LOG_INFO, "Deleting entire call");
		rwlock_unlock_w(&c->master_lock);
		call_destroy(c);
		update = false;
	}
	goto success;

success_unlock:
	rwlock_unlock_w(&c->master_lock);
success:
	ret = 0;
	goto out;

err:
	rwlock_unlock_w(&c->master_lock);
	ret = -1;
	goto out;

out:
	if (update)
		redis_update_onekey(c, rtpe_redis_write);
	obj_put(c);

	return ret;
}


int call_delete_branch_by_id(const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay)
{
	struct call *c = call_get(callid);
	if (!c) {
		ilog(LOG_INFO, "Call-ID to delete not found");
		return -1;
	}
	return call_delete_branch(c, branch, fromtag, totag, output, delete_delay);
}
