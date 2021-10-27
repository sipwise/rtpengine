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
#include <stdbool.h>
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
#include "main.h"
#include "graphite.h"
#include "codec.h"
#include "media_player.h"
#include "jitter_buffer.h"
#include "t38.h"
#include "mqtt.h"
#include "janus.h"


struct iterator_helper {
	GSList			*del_timeout;
	GSList			*del_scheduled;
	GHashTable		*addr_sfd;
	uint64_t		transcoded_media;
};
struct xmlrpc_helper {
	enum xmlrpc_format fmt;
	GQueue			strings;
};


struct global_stats_gauge rtpe_stats_gauge;
struct global_stats_gauge_min_max rtpe_stats_gauge_graphite_min_max;
struct global_stats_gauge_min_max rtpe_stats_gauge_graphite_min_max_interval;

struct global_stats_ax rtpe_stats;
struct global_stats_counter rtpe_stats_interval;
struct global_stats_counter rtpe_stats_cumulative;
struct global_stats_ax rtpe_stats_graphite;
struct global_stats_counter rtpe_stats_graphite_interval;
struct global_stats_min_max rtpe_stats_graphite_min_max;
struct global_stats_min_max rtpe_stats_graphite_min_max_interval;

rwlock_t rtpe_callhash_lock;
GHashTable *rtpe_callhash;
struct call_iterator_list rtpe_call_iterators[NUM_CALL_ITERATORS];
static struct mqtt_timer *global_mqtt_timer;

unsigned int call_socket_cpu_affinity = 0;

/* ********** */

static void __monologue_destroy(struct call_monologue *monologue, int recurse);
static struct timeval add_ongoing_calls_dur_in_interval(struct timeval *interval_start,
		struct timeval *interval_duration);
static void __call_free(void *p);
static void __call_cleanup(struct call *c);
static void __monologue_stop(struct call_monologue *ml);
static void media_stop(struct call_media *m);

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
		if (ml->deleted > rtpe_now.tv_sec) {
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

		if (g_hash_table_contains(hlp->addr_sfd, &sfd->socket.local))
			goto next;
		g_hash_table_insert(hlp->addr_sfd, &sfd->socket.local, obj_get(sfd));

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
		if (MEDIA_ISSET(media, TRANSCODE))
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
				for (int i = 0; i < els_per_ent; i++)
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
		for (int i = 0; i < els_per_ent; i++)
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
		log_info_clear();

		if (dup_tags)
			g_hash_table_destroy(dup_tags);
	}

	if (xh)
		thread_create_detach_prio(xmlrpc_kill_calls, xh, rtpe_config.idle_scheduling,
				rtpe_config.idle_priority, "XMLRPC callback");
	if (url_prefix)
		free(url_prefix);
	if (url_suffix)
		free(url_suffix);
}


// reverse of count_stream_stats_userspace()
static void count_stream_stats_kernel(struct packet_stream *ps) {
	if (!PS_ISSET(ps, RTP))
		return;
	if (bf_set(&ps->stats_flags, PS_STATS_KERNEL))
		return; // flag was already set, nothing to do

	if (bf_isset(&ps->stats_flags, PS_STATS_USERSPACE)) {
		// mixed stream. count as only mixed stream.
		if (bf_clear(&ps->stats_flags, PS_STATS_KERNEL_COUNTED))
			RTPE_GAUGE_DEC(kernel_only_streams);
		if (bf_clear(&ps->stats_flags, PS_STATS_USERSPACE_COUNTED))
			RTPE_GAUGE_DEC(userspace_streams);
		if (!bf_set(&ps->stats_flags, PS_STATS_MIXED_COUNTED))
			RTPE_GAUGE_INC(kernel_user_streams);
	}
	else {
		// kernel-only (for now). count it.
		if (!bf_set(&ps->stats_flags, PS_STATS_KERNEL_COUNTED))
			RTPE_GAUGE_INC(kernel_only_streams);
	}
}


#define DS(x) do {							\
		uint64_t ks_val;					\
		ks_val = atomic64_get(&ps->kernel_stats.x);		\
		if (ke->stats.x < ks_val)				\
			diff_ ## x = 0;					\
		else							\
			diff_ ## x = ke->stats.x - ks_val;		\
		atomic64_add(&ps->stats.x, diff_ ## x);			\
		RTPE_STATS_ADD(x ## _kernel, diff_ ## x);		\
	} while (0)

void call_timer(void *ptr) {
	struct iterator_helper hlp;
	GList *i, *l;
	struct rtpengine_list_entry *ke;
	struct packet_stream *ps;
	int j;
	struct stream_fd *sfd;
	struct rtp_stats *rs;
	unsigned int pt;
	endpoint_t ep;
	struct timeval tv_start;
	long long run_diff_us;

	// timers are run in a single thread, so no locking required here
	static struct timeval last_run;
	static long long interval = 900000; // usec

	tv_start = rtpe_now;

	// ready to start?
	run_diff_us = timeval_diff(&tv_start, &last_run);
	if (run_diff_us < interval)
		return;

	last_run = tv_start;

	ZERO(hlp);
	hlp.addr_sfd = g_hash_table_new(g_endpoint_hash, g_endpoint_eq);

	ITERATE_CALL_LIST_START(CALL_ITERATOR_TIMER, c);
		call_timer_iterator(c, &hlp);
	ITERATE_CALL_LIST_NEXT_END(c);

	stats_counters_ax_calc_avg(&rtpe_stats, run_diff_us, &rtpe_stats_interval);

	stats_counters_min_max(&rtpe_stats_graphite_min_max, &rtpe_stats.intv);

	// stats derived while iterating calls
	RTPE_GAUGE_SET(transcoded_media, hlp.transcoded_media);

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

		uint64_t diff_packets, diff_bytes, diff_errors;

		DS(packets);
		DS(bytes);
		DS(errors);


		if (ke->stats.packets != atomic64_get(&ps->kernel_stats.packets)) {
			atomic64_set(&ps->last_packet, rtpe_now.tv_sec);
			count_stream_stats_kernel(ps);
		}

		ps->in_tos_tclass = ke->stats.in_tos;

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
			pt = ke->target.payload_types[j].pt_num;
			rs = g_hash_table_lookup(ps->rtp_stats, GINT_TO_POINTER(pt));
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

		bool update = false;

		if (diff_packets)
			sfd->call->foreign_media = 0;

		if (!ke->target.non_forwarding && diff_packets) {
			for (GList *l = ps->rtp_sinks.head; l; l = l->next) {
				struct sink_handler *sh = l->data;
				struct packet_stream *sink = sh->sink;

				if (sh->kernel_output_idx < 0
						|| sh->kernel_output_idx >= ke->target.num_destinations)
					continue;

				struct rtpengine_output_info *o = &ke->outputs[sh->kernel_output_idx];

				mutex_lock(&sink->out_lock);
				for (unsigned int u = 0; u < G_N_ELEMENTS(ke->target.ssrc); u++) {
					if (!ke->target.ssrc[u]) // end of list
						break;
					struct ssrc_ctx *ctx = __hunt_ssrc_ctx(ntohl(ke->target.ssrc[u]),
							sink->ssrc_out, 0);
					if (!ctx)
						continue;
					if (sink->crypto.params.crypto_suite
							&& o->encrypt.last_index[u] - ctx->srtp_index > 0x4000)
					{
						ctx->srtp_index = o->encrypt.last_index[u];
						update = true;
					}
				}
				mutex_unlock(&sink->out_lock);
			}

			mutex_lock(&ps->in_lock);

			for (unsigned int u = 0; u < G_N_ELEMENTS(ke->target.ssrc); u++) {
				if (!ke->target.ssrc[u]) // end of list
					break;
				struct ssrc_ctx *ctx = __hunt_ssrc_ctx(ntohl(ke->target.ssrc[u]),
						ps->ssrc_in, 0);
				if (!ctx)
					continue;
				atomic64_add(&ctx->octets, diff_bytes);
				atomic64_add(&ctx->packets, diff_packets);
				atomic64_set(&ctx->last_seq, ke->target.decrypt.last_index[u]);
				ctx->srtp_index = ke->target.decrypt.last_index[u];

				if (sfd->crypto.params.crypto_suite
						&& ke->target.decrypt.last_index[u]
						- ctx->srtp_index > 0x4000)
					update = true;
			}
			mutex_unlock(&ps->in_lock);
		}

		rwlock_unlock_r(&sfd->call->master_lock);

		if (update)
			redis_update_onekey(ps->call, rtpe_redis_write);

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
	kill_calls_timer(hlp.del_timeout, rtpe_config.b2b_url);

	call_interfaces_timer();

	struct timeval tv_stop;
	gettimeofday(&tv_stop, NULL);
	long long duration = timeval_diff(&tv_stop, &tv_start);
	ilog(LOG_DEBUG, "timer run time = %llu.%06llu sec", duration / 1000000, duration % 1000000);

	// increase timer run duration if runtime was within 10% of the interval
	if (duration > interval / 10) {
		interval *= 2;
		ilog(LOG_INFO, "Increasing timer run interval to %llu seconds", interval / 1000000);
	}
	// or if the runtime was less than 2% of the interval, decrease the interval
	else if (interval > 1000000 && duration < interval / 50) {
		interval /= 2;
		ilog(LOG_INFO, "Decreasing timer run interval to %llu seconds", interval / 1000000);
	}
}
#undef DS


int call_init() {
	rtpe_callhash = g_hash_table_new(str_hash, str_equal);
	if (!rtpe_callhash)
		return -1;
	rwlock_init(&rtpe_callhash_lock);

	for (int i = 0; i < NUM_CALL_ITERATORS; i++)
		mutex_init(&rtpe_call_iterators[i].lock);

	poller_add_timer(rtpe_poller, call_timer, NULL);

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
	mutex_init(&med->dtmf_lock);
	return med;
}

static struct call_media *__get_media(struct call_monologue *ml, GList **it, const struct stream_params *sp,
		const struct sdp_ng_flags *flags, int index)
{
	struct call_media *med;
	struct call *call;

	// is this a repeated call with *it set but for a different ml?
	if (*it) {
		med = (*it)->data;
		if (med->monologue != ml)
			*it = NULL;
	}

	/* iterator points to last seen element, or NULL if uninitialized */
	if (!*it)
		*it = ml->medias.head;
	else
		*it = (*it)->next;

	// check for trickle ICE SDP fragment
	if (flags && flags->fragment && sp->media_id.s) {
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

	unsigned int want_index = sp->index;
	if (index != -1)
		want_index = index;

	/* possible incremental update, hunt for correct media struct */
	while (*it) {
		med = (*it)->data;
		if (med->index == want_index) {
			__C_DBG("found existing call_media for stream #%u", want_index);
			return med;
		}
		*it = (*it)->next;
	}

	__C_DBG("allocating new call_media for stream #%u", want_index);
	call = ml->call;
	med = call_media_new(call);
	med->monologue = ml;
	med->index = want_index;
	call_str_cpy(ml->call, &med->type, &sp->type);
	med->type_id = sp->type_id;

	g_queue_push_tail(&ml->medias, med);

	*it = ml->medias.tail;

	return med;
}

static struct endpoint_map *__get_endpoint_map(struct call_media *media, unsigned int num_ports,
		const struct endpoint *ep, const struct sdp_ng_flags *flags, bool always_resuse)
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
		if ((em->wildcard || always_resuse) && em->num_ports >= num_ports) {
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
		else if (MEDIA_ISSET(media, ICE) && (!flags || !flags->no_port_latching))
			; // don't change endpoint address if we're talking ICE
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
	if (get_consecutive_ports(&intf_sockets, num_ports, media))
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
			if (media->call->cpu_affinity >= 0) {
				if (socket_cpu_affinity(sock, media->call->cpu_affinity))
					ilog(LOG_ERR | LOG_FLAG_LIMIT, "Failed to set socket CPU "
							"affinity: %s", strerror(errno));
			}
			sfd = stream_fd_new(sock, media->call, il->local_intf);
			g_queue_push_tail(&em_il->list, sfd); /* not referenced */
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
		int sfd_found = 0;
		struct stream_fd *intf_sfd = NULL;

		for (GList *l = intf_sfds->head; l; l = l->next) {
			struct intf_list *il = l->data;

			struct stream_fd *sfd = g_queue_peek_nth(&il->list, ps->component - 1);
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

	if (ps->selected_sfd && ep.address.family != ps->selected_sfd->socket.family) {
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
	crypto_reset(&ps->crypto);

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
			socket_sendto(&sfd->socket, fake_rtp.s, fake_rtp.len, &ps->endpoint);
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
void __add_sink_handler(GQueue *q, struct packet_stream *sink) {
	struct sink_handler *sh = g_slice_alloc0(sizeof(*sh));
	sh->sink = sink;
	sh->kernel_output_idx = -1;
	g_queue_push_tail(q, sh);
}

// called once before calling __init_streams once for each sink
static void __reset_streams(struct call_media *media) {
	for (GList *l = media->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;
		g_queue_clear_full(&ps->rtp_sinks, free_sink_handler);
		g_queue_clear_full(&ps->rtcp_sinks, free_sink_handler);
	}
}
// called once on media A for each sink media B
// B can be NULL
// XXX this function seems to do two things - stream init (with B NULL) and sink init - split up?
static int __init_streams(struct call_media *A, struct call_media *B, const struct stream_params *sp,
		const struct sdp_ng_flags *flags) {
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
		if (MEDIA_ISSET(A, ECHO) || MEDIA_ISSET(A, BLACKHOLE))
			__add_sink_handler(&a->rtp_sinks, a);
		else if (b)
			__add_sink_handler(&a->rtp_sinks, b);
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
				__add_sink_handler(&a->rtcp_sinks, b);
			PS_SET(a, RTCP);
			PS_CLEAR(a, IMPLICIT_RTCP);
		}

		ax = a;

		/* if muxing, this is the fallback RTCP port. it also contains the RTCP
		 * crypto context */
		la = la->next;
		assert(la != NULL);
		a = la->data;

		if (MEDIA_ISSET(A, ECHO) || MEDIA_ISSET(A, BLACKHOLE)) {
			__add_sink_handler(&a->rtcp_sinks, a);
			if (MEDIA_ISSET(A, RTCP_MUX))
				__add_sink_handler(&ax->rtcp_sinks, a);
		}
		else if (b)
			__add_sink_handler(&a->rtcp_sinks, b);
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

		recording_setup_stream(ax); // RTP
		recording_setup_stream(a); // RTCP

		la = la->next;
		lb = lb ? lb->next : NULL;

		port_off += 2;
	}

	return 0;
}

static void __ice_offer(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other)
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

	if (flags->opmode == OP_OFFER || flags->opmode == OP_REQUEST) {
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
	}

	/* determine roles (even if we don't actually do ICE) */
	/* this = receiver, other = sender */
	/* ICE_CONTROLLING is from our POV, the other ICE flags are from peer's POV */
	if (MEDIA_ISSET(this, ICE_LITE_PEER) && !MEDIA_ISSET(this, ICE_LITE_SELF))
		MEDIA_SET(this, ICE_CONTROLLING);
	else if (!MEDIA_ISSET(this, INITIALIZED)) {
		if (MEDIA_ISSET(this, ICE_LITE_SELF))
			MEDIA_CLEAR(this, ICE_CONTROLLING);
		else if (flags->opmode == OP_OFFER)
			MEDIA_SET(this, ICE_CONTROLLING);
		else
			MEDIA_CLEAR(this, ICE_CONTROLLING);
	}

	if (flags->opmode == OP_OFFER || flags->opmode == OP_ANSWER) {
		/* roles are reversed for the other side */
		if (MEDIA_ISSET(other, ICE_LITE_PEER) && !MEDIA_ISSET(other, ICE_LITE_SELF))
			MEDIA_SET(other, ICE_CONTROLLING);
		else if (!MEDIA_ISSET(other, INITIALIZED)) {
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

/* generates SDES parameters for outgoing SDP, which is our media "out" direction */
// `other` can be NULL
static void __generate_crypto(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other)
{
	GQueue *cpq = &this->sdes_out;
	GQueue *cpq_in = &this->sdes_in;
	const GQueue *offered_cpq = other ? &other->sdes_in : NULL;

	if (!flags)
		return;

	bool is_offer = (flags->opmode == OP_OFFER || flags->opmode == OP_REQUEST);

	if (!this->protocol || !this->protocol->srtp || MEDIA_ISSET(this, PASSTHRU)) {
		crypto_params_sdes_queue_clear(cpq);
		/* clear crypto for the this leg b/c we are in passthrough mode */
		MEDIA_CLEAR(this, DTLS);
		MEDIA_CLEAR(this, SDES);
		MEDIA_CLEAR(this, SETUP_PASSIVE);
		MEDIA_CLEAR(this, SETUP_ACTIVE);

		if (MEDIA_ISSET(this, PASSTHRU) && other) {
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

	if (is_offer) {
		// generate full set of params
		// re-create the entire list - steal for later flushing
		GQueue cpq_orig = *cpq;
		g_queue_init(cpq);

		// if we were offered some crypto suites, copy those first into our offer
		unsigned int c_tag = 1; // tag for next crypto suite generated by us
		unsigned long types_offered = 0;

		// make sure our bit field is large enough
		assert(num_crypto_suites <= sizeof(types_offered) * 8);

		for (GList *l = offered_cpq ? offered_cpq->head : NULL; l; l = l->next) {
			struct crypto_params_sdes *offered_cps = l->data;

			struct crypto_params_sdes *cps = g_slice_alloc0(sizeof(*cps));
			g_queue_push_tail(cpq, cps);

			cps->tag = offered_cps->tag;
			// our own offered tags will be higher than the ones we received
			if (cps->tag >= c_tag)
				c_tag = cps->tag + 1;
			crypto_params_copy(&cps->params, &offered_cps->params, 1);

			// we use a bit field to keep track of which types we've seen here
			types_offered |= 1 << cps->params.crypto_suite->idx;

			__sdes_flags(cps, flags);
		}

		// if we had any suites added before, re-add those that aren't there yet
		struct crypto_params_sdes *cps_orig;
		while ((cps_orig = g_queue_pop_head(&cpq_orig))) {
			if ((types_offered & (1 << cps_orig->params.crypto_suite->idx))) {
				crypto_params_sdes_free(cps_orig);
				continue;
			}

			// make sure our tag is higher than what we've seen
			if (cps_orig->tag < c_tag)
				cps_orig->tag = c_tag;
			if (cps_orig->tag >= c_tag)
				c_tag = cps_orig->tag + 1;

			g_queue_push_tail(cpq, cps_orig);

			types_offered |= 1 << cps_orig->params.crypto_suite->idx;
		}

		// generate crypto suite offers for any types that we haven't seen above
		// XXX for re-invites, this always creates new crypto keys for suites
		// that weren't accepted before, instead of re-using the same keys (and
		// suites) that were previously offered but not accepted
		for (unsigned int i = 0; i < num_crypto_suites; i++) {
			if ((types_offered & (1 << i)))
				continue;

			if (flags->sdes_no && g_hash_table_lookup(flags->sdes_no,
						&crypto_suites[i].name_str))
			{
				ilogs(crypto, LOG_DEBUG, "Not offering crypto suite '%s' "
						"due to 'SDES-no' option",
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
	else { // OP_ANSWER
		// we pick the first supported crypto suite
		struct crypto_params_sdes *cps = cpq->head ? cpq->head->data : NULL;
		struct crypto_params_sdes *cps_in = cpq_in->head ? cpq_in->head->data : NULL;
		struct crypto_params_sdes *offered_cps = (offered_cpq && offered_cpq->head)
			? offered_cpq->head->data : NULL;

		if (flags && flags->sdes_static && cps) {
			// reverse logic: instead of looking for a matching crypto suite to put in
			// our answer, we want to leave what we already had. however, this is only
			// valid if the currently present crypto suite matches the offer
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

		if (offered_cps) {
			ilogs(crypto, LOG_DEBUG, "Looking for matching crypto suite to offered %u:%s", offered_cps->tag,
					offered_cps->params.crypto_suite->name);
			// check if we can do SRTP<>SRTP passthrough. the crypto suite that was accepted
			// must have been present in what was offered to us
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
#if GLIB_CHECK_VERSION(2,30,0)
			if (!g_queue_remove(cpq_in, cps_in))
				ilogs(crypto, LOG_ERR, "BUG: incoming crypto suite not found in queue");
#else
			g_queue_remove(cpq_in, cps_in);
#endif
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
// for an answer, uses the incoming received list of SDES crypto suites to prune
// the list of (generated) outgoing crypto suites to contain only the one that was
// accepted
static void __sdes_accept(struct call_media *media, const struct sdp_ng_flags *flags) {
	if (!media->sdes_in.length)
		return;

	if (flags && flags->sdes_no) {
		// first remove SDES-no suites from offered ones
		GList *l = media->sdes_in.head;
		while (l) {
			struct crypto_params_sdes *offered_cps = l->data;

			if (!g_hash_table_lookup(flags->sdes_no,
						&offered_cps->params.crypto_suite->name_str))
			{
				l = l->next;
				continue;
			}

			ilogs(crypto, LOG_DEBUG, "Dropping offered crypto suite '%s' from offer "
					"due to 'SDES-no' option",
					offered_cps->params.crypto_suite->name);

			GList *next = l->next;
			g_queue_delete_link(&media->sdes_in, l);
			crypto_params_sdes_free(offered_cps);
			l = next;
		}
	}

	if (media->sdes_in.head == NULL)
		return;

	struct crypto_params_sdes *cps_in = media->sdes_in.head->data;
	GList *l = media->sdes_out.head;
	while (l) {
		struct crypto_params_sdes *cps_out = l->data;
		if (cps_out->params.crypto_suite != cps_in->params.crypto_suite)
			goto del_next;
		if (cps_out->tag != cps_in->tag)
			goto del_next;

		// this one's good
		l = l->next;
		continue;
del_next:
		// mismatch, prune this one out
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

static void __rtcp_mux_logic(const struct sdp_ng_flags *flags, struct call_media *media,
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

static void __fingerprint_changed(struct call_media *m) {
	GList *l;
	struct packet_stream *ps;

	if (!m->fingerprint.hash_func || !m->fingerprint.digest_len)
		return;

	ilogs(crypto, LOG_INFO, "DTLS fingerprint changed, restarting DTLS");

	for (l = m->streams.head; l; l = l->next) {
		ps = l->data;
		PS_CLEAR(ps, FINGERPRINT_VERIFIED);
		dtls_shutdown(ps);
		__init_stream(ps);
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
	if (media->monologue)
		media->monologue->logical_intf = media->logical_intf;
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
		if ((flags->opmode == OP_OFFER || flags->opmode == OP_PUBLISH)
				&& MEDIA_ARESET2(other_media, SETUP_ACTIVE, SETUP_PASSIVE)
				&& (tmp & (MEDIA_FLAG_SETUP_ACTIVE | MEDIA_FLAG_SETUP_PASSIVE))
				== MEDIA_FLAG_SETUP_PASSIVE)
			MEDIA_CLEAR(other_media, SETUP_ACTIVE);
		/* if passive mode is requested, honour it if we can */
		if (flags->dtls_reverse_passive && MEDIA_ISSET(other_media, SETUP_PASSIVE))
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
					if (flags->osrtp_accept)
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

void codecs_offer_answer(struct call_media *media, struct call_media *other_media,
		struct stream_params *sp, struct sdp_ng_flags *flags)
{
	if (!flags || flags->opmode != OP_ANSWER) {
		// offer
		ilogs(codec, LOG_DEBUG, "Updating codecs for offerer " STR_FORMAT " #%u",
				STR_FMT(&other_media->monologue->tag),
				other_media->index);
		if (flags) {
			if (flags->reuse_codec)
				codec_store_populate_reuse(&other_media->codecs, &sp->codecs, flags->codec_set);
			else
				codec_store_populate(&other_media->codecs, &sp->codecs, flags->codec_set);
			codec_store_strip(&other_media->codecs, &flags->codec_strip, flags->codec_except);
			codec_store_offer(&other_media->codecs, &flags->codec_offer, &sp->codecs);
			if (!other_media->codecs.strip_full)
				codec_store_offer(&other_media->codecs, &flags->codec_transcode, &sp->codecs);
			codec_store_accept(&other_media->codecs, &flags->codec_accept, NULL);
			codec_store_accept(&other_media->codecs, &flags->codec_consume, &sp->codecs);
			codec_store_track(&other_media->codecs, &flags->codec_mask);
		} else
			codec_store_populate(&other_media->codecs, &sp->codecs, NULL);

		// we don't update the answerer side if the offer is not RTP but is going
		// to RTP (i.e. T.38 transcoding) - instead we leave the existing codec list
		// intact
		int update_answerer = 1;
		if (proto_is_rtp(media->protocol) && !proto_is_rtp(other_media->protocol))
			update_answerer = 0;

		if (update_answerer) {
			// update/create answer/receiver side
			ilogs(codec, LOG_DEBUG, "Updating codecs for answerer " STR_FORMAT " #%u",
					STR_FMT(&media->monologue->tag),
					media->index);
			if (flags && flags->reuse_codec)
				codec_store_populate_reuse(&media->codecs, &sp->codecs, NULL);
			else
				codec_store_populate(&media->codecs, &sp->codecs, NULL);
		}
		if (flags) {
			codec_store_strip(&media->codecs, &flags->codec_strip, flags->codec_except);
			codec_store_strip(&media->codecs, &flags->codec_consume, flags->codec_except);
			codec_store_strip(&media->codecs, &flags->codec_mask, flags->codec_except);
			codec_store_offer(&media->codecs, &flags->codec_offer, &sp->codecs);
			codec_store_transcode(&media->codecs, &flags->codec_transcode, &sp->codecs);
		}
		codec_store_synthesise(&media->codecs, &other_media->codecs);

		// update supp codecs based on actions so far
		codec_tracker_update(&media->codecs);

		// set up handlers
		codec_handlers_update(media, other_media, flags, sp);

		// updating the handlers may have removed some codecs, so run update the supp codecs again
		codec_tracker_update(&media->codecs);

		// finally set up handlers again based on final results
		codec_handlers_update(media, other_media, flags, sp);
	}
	else {
		// answer
		ilogs(codec, LOG_DEBUG, "Updating codecs for answerer " STR_FORMAT " #%u",
				STR_FMT(&other_media->monologue->tag),
				other_media->index);
		if (flags->reuse_codec)
			codec_store_populate_reuse(&other_media->codecs, &sp->codecs, flags->codec_set);
		else
			codec_store_populate(&other_media->codecs, &sp->codecs, flags->codec_set);
		codec_store_strip(&other_media->codecs, &flags->codec_strip, flags->codec_except);
		codec_store_offer(&other_media->codecs, &flags->codec_offer, &sp->codecs);

		// update callee side codec handlers again (second pass after the offer) as we
		// might need to update some handlers, e.g. when supplemental codecs have been
		// rejected
		codec_handlers_update(other_media, media, NULL, NULL);

		// finally set up our caller side codecs
		ilogs(codec, LOG_DEBUG, "Codec answer for " STR_FORMAT " #%u",
				STR_FMT(&other_media->monologue->tag),
				other_media->index);
		codec_store_answer(&media->codecs, &other_media->codecs, flags);

		// set up handlers
		codec_handlers_update(media, other_media, flags, sp);

		// updating the handlers may have removed some codecs, so run update the supp codecs again
		codec_tracker_update(&media->codecs);
		codec_tracker_update(&other_media->codecs);

		// finally set up handlers again based on final results
		codec_handlers_update(media, other_media, flags, sp);
		codec_handlers_update(other_media, media, NULL, NULL);
	}
}


/* called with call->master_lock held in W */
static void __update_init_subscribers(struct call_monologue *ml, GQueue *streams, struct sdp_ng_flags *flags) {
	GList *sl = streams ? streams->head : NULL;

	// create media iterators for all subscribers
	GList *sub_medias[ml->subscribers.length];
	unsigned int num_subs = 0;
	for (GList *l = ml->subscribers.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		struct call_monologue *sub_ml = cs->monologue;
		sub_medias[num_subs] = sub_ml->medias.head;
		// skip into correct media section for multi-ml subscriptions
		for (unsigned int offset = cs->media_offset; offset && sub_medias[num_subs]; offset--)
			sub_medias[num_subs] = sub_medias[num_subs]->next;
		num_subs++;
	}
	// keep num_subs as shortcut to ml->subscribers.length

	recording_setup_monologue(ml);

	for (GList *l = ml->medias.head; l; l = l->next) {
		struct call_media *media = l->data;

		struct stream_params *sp = NULL;
		if (sl) {
			sp = sl->data;
			sl = sl->next;
		}

		__ice_start(media);

		// update all subscribers
		__reset_streams(media);
		for (unsigned int i = 0; i < num_subs; i++) {
			if (!sub_medias[i])
				continue;

			struct call_media *sub_media = sub_medias[i]->data;
			sub_medias[i] = sub_medias[i]->next;

			if (__init_streams(media, sub_media, sp, flags))
				ilog(LOG_WARN, "Error initialising streams");
		}

		// we are now ready to fire up ICE if so desired and requested
		ice_update(media->ice_agent, sp); // sp == NULL: update in case rtcp-mux changed

		recording_setup_media(media);
		t38_gateway_start(media->t38_gateway);

		if (mqtt_publish_scope() == MPS_MEDIA)
			mqtt_timer_start(&media->mqtt_timer, media->call, media);
	}
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
static int __media_init_from_flags(struct call_media *other_media, struct call_media *media,
		struct stream_params *sp, struct sdp_ng_flags *flags)
{
	struct call *call = other_media->call;

	if (flags && flags->fragment) {
		// trickle ICE SDP fragment. don't do anything other than update
		// the ICE stuff.
		if (!MEDIA_ISSET(other_media, TRICKLE_ICE))
			return ERROR_NO_ICE_AGENT;
		if (!other_media->ice_agent)
			return ERROR_NO_ICE_AGENT;
		ice_update(other_media->ice_agent, sp);
		return 1; // done, continue
	}

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
				SHARED_FLAG_RTCP_FB);

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

	// deduct address family from stream parameters received
	other_media->desired_family = sp->rtp_endpoint.address.family;
	// for outgoing SDP, use "direction"/DF or default to what was offered
	if (media && !media->desired_family)
		media->desired_family = other_media->desired_family;
	if (media && sp->desired_family)
		media->desired_family = sp->desired_family;

	return 0;
}

/* called with call->master_lock held in W */
int monologue_offer_answer(struct call_monologue *dialogue[2], GQueue *streams,
		struct sdp_ng_flags *flags)
{
	struct stream_params *sp;
	GList *media_iter, *ml_media, *other_ml_media;
	struct call_media *media, *other_media;
	struct endpoint_map *em;
	struct call_monologue *other_ml = dialogue[0];
	struct call_monologue *monologue = dialogue[1];

	/* we must have a complete dialogue, even though the to-tag (monologue->tag)
	 * may not be known yet */
	if (!other_ml) {
		ilog(LOG_ERROR, "Incomplete dialogue association");
		return -1;
	}

	__call_monologue_init_from_flags(other_ml, flags);

	__C_DBG("this="STR_FORMAT" other="STR_FORMAT, STR_FMT(&monologue->tag), STR_FMT(&other_ml->tag));

	ml_media = other_ml_media = NULL;

	for (media_iter = streams->head; media_iter; media_iter = media_iter->next) {
		sp = media_iter->data;
		__C_DBG("processing media stream #%u", sp->index);

		/* first, check for existence of call_media struct on both sides of
		 * the dialogue */
		media = __get_media(monologue, &ml_media, sp, flags, -1);
		other_media = __get_media(other_ml, &other_ml_media, sp, flags, -1);
		/* OTHER is the side which has sent the message. SDP parameters in
		 * "sp" are as advertised by OTHER side. The message will be sent to
		 * THIS side. Parameters sent to THIS side may be overridden by
		 * what's in "flags". If this is an answer, or if we have talked to
		 * THIS side (recipient) before, then the structs will be populated with
		 * details already. */

		if (__media_init_from_flags(other_media, media, sp, flags) == 1)
			continue;

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

		/* local interface selection */
		__init_interface(media, &sp->direction[1], sp->num_ports);
		__init_interface(other_media, &sp->direction[0], sp->num_ports);

		if (media->logical_intf == NULL || other_media->logical_intf == NULL) {
			goto error_intf;
		}

		/* ICE stuff - must come after interface and address family selection */
		__ice_offer(flags, media, other_media);


		/* we now know what's being advertised by the other side */
		MEDIA_SET(other_media, INITIALIZED);


		if (!sp->rtp_endpoint.port) {
			/* Zero port: stream has been rejected.
			 * RFC 3264, chapter 6:
			 * If a stream is rejected, the offerer and answerer MUST NOT
			 * generate media (or RTCP packets) for that stream. */
			__disable_streams(media, sp->num_ports);
			__disable_streams(other_media, sp->num_ports);
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
		em = __get_endpoint_map(media, sp->num_ports, &sp->rtp_endpoint, flags, false);
		if (!em) {
			goto error_ports;
		}

		if(flags->disable_jb && media->call)
			media->call->disable_jb=1;

		__num_media_streams(media, sp->num_ports);
		__assign_stream_fds(media, &em->intf_sfds);

		if (__num_media_streams(other_media, sp->num_ports)) {
			/* new streams created on OTHER side. normally only happens in
			 * initial offer. create a wildcard endpoint_map to be filled in
			 * when the answer comes. */
			if (__wildcard_endpoint_map(other_media, sp->num_ports))
				goto error_ports;
		}
	}

	__update_init_subscribers(other_ml, streams, flags);
	__update_init_subscribers(monologue, NULL, NULL);

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
		if (!cs->offer_answer) {
			l = l->next;
			continue;
		}
		GList *next = l->next;
		__unsubscribe_one(cs->monologue, ml);
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
void __add_subscription(struct call_monologue *which, struct call_monologue *to, bool offer_answer,
		unsigned int offset)
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
	// keep offer-answer subscriptions first in the list
	if (!offer_answer) {
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
	which_cs->offer_answer = offer_answer ? 1 : 0;
	to_rev_cs->offer_answer = which_cs->offer_answer;
	g_hash_table_insert(which->subscriptions_ht, to, to_rev_cs->link);
	g_hash_table_insert(to->subscribers_ht, which, which_cs->link);
}
static void __subscribe_offer_answer_both_ways(struct call_monologue *a, struct call_monologue *b) {
	__unsubscribe_all_offer_answer_subscribers(a);
	__unsubscribe_all_offer_answer_subscribers(b);
	__add_subscription(a, b, true, 0);
	__add_subscription(b, a, true, 0);
}



/* called with call->master_lock held in W */
int monologue_publish(struct call_monologue *ml, GQueue *streams, struct sdp_ng_flags *flags) {
	__call_monologue_init_from_flags(ml, flags);

	GList *media_iter = NULL;

	for (GList *l = streams->head; l; l = l->next) {
		struct stream_params *sp = l->data;
		struct call_media *media = __get_media(ml, &media_iter, sp, flags, -1);

		__media_init_from_flags(media, NULL, sp, flags);

		codec_store_populate(&media->codecs, &sp->codecs, NULL);
		if (codec_store_accept_one(&media->codecs, &flags->codec_accept, flags->accept_any ? true : false))
			return -1;

		// the most we can do is receive
		bf_copy(&media->media_flags, MEDIA_FLAG_RECV, &sp->sp_flags, SP_FLAG_SEND);

		if (sp->rtp_endpoint.port) {
			__dtls_logic(flags, media, sp);
			__generate_crypto(flags, media, NULL);
		}

		/* local interface selection */
		__init_interface(media, &flags->interface, sp->num_ports);

		if (media->logical_intf == NULL)
			return -1; // XXX return error code

		/* ICE stuff - must come after interface and address family selection */
		__ice_offer(flags, media, media);

		MEDIA_SET(media, INITIALIZED);

		if (!sp->rtp_endpoint.port) {
			/* Zero port: stream has been rejected.
			 * RFC 3264, chapter 6:
			 * If a stream is rejected, the offerer and answerer MUST NOT
			 * generate media (or RTCP packets) for that stream. */
			__disable_streams(media, sp->num_ports);
			continue;
		}

		struct endpoint_map *em = __get_endpoint_map(media, sp->num_ports, NULL, flags, true);
		if (!em)
			return -1; // XXX error - no ports

		__num_media_streams(media, sp->num_ports);
		__assign_stream_fds(media, &em->intf_sfds);

		// XXX this should be covered by __update_init_subscribers ?
		if (__init_streams(media, NULL, sp, flags))
			return -1;
		__ice_start(media);
		ice_update(media->ice_agent, sp);
	}

	return 0;
}

/* called with call->master_lock held in W */
static int monologue_subscribe_request1(struct call_monologue *src_ml, struct call_monologue *dst_ml,
		struct sdp_ng_flags *flags, GList **src_media_it, GList **dst_media_it, unsigned int *index)
{
	unsigned int idx_diff = 0;

	for (GList *l = src_ml->last_in_sdp_streams.head; l; l = l->next) {
		struct stream_params *sp = l->data;

		struct call_media *dst_media = __get_media(dst_ml, dst_media_it, sp, flags, (*index)++);
		struct call_media *src_media = __get_media(src_ml, src_media_it, sp, flags, -1);

		// track media index difference if one ml is subscribed to multiple other mls
		if (idx_diff == 0 && dst_media->index > src_media->index)
			idx_diff = dst_media->index - src_media->index;

		if (__media_init_from_flags(src_media, dst_media, sp, flags) == 1)
			continue;

		codec_store_populate(&dst_media->codecs, &src_media->codecs, NULL);
		codec_store_strip(&dst_media->codecs, &flags->codec_strip, flags->codec_except);
		codec_store_strip(&dst_media->codecs, &flags->codec_consume, flags->codec_except);
		codec_store_strip(&dst_media->codecs, &flags->codec_mask, flags->codec_except);
		codec_store_offer(&dst_media->codecs, &flags->codec_offer, &sp->codecs);
		codec_store_transcode(&dst_media->codecs, &flags->codec_transcode, &sp->codecs);
		codec_store_synthesise(&dst_media->codecs, &src_media->codecs);

		codec_handlers_update(dst_media, src_media, flags, sp);

		MEDIA_SET(dst_media, SEND);
		MEDIA_CLEAR(dst_media, RECV);

		__rtcp_mux_set(flags, dst_media);
		__generate_crypto(flags, dst_media, src_media);

		// interface selection
		__init_interface(dst_media, &flags->interface, sp->num_ports);
		if (dst_media->logical_intf == NULL)
			return -1; // XXX return error code

		__ice_offer(flags, dst_media, src_media);

		struct endpoint_map *em = __get_endpoint_map(dst_media, sp->num_ports, NULL, flags, true);
		if (!em)
			return -1; // XXX error - no ports

		__num_media_streams(dst_media, sp->num_ports);
		__assign_stream_fds(dst_media, &em->intf_sfds);

		if (__init_streams(dst_media, NULL, NULL, flags))
			return -1;
	}

	__add_subscription(dst_ml, src_ml, false, idx_diff);

	__update_init_subscribers(src_ml, NULL, NULL);
	__update_init_subscribers(dst_ml, NULL, NULL);

	return 0;
}
/* called with call->master_lock held in W */
int monologue_subscribe_request(const GQueue *srcs, struct call_monologue *dst_ml,
		struct sdp_ng_flags *flags)
{
	__unsubscribe_from_all(dst_ml);

	__call_monologue_init_from_flags(dst_ml, flags);

	GList *dst_media_it = NULL;
	GList *src_media_it = NULL;
	unsigned int index = 1; // running counter for output/dst medias

	for (GList *sl = srcs->head; sl; sl = sl->next) {
		struct call_subscription *cs = sl->data;
		struct call_monologue *src_ml = cs->monologue;

		int ret = monologue_subscribe_request1(src_ml, dst_ml, flags, &src_media_it, &dst_media_it,
				&index);
		if (ret)
			return -1;
	}
	return 0;
}

/* called with call->master_lock held in W */
int monologue_subscribe_answer(struct call_monologue *dst_ml, struct sdp_ng_flags *flags, GQueue *streams) {
	GList *dst_media_it = NULL;
	GList *src_media_it = NULL;
	GList *src_ml_it = dst_ml->subscriptions.head;
	unsigned int index = 1; // running counter for input/src medias

	for (GList *l = streams->head; l; l = l->next) {
		struct stream_params *sp = l->data;

		// grab the matching source ml:
		// we need to move to the next one when we've reached the last media of
		// the current source ml
		if (src_media_it && !src_media_it->next) {
			src_ml_it = src_ml_it->next;
			index = 1; // starts over at 1
		}
		if (!src_ml_it)
			return -1;

		struct call_subscription *cs = src_ml_it->data;
		struct call_monologue *src_ml = cs->monologue;

		struct call_media *dst_media = __get_media(dst_ml, &dst_media_it, sp, flags, -1);
		struct call_media *src_media = __get_media(src_ml, &src_media_it, sp, flags, index++);

		if (__media_init_from_flags(dst_media, NULL, sp, flags) == 1)
			continue;

		if (flags && flags->allow_transcoding) {
			codec_store_populate(&dst_media->codecs, &sp->codecs, flags->codec_set);
			codec_store_strip(&dst_media->codecs, &flags->codec_strip, flags->codec_except);
			codec_store_offer(&dst_media->codecs, &flags->codec_offer, &sp->codecs);
		}
		else {
			codec_store_populate(&dst_media->codecs, &sp->codecs, NULL);
			if (!codec_store_is_full_answer(&src_media->codecs, &dst_media->codecs))
				return -1;
		}

		codec_handlers_update(src_media, dst_media, NULL, NULL);
		codec_handlers_update(dst_media, src_media, flags, sp);

		__dtls_logic(flags, dst_media, sp);

		if (__init_streams(dst_media, NULL, sp, flags))
			return -1;

		MEDIA_CLEAR(dst_media, RECV);

		// XXX check answer SDP parameters

		MEDIA_SET(dst_media, INITIALIZED);
	}

	__update_init_subscribers(dst_ml, streams, flags);
	dialogue_unkernelize(dst_ml);

	for (GList *l = dst_ml->subscriptions.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		struct call_monologue *src_ml = cs->monologue;
		__update_init_subscribers(src_ml, NULL, NULL);
		dialogue_unkernelize(src_ml);
	}

	return 0;
}

/* called with call->master_lock held in W */
int monologue_unsubscribe(struct call_monologue *dst_ml, struct sdp_ng_flags *flags) {
	for (GList *l = dst_ml->subscriptions.head; l; ) {
		GList *next = l->next;
		struct call_subscription *cs = l->data;
		struct call_monologue *src_ml = cs->monologue;

		__unsubscribe_one_link(dst_ml, l);

		__update_init_subscribers(dst_ml, NULL, NULL);
		__update_init_subscribers(src_ml, NULL, NULL);

		dialogue_unkernelize(src_ml);
		dialogue_unkernelize(dst_ml);

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
	RTPE_STATS_ADD(total_calls_duration, timeval_us(&ongoing_calls_dur));
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
		__unkernelize(ps);
		dtls_shutdown(ps);
		ps->selected_sfd = NULL;
		g_queue_clear(&ps->sfds);
		crypto_cleanup(&ps->crypto);

		g_queue_clear_full(&ps->rtp_sinks, free_sink_handler);
		g_queue_clear_full(&ps->rtcp_sinks, free_sink_handler);
	}

	for (GList *l = c->medias.head; l; l = l->next) {
		struct call_media *md = l->data;
		ice_shutdown(&md->ice_agent);
		media_stop(md);
		t38_gateway_put(&md->t38_gateway);
	}

	for (GList *l = c->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		__monologue_stop(ml);
		media_player_put(&ml->player);
	}

	while (c->stream_fds.head) {
		struct stream_fd *sfd = g_queue_pop_head(&c->stream_fds);
		poller_del_item(rtpe_poller, sfd->socket.fd);
		obj_put(sfd);
	}

	recording_finish(c);

	if (c->janus_session)
		obj_put_o((void *) c->janus_session);
	c->janus_session = NULL;
}

/* called lock-free, but must hold a reference to the call */
void call_destroy(struct call *c) {
	struct packet_stream *ps=0;
	GList *l;
	int ret;
	struct call_monologue *ml;
	struct call_media *md;
	GList *k, *o;
	const struct rtp_payload_type *rtp_pt;

	if (!c) {
		return;
	}

	rwlock_lock_w(&rtpe_callhash_lock);
	ret = (g_hash_table_lookup(rtpe_callhash, &c->callid) == c);
	if (ret) {
		g_hash_table_remove(rtpe_callhash, &c->callid);
		RTPE_GAUGE_DEC(total_sessions);
	}
	rwlock_unlock_w(&rtpe_callhash_lock);

	// if call not found in callhash => previously deleted
	if (!ret)
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

		for (k = ml->medias.head; k; k = k->next) {
			md = k->data;

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
				char *local_addr = ps->selected_sfd ? sockaddr_print_buf(&ps->selected_sfd->socket.local.address) : "0.0.0.0";

				ilog(LOG_INFO, "--------- Port %15s:%-5u <> %s%15s:%-5u%s%s, SSRC %s%" PRIx32 "%s, "
						""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" ts",
						local_addr,
						(unsigned int) (ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
						FMT_M(addr, ps->endpoint.port),
						(!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
						FMT_M(ps->ssrc_in[0] ? ps->ssrc_in[0]->parent->h.ssrc : 0),
						atomic64_get(&ps->stats.packets),
						atomic64_get(&ps->stats.bytes),
						atomic64_get(&ps->stats.errors),
						rtpe_now.tv_sec - atomic64_get(&ps->last_packet));
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
		int *len, const struct local_intf *ifa, int keep_unspec)
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
	mutex_destroy(&md->dtmf_lock);
	g_slice_free1(sizeof(*md), md);
	*mdp = NULL;
}

void call_subscription_free(void *p) {
	g_slice_free1(sizeof(struct call_subscription), p);
}

static void __call_free(void *p) {
	struct call *c = p;
	struct call_monologue *m;
	struct call_media *md;
	struct packet_stream *ps;
	struct endpoint_map *em;

	//ilog(LOG_DEBUG, "freeing main call struct");

	obj_put(c->dtls_cert);
	mqtt_timer_stop(&c->mqtt_timer);

	while (c->monologues.head) {
		m = g_queue_pop_head(&c->monologues);

		g_queue_clear(&m->medias);
		g_hash_table_destroy(m->other_tags);
		g_hash_table_destroy(m->branches);
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

/* returns call with master_lock held in W, or NULL if not found */
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

/* must be called with call->master_lock held in W */
struct call_monologue *__monologue_create(struct call *call) {
	struct call_monologue *ret;

	__C_DBG("creating new monologue");
	ret = uid_slice_alloc0(ret, &call->monologues);

	ret->call = call;
	ret->created = rtpe_now.tv_sec;
	ret->other_tags = g_hash_table_new(str_hash, str_equal);
	ret->branches = g_hash_table_new(str_hash, str_equal);
	ret->media_ids = g_hash_table_new(str_hash, str_equal);
	ret->ssrc_hash = create_ssrc_hash_call();
	ret->subscribers_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
	ret->subscriptions_ht = g_hash_table_new(g_direct_hash, g_direct_equal);

	g_queue_init(&ret->medias);
	gettimeofday(&ret->started, NULL);

	return ret;
}

/* must be called with call->master_lock held in W */
void __monologue_tag(struct call_monologue *ml, const str *tag) {
	struct call *call = ml->call;

	__C_DBG("tagging monologue with '"STR_FORMAT"'", STR_FMT(tag));
	if (ml->tag.s)
		g_hash_table_remove(call->tags, &ml->tag);
	call_str_cpy(call, &ml->tag, tag);
	g_hash_table_insert(call->tags, &ml->tag, ml);
}
void __monologue_viabranch(struct call_monologue *ml, const str *viabranch) {
	struct call *call = ml->call;

	if (!viabranch || !viabranch->len)
		return;

	__C_DBG("tagging monologue with viabranch '"STR_FORMAT"'", STR_FMT(viabranch));
	if (ml->viabranch.s) {
		g_hash_table_remove(call->viabranches, &ml->viabranch);
		for (GList *sub = ml->subscribers.head; sub; sub = sub->next) {
			struct call_subscription *cs = sub->data;
			g_hash_table_remove(cs->monologue->branches, &ml->viabranch);
		}
	}
	call_str_cpy(call, &ml->viabranch, viabranch);
	g_hash_table_insert(call->viabranches, &ml->viabranch, ml);
	for (GList *sub = ml->subscribers.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		g_hash_table_insert(cs->monologue->branches, &ml->viabranch, ml);
	}
}

static void __unconfirm_sinks(GQueue *q) {
	for (GList *l = q->head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		__stream_unconfirm(sh->sink);
	}
}
/* must be called with call->master_lock held in W */
void __monologue_unkernelize(struct call_monologue *monologue) {
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
			__unconfirm_sinks(&stream->rtp_sinks);
			__unconfirm_sinks(&stream->rtcp_sinks);
		}
	}
}
void dialogue_unkernelize(struct call_monologue *ml) {
	__monologue_unkernelize(ml);

	for (GList *sub = ml->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		__monologue_unkernelize(cs->monologue);
	}
	for (GList *sub = ml->subscribers.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		__monologue_unkernelize(cs->monologue);
	}
}

static void __unkernelize_sinks(GQueue *q) {
	for (GList *l = q->head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		unkernelize(sh->sink);
	}
}
/* call locked in R */
void call_media_unkernelize(struct call_media *media) {
	GList *m;
	struct packet_stream *stream;

	for (m = media->streams.head; m; m = m->next) {
		stream = m->data;
		unkernelize(stream);
		__unkernelize_sinks(&stream->rtp_sinks);
		__unkernelize_sinks(&stream->rtcp_sinks);
	}
}

/* must be called with call->master_lock held in W */
static void __monologue_destroy(struct call_monologue *monologue, int recurse) {
	struct call *call;
	struct call_monologue *dialogue;

	call = monologue->call;

	ilog(LOG_DEBUG, "Destroying monologue '" STR_FORMAT "' (" STR_FORMAT ")",
			STR_FMT(&monologue->tag),
			STR_FMT0(&monologue->viabranch));

	g_hash_table_remove(call->tags, &monologue->tag);
	if (monologue->viabranch.s)
		g_hash_table_remove(call->viabranches, &monologue->viabranch);

	for (GList *l = call->monologues.head; l; l = l->next) {
		dialogue = l->data;

		if (dialogue == monologue)
			continue;
		if (monologue->tag.len
				&& dialogue->tag.len
				&& !g_hash_table_lookup(dialogue->other_tags, &monologue->tag))
			continue;
		if (monologue->viabranch.len
				&& !monologue->tag.len
				&& !g_hash_table_lookup(dialogue->branches, &monologue->viabranch))
			continue;
		if (!dialogue->tag.len
				&& dialogue->viabranch.len
				&& !g_hash_table_lookup(monologue->branches, &dialogue->viabranch))
			continue;

		g_hash_table_remove(dialogue->other_tags, &monologue->tag);
		g_hash_table_remove(dialogue->branches, &monologue->viabranch);
		if (recurse && !g_hash_table_size(dialogue->other_tags) && !g_hash_table_size(dialogue->branches))
			__monologue_destroy(dialogue, 0);
	}

	monologue->deleted = 0;
}

/* must be called with call->master_lock held in W */
int monologue_destroy(struct call_monologue *ml) {
	struct call *c = ml->call;

	__monologue_destroy(ml, 1);

	if (g_hash_table_size(c->tags) < 2 && g_hash_table_size(c->viabranches) == 0) {
		ilog(LOG_INFO, "Call branch '" STR_FORMAT_M "' (%s" STR_FORMAT "%svia-branch '" STR_FORMAT_M "') "
				"deleted, no more branches remaining",
				STR_FMT_M(&ml->tag),
				ml->label.s ? "label '" : "",
				STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
				ml->label.s ? "', " : "",
				STR_FMT0_M(&ml->viabranch));
		return 1; /* destroy call */
	}

	ilog(LOG_INFO, "Call branch '" STR_FORMAT_M "' (%s" STR_FORMAT "%svia-branch '" STR_FORMAT_M "') deleted",
			STR_FMT_M(&ml->tag),
			ml->label.s ? "label '" : "",
			STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
			ml->label.s ? "', " : "",
			STR_FMT0_M(&ml->viabranch));
	return 0;
}

/* must be called with call->master_lock held in W */
static void __fix_other_tags(struct call_monologue *one) {
	if (!one || !one->tag.len)
		return;

	for (GList *sub = one->subscribers.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		struct call_monologue *two = cs->monologue;
		g_hash_table_insert(one->other_tags, &two->tag, two);
		g_hash_table_insert(two->other_tags, &one->tag, one);
	}
}

/* must be called with call->master_lock held in W */
struct call_monologue *call_get_monologue(struct call *call, const str *fromtag) {
	return g_hash_table_lookup(call->tags, fromtag);
}
/* must be called with call->master_lock held in W */
struct call_monologue *call_get_or_create_monologue(struct call *call, const str *fromtag) {
	struct call_monologue *ret = call_get_monologue(call, fromtag);
	if (!ret) {
		ret = __monologue_create(call);
		__monologue_tag(ret, fromtag);
	}
	return ret;
}

/* must be called with call->master_lock held in W */
static int call_get_monologue_new(struct call_monologue *dialogue[2], struct call *call,
		const str *fromtag, const str *totag,
		const str *viabranch)
{
	struct call_monologue *ret, *os = NULL;

	__C_DBG("getting monologue for tag '"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(&call->callid));
	ret = call_get_monologue(call, fromtag);
	if (!ret) {
		ret = __monologue_create(call);
		__monologue_tag(ret, fromtag);
		goto new_branch;
	}

	__C_DBG("found existing monologue");
	__monologue_unkernelize(ret);
	for (GList *sub = ret->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		__monologue_unkernelize(cs->monologue);
	}

	// if we have a to-tag, confirm that this dialogue association is intact
	if (totag && totag->s) {
		for (GList *sub = ret->subscribers.head; sub; sub = sub->next) {
			struct call_subscription *cs = sub->data;
			if (!cs->offer_answer)
				continue;
			struct call_monologue *csm = cs->monologue;
			if (str_cmp_str(&csm->tag, totag)) {
				__C_DBG("different to-tag than existing dialogue association");
				csm = call_get_monologue(call, totag);
				if (!csm)
					goto new_branch;
				// use existing to-tag
				__monologue_unkernelize(csm);
				__subscribe_offer_answer_both_ways(ret, csm);
				break;
			}
			break; // there should only be one
			// XXX check if there's more than a one-to-one mapping here?
		}
	}

	if (!viabranch)
		goto ok_check_tag;

	for (GList *sub = ret->subscribers.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		struct call_monologue *csm = cs->monologue;
		/* check the viabranch. if it's not known, then this is a branched offer and we need
		 * to create a new "other side" for this branch. */
		if (!csm->viabranch.s) {
			/* previous "other side" hasn't been tagged with the via-branch, so we'll just
			 * use this one and tag it */
			__monologue_viabranch(csm, viabranch);
			goto ok_check_tag;
		}
		if (!str_cmp_str(&csm->viabranch, viabranch))
			goto ok_check_tag; /* dialogue still intact */
	}
	os = g_hash_table_lookup(call->viabranches, viabranch);
	if (os) {
		/* previously seen branch. use it */
		__monologue_unkernelize(os);
		__subscribe_offer_answer_both_ways(ret, os);
		goto ok_check_tag;
	}

	/* we need both sides of the dialogue even in the initial offer, so create
	 * another monologue without to-tag (to be filled in later) */
new_branch:
	__C_DBG("create new \"other side\" monologue for viabranch "STR_FORMAT, STR_FMT0(viabranch));
	os = __monologue_create(call);
	__subscribe_offer_answer_both_ways(ret, os);
	__monologue_viabranch(os, viabranch);

ok_check_tag:
	for (GList *sub = ret->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		if (!cs->offer_answer)
			continue;
		struct call_monologue *csm = cs->monologue;
		if (!os)
			os = csm;
		if (totag && totag->s && !csm->tag.s) {
			__monologue_tag(csm, totag);
			__fix_other_tags(ret);
		}
		break; // there should only be one
		// XXX check if there's more than a one-to-one mapping here?
	}
	dialogue[0] = ret;
	dialogue[1] = os;
	return 0;
}

/* must be called with call->master_lock held in W */
static int call_get_dialogue(struct call_monologue *dialogue[2], struct call *call, const str *fromtag,
		const str *totag,
		const str *viabranch)
{
	struct call_monologue *ft, *tt;

	__C_DBG("getting dialogue for tags '"STR_FORMAT"'<>'"STR_FORMAT"' in call '"STR_FORMAT"'",
			STR_FMT(fromtag), STR_FMT(totag), STR_FMT(&call->callid));

	/* we start with the to-tag. if it's not known, we treat it as a branched offer */
	tt = call_get_monologue(call, totag);
	if (!tt)
		return call_get_monologue_new(dialogue, call, fromtag, totag, viabranch);

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

	dialogue_unkernelize(ft);
	dialogue_unkernelize(tt);
	__subscribe_offer_answer_both_ways(ft, tt);
	__fix_other_tags(ft);

done:
	__monologue_unkernelize(ft);
	dialogue_unkernelize(ft);
	dialogue[0] = ft;
	dialogue[1] = tt;
	return 0;
}

/* fromtag and totag strictly correspond to the directionality of the message, not to the actual
 * SIP headers. IOW, the fromtag corresponds to the monologue sending this message, even if the
 * tag is actually from the TO header of the SIP message (as it would be in a 200 OK) */
int call_get_mono_dialogue(struct call_monologue *dialogue[2], struct call *call, const str *fromtag,
		const str *totag,
		const str *viabranch)
{
	if (!totag || !totag->s) /* initial offer */
		return call_get_monologue_new(dialogue, call, fromtag, NULL, viabranch);
	return call_get_dialogue(dialogue, call, fromtag, totag, viabranch);
}



static void media_stop(struct call_media *m) {
	t38_gateway_stop(m->t38_gateway);
	codec_handlers_stop(&m->codec_handlers_store);
	rtcp_timer_stop(&m->rtcp_timer);
	mqtt_timer_stop(&m->mqtt_timer);
}
static void __monologue_stop(struct call_monologue *ml) {
	media_player_stop(ml->player);
}
static void monologue_stop(struct call_monologue *ml) {
	__monologue_stop(ml);
	for (GList *l = ml->medias.head; l; l = l->next)
		media_stop(l->data);
}


int call_delete_branch(const str *callid, const str *branch,
	const str *fromtag, const str *totag, bencode_item_t *output, int delete_delay)
{
	struct call *c;
	struct call_monologue *ml;
	int ret;
	const str *match_tag;
	GList *i;

	if (delete_delay < 0)
		delete_delay = rtpe_config.delete_delay;

	c = call_get(callid);
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
	if (output)
		ng_call_stats(c, fromtag, totag, output, NULL);

	monologue_stop(ml);
	for (GList *l = ml->subscribers.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		monologue_stop(cs->monologue);
	}

	if (delete_delay > 0) {
		ilog(LOG_INFO, "Scheduling deletion of call branch '" STR_FORMAT_M "' "
				"(via-branch '" STR_FORMAT_M "') in %d seconds",
				STR_FMT_M(&ml->tag), STR_FMT0_M(branch), delete_delay);
		ml->deleted = rtpe_now.tv_sec + delete_delay;
		if (!c->ml_deleted || c->ml_deleted > ml->deleted)
			c->ml_deleted = ml->deleted;
	}
	else {
		ilog(LOG_INFO, "Deleting call branch '" STR_FORMAT_M "' (via-branch '" STR_FORMAT_M "')",
				STR_FMT_M(&ml->tag), STR_FMT0_M(branch));
		if (monologue_destroy(ml))
			goto del_all;
	}
	goto success_unlock;

del_all:
	for (i = c->monologues.head; i; i = i->next) {
		ml = i->data;
		monologue_stop(ml);
	}

	if (delete_delay > 0) {
		ilog(LOG_INFO, "Scheduling deletion of entire call in %d seconds", delete_delay);
		c->deleted = rtpe_now.tv_sec + delete_delay;
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
