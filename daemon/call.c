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
#include "main.h"
#include "graphite.h"
#include "codec.h"
#include "media_player.h"
#include "jitter_buffer.h"
#include "t38.h"


struct iterator_helper {
	GSList			*del_timeout;
	GSList			*del_scheduled;
	GHashTable		*addr_sfd;
	uint64_t		transcoded_media;
};
struct xmlrpc_helper {
	enum xmlrpc_format fmt;
	GStringChunk		*c;
	GQueue			strings;
};


/* XXX rework these */
struct stats rtpe_statsps;
struct stats rtpe_stats;

rwlock_t rtpe_callhash_lock;
GHashTable *rtpe_callhash;

/* ********** */

static void __monologue_destroy(struct call_monologue *monologue, int recurse);
static int monologue_destroy(struct call_monologue *ml);
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



void call_make_own_foreign(struct call *c, int foreign) {
	statistics_update_foreignown_dec(c);
	c->foreign_call = foreign ? 1 : 0;
	statistics_update_foreignown_inc(c);
}



/* called with hashlock held */
static void call_timer_iterator(struct call *c, struct iterator_helper *hlp) {
	GList *it;
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
			good = 1;

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

drop:
	hlp->del_timeout = g_slist_prepend(hlp->del_timeout, obj_get(c));
	goto out;

delete:
	hlp->del_scheduled = g_slist_prepend(hlp->del_scheduled, obj_get(c));
	goto out;

out:
	rwlock_unlock_r(&rtpe_config.config_lock);
	rwlock_unlock_r(&c->master_lock);
	log_info_clear();
	obj_put(c);
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
					g_queue_pop_head(&xh->strings);
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
			g_queue_pop_head(&xh->strings);
		xmlrpc_env_clean(&e);

		_exit(0);

fault:
		ilog(LOG_WARNING, "XMLRPC fault occurred: %s", e.fault_string);
		_exit(1);
	}

	g_string_chunk_free(xh->c);
	g_slice_free1(sizeof(*xh), xh);
}

void kill_calls_timer(GSList *list, const char *url) {
	struct call *ca;
	GList *csl;
	struct call_monologue *cm, *cd;
	const char *url_prefix, *url_suffix;
	struct xmlrpc_helper *xh = NULL;
	char url_buf[128];

	if (!list)
		return;

	/* if url is NULL, it's the scheduled deletions, otherwise it's the timeouts */
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
				g_queue_push_tail(&xh->strings, g_string_chunk_insert(xh->c, url_buf));
				g_queue_push_tail(&xh->strings, str_chunk_insert(xh->c, &cm->tag));
			}
			break;
		case XF_CALLID:
			g_queue_push_tail(&xh->strings, g_string_chunk_insert(xh->c, url_buf));
			g_queue_push_tail(&xh->strings, str_chunk_insert(xh->c, &ca->callid));
			break;
		case XF_KAMAILIO:
			for (csl = ca->monologues.head; csl; csl = csl->next) {
				cm = csl->data;
				cd = cm->active_dialogue;
				if (!cm->tag.s || !cm->tag.len || !cd || !cd->tag.s || !cd->tag.len)
					continue;

				str *from_tag = g_hash_table_lookup(dup_tags, &cd->tag);
				if (from_tag && !str_cmp_str(from_tag, &cm->tag))
					continue;

				from_tag = str_chunk_insert(xh->c, &cm->tag);
				str *to_tag = str_chunk_insert(xh->c, &cd->tag);

				g_queue_push_tail(&xh->strings,
						g_string_chunk_insert(xh->c, url_buf));
				g_queue_push_tail(&xh->strings,
						str_chunk_insert(xh->c, &ca->callid));
				g_queue_push_tail(&xh->strings, from_tag);
				g_queue_push_tail(&xh->strings, to_tag);

				g_hash_table_insert(dup_tags, from_tag, to_tag);
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
				rtpe_config.idle_priority);
}


#define DS(x) do {							\
		u_int64_t ks_val;					\
		ks_val = atomic64_get(&ps->kernel_stats.x);		\
		if (ke->stats.x < ks_val)				\
			diff_ ## x = 0;					\
		else							\
			diff_ ## x = ke->stats.x - ks_val;		\
		atomic64_add(&ps->stats.x, diff_ ## x);			\
		atomic64_add(&rtpe_statsps.x, diff_ ## x);		\
	} while (0)

static void update_requests_per_second_stats(struct requests_ps *request, u_int64_t new_val) {
	mutex_lock(&request->lock);

	request->count++;
	request->ps_avg += new_val;

	if ((request->ps_min == 0) || (request->ps_min > new_val)) {
		request->ps_min = new_val;
	}

	if ((request->ps_max == 0) || (request->ps_max < new_val)) {
		request->ps_max = new_val;
	}

	mutex_unlock(&request->lock);
}

static void calls_build_list(void *k, void *v, void *d) {
	GSList **list = d;
	struct call *c = v;
	*list = g_slist_prepend(*list, obj_get(c));
}

static void call_timer(void *ptr) {
	struct iterator_helper hlp;
	GList *i, *l;
	GSList *calls = NULL;
	struct rtpengine_list_entry *ke;
	struct packet_stream *ps, *sink;
	struct stats tmpstats;
	int j, update;
	struct stream_fd *sfd;
	struct rtp_stats *rs;
	unsigned int pt;
	endpoint_t ep;
	u_int64_t offers, answers, deletes;
	struct timeval tv_start;
	long long run_diff;

	// timers are run in a single thread, so no locking required here
	static struct timeval last_run;
	static long long interval = 1000000; // usec

	gettimeofday(&tv_start, NULL);

	// ready to start?
	run_diff = timeval_diff(&tv_start, &last_run);
	if (run_diff < interval)
		return;

	last_run = tv_start;

	// round up and make integer seconds
	run_diff += 499999;
	run_diff /= 1000000;
	if (run_diff < 1)
		run_diff = 1;

	ZERO(hlp);
	hlp.addr_sfd = g_hash_table_new(g_endpoint_hash, g_endpoint_eq);

	/* obtain the call list and make a copy from it so not to hold the lock */
	rwlock_lock_r(&rtpe_callhash_lock);
	g_hash_table_foreach(rtpe_callhash, calls_build_list, &calls);
	rwlock_unlock_r(&rtpe_callhash_lock);

	while (calls) {
		struct call *c = calls->data;
		call_timer_iterator(c, &hlp);
		calls = g_slist_delete_link(calls, calls);
	}

	atomic64_local_copy_zero_struct(&tmpstats, &rtpe_statsps, bytes);
	atomic64_local_copy_zero_struct(&tmpstats, &rtpe_statsps, packets);
	atomic64_local_copy_zero_struct(&tmpstats, &rtpe_statsps, errors);

	atomic64_set(&rtpe_stats.bytes, atomic64_get_na(&tmpstats.bytes) / run_diff);
	atomic64_set(&rtpe_stats.packets, atomic64_get_na(&tmpstats.packets) / run_diff);
	atomic64_set(&rtpe_stats.errors, atomic64_get_na(&tmpstats.errors) / run_diff);

	/* update statistics regarding requests per second */
	offers = atomic64_get_set(&rtpe_statsps.offers, 0);
	update_requests_per_second_stats(&rtpe_totalstats_interval.offers_ps, offers / run_diff);

	answers = atomic64_get_set(&rtpe_statsps.answers, 0);
	update_requests_per_second_stats(&rtpe_totalstats_interval.answers_ps,	answers / run_diff);

	deletes = atomic64_get_set(&rtpe_statsps.deletes, 0);
	update_requests_per_second_stats(&rtpe_totalstats_interval.deletes_ps,	deletes / run_diff);

	// stats derived while iterating calls
	atomic64_set(&rtpe_stats.transcoded_media, hlp.transcoded_media);

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


		if (ke->stats.packets != atomic64_get(&ps->kernel_stats.packets))
			atomic64_set(&ps->last_packet, rtpe_now.tv_sec);

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

		if (!ke->target.non_forwarding && diff_packets) {
			if (sink) {
				mutex_lock(&sink->out_lock);
				if (sink->crypto.params.crypto_suite && sink->ssrc_out
						&& ntohl(ke->target.ssrc) == sink->ssrc_out->parent->h.ssrc
						&& ke->target.encrypt.last_index - sink->ssrc_out->srtp_index > 0x4000)
				{
					sink->ssrc_out->srtp_index = ke->target.encrypt.last_index;
					update = 1;
				}
				mutex_unlock(&sink->out_lock);
			}

			mutex_lock(&ps->in_lock);

			if (ps->ssrc_in && ntohl(ke->target.ssrc) == ps->ssrc_in->parent->h.ssrc) {
				atomic64_add(&ps->ssrc_in->octets, diff_bytes);
				atomic64_add(&ps->ssrc_in->packets, diff_packets);
				atomic64_set(&ps->ssrc_in->last_seq, ke->target.decrypt.last_index);
				ps->ssrc_in->srtp_index = ke->target.decrypt.last_index;

				if (sfd->crypto.params.crypto_suite
						&& ke->target.decrypt.last_index
						- ps->ssrc_in->srtp_index > 0x4000)
					update = 1;
			}
			mutex_unlock(&ps->in_lock);
		}

		rwlock_unlock_r(&sfd->call->master_lock);

		if (update) {
				redis_update_onekey(ps->call, rtpe_redis_write);
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
	kill_calls_timer(hlp.del_timeout, rtpe_config.b2b_url);

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

	poller_add_timer(rtpe_poller, call_timer, NULL);

	return 0;
}

void call_free(void) {
	GList *ll = g_hash_table_get_values(rtpe_callhash);
	for (GList *l = ll; l; l = l->next) {
		struct call *c = l->data;
		__call_cleanup(c);
		obj_put(c);
	}
	g_list_free(ll);
	g_hash_table_destroy(rtpe_callhash);
}



void payload_type_free(struct rtp_payload_type *p) {
	g_slice_free1(sizeof(*p), p);
}

struct call_media *call_media_new(struct call *call) {
	struct call_media *med;
	med = uid_slice_alloc0(med, &call->medias);
	med->call = call;
	med->codecs_recv = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, NULL);
	med->codecs_send = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, NULL);
	med->codec_names_recv = g_hash_table_new_full(str_case_hash, str_case_equal, free,
			(void (*)(void*)) g_queue_free);
	med->codec_names_send = g_hash_table_new_full(str_case_hash, str_case_equal, free,
			(void (*)(void*)) g_queue_free);
	return med;
}

static struct call_media *__get_media(struct call_monologue *ml, GList **it, const struct stream_params *sp,
		const struct sdp_ng_flags *flags)
{
	struct call_media *med;
	struct call *call;

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
		ilog(LOG_ERR, "Received trickle ICE SDP fragment with unknown media ID '"
				STR_FORMAT "'",
				STR_FMT(&sp->media_id));
	}

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
	med = call_media_new(call);
	med->monologue = ml;
	med->index = sp->index;
	call_str_cpy(ml->call, &med->type, &sp->type);
	med->type_id = codec_get_type(&med->type);

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
	if (get_consecutive_ports(&intf_sockets, num_ports, media->logical_intf, &media->call->callid))
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
	atomic64_set_na(&stream->last_packet, rtpe_now.tv_sec);
	stream->rtp_stats = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, __rtp_stats_free);
	recording_init_stream(stream);
	stream->send_timer = send_timer_new(stream);

	if (rtpe_config.jb_length)
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

	if (PS_ISSET(ps, FILLED) && !MEDIA_ISSET(media, DTLS)) {
		/* we reset crypto params whenever the endpoint changes */
		// XXX fix WRT SSRC handling
		crypto_reset(&ps->crypto);
		dtls_shutdown(ps);
	}

	ilog(LOG_DEBUG, "set FILLED flag for stream %s%s:%d%s",
			FMT_M(sockaddr_print_buf(&ps->endpoint.address), ps->endpoint.port));
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
			ilog(LOG_DEBUG, "[%s] Initialized incoming SRTP with SDES crypto params: %s%s%s",
					endpoint_print_buf(&sfd->socket.local),
					FMT_M(crypto_params_sdes_dump(cps, &paramsbuf)));
		}
		struct crypto_params_sdes *cps = media->sdes_out.head
			? media->sdes_out.head->data : NULL;
		crypto_init(&ps->crypto, cps ? &cps->params : NULL);
		ilog(LOG_DEBUG, "[%i] Initialized outgoing SRTP with SDES crypto params: %s%s%s",
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

void __rtp_stats_update(GHashTable *dst, GHashTable *src) {
	struct rtp_stats *rs;
	struct rtp_payload_type *pt;
	GList *values, *l;

	/* "src" is a call_media->codecs table, while "dst" is a
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

		__rtp_stats_update(a->rtp_stats, A->codecs_recv);

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
	// unless instructed not to
	if (flags->ice_option == ICE_DEFAULT) {
		if (!MEDIA_ISSET(other, ICE))
			MEDIA_CLEAR(this, ICE);
	}
	else if (flags->ice_option == ICE_REMOVE)
		MEDIA_CLEAR(this, ICE);

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
	};

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
static void __generate_crypto(const struct sdp_ng_flags *flags, struct call_media *this,
		struct call_media *other)
{
	GQueue *cpq = &this->sdes_out;
	GQueue *cpq_in = &this->sdes_in;
	GQueue *offered_cpq = &other->sdes_in;

	if (!flags)
		return;

	if (!this->protocol || !this->protocol->srtp || MEDIA_ISSET(this, PASSTHRU)) {
		crypto_params_sdes_queue_clear(cpq);
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

	if (flags->opmode == OP_OFFER) {
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

	if (flags->opmode == OP_OFFER) {
		// generate full set of params
		// re-create the entire list - steal for later flushing
		GQueue cpq_orig = *cpq;
		g_queue_init(cpq);

		// if we were offered some crypto suites, copy those first into our offer
		unsigned int c_tag = 1; // tag for next crypto suite generated by us
		unsigned long types_offered = 0;

		// make sure our bit field is large enough
		assert(num_crypto_suites <= sizeof(types_offered) * 8);

		for (GList *l = offered_cpq->head; l; l = l->next) {
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
				ilog(LOG_DEBUG, "Not offering crypto suite '%s' "
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
		struct crypto_params_sdes *offered_cps = offered_cpq->head ? offered_cpq->head->data : NULL;
		if (offered_cps) {
			ilog(LOG_DEBUG, "Looking for matching crypto suite to offered %u:%s", offered_cps->tag,
					offered_cps->params.crypto_suite->name);
			// check if we can do SRTP<>SRTP passthrough. the crypto suite that was accepted
			// must have been present in what was offered to us
			for (GList *l = cpq_in->head; l; l = l->next) {
				struct crypto_params_sdes *check_cps = l->data;
				if (check_cps->params.crypto_suite == offered_cps->params.crypto_suite) {
					ilog(LOG_DEBUG, "Found matching crypto suite %u:%s", check_cps->tag,
							check_cps->params.crypto_suite->name);
					cps_in = check_cps;
					break;
				}
			}
		}
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
				ilog(LOG_DEBUG, "Copied crypto params from %i:%s for SRTP passthrough",
						cps_in->tag, cps_in->params.crypto_suite->name);
			}
			else {
				random_string((unsigned char *) cps->params.master_key,
						cps->params.crypto_suite->master_key_len);
				random_string((unsigned char *) cps->params.master_salt,
						cps->params.crypto_suite->master_salt_len);
				/* mki = mki_len = 0 */
				cps->params.session_params = cps_in->params.session_params;
				ilog(LOG_DEBUG, "Creating new SRTP crypto params for %i:%s",
						cps->tag, cps->params.crypto_suite->name);
			}

			// flush out crypto suites we ended up not using - leave only one
#if GLIB_CHECK_VERSION(2,30,0)
			if (!g_queue_remove(cpq_in, cps_in))
				ilog(LOG_ERR, "BUG: incoming crypto suite not found in queue");
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
	if (flags->opmode == OP_OFFER) {
		if (MEDIA_ISSET(this, DTLS) && !this->fingerprint.hash_func && flags->dtls_fingerprint.len)
			this->fingerprint.hash_func = dtls_find_hash_func(&flags->dtls_fingerprint);
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

			ilog(LOG_DEBUG, "Dropping offered crypto suite '%s' from offer "
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
	if (flags->rtcp_mux_offer || flags->rtcp_mux_require)
		MEDIA_SET(media, RTCP_MUX);
	else if (flags->rtcp_mux_demux)
		MEDIA_CLEAR(media, RTCP_MUX);

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

	ilog(LOG_INFO, "DTLS fingerprint changed, restarting DTLS");

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
	/* we're holding master_lock in W mode here, so we can safely ignore the
	 * atomic ops */

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
		if (flags && flags->dtls_reverse_passive && MEDIA_ISSET(other_media, SETUP_PASSIVE))
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

	struct call *call = media->call;
	struct call_monologue *ml = media->monologue;
	struct call_monologue *other_ml = other_media->monologue;

	if (flags->opmode == OP_OFFER) {
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
		if (!media->media_id.s) {
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
		call_str_cpy(media->call, &media->type, &sp->type);
		media->type_id = other_media->type_id;
	}

	/* deduct protocol from stream parameters received */
	if (other_media->protocol != sp->protocol) {
		other_media->protocol = sp->protocol;
		/* If the endpoint changes the protocol, we reset the other side's
		 * protocol as well. this lets us remember our previous overrides,
		 * but also lets endpoints re-negotiate.
		 * Answers are a special case: handle OSRTP answer/accept, but otherwise
		 * answer with the same protocol that was offered, unless we're instructed
		 * not to. */
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
	/* default is to leave the protocol unchanged */
	if (!media->protocol)
		media->protocol = other_media->protocol;

	// handler overrides requested by the user
	if (!flags)
		return;

	/* allow override of outgoing protocol even if we know it already */
	/* but only if this is an RTP-based protocol */
	if (flags->transport_protocol
			&& proto_is_rtp(other_media->protocol))
		media->protocol = flags->transport_protocol;

	// OSRTP offer requested?
	if (media->protocol && media->protocol->rtp && !media->protocol->srtp
			&& media->protocol->osrtp_proto && flags->osrtp_offer && flags->opmode == OP_OFFER)
	{
		media->protocol = &transport_protocols[media->protocol->osrtp_proto];
	}

	// T.38 decoder?
	if (other_media->type_id == MT_IMAGE && proto_is(other_media->protocol, PROTO_UDPTL)
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
	if (other_media->type_id == MT_AUDIO && proto_is_rtp(other_media->protocol)
			&& flags->t38_force)
	{
		media->protocol = &transport_protocols[PROTO_UDPTL];
		media->type_id = MT_IMAGE;
		call_str_cpy_c(media->call, &media->type, "image");
		call_str_cpy_c(media->call, &media->format_str, "t38");
		return;
	}

	// previous T.38 gateway but now stopping?
	if (flags->t38_stop) {
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

/* called with call->master_lock held in W */
int monologue_offer_answer(struct call_monologue *other_ml, GQueue *streams,
		struct sdp_ng_flags *flags)
{
	struct stream_params *sp;
	GList *media_iter, *ml_media, *other_ml_media;
	struct call_media *media, *other_media;
	unsigned int num_ports;
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

	call->last_signal = rtpe_now.tv_sec;
	call->deleted = 0;

	__C_DBG("this="STR_FORMAT" other="STR_FORMAT, STR_FMT(&monologue->tag), STR_FMT(&other_ml->tag));

	__tos_change(call, flags);

	if (flags && flags->label.s) {
		call_str_cpy(call, &other_ml->label, &flags->label);
		g_hash_table_replace(call->labels, &other_ml->label, other_ml);
	}

	ml_media = other_ml_media = NULL;

	for (media_iter = streams->head; media_iter; media_iter = media_iter->next) {
		sp = media_iter->data;
		__C_DBG("processing media stream #%u", sp->index);

		/* first, check for existence of call_media struct on both sides of
		 * the dialogue */
		media = __get_media(monologue, &ml_media, sp, flags);
		other_media = __get_media(other_ml, &other_ml_media, sp, flags);
		/* OTHER is the side which has sent the message. SDP parameters in
		 * "sp" are as advertised by OTHER side. The message will be sent to
		 * THIS side. Parameters sent to THIS side may be overridden by
		 * what's in "flags". If this is an answer, or if we have talked to
		 * THIS side (recipient) before, then the structs will be populated with
		 * details already. */

		if (flags && flags->fragment) {
			// trickle ICE SDP fragment. don't do anything other than update
			// the ICE stuff.
			ice_update(other_media->ice_agent, sp);
			continue;
		}

		if (flags && flags->opmode == OP_OFFER && flags->reset) {
			MEDIA_CLEAR(media, INITIALIZED);
			MEDIA_CLEAR(other_media, INITIALIZED);
			if (media->ice_agent)
				ice_restart(media->ice_agent);
			if (other_media->ice_agent)
				ice_restart(other_media->ice_agent);
		}

		if (flags && flags->generate_rtcp) {
			MEDIA_SET(media, RTCP_GEN);
			MEDIA_SET(other_media, RTCP_GEN);
		}

		__update_media_protocol(media, other_media, sp, flags);
		__update_media_id(media, other_media, sp, flags);
		__endpoint_loop_protect(sp, other_media);

		if (sp->rtp_endpoint.port) {
			/* copy parameters advertised by the sender of this message */
			bf_copy_same(&other_media->media_flags, &sp->sp_flags,
					SHARED_FLAG_RTCP_MUX | SHARED_FLAG_ASYMMETRIC | SHARED_FLAG_UNIDIRECTIONAL |
					SHARED_FLAG_ICE | SHARED_FLAG_TRICKLE_ICE | SHARED_FLAG_ICE_LITE_PEER |
					SHARED_FLAG_RTCP_FB);

			// steal the entire queue of offered crypto params
			crypto_params_sdes_queue_clear(&other_media->sdes_in);
			other_media->sdes_in = sp->sdes_params;
			g_queue_init(&sp->sdes_params);

			if (other_media->sdes_in.length) {
				MEDIA_SET(other_media, SDES);
				__sdes_accept(other_media, flags);
			}
		}

		// codec and RTP payload types handling
		if (sp->ptime > 0) {
			if (!MEDIA_ISSET(media, PTIME_OVERRIDE))
				media->ptime = sp->ptime;
			if (!MEDIA_ISSET(other_media, PTIME_OVERRIDE))
				other_media->ptime = sp->ptime;
		}
		if (flags && flags->ptime > 0) {
			media->ptime = flags->ptime;
			MEDIA_SET(media, PTIME_OVERRIDE);
			MEDIA_SET(other_media, PTIME_OVERRIDE);
		}
		if (flags && flags->rev_ptime > 0) {
			other_media->ptime = flags->rev_ptime;
			MEDIA_SET(media, PTIME_OVERRIDE);
			MEDIA_SET(other_media, PTIME_OVERRIDE);
		}
		if (str_cmp_str(&other_media->format_str, &sp->format_str))
			call_str_cpy(call, &other_media->format_str, &sp->format_str);
		if (str_cmp_str(&media->format_str, &sp->format_str)) {
			// update opposite side format string only if protocols match
			if (media->protocol == other_media->protocol)
				call_str_cpy(call, &media->format_str, &sp->format_str);
		}

		codec_tracker_init(media);
		codec_rtp_payload_types(media, other_media, &sp->rtp_payload_types, flags);
		codec_handlers_update(media, other_media, flags, sp);
		codec_tracker_finish(media);

		/* send and recv are from our POV */
		bf_copy_same(&media->media_flags, &sp->sp_flags,
				SP_FLAG_SEND | SP_FLAG_RECV);
		bf_copy(&other_media->media_flags, MEDIA_FLAG_RECV, &sp->sp_flags, SP_FLAG_SEND);
		bf_copy(&other_media->media_flags, MEDIA_FLAG_SEND, &sp->sp_flags, SP_FLAG_RECV);

		/* deduct address family from stream parameters received */
		other_media->desired_family = sp->rtp_endpoint.address.family;
		/* for outgoing SDP, use "direction"/DF or default to what was offered */
		if (!media->desired_family)
			media->desired_family = other_media->desired_family;
		if (sp->desired_family)
			media->desired_family = sp->desired_family;

		if (sp->rtp_endpoint.port) {
			/* DTLS stuff */
			__dtls_logic(flags, other_media, sp);

			/* control rtcp-mux */
			__rtcp_mux_logic(flags, media, other_media);

			/* SDES and DTLS */
			__generate_crypto(flags, media, other_media);

		}

		/* determine number of consecutive ports needed locally.
		 * XXX only do *=2 for RTP streams? */
		num_ports = sp->consecutive_ports;
		num_ports *= 2;


		/* local interface selection */
		__init_interface(media, &sp->direction[1], num_ports);
		__init_interface(other_media, &sp->direction[0], num_ports);

		if (media->logical_intf == NULL || other_media->logical_intf == NULL) {
			goto error_intf;
		}

		/* ICE stuff - must come after interface and address family selection */
		__ice_offer(flags, media, other_media);
		__ice_start(other_media);
		__ice_start(media);



		/* we now know what's being advertised by the other side */
		MEDIA_SET(other_media, INITIALIZED);


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
		}

		__num_media_streams(media, num_ports);
		__assign_stream_fds(media, &em->intf_sfds);

		if (__num_media_streams(other_media, num_ports)) {
			/* new streams created on OTHER side. normally only happens in
			 * initial offer. create a wildcard endpoint_map to be filled in
			 * when the answer comes. */
			if (__wildcard_endpoint_map(other_media, num_ports))
				goto error_ports;
		}

init:
		if (__init_streams(media, other_media, NULL))
			return -1;
		if (__init_streams(other_media, media, sp))
			return -1;

		/* we are now ready to fire up ICE if so desired and requested */
		ice_update(other_media->ice_agent, sp);
		ice_update(media->ice_agent, NULL); /* this is in case rtcp-mux has changed */

		recording_setup_media(media);
		t38_gateway_start(media->t38_gateway);
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

	rtp_pt = rtp_payload_type(rtp_s->payload_type, m->codecs_recv);

out:
	g_list_free(values);
	return rtp_pt; /* may be NULL */
}

void add_total_calls_duration_in_interval(struct timeval *interval_tv) {
	struct timeval ongoing_calls_dur = add_ongoing_calls_dur_in_interval(
			&rtpe_latest_graphite_interval_start, interval_tv);

	mutex_lock(&rtpe_totalstats_interval.total_calls_duration_lock);
	timeval_add(&rtpe_totalstats_interval.total_calls_duration_interval,
			&rtpe_totalstats_interval.total_calls_duration_interval,
			&ongoing_calls_dur);
	mutex_unlock(&rtpe_totalstats_interval.total_calls_duration_lock);
}

static struct timeval add_ongoing_calls_dur_in_interval(struct timeval *interval_start,
		struct timeval *interval_duration)
{
	GHashTableIter iter;
	gpointer key, value;
	struct timeval call_duration, res = {0};
	struct call *call;
	struct call_monologue *ml;

	rwlock_lock_r(&rtpe_callhash_lock);
	g_hash_table_iter_init(&iter, rtpe_callhash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		call = (struct call*) value;
		if (!call->monologues.head || IS_FOREIGN_CALL(call))
			continue;
		ml = call->monologues.head->data;
		if (timercmp(interval_start, &ml->started, >)) {
			timeval_add(&res, &res, interval_duration);
		} else {
			timeval_subtract(&call_duration, &rtpe_now, &ml->started);
			timeval_add(&res, &res, &call_duration);
		}
	}
	rwlock_unlock_r(&rtpe_callhash_lock);
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

		ps->rtp_sink = NULL;
		ps->rtcp_sink = NULL;
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
	if (ret)
		g_hash_table_remove(rtpe_callhash, &c->callid);
	rwlock_unlock_w(&rtpe_callhash_lock);

	// if call not found in callhash => previously deleted
	if (!ret)
		return;

	obj_put(c);


	statistics_update_foreignown_dec(c);

	if (IS_OWN_CALL(c)) {
		redis_delete(c, rtpe_redis_write);
	}

	rwlock_lock_w(&c->master_lock);
	/* at this point, no more packet streams can be added */

	if (!IS_OWN_CALL(c))
		goto no_stats_output;

	///// stats output

	ilog(LOG_INFO, "Final packet stats:");

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;

		// stats output only - no cleanups

		ilog(LOG_INFO, "--- Tag '" STR_FORMAT_M "'%s"STR_FORMAT"%s, created "
				"%u:%02u ago for branch '" STR_FORMAT_M "', in dialogue with '" STR_FORMAT_M "'",
				STR_FMT_M(&ml->tag),
				ml->label.s ? " (label '" : "",
				STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
				ml->label.s ? "')" : "",
				(unsigned int) (rtpe_now.tv_sec - ml->created) / 60,
				(unsigned int) (rtpe_now.tv_sec - ml->created) % 60,
				STR_FMT_M(&ml->viabranch),
				ml->active_dialogue ? rtpe_common_config_ptr->log_mark_prefix : "",
				ml->active_dialogue ? ml->active_dialogue->tag.len : 6,
				ml->active_dialogue ? ml->active_dialogue->tag.s : "(none)",
				ml->active_dialogue ? rtpe_common_config_ptr->log_mark_suffix : "");

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
						FMT_M(ps->ssrc_in ? ps->ssrc_in->parent->h.ssrc : 0),
						atomic64_get(&ps->stats.packets),
						atomic64_get(&ps->stats.bytes),
						atomic64_get(&ps->stats.errors),
						rtpe_now.tv_sec - atomic64_get(&ps->last_packet));

				statistics_update_totals(ps);
			}
		}
	}

	k = g_hash_table_get_values(c->ssrc_hash->ht);
	for (l = k; l; l = l->next) {
		struct ssrc_entry_call *se = l->data;

		// stats output only - no cleanups

		if (!se->stats_blocks.length || !se->lowest_mos || !se->highest_mos)
			continue;

		ilog(LOG_INFO, "--- SSRC %s%" PRIx32 "%s", FMT_M(se->h.ssrc));
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
	// cleanups

	statistics_update_oneway(c);

	cdr_update_entry(c);

	__call_cleanup(c);

	rwlock_unlock_w(&c->master_lock);
}


/* XXX move these */
int call_stream_address46(char *o, struct packet_stream *ps, enum stream_address_format format,
		int *len, const struct local_intf *ifa, int keep_unspec)
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
			&& !is_trickle_ice_address(&sink->advertised_endpoint)
			&& keep_unspec)
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

	ilog(LOG_DEBUG, "freeing main call struct");

	obj_put(c->dtls_cert);

	while (c->monologues.head) {
		m = g_queue_pop_head(&c->monologues);

		g_queue_clear(&m->medias);
		g_hash_table_destroy(m->other_tags);
		g_hash_table_destroy(m->branches);
		g_hash_table_destroy(m->media_ids);
		g_slice_free1(sizeof(*m), m);
	}

	while (c->medias.head) {
		md = g_queue_pop_head(&c->medias);

		crypto_params_sdes_queue_clear(&md->sdes_in);
		crypto_params_sdes_queue_clear(&md->sdes_out);
		g_queue_clear(&md->streams);
		g_queue_clear(&md->endpoint_maps);
		g_hash_table_destroy(md->codecs_recv);
		g_hash_table_destroy(md->codecs_send);
		g_hash_table_destroy(md->codec_names_recv);
		g_hash_table_destroy(md->codec_names_send);
		g_queue_clear_full(&md->codecs_prefs_recv, (GDestroyNotify) payload_type_free);
		g_queue_clear_full(&md->codecs_prefs_send, (GDestroyNotify) payload_type_free);
		codec_handlers_free(md);
		codec_handler_free(&md->t38_handler);
		t38_gateway_put(&md->t38_gateway);
		g_queue_clear_full(&md->sdp_attributes, free);
		g_slice_free1(sizeof(*md), md);
	}

	while (c->endpoint_maps.head) {
		em = g_queue_pop_head(&c->endpoint_maps);

		g_queue_clear_full(&em->intf_sfds, (void *) free_intf_list);
		g_slice_free1(sizeof(*em), em);
	}

	g_hash_table_destroy(c->tags);
	g_hash_table_destroy(c->viabranches);
	g_hash_table_destroy(c->labels);
	free_ssrc_hash(&c->ssrc_hash);

	while (c->streams.head) {
		ps = g_queue_pop_head(&c->streams);
		crypto_cleanup(&ps->crypto);
		g_queue_clear(&ps->sfds);
		g_hash_table_destroy(ps->rtp_stats);
		ssrc_ctx_put(&ps->ssrc_in);
		ssrc_ctx_put(&ps->ssrc_out);
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
	c->ssrc_hash = create_ssrc_hash_call();

	return c;
}

/* returns call with master_lock held in W */
struct call *call_get_or_create(const str *callid, int foreign) {
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

		c->foreign_call = foreign;

		statistics_update_foreignown_inc(c);

		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_w(&rtpe_callhash_lock);
	}
	else {
		obj_hold(c);
		rwlock_lock_w(&c->master_lock);
		rwlock_unlock_r(&rtpe_callhash_lock);
	}

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
		return call_get_or_create(callid, 0);
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
	struct call_monologue *other = ml->active_dialogue;

	if (!viabranch || !viabranch->len)
		return;

	__C_DBG("tagging monologue with viabranch '"STR_FORMAT"'", STR_FMT(viabranch));
	if (ml->viabranch.s) {
		g_hash_table_remove(call->viabranches, &ml->viabranch);
		if (other)
			g_hash_table_remove(other->branches, &ml->viabranch);
	}
	call_str_cpy(call, &ml->viabranch, viabranch);
	g_hash_table_insert(call->viabranches, &ml->viabranch, ml);
	if (other)
		g_hash_table_insert(other->branches, &ml->viabranch, ml);
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
static int monologue_destroy(struct call_monologue *ml) {
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
	if (!ft->tag.s || str_cmp_str(&ft->tag, fromtag))
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



static void media_stop(struct call_media *m) {
	t38_gateway_stop(m->t38_gateway);
	codec_handlers_stop(&m->codec_handlers_store);
	m->rtcp_timer.tv_sec = 0;
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

	monologue_stop(ml);
	if (ml->active_dialogue && ml->active_dialogue->active_dialogue == ml)
		monologue_stop(ml->active_dialogue);

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


static void call_get_all_calls_interator(void *key, void *val, void *ptr) {
	GQueue *q = ptr;
	g_queue_push_tail(q, obj_get_o(val));
}

void call_get_all_calls(GQueue *q) {
	rwlock_lock_r(&rtpe_callhash_lock);
	g_hash_table_foreach(rtpe_callhash, call_get_all_calls_interator, q);
	rwlock_unlock_r(&rtpe_callhash_lock);

}
