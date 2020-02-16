#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>

#include "poller.h"
#include "aux.h"
#include "log.h"
#include "log_funcs.h"
#include "call.h"
#include "cli.h"
#include "socket.h"
#include "redis.h"
#include "control_ng.h"
#include "media_socket.h"
#include "cdr.h"
#include "streambuf.h"
#include "tcp_listener.h"
#include "str.h"
#include "statistics.h"
#include "main.h"
#include "media_socket.h"
#include "rtplib.h"
#include "ssrc.h"

#include "rtpengine_config.h"


typedef void (*cli_handler_func)(str *, struct streambuf *);
typedef struct {
	const char *cmd;
	cli_handler_func handler;
} cli_handler_t;

static void cli_incoming_list(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set(str *instr, struct streambuf *replybuffer);
static void cli_incoming_params(str *instr, struct streambuf *replybuffer);
static void cli_incoming_terminate(str *instr, struct streambuf *replybuffer);
static void cli_incoming_ksadd(str *instr, struct streambuf *replybuffer);
static void cli_incoming_ksrm(str *instr, struct streambuf *replybuffer);
static void cli_incoming_kslist(str *instr, struct streambuf *replybuffer);

static void cli_incoming_set_maxopenfiles(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_maxsessions(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_maxcpu(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_maxload(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_maxbw(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_timeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_silenttimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_offertimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_finaltimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_loglevel(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_redisallowederrors(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_redisdisabletime(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_redisconnecttimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_rediscmdtimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_set_controltos(str *instr, struct streambuf *replybuffer);

static void cli_incoming_params_start(str *instr, struct streambuf *replybuffer);
static void cli_incoming_params_current(str *instr, struct streambuf *replybuffer);
static void cli_incoming_params_diff(str *instr, struct streambuf *replybuffer);
static void cli_incoming_params_revert(str *instr, struct streambuf *replybuffer);

static void cli_incoming_list_numsessions(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_maxsessions(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_maxcpu(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_maxload(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_maxbw(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_maxopenfiles(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_totals(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_counters(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_sessions(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_timeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_silenttimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_offertimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_finaltimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_loglevel(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_loglevel(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_redisallowederrors(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_redisdisabletime(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_redisconnecttimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_rediscmdtimeout(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_controltos(str *instr, struct streambuf *replybuffer);
static void cli_incoming_list_interfaces(str *instr, struct streambuf *replybuffer);

static const cli_handler_t cli_top_handlers[] = {
	{ "list",		cli_incoming_list		},
	{ "terminate",		cli_incoming_terminate		},
	{ "set",		cli_incoming_set		},
	{ "get",		cli_incoming_list		},
	{ "params",		cli_incoming_params		},
	{ "ksadd",		cli_incoming_ksadd		},
	{ "ksrm",		cli_incoming_ksrm		},
	{ "kslist",		cli_incoming_kslist		},
	{ NULL, },
};
static const cli_handler_t cli_set_handlers[] = {
	{ "maxopenfiles",		cli_incoming_set_maxopenfiles		},
	{ "maxsessions",		cli_incoming_set_maxsessions		},
	{ "maxcpu",			cli_incoming_set_maxcpu			},
	{ "maxload",			cli_incoming_set_maxload		},
	{ "maxbw",			cli_incoming_set_maxbw			},
	{ "timeout",			cli_incoming_set_timeout		},
	{ "silenttimeout",		cli_incoming_set_silenttimeout		},
	{ "offertimeout",		cli_incoming_set_offertimeout		},
	{ "finaltimeout",		cli_incoming_set_finaltimeout		},
	{ "loglevel",			cli_incoming_set_loglevel		},
	{ "redisallowederrors",		cli_incoming_set_redisallowederrors	},
	{ "redisdisabletime",		cli_incoming_set_redisdisabletime	},
	{ "redisconnecttimeout",	cli_incoming_set_redisconnecttimeout	},
	{ "rediscmdtimeout",		cli_incoming_set_rediscmdtimeout	},
	{ "controltos",			cli_incoming_set_controltos		},
	{ NULL, },
};
static const cli_handler_t cli_list_handlers[] = {
	{ "numsessions",		cli_incoming_list_numsessions		},
	{ "sessions",			cli_incoming_list_sessions		},
	{ "totals",			cli_incoming_list_totals		},
	{ "counters",			cli_incoming_list_counters		},
	{ "maxopenfiles",		cli_incoming_list_maxopenfiles		},
	{ "maxsessions",		cli_incoming_list_maxsessions		},
	{ "maxcpu",			cli_incoming_list_maxcpu		},
	{ "maxload",			cli_incoming_list_maxload		},
	{ "maxbw",			cli_incoming_list_maxbw			},
	{ "timeout",			cli_incoming_list_timeout		},
	{ "silenttimeout",		cli_incoming_list_silenttimeout		},
	{ "offertimeout",		cli_incoming_list_offertimeout		},
	{ "finaltimeout",		cli_incoming_list_finaltimeout		},
	{ "loglevel",			cli_incoming_list_loglevel		},
	{ "redisallowederrors",		cli_incoming_list_redisallowederrors	},
	{ "redisdisabletime",		cli_incoming_list_redisdisabletime	},
	{ "redisconnecttimeout",	cli_incoming_list_redisconnecttimeout	},
	{ "rediscmdtimeout",		cli_incoming_list_rediscmdtimeout	},
	{ "controltos",			cli_incoming_list_controltos		},
	{ "interfaces",			cli_incoming_list_interfaces		},
	{ NULL, },
};

static const cli_handler_t cli_params_handlers[] = {
	{ "start",	cli_incoming_params_start	},
	{ "current",	cli_incoming_params_current	},
	{ "diff",	cli_incoming_params_diff	},
	{ "revert",	cli_incoming_params_revert	},
	{ NULL, },
};

static void cli_handler_do(const cli_handler_t *handlers, str *instr,
		struct streambuf *replybuffer)
{
	const cli_handler_t *h;

	for (h = handlers; h->cmd; h++) {
		if (str_shift_cmp(instr, h->cmd))
			continue;
		h->handler(instr, replybuffer);
		return;
	}

	streambuf_printf(replybuffer, "%s:%s\n", "Unknown or incomplete command:", instr->s);
}

static void destroy_own_foreign_calls(unsigned int foreign_call, unsigned int uint_keyspace_db) {
	struct call *c = NULL;
	struct call_monologue *ml = NULL;
	GQueue call_list = G_QUEUE_INIT;
	GHashTableIter iter;
	gpointer key, value;
	GList *i;

	// lock read
	rwlock_lock_r(&rtpe_callhash_lock);

	g_hash_table_iter_init(&iter, rtpe_callhash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		c = (struct call*)value;
		if (!c) {
			continue;
		}

		// match foreign_call flag
		if ((foreign_call != UNDEFINED) && !(foreign_call == IS_FOREIGN_CALL(c))) {
			continue;
		}

		// match uint_keyspace_db, if some given
		if ((uint_keyspace_db != UNDEFINED) && !(uint_keyspace_db == c->redis_hosted_db)) {
			continue;
		}
		
		// increase ref counter
		obj_get(c);

		// save call reference
		g_queue_push_tail(&call_list, c);
	}

	// unlock read
	rwlock_unlock_r(&rtpe_callhash_lock);

	// destroy calls
	while ((c = g_queue_pop_head(&call_list))) {
		if (!c->ml_deleted) {
			for (i = c->monologues.head; i; i = i->next) {
				ml = i->data;
				gettimeofday(&(ml->terminated), NULL);
				ml->term_reason = FORCED;
			}
		}
		call_destroy(c);

		// decrease ref counter
		obj_put(c);
	}
}

static void destroy_all_foreign_calls(void) {
	destroy_own_foreign_calls(CT_FOREIGN_CALL, UNDEFINED);
}

static void destroy_all_own_calls(void) {
	destroy_own_foreign_calls(CT_OWN_CALL, UNDEFINED);
}

static void destroy_keyspace_foreign_calls(unsigned int uint_keyspace_db) {
	destroy_own_foreign_calls(CT_FOREIGN_CALL, uint_keyspace_db);
}

static void cli_incoming_params_start(str *instr, struct streambuf *replybuffer) {
	int count = 0;
	GList *s;
	struct intf_config *ifa;

	streambuf_printf(replybuffer, "log-level = %d\ntable = %d\nmax-sessions = %d\ntimeout = %d\nsilent-timeout = %d\n"
			"final-timeout = %d\noffer-timeout = %d\n"
			"delete-delay = %d\nredis-expires = %d\ntos = %d\ncontrol-tos = %d\ngraphite-interval = %d\nredis-num-threads = %d\n"
			"homer-protocol = %d\nhomer-id = %d\nno-fallback = %d\nport-min = %d\nport-max = %d\nredis = %s:%d/%d\n"
			"redis-write = %s:%d/%d\nno-redis-required = %d\nnum-threads = %d\nxmlrpc-format = %d\nlog_format = %d\n"
			"redis_allowed_errors = %d\nredis_disable_time = %d\nredis_cmd_timeout = %d\nredis_connect_timeout = %d\n"
			"max-cpu = %.1f\n"
			"max-load = %.2f\n"
			"max-bandwidth = %" PRIu64 "\n",
			initial_rtpe_config.common.log_level, initial_rtpe_config.kernel_table, initial_rtpe_config.max_sessions,
			initial_rtpe_config.timeout, initial_rtpe_config.silent_timeout, initial_rtpe_config.final_timeout,
			initial_rtpe_config.offer_timeout, initial_rtpe_config.delete_delay,
			initial_rtpe_config.redis_expires_secs, initial_rtpe_config.default_tos, initial_rtpe_config.control_tos,
			initial_rtpe_config.graphite_interval, initial_rtpe_config.redis_num_threads, initial_rtpe_config.homer_protocol,
			initial_rtpe_config.homer_id, initial_rtpe_config.no_fallback, initial_rtpe_config.port_min, initial_rtpe_config.port_max,
			sockaddr_print_buf(&initial_rtpe_config.redis_ep.address), initial_rtpe_config.redis_ep.port, initial_rtpe_config.redis_db,
			sockaddr_print_buf(&initial_rtpe_config.redis_write_ep.address), initial_rtpe_config.redis_write_ep.port,
			initial_rtpe_config.redis_write_db, initial_rtpe_config.no_redis_required, initial_rtpe_config.num_threads,
			initial_rtpe_config.fmt, initial_rtpe_config.log_format, initial_rtpe_config.redis_allowed_errors,
			initial_rtpe_config.redis_disable_time, initial_rtpe_config.redis_cmd_timeout, initial_rtpe_config.redis_connect_timeout,
			(double) initial_rtpe_config.cpu_limit / 100,
			(double) initial_rtpe_config.load_limit / 100,
			initial_rtpe_config.bw_limit);

	for(s = initial_rtpe_config.interfaces.head; s ; s = s->next) {
		ifa = s->data;
		streambuf_printf(replybuffer,"interface[%d] = %s\\%s \n", count, ifa->name.s, sockaddr_print_buf(&(ifa->local_address.addr)));
		++count;
	}
	count=0;
	for (s = initial_rtpe_config.redis_subscribed_keyspaces.head; s ; s = s->next) {
		streambuf_printf(replybuffer,"keyspace[%d] = %d \n", count, GPOINTER_TO_UINT(s->data));
		++count;
	}
	streambuf_printf(replybuffer, "b2b_url = %s\nredis-auth = %s\nredis-write-auth = %s\nrecording-dir = %s\nrecording-method = %s\n"
			"recording-format = %s\niptables-chain = %s\n", initial_rtpe_config.b2b_url, initial_rtpe_config.redis_auth,
			initial_rtpe_config.redis_write_auth, initial_rtpe_config.spooldir, initial_rtpe_config.rec_method,
			initial_rtpe_config.rec_format, initial_rtpe_config.iptables_chain);
	streambuf_printf(replybuffer,"listen-tcp = %s:%d\nlisten-udp = %s:%d\nlisten-ng = %s:%d\nlisten-cli = %s:%d\n",
			sockaddr_print_buf(&initial_rtpe_config.tcp_listen_ep.address), initial_rtpe_config.tcp_listen_ep.port,
			sockaddr_print_buf(&initial_rtpe_config.udp_listen_ep.address), initial_rtpe_config.udp_listen_ep.port,
			sockaddr_print_buf(&initial_rtpe_config.ng_listen_ep.address), initial_rtpe_config.ng_listen_ep.port,
			sockaddr_print_buf(&initial_rtpe_config.cli_listen_ep.address), initial_rtpe_config.cli_listen_ep.port);
}

static void cli_incoming_params_current(str *instr, struct streambuf *replybuffer) {
	int count = 0;
	GList *c;
	struct intf_config *ifa;

	streambuf_printf(replybuffer, "log-level = %d\ntable = %d\nmax-sessions = %d\ntimeout = %d\nsilent-timeout = %d\n"
			"final-timeout = %d\noffer-timeout = %d\n"
			"delete-delay = %d\nredis-expires = %d\ntos = %d\ncontrol-tos = %d\ngraphite-interval = %d\nredis-num-threads = %d\n"
			"homer-protocol = %d\nhomer-id = %d\nno-fallback = %d\nport-min = %d\nport-max = %d\nredis-db = %d\n"
			"redis-write-db = %d\nno-redis-required = %d\nnum-threads = %d\nxmlrpc-format = %d\nlog_format = %d\n"
			"redis_allowed_errors = %d\nredis_disable_time = %d\nredis_cmd_timeout = %d\nredis_connect_timeout = %d\n"
			"max-cpu = %.1f\n"
			"max-load = %.2f\n"
			"max-bw = %" PRIu64 "\n",
			rtpe_config.common.log_level, rtpe_config.kernel_table, rtpe_config.max_sessions, rtpe_config.timeout,
			rtpe_config.silent_timeout, rtpe_config.final_timeout, rtpe_config.offer_timeout,
			rtpe_config.delete_delay, rtpe_config.redis_expires_secs, rtpe_config.default_tos,
			rtpe_config.control_tos, rtpe_config.graphite_interval, rtpe_config.redis_num_threads, rtpe_config.homer_protocol,
			rtpe_config.homer_id, rtpe_config.no_fallback, rtpe_config.port_min, rtpe_config.port_max,
			rtpe_config.redis_db, rtpe_config.redis_write_db, rtpe_config.no_redis_required,
			rtpe_config.num_threads, rtpe_config.fmt, rtpe_config.log_format, rtpe_config.redis_allowed_errors,
			rtpe_config.redis_disable_time, rtpe_config.redis_cmd_timeout, rtpe_config.redis_connect_timeout,
			(double) rtpe_config.cpu_limit / 100,
			(double) rtpe_config.load_limit / 100,
			rtpe_config.bw_limit);

	for(c = rtpe_config.interfaces.head; c ; c = c->next) {
		ifa = c->data;
		streambuf_printf(replybuffer,"interface[%d] = %s\\%s \n", count, ifa->name.s, sockaddr_print_buf(&(ifa->local_address.addr)));
		++count;
	}
	count=0;
	for (c = rtpe_config.redis_subscribed_keyspaces.head; c ; c = c->next) {
		streambuf_printf(replybuffer,"keyspace[%d] = %d \n", count, GPOINTER_TO_UINT(c->data));
		++count;
	}
	streambuf_printf(replybuffer, "b2b_url = %s\nredis-auth = %s\nredis-write-auth = %s\nrecording-dir = %s\nrecording-method = %s\n"
			"recording-format = %s\niptables-chain = %s\n", rtpe_config.b2b_url, rtpe_config.redis_auth,
			rtpe_config.redis_write_auth, rtpe_config.spooldir, rtpe_config.rec_method,
			rtpe_config.rec_format, rtpe_config.iptables_chain);
	streambuf_printf(replybuffer,"listen-tcp = %s:%d\nlisten-udp = %s:%d\nlisten-ng = %s:%d\nlisten-cli = %s:%d\n",
			sockaddr_print_buf(&rtpe_config.tcp_listen_ep.address), rtpe_config.tcp_listen_ep.port,
			sockaddr_print_buf(&rtpe_config.udp_listen_ep.address), rtpe_config.udp_listen_ep.port,
			sockaddr_print_buf(&rtpe_config.ng_listen_ep.address), rtpe_config.ng_listen_ep.port,
			sockaddr_print_buf(&rtpe_config.cli_listen_ep.address), rtpe_config.cli_listen_ep.port);
}

static void int_diff_print_sz(long long start_param, void* current_param, size_t sz, char* param, struct streambuf *replybuffer, char* option) {
	long long cur_param;

	if (sz == sizeof(int))
		cur_param = *(int *) current_param;
	else if (sz == sizeof(long))
		cur_param = *(long *) current_param;
	else if (sz == sizeof(long long))
		cur_param = *(long long *) current_param;
	else
		abort();

	if(start_param != cur_param) {
		if (strcmp(option, "diff") == 0) {
			streambuf_printf(replybuffer, "%s: %lld => %lld\n", param, start_param, cur_param);
		} else if(strcmp(option, "revert") == 0) {
			if (sz == sizeof(int))
				*(int *) current_param = start_param;
			else if (sz == sizeof(long))
				*(long *) current_param = start_param;
			else if (sz == sizeof(long long))
				*(long long *) current_param = start_param;
		}
	}
}

#define int_diff_print(struct_member, option_string) \
	int_diff_print_sz((long long) initial_rtpe_config.struct_member, (void *) &rtpe_config.struct_member, sizeof(rtpe_config.struct_member), \
			option_string, replybuffer, option)

static void cli_incoming_diff_or_revert(struct streambuf *replybuffer, char* option) {
	int_diff_print(common.log_level, "log-level");
	int_diff_print(max_sessions, "max-sessions");
	int_diff_print(cpu_limit, "max-cpu");
	int_diff_print(load_limit, "max-load");
	int_diff_print(bw_limit, "max-bw");
	int_diff_print(timeout, "timeout");
	int_diff_print(silent_timeout, "silent-timeout");
	int_diff_print(final_timeout, "final-timeout");
	int_diff_print(control_tos, "control-tos");
	int_diff_print(redis_allowed_errors, "redis_allowed_errors");
	int_diff_print(redis_disable_time, "redis_disable_time");
	int_diff_print(redis_cmd_timeout, "redis_cmd_timeout");
	int_diff_print(redis_connect_timeout, "redis_connect_timeout-db");
}

static void cli_incoming_params_diff(str *instr, struct streambuf *replybuffer) {

	cli_incoming_diff_or_revert(replybuffer, "diff");
}

static void cli_incoming_params_revert(str *instr, struct streambuf *replybuffer) {

	cli_incoming_diff_or_revert(replybuffer, "revert");
}


static void cli_incoming_list_counters(str *instr, struct streambuf *replybuffer) {
	streambuf_printf(replybuffer, "\nCurrent per-second counters:\n\n");
	streambuf_printf(replybuffer, " Packets per second                              :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.packets));
	streambuf_printf(replybuffer, " Bytes per second                                :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.bytes));
	streambuf_printf(replybuffer, " Errors per second                               :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.errors));
}

static void cli_incoming_list_totals(str *instr, struct streambuf *replybuffer) {
	struct timeval avg, calls_dur_iv;
	u_int64_t num_sessions, min_sess_iv, max_sess_iv;
	struct request_time offer_iv, answer_iv, delete_iv;
	struct requests_ps offers_ps, answers_ps, deletes_ps;

	mutex_lock(&rtpe_totalstats.total_average_lock);
	avg = rtpe_totalstats.total_average_call_dur;
	num_sessions = rtpe_totalstats.total_managed_sess;
	mutex_unlock(&rtpe_totalstats.total_average_lock);

	streambuf_printf(replybuffer, "\nTotal statistics (does not include current running sessions):\n\n");
	streambuf_printf(replybuffer, " Uptime of rtpengine                             :%llu seconds\n", (unsigned long long)time(NULL)-rtpe_totalstats.started);
	streambuf_printf(replybuffer, " Total managed sessions                          :"UINT64F"\n", num_sessions);
	streambuf_printf(replybuffer, " Total rejected sessions                         :"UINT64F"\n", atomic64_get(&rtpe_totalstats.total_rejected_sess));
	streambuf_printf(replybuffer, " Total timed-out sessions via TIMEOUT            :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_timeout_sess));
	streambuf_printf(replybuffer, " Total timed-out sessions via SILENT_TIMEOUT     :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_silent_timeout_sess));
	streambuf_printf(replybuffer, " Total timed-out sessions via FINAL_TIMEOUT      :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_final_timeout_sess));
	streambuf_printf(replybuffer, " Total timed-out sessions via OFFER_TIMEOUT      :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_offer_timeout_sess));
	streambuf_printf(replybuffer, " Total regular terminated sessions               :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_regular_term_sess));
	streambuf_printf(replybuffer, " Total forced terminated sessions                :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_forced_term_sess));
	streambuf_printf(replybuffer, " Total relayed packets                           :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_relayed_packets));
	streambuf_printf(replybuffer, " Total relayed packet errors                     :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_relayed_errors));
	streambuf_printf(replybuffer, " Total number of streams with no relayed packets :"UINT64F"\n", atomic64_get(&rtpe_totalstats.total_nopacket_relayed_sess));
	streambuf_printf(replybuffer, " Total number of 1-way streams                   :"UINT64F"\n",atomic64_get(&rtpe_totalstats.total_oneway_stream_sess));
	streambuf_printf(replybuffer, " Average call duration                           :%ld.%06ld\n\n",avg.tv_sec,avg.tv_usec);

	mutex_lock(&rtpe_totalstats_lastinterval_lock);
	calls_dur_iv = rtpe_totalstats_lastinterval.total_calls_duration_interval;
	min_sess_iv = rtpe_totalstats_lastinterval.managed_sess_min;
	max_sess_iv = rtpe_totalstats_lastinterval.managed_sess_max;
	offer_iv = rtpe_totalstats_lastinterval.offer;
	answer_iv = rtpe_totalstats_lastinterval.answer;
	delete_iv = rtpe_totalstats_lastinterval.delete;
	offers_ps = rtpe_totalstats_lastinterval.offers_ps;
	answers_ps = rtpe_totalstats_lastinterval.answers_ps;
	deletes_ps = rtpe_totalstats_lastinterval.deletes_ps;
	mutex_unlock(&rtpe_totalstats_lastinterval_lock);

	streambuf_printf(replybuffer, "\nGraphite interval statistics (last reported values to graphite):\n");
	streambuf_printf(replybuffer, " Total calls duration                            :%ld.%06ld\n\n",calls_dur_iv.tv_sec,calls_dur_iv.tv_usec);
	streambuf_printf(replybuffer, " Min managed sessions                            :"UINT64F"\n", min_sess_iv);
	streambuf_printf(replybuffer, " Max managed sessions                            :"UINT64F"\n", max_sess_iv);
	streambuf_printf(replybuffer, " Min/Max/Avg offer processing delay              :%llu.%06llu/%llu.%06llu/%llu.%06llu sec\n",
			(unsigned long long)offer_iv.time_min.tv_sec,(unsigned long long)offer_iv.time_min.tv_usec,
			(unsigned long long)offer_iv.time_max.tv_sec,(unsigned long long)offer_iv.time_max.tv_usec,
			(unsigned long long)offer_iv.time_avg.tv_sec,(unsigned long long)offer_iv.time_avg.tv_usec);
	streambuf_printf(replybuffer, " Min/Max/Avg answer processing delay             :%llu.%06llu/%llu.%06llu/%llu.%06llu sec\n",
			(unsigned long long)answer_iv.time_min.tv_sec,(unsigned long long)answer_iv.time_min.tv_usec,
			(unsigned long long)answer_iv.time_max.tv_sec,(unsigned long long)answer_iv.time_max.tv_usec,
			(unsigned long long)answer_iv.time_avg.tv_sec,(unsigned long long)answer_iv.time_avg.tv_usec);
	streambuf_printf(replybuffer, " Min/Max/Avg delete processing delay             :%llu.%06llu/%llu.%06llu/%llu.%06llu sec\n",
			(unsigned long long)delete_iv.time_min.tv_sec,(unsigned long long)delete_iv.time_min.tv_usec,
			(unsigned long long)delete_iv.time_max.tv_sec,(unsigned long long)delete_iv.time_max.tv_usec,
			(unsigned long long)delete_iv.time_avg.tv_sec,(unsigned long long)delete_iv.time_avg.tv_usec);

	streambuf_printf(replybuffer, " Min/Max/Avg offer requests per second           :%llu/%llu/%llu per sec\n",
			(unsigned long long)offers_ps.ps_min,
			(unsigned long long)offers_ps.ps_max,
			(unsigned long long)offers_ps.ps_avg);
	streambuf_printf(replybuffer, " Min/Max/Avg answer requests per second          :%llu/%llu/%llu per sec\n",	(unsigned long long)answers_ps.ps_min,
			(unsigned long long)answers_ps.ps_max,
			(unsigned long long)answers_ps.ps_avg);
	streambuf_printf(replybuffer, " Min/Max/Avg delete requests per second          :%llu/%llu/%llu per sec\n",
			(unsigned long long)deletes_ps.ps_min,
			(unsigned long long)deletes_ps.ps_max,
			(unsigned long long)deletes_ps.ps_avg);

	streambuf_printf(replybuffer, "\n\n");

	streambuf_printf(replybuffer, "Control statistics:\n\n");
	streambuf_printf(replybuffer, " %20s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s \n",
			"Proxy", "Offer", "Answer", "Delete", "Ping", "List", "Query", "StartRec", "StopRec", "Errors", "BlkDTMF", "UnblkDTMF");

	mutex_lock(&rtpe_cngs_lock);
	GList *list = g_hash_table_get_values(rtpe_cngs_hash);

	if (!list) {
		streambuf_printf(replybuffer, "\n                  No proxies have yet tried to send data.");
	}
	for (GList *l = list; l; l = l->next) {
		struct control_ng_stats* cur = l->data;
		streambuf_printf(replybuffer, " %20s | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u \n",
				sockaddr_print_buf(&cur->proxy),
				cur->offer,
				cur->answer,
				cur->delete,
				cur->ping,
				cur->list,
				cur->query,
				cur->start_recording,
				cur->stop_recording,
				cur->errors,
				cur->block_dtmf,
				cur->unblock_dtmf);
	}
	streambuf_printf(replybuffer, "\n\n");
	mutex_unlock(&rtpe_cngs_lock);
	g_list_free(list);
}

static void cli_incoming_list_numsessions(str *instr, struct streambuf *replybuffer) {
       rwlock_lock_r(&rtpe_callhash_lock);
       streambuf_printf(replybuffer, "Current sessions own: "UINT64F"\n", g_hash_table_size(rtpe_callhash) - atomic64_get(&rtpe_stats.foreign_sessions));
       streambuf_printf(replybuffer, "Current sessions foreign: "UINT64F"\n", atomic64_get(&rtpe_stats.foreign_sessions));
       streambuf_printf(replybuffer, "Current sessions total: %i\n", g_hash_table_size(rtpe_callhash));
       rwlock_unlock_r(&rtpe_callhash_lock);
}

static void cli_incoming_list_maxsessions(str *instr, struct streambuf *replybuffer) {
	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "Maximum sessions configured on rtpengine: %d\n", rtpe_config.max_sessions);

	return ;
}
static void cli_incoming_list_maxcpu(str *instr, struct streambuf *replybuffer) {
	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "Maximum CPU usage configured on rtpengine: %.1f\n", (double) rtpe_config.cpu_limit / 100.0);

	return ;
}
static void cli_incoming_list_maxload(str *instr, struct streambuf *replybuffer) {
	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "Maximum load average configured on rtpengine: %.2f\n", (double) rtpe_config.load_limit / 100.0);

	return ;
}

static void cli_incoming_list_maxbw(str *instr, struct streambuf *replybuffer) {
	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "Maximum bandwidth configured on rtpengine: %" PRIu64 "\n",
			rtpe_config.bw_limit);

	return ;
}

static void cli_incoming_list_maxopenfiles(str *instr, struct streambuf *replybuffer) {
	struct rlimit rlim;
	pid_t pid = getpid();

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		streambuf_printf(replybuffer, "Fail getting rtpengine configured limits; cat /proc/%u/limits\n", pid);
		return ;
	}

	if (rlim.rlim_cur == RLIM_INFINITY) {
		streambuf_printf(replybuffer, "Maximum open-files configured on rtpengine: infinite; cat /proc/%u/limits\n", pid);
	} else {
		streambuf_printf(replybuffer, "Maximum open-files configured on rtpengine: %lld; cat /proc/%u/limits\n", (long long) rlim.rlim_cur, pid);
	}

	return ;
}

static void cli_incoming_list_timeout(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "TIMEOUT=%u\n", rtpe_config.timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}
static void cli_incoming_list_silenttimeout(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "SILENT_TIMEOUT=%u\n", rtpe_config.silent_timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}
static void cli_incoming_list_finaltimeout(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "FINAL_TIMEOUT=%u\n", rtpe_config.final_timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}
static void cli_incoming_list_offertimeout(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	streambuf_printf(replybuffer, "OFFER_TIMEOUT=%u\n", rtpe_config.offer_timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}

static void cli_incoming_list_callid(str *instr, struct streambuf *replybuffer) {
	struct call *c = 0;
	struct call_monologue *ml;
	struct call_media *md;
	struct packet_stream *ps;
	GList *l;
	GList *k, *o;
	struct timeval tim_result_duration;
	struct timeval now;
	char *local_addr;

	if (instr->len == 0) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	c = call_get(instr);

	if (!c) {
		streambuf_printf(replybuffer, "\nCall Id not found (%s).\n\n", instr->s);
		return;
	}

	streambuf_printf(replybuffer,
			 "\ncallid: %s\ndeletionmark: %s\ncreated: %i\nproxy: %s\ntos: %u\nlast_signal: %llu\n"
			 "redis_keyspace: %i\nforeign: %s\n\n",
			 c->callid.s, c->ml_deleted ? "yes" : "no", (int) c->created.tv_sec, c->created_from,
			 (unsigned int) c->tos, (unsigned long long) c->last_signal.tv_sec, c->redis_hosted_db,
			 IS_FOREIGN_CALL(c) ? "yes" : "no");

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;
		if (!ml->terminated.tv_sec)
			gettimeofday(&now, NULL);
		else
			now = ml->terminated;

		timeval_subtract(&tim_result_duration, &now, &ml->started);

		streambuf_printf(replybuffer, "--- Tag '" STR_FORMAT "', type: %s, label '" STR_FORMAT "', "
				"branch '" STR_FORMAT "', "
				"callduration "
				"%ld.%06ld, in dialogue with '" STR_FORMAT "'\n",
			STR_FMT(&ml->tag), get_tag_type_text(ml->tagtype),
			STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
			STR_FMT(&ml->viabranch),
			tim_result_duration.tv_sec,
			tim_result_duration.tv_usec,
			ml->active_dialogue ? ml->active_dialogue->tag.len : 6,
			ml->active_dialogue ? ml->active_dialogue->tag.s : "(none)");

		for (k = ml->medias.head; k; k = k->next) {
			md = k->data;

			const struct rtp_payload_type *rtp_pt = __rtp_stats_codec(md);

			streambuf_printf(replybuffer, "------ Media #%u (" STR_FORMAT " over %s) using ",
					md->index,
					STR_FMT(&md->type),
					md->protocol ? md->protocol->name : "(unknown)");
			if (!rtp_pt)
				streambuf_printf(replybuffer, "unknown codec\n");
			else
				streambuf_printf(replybuffer, STR_FORMAT "\n", STR_FMT(&rtp_pt->encoding_with_params));

			for (o = md->streams.head; o; o = o->next) {
				ps = o->data;

				if (PS_ISSET(ps, FALLBACK_RTCP))
					continue;

				local_addr = ps->selected_sfd ? sockaddr_print_buf(&ps->selected_sfd->socket.local.address)
					: "0.0.0.0";

				streambuf_printf(replybuffer, "-------- Port %15s:%-5u <> %15s:%-5u%s, SSRC %" PRIx32 ", "
						 "" UINT64F " p, " UINT64F " b, " UINT64F " e, " UINT64F " ts",
						 local_addr,
						 (unsigned int) (ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
						 sockaddr_print_buf(&ps->endpoint.address),
						 ps->endpoint.port,
						 (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
						 ps->ssrc_in ? ps->ssrc_in->parent->h.ssrc : 0,
						 atomic64_get(&ps->stats.packets),
						 atomic64_get(&ps->stats.bytes), atomic64_get(&ps->stats.errors),
						 atomic64_get(&ps->last_packet));
#if RE_HAS_MEASUREDELAY
				if (PS_ISSET(ps, RTP) || !PS_ISSET(ps, RTCP))
					streambuf_printf(replybuffer, ", %.9f delay_min, %.9f delay_avg, %.9f delay_max",
							 (double) ps->stats.delay_min / 1000000,
							 (double) ps->stats.delay_avg / 1000000,
							 (double) ps->stats.delay_max / 1000000);
#endif
				streambuf_printf(replybuffer, "\n");
			}
		}
	}
	streambuf_printf(replybuffer, "\n");

	rwlock_unlock_w(&c->master_lock);	// because of call_get(..)
	obj_put(c);
}

static void cli_incoming_list_sessions(str *instr, struct streambuf *replybuffer) {
	GHashTableIter iter;
	gpointer key, value;
	str *ptrkey;
	struct call *call;
	int found_own = 0, found_foreign = 0;

	static const char* LIST_ALL = "all";
	static const char* LIST_OWN = "own";
	static const char* LIST_FOREIGN = "foreign";

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	rwlock_lock_r(&rtpe_callhash_lock);

	if (g_hash_table_size(rtpe_callhash)==0) {
		streambuf_printf(replybuffer, "No sessions on this media relay.\n");
		rwlock_unlock_r(&rtpe_callhash_lock);
		return;
	}

	g_hash_table_iter_init (&iter, rtpe_callhash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		ptrkey = (str*)key;
		call = (struct call*)value;

		if (str_cmp(instr, LIST_ALL) == 0) {
			if (!call) {
				continue;
			}
		} else if (str_cmp(instr, LIST_OWN) == 0) {
			if (!call || IS_FOREIGN_CALL(call)) {
				continue;
			} else {
				found_own = 1;
			}
		} else if (str_cmp(instr, LIST_FOREIGN) == 0) {
			if (!call || !IS_FOREIGN_CALL(call)) {
				continue;
			} else {
				found_foreign = 1;
			}
		} else {
			// expect callid parameter
			break;
		}

		streambuf_printf(replybuffer, "callid: %60s | deletionmark:%4s | created:%12i | proxy:%s | redis_keyspace:%i | foreign:%s\n", ptrkey->s, call->ml_deleted?"yes":"no", (int)call->created.tv_sec, call->created_from, call->redis_hosted_db, IS_FOREIGN_CALL(call)?"yes":"no");
	}
	rwlock_unlock_r(&rtpe_callhash_lock);

	if (str_cmp(instr, LIST_ALL) == 0) {
		;
	} else if (str_cmp(instr, LIST_OWN) == 0) {
		if (!found_own) {
			streambuf_printf(replybuffer, "No own sessions on this media relay.\n");
		}
	} else if (str_cmp(instr, LIST_FOREIGN) == 0) {
		if (!found_foreign) {
			streambuf_printf(replybuffer, "No foreign sessions on this media relay.\n");
		}
	} else {
		// list session for callid
		cli_incoming_list_callid(instr, replybuffer);
	}

	return;
}

static void cli_incoming_set_maxopenfiles(str *instr, struct streambuf *replybuffer) {
	unsigned long open_files_num;
	pid_t pid;
	char *endptr;

	// limit the minimum number of open files to avoid rtpengine freeze for low open_files_num values
	unsigned long min_open_files_num = (1 << 16);

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	open_files_num = strtoul(instr->s, &endptr, 10);

	if ((errno == ERANGE && (open_files_num == ULONG_MAX)) || (errno != 0 && open_files_num == 0)) {
		streambuf_printf(replybuffer,  "Fail setting open_files to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer,  "Fail setting open_files to %s; no digists found\n", instr->s);
		return;
	} else if (open_files_num < min_open_files_num) {
		streambuf_printf(replybuffer,  "Fail setting open_files to %lu; can't set it under %lu\n", open_files_num, min_open_files_num);
		return;
	} else if (rlim(RLIMIT_NOFILE, open_files_num) == -1){
		streambuf_printf(replybuffer,  "Fail setting open_files to %lu; errno = %d\n", open_files_num, errno);
		return;
	} else {
		pid = getpid();
		streambuf_printf(replybuffer,  "Success setting open_files to %lu; cat /proc/%u/limits\n", open_files_num, pid);
	}
}

static void cli_incoming_set_maxsessions(str *instr, struct streambuf *replybuffer) {
	long maxsessions_num;
	int disabled = -1;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	maxsessions_num = strtol(instr->s, &endptr, 10);

	if ((errno == ERANGE && (maxsessions_num == LONG_MAX || maxsessions_num == LONG_MIN)) || (errno != 0 && maxsessions_num == 0)) {
		streambuf_printf(replybuffer,  "Fail setting maxsessions to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer,  "Fail setting maxsessions to %s; no digists found\n", instr->s);
		return;
	} else if (maxsessions_num < disabled) {
		streambuf_printf(replybuffer,  "Fail setting maxsessions to %ld; either positive or -1 values allowed\n", maxsessions_num);
	} else if (maxsessions_num == disabled) {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.max_sessions = maxsessions_num;
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting maxsessions to %ld; disable feature\n", maxsessions_num);
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.max_sessions = maxsessions_num;
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting maxsessions to %ld\n", maxsessions_num);
	}

	return;
}

// XXX lots of code duplication, unify those set functions
static void cli_incoming_set_maxcpu(str *instr, struct streambuf *replybuffer) {
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	double num = strtod(instr->s, &endptr);

	if ((errno == ERANGE && (num == HUGE_VAL || num == -HUGE_VAL)) || (errno != 0 && num == 0) || isnan(num) || !isfinite(num)) {
		streambuf_printf(replybuffer,  "Fail setting maxcpu to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer,  "Fail setting maxcpu to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.cpu_limit = num * 100;
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting maxcpu to %.1f\n", num);
	}

	return;
}

static void cli_incoming_set_maxload(str *instr, struct streambuf *replybuffer) {
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	double num = strtod(instr->s, &endptr);

	if ((errno == ERANGE && (num == HUGE_VAL || num == -HUGE_VAL)) || (errno != 0 && num == 0) || isnan(num) || !isfinite(num)) {
		streambuf_printf(replybuffer,  "Fail setting maxload to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer,  "Fail setting maxload to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.load_limit = num * 100;
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting maxload to %.2f\n", num);
	}

	return;
}

static void cli_incoming_set_maxbw(str *instr, struct streambuf *replybuffer) {
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	uint64_t num = strtoull(instr->s, &endptr, 10);

	if ((errno == ERANGE && (num == ULLONG_MAX)) || (errno != 0 && num == 0) ) {
		streambuf_printf(replybuffer,  "Fail setting maxbw to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer,  "Fail setting maxbw to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.bw_limit = num * 100;
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting maxbw to %" PRIu64 "\n", num);
	}

	return;
}

static void cli_incoming_set_gentimeout(str *instr, struct streambuf *replybuffer, int *conf_timeout) {
	long timeout_num;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	timeout_num = strtol(instr->s, &endptr, 10);

	if ((errno == ERANGE && (timeout_num == ULONG_MAX)) || (errno != 0 && timeout_num == 0) || timeout_num < 0 || timeout_num >= INT_MAX) {
		streambuf_printf(replybuffer,  "Fail setting timeout to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer,  "Fail setting timeout to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		*conf_timeout = (int) timeout_num;
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting timeout to %lu\n", timeout_num);
	}
}

static void cli_incoming_set_timeout(str *instr, struct streambuf *replybuffer) {
	cli_incoming_set_gentimeout(instr, replybuffer, &rtpe_config.timeout);
}
static void cli_incoming_set_silenttimeout(str *instr, struct streambuf *replybuffer) {
	cli_incoming_set_gentimeout(instr, replybuffer, &rtpe_config.silent_timeout);
}
static void cli_incoming_set_finaltimeout(str *instr, struct streambuf *replybuffer) {
	cli_incoming_set_gentimeout(instr, replybuffer, &rtpe_config.final_timeout);
}
static void cli_incoming_set_offertimeout(str *instr, struct streambuf *replybuffer) {
	cli_incoming_set_gentimeout(instr, replybuffer, &rtpe_config.offer_timeout);
}

static void cli_incoming_list(str *instr, struct streambuf *replybuffer) {
   if (str_shift(instr, 1)) {
       streambuf_printf(replybuffer, "%s\n", "More parameters required.");
       return;
   }

   cli_handler_do(cli_list_handlers, instr, replybuffer);
}

static void cli_incoming_set(str *instr, struct streambuf *replybuffer) {
	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	cli_handler_do(cli_set_handlers, instr, replybuffer);
}

static void cli_incoming_params(str *instr, struct streambuf *replybuffer) {
	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}
	cli_handler_do(cli_params_handlers, instr, replybuffer);
}

static void cli_incoming_terminate(str *instr, struct streambuf *replybuffer) {
   struct call* c=0;
   struct call_monologue *ml;
   GList *i;

   if (str_shift(instr, 1)) {
       streambuf_printf(replybuffer, "%s\n", "More parameters required.");
       return;
   }

	// --- terminate all calls
	if (!str_memcmp(instr,"all")) {
		// destroy own calls
		destroy_all_own_calls();

		// destroy foreign calls
		destroy_all_foreign_calls();

		// update cli
		ilog(LOG_INFO,"All calls terminated by operator.");
		streambuf_printf(replybuffer, "%s\n", "All calls terminated by operator.");

		return;

	// --- terminate own calls
	} else if (!str_memcmp(instr,"own")) {
		// destroy own calls
		destroy_all_own_calls();

		// update cli
		ilog(LOG_INFO,"All own calls terminated by operator.");
		streambuf_printf(replybuffer, "%s\n", "All own calls terminated by operator.");

		return;

	// --- terminate foreign calls
	} else if (!str_memcmp(instr,"foreign")) {
		// destroy foreign calls
		destroy_all_foreign_calls();

		// update cli
		ilog(LOG_INFO,"All foreign calls terminated by operator.");
		streambuf_printf(replybuffer, "%s\n", "All foreign calls terminated by operator.");

		return;
	}

   // --- terminate a dedicated call id
   c = call_get(instr);

   if (!c) {
       streambuf_printf(replybuffer, "\nCall Id not found (%s).\n\n",instr->s);
       return;
   }

   if (!c->ml_deleted) {
	   for (i = c->monologues.head; i; i = i->next) {
		   ml = i->data;
		   gettimeofday(&(ml->terminated), NULL);
		   ml->term_reason = FORCED;
	   }
   }

   streambuf_printf(replybuffer, "\nCall Id (%s) successfully terminated by operator.\n\n",instr->s);
   ilog(LOG_WARN, "Call Id (%s) successfully terminated by operator.",instr->s);

   rwlock_unlock_w(&c->master_lock);

   call_destroy(c);
   obj_put(c);
}

static void cli_incoming_ksadd(str *instr, struct streambuf *replybuffer) {
	unsigned long uint_keyspace_db;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	uint_keyspace_db = strtoul(instr->s, &endptr, 10);

	if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) || (errno != 0 && uint_keyspace_db == 0)) {
		streambuf_printf(replybuffer, "Fail adding keyspace %s to redis notifications; errono=%d\n", instr->s, errno);
	} else if (endptr == instr->s) {
		streambuf_printf(replybuffer, "Fail adding keyspace %s to redis notifications; no digists found\n", instr->s);
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		if (!g_queue_find(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db))) {
			g_queue_push_tail(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db));
			redis_notify_subscribe_action(SUBSCRIBE_KEYSPACE, uint_keyspace_db);
			streambuf_printf(replybuffer, "Success adding keyspace %lu to redis notifications.\n", uint_keyspace_db);
		} else {
			streambuf_printf(replybuffer, "Keyspace %lu is already among redis notifications.\n", uint_keyspace_db);
		}
		rwlock_unlock_w(&rtpe_config.config_lock);
	}
}

static void cli_incoming_ksrm(str *instr, struct streambuf *replybuffer) {
	GList *l; 
	unsigned long uint_keyspace_db;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	uint_keyspace_db = strtoul(instr->s, &endptr, 10);

	rwlock_lock_w(&rtpe_config.config_lock);
	if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) || (errno != 0 && uint_keyspace_db == 0)) {
		streambuf_printf(replybuffer, "Fail removing keyspace %s to redis notifications; errono=%d\n", instr->s, errno);
        } else if (endptr == instr->s) {
                streambuf_printf(replybuffer, "Fail removing keyspace %s to redis notifications; no digists found\n", instr->s);
	} else if ((l = g_queue_find(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db)))) {
		// remove this keyspace
		redis_notify_subscribe_action(UNSUBSCRIBE_KEYSPACE, uint_keyspace_db);
		g_queue_remove(&rtpe_config.redis_subscribed_keyspaces, l->data);
		streambuf_printf(replybuffer, "Successfully unsubscribed from keyspace %lu.\n", uint_keyspace_db);

		// destroy foreign calls for this keyspace
		destroy_keyspace_foreign_calls(uint_keyspace_db);

		// update cli
		streambuf_printf(replybuffer, "Successfully removed all foreign calls for keyspace %lu.\n", uint_keyspace_db);
	} else {
		streambuf_printf(replybuffer, "Keyspace %lu is not among redis notifications.\n", uint_keyspace_db);
	}
	rwlock_unlock_w(&rtpe_config.config_lock);

}

static void cli_incoming_kslist(str *instr, struct streambuf *replybuffer) {
	GList *l;

	streambuf_printf(replybuffer,  "\nSubscribed-on keyspaces:\n");
    
	rwlock_lock_r(&rtpe_config.config_lock);
	for (l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
		streambuf_printf(replybuffer,  "%u ", GPOINTER_TO_UINT(l->data));
	}
	rwlock_unlock_r(&rtpe_config.config_lock);

	streambuf_printf(replybuffer, "\n");
}

static void cli_incoming(struct streambuf_stream *s) {
   ilog(LOG_INFO, "New cli connection from %s", s->addr);
}

static void cli_stream_readable(struct streambuf_stream *s) {
   static const int MAXINPUT = 1024;
   char *inbuf;
   str instr;

   inbuf = streambuf_getline(s->inbuf);
   if (!inbuf) {
       if (streambuf_bufsize(s->inbuf) > MAXINPUT) {
           ilog(LOG_INFO, "Buffer length exceeded in CLI connection from %s", s->addr);
           streambuf_stream_close(s);
       }
       return;
   }

   ilog(LOG_INFO, "Got CLI command: %s%s%s", FMT_M(inbuf));
   str_init(&instr, inbuf);

   cli_handler_do(cli_top_handlers, &instr, s->outbuf);

   free(inbuf);
   streambuf_stream_shutdown(s);
   log_info_clear();
}

struct cli *cli_new(struct poller *p, endpoint_t *ep) {
   struct cli *c;

   if (!p)
       return NULL;

   c = obj_alloc0("cli", sizeof(*c), NULL);

   if (streambuf_listener_init(&c->listeners[0], p, ep,
            cli_incoming, cli_stream_readable,
            NULL,
            NULL,
            &c->obj))
   {
      ilog(LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
      goto fail;
   }
   if (ipv46_any_convert(ep)) {
      if (streambuf_listener_init(&c->listeners[1], p, ep,
               cli_incoming, cli_stream_readable,
               NULL,
               NULL,
               &c->obj))
      {
         ilog(LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
         goto fail;
      }
   }

   c->poller = p;

   obj_put(c);
   return c;

fail:
   // XXX streambuf_listener_close ...
   obj_put(c);
   return NULL;
}

static void cli_incoming_list_loglevel(str *instr, struct streambuf *replybuffer) {
	streambuf_printf(replybuffer, "%i\n", get_log_level());
}
static void cli_incoming_set_loglevel(str *instr, struct streambuf *replybuffer) {
	int nl;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	nl = atoi(instr->s);
	if (nl < 1 || nl > 7) {
		streambuf_printf(replybuffer, "Invalid log level '%s', must be number between 1 and 7\n",
				instr->s);
		return;
	}

	g_atomic_int_set(&rtpe_config.common.log_level, nl);
	streambuf_printf(replybuffer,  "Success setting loglevel to %i\n", nl);
}

static void cli_incoming_list_redisallowederrors(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);
	streambuf_printf(replybuffer, "%d\n", rtpe_config.redis_allowed_errors);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_redisallowederrors(str *instr, struct streambuf *replybuffer) {
	long allowed_errors;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	allowed_errors = strtol(instr->s, &endptr, 10);

	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.redis_allowed_errors = allowed_errors;
	rwlock_unlock_w(&rtpe_config.config_lock);

	streambuf_printf(replybuffer,  "Success setting redis-allowed-errors to %ld\n", allowed_errors);
}

static void cli_incoming_list_redisdisabletime(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);
	streambuf_printf(replybuffer, "%d\n", rtpe_config.redis_disable_time);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_redisdisabletime(str *instr, struct streambuf *replybuffer) {
	long seconds;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	seconds = strtol(instr->s, &endptr, 10);
	if (seconds < 0) {
		streambuf_printf(replybuffer,  "Invalid redis-disable-time value %ld, must be >= 0\n", seconds);
		return;
	}

	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.redis_disable_time = seconds;
	rwlock_unlock_w(&rtpe_config.config_lock);

	streambuf_printf(replybuffer,  "Success setting redis-disable-time to %ld\n", seconds);
}

static void cli_incoming_list_redisconnecttimeout(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);
	streambuf_printf(replybuffer, "%d\n", rtpe_config.redis_connect_timeout);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_redisconnecttimeout(str *instr, struct streambuf *replybuffer) {
	long timeout;
	char *endptr;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return ;
	}

	errno = 0;
	timeout = strtol(instr->s, &endptr, 10);
	if (timeout <= 0) {
		streambuf_printf(replybuffer,  "Invalid redis-connect-timeout value %ld, must be > 0\n", timeout);
		return;
	}
	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.redis_connect_timeout = timeout;
	rwlock_unlock_w(&rtpe_config.config_lock);
	streambuf_printf(replybuffer,  "Success setting redis-connect-timeout to %ld\n", timeout);
}

static void cli_incoming_list_rediscmdtimeout(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);
	streambuf_printf(replybuffer, "%d\n", rtpe_config.redis_cmd_timeout);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_rediscmdtimeout(str *instr, struct streambuf *replybuffer) {
	long timeout;
	char *endptr;
	int fail = 0;


	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	timeout = strtol(instr->s, &endptr, 10);
	if (timeout < 0) {
		streambuf_printf(replybuffer, "Invalid redis-cmd-timeout value %ld, must be >= 0\n", timeout);
		return;
	}

	rwlock_lock_w(&rtpe_config.config_lock);
	if (rtpe_config.redis_cmd_timeout == timeout) {
		rwlock_unlock_w(&rtpe_config.config_lock);
		streambuf_printf(replybuffer,  "Success setting redis-cmd-timeout to %ld\n", timeout);
		return;
	}
	rtpe_config.redis_cmd_timeout = timeout;
	rwlock_unlock_w(&rtpe_config.config_lock);


	if (timeout == 0) {
		streambuf_printf(replybuffer, "Warning: Setting redis-cmd-timeout to 0 (no timeout) will require a redis reconnect\n");
		if (rtpe_redis && redis_reconnect(rtpe_redis)) {
			streambuf_printf(replybuffer, "Failed reconnecting to redis\n");
			fail = 1;
		}
		if (rtpe_redis && redis_reconnect(rtpe_redis_write)) {
			streambuf_printf(replybuffer, "Failed reconnecting to redis-write\n");
			fail = 1;
		}
		if (rtpe_redis && redis_reconnect(rtpe_redis_notify)) {
			streambuf_printf(replybuffer, "Failed reconnecting to redis-notify\n");
			fail = 1;
		}
	} else {
		if (rtpe_redis && redis_set_timeout(rtpe_redis, timeout)) {
			streambuf_printf(replybuffer, "Failed setting redis-cmd-timeout for redis %ld\n", timeout);
			fail = 1;
		}
		if (rtpe_redis_write && redis_set_timeout(rtpe_redis_write, timeout)) {
			streambuf_printf(replybuffer, "Failed setting redis-cmd-timeout for redis-write %ld\n", timeout);
			fail = 1;
		}
		if (rtpe_redis_notify && redis_set_timeout(rtpe_redis_notify, timeout)) {
			streambuf_printf(replybuffer, "Failed setting redis-cmd-timeout for redis-notify %ld\n", timeout);
			fail = 1;
		}
	}

	if (!fail)
		streambuf_printf(replybuffer,  "Success setting redis-cmd-timeout to %ld\n", timeout);
}

static void cli_incoming_list_interfaces(str *instr, struct streambuf *replybuffer) {
	for (GList *l = all_local_interfaces.head; l; l = l->next) {
		struct local_intf *lif = l->data;
		// only show first-order interface entries: socket families must match
		if (lif->logical->preferred_family != lif->spec->local_address.addr.family)
			continue;
		streambuf_printf(replybuffer, "Interface '%s' address '%s' (%s)\n", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr),
				lif->spec->local_address.addr.family->name);
		streambuf_printf(replybuffer, " Port range: %5u - %5u\n",
				lif->spec->port_pool.min,
				lif->spec->port_pool.max);
		unsigned int f = g_atomic_int_get(&lif->spec->port_pool.free_ports);
		unsigned int l = g_atomic_int_get(&lif->spec->port_pool.last_used);
		unsigned int r = lif->spec->port_pool.max - lif->spec->port_pool.min + 1;
		streambuf_printf(replybuffer, " Ports used: %5u / %5u (%5.1f%%)\n",
				r - f, r, (double) (r - f) * 100.0 / r);
		streambuf_printf(replybuffer, " Last port used: %5u\n",
				l);
	}
}

static void cli_incoming_list_controltos(str *instr, struct streambuf *replybuffer) {
	rwlock_lock_r(&rtpe_config.config_lock);
	streambuf_printf(replybuffer, "%d\n", rtpe_config.control_tos);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_controltos(str *instr, struct streambuf *replybuffer) {
	long tos;
	char *endptr;
	int i;

	if (str_shift(instr, 1)) {
		streambuf_printf(replybuffer, "%s\n", "More parameters required.");
		return ;
	}

	errno = 0;
	tos = strtol(instr->s, &endptr, 10);
	if (tos < 0 || tos > 255) {
		streambuf_printf(replybuffer,  "Invalid control-tos value %ld, must be between 0 and 255\n", tos);
		return;
	}

	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.control_tos = tos;
	rwlock_unlock_w(&rtpe_config.config_lock);

	for (i=0; i < G_N_ELEMENTS(rtpe_control_ng->udp_listeners); i++) {
		if (rtpe_control_ng->udp_listeners[i].fd != -1) {
			set_tos(&rtpe_control_ng->udp_listeners[i],tos);
		}
	}

	streambuf_printf(replybuffer,  "Success setting redis-connect-timeout to %ld\n", tos);
}
