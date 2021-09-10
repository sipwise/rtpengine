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
#include <stdbool.h>

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
#include "codec.h"

#include "rtpengine_config.h"


typedef void (*cli_handler_func)(str *, struct cli_writer *);
typedef struct {
	const char *cmd;
	cli_handler_func handler;
} cli_handler_t;

static void cli_incoming_list(str *instr, struct cli_writer *cw);
static void cli_incoming_set(str *instr, struct cli_writer *cw);
static void cli_incoming_params(str *instr, struct cli_writer *cw);
static void cli_incoming_terminate(str *instr, struct cli_writer *cw);
static void cli_incoming_ksadd(str *instr, struct cli_writer *cw);
static void cli_incoming_ksrm(str *instr, struct cli_writer *cw);
static void cli_incoming_kslist(str *instr, struct cli_writer *cw);
static void cli_incoming_active(str *instr, struct cli_writer *cw);
static void cli_incoming_standby(str *instr, struct cli_writer *cw);
static void cli_incoming_debug(str *instr, struct cli_writer *cw);
static void cli_incoming_call(str *instr, struct cli_writer *cw);

static void cli_incoming_set_maxopenfiles(str *instr, struct cli_writer *cw);
static void cli_incoming_set_maxsessions(str *instr, struct cli_writer *cw);
static void cli_incoming_set_maxcpu(str *instr, struct cli_writer *cw);
static void cli_incoming_set_maxload(str *instr, struct cli_writer *cw);
static void cli_incoming_set_maxbw(str *instr, struct cli_writer *cw);
static void cli_incoming_set_timeout(str *instr, struct cli_writer *cw);
static void cli_incoming_set_silenttimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_set_offertimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_set_finaltimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_set_loglevel(str *instr, struct cli_writer *cw);
static void cli_incoming_set_redisallowederrors(str *instr, struct cli_writer *cw);
static void cli_incoming_set_redisdisabletime(str *instr, struct cli_writer *cw);
static void cli_incoming_set_redisconnecttimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_set_rediscmdtimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_set_controltos(str *instr, struct cli_writer *cw);
static void cli_incoming_set_deletedelay(str *instr, struct cli_writer *cw);

static void cli_incoming_params_start(str *instr, struct cli_writer *cw);
static void cli_incoming_params_current(str *instr, struct cli_writer *cw);
static void cli_incoming_params_diff(str *instr, struct cli_writer *cw);
static void cli_incoming_params_revert(str *instr, struct cli_writer *cw);

static void cli_incoming_list_numsessions(str *instr, struct cli_writer *cw);
static void cli_incoming_list_maxsessions(str *instr, struct cli_writer *cw);
static void cli_incoming_list_maxcpu(str *instr, struct cli_writer *cw);
static void cli_incoming_list_maxload(str *instr, struct cli_writer *cw);
static void cli_incoming_list_maxbw(str *instr, struct cli_writer *cw);
static void cli_incoming_list_maxopenfiles(str *instr, struct cli_writer *cw);
static void cli_incoming_list_totals(str *instr, struct cli_writer *cw);
static void cli_incoming_list_counters(str *instr, struct cli_writer *cw);
static void cli_incoming_list_sessions(str *instr, struct cli_writer *cw);
static void cli_incoming_list_timeout(str *instr, struct cli_writer *cw);
static void cli_incoming_list_silenttimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_list_offertimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_list_finaltimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_list_loglevel(str *instr, struct cli_writer *cw);
static void cli_incoming_list_loglevels(str *instr, struct cli_writer *cw);
static void cli_incoming_list_redisallowederrors(str *instr, struct cli_writer *cw);
static void cli_incoming_list_redisdisabletime(str *instr, struct cli_writer *cw);
static void cli_incoming_list_redisconnecttimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_list_rediscmdtimeout(str *instr, struct cli_writer *cw);
static void cli_incoming_list_controltos(str *instr, struct cli_writer *cw);
static void cli_incoming_list_deletedelay(str *instr, struct cli_writer *cw);
static void cli_incoming_list_interfaces(str *instr, struct cli_writer *cw);
static void cli_incoming_list_jsonstats(str *instr, struct cli_writer *cw);
static void cli_incoming_list_transcoders(str *instr, struct cli_writer *cw);

static void cli_incoming_call_info(str *instr, struct cli_writer *cw);
static void cli_incoming_call_terminate(str *instr, struct cli_writer *cw);
static void cli_incoming_call_debug(str *instr, struct cli_writer *cw);
static void cli_incoming_call_tag(str *instr, struct cli_writer *cw);

static void cli_incoming_tag_info(str *instr, struct cli_writer *cw);

static const cli_handler_t cli_top_handlers[] = {
	{ "list",		cli_incoming_list		},
	{ "terminate",		cli_incoming_terminate		},
	{ "set",		cli_incoming_set		},
	{ "get",		cli_incoming_list		},
	{ "params",		cli_incoming_params		},
	{ "ksadd",		cli_incoming_ksadd		},
	{ "ksrm",		cli_incoming_ksrm		},
	{ "kslist",		cli_incoming_kslist		},
	{ "active",		cli_incoming_active		},
	{ "standby",		cli_incoming_standby		},
	{ "debug",		cli_incoming_debug		},
	{ "call",		cli_incoming_call 		},
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
	{ "deletedelay",		cli_incoming_set_deletedelay 		},
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
	{ "loglevels",			cli_incoming_list_loglevels		},
	{ "loglevel",			cli_incoming_list_loglevel		},
	{ "redisallowederrors",		cli_incoming_list_redisallowederrors	},
	{ "redisdisabletime",		cli_incoming_list_redisdisabletime	},
	{ "redisconnecttimeout",	cli_incoming_list_redisconnecttimeout	},
	{ "rediscmdtimeout",		cli_incoming_list_rediscmdtimeout	},
	{ "controltos",			cli_incoming_list_controltos		},
	{ "deletedelay", 		cli_incoming_list_deletedelay 		},
	{ "interfaces",			cli_incoming_list_interfaces		},
	{ "jsonstats",			cli_incoming_list_jsonstats		},
	{ "transcoders",		cli_incoming_list_transcoders		},
	{ NULL, },
};
static const cli_handler_t cli_call_handlers[] = {
	{ "info",			cli_incoming_call_info			},
	{ "terminate",			cli_incoming_call_terminate		},
	{ "debug",			cli_incoming_call_debug			},
	{ "tag",			cli_incoming_call_tag			},
	{ NULL, },
};
static const cli_handler_t cli_tag_handlers[] = {
	{ "info",			cli_incoming_tag_info			},
	{ NULL, },
};
static const cli_handler_t cli_params_handlers[] = {
	{ "start",	cli_incoming_params_start	},
	{ "current",	cli_incoming_params_current	},
	{ "diff",	cli_incoming_params_diff	},
	{ "revert",	cli_incoming_params_revert	},
	{ NULL, },
};


static void cli_list_call_info(struct cli_writer *cw, struct call *c);
static void cli_list_tag_info(struct cli_writer *cw, struct call_monologue *ml);



static void cli_handler_do(const cli_handler_t *handlers, str *instr,
		struct cli_writer *cw)
{
	const cli_handler_t *h;

	if (!str_cmp(instr, "help")) {
		cw->cw_printf(cw, "Available sub-commands at this level:\n");
		for (h = handlers; h->cmd; h++)
			cw->cw_printf(cw, "\t%s\n", h->cmd);
		return;
	}

	for (h = handlers; h->cmd; h++) {
		if (str_shift_cmp(instr, h->cmd))
			continue;
		h->handler(instr, cw);
		return;
	}

	cw->cw_printf(cw, "%s:" STR_FORMAT "\n", "Unknown or incomplete command:", STR_FMT(instr));
}

static void destroy_own_foreign_calls(bool foreign_call, unsigned int uint_keyspace_db) {
	struct call *c = NULL;
	struct call_monologue *ml = NULL;
	GQueue call_list = G_QUEUE_INIT;
	GList *i;

	ITERATE_CALL_LIST_START(CALL_ITERATOR_MAIN, c);
		// match foreign_call flag
		if (foreign_call && !IS_FOREIGN_CALL(c))
			goto next;
		if (!foreign_call && IS_FOREIGN_CALL(c))
			goto next;

		// match uint_keyspace_db, if some given
		if ((uint_keyspace_db != UNDEFINED) && !(uint_keyspace_db == c->redis_hosted_db))
			goto next;
		
		// increase ref counter
		obj_get(c);

		// save call reference
		g_queue_push_tail(&call_list, c);
next:;
	ITERATE_CALL_LIST_NEXT_END(c);

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
	destroy_own_foreign_calls(true, UNDEFINED);
}

static void destroy_all_own_calls(void) {
	destroy_own_foreign_calls(false, UNDEFINED);
}

static void destroy_keyspace_foreign_calls(unsigned int uint_keyspace_db) {
	destroy_own_foreign_calls(true, uint_keyspace_db);
}

static void cli_incoming_params_start(str *instr, struct cli_writer *cw) {
	int count = 0;
	GList *s;
	struct intf_config *ifa;

	for (unsigned int i = 0; i < num_log_levels; i++)
		cw->cw_printf(cw, "log-level-%s = %d\n",
				log_level_names[i],
				g_atomic_int_get(&initial_rtpe_config.common.log_levels[i]));

	cw->cw_printf(cw, "table = %d\nmax-sessions = %d\ntimeout = %d\nsilent-timeout = %d\n"
			"final-timeout = %d\noffer-timeout = %d\n"
			"delete-delay = %d\nredis-expires = %d\ntos = %d\ncontrol-tos = %d\ngraphite-interval = %d\nredis-num-threads = %d\n"
			"homer-protocol = %d\nhomer-id = %d\nno-fallback = %d\nport-min = %d\nport-max = %d\nredis = %s:%d/%d\n"
			"redis-write = %s:%d/%d\nno-redis-required = %d\nnum-threads = %d\nxmlrpc-format = %d\nlog_format = %d\n"
			"redis_allowed_errors = %d\nredis_disable_time = %d\nredis_cmd_timeout = %d\nredis_connect_timeout = %d\n"
			"max-cpu = %.1f\n"
			"max-load = %.2f\n"
			"max-bandwidth = %" PRIu64 "\n",
			initial_rtpe_config.kernel_table, initial_rtpe_config.max_sessions,
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
		cw->cw_printf(cw,"interface[%d] = %s\\%s \n", count, ifa->name.s, sockaddr_print_buf(&(ifa->local_address.addr)));
		++count;
	}
	count=0;
	for (s = initial_rtpe_config.redis_subscribed_keyspaces.head; s ; s = s->next) {
		cw->cw_printf(cw,"keyspace[%d] = %d \n", count, GPOINTER_TO_UINT(s->data));
		++count;
	}
	cw->cw_printf(cw, "b2b_url = %s\nredis-auth = %s\nredis-write-auth = %s\nrecording-dir = %s\nrecording-method = %s\n"
			"recording-format = %s\niptables-chain = %s\n", initial_rtpe_config.b2b_url, initial_rtpe_config.redis_auth,
			initial_rtpe_config.redis_write_auth, initial_rtpe_config.spooldir, initial_rtpe_config.rec_method,
			initial_rtpe_config.rec_format, initial_rtpe_config.iptables_chain);
	cw->cw_printf(cw,"listen-tcp = %s:%d\nlisten-udp = %s:%d\nlisten-ng = %s:%d\nlisten-cli = %s:%d\n",
			sockaddr_print_buf(&initial_rtpe_config.tcp_listen_ep.address), initial_rtpe_config.tcp_listen_ep.port,
			sockaddr_print_buf(&initial_rtpe_config.udp_listen_ep.address), initial_rtpe_config.udp_listen_ep.port,
			sockaddr_print_buf(&initial_rtpe_config.ng_listen_ep.address), initial_rtpe_config.ng_listen_ep.port,
			sockaddr_print_buf(&initial_rtpe_config.cli_listen_ep.address), initial_rtpe_config.cli_listen_ep.port);
}

static void cli_incoming_params_current(str *instr, struct cli_writer *cw) {
	int count = 0;
	GList *c;
	struct intf_config *ifa;

	for (unsigned int i = 0; i < num_log_levels; i++)
		cw->cw_printf(cw, "log-level-%s = %d\n",
				log_level_names[i],
				g_atomic_int_get(&rtpe_config.common.log_levels[i]));

	cw->cw_printf(cw, "table = %d\nmax-sessions = %d\ntimeout = %d\nsilent-timeout = %d\n"
			"final-timeout = %d\noffer-timeout = %d\n"
			"delete-delay = %d\nredis-expires = %d\ntos = %d\ncontrol-tos = %d\ngraphite-interval = %d\nredis-num-threads = %d\n"
			"homer-protocol = %d\nhomer-id = %d\nno-fallback = %d\nport-min = %d\nport-max = %d\nredis-db = %d\n"
			"redis-write-db = %d\nno-redis-required = %d\nnum-threads = %d\nxmlrpc-format = %d\nlog_format = %d\n"
			"redis_allowed_errors = %d\nredis_disable_time = %d\nredis_cmd_timeout = %d\nredis_connect_timeout = %d\n"
			"max-cpu = %.1f\n"
			"max-load = %.2f\n"
			"max-bw = %" PRIu64 "\n",
			rtpe_config.kernel_table, rtpe_config.max_sessions, rtpe_config.timeout,
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
		cw->cw_printf(cw,"interface[%d] = %s\\%s \n", count, ifa->name.s, sockaddr_print_buf(&(ifa->local_address.addr)));
		++count;
	}
	count=0;
	for (c = rtpe_config.redis_subscribed_keyspaces.head; c ; c = c->next) {
		cw->cw_printf(cw,"keyspace[%d] = %d \n", count, GPOINTER_TO_UINT(c->data));
		++count;
	}
	cw->cw_printf(cw, "b2b_url = %s\nredis-auth = %s\nredis-write-auth = %s\nrecording-dir = %s\nrecording-method = %s\n"
			"recording-format = %s\niptables-chain = %s\n", rtpe_config.b2b_url, rtpe_config.redis_auth,
			rtpe_config.redis_write_auth, rtpe_config.spooldir, rtpe_config.rec_method,
			rtpe_config.rec_format, rtpe_config.iptables_chain);
	cw->cw_printf(cw,"listen-tcp = %s:%d\nlisten-udp = %s:%d\nlisten-ng = %s:%d\nlisten-cli = %s:%d\n",
			sockaddr_print_buf(&rtpe_config.tcp_listen_ep.address), rtpe_config.tcp_listen_ep.port,
			sockaddr_print_buf(&rtpe_config.udp_listen_ep.address), rtpe_config.udp_listen_ep.port,
			sockaddr_print_buf(&rtpe_config.ng_listen_ep.address), rtpe_config.ng_listen_ep.port,
			sockaddr_print_buf(&rtpe_config.cli_listen_ep.address), rtpe_config.cli_listen_ep.port);
}

#define int_diff_print(struct_member, option_string) \
	if (initial_rtpe_config.struct_member != rtpe_config.struct_member) { \
		if (strcmp(option, "diff") == 0) \
			cw->cw_printf(cw, "%s: %lld => %lld\n", option_string, \
			              (long long)initial_rtpe_config.struct_member, \
			              (long long)rtpe_config.struct_member); \
		else if (strcmp(option, "revert") == 0) \
			rtpe_config.struct_member = initial_rtpe_config.struct_member; \
	}

static void cli_incoming_diff_or_revert(struct cli_writer *cw, char* option) {
#define ll(system, descr) \
	int_diff_print(common.log_levels[log_level_index_ ## system], "log-level-" #system);
#include "loglevels.h"
#undef ll

	rwlock_lock_w(&rtpe_config.config_lock);
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
	rwlock_unlock_w(&rtpe_config.config_lock);
}

static void cli_incoming_params_diff(str *instr, struct cli_writer *cw) {

	cli_incoming_diff_or_revert(cw, "diff");
}

static void cli_incoming_params_revert(str *instr, struct cli_writer *cw) {

	cli_incoming_diff_or_revert(cw, "revert");
}


static void cli_incoming_list_counters(str *instr, struct cli_writer *cw) {
	cw->cw_printf(cw, "\nCurrent per-second counters:\n\n");
	cw->cw_printf(cw, " Packets per second (userspace)                  :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.packets_user));
	cw->cw_printf(cw, " Bytes per second (userspace)                    :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.bytes_user));
	cw->cw_printf(cw, " Errors per second (userspace)                   :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.errors_user));
	cw->cw_printf(cw, " Packets per second (kernel)                     :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.packets_kernel));
	cw->cw_printf(cw, " Bytes per second (kernel)                       :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.bytes_kernel));
	cw->cw_printf(cw, " Errors per second (kernel)                      :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.errors_kernel));
	cw->cw_printf(cw, " Packets per second (total)                      :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.packets_user) +
			atomic64_get(&rtpe_stats.intv.packets_kernel));
	cw->cw_printf(cw, " Bytes per second (total)                        :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.bytes_user) +
			atomic64_get(&rtpe_stats.intv.bytes_kernel));
	cw->cw_printf(cw, " Errors per second (total)                       :%" PRIu64 "\n",
			atomic64_get(&rtpe_stats.intv.errors_user) +
			atomic64_get(&rtpe_stats.intv.errors_kernel));
}

static void cli_incoming_list_totals(str *instr, struct cli_writer *cw) {
	AUTO_CLEANUP_INIT(GQueue *metrics, statistics_free_metrics, statistics_gather_metrics());

	for (GList *l = metrics->head; l; l = l->next) {
		struct stats_metric *m = l->data;
		if (!m->descr)
			continue;
		if (m->value_long) {
			if (!strcmp(m->descr, ""))
				cw->cw_printf(cw, "%s\n", m->value_long);
			else
				cw->cw_printf(cw, " %-48s:%s\n", m->descr, m->value_long);
		}
		else
			cw->cw_printf(cw, "%s\n", m->descr);
	}
}

static void cli_incoming_list_numsessions(str *instr, struct cli_writer *cw) {
       rwlock_lock_r(&rtpe_callhash_lock);
       cw->cw_printf(cw, "Current sessions own: "UINT64F"\n", g_hash_table_size(rtpe_callhash) - atomic64_get(&rtpe_stats_gauge.foreign_sessions));
       cw->cw_printf(cw, "Current sessions foreign: "UINT64F"\n", atomic64_get(&rtpe_stats_gauge.foreign_sessions));
       cw->cw_printf(cw, "Current sessions total: %i\n", g_hash_table_size(rtpe_callhash));
       rwlock_unlock_r(&rtpe_callhash_lock);
       cw->cw_printf(cw, "Current transcoded media: "UINT64F"\n", atomic64_get(&rtpe_stats_gauge.transcoded_media));
       cw->cw_printf(cw, "Current sessions ipv4 only media: " UINT64F "\n",
		       atomic64_get(&rtpe_stats_gauge.ipv4_sessions));
       cw->cw_printf(cw, "Current sessions ipv6 only media: " UINT64F "\n",
		       atomic64_get(&rtpe_stats_gauge.ipv6_sessions));
       cw->cw_printf(cw, "Current sessions ip mixed  media: " UINT64F "\n",
		       atomic64_get(&rtpe_stats_gauge.mixed_sessions));
}

static void cli_incoming_list_maxsessions(str *instr, struct cli_writer *cw) {
	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "Maximum sessions configured on rtpengine: %d\n", rtpe_config.max_sessions);

	return ;
}
static void cli_incoming_list_maxcpu(str *instr, struct cli_writer *cw) {
	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "Maximum CPU usage configured on rtpengine: %.1f\n", (double) rtpe_config.cpu_limit / 100.0);

	return ;
}
static void cli_incoming_list_maxload(str *instr, struct cli_writer *cw) {
	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "Maximum load average configured on rtpengine: %.2f\n", (double) rtpe_config.load_limit / 100.0);

	return ;
}

static void cli_incoming_list_maxbw(str *instr, struct cli_writer *cw) {
	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "Maximum bandwidth configured on rtpengine: %" PRIu64 "\n",
			rtpe_config.bw_limit);

	return ;
}

static void cli_incoming_list_maxopenfiles(str *instr, struct cli_writer *cw) {
	struct rlimit rlim;
	pid_t pid = getpid();

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		cw->cw_printf(cw, "Fail getting rtpengine configured limits; cat /proc/%u/limits\n", pid);
		return ;
	}

	if (rlim.rlim_cur == RLIM_INFINITY) {
		cw->cw_printf(cw, "Maximum open-files configured on rtpengine: infinite; cat /proc/%u/limits\n", pid);
	} else {
		cw->cw_printf(cw, "Maximum open-files configured on rtpengine: %lld; cat /proc/%u/limits\n", (long long) rlim.rlim_cur, pid);
	}

	return ;
}

static void cli_incoming_list_timeout(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "TIMEOUT=%u\n", rtpe_config.timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}
static void cli_incoming_list_silenttimeout(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "SILENT_TIMEOUT=%u\n", rtpe_config.silent_timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}
static void cli_incoming_list_finaltimeout(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "FINAL_TIMEOUT=%u\n", rtpe_config.final_timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}
static void cli_incoming_list_offertimeout(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);

	/* don't lock anything while reading the value */
	cw->cw_printf(cw, "OFFER_TIMEOUT=%u\n", rtpe_config.offer_timeout);

	rwlock_unlock_r(&rtpe_config.config_lock);

	return ;
}

static void cli_incoming_list_callid(str *instr, struct cli_writer *cw) {
	struct call *c = 0;

	if (instr->len == 0) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	c = call_get(instr);

	if (!c) {
		cw->cw_printf(cw, "\nCall ID not found (" STR_FORMAT ").\n\n", STR_FMT(instr));
		return;
	}

	cli_list_call_info(cw, c);

	rwlock_unlock_w(&c->master_lock);	// because of call_get(..)
	obj_put(c);
}


static void cli_list_call_info(struct cli_writer *cw, struct call *c) {
	struct call_monologue *ml;
	GList *l;

	cw->cw_printf(cw,
			 "\ncallid: %s\ndeletionmark: %s\ncreated: %i\nproxy: %s\ntos: %u\nlast_signal: %llu\n"
			 "redis_keyspace: %i\nforeign: %s\n\n",
			 c->callid.s, c->ml_deleted ? "yes" : "no", (int) c->created.tv_sec, c->created_from,
			 (unsigned int) c->tos, (unsigned long long) c->last_signal, c->redis_hosted_db,
			 IS_FOREIGN_CALL(c) ? "yes" : "no");

	for (l = c->monologues.head; l; l = l->next) {
		ml = l->data;
		cli_list_tag_info(cw, ml);
	}
	cw->cw_printf(cw, "\n");
}


static void cli_list_tag_info(struct cli_writer *cw, struct call_monologue *ml) {
	struct call_media *md;
	struct packet_stream *ps;
	struct timeval tim_result_duration;
	struct timeval now;
	char *local_addr;

	if (!ml->terminated.tv_sec)
		gettimeofday(&now, NULL);
	else
		now = ml->terminated;

	timeval_subtract(&tim_result_duration, &now, &ml->started);

	cw->cw_printf(cw, "--- Tag '" STR_FORMAT "', type: %s, label '" STR_FORMAT "', "
			"branch '" STR_FORMAT "', "
			"callduration "
			"%" TIME_T_INT_FMT ".%06" TIME_T_INT_FMT "\n",
		STR_FMT(&ml->tag), get_tag_type_text(ml->tagtype),
		STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY),
		STR_FMT(&ml->viabranch),
		tim_result_duration.tv_sec,
		tim_result_duration.tv_usec);

	for (GList *sub = ml->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		struct call_monologue *csm = cs->monologue;
		cw->cw_printf(cw, "---     subscribed to '" STR_FORMAT_M "'\n",
				STR_FMT_M(&csm->tag));
	}
	for (GList *sub = ml->subscriptions.head; sub; sub = sub->next) {
		struct call_subscription *cs = sub->data;
		struct call_monologue *csm = cs->monologue;
		cw->cw_printf(cw, "---     subscription of '" STR_FORMAT_M "'\n",
				STR_FMT_M(&csm->tag));
	}

	for (GList *k = ml->medias.head; k; k = k->next) {
		md = k->data;

		const struct rtp_payload_type *rtp_pt = __rtp_stats_codec(md);

		cw->cw_printf(cw, "------ Media #%u (" STR_FORMAT " over %s) using ",
				md->index,
				STR_FMT(&md->type),
				md->protocol ? md->protocol->name : "(unknown)");
		if (!rtp_pt)
			cw->cw_printf(cw, "unknown codec\n");
		else
			cw->cw_printf(cw, STR_FORMAT "\n", STR_FMT(&rtp_pt->encoding_with_params));

		for (GList *o = md->streams.head; o; o = o->next) {
			ps = o->data;

			if (PS_ISSET(ps, FALLBACK_RTCP))
				continue;

			local_addr = ps->selected_sfd ? sockaddr_print_buf(&ps->selected_sfd->socket.local.address)
				: "0.0.0.0";

			cw->cw_printf(cw, "-------- Port %15s:%-5u <> %15s:%-5u%s, SSRC %" PRIx32 ", "
					 "" UINT64F " p, " UINT64F " b, " UINT64F " e, " UINT64F " ts",
					 local_addr,
					 (unsigned int) (ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
					 sockaddr_print_buf(&ps->endpoint.address),
					 ps->endpoint.port,
					 (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
					 ps->ssrc_in[0] ? ps->ssrc_in[0]->parent->h.ssrc : 0,
					 atomic64_get(&ps->stats.packets),
					 atomic64_get(&ps->stats.bytes), atomic64_get(&ps->stats.errors),
					 atomic64_get(&ps->last_packet));
#if RE_HAS_MEASUREDELAY
			if (PS_ISSET(ps, RTP) || !PS_ISSET(ps, RTCP))
				cw->cw_printf(cw, ", %.9f delay_min, %.9f delay_avg, %.9f delay_max",
						 (double) ps->stats.delay_min / 1000000,
						 (double) ps->stats.delay_avg / 1000000,
						 (double) ps->stats.delay_max / 1000000);
#endif
			cw->cw_printf(cw, "\n");
		}
	}
}


static void cli_incoming_list_sessions(str *instr, struct cli_writer *cw) {
	size_t found = 0;
	bool all = false, own = false;

	static const char* LIST_ALL = "all";
	static const char* LIST_OWN = "own";
	static const char* LIST_FOREIGN = "foreign";

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	if (str_cmp(instr, LIST_ALL) == 0)
		all = true;
	else if (str_cmp(instr, LIST_OWN) == 0)
		own = true;
	else if (str_cmp(instr, LIST_FOREIGN) == 0)
	{ } // default
	else {
		// list session for callid
		cli_incoming_list_callid(instr, cw);
		return;
	}

	ITERATE_CALL_LIST_START(CALL_ITERATOR_MAIN, call);
		if (!all) {
			if (IS_FOREIGN_CALL(call) && own)
				goto next;
			if (!IS_FOREIGN_CALL(call) && !own)
				goto next;
		}
		found++;

		cw->cw_printf(cw, "callid: %60s | deletionmark:%4s | created:%12i | proxy:%s | redis_keyspace:%i | foreign:%s\n", call->callid.s, call->ml_deleted?"yes":"no", (int)call->created.tv_sec, call->created_from, call->redis_hosted_db, IS_FOREIGN_CALL(call)?"yes":"no");

next:;
	ITERATE_CALL_LIST_NEXT_END(call);

	if (!found) {
		if (all)
			cw->cw_printf(cw, "No sessions on this media relay.\n");
		else if (own)
			cw->cw_printf(cw, "No own sessions on this media relay.\n");
		else
			cw->cw_printf(cw, "No foreign sessions on this media relay.\n");
	}

	return;
}

static void cli_incoming_set_maxopenfiles(str *instr, struct cli_writer *cw) {
	unsigned long open_files_num;
	pid_t pid;
	char *endptr;

	// limit the minimum number of open files to avoid rtpengine freeze for low open_files_num values
	unsigned long min_open_files_num = (1 << 16);

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	open_files_num = strtoul(instr->s, &endptr, 10);

	if ((errno == ERANGE && (open_files_num == ULONG_MAX)) || (errno != 0 && open_files_num == 0)) {
		cw->cw_printf(cw,  "Fail setting open_files to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		cw->cw_printf(cw,  "Fail setting open_files to %s; no digists found\n", instr->s);
		return;
	} else if (open_files_num < min_open_files_num) {
		cw->cw_printf(cw,  "Fail setting open_files to %lu; can't set it under %lu\n", open_files_num, min_open_files_num);
		return;
	} else if (rlim(RLIMIT_NOFILE, open_files_num) == -1){
		cw->cw_printf(cw,  "Fail setting open_files to %lu; errno = %d\n", open_files_num, errno);
		return;
	} else {
		pid = getpid();
		cw->cw_printf(cw,  "Success setting open_files to %lu; cat /proc/%u/limits\n", open_files_num, pid);
	}
}

static void cli_incoming_set_maxsessions(str *instr, struct cli_writer *cw) {
	long maxsessions_num;
	int disabled = -1;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	maxsessions_num = strtol(instr->s, &endptr, 10);

	if ((errno == ERANGE && (maxsessions_num == LONG_MAX || maxsessions_num == LONG_MIN)) || (errno != 0 && maxsessions_num == 0)) {
		cw->cw_printf(cw,  "Fail setting maxsessions to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		cw->cw_printf(cw,  "Fail setting maxsessions to %s; no digists found\n", instr->s);
		return;
	} else if (maxsessions_num < disabled) {
		cw->cw_printf(cw,  "Fail setting maxsessions to %ld; either positive or -1 values allowed\n", maxsessions_num);
	} else if (maxsessions_num == disabled) {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.max_sessions = maxsessions_num;
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting maxsessions to %ld; disable feature\n", maxsessions_num);
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.max_sessions = maxsessions_num;
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting maxsessions to %ld\n", maxsessions_num);
	}

	return;
}

// XXX lots of code duplication, unify those set functions
static void cli_incoming_set_maxcpu(str *instr, struct cli_writer *cw) {
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	double num = strtod(instr->s, &endptr);

	if ((errno == ERANGE && (num == HUGE_VAL || num == -HUGE_VAL)) || (errno != 0 && num == 0) || isnan(num) || !isfinite(num)) {
		cw->cw_printf(cw,  "Fail setting maxcpu to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		cw->cw_printf(cw,  "Fail setting maxcpu to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.cpu_limit = num * 100;
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting maxcpu to %.1f\n", num);
	}

	return;
}

static void cli_incoming_set_maxload(str *instr, struct cli_writer *cw) {
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	double num = strtod(instr->s, &endptr);

	if ((errno == ERANGE && (num == HUGE_VAL || num == -HUGE_VAL)) || (errno != 0 && num == 0) || isnan(num) || !isfinite(num)) {
		cw->cw_printf(cw,  "Fail setting maxload to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		cw->cw_printf(cw,  "Fail setting maxload to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.load_limit = num * 100;
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting maxload to %.2f\n", num);
	}

	return;
}

static void cli_incoming_set_maxbw(str *instr, struct cli_writer *cw) {
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	uint64_t num = strtoull(instr->s, &endptr, 10);

	if ((errno == ERANGE && (num == ULLONG_MAX)) || (errno != 0 && num == 0) ) {
		cw->cw_printf(cw,  "Fail setting maxbw to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		cw->cw_printf(cw,  "Fail setting maxbw to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		rtpe_config.bw_limit = num * 100;
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting maxbw to %" PRIu64 "\n", num);
	}

	return;
}

static void cli_incoming_set_gentimeout(str *instr, struct cli_writer *cw, int *conf_timeout) {
	long timeout_num;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	timeout_num = strtol(instr->s, &endptr, 10);

	if ((errno == ERANGE && (timeout_num == ULONG_MAX)) || (errno != 0 && timeout_num == 0) || timeout_num < 0 || timeout_num >= INT_MAX) {
		cw->cw_printf(cw,  "Fail setting timeout to %s; errno=%d\n", instr->s, errno);
		return;
	} else if (endptr == instr->s) {
		cw->cw_printf(cw,  "Fail setting timeout to %s; no digists found\n", instr->s);
		return;
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		*conf_timeout = (int) timeout_num;
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting timeout to %lu\n", timeout_num);
	}
}

static void cli_incoming_set_timeout(str *instr, struct cli_writer *cw) {
	cli_incoming_set_gentimeout(instr, cw, &rtpe_config.timeout);
}
static void cli_incoming_set_silenttimeout(str *instr, struct cli_writer *cw) {
	cli_incoming_set_gentimeout(instr, cw, &rtpe_config.silent_timeout);
}
static void cli_incoming_set_finaltimeout(str *instr, struct cli_writer *cw) {
	cli_incoming_set_gentimeout(instr, cw, &rtpe_config.final_timeout);
}
static void cli_incoming_set_offertimeout(str *instr, struct cli_writer *cw) {
	cli_incoming_set_gentimeout(instr, cw, &rtpe_config.offer_timeout);
}

static void cli_incoming_list(str *instr, struct cli_writer *cw) {
   if (str_shift(instr, 1)) {
       cw->cw_printf(cw, "%s\n", "More parameters required.");
       return;
   }

   cli_handler_do(cli_list_handlers, instr, cw);
}

static void cli_incoming_set(str *instr, struct cli_writer *cw) {
	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	cli_handler_do(cli_set_handlers, instr, cw);
}

static void cli_incoming_params(str *instr, struct cli_writer *cw) {
	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}
	cli_handler_do(cli_params_handlers, instr, cw);
}

static void cli_incoming_terminate(str *instr, struct cli_writer *cw) {
   struct call* c=0;
   struct call_monologue *ml;
   GList *i;

   if (str_shift(instr, 1)) {
       cw->cw_printf(cw, "%s\n", "More parameters required.");
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
		cw->cw_printf(cw, "%s\n", "All calls terminated by operator.");

		return;

	// --- terminate own calls
	} else if (!str_memcmp(instr,"own")) {
		// destroy own calls
		destroy_all_own_calls();

		// update cli
		ilog(LOG_INFO,"All own calls terminated by operator.");
		cw->cw_printf(cw, "%s\n", "All own calls terminated by operator.");

		return;

	// --- terminate foreign calls
	} else if (!str_memcmp(instr,"foreign")) {
		// destroy foreign calls
		destroy_all_foreign_calls();

		// update cli
		ilog(LOG_INFO,"All foreign calls terminated by operator.");
		cw->cw_printf(cw, "%s\n", "All foreign calls terminated by operator.");

		return;
	}

   // --- terminate a dedicated call id
   c = call_get(instr);

   if (!c) {
       cw->cw_printf(cw, "\nCall Id not found (%s).\n\n",instr->s);
       return;
   }

   if (!c->ml_deleted) {
	   for (i = c->monologues.head; i; i = i->next) {
		   ml = i->data;
		   gettimeofday(&(ml->terminated), NULL);
		   ml->term_reason = FORCED;
	   }
   }

   cw->cw_printf(cw, "\nCall Id (%s) successfully terminated by operator.\n\n",instr->s);
   ilog(LOG_WARN, "Call Id (%s) successfully terminated by operator.",instr->s);

   rwlock_unlock_w(&c->master_lock);

   call_destroy(c);
   obj_put(c);
}

static void cli_incoming_ksadd(str *instr, struct cli_writer *cw) {
	unsigned long uint_keyspace_db;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	uint_keyspace_db = strtoul(instr->s, &endptr, 10);

	if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) || (errno != 0 && uint_keyspace_db == 0)) {
		cw->cw_printf(cw, "Fail adding keyspace %s to redis notifications; errono=%d\n", instr->s, errno);
	} else if (endptr == instr->s) {
		cw->cw_printf(cw, "Fail adding keyspace %s to redis notifications; no digists found\n", instr->s);
	} else {
		rwlock_lock_w(&rtpe_config.config_lock);
		if (!g_queue_find(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db))) {
			g_queue_push_tail(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db));
			redis_notify_subscribe_action(rtpe_redis_notify, SUBSCRIBE_KEYSPACE, uint_keyspace_db);
			cw->cw_printf(cw, "Success adding keyspace %lu to redis notifications.\n", uint_keyspace_db);
		} else {
			cw->cw_printf(cw, "Keyspace %lu is already among redis notifications.\n", uint_keyspace_db);
		}
		rwlock_unlock_w(&rtpe_config.config_lock);
	}
}

static void cli_incoming_ksrm(str *instr, struct cli_writer *cw) {
	GList *l; 
	unsigned long uint_keyspace_db;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	uint_keyspace_db = strtoul(instr->s, &endptr, 10);

	rwlock_lock_w(&rtpe_config.config_lock);
	if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) || (errno != 0 && uint_keyspace_db == 0)) {
		cw->cw_printf(cw, "Fail removing keyspace %s to redis notifications; errono=%d\n", instr->s, errno);
        } else if (endptr == instr->s) {
                cw->cw_printf(cw, "Fail removing keyspace %s to redis notifications; no digists found\n", instr->s);
	} else if ((l = g_queue_find(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db)))) {
		// remove this keyspace
		redis_notify_subscribe_action(rtpe_redis_notify, UNSUBSCRIBE_KEYSPACE, uint_keyspace_db);
		g_queue_remove(&rtpe_config.redis_subscribed_keyspaces, l->data);
		cw->cw_printf(cw, "Successfully unsubscribed from keyspace %lu.\n", uint_keyspace_db);

		// destroy foreign calls for this keyspace
		destroy_keyspace_foreign_calls(uint_keyspace_db);

		// update cli
		cw->cw_printf(cw, "Successfully removed all foreign calls for keyspace %lu.\n", uint_keyspace_db);
	} else {
		cw->cw_printf(cw, "Keyspace %lu is not among redis notifications.\n", uint_keyspace_db);
	}
	rwlock_unlock_w(&rtpe_config.config_lock);

}

static void cli_incoming_kslist(str *instr, struct cli_writer *cw) {
	GList *l;

	cw->cw_printf(cw,  "\nSubscribed-on keyspaces:\n");
    
	rwlock_lock_r(&rtpe_config.config_lock);
	for (l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
		cw->cw_printf(cw,  "%u ", GPOINTER_TO_UINT(l->data));
	}
	rwlock_unlock_r(&rtpe_config.config_lock);

	cw->cw_printf(cw, "\n");
}

static void cli_incoming_active_standby(struct cli_writer *cw, bool foreign) {
	ITERATE_CALL_LIST_START(CALL_ITERATOR_MAIN, c);
		rwlock_lock_w(&c->master_lock);
		call_make_own_foreign(c, foreign);
		c->last_signal = MAX(c->last_signal, rtpe_now.tv_sec);
		if (!foreign) {
			c->foreign_media = 1; // ignore timeout until we have media
			c->last_signal++; // we are authoritative now
		}
		rwlock_unlock_w(&c->master_lock);
		redis_update_onekey(c, rtpe_redis_write);
	ITERATE_CALL_LIST_NEXT_END(c);

	cw->cw_printf(cw, "Ok, all calls set to '%s'\n", foreign ? "foreign (standby)" : "owned (active)");
}
static void cli_incoming_active(str *instr, struct cli_writer *cw) {
	cli_incoming_active_standby(cw, false);
}
static void cli_incoming_standby(str *instr, struct cli_writer *cw) {
	cli_incoming_active_standby(cw, true);
}


static void cli_incoming_debug(str *instr, struct cli_writer *cw) {
	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "No call ID specified\n");
		return;
	}

	str callid;
	if (str_token_sep(&callid, instr, ' '))
		callid = STR_NULL;

	if (!callid.len) {
		cw->cw_printf(cw, "No call ID specified\n");
		return;
	}

	int flag = 1;

	if (instr->len) {
		if (!str_cmp(instr, "on") || !str_cmp(instr, "enable"))
			;
		else if (!str_cmp(instr, "off") || !str_cmp(instr, "disable"))
			flag = 0;
		else {
			cw->cw_printf(cw, "Invalid on/off flag ('" STR_FORMAT "') specified\n", STR_FMT(instr));
			return;
		}
	}

	struct call *c = call_get(&callid);

	if (!c) {
		cw->cw_printf(cw, "Call ID '" STR_FORMAT "' not found\n", STR_FMT(&callid));
		return;
	}

	c->debug = flag;

	cw->cw_printf(cw, "%s debugging for call '" STR_FORMAT "'\n", flag ? "Enabled" : "Disabled",
			STR_FMT(&callid));

	rwlock_unlock_w(&c->master_lock);
	obj_put(c);
}

static void cli_incoming(struct streambuf_stream *s) {
   ilogs(control, LOG_INFO, "New cli connection from %s", s->addr);
}

static void cli_streambuf_printf(struct cli_writer *cw, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	streambuf_vprintf(cw->ptr, fmt, va);
	va_end(va);
}

static void cli_stream_readable(struct streambuf_stream *s) {
   static const int MAXINPUT = 1024;
   char *inbuf;
   str instr;

   inbuf = streambuf_getline(s->inbuf);
   if (!inbuf) {
       if (streambuf_bufsize(s->inbuf) > MAXINPUT) {
           ilogs(control, LOG_INFO, "Buffer length exceeded in CLI connection from %s", s->addr);
           streambuf_stream_close(s);
       }
       return;
   }

   str_init(&instr, inbuf);

   struct cli_writer cw = {
       .cw_printf = cli_streambuf_printf,
       .ptr = s->outbuf,
   };
   cli_handle(&instr, &cw);

   free(inbuf);
   streambuf_stream_shutdown(s);
   log_info_clear();
}

void cli_handle(str *instr, struct cli_writer *cw) {
	ilogs(control, LOG_INFO, "Got CLI command: " STR_FORMAT_M, STR_FMT_M(instr));
	cli_handler_do(cli_top_handlers, instr, cw);
}

static void cli_free(void *p) {
	struct cli *c = p;
	streambuf_listener_shutdown(&c->listeners[0]);
	streambuf_listener_shutdown(&c->listeners[1]);
}

struct cli *cli_new(struct poller *p, endpoint_t *ep) {
   struct cli *c;

   if (!p)
       return NULL;

   c = obj_alloc0("cli", sizeof(*c), cli_free);

   if (streambuf_listener_init(&c->listeners[0], p, ep,
            cli_incoming, cli_stream_readable,
            NULL,
            NULL,
            &c->obj))
   {
      ilogs(control, LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
      goto fail;
   }
   if (ipv46_any_convert(ep)) {
      if (streambuf_listener_init(&c->listeners[1], p, ep,
               cli_incoming, cli_stream_readable,
               NULL,
               NULL,
               &c->obj))
      {
         ilogs(control, LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
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

static void cli_incoming_list_loglevel(str *instr, struct cli_writer *cw) {
	if (instr && instr->len)
		str_shift(instr, 1);

	for (unsigned int i = 0; i < num_log_levels; i++) {
		if (instr && instr->len) {
			if (str_cmp(instr, log_level_names[i]))
				continue;
		}
		if (instr && instr->len)
			cw->cw_printf(cw, "%i\n", __get_log_level(i));
		else
			cw->cw_printf(cw, "%s = %i\n", log_level_names[i], __get_log_level(i));
	}
}
static void cli_incoming_list_loglevels(str *instr, struct cli_writer *cw) {
	for (unsigned int i = 0; i < num_log_levels; i++)
		cw->cw_printf(cw, "%s - %s\n", log_level_names[i], log_level_descriptions[i]);
}
static void cli_incoming_set_loglevel(str *instr, struct cli_writer *cw) {
	int nl;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	str subsys = STR_NULL;
	if (instr->len && (instr->s[0] < '0' || instr->s[0] > '9'))
		if (str_token_sep(&subsys, instr, ' '))
			subsys = STR_NULL;

	if (!instr->len) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	nl = atoi(instr->s);

	for (unsigned int i = 0; i < num_log_levels; i++) {
		if (subsys.len) {
			if (str_cmp(&subsys, log_level_names[i]))
				continue;
		}
		g_atomic_int_set(&rtpe_config.common.log_levels[i], nl);
	}
	cw->cw_printf(cw,  "Success setting loglevel to %i\n", nl);
}

static void cli_incoming_list_redisallowederrors(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);
	cw->cw_printf(cw, "%d\n", rtpe_config.redis_allowed_errors);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_redisallowederrors(str *instr, struct cli_writer *cw) {
	long allowed_errors;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	allowed_errors = strtol(instr->s, &endptr, 10);

	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.redis_allowed_errors = allowed_errors;
	rwlock_unlock_w(&rtpe_config.config_lock);

	cw->cw_printf(cw,  "Success setting redis-allowed-errors to %ld\n", allowed_errors);
}

static void cli_incoming_list_redisdisabletime(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);
	cw->cw_printf(cw, "%d\n", rtpe_config.redis_disable_time);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_redisdisabletime(str *instr, struct cli_writer *cw) {
	long seconds;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	seconds = strtol(instr->s, &endptr, 10);
	if (seconds < 0) {
		cw->cw_printf(cw,  "Invalid redis-disable-time value %ld, must be >= 0\n", seconds);
		return;
	}

	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.redis_disable_time = seconds;
	rwlock_unlock_w(&rtpe_config.config_lock);

	cw->cw_printf(cw,  "Success setting redis-disable-time to %ld\n", seconds);
}

static void cli_incoming_list_redisconnecttimeout(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);
	cw->cw_printf(cw, "%d\n", rtpe_config.redis_connect_timeout);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_redisconnecttimeout(str *instr, struct cli_writer *cw) {
	long timeout;
	char *endptr;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return ;
	}

	errno = 0;
	timeout = strtol(instr->s, &endptr, 10);
	if (timeout <= 0) {
		cw->cw_printf(cw,  "Invalid redis-connect-timeout value %ld, must be > 0\n", timeout);
		return;
	}
	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.redis_connect_timeout = timeout;
	rwlock_unlock_w(&rtpe_config.config_lock);
	cw->cw_printf(cw,  "Success setting redis-connect-timeout to %ld\n", timeout);
}

static void cli_incoming_list_deletedelay(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);
	cw->cw_printf(cw, "%d\n", rtpe_config.delete_delay);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_deletedelay(str *instr, struct cli_writer *cw) {
	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	int seconds = str_to_i(instr, -1);
	if (seconds == -1) {
		cw->cw_printf(cw, "Invalid delete-delay value\n");
		return;
	}
	rwlock_lock_w(&rtpe_config.config_lock);
	rtpe_config.delete_delay = seconds;
	rwlock_unlock_w(&rtpe_config.config_lock);
	cw->cw_printf(cw, "Success setting delete-delay to %d\n", seconds);
}

static void cli_incoming_call(str *instr, struct cli_writer *cw) {
	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "More parameters required.\n");
		return;
	}

	str callid;
	if (str_token_sep(&callid, instr, ' '))
		callid = STR_NULL;

	if (!callid.len) {
		cw->cw_printf(cw, "No call ID specified\n");
		return;
	}

	cw->call = call_get(&callid);
	if (!cw->call) {
		cw->cw_printf(cw, "No such call '" STR_FORMAT "'\n", STR_FMT(&callid));
		return;
	}

	cli_handler_do(cli_call_handlers, instr, cw);

	if (cw->call) {
		rwlock_unlock_w(&cw->call->master_lock);
		obj_put(cw->call);
		cw->call = NULL;
	}
}



static void cli_incoming_call_info(str *instr, struct cli_writer *cw) {
	cli_list_call_info(cw, cw->call);
}
static void cli_incoming_call_terminate(str *instr, struct cli_writer *cw) {
	cw->cw_printf(cw, "\nCall '" STR_FORMAT "' terminated.\n\n", STR_FMT(&cw->call->callid));
	ilog(LOG_WARN, "Call " STR_FORMAT_M " terminated by operator", STR_FMT_M(&cw->call->callid));
	rwlock_unlock_w(&cw->call->master_lock);
	call_destroy(cw->call);
	obj_put(cw->call);
	cw->call = NULL;
}
static void cli_incoming_call_debug(str *instr, struct cli_writer *cw) {
	str_shift(instr, 1);

	int flag = 1;

	if (instr->len) {
		if (!str_cmp(instr, "on") || !str_cmp(instr, "enable"))
			;
		else if (!str_cmp(instr, "off") || !str_cmp(instr, "disable"))
			flag = 0;
		else {
			cw->cw_printf(cw, "Invalid on/off flag ('" STR_FORMAT "') specified\n", STR_FMT(instr));
			return;
		}
	}

	cw->call->debug = flag;

	cw->cw_printf(cw, "%s debugging for call '" STR_FORMAT "'\n", flag ? "Enabled" : "Disabled",
			STR_FMT(&cw->call->callid));
}
static void cli_incoming_call_tag(str *instr, struct cli_writer *cw) {
	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "More parameters required.\n");
		return;
	}

	str tag;
	if (str_token_sep(&tag, instr, ' '))
		tag = STR_NULL;

	if (!tag.len) {
		cw->cw_printf(cw, "No tag specified\n");
		return;
	}

	cw->ml = call_get_monologue(cw->call, &tag);
	if (!cw->ml) {
		cw->cw_printf(cw, "No such tag '" STR_FORMAT "'\n", STR_FMT(&tag));
		return;
	}

	cli_handler_do(cli_tag_handlers, instr, cw);

	cw->ml = NULL;
}



static void cli_incoming_tag_info(str *instr, struct cli_writer *cw) {
	cli_list_tag_info(cw, cw->ml);
}



static void cli_incoming_list_rediscmdtimeout(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);
	cw->cw_printf(cw, "%d\n", rtpe_config.redis_cmd_timeout);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_rediscmdtimeout(str *instr, struct cli_writer *cw) {
	long timeout;
	char *endptr;
	int fail = 0;


	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return;
	}

	errno = 0;
	timeout = strtol(instr->s, &endptr, 10);
	if (timeout < 0) {
		cw->cw_printf(cw, "Invalid redis-cmd-timeout value %ld, must be >= 0\n", timeout);
		return;
	}

	rwlock_lock_w(&rtpe_config.config_lock);
	if (rtpe_config.redis_cmd_timeout == timeout) {
		rwlock_unlock_w(&rtpe_config.config_lock);
		cw->cw_printf(cw,  "Success setting redis-cmd-timeout to %ld\n", timeout);
		return;
	}
	rtpe_config.redis_cmd_timeout = timeout;
	rwlock_unlock_w(&rtpe_config.config_lock);


	if (timeout == 0) {
		cw->cw_printf(cw, "Warning: Setting redis-cmd-timeout to 0 (no timeout) will require a redis reconnect\n");
		if (rtpe_redis && redis_reconnect(rtpe_redis)) {
			cw->cw_printf(cw, "Failed reconnecting to redis\n");
			fail = 1;
		}
		if (rtpe_redis && redis_reconnect(rtpe_redis_write)) {
			cw->cw_printf(cw, "Failed reconnecting to redis-write\n");
			fail = 1;
		}
		if (rtpe_redis && redis_reconnect(rtpe_redis_notify)) {
			cw->cw_printf(cw, "Failed reconnecting to redis-notify\n");
			fail = 1;
		}
	} else {
		if (rtpe_redis && redis_set_timeout(rtpe_redis, timeout)) {
			cw->cw_printf(cw, "Failed setting redis-cmd-timeout for redis %ld\n", timeout);
			fail = 1;
		}
		if (rtpe_redis_write && redis_set_timeout(rtpe_redis_write, timeout)) {
			cw->cw_printf(cw, "Failed setting redis-cmd-timeout for redis-write %ld\n", timeout);
			fail = 1;
		}
		if (rtpe_redis_notify && redis_set_timeout(rtpe_redis_notify, timeout)) {
			cw->cw_printf(cw, "Failed setting redis-cmd-timeout for redis-notify %ld\n", timeout);
			fail = 1;
		}
	}

	if (!fail)
		cw->cw_printf(cw,  "Success setting redis-cmd-timeout to %ld\n", timeout);
}

static void cli_incoming_list_interfaces(str *instr, struct cli_writer *cw) {
	for (GList *l = all_local_interfaces.head; l; l = l->next) {
		struct local_intf *lif = l->data;
		// only show first-order interface entries: socket families must match
		if (lif->logical->preferred_family != lif->spec->local_address.addr.family)
			continue;
		cw->cw_printf(cw, "Interface '%s' address '%s' (%s)\n", lif->logical->name.s,
				sockaddr_print_buf(&lif->spec->local_address.addr),
				lif->spec->local_address.addr.family->name);
		cw->cw_printf(cw, " Port range: %5u - %5u\n",
				lif->spec->port_pool.min,
				lif->spec->port_pool.max);
		unsigned int f = g_atomic_int_get(&lif->spec->port_pool.free_ports);
		unsigned int l = g_atomic_int_get(&lif->spec->port_pool.last_used);
		unsigned int r = lif->spec->port_pool.max - lif->spec->port_pool.min + 1;
		cw->cw_printf(cw, " Ports used: %5u / %5u (%5.1f%%)\n",
				r - f, r, (double) (r - f) * 100.0 / r);
		cw->cw_printf(cw, " Last port used: %5u\n",
				l);
	}
}

static void cli_incoming_list_jsonstats(str *instr, struct cli_writer *cw) {
	AUTO_CLEANUP_INIT(GQueue *metrics, statistics_free_metrics, statistics_gather_metrics());

	for (GList *l = metrics->head; l; l = l->next) {
		struct stats_metric *m = l->data;
		if (!m->label)
			continue;

		if (m->is_follow_up)
			cw->cw_printf(cw, ",");

		if (m->value_short)
			cw->cw_printf(cw, "\"%s\":%s", m->label, m->value_short);
		else if (m->is_bracket)
			cw->cw_printf(cw, "%s", m->label);
		else
			cw->cw_printf(cw, "\"%s\":", m->label);
	}
}

static void cli_incoming_list_transcoders(str *instr, struct cli_writer *cw) {
	mutex_lock(&rtpe_codec_stats_lock);

	GList *chains = g_hash_table_get_keys(rtpe_codec_stats);
	if (!chains)
		cw->cw_printf(cw, "No stats entries\n");
	else {
		int last_tv_sec = rtpe_now.tv_sec - 1;
		unsigned int idx = last_tv_sec & 1;
		for (GList *l = chains; l; l = l->next) {
			char *chain = l->data;
			struct codec_stats *stats_entry = g_hash_table_lookup(rtpe_codec_stats, chain);
			cw->cw_printf(cw, "%s: %i transcoders\n", chain, g_atomic_int_get(&stats_entry->num_transcoders));
			if (g_atomic_int_get(&stats_entry->last_tv_sec[idx]) != last_tv_sec)
				continue;
			cw->cw_printf(cw, "     " UINT64F " packets/s\n", atomic64_get(&stats_entry->packets_input[idx]));
			cw->cw_printf(cw, "     " UINT64F " bytes/s\n", atomic64_get(&stats_entry->bytes_input[idx]));
			cw->cw_printf(cw, "     " UINT64F " samples/s\n", atomic64_get(&stats_entry->pcm_samples[idx]));
		}
	}

	mutex_unlock(&rtpe_codec_stats_lock);

	g_list_free(chains);
}

static void cli_incoming_list_controltos(str *instr, struct cli_writer *cw) {
	rwlock_lock_r(&rtpe_config.config_lock);
	cw->cw_printf(cw, "%d\n", rtpe_config.control_tos);
	rwlock_unlock_r(&rtpe_config.config_lock);
}

static void cli_incoming_set_controltos(str *instr, struct cli_writer *cw) {
	long tos;
	char *endptr;
	int i;

	if (str_shift(instr, 1)) {
		cw->cw_printf(cw, "%s\n", "More parameters required.");
		return ;
	}

	errno = 0;
	tos = strtol(instr->s, &endptr, 10);
	if (tos < 0 || tos > 255) {
		cw->cw_printf(cw,  "Invalid control-tos value %ld, must be between 0 and 255\n", tos);
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

	cw->cw_printf(cw,  "Success setting redis-connect-timeout to %ld\n", tos);
}
