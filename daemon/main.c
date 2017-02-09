#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ssl.h>

#include "poller.h"
#include "control_tcp.h"
#include "control_udp.h"
#include "control_ng.h"
#include "aux.h"
#include "log.h"
#include "call.h"
#include "kernel.h"
#include "redis.h"
#include "sdp.h"
#include "dtls.h"
#include "call_interfaces.h"
#include "cli.h"
#include "graphite.h"
#include "ice.h"
#include "socket.h"
#include "media_socket.h"
#include "homer.h"
#include "recording.h"
#include "auxlib.h"



struct main_context {
	struct poller		*p;
	struct callmaster	*m;
};




static GQueue interfaces = G_QUEUE_INIT;
static GQueue keyspaces = G_QUEUE_INIT;
static endpoint_t tcp_listen_ep;
static endpoint_t udp_listen_ep;
static endpoint_t ng_listen_ep;
static endpoint_t cli_listen_ep;
static endpoint_t graphite_ep;
static endpoint_t redis_ep;
static endpoint_t redis_write_ep;
static endpoint_t homer_ep;
static int homer_protocol = SOCK_DGRAM;
static int homer_id = 2001;
static int tos;
static int table = -1;
static int no_fallback;
static unsigned int timeout;
static unsigned int silent_timeout;
static unsigned int final_timeout;
static unsigned int redis_expires = 86400;
static unsigned int redis_multikey = 0;
static int port_min = 30000;
static int port_max = 40000;
static int max_sessions = -1;
static int redis_db = -1;
static int redis_write_db = -1;
static int redis_num_threads;
static int no_redis_required;
static char *redis_auth;
static char *redis_write_auth;
static char *b2b_url;
static enum xmlrpc_format xmlrpc_fmt = XF_SEMS;
static int num_threads;
static int delete_delay = 30;
static int graphite_interval = 0;
static char *spooldir;
static char *rec_method = "pcap";
static char *rec_format = "raw";

static void sighandler(gpointer x) {
	sigset_t ss;
	int ret;
	struct timespec ts;

	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGUSR1);
	sigaddset(&ss, SIGUSR2);

	ts.tv_sec = 0;
	ts.tv_nsec = 100000000; /* 0.1 sec */

	while (!g_shutdown) {
		ret = sigtimedwait(&ss, NULL, &ts);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			abort();
		}

		if (ret == SIGINT || ret == SIGTERM)
			g_shutdown = 1;
		else if (ret == SIGUSR1) {
		        if (get_log_level() > 0) {
				g_atomic_int_add(&log_level, -1);
				ilog(get_log_level(), "Set log level to %d\n",
						get_log_level());
			}
		}
		else if (ret == SIGUSR2) {
		        if (get_log_level() < 7) {
				g_atomic_int_add(&log_level, 1);
				ilog(get_log_level(), "Set log level to %d\n",
						get_log_level());
			}
		}
		else
			abort();
	}
}


static void signals(void) {
	sigset_t ss;

	sigfillset(&ss);
	sigdelset(&ss, SIGABRT);
	sigdelset(&ss, SIGSEGV);
	sigdelset(&ss, SIGQUIT);
	sigprocmask(SIG_SETMASK, &ss, NULL);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);
}

static void resources(void) {
	struct rlimit rl;
	int tryv;

	rlim(RLIMIT_CORE, RLIM_INFINITY);

	if (getrlimit(RLIMIT_NOFILE, &rl))
		rl.rlim_cur = 0;
	for (tryv = ((1<<20) - 1); tryv && tryv > rl.rlim_cur && rlim(RLIMIT_NOFILE, tryv) == -1; tryv >>= 1)
		;

	rlim(RLIMIT_DATA, RLIM_INFINITY);
	rlim(RLIMIT_RSS, RLIM_INFINITY);
	rlim(RLIMIT_AS, RLIM_INFINITY);
}



static int parse_log_facility(char *name, int *dst) {
	int i;
	for (i = 0 ; _facilitynames[i].c_name; i++) {
		if (strcmp(_facilitynames[i].c_name, name) == 0) {
			*dst = _facilitynames[i].c_val;
			return 1;
		}
	}
	return 0;
}

static void print_available_log_facilities () {
	int i;

	fprintf(stderr, "available facilities:");
	for (i = 0 ; _facilitynames[i].c_name; i++) {
		fprintf(stderr, " %s",  _facilitynames[i].c_name);
	}
	fprintf(stderr, "\n");
}


static struct intf_config *if_addr_parse(char *s) {
	str name;
	char *c;
	sockaddr_t addr, adv;
	struct intf_config *ifa;

	/* name */
	c = strchr(s, '/');
	if (c) {
		*c++ = 0;
		str_init(&name, s);
		s = c;
	}
	else
		str_init(&name, "default");

	/* advertised address */
	c = strchr(s, '!');
	if (c)
		*c++ = 0;

	/* address */
	if (sockaddr_parse_any(&addr, s))
		return NULL;

	adv = addr;
	if (c) {
		if (sockaddr_parse_any(&adv, c))
			return NULL;
	}

	ifa = g_slice_alloc0(sizeof(*ifa));
	ifa->name = name;
	ifa->local_address.addr = addr;
	ifa->local_address.type = socktype_udp;
	ifa->advertised_address.addr = adv;
	ifa->advertised_address.type = ifa->local_address.type;
	ifa->port_min = port_min;
	ifa->port_max = port_max;

	return ifa;
}



static int redis_ep_parse(endpoint_t *ep, int *db, char **auth, const char *auth_env, char *str) {
	char *sl;
	long l;

	sl = strchr(str, '@');
	if (sl) {
		*sl = 0;
		*auth = str;
		str = sl+1;
	}
	else if ((sl = getenv(auth_env)))
		*auth = sl;

	sl = strchr(str, '/');
	if (!sl)
		return -1;
	*sl = 0;
	sl++;
	if (!*sl)
		return -1;
	l = strtol(sl, &sl, 10);
	if (*sl != 0)
		return -1;
	if (l < 0)
		return -1;
	*db = l;
	if (endpoint_parse_any_full(ep, str))
		return -1;
	return 0;
}



static void options(int *argc, char ***argv) {
	char **if_a = NULL;
	char **ks_a = NULL;
	unsigned int uint_keyspace_db;
	str str_keyspace_db;
	char **iter;
	struct intf_config *ifa;
	char *listenps = NULL;
	char *listenudps = NULL;
	char *listenngs = NULL;
	char *listencli = NULL;
	char *graphitep = NULL;
	char *graphite_prefix_s = NULL;
	char *redisps = NULL;
	char *redisps_write = NULL;
	char *log_facility_s = NULL;
	char *log_facility_cdr_s = NULL;
	char *log_facility_rtcp_s = NULL;
	int sip_source = 0;
	char *homerp = NULL;
	char *homerproto = NULL;
	char *endptr;

	GOptionEntry e[] = {
		{ "table",	't', 0, G_OPTION_ARG_INT,	&table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&no_fallback,	"Only start when kernel module is available", NULL },
		{ "interface",	'i', 0, G_OPTION_ARG_STRING_ARRAY,&if_a,	"Local interface for RTP",	"[NAME/]IP[!IP]"},
		{ "subscribe-keyspace", 'k', 0, G_OPTION_ARG_STRING_ARRAY,&ks_a,	"Subscription keyspace list",	"INT INT ..."},
		{ "listen-tcp",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP46:]PORT"	},
		{ "listen-ng",	'n', 0, G_OPTION_ARG_STRING,	&listenngs,	"UDP port to listen on, NG protocol", "[IP46:]PORT"	},
		{ "listen-cli", 'c', 0, G_OPTION_ARG_STRING,    &listencli,     "UDP port to listen on, CLI",   "[IP46:]PORT"     },
		{ "graphite", 'g', 0, G_OPTION_ARG_STRING,    &graphitep,     "Address of the graphite server",   "IP46:PORT"     },
		{ "graphite-interval",  'G', 0, G_OPTION_ARG_INT,    &graphite_interval,  "Graphite send interval in seconds",    "INT"   },
		{ "graphite-prefix",0,  0,	G_OPTION_ARG_STRING, &graphite_prefix_s, "Prefix for graphite line", "STRING"},
		{ "tos",	'T', 0, G_OPTION_ARG_INT,	&tos,		"Default TOS value to set on streams",	"INT"		},
		{ "timeout",	'o', 0, G_OPTION_ARG_INT,	&timeout,	"RTP timeout",			"SECS"		},
		{ "silent-timeout",'s',0,G_OPTION_ARG_INT,	&silent_timeout,"RTP timeout for muted",	"SECS"		},
		{ "final-timeout",'a',0,G_OPTION_ARG_INT,	&final_timeout,	"Call timeout",			"SECS"		},
		{ "port-min",	'm', 0, G_OPTION_ARG_INT,	&port_min,	"Lowest port to use for RTP",	"INT"		},
		{ "port-max",	'M', 0, G_OPTION_ARG_INT,	&port_max,	"Highest port to use for RTP",	"INT"		},
		{ "redis",	'r', 0, G_OPTION_ARG_STRING,	&redisps,	"Connect to Redis database",	"[PW@]IP:PORT/INT"	},
		{ "redis-write",'w', 0, G_OPTION_ARG_STRING,    &redisps_write, "Connect to Redis write database",      "[PW@]IP:PORT/INT"       },
		{ "redis-num-threads", 0, 0, G_OPTION_ARG_INT, &redis_num_threads, "Number of Redis restore threads",      "INT"       },
		{ "redis-expires", 0, 0, G_OPTION_ARG_INT, &redis_expires, "Expire time in seconds for redis keys",      "INT"       },
		{ "redis-multikey", 0, 0, G_OPTION_ARG_NONE, &redis_multikey, "Use multiple redis keys for storing the call (old behaviour) DEPRECATED", NULL },
		{ "no-redis-required", 'q', 0, G_OPTION_ARG_NONE, &no_redis_required, "Start no matter of redis connection state", NULL },
		{ "b2b-url",	'b', 0, G_OPTION_ARG_STRING,	&b2b_url,	"XMLRPC URL of B2B UA"	,	"STRING"	},
		{ "log-facility",0,  0,	G_OPTION_ARG_STRING, &log_facility_s, "Syslog facility to use for logging", "daemon|local0|...|local7"},
		{ "log-facility-cdr",0,  0, G_OPTION_ARG_STRING, &log_facility_cdr_s, "Syslog facility to use for logging CDRs", "daemon|local0|...|local7"},
		{ "log-facility-rtcp",0,  0, G_OPTION_ARG_STRING, &log_facility_rtcp_s, "Syslog facility to use for logging RTCP", "daemon|local0|...|local7"},
		{ "log-stderr",	'E', 0, G_OPTION_ARG_NONE,	&_log_stderr,	"Log on stderr instead of syslog",	NULL		},
		{ "xmlrpc-format",'x', 0, G_OPTION_ARG_INT,	&xmlrpc_fmt,	"XMLRPC timeout request format to use. 0: SEMS DI, 1: call-id only",	"INT"	},
		{ "num-threads",  0, 0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads to create",	"INT"	},
		{ "delete-delay",  'd', 0, G_OPTION_ARG_INT,    &delete_delay,  "Delay for deleting a session from memory.",    "INT"   },
		{ "sip-source",  0,  0, G_OPTION_ARG_NONE,	&sip_source,	"Use SIP source address by default",	NULL	},
		{ "dtls-passive", 0, 0, G_OPTION_ARG_NONE,	&dtls_passive_def,"Always prefer DTLS passive role",	NULL	},
		{ "max-sessions", 0, 0, G_OPTION_ARG_INT,	&max_sessions,	"Limit of maximum number of sessions",	"INT"	},
		{ "homer",	0,  0, G_OPTION_ARG_STRING,	&homerp,	"Address of Homer server for RTCP stats","IP46:PORT"},
		{ "homer-protocol",0,0,G_OPTION_ARG_STRING,	&homerproto,	"Transport protocol for Homer (default udp)",	"udp|tcp"	},
		{ "homer-id",	0,  0, G_OPTION_ARG_STRING,	&homer_id,	"'Capture ID' to use within the HEP protocol", "INT"	},
		{ "recording-dir", 0, 0, G_OPTION_ARG_STRING,	&spooldir,	"Directory for storing pcap and metadata files", "FILE"	},
		{ "recording-method",0, 0, G_OPTION_ARG_STRING,	&rec_method,	"Strategy for call recording",		"pcap|proc"	},
		{ "recording-format",0, 0, G_OPTION_ARG_STRING,	&rec_format,	"File format for stored pcap files",	"raw|eth"	},
		{ NULL, }
	};

	config_load(argc, argv, e, " - next-generation media proxy",
			"/etc/rtpengine/rtpengine.conf", "rtpengine");

	if (!if_a)
		die("Missing option --interface");
	if (!listenps && !listenudps && !listenngs)
		die("Missing option --listen-tcp, --listen-udp or --listen-ng");

	for (iter = if_a; *iter; iter++) {
		ifa = if_addr_parse(*iter);
		if (!ifa)
			die("Invalid interface specification: %s", *iter);
		g_queue_push_tail(&interfaces, ifa);
	}

	if (ks_a) {
		for (iter = ks_a; *iter; iter++) {
			str_keyspace_db.s = *iter;
			str_keyspace_db.len = strlen(*iter);
			uint_keyspace_db = strtol(str_keyspace_db.s, &endptr, 10);

			if ((errno == ERANGE && (uint_keyspace_db == LONG_MAX || uint_keyspace_db == LONG_MIN)) ||
			    (errno != 0 && uint_keyspace_db == 0)) {
				ilog(LOG_ERR, "Fail adding keyspace %.*s to redis notifications; errono=%d\n", str_keyspace_db.len, str_keyspace_db.s, errno);
			} else if (endptr == str_keyspace_db.s) {
				ilog(LOG_ERR, "Fail adding keyspace %.*s to redis notifications; no digists found\n", str_keyspace_db.len, str_keyspace_db.s);
			} else {
				g_queue_push_tail(&keyspaces, GUINT_TO_POINTER(uint_keyspace_db));
			}
		}
	}

	if (listenps) {
		if (endpoint_parse_any(&tcp_listen_ep, listenps))
			die("Invalid IP or port (--listen-tcp)");
	}
	if (listenudps) {
		if (endpoint_parse_any(&udp_listen_ep, listenudps))
			die("Invalid IP or port (--listen-udp)");
	}
	if (listenngs) {
		if (endpoint_parse_any(&ng_listen_ep, listenngs))
			die("Invalid IP or port (--listen-ng)");
	}

	if (listencli) {if (endpoint_parse_any(&cli_listen_ep, listencli))
	    die("Invalid IP or port (--listen-cli)");
	}

	if (graphitep) {if (endpoint_parse_any_full(&graphite_ep, graphitep))
	    die("Invalid IP or port (--graphite)");
	}

	if (graphite_prefix_s)
		set_prefix(graphite_prefix_s);

	if (homerp) {
		if (endpoint_parse_any_full(&homer_ep, homerp))
			die("Invalid IP or port (--homer)");
	}
	if (homerproto) {
		if (!strcmp(homerproto, "tcp"))
			homer_protocol = SOCK_STREAM;
		else if (!strcmp(homerproto, "udp"))
			homer_protocol = SOCK_DGRAM;
		else
			die("Invalid protocol (--homer-protocol)");
	}

	if (tos < 0 || tos > 255)
		die("Invalid TOS value");

	if (timeout <= 0)
		timeout = 60;

	if (silent_timeout <= 0)
		silent_timeout = 3600;

	if (final_timeout <= 0)
		final_timeout = 0;

	if (redisps)
		if (redis_ep_parse(&redis_ep, &redis_db, &redis_auth, "RTPENGINE_REDIS_AUTH_PW", redisps))
			die("Invalid Redis endpoint [IP:PORT/INT] (--redis)");

	if (redisps_write)
		if (redis_ep_parse(&redis_write_ep, &redis_write_db, &redis_write_auth,
					"RTPENGINE_REDIS_WRITE_AUTH_PW", redisps_write))
			die("Invalid Redis endpoint [IP:PORT/INT] (--redis-write)");

	if (xmlrpc_fmt > 1)
		die("Invalid XMLRPC format");

	if ((log_level < LOG_EMERG) || (log_level > LOG_DEBUG))
	        die("Invalid log level (--log_level)");

	if (log_facility_s) {
		if (!parse_log_facility(log_facility_s, &_log_facility)) {
			print_available_log_facilities();
			die ("Invalid log facility '%s' (--log-facility)", log_facility_s);
		}
	}

	if (log_facility_cdr_s) {
		if (!parse_log_facility(log_facility_cdr_s, &_log_facility_cdr)) {
			print_available_log_facilities();
			die ("Invalid log facility for CDR '%s' (--log-facility-cdr)", log_facility_cdr_s);
		}
	}

	if (log_facility_rtcp_s) {
		if (!parse_log_facility(log_facility_rtcp_s, &_log_facility_rtcp)) {
			print_available_log_facilities();
			die ("Invalid log facility for RTCP '%s' (--log-facility-rtcp)n", log_facility_rtcp_s);
		}
	}

	if (_log_stderr) {
		write_log = log_to_stderr;
		max_log_line_length = 0;
	}

	if (!sip_source)
		trust_address_def = 1;
}


#if OPENSSL_VERSION_NUMBER < 0x10100000L
static mutex_t *openssl_locks;

static void cb_openssl_threadid(CRYPTO_THREADID *tid) {
	pthread_t me;

	me = pthread_self();

	if (sizeof(me) == sizeof(void *))
		CRYPTO_THREADID_set_pointer(tid, (void *) me);
	else
		CRYPTO_THREADID_set_numeric(tid, (unsigned long) me);
}

static void cb_openssl_lock(int mode, int type, const char *file, int line) {
	if ((mode & CRYPTO_LOCK))
		mutex_lock(&openssl_locks[type]);
	else
		mutex_unlock(&openssl_locks[type]);
}

static void make_OpenSSL_thread_safe(void) {
	int i;

	openssl_locks = malloc(sizeof(*openssl_locks) * CRYPTO_num_locks());
	for (i = 0; i < CRYPTO_num_locks(); i++)
		mutex_init(&openssl_locks[i]);

	CRYPTO_THREADID_set_callback(cb_openssl_threadid);
	CRYPTO_set_locking_callback(cb_openssl_lock);
}
#else
static void make_OpenSSL_thread_safe(void) {
	;
}
#endif


static void early_init() {
	socket_init(); // needed for socktype_udp
}

static void init_everything() {
	struct timespec ts;

	log_init();
	recording_fs_init(spooldir, rec_method, rec_format);
	clock_gettime(CLOCK_REALTIME, &ts);
	srandom(ts.tv_sec ^ ts.tv_nsec);
	SSL_library_init();
	SSL_load_error_strings();
	make_OpenSSL_thread_safe();

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(NULL);
#endif

#if !(GLIB_CHECK_VERSION(2,36,0))
	g_type_init();
#endif

	if (!_log_stderr)
		openlog("rtpengine", LOG_PID | LOG_NDELAY, _log_facility);
	signals();
	resources();
	sdp_init();
	dtls_init();
	ice_init();
	interfaces_init(&interfaces);
}


static void create_everything(struct main_context *ctx) {
	struct callmaster_config mc;
	struct control_tcp *ct;
	struct control_udp *cu;
	struct control_ng *cn;
	struct cli *cl;
	struct timeval tmp_tv;
	struct timeval redis_start, redis_stop;
	double redis_diff = 0;

	if (table < 0)
		goto no_kernel;
	if (kernel_setup_table(table)) {
		if (no_fallback) {
			ilog(LOG_CRIT, "Userspace fallback disallowed - exiting");
			exit(-1);
		}
		goto no_kernel;
	}

no_kernel:
	ctx->p = poller_new();
	if (!ctx->p)
		die("poller creation failed");

	ctx->m = callmaster_new(ctx->p);
	if (!ctx->m)
		die("callmaster creation failed");

	dtls_timer(ctx->p);

	ZERO(mc);
        rwlock_init(&mc.config_lock);
	if (max_sessions < -1) {
		max_sessions = -1;
	}
	mc.max_sessions = max_sessions;
	mc.timeout = timeout;
	mc.silent_timeout = silent_timeout;
	mc.final_timeout = final_timeout;
	mc.delete_delay = delete_delay;
	mc.default_tos = tos;
	mc.b2b_url = b2b_url;
	mc.fmt = xmlrpc_fmt;
	mc.graphite_ep = graphite_ep;
	mc.graphite_interval = graphite_interval;
	mc.redis_subscribed_keyspaces = g_queue_copy(&keyspaces);

	if (redis_num_threads < 1) {
#ifdef _SC_NPROCESSORS_ONLN
		redis_num_threads = sysconf( _SC_NPROCESSORS_ONLN );
#endif
		if (redis_num_threads < 1) {
			redis_num_threads = REDIS_RESTORE_NUM_THREADS;
		}
	}
	mc.redis_num_threads = redis_num_threads;

	ct = NULL;
	if (tcp_listen_ep.port) {
		ct = control_tcp_new(ctx->p, &tcp_listen_ep, ctx->m);
		if (!ct)
			die("Failed to open TCP control connection port");
	}

	cu = NULL;
	if (udp_listen_ep.port) {
		interfaces_exclude_port(udp_listen_ep.port);
		cu = control_udp_new(ctx->p, &udp_listen_ep, ctx->m);
		if (!cu)
			die("Failed to open UDP control connection port");
	}

	cn = NULL;
	if (ng_listen_ep.port) {
		interfaces_exclude_port(ng_listen_ep.port);
		cn = control_ng_new(ctx->p, &ng_listen_ep, ctx->m);
		if (!cn)
			die("Failed to open UDP control connection port");
	}

	cl = NULL;
	if (cli_listen_ep.port) {
		interfaces_exclude_port(cli_listen_ep.port);
	    cl = cli_new(ctx->p, &cli_listen_ep, ctx->m);
	    if (!cl)
	        die("Failed to open UDP CLI connection port");
	}

	if (!is_addr_unspecified(&redis_write_ep.address)) {
		mc.redis_write = redis_new(&redis_write_ep, redis_write_db, redis_write_auth, ANY_REDIS_ROLE, no_redis_required);
		if (!mc.redis_write)
			die("Cannot start up without running Redis %s write database! See also NO_REDIS_REQUIRED paramter.",
				endpoint_print_buf(&redis_write_ep));
	}

	if (!is_addr_unspecified(&redis_ep.address)) {
		mc.redis = redis_new(&redis_ep, redis_db, redis_auth, mc.redis_write ? ANY_REDIS_ROLE : MASTER_REDIS_ROLE, no_redis_required);
		mc.redis_notify = redis_new(&redis_ep, redis_db, redis_auth, mc.redis_write ? ANY_REDIS_ROLE : MASTER_REDIS_ROLE, no_redis_required);
		if (!mc.redis || !mc.redis_notify)
			die("Cannot start up without running Redis %s database! See also NO_REDIS_REQUIRED paramter.",
				endpoint_print_buf(&redis_ep));

		if (!mc.redis_write)
			mc.redis_write = mc.redis;
	}

	mc.redis_expires_secs = redis_expires;
	mc.redis_multikey = redis_multikey;

	ctx->m->conf = mc;

	daemonize();
	wpidfile();

	ctx->m->homer = homer_sender_new(&homer_ep, homer_protocol, homer_id);

	if (mc.redis) {
		// start redis restore timer
		gettimeofday(&redis_start, NULL);

		// restore
		if (redis_restore(ctx->m, mc.redis))
			die("Refusing to continue without working Redis database");

		// stop redis restore timer
		gettimeofday(&redis_stop, NULL);

		// print redis restore duration
		redis_diff += timeval_diff(&redis_stop, &redis_start) / 1000.0;
		ilog(LOG_INFO, "Redis restore time = %.0lf ms", redis_diff);
	}

	gettimeofday(&ctx->m->latest_graphite_interval_start, NULL);

	timeval_from_us(&tmp_tv, graphite_interval*1000000);
	set_graphite_interval_tv(&tmp_tv);
}


int main(int argc, char **argv) {
	struct main_context ctx;
	int idx=0;

	early_init();
	options(&argc, &argv);
	init_everything();
	create_everything(&ctx);

	ilog(LOG_INFO, "Startup complete, version %s", RTPENGINE_VERSION);

	thread_create_detach(sighandler, NULL);
	thread_create_detach(poller_timer_loop, ctx.p);

	if (!is_addr_unspecified(&redis_ep.address))
		thread_create_detach(redis_notify_loop, ctx.m);

	if (!is_addr_unspecified(&graphite_ep.address))
		thread_create_detach(graphite_loop, ctx.m);

	thread_create_detach(ice_thread_run, NULL);

	if (num_threads < 1) {
#ifdef _SC_NPROCESSORS_ONLN
		num_threads = sysconf( _SC_NPROCESSORS_ONLN );
#endif
		if (num_threads < 1)
			num_threads = 4;
	}

	for (;idx<num_threads;++idx) {
		thread_create_detach(poller_loop, ctx.p);
	}

	while (!g_shutdown) {
		usleep(100000);
		threads_join_all(0);
	}

	if (!is_addr_unspecified(&redis_ep.address))
		redis_notify_event_base_action(ctx.m, EVENT_BASE_LOOPBREAK);

	threads_join_all(1);

	ilog(LOG_INFO, "Version %s shutting down", RTPENGINE_VERSION);

	return 0;
}
