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



#define REDIS_MODULE_VERSION "redis/9"




#define die(x...) do {									\
	fprintf(stderr, x);								\
	fprintf(stderr, "\n");								\
	ilog(LOG_CRIT, x);								\
	exit(-1);									\
} while(0)



struct main_context {
	struct poller		*p;
	struct callmaster	*m;
};




static mutex_t *openssl_locks;

static char *pidfile;
static gboolean foreground;
static GQueue interfaces = G_QUEUE_INIT;
static u_int32_t listenp;
static u_int16_t listenport;
static struct in6_addr udp_listenp;
static u_int16_t udp_listenport;
static struct in6_addr ng_listenp;
static u_int16_t ng_listenport;
static u_int32_t cli_listenp;
static u_int16_t cli_listenport;
static int tos;
static int table = -1;
static int no_fallback;
static int timeout;
static int silent_timeout;
static int port_min = 30000;
static int port_max = 40000;
static int max_sessions = 0;
static u_int32_t redis_ip;
static u_int16_t redis_port;
static int redis_db = -1;
static char *b2b_url;
static enum xmlrpc_format xmlrpc_fmt = XF_SEMS;
static int num_threads;
static int delete_delay = 30;
static u_int32_t graphite_ip = 0;
static u_int16_t graphite_port;
static int graphite_interval = 0;

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
	int tryv;

	rlim(RLIMIT_CORE, RLIM_INFINITY);
	for (tryv = ((1<<16) - 1); tryv && rlim(RLIMIT_NOFILE, tryv) == -1; tryv >>= 1)
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


static struct interface_address *if_addr_parse(char *s) {
	str name;
	char *c;
	struct in6_addr addr, adv;
	struct interface_address *ifa;
	int family;

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
	if (pton_46(&addr, s, &family))
		return NULL;

	adv = addr;
	if (c) {
		if (pton_46(&adv, c, NULL))
			return NULL;
	}

	ifa = g_slice_alloc0(sizeof(*ifa));
	ifa->interface_name = name;
	ifa->addr = addr;
	ifa->advertised = adv;
	ifa->family = family;

	return ifa;
}



static void options(int *argc, char ***argv) {
	char **if_a = NULL;
	char **iter;
	struct interface_address *ifa;
	char *listenps = NULL;
	char *listenudps = NULL;
	char *listenngs = NULL;
	char *listencli = NULL;
	char *graphitep = NULL;
	char *graphite_prefix_s = NULL;
	char *redisps = NULL;
	char *log_facility_s = NULL;
    char *log_facility_cdr_s = NULL;
    char *log_facility_rtcp_s = NULL;
	int version = 0;
	int sip_source = 0;

	GOptionEntry e[] = {
		{ "version",	'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",	NULL		},
		{ "table",	't', 0, G_OPTION_ARG_INT,	&table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&no_fallback,	"Only start when kernel module is available", NULL },
		{ "interface",	'i', 0, G_OPTION_ARG_STRING_ARRAY,&if_a,	"Local interface for RTP",	"[NAME/]IP[!IP]"},
		{ "listen-tcp",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP46:]PORT"	},
		{ "listen-ng",	'n', 0, G_OPTION_ARG_STRING,	&listenngs,	"UDP port to listen on, NG protocol", "[IP46:]PORT"	},
        { "listen-cli", 'c', 0, G_OPTION_ARG_STRING,    &listencli,     "UDP port to listen on, CLI",   "[IP46:]PORT"     },
        { "graphite", 'g', 0, G_OPTION_ARG_STRING,    &graphitep,     "Address of the graphite server",   "[IP46:]PORT"     },
		{ "graphite-interval",  'w', 0, G_OPTION_ARG_INT,    &graphite_interval,  "Graphite send interval in seconds",    "INT"   },
		{ "graphite-prefix",0,  0,	G_OPTION_ARG_STRING, &graphite_prefix_s, "Prefix for graphite line", "STRING"},
		{ "tos",	'T', 0, G_OPTION_ARG_INT,	&tos,		"Default TOS value to set on streams",	"INT"		},
		{ "timeout",	'o', 0, G_OPTION_ARG_INT,	&timeout,	"RTP timeout",			"SECS"		},
		{ "silent-timeout",'s',0,G_OPTION_ARG_INT,	&silent_timeout,"RTP timeout for muted",	"SECS"		},
		{ "pidfile",	'p', 0, G_OPTION_ARG_FILENAME,	&pidfile,	"Write PID to file",		"FILE"		},
		{ "foreground",	'f', 0, G_OPTION_ARG_NONE,	&foreground,	"Don't fork to background",	NULL		},
		{ "port-min",	'm', 0, G_OPTION_ARG_INT,	&port_min,	"Lowest port to use for RTP",	"INT"		},
		{ "port-max",	'M', 0, G_OPTION_ARG_INT,	&port_max,	"Highest port to use for RTP",	"INT"		},
		{ "redis",	'r', 0, G_OPTION_ARG_STRING,	&redisps,	"Connect to Redis database",	"IP:PORT"	},
		{ "redis-db",	'R', 0, G_OPTION_ARG_INT,	&redis_db,	"Which Redis DB to use",	"INT"	},
		{ "b2b-url",	'b', 0, G_OPTION_ARG_STRING,	&b2b_url,	"XMLRPC URL of B2B UA"	,	"STRING"	},
		{ "log-level",	'L', 0, G_OPTION_ARG_INT,	(void *)&log_level,"Mask log priorities above this level","INT"	},
		{ "log-facility",0,  0,	G_OPTION_ARG_STRING, &log_facility_s, "Syslog facility to use for logging", "daemon|local0|...|local7"},
		{ "log-facility-cdr",0,  0, G_OPTION_ARG_STRING, &log_facility_cdr_s, "Syslog facility to use for logging CDRs", "daemon|local0|...|local7"},
		{ "log-facility-rtcp",0,  0, G_OPTION_ARG_STRING, &log_facility_rtcp_s, "Syslog facility to use for logging RTCP", "daemon|local0|...|local7"},
		{ "log-stderr",	'E', 0, G_OPTION_ARG_NONE,	&_log_stderr,	"Log on stderr instead of syslog",	NULL		},
		{ "xmlrpc-format",'x', 0, G_OPTION_ARG_INT,	&xmlrpc_fmt,	"XMLRPC timeout request format to use. 0: SEMS DI, 1: call-id only",	"INT"	},
		{ "num-threads",  0, 0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads to create",	"INT"	},
		{ "delete-delay",  'd', 0, G_OPTION_ARG_INT,    &delete_delay,  "Delay for deleting a session from memory.",    "INT"   },
		{ "sip-source",  0,  0, G_OPTION_ARG_NONE,	&sip_source,	"Use SIP source address by default",	NULL	},
		{ "dtls-passive", 0, 0, G_OPTION_ARG_NONE,	&dtls_passive_def,"Always prefer DTLS passive role",	NULL	},
		{ "max-sessions", 0, 0, G_OPTION_ARG_INT,	&max_sessions,	"Limit of maximum number of sessions",	NULL	},
		{ NULL, }
	};

	GOptionContext *c;
	GError *er = NULL;

	c = g_option_context_new(" - next-generation media proxy");
	g_option_context_add_main_entries(c, e, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		die("Bad command line: %s", er->message);

	if (version)
		die("%s", RTPENGINE_VERSION);

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

	if (listenps) {
		if (parse_ip_port(&listenp, &listenport, listenps))
			die("Invalid IP or port (--listen-tcp)");
	}
	if (listenudps) {
		if (parse_ip6_port(&udp_listenp, &udp_listenport, listenudps))
			die("Invalid IP or port (--listen-udp)");
	}
	if (listenngs) {
		if (parse_ip6_port(&ng_listenp, &ng_listenport, listenngs))
			die("Invalid IP or port (--listen-ng)");
	}

	if (listencli) {if (parse_ip_port(&cli_listenp, &cli_listenport, listencli))
	    die("Invalid IP or port (--listen-cli)");
	}

	if (graphitep) {if (parse_ip_port(&graphite_ip, &graphite_port, graphitep))
	    die("Invalid IP or port (--graphite)");
	}

	if (graphite_prefix_s)
		set_prefix(graphite_prefix_s);

	if (tos < 0 || tos > 255)
		die("Invalid TOS value");

	if (timeout <= 0)
		timeout = 60;
	if (silent_timeout <= 0)
		silent_timeout = 3600;

	if (redisps) {
		if (parse_ip_port(&redis_ip, &redis_port, redisps) || !redis_ip)
			die("Invalid IP or port (--redis)");
		if (redis_db < 0)
			die("Must specify Redis DB number (--redis-db) when using Redis");
	}
	
	if (xmlrpc_fmt > 1)
		die("Invalid XMLRPC format");

	if ((log_level < LOG_EMERG) || (log_level > LOG_DEBUG))
	        die("Invalid log level (--log_level)");

	if (log_facility_s) {
		if (!parse_log_facility(log_facility_s, &_log_facility)) {
			print_available_log_facilities();
			die ("Invalid log facility '%s' (--log-facility)\n", log_facility_s);
		}
	}

	if (log_facility_cdr_s) {
		if (!parse_log_facility(log_facility_cdr_s, &_log_facility_cdr)) {
			print_available_log_facilities();
			die ("Invalid log facility for CDR '%s' (--log-facility-cdr)\n", log_facility_cdr_s);
		}
	}

	if (log_facility_rtcp_s) {
		if (!parse_log_facility(log_facility_rtcp_s, &_log_facility_rtcp)) {
			print_available_log_facilities();
			die ("Invalid log facility for RTCP '%s' (--log-facility-rtcp)\n", log_facility_rtcp_s);
		}
	}

	if (_log_stderr) {
		write_log = log_to_stderr;
		max_log_line_length = 0;
	}

	if (!sip_source)
		trust_address_def = 1;
}


static void daemonize(void) {
	if (fork())
		_exit(0);
	stdin = freopen("/dev/null", "r", stdin);
	stdout = freopen("/dev/null", "w", stdout);
	stderr = freopen("/dev/null", "w", stderr);
	setpgrp();
}

static void wpidfile(void) {
	FILE *fp;

	if (!pidfile)
		return;

	fp = fopen(pidfile, "w");
	if (fp) {
		fprintf(fp, "%u\n", getpid());
		fclose(fp);
	}
}


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


static void init_everything() {
	struct timespec ts;

	log_init();
	clock_gettime(CLOCK_REALTIME, &ts);
	srandom(ts.tv_sec ^ ts.tv_nsec);
	SSL_library_init();
	SSL_load_error_strings();
	make_OpenSSL_thread_safe();

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(NULL);
#endif
	if (!_log_stderr)
		openlog("rtpengine", LOG_PID | LOG_NDELAY, _log_facility);
	signals();
	resources();
	sdp_init();
	dtls_init();
	ice_init();
}

void create_everything(struct main_context *ctx) {
	struct callmaster_config mc;
	struct control_tcp *ct;
	struct control_udp *cu;
	struct control_ng *cn;
	struct cli *cl;
	int kfd = -1;
	struct timeval tmp_tv;

	if (table < 0)
		goto no_kernel;
	if (kernel_create_table(table)) {
		fprintf(stderr, "FAILED TO CREATE KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
		ilog(LOG_CRIT, "FAILED TO CREATE KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
		if (no_fallback)
			exit(-1);
		goto no_kernel;
	}
	kfd = kernel_open_table(table);
	if (kfd == -1) {
		fprintf(stderr, "FAILED TO OPEN KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
		ilog(LOG_CRIT, "FAILED TO OPEN KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
		if (no_fallback)
			exit(-1);
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
	mc.kernelfd = kfd;
	mc.kernelid = table;
	mc.interfaces = &interfaces;
	mc.port_min = port_min;
	mc.port_max = port_max;
	mc.max_sessions = max_sessions;
	mc.timeout = timeout;
	mc.silent_timeout = silent_timeout;
	mc.delete_delay = delete_delay;
	mc.default_tos = tos;
	mc.b2b_url = b2b_url;
	mc.fmt = xmlrpc_fmt;
	mc.graphite_port = graphite_port;
	mc.graphite_ip = graphite_ip;
	mc.graphite_interval = graphite_interval;

	ct = NULL;
	if (listenport) {
		ct = control_tcp_new(ctx->p, listenp, listenport, ctx->m);
		if (!ct)
			die("Failed to open TCP control connection port");
	}

	cu = NULL;
	if (udp_listenport) {
		callmaster_exclude_port(ctx->m, udp_listenport);
		cu = control_udp_new(ctx->p, udp_listenp, udp_listenport, ctx->m);
		if (!cu)
			die("Failed to open UDP control connection port");
	}

	cn = NULL;
	if (ng_listenport) {
		callmaster_exclude_port(ctx->m, ng_listenport);
		cn = control_ng_new(ctx->p, ng_listenp, ng_listenport, ctx->m);
		if (!cn)
			die("Failed to open UDP control connection port");
	}

	cl = NULL;
	if (cli_listenport) {
	    callmaster_exclude_port(ctx->m, cli_listenport);
	    cl = cli_new(ctx->p, cli_listenp, cli_listenport, ctx->m);
	    if (!cl)
	        die("Failed to open UDP CLI connection port");
	}

	if (redis_ip) {
		mc.redis = redis_new(redis_ip, redis_port, redis_db);
		if (!mc.redis)
			die("Cannot start up without Redis database");
	}

	ctx->m->conf = mc;
	callmaster_config_init(ctx->m);

	if (!foreground)
		daemonize();
	wpidfile();

	if (redis_restore(ctx->m, mc.redis))
		die("Refusing to continue without working Redis database");

	gettimeofday(&ctx->m->latest_graphite_interval_start, NULL);

	timeval_from_ms(&tmp_tv, graphite_interval*1000000);
	set_graphite_interval_tv(&tmp_tv);
}

int main(int argc, char **argv) {
	struct main_context ctx;
	int idx=0;

	options(&argc, &argv);
	init_everything();
	create_everything(&ctx);

	ilog(LOG_INFO, "Startup complete, version %s", RTPENGINE_VERSION);

	thread_create_detach(sighandler, NULL);
	thread_create_detach(poller_timer_loop, ctx.p);

	if (graphite_ip)
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

	threads_join_all(1);

	ilog(LOG_INFO, "Version %s shutting down", RTPENGINE_VERSION);

	return 0;
}
