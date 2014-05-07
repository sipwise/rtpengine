#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
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




#define die(x...) do { fprintf(stderr, x); exit(-1); } while(0)
#define dlresolve(n) do {								\
	n ## _mod = dlsym(dlh, "mod_" #n);						\
	if (!n ## _mod)									\
		die("Failed to resolve symbol from plugin: %s\n", "mod_" #n);		\
} while(0)
#define check_struct_size(x) do {							\
	unsigned long *uip;								\
	uip = dlsym(dlh, "__size_struct_" #x);						\
	if (!uip)									\
		die("Failed to resolve symbol from plugin: %s\n", "__size_struct_" #x);	\
	if (*uip != sizeof(struct x))							\
		die("Struct size mismatch in plugin: %s\n", #x);			\
} while(0)
#define check_struct_offset(x,y) do {							\
	unsigned long *uip;								\
	uip = dlsym(dlh, "__offset_struct_" #x "_" #y);					\
	if (!uip)									\
		die("Failed to resolve symbol from plugin: %s\n", 			\
		"__offset_struct_" #x "_" #y);						\
	if (*uip != (unsigned long) &(((struct x *) 0)->y))				\
		die("Struct offset mismatch in plugin: %s->%s\n", #x, #y);		\
	uip = dlsym(dlh, "__size_struct_" #x "_" #y);					\
	if (!uip)									\
		die("Failed to resolve symbol from plugin: %s\n", 			\
		"__size_struct_" #x "_" #y);						\
	if (*uip != sizeof(((struct x *) 0)->y))					\
		die("Struct member size mismatch in plugin: %s->%s\n", #x, #y);		\
} while(0)



struct main_context {
	struct poller		*p;
	struct callmaster	*m;
};




static int global_shutdown;

static char *pidfile;
static gboolean foreground;
static u_int32_t ipv4;
static u_int32_t adv_ipv4;
static struct in6_addr ipv6;
static struct in6_addr adv_ipv6;
static u_int32_t listenp;
static u_int16_t listenport;
static struct in6_addr udp_listenp;
static u_int16_t udp_listenport;
static struct in6_addr ng_listenp;
static u_int16_t ng_listenport;
static int tos;
static int table = -1;
static int no_fallback;
static int timeout;
static int silent_timeout;
static int port_min = 30000;
static int port_max = 40000;
static u_int32_t redis_ip;
static u_int16_t redis_port;
static int redis_db = -1;
static char *b2b_url;



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

	while (!global_shutdown) {
		ret = sigtimedwait(&ss, NULL, &ts);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			abort();
		}
		
		if (ret == SIGINT || ret == SIGTERM)
			global_shutdown = 1;
		else if (ret == SIGUSR1) {
		        if (g_atomic_int_get(&log_level) > 0) {
				g_atomic_int_add(&log_level, -1);
				setlogmask(LOG_UPTO(g_atomic_int_get(&log_level)));
				ilog(g_atomic_int_get(&log_level), "Set log level to %d\n",
						g_atomic_int_get(&log_level));
			}
		}
		else if (ret == SIGUSR2) {
		        if (g_atomic_int_get(&log_level) < 7) {
				g_atomic_int_add(&log_level, 1);
				setlogmask(LOG_UPTO(g_atomic_int_get(&log_level)));
				ilog(g_atomic_int_get(&log_level), "Set log level to %d\n",
						g_atomic_int_get(&log_level));
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



static int parse_ip_port(u_int32_t *ip, u_int16_t *port, char *s) {
	char *p = NULL;
	int ret = -1;

	p = strchr(s, ':');
	if (p) {
		*p++ = 0;
		*ip = inet_addr(s);
		if (*ip == -1)
			goto out;
		*port = atoi(p);
	}
	else {
		*ip = 0;
		if (strchr(s, '.'))
			goto out;
		*port = atoi(s);
	}
	if (!*port)
		goto out;

	ret = 0;

out:
	if (p)
		*--p = ':';
	return ret;
}

static int parse_ip6_port(struct in6_addr *ip6, u_int16_t *port, char *s) {
	u_int32_t ip;
	char *p;

	if (!parse_ip_port(&ip, port, s)) {
		if (ip)
			in4_to_6(ip6, ip);
		else
			*ip6 = in6addr_any;
		return 0;
	}
	if (*s != '[')
		return -1;
	p = strstr(s, "]:");
	if (!p)
		return -1;
	*p = '\0';
	if (inet_pton(AF_INET6, s+1, ip6) != 1)
		goto fail;
	*p = ']';
	*port = atoi(p+2);
	if (!*port)
		return -1;

	return 0;

fail:
	*p = ']';
	return -1;
}



static void options(int *argc, char ***argv) {
	char *ipv4s = NULL;
	char *adv_ipv4s = NULL;
	char *ipv6s = NULL;
	char *adv_ipv6s = NULL;
	char *listenps = NULL;
	char *listenudps = NULL;
	char *listenngs = NULL;
	char *redisps = NULL;
	int version = 0;

	GOptionEntry e[] = {
		{ "version",	'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",	NULL		},
		{ "table",	't', 0, G_OPTION_ARG_INT,	&table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&no_fallback,	"Only start when kernel module is available", NULL },
		{ "ip",		'i', 0, G_OPTION_ARG_STRING,	&ipv4s,		"Local IPv4 address for RTP",	"IP"		},
		{ "advertised-ip", 'a', 0, G_OPTION_ARG_STRING,	&adv_ipv4s,	"IPv4 address to advertise",	"IP"		},
		{ "ip6",	'I', 0, G_OPTION_ARG_STRING,	&ipv6s,		"Local IPv6 address for RTP",	"IP6"		},
		{ "advertised-ip6",'A',0,G_OPTION_ARG_STRING,	&adv_ipv6s,	"IPv6 address to advertise",	"IP6"		},
		{ "listen-tcp",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP46:]PORT"	},
		{ "listen-ng",	'n', 0, G_OPTION_ARG_STRING,	&listenngs,	"UDP port to listen on, NG protocol", "[IP46:]PORT"	},
		{ "tos",	'T', 0, G_OPTION_ARG_INT,	&tos,		"TOS value to set on streams",	"INT"		},
		{ "timeout",	'o', 0, G_OPTION_ARG_INT,	&timeout,	"RTP timeout",			"SECS"		},
		{ "silent-timeout",'s',0,G_OPTION_ARG_INT,	&silent_timeout,"RTP timeout for muted",	"SECS"		},
		{ "pidfile",	'p', 0, G_OPTION_ARG_STRING,	&pidfile,	"Write PID to file",		"FILE"		},
		{ "foreground",	'f', 0, G_OPTION_ARG_NONE,	&foreground,	"Don't fork to background",	NULL		},
		{ "port-min",	'm', 0, G_OPTION_ARG_INT,	&port_min,	"Lowest port to use for RTP",	"INT"		},
		{ "port-max",	'M', 0, G_OPTION_ARG_INT,	&port_max,	"Highest port to use for RTP",	"INT"		},
		{ "redis",	'r', 0, G_OPTION_ARG_STRING,	&redisps,	"Connect to Redis database",	"IP:PORT"	},
		{ "redis-db",	'R', 0, G_OPTION_ARG_INT,	&redis_db,	"Which Redis DB to use",	"INT"	},
		{ "b2b-url",	'b', 0, G_OPTION_ARG_STRING,	&b2b_url,	"XMLRPC URL of B2B UA"	,	"STRING"	},
		{ "log-level",	'L', 0, G_OPTION_ARG_INT,	(void *)&log_level,	"Mask log priorities above this level",	"INT"	},
		{ NULL, }
	};

	GOptionContext *c;
	GError *er = NULL;

	c = g_option_context_new(" - next-generation media proxy");
	g_option_context_add_main_entries(c, e, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		die("Bad command line: %s\n", er->message);

	if (version)
		die("%s\n", MEDIAPROXY_VERSION);

	if (!ipv4s)
		die("Missing option --ip\n");
	if (!listenps && !listenudps && !listenngs)
		die("Missing option --listen-tcp, --listen-udp or --listen-ng\n");

	ipv4 = inet_addr(ipv4s);
	if (ipv4 == -1)
		die("Invalid IPv4 address (--ip)\n");

	if (adv_ipv4s) {
		adv_ipv4 = inet_addr(adv_ipv4s);
		if (adv_ipv4 == -1)
			die("Invalid IPv4 address (--advertised-ip)\n");
	}

	if (ipv6s) {
		if (smart_pton(AF_INET6, ipv6s, &ipv6) != 1)
			die("Invalid IPv6 address (--ip6)\n");
	}
	if (adv_ipv6s) {
		if (smart_pton(AF_INET6, adv_ipv6s, &adv_ipv6) != 1)
			die("Invalid IPv6 address (--advertised-ip6)\n");
	}

	if (listenps) {
		if (parse_ip_port(&listenp, &listenport, listenps))
			die("Invalid IP or port (--listen-tcp)\n");
	}
	if (listenudps) {
		if (parse_ip6_port(&udp_listenp, &udp_listenport, listenudps))
			die("Invalid IP or port (--listen-udp)\n");
	}
	if (listenngs) {
		if (parse_ip6_port(&ng_listenp, &ng_listenport, listenngs))
			die("Invalid IP or port (--listen-ng)\n");
	}

	if (tos < 0 || tos > 255)
		die("Invalid TOS value\n");

	if (timeout <= 0)
		timeout = 60;
	if (silent_timeout <= 0)
		silent_timeout = 3600;

	if (redisps) {
		if (parse_ip_port(&redis_ip, &redis_port, redisps) || !redis_ip)
			die("Invalid IP or port (--redis)\n");
		if (redis_db < 0)
			die("Must specify Redis DB number (--redis-db) when using Redis\n");
	}
	
	if ((log_level < LOG_EMERG) || (log_level > LOG_DEBUG))
	        die("Invalid log level (--log_level)\n");
	setlogmask(LOG_UPTO(log_level));
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


static void init_everything() {
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	srandom(ts.tv_sec ^ ts.tv_nsec);
	SSL_library_init();
	SSL_load_error_strings();

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(NULL);
#endif
	openlog("rtpengine", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	signals();
	resources();
	sdp_init();
	dtls_init();
}

void redis_mod_verify(void *dlh) {
	dlresolve(redis_new);
	dlresolve(redis_restore);
	dlresolve(redis_update);
	dlresolve(redis_delete);
	dlresolve(redis_wipe);

	check_struct_size(call);
	check_struct_size(packet_stream);
	check_struct_size(call_media);
	check_struct_size(call_monologue);
	check_struct_size(crypto_suite);
	check_struct_size(crypto_context);

	check_struct_offset(call, callmaster);
	check_struct_offset(call, master_lock);
	check_struct_offset(call, monologues);
	check_struct_offset(call, tags);
	check_struct_offset(call, streams);
	check_struct_offset(call, stream_fds);
	check_struct_offset(call, dtls_cert);
	check_struct_offset(call, callid);
	check_struct_offset(call, last_signal);

	check_struct_offset(packet_stream, media);
	check_struct_offset(packet_stream, call);
	check_struct_offset(packet_stream, rtcp_sibling);
	check_struct_offset(packet_stream, handler);
	check_struct_offset(packet_stream, crypto);
	check_struct_offset(packet_stream, dtls_cert);
	check_struct_offset(packet_stream, ps_flags);

	check_struct_offset(call_media, monologue);
	check_struct_offset(call_media, call);
	check_struct_offset(call_media, protocol);
	check_struct_offset(call_media, fingerprint);
	check_struct_offset(call_media, streams);
	check_struct_offset(call_media, media_flags);

	check_struct_offset(call_monologue, call);
	check_struct_offset(call_monologue, tag);
	check_struct_offset(call_monologue, created);
	check_struct_offset(call_monologue, other_tags);
	check_struct_offset(call_monologue, active_dialogue);
	check_struct_offset(call_monologue, medias);

	check_struct_offset(stream_fd, fd);
	check_struct_offset(stream_fd, call);
	check_struct_offset(stream_fd, stream);
	check_struct_offset(stream_fd, dtls);
}

void create_everything(struct main_context *ctx) {
	struct callmaster_config mc;
	struct control_tcp *ct;
	struct control_udp *cu;
	struct control_ng *cn;
	int kfd = -1;
	void *dlh;
	const char **strp;

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
		die("poller creation failed\n");

	ctx->m = callmaster_new(ctx->p);
	if (!ctx->m)
		die("callmaster creation failed\n");

	dtls_timer(ctx->p);

	ZERO(mc);
	mc.kernelfd = kfd;
	mc.kernelid = table;
	mc.ipv4 = ipv4;
	mc.adv_ipv4 = adv_ipv4;
	mc.ipv6 = ipv6;
	mc.adv_ipv6 = adv_ipv6;
	mc.port_min = port_min;
	mc.port_max = port_max;
	mc.timeout = timeout;
	mc.silent_timeout = silent_timeout;
	mc.tos = tos;
	mc.b2b_url = b2b_url;

	ct = NULL;
	if (listenport) {
		ct = control_tcp_new(ctx->p, listenp, listenport, ctx->m);
		if (!ct)
			die("Failed to open TCP control connection port\n");
	}

	cu = NULL;
	if (udp_listenport) {
		callmaster_exclude_port(ctx->m, udp_listenport);
		cu = control_udp_new(ctx->p, udp_listenp, udp_listenport, ctx->m);
		if (!cu)
			die("Failed to open UDP control connection port\n");
	}

	cn = NULL;
	if (ng_listenport) {
		callmaster_exclude_port(ctx->m, ng_listenport);
		cn = control_ng_new(ctx->p, ng_listenp, ng_listenport, ctx->m);
		if (!cn)
			die("Failed to open UDP control connection port\n");
	}

	if (redis_ip) {
		dlh = dlopen(MP_PLUGIN_DIR "/rtpengine-redis.so", RTLD_NOW | RTLD_GLOBAL);
		if (!dlh && !g_file_test(MP_PLUGIN_DIR "/rtpengine-redis.so", G_FILE_TEST_IS_REGULAR)
				&& g_file_test("../../rtpengine-redis/redis.so", G_FILE_TEST_IS_REGULAR))
			dlh = dlopen("../../rtpengine-redis/redis.so", RTLD_NOW | RTLD_GLOBAL);
		if (!dlh)
			die("Failed to open redis plugin, aborting (%s)\n", dlerror());
		strp = dlsym(dlh, "__module_version");
		if (!strp || !*strp || strcmp(*strp, "redis/4"))
			die("Incorrect redis module version: %s\n", *strp);
		redis_mod_verify(dlh);
		mc.redis = redis_new_mod(redis_ip, redis_port, redis_db);
		if (!mc.redis)
			die("Cannot start up without Redis database\n");
	}

	ctx->m->conf = mc;

	if (!foreground)
		daemonize();
	wpidfile();

	if (redis_restore(ctx->m, mc.redis))
		die("Refusing to continue without working Redis database\n");
}

static void timer_loop(void *d) {
	struct poller *p = d;

	while (!global_shutdown)
		poller_timers_wait_run(p, 100);
}

static void poller_loop(void *d) {
	struct poller *p = d;

	while (!global_shutdown)
		poller_poll(p, 100);
}

int main(int argc, char **argv) {
	struct main_context ctx;

	init_everything();
	options(&argc, &argv);
	create_everything(&ctx);

	ilog(LOG_INFO, "Startup complete, version %s", MEDIAPROXY_VERSION);

	thread_create_detach(sighandler, NULL);
	thread_create_detach(timer_loop, ctx.p);
	thread_create_detach(poller_loop, ctx.p);
	thread_create_detach(poller_loop, ctx.p);
	thread_create_detach(poller_loop, ctx.p);
	thread_create_detach(poller_loop, ctx.p);

	while (!global_shutdown) {
		usleep(100000);
		threads_join_all(0);
	}

	threads_join_all(1);

	ilog(LOG_INFO, "Version %s shutting down", MEDIAPROXY_VERSION);

	return 0;
}
