#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <glib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include "poller.h"
#include "control.h"
#include "control_udp.h"
#include "aux.h"
#include "log.h"
#include "call.h"
#include "kernel.h"
#include "redis.h"




#define die(x...) do { fprintf(stderr, x); exit(-1); } while(0)
#define dlresolve(m,n) do {										\
				n = dlsym(m, "mod_" #n);						\
				if (!n)									\
					die("Failed to resolve symbol from plugin: %s\n", #n);		\
			} while(0)





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
static int tos;
static int table;
static int no_fallback;
static int timeout;
static int silent_timeout;
static int port_min;
static int port_max;
static u_int32_t redis_ip;
static u_int16_t redis_port;
static int redis_db = -1;
static char *b2b_url;




gpointer sighandler(gpointer x) {
	sigset_t ss;
	int ret, sig;

	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGABRT);
	sigaddset(&ss, SIGSEGV);
	sigaddset(&ss, SIGQUIT);

	while (!global_shutdown) {
		ret = sigwait(&ss, &sig);
		if (ret)
			abort();

		if (sig == SIGINT || sig == SIGTERM)
			global_shutdown = 1;
		else
			abort();
	}

	return NULL;
}


static void signals(void) {
	sigset_t ss;

	sigfillset(&ss);
	sigprocmask(SIG_SETMASK, &ss, NULL);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);
}

static int rlim(int res, rlim_t val) {
	struct rlimit rlim;

	ZERO(rlim);
	rlim.rlim_cur = rlim.rlim_max = val;
	return setrlimit(res, &rlim);
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
	static char *ipv4s;
	static char *adv_ipv4s;
	static char *ipv6s;
	static char *adv_ipv6s;
	static char *listenps;
	static char *listenudps;
	static char *redisps;
	static int version;

	static GOptionEntry e[] = {
		{ "version",	'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",	NULL		},
		{ "table",	't', 0, G_OPTION_ARG_INT,	&table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&no_fallback,	"Only start when kernel module is available", NULL },
		{ "ip",		'i', 0, G_OPTION_ARG_STRING,	&ipv4s,		"Local IPv4 address for RTP",	"IP"		},
		{ "advertised-ip", 'a', 0, G_OPTION_ARG_STRING,	&adv_ipv4s,	"IPv4 address to advertise",	"IP"		},
		{ "ip6",	'I', 0, G_OPTION_ARG_STRING,	&ipv6s,		"Local IPv6 address for RTP",	"IP6"		},
		{ "advertised-ip6",'A',0,G_OPTION_ARG_STRING,	&adv_ipv6s,	"IPv6 address to advertise",	"IP6"		},
		{ "listen",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP46:]PORT"	},
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
	if (!listenps && !listenudps)
		die("Missing option --listen or --listen-udp\n");

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
			die("Invalid IP or port (--listen)\n");
	}
	if (listenudps) {
		if (parse_ip6_port(&udp_listenp, &udp_listenport, listenudps))
			die("Invalid IP or port (--listen-udp)\n");
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
}


static void daemonize(void) {
	printf("Going to background...\n");
	if (fork())
		_exit(0);
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
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


int main(int argc, char **argv) {
	struct poller *p;
	struct callmaster *m;
	struct callmaster_config mc;
	struct control *c;
	struct control_udp *cu;
	int kfd = -1;
	int ret;
	void *dlh;
	const char **strp;
	GThread *signal_handler_thread;

	options(&argc, &argv);
	g_thread_init(NULL);
	signals();
	resources();


	if (table >= 0 && kernel_create_table(table)) {
		fprintf(stderr, "FAILED TO CREATE KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
		mylog(LOG_CRIT, "FAILED TO CREATE KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
		table = -1;
		if (no_fallback)
			exit(-1);
	}
	if (table >= 0) {
		kfd = kernel_open_table(table);
		if (kfd == -1) {
			fprintf(stderr, "FAILED TO OPEN KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
			mylog(LOG_CRIT, "FAILED TO OPEN KERNEL TABLE %i, KERNEL FORWARDING DISABLED\n", table);
			table = -1;
			if (no_fallback)
				exit(-1);
		}
	}

	p = poller_new();
	if (!p)
		die("poller creation failed\n");

	m = callmaster_new(p);
	if (!m)
		return -1;

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

	c = NULL;
	if (listenport) {
		c = control_new(p, listenp, listenport, m);
		if (!c)
			die("Failed to open TCP control connection port\n");
	}

	cu = NULL;
	if (udp_listenport) {
		cu = control_udp_new(p, udp_listenp, udp_listenport, m);
		if (!cu)
			die("Failed to open UDP control connection port\n");
	}

	if (redis_ip) {
		dlh = dlopen(MP_PLUGIN_DIR "/mediaproxy-redis.so", RTLD_NOW | RTLD_GLOBAL);
		if (!dlh)
			die("Failed to open redis plugin, aborting (%s)\n", dlerror());
		strp = dlsym(dlh, "__module_version");
		if (!strp || !*strp || strcmp(*strp, "redis/1.0.1"))
			die("Incorrect redis module version: %s\n", *strp);

		dlresolve(dlh, redis_new);
		dlresolve(dlh, redis_restore);
		dlresolve(dlh, redis_update);
		dlresolve(dlh, redis_delete);
		dlresolve(dlh, redis_wipe);

		mc.redis = redis_new(redis_ip, redis_port, redis_db);
		if (!mc.redis)
			die("Cannot start up without Redis database\n");
	}

	callmaster_config(m, &mc);
	mylog(LOG_INFO, "Startup complete, version %s", MEDIAPROXY_VERSION);

	if (!foreground)
		daemonize();
	wpidfile();

	if (mc.redis) {
		if (redis_restore(m, mc.redis))
			die("Refusing to continue without working Redis database\n");
	}

	signal_handler_thread = g_thread_create(sighandler, NULL, TRUE, NULL);
	if (!signal_handler_thread)
		die("Failed to create thread\n");

	while (!global_shutdown) {
		ret = poller_poll(p, 100);
		if (ret == -1)
			break;
	}

	g_thread_join(signal_handler_thread);

	mylog(LOG_INFO, "Version %s shutting down", MEDIAPROXY_VERSION);

	return 0;
}
