#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <glib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "poller.h"
#include "control.h"
#include "control_udp.h"
#include "aux.h"
#include "log.h"
#include "call.h"
#include "kernel.h"
#ifndef NO_REDIS
#include "redis.h"
#endif
#include "build_time.h"




#define die(x...) do { fprintf(stderr, x); exit(-1); } while(0)





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
static int timeout;
static int silent_timeout;
static int port_min;
static int port_max;
#ifndef NO_REDIS
static u_int32_t redis_ip;
static u_int16_t redis_port;
static int redis_db = -1;
#endif




static void signals(void) {
	signal(SIGPIPE, SIG_IGN);
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
	if (inet_pton(AF_INET6, s+1, ip6) != 1)
		return -1;
	p = strstr(s, "]:");
	if (!p)
		return -1;
	*port = atoi(p+2);
	if (!*port)
		return -1;

	return 0;
}



static void options(int *argc, char ***argv) {
	static char *ipv4s;
	static char *adv_ipv4s;
	static char *ipv6s;
	static char *adv_ipv6s;
	static char *listenps;
	static char *listenudps;
#ifndef NO_REDIS
	static char *redisps;
#endif
	static int version;

	static GOptionEntry e[] = {
		{ "version",	'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",	NULL		},
		{ "table",	't', 0, G_OPTION_ARG_INT,	&table,		"Kernel table to use",		"INT"		},
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
#ifndef NO_REDIS
		{ "redis",	'r', 0, G_OPTION_ARG_STRING,	&redisps,	"Connect to Redis database",	"IP:PORT"	},
		{ "redis-db",	'R', 0, G_OPTION_ARG_INT,	&redis_db,	"Which Redis DB to use",	"INT"	},
#endif
		{ NULL, }
	};

	GOptionContext *c;
	GError *er = NULL;

	c = g_option_context_new(" - next-generation media proxy");
	g_option_context_add_main_entries(c, e, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		die("Bad command line: %s\n", er->message);

	if (version)
		die("Build time: %s\n", BUILD_TIME);

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

#ifndef NO_REDIS
	if (redisps) {
		if (parse_ip_port(&redis_ip, &redis_port, redisps) || !redis_ip)
			die("Invalid IP or port (--redis)\n");
		if (redis_db < 0)
			die("Must specify Redis DB number (--redis-db) when using Redis\n");
	}
#endif
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
	struct control *c;
	struct control_udp *cu;
	int kfd;
	int ret;

	options(&argc, &argv);
	signals();
	resources();


	if (kernel_create_table(table))
		die("Failed to create kernel table %i\n", table);
	kfd = kernel_open_table(table);
	if (kfd == -1)
		die("Failed to open kernel table %i\n", table);

	p = poller_new();
	if (!p)
		die("poller creation failed\n");

	m = callmaster_new(p);
	if (!m)
		return -1;
	m->kernelfd = kfd;
	m->kernelid = table;
	m->ipv4 = ipv4;
	m->adv_ipv4 = adv_ipv4;
	m->ipv6 = ipv6;
	m->adv_ipv6 = adv_ipv6;
	m->port_min = port_min;
	m->port_max = port_max;
	m->timeout = timeout;
	m->silent_timeout = silent_timeout;
	m->tos = tos;

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

#ifndef NO_REDIS
	if (redis_ip) {
		m->redis = redis_new(redis_ip, redis_port, redis_db);
		if (!m->redis)
			die("Cannot start up without Redis database\n");
	}
#endif

	mylog(LOG_INFO, "Startup complete");

	if (!foreground)
		daemonize();
	wpidfile();

#ifndef NO_REDIS
	if (m->redis) {
		if (redis_restore(m))
			die("Refusing to continue without working Redis database\n");
	}
#endif

	for (;;) {
		ret = poller_poll(p, 100);
		if (ret == -1)
			break;
	}

	return 0;
}
