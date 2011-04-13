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




#define die(x...) do { fprintf(stderr, x); exit(-1); } while(0)





static char *pidfile;
static gboolean foreground;
static u_int32_t ip;
static u_int32_t listenp;
static u_int16_t listenport;
static u_int32_t udp_listenp;
static u_int16_t udp_listenport;
static int tos;
static int table;
static int timeout;
static int silent_timeout;




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



static void options(int *argc, char ***argv) {
	static char *ips;
	static char *listenps;
	static char *listenudps;
	static GOptionEntry e[] = {
		{ "table",	't', 0, G_OPTION_ARG_INT,	&table,		"Kernel table to use",		"INT"		},
		{ "ip",		'i', 0, G_OPTION_ARG_STRING,	&ips,		"Local IP address",		"IP"		},
		{ "listen",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP:]PORT"	},
		{ "tos",	'T', 0, G_OPTION_ARG_INT,	&tos,		"TOS value to set on streams",	"INT"		},
		{ "timeout",	'o', 0, G_OPTION_ARG_INT,	&timeout,	"RTP timeout",			"SECS"		},
		{ "silent-timeout",'s',0,G_OPTION_ARG_INT,	&silent_timeout,"RTP timeout for muted",	"SECS"		},
		{ "pidfile",	'p', 0, G_OPTION_ARG_STRING,	&pidfile,	"Write PID to file",		"FILE"		},
		{ "foreground",	'f', 0, G_OPTION_ARG_NONE,	&foreground,	"Don't fork to background",	NULL		},
		{ NULL, }
	};

	GOptionContext *c;
	GError *er = NULL;

	c = g_option_context_new(" - next-generation media proxy");
	g_option_context_add_main_entries(c, e, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		die("Bad command line: %s\n", er->message);

	if (!ips)
		die("Missing option IP\n");
	if (!listenps || !listenudps)
		die("Missing option LISTEN or LISTEN-UDP\n");

	ip = inet_addr(ips);
	if (ip == -1)
		die("Invalid IP\n");

	if (listenps) {
		if (parse_ip_port(&listenp, &listenport, listenps))
			die("Invalid IP or port");
	}
	if (listenudps) {
		if (parse_ip_port(&udp_listenp, &udp_listenport, listenudps))
			die("Invalid IP or port");
	}

	if (tos < 0 || tos > 255)
		die("Invalid TOS value");

	if (timeout <= 0)
		timeout = 60;
	if (silent_timeout <= 0)
		silent_timeout = 3600;
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
	m->ip = ip;
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

	mylog(LOG_INFO, "Startup complete");

	if (!foreground)
		daemonize();
	wpidfile();

	for (;;) {
		ret = poller_poll(p, 100);
		if (ret == -1)
			break;
	}

	return 0;
}
