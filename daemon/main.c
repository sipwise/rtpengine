#include "main.h"

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
#include <ifaddrs.h>
#include <net/if.h>

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
#include "rtcp.h"
#include "iptables.h"
#include "statistics.h"
#include "graphite.h"
#include "codeclib.h"
#include "load.h"
#include "ssllib.h"
#include "media_player.h"
#include "dtmf.h"
#include "jitter_buffer.h"



struct poller *rtpe_poller;
struct rtpengine_config initial_rtpe_config;

struct rtpengine_config rtpe_config = {
	// non-zero defaults
	.kernel_table = -1,
	.max_sessions = -1,
	.delete_delay = 30,
	.redis_subscribed_keyspaces = G_QUEUE_INIT,
	.redis_expires_secs = 86400,
	.interfaces = G_QUEUE_INIT,
	.homer_protocol = SOCK_DGRAM,
	.homer_id = 2001,
	.port_min = 30000,
	.port_max = 40000,
	.redis_db = -1,
	.redis_write_db = -1,
	.redis_allowed_errors = -1,
	.redis_disable_time = 10,
	.redis_connect_timeout = 1000,
	.rec_method = "pcap",
	.rec_format = "raw",
	.media_num_threads = -1,
};


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

	while (!rtpe_shutdown) {
		ret = sigtimedwait(&ss, NULL, &ts);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			abort();
		}

		if (ret == SIGINT || ret == SIGTERM)
			rtpe_shutdown = 1;
		else if (ret == SIGUSR1) {
		        if (get_log_level() > 0) {
				g_atomic_int_add(&rtpe_config.common.log_level, -1);
				ilog(get_log_level(), "Set log level to %d\n",
						get_log_level());
			}
		}
		else if (ret == SIGUSR2) {
		        if (get_log_level() < 7) {
				g_atomic_int_add(&rtpe_config.common.log_level, 1);
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



static int if_addr_parse(GQueue *q, char *s, struct ifaddrs *ifas) {
	str name;
	char *c;
	sockaddr_t *addr, adv;
	GQueue addrs = G_QUEUE_INIT;
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
	addr = g_slice_alloc(sizeof(*addr));
	if (!sockaddr_parse_any(addr, s)) {
		if (is_addr_unspecified(addr))
			return -1;
		g_queue_push_tail(&addrs, addr);
	}
	else {
		// could be an interface name?
		ilog(LOG_DEBUG, "Could not parse '%s' as network address, checking to see if "
				"it's an interface", s);
		for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
			if (strcmp(ifa->ifa_name, s))
				continue;
			if (!(ifa->ifa_flags & IFF_UP))
				continue;
			if (!ifa->ifa_addr)
				continue;
			if (ifa->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *sin = (void *) ifa->ifa_addr;
				addr->family = __get_socket_family_enum(SF_IP4);
				addr->u.ipv4 = sin->sin_addr;
			}
			else if (ifa->ifa_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin = (void *) ifa->ifa_addr;
				if (sin->sin6_scope_id)
					continue; // link-local
				addr->family = __get_socket_family_enum(SF_IP6);
				addr->u.ipv6 = sin->sin6_addr;
			}
			else
				continue;

			// got one
			ilog(LOG_DEBUG, "Determined address %s for interface '%s'",
					sockaddr_print_buf(addr), s);
			g_queue_push_tail(&addrs, addr);
			addr = g_slice_alloc(sizeof(*addr));
		}

		// free last unused entry
		g_slice_free1(sizeof(*addr), addr);
	}

	if (!addrs.length) // nothing found
		return -1;

	ZERO(adv);
	if (c) {
		if (sockaddr_parse_any(&adv, c))
			return -1;
		if (is_addr_unspecified(&adv))
			return -1;
	}

	while ((addr = g_queue_pop_head(&addrs))) {
		ifa = g_slice_alloc0(sizeof(*ifa));
		ifa->name = name;
		ifa->local_address.addr = *addr;
		ifa->local_address.type = socktype_udp;
		ifa->advertised_address.addr = adv;
		if (is_addr_unspecified(&ifa->advertised_address.addr))
			ifa->advertised_address.addr = *addr;
		ifa->advertised_address.type = ifa->local_address.type;
		ifa->port_min = rtpe_config.port_min;
		ifa->port_max = rtpe_config.port_max;

		// handle "base:suffix" separation for round-robin selection
		ifa->name_rr_spec = ifa->name;
		str_token(&ifa->name_base, &ifa->name_rr_spec, ':'); // sets name_rr_spec to null string if no ':' found

		g_queue_push_tail(q, ifa);

		g_slice_free1(sizeof(*addr), addr);
	}

	return 0;
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
	if (endpoint_parse_any_getaddrinfo_full(ep, str))
		return -1;
	return 0;
}



static void options(int *argc, char ***argv) {
	char **if_a = NULL;
	char **ks_a = NULL;
	unsigned long uint_keyspace_db;
	str str_keyspace_db;
	char **iter;
	char *listenps = NULL;
	char *listenudps = NULL;
	char *listenngs = NULL;
	char *listencli = NULL;
	char *graphitep = NULL;
	char *graphite_prefix_s = NULL;
	char *redisps = NULL;
	char *redisps_write = NULL;
	char *log_facility_cdr_s = NULL;
	char *log_facility_rtcp_s = NULL;
	char *log_facility_dtmf_s = NULL;
	char *log_format = NULL;
	int sip_source = 0;
	char *homerp = NULL;
	char *homerproto = NULL;
	char *endptr;
	int codecs = 0;
	double max_load = 0;
	double max_cpu = 0;
	char *dtmf_udp_ep = NULL;
	char *endpoint_learning = NULL;

	GOptionEntry e[] = {
		{ "table",	't', 0, G_OPTION_ARG_INT,	&rtpe_config.kernel_table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&rtpe_config.no_fallback,	"Only start when kernel module is available", NULL },
		{ "interface",	'i', 0, G_OPTION_ARG_STRING_ARRAY,&if_a,	"Local interface for RTP",	"[NAME/]IP[!IP]"},
		{ "subscribe-keyspace", 'k', 0, G_OPTION_ARG_STRING_ARRAY,&ks_a,	"Subscription keyspace list",	"INT INT ..."},
		{ "listen-tcp",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP46|HOSTNAME:]PORT"	},
		{ "listen-ng",	'n', 0, G_OPTION_ARG_STRING,	&listenngs,	"UDP port to listen on, NG protocol", "[IP46|HOSTNAME:]PORT"	},
		{ "listen-cli", 'c', 0, G_OPTION_ARG_STRING,    &listencli,     "UDP port to listen on, CLI",   "[IP46|HOSTNAME:]PORT"     },
		{ "graphite", 'g', 0, G_OPTION_ARG_STRING,    &graphitep,     "Address of the graphite server",   "IP46|HOSTNAME:PORT"     },
		{ "graphite-interval",  'G', 0, G_OPTION_ARG_INT,    &rtpe_config.graphite_interval,  "Graphite send interval in seconds",    "INT"   },
		{ "graphite-prefix",0,  0,	G_OPTION_ARG_STRING, &graphite_prefix_s, "Prefix for graphite line", "STRING"},
		{ "tos",	'T', 0, G_OPTION_ARG_INT,	&rtpe_config.default_tos,		"Default TOS value to set on streams",	"INT"		},
		{ "control-tos",0 , 0, G_OPTION_ARG_INT,	&rtpe_config.control_tos,		"Default TOS value to set on control-ng",	"INT"		},
		{ "timeout",	'o', 0, G_OPTION_ARG_INT,	&rtpe_config.timeout,	"RTP timeout",			"SECS"		},
		{ "silent-timeout",'s',0,G_OPTION_ARG_INT,	&rtpe_config.silent_timeout,"RTP timeout for muted",	"SECS"		},
		{ "final-timeout",'a',0,G_OPTION_ARG_INT,	&rtpe_config.final_timeout,	"Call timeout",			"SECS"		},
		{ "offer-timeout",0,0,	G_OPTION_ARG_INT,	&rtpe_config.offer_timeout,	"Timeout for incomplete one-sided calls",	"SECS"		},
		{ "port-min",	'm', 0, G_OPTION_ARG_INT,	&rtpe_config.port_min,	"Lowest port to use for RTP",	"INT"		},
		{ "port-max",	'M', 0, G_OPTION_ARG_INT,	&rtpe_config.port_max,	"Highest port to use for RTP",	"INT"		},
		{ "redis",	'r', 0, G_OPTION_ARG_STRING,	&redisps,	"Connect to Redis database",	"[PW@]IP:PORT/INT"	},
		{ "redis-write",'w', 0, G_OPTION_ARG_STRING,    &redisps_write, "Connect to Redis write database",      "[PW@]IP:PORT/INT"       },
		{ "redis-num-threads", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_num_threads, "Number of Redis restore threads",      "INT"       },
		{ "redis-expires", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_expires_secs, "Expire time in seconds for redis keys",      "INT"       },
		{ "no-redis-required", 'q', 0, G_OPTION_ARG_NONE, &rtpe_config.no_redis_required, "Start no matter of redis connection state", NULL },
		{ "redis-allowed-errors", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_allowed_errors, "Number of allowed errors before redis is temporarily disabled", "INT" },
		{ "redis-disable-time", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_disable_time, "Number of seconds redis communication is disabled because of errors", "INT" },
		{ "redis-cmd-timeout", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_cmd_timeout, "Sets a timeout in milliseconds for redis commands", "INT" },
		{ "redis-connect-timeout", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_connect_timeout, "Sets a timeout in milliseconds for redis connections", "INT" },
		{ "b2b-url",	'b', 0, G_OPTION_ARG_STRING,	&rtpe_config.b2b_url,	"XMLRPC URL of B2B UA"	,	"STRING"	},
		{ "log-facility-cdr",0,  0, G_OPTION_ARG_STRING, &log_facility_cdr_s, "Syslog facility to use for logging CDRs", "daemon|local0|...|local7"},
		{ "log-facility-rtcp",0,  0, G_OPTION_ARG_STRING, &log_facility_rtcp_s, "Syslog facility to use for logging RTCP", "daemon|local0|...|local7"},
		{ "log-facility-dtmf",0,  0, G_OPTION_ARG_STRING, &log_facility_dtmf_s, "Syslog facility to use for logging DTMF", "daemon|local0|...|local7"},
		{ "log-format",	0, 0,	G_OPTION_ARG_STRING,	&log_format,	"Log prefix format",		"default|parsable"},
		{ "dtmf-log-dest", 0,0,	G_OPTION_ARG_STRING,	&dtmf_udp_ep,	"Destination address for DTMF logging via UDP",	"IP46|HOSTNAME:PORT"	},
		{ "xmlrpc-format",'x', 0, G_OPTION_ARG_INT,	&rtpe_config.fmt,	"XMLRPC timeout request format to use. 0: SEMS DI, 1: call-id only, 2: Kamailio",	"INT"	},
		{ "num-threads",  0, 0, G_OPTION_ARG_INT,	&rtpe_config.num_threads,	"Number of worker threads to create",	"INT"	},
		{ "media-num-threads",  0, 0, G_OPTION_ARG_INT,	&rtpe_config.media_num_threads,	"Number of worker threads for media playback",	"INT"	},
		{ "delete-delay",  'd', 0, G_OPTION_ARG_INT,    &rtpe_config.delete_delay,  "Delay for deleting a session from memory.",    "INT"   },
		{ "sip-source",  0,  0, G_OPTION_ARG_NONE,	&sip_source,	"Use SIP source address by default",	NULL	},
		{ "dtls-passive", 0, 0, G_OPTION_ARG_NONE,	&dtls_passive_def,"Always prefer DTLS passive role",	NULL	},
		{ "max-sessions", 0, 0, G_OPTION_ARG_INT,	&rtpe_config.max_sessions,	"Limit of maximum number of sessions",	"INT"	},
		{ "max-load",	0, 0,	G_OPTION_ARG_DOUBLE,	&max_load,	"Reject new sessions if load averages exceeds this value",	"FLOAT"	},
		{ "max-cpu",	0, 0,	G_OPTION_ARG_DOUBLE,	&max_cpu,	"Reject new sessions if CPU usage (in percent) exceeds this value",	"FLOAT"	},
		{ "max-bandwidth",0, 0,	G_OPTION_ARG_INT64,	&rtpe_config.bw_limit,	"Reject new sessions if bandwidth usage (in bytes per second) exceeds this value",	"INT"	},
		{ "homer",	0,  0, G_OPTION_ARG_STRING,	&homerp,	"Address of Homer server for RTCP stats","IP46|HOSTNAME:PORT"},
		{ "homer-protocol",0,0,G_OPTION_ARG_STRING,	&homerproto,	"Transport protocol for Homer (default udp)",	"udp|tcp"	},
		{ "homer-id",	0,  0, G_OPTION_ARG_INT,	&rtpe_config.homer_id,	"'Capture ID' to use within the HEP protocol", "INT"	},
		{ "recording-dir", 0, 0, G_OPTION_ARG_STRING,	&rtpe_config.spooldir,	"Directory for storing pcap and metadata files", "FILE"	},
		{ "recording-method",0, 0, G_OPTION_ARG_STRING,	&rtpe_config.rec_method,	"Strategy for call recording",		"pcap|proc"	},
		{ "recording-format",0, 0, G_OPTION_ARG_STRING,	&rtpe_config.rec_format,	"File format for stored pcap files",	"raw|eth"	},
#ifdef WITH_IPTABLES_OPTION
		{ "iptables-chain",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.iptables_chain,"Add explicit firewall rules to this iptables chain","STRING" },
#endif
		{ "codecs",	0, 0,	G_OPTION_ARG_NONE,	&codecs,		"Print a list of supported codecs and exit",	NULL },
		{ "scheduling",	0, 0,	G_OPTION_ARG_STRING,	&rtpe_config.scheduling,"Thread scheduling policy",	"default|none|fifo|rr|other|batch|idle" },
		{ "priority",	0, 0,	G_OPTION_ARG_INT,	&rtpe_config.priority,	"Thread scheduling priority",	"INT" },
		{ "idle-scheduling",0, 0,G_OPTION_ARG_STRING,	&rtpe_config.idle_scheduling,"Idle thread scheduling policy",	"default|none|fifo|rr|other|batch|idle" },
		{ "idle-priority",0, 0,	G_OPTION_ARG_INT,	&rtpe_config.idle_priority,"Idle thread scheduling priority",	"INT" },
		{ "log-srtp-keys",'F', 0, G_OPTION_ARG_NONE,	&rtpe_config.log_keys,	"Log SRTP keys to error log", NULL },
		{ "mysql-host",	0,   0,	G_OPTION_ARG_STRING,	&rtpe_config.mysql_host,"MySQL host for stored media files","HOST|IP"	},
		{ "mysql-port",	0,   0,	G_OPTION_ARG_INT,	&rtpe_config.mysql_port,"MySQL port"				,"INT"		},
		{ "mysql-user",	0,   0,	G_OPTION_ARG_STRING,	&rtpe_config.mysql_user,"MySQL connection credentials",		"USERNAME"	},
		{ "mysql-pass",	0,   0,	G_OPTION_ARG_STRING,	&rtpe_config.mysql_pass,"MySQL connection credentials",		"PASSWORD"	},
		{ "mysql-query",0,   0,	G_OPTION_ARG_STRING,	&rtpe_config.mysql_query,"MySQL select query",			"STRING"	},
		{ "endpoint-learning",0,0,G_OPTION_ARG_STRING,	&endpoint_learning,	"RTP endpoint learning algorithm",	"delayed|immediate|off|heuristic"	},
		{ "jitter-buffer",0, 0,	G_OPTION_ARG_INT,	&rtpe_config.jb_length,	"Size of jitter buffer",		"INT" },
		{ "jb-clock-drift",0,0,	G_OPTION_ARG_NONE,	&rtpe_config.jb_clock_drift,"Compensate for source clock drift",NULL },

		{ NULL, }
	};

	config_load(argc, argv, e, " - next-generation media proxy",
			"/etc/rtpengine/rtpengine.conf", "rtpengine", &rtpe_config.common);

	if (codecs) {
		codeclib_init(1);
		exit(0);
	}

	if (!if_a)
		die("Missing option --interface");
	if (!listenps && !listenudps && !listenngs)
		die("Missing option --listen-tcp, --listen-udp or --listen-ng");

	struct ifaddrs *ifas;
	if (getifaddrs(&ifas)) {
		ifas = NULL;
		ilog(LOG_WARN, "Failed to retrieve list of network interfaces: %s", strerror(errno));
	}
	for (iter = if_a; *iter; iter++) {
		int ret = if_addr_parse(&rtpe_config.interfaces, *iter, ifas);
		if (ret)
			die("Invalid interface specification: '%s'", *iter);
	}
	if (ifas)
		freeifaddrs(ifas);

	if (!rtpe_config.interfaces.length)
		die("Cannot start without any configured interfaces");

	if (ks_a) {
		for (iter = ks_a; *iter; iter++) {
			str_keyspace_db.s = *iter;
			str_keyspace_db.len = strlen(*iter);
			uint_keyspace_db = strtoul(str_keyspace_db.s, &endptr, 10);

			if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) ||
			    (errno != 0 && uint_keyspace_db == 0)) {
				ilog(LOG_ERR, "Fail adding keyspace '%.*s' to redis notifications; errono=%d\n", str_keyspace_db.len, str_keyspace_db.s, errno);
			} else if (endptr == str_keyspace_db.s) {
				ilog(LOG_ERR, "Fail adding keyspace '%.*s' to redis notifications; no digits found\n", str_keyspace_db.len, str_keyspace_db.s);
			} else {
				g_queue_push_tail(&rtpe_config.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db));
			}
		}
	}

	if (listenps) {
		if (endpoint_parse_any_getaddrinfo(&rtpe_config.tcp_listen_ep, listenps))
			die("Invalid IP or port '%s' (--listen-tcp)", listenps);
	}
	if (listenudps) {
		if (endpoint_parse_any_getaddrinfo(&rtpe_config.udp_listen_ep, listenudps))
			die("Invalid IP or port '%s' (--listen-udp)", listenudps);
	}
	if (listenngs) {
		if (endpoint_parse_any_getaddrinfo(&rtpe_config.ng_listen_ep, listenngs))
			die("Invalid IP or port '%s' (--listen-ng)", listenngs);
	}

	if (listencli) {if (endpoint_parse_any_getaddrinfo(&rtpe_config.cli_listen_ep, listencli))
	    die("Invalid IP or port '%s' (--listen-cli)", listencli);
	}

	if (graphitep) {if (endpoint_parse_any_getaddrinfo_full(&rtpe_config.graphite_ep, graphitep))
	    die("Invalid IP or port '%s' (--graphite)", graphitep);
	}

	if (graphite_prefix_s)
		set_prefix(graphite_prefix_s);

	if (homerp) {
		if (endpoint_parse_any_getaddrinfo_full(&rtpe_config.homer_ep, homerp))
			die("Invalid IP or port '%s' (--homer)", homerp);
	}
	if (homerproto) {
		if (!strcmp(homerproto, "tcp"))
			rtpe_config.homer_protocol = SOCK_STREAM;
		else if (!strcmp(homerproto, "udp"))
			rtpe_config.homer_protocol = SOCK_DGRAM;
		else
			die("Invalid protocol '%s' (--homer-protocol)", homerproto);
	}

	if (rtpe_config.default_tos < 0 || rtpe_config.default_tos > 255)
		die("Invalid TOS value");

	if (rtpe_config.control_tos < 0 || rtpe_config.control_tos > 255)
		die("Invalid control-ng TOS value");

	if (rtpe_config.timeout <= 0)
		rtpe_config.timeout = 60;

	if (rtpe_config.silent_timeout <= 0)
		rtpe_config.silent_timeout = 3600;

	if (rtpe_config.offer_timeout <= 0)
		rtpe_config.offer_timeout = 3600;

	if (rtpe_config.final_timeout <= 0)
		rtpe_config.final_timeout = 0;

	if (redisps)
		if (redis_ep_parse(&rtpe_config.redis_ep, &rtpe_config.redis_db, &rtpe_config.redis_auth, "RTPENGINE_REDIS_AUTH_PW", redisps))
			die("Invalid Redis endpoint [IP:PORT/INT] '%s' (--redis)", redisps);

	if (redisps_write)
		if (redis_ep_parse(&rtpe_config.redis_write_ep, &rtpe_config.redis_write_db, &rtpe_config.redis_write_auth,
					"RTPENGINE_REDIS_WRITE_AUTH_PW", redisps_write))
			die("Invalid Redis endpoint [IP:PORT/INT] '%s' (--redis-write)", redisps_write);

	if (rtpe_config.fmt > 2)
		die("Invalid XMLRPC format");

	// XXX unify the log facility options
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

	if (log_facility_dtmf_s) {
		if (!parse_log_facility(log_facility_dtmf_s, &_log_facility_dtmf)) {
			print_available_log_facilities();
			die ("Invalid log facility for DTMF '%s' (--log-facility-dtmf)n", log_facility_dtmf_s);
		}
	}

	if (log_format) {
		if (!strcmp(log_format, "default"))
			rtpe_config.log_format = LF_DEFAULT;
		else if (!strcmp(log_format, "parsable"))
			rtpe_config.log_format = LF_PARSABLE;
		else
			die("Invalid --log-format option");
	}

	if (dtmf_udp_ep) {
		if (endpoint_parse_any_getaddrinfo_full(&rtpe_config.dtmf_udp_ep, dtmf_udp_ep))
			die("Invalid IP or port '%s' (--dtmf-log-dest)", dtmf_udp_ep);
	}

	if (!sip_source)
		trust_address_def = 1;

	rtpe_config.cpu_limit = max_cpu * 100;
	rtpe_config.load_limit = max_load * 100;

	if (rtpe_config.mysql_query) {
		// require exactly one %llu placeholder and allow no other % placeholders
		if (!strstr(rtpe_config.mysql_query, "%llu"))
			die("No '%%llu' present in --mysql-query='%s'", rtpe_config.mysql_query);
		const char *front = rtpe_config.mysql_query;
		unsigned int count = 0;
		const char *match;
		while ((match = strchr(front, '%'))) {
			front = match + 1;
			count++;
		}
		if (count != 1)
			die("Too many '%%' placeholders (%u) present in --mysql-query='%s'",
					count, rtpe_config.mysql_query);
	}

	enum endpoint_learning el_config = EL_DELAYED;
	if (endpoint_learning) {
		if (!strcasecmp(endpoint_learning, "delayed"))
			el_config = EL_DELAYED;
		else if (!strcasecmp(endpoint_learning, "immediate"))
			el_config = EL_IMMEDIATE;
		else if (!strcasecmp(endpoint_learning, "off"))
			el_config = EL_OFF;
		else if (!strcasecmp(endpoint_learning, "heuristic"))
			el_config = EL_HEURISTIC;
		else
			die("Invalid --endpoint-learning option ('%s')", endpoint_learning);
	}
	rtpe_config.endpoint_learning = el_config;

	if (rtpe_config.jb_length < 0)
		die("Invalid negative jitter buffer size");
}

void fill_initial_rtpe_cfg(struct rtpengine_config* ini_rtpe_cfg) {

	GList* l;
	struct intf_config* gptr_data;

	for(l = rtpe_config.interfaces.head; l ; l=l->next) {
		gptr_data = (struct intf_config*)malloc(sizeof(struct intf_config));
		memcpy(gptr_data, (struct intf_config*)(l->data), sizeof(struct intf_config));

		g_queue_push_tail(&ini_rtpe_cfg->interfaces, gptr_data);
	}

	for(l = rtpe_config.redis_subscribed_keyspaces.head; l ; l = l->next) {
		// l->data has been assigned to a variable before being given into the queue structure not to get a shallow copy
		unsigned int num = GPOINTER_TO_UINT(l->data);
		g_queue_push_tail(&ini_rtpe_cfg->redis_subscribed_keyspaces, GINT_TO_POINTER(num));
	}

	ini_rtpe_cfg->kernel_table = rtpe_config.kernel_table;
	ini_rtpe_cfg->max_sessions = rtpe_config.max_sessions;
	ini_rtpe_cfg->cpu_limit = rtpe_config.cpu_limit;
	ini_rtpe_cfg->load_limit = rtpe_config.load_limit;
	ini_rtpe_cfg->bw_limit = rtpe_config.bw_limit;
	ini_rtpe_cfg->timeout = rtpe_config.timeout;
	ini_rtpe_cfg->silent_timeout = rtpe_config.silent_timeout;
	ini_rtpe_cfg->offer_timeout = rtpe_config.offer_timeout;
	ini_rtpe_cfg->final_timeout = rtpe_config.final_timeout;
	ini_rtpe_cfg->delete_delay = rtpe_config.delete_delay;
	ini_rtpe_cfg->redis_expires_secs = rtpe_config.redis_expires_secs;
	ini_rtpe_cfg->default_tos = rtpe_config.default_tos;
	ini_rtpe_cfg->control_tos = rtpe_config.control_tos;
	ini_rtpe_cfg->graphite_interval = rtpe_config.graphite_interval;
	ini_rtpe_cfg->redis_num_threads = rtpe_config.redis_num_threads;
	ini_rtpe_cfg->homer_protocol = rtpe_config.homer_protocol;
	ini_rtpe_cfg->homer_id = rtpe_config.homer_id;
	ini_rtpe_cfg->no_fallback = rtpe_config.no_fallback;
	ini_rtpe_cfg->port_min = rtpe_config.port_min;
	ini_rtpe_cfg->port_max = rtpe_config.port_max;
	ini_rtpe_cfg->redis_db = rtpe_config.redis_db;
	ini_rtpe_cfg->redis_write_db = rtpe_config.redis_write_db;
	ini_rtpe_cfg->no_redis_required = rtpe_config.no_redis_required;
	ini_rtpe_cfg->num_threads = rtpe_config.num_threads;
	ini_rtpe_cfg->media_num_threads = rtpe_config.media_num_threads;
	ini_rtpe_cfg->fmt = rtpe_config.fmt;
	ini_rtpe_cfg->log_format = rtpe_config.log_format;
	ini_rtpe_cfg->redis_allowed_errors = rtpe_config.redis_allowed_errors;
	ini_rtpe_cfg->redis_disable_time = rtpe_config.redis_disable_time;
	ini_rtpe_cfg->redis_cmd_timeout = rtpe_config.redis_cmd_timeout;
	ini_rtpe_cfg->redis_connect_timeout = rtpe_config.redis_connect_timeout;
	ini_rtpe_cfg->common.log_level = rtpe_config.common.log_level;

	ini_rtpe_cfg->graphite_ep = rtpe_config.graphite_ep;
	ini_rtpe_cfg->tcp_listen_ep = rtpe_config.tcp_listen_ep;
	ini_rtpe_cfg->udp_listen_ep = rtpe_config.udp_listen_ep;
	ini_rtpe_cfg->ng_listen_ep = rtpe_config.ng_listen_ep;
	ini_rtpe_cfg->cli_listen_ep = rtpe_config.cli_listen_ep;
	ini_rtpe_cfg->redis_ep = rtpe_config.redis_ep;
	ini_rtpe_cfg->redis_write_ep = rtpe_config.redis_write_ep;
	ini_rtpe_cfg->homer_ep = rtpe_config.homer_ep;
	ini_rtpe_cfg->endpoint_learning = rtpe_config.endpoint_learning;

	ini_rtpe_cfg->b2b_url = g_strdup(rtpe_config.b2b_url);
	ini_rtpe_cfg->redis_auth = g_strdup(rtpe_config.redis_auth);
	ini_rtpe_cfg->redis_write_auth = g_strdup(rtpe_config.redis_write_auth);
	ini_rtpe_cfg->spooldir = g_strdup(rtpe_config.spooldir);
	ini_rtpe_cfg->iptables_chain = g_strdup(rtpe_config.iptables_chain);
	ini_rtpe_cfg->rec_method = g_strdup(rtpe_config.rec_method);
	ini_rtpe_cfg->rec_format = g_strdup(rtpe_config.rec_format);

	ini_rtpe_cfg->jb_length = rtpe_config.jb_length;
	ini_rtpe_cfg->jb_clock_drift = rtpe_config.jb_clock_drift;
}

static void early_init(void) {
	socket_init(); // needed for socktype_udp
}

static void init_everything(void) {
	log_init("rtpengine");
	log_format(rtpe_config.log_format);
	recording_fs_init(rtpe_config.spooldir, rtpe_config.rec_method, rtpe_config.rec_format);
	rtpe_ssl_init();

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(NULL);
#endif

#if !(GLIB_CHECK_VERSION(2,36,0))
	g_type_init();
#endif

	signals();
	resources();
	sdp_init();
	dtls_init();
	ice_init();
	crypto_init_main();
	interfaces_init(&rtpe_config.interfaces);
	iptables_init();
	control_ng_init();
	if (call_interfaces_init())
		abort();
	statistics_init();
	codeclib_init(0);
	media_player_init();
	dtmf_init();
	jitter_buffer_init();
}


static void create_everything(void) {
	struct control_tcp *ct;
	struct control_udp *cu;
	struct cli *cl;
	struct timeval tmp_tv;
	struct timeval redis_start, redis_stop;
	double redis_diff = 0;

	if (rtpe_config.kernel_table < 0)
		goto no_kernel;
	if (kernel_setup_table(rtpe_config.kernel_table)) {
		if (rtpe_config.no_fallback) {
			ilog(LOG_CRIT, "Userspace fallback disallowed - exiting");
			exit(-1);
		}
		goto no_kernel;
	}

no_kernel:
	rtpe_poller = poller_new();
	if (!rtpe_poller)
		die("poller creation failed");

	dtls_timer(rtpe_poller);

	if (call_init())
		abort();

        rwlock_init(&rtpe_config.config_lock);
	if (rtpe_config.max_sessions < -1) {
		rtpe_config.max_sessions = -1;
	}

	if (rtpe_config.redis_num_threads < 1) {
#ifdef _SC_NPROCESSORS_ONLN
		rtpe_config.redis_num_threads = sysconf( _SC_NPROCESSORS_ONLN );
#endif
		if (rtpe_config.redis_num_threads < 1) {
			rtpe_config.redis_num_threads = REDIS_RESTORE_NUM_THREADS;
		}
	}

	ct = NULL;
	if (rtpe_config.tcp_listen_ep.port) {
		ct = control_tcp_new(rtpe_poller, &rtpe_config.tcp_listen_ep);
		if (!ct)
			die("Failed to open TCP control connection port");
	}

	cu = NULL;
	if (rtpe_config.udp_listen_ep.port) {
		interfaces_exclude_port(rtpe_config.udp_listen_ep.port);
		cu = control_udp_new(rtpe_poller, &rtpe_config.udp_listen_ep);
		if (!cu)
			die("Failed to open UDP control connection port");
	}

	rtpe_control_ng = NULL;
	if (rtpe_config.ng_listen_ep.port) {
		interfaces_exclude_port(rtpe_config.ng_listen_ep.port);
		rtpe_control_ng = control_ng_new(rtpe_poller, &rtpe_config.ng_listen_ep, rtpe_config.control_tos);
		if (!rtpe_control_ng)
			die("Failed to open UDP control connection port");
	}

	cl = NULL;
	if (rtpe_config.cli_listen_ep.port) {
		interfaces_exclude_port(rtpe_config.cli_listen_ep.port);
	    cl = cli_new(rtpe_poller, &rtpe_config.cli_listen_ep);
	    if (!cl)
	        die("Failed to open UDP CLI connection port");
	}

	if (!is_addr_unspecified(&rtpe_config.redis_write_ep.address)) {
		rtpe_redis_write = redis_new(&rtpe_config.redis_write_ep,
				rtpe_config.redis_write_db, rtpe_config.redis_write_auth,
				ANY_REDIS_ROLE, rtpe_config.no_redis_required);
		if (!rtpe_redis_write)
			die("Cannot start up without running Redis %s write database! See also NO_REDIS_REQUIRED parameter.",
				endpoint_print_buf(&rtpe_config.redis_write_ep));
	}

		if (!is_addr_unspecified(&rtpe_config.redis_ep.address)) {
			rtpe_redis = redis_new(&rtpe_config.redis_ep, rtpe_config.redis_db, rtpe_config.redis_auth, rtpe_redis_write ? ANY_REDIS_ROLE : MASTER_REDIS_ROLE, rtpe_config.no_redis_required);
			if (!rtpe_redis)
			die("Cannot start up without running Redis %s database! "
					"See also NO_REDIS_REQUIRED parameter.",
				endpoint_print_buf(&rtpe_config.redis_ep));

			if (rtpe_config.redis_subscribed_keyspaces.length) {
				rtpe_redis_notify = redis_new(&rtpe_config.redis_ep, rtpe_config.redis_db, rtpe_config.redis_auth, rtpe_redis_write ? ANY_REDIS_ROLE : MASTER_REDIS_ROLE, rtpe_config.no_redis_required);
				if (!rtpe_redis_notify)
					die("Cannot start up without running notification Redis %s database! "
							"See also NO_REDIS_REQUIRED parameter.",
						endpoint_print_buf(&rtpe_config.redis_ep));
			}

		if (!rtpe_redis_write)
			rtpe_redis_write = rtpe_redis;
	}

	daemonize();
	wpidfile();

	homer_sender_init(&rtpe_config.homer_ep, rtpe_config.homer_protocol, rtpe_config.homer_id);

	rtcp_init(); // must come after Homer init

	if (rtpe_redis) {
		// start redis restore timer
		gettimeofday(&redis_start, NULL);

		// restore
		if (redis_restore(rtpe_redis))
			die("Refusing to continue without working Redis database");

		// stop redis restore timer
		gettimeofday(&redis_stop, NULL);

		// print redis restore duration
		redis_diff += timeval_diff(&redis_stop, &redis_start) / 1000.0;
		ilog(LOG_INFO, "Redis restore time = %.0lf ms", redis_diff);
	}

	gettimeofday(&rtpe_latest_graphite_interval_start, NULL);

	timeval_from_us(&tmp_tv, (long long) rtpe_config.graphite_interval*1000000);
	set_graphite_interval_tv(&tmp_tv);
}


int main(int argc, char **argv) {
	int idx;

	early_init();
	options(&argc, &argv);
	init_everything();
	create_everything();
	fill_initial_rtpe_cfg(&initial_rtpe_config);

	ilog(LOG_INFO, "Startup complete, version %s", RTPENGINE_VERSION);

	thread_create_detach(sighandler, NULL);
	thread_create_detach_prio(poller_timer_loop, rtpe_poller, rtpe_config.idle_scheduling, rtpe_config.idle_priority);
	thread_create_detach_prio(load_thread, NULL, rtpe_config.idle_scheduling, rtpe_config.idle_priority);

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && rtpe_redis_notify)
		thread_create_detach(redis_notify_loop, NULL);

	if (!is_addr_unspecified(&rtpe_config.graphite_ep.address))
		thread_create_detach(graphite_loop, NULL);

	thread_create_detach(ice_thread_run, NULL);

	if (rtpe_config.num_threads < 1) {
#ifdef _SC_NPROCESSORS_ONLN
		rtpe_config.num_threads = sysconf( _SC_NPROCESSORS_ONLN ) + 3;
#endif
		if (rtpe_config.num_threads <= 1)
			rtpe_config.num_threads = 4;
	}

	service_notify("READY=1\n");

	for (idx = 0; idx < rtpe_config.num_threads; ++idx)
		thread_create_detach_prio(poller_loop, rtpe_poller, rtpe_config.scheduling, rtpe_config.priority);

	if (rtpe_config.media_num_threads < 0)
		rtpe_config.media_num_threads = rtpe_config.num_threads;
	for (idx = 0; idx < rtpe_config.media_num_threads; ++idx) {
#ifdef WITH_TRANSCODING
		thread_create_detach_prio(media_player_loop, NULL, rtpe_config.scheduling, rtpe_config.priority);
#endif
		thread_create_detach_prio(send_timer_loop, NULL, rtpe_config.scheduling, rtpe_config.priority);
		if (rtpe_config.jb_length > 0)
			thread_create_detach_prio(jitter_buffer_loop, NULL, rtpe_config.scheduling,
					rtpe_config.priority);
	}


	while (!rtpe_shutdown) {
		usleep(100000);
		threads_join_all(0);
	}

	service_notify("STOPPING=1\n");

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && rtpe_redis_notify)
		redis_notify_event_base_action(EVENT_BASE_LOOPBREAK);

	threads_join_all(1);

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && rtpe_redis_notify)
		redis_notify_event_base_action(EVENT_BASE_FREE);

	ilog(LOG_INFO, "Version %s shutting down", RTPENGINE_VERSION);

	return 0;
}
