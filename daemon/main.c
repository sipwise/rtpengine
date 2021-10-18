#include "main.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdbool.h>
#ifdef HAVE_MQTT
#include <mosquitto.h>
#endif

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
#include "websocket.h"
#include "codec.h"
#include "mqtt.h"
#include "janus.h"



struct poller *rtpe_poller;
struct poller_map *rtpe_poller_map;
struct rtpengine_config initial_rtpe_config;

static struct control_tcp *rtpe_tcp;
static struct control_udp *rtpe_udp;
static struct cli *rtpe_cli;

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
	.media_num_threads = -1,
	.dtls_rsa_key_size = 2048,
	.dtls_mtu = 1200, // chrome default mtu
	.dtls_signature = 256,
	.max_dtx = 30,
	.dtx_shift = 5,
	.dtx_buffer = 10,
	.dtx_lag = 100,
	.mqtt_port = 1883,
	.mqtt_keepalive = 30,
	.mqtt_publish_interval = 5000,
	.common = {
		.log_levels = {
			[log_level_index_internals] = -1,
		},
	},
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
			for (unsigned int i = 0; i < num_log_levels; i++) {
				g_atomic_int_add(&rtpe_config.common.log_levels[i], -1);
				ilogsn(i, __get_log_level(i), "Decreased '%s' log level to %d\n",
						log_level_names[i],
						__get_log_level(i));
			}
		}
		else if (ret == SIGUSR2) {
			for (unsigned int i = 0; i < num_log_levels; i++) {
				g_atomic_int_add(&rtpe_config.common.log_levels[i], 1);
				ilogsn(i, __get_log_level(i), "Increased '%s' log level to %d\n",
						log_level_names[i],
						__get_log_level(i));
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



static void __find_if_name(char *s, struct ifaddrs *ifas, GQueue *addrs) {
	sockaddr_t *addr;

	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, s))
			continue;
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		if (!ifa->ifa_addr)
			continue;

		addr = g_slice_alloc(sizeof(*addr));
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin = (void *) ifa->ifa_addr;
			addr->family = __get_socket_family_enum(SF_IP4);
			addr->u.ipv4 = sin->sin_addr;
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin = (void *) ifa->ifa_addr;
			if (sin->sin6_scope_id) {
				// link-local
				g_slice_free1(sizeof(*addr), addr);
				continue;
			}
			addr->family = __get_socket_family_enum(SF_IP6);
			addr->u.ipv6 = sin->sin6_addr;
		}
		else {
			g_slice_free1(sizeof(*addr), addr);
			continue;
		}

		// got one
		ilog(LOG_DEBUG, "Determined address %s for interface '%s'",
				sockaddr_print_buf(addr), s);
		g_queue_push_tail(addrs, addr);
	}
}

static void __resolve_ifname(char *s, GQueue *addrs) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
	};

	struct addrinfo *res = NULL;
	int status = getaddrinfo(s, NULL, &hints, &res);
	if (status) {
		ilog(LOG_ERR, "Failed to resolve '%s' as a DNS host name: %s", s, gai_strerror(status));
		return;
	}

	for (struct addrinfo *r = res; r; r = r->ai_next) {
		sockaddr_t *addr = g_slice_alloc0(sizeof(*addr));

		if (r->ai_family == AF_INET) {
			struct sockaddr_in *sin = (void *) r->ai_addr;
			assert(r->ai_addrlen >= sizeof(*sin));
			addr->family = __get_socket_family_enum(SF_IP4);
			addr->u.ipv4 = sin->sin_addr;
		}
		else if (r->ai_family == AF_INET6) {
			struct sockaddr_in6 *sin = (void *) r->ai_addr;
			assert(r->ai_addrlen >= sizeof(*sin));
			addr->family = __get_socket_family_enum(SF_IP6);
			addr->u.ipv6 = sin->sin6_addr;
		}
		else {
			g_slice_free1(sizeof(*addr), addr);
			continue;
		}

		ilog(LOG_DEBUG, "Determined address %s for host name '%s'",
				sockaddr_print_buf(addr), s);
		g_queue_push_tail(addrs, addr);
	}

	freeaddrinfo(res);
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
		g_slice_free1(sizeof(*addr), addr);
		// could be an interface name?
		ilog(LOG_DEBUG, "Could not parse '%s' as network address, checking to see if "
				"it's an interface", s);
		__find_if_name(s, ifas, &addrs);

		if (!addrs.length) {
			ilog(LOG_DEBUG, "'%s' is not an interface, attempting to resolve it as DNS host name", s);
			__resolve_ifname(s, &addrs);
		}
	}

	if (!addrs.length) // nothing found
		return -1;

	ZERO(adv);
	if (c) {
		if (sockaddr_parse_any(&adv, c)) {
			ilog(LOG_DEBUG, "Could not parse '%s' as an address, attempting DNS lookup", c);
			if (sockaddr_getaddrinfo(&adv, c)) {
				ilog(LOG_WARN, "DNS lookup for '%s' failed", c);
				return -1;
			}
		}
		if (is_addr_unspecified(&adv))
			return -1;
	}

	while ((addr = g_queue_pop_head(&addrs))) {
		ifa = g_slice_alloc0(sizeof(*ifa));
		str_init_dup_str(&ifa->name, &name);
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

	sl = strrchr(str, '@');
	if (sl) {
		*sl = 0;
		*auth = g_strdup(str);
		str = sl+1;
	}
	else if ((sl = getenv(auth_env)))
		*auth = g_strdup(sl);

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


static void parse_cn_payload(str *out, char **in, const char *def, const char *name) {
	if (!in || !*in) {
		if (def)
			str_init_dup(out, def);
		return;
	}

	int len = g_strv_length(in);
	if (len < 1)
		die("Invalid CN payload specified (--%s)", name);
	out->s = malloc(len);
	for (int i = 0; i < len; i++) {
		char *endp;
		long p = strtol(in[i], &endp, 0);
		if (endp == in[i] || *endp != '\0')
			die("Invalid CN payload specified (--%s)", name);
		if (p < 0 || p > 254)
			die("Invalid CN payload specified (--%s)", name);
		if (i == 0 && p > 127)
			die("Invalid CN payload specified (--%s)", name);
		out->s[i] = p;
	}
	out->len = len;
}



static void options(int *argc, char ***argv) {
	AUTO_CLEANUP_GVBUF(if_a);
	AUTO_CLEANUP_GVBUF(ks_a);
	unsigned long uint_keyspace_db;
	str str_keyspace_db;
	char **iter;
	AUTO_CLEANUP_GBUF(listenps);
	AUTO_CLEANUP_GBUF(listenudps);
	AUTO_CLEANUP_GBUF(listenngs);
	AUTO_CLEANUP_GBUF(listenngtcps);
	AUTO_CLEANUP_GBUF(listencli);
	AUTO_CLEANUP_GBUF(graphitep);
	AUTO_CLEANUP_GBUF(graphite_prefix_s);
	AUTO_CLEANUP_GBUF(redisps);
	AUTO_CLEANUP_GBUF(redisps_write);
	AUTO_CLEANUP_GBUF(log_facility_cdr_s);
	AUTO_CLEANUP_GBUF(log_facility_rtcp_s);
	AUTO_CLEANUP_GBUF(log_facility_dtmf_s);
	AUTO_CLEANUP_GBUF(log_format);
	int sip_source = 0;
	AUTO_CLEANUP_GBUF(homerp);
	AUTO_CLEANUP_GBUF(homerproto);
	char *endptr;
	int codecs = 0;
	double max_load = 0;
	double max_cpu = 0;
	AUTO_CLEANUP_GBUF(dtmf_udp_ep);
	AUTO_CLEANUP_GBUF(endpoint_learning);
	AUTO_CLEANUP_GBUF(dtls_sig);
	double silence_detect = 0;
	AUTO_CLEANUP_GVBUF(cn_payload);
	AUTO_CLEANUP_GVBUF(dtx_cn_params);
	int debug_srtp = 0;
	AUTO_CLEANUP_GBUF(amr_dtx);
#ifdef HAVE_MQTT
	AUTO_CLEANUP_GBUF(mqtt_publish_scope);
#endif
	AUTO_CLEANUP_GBUF(mos);

	rwlock_lock_w(&rtpe_config.config_lock);

	GOptionEntry e[] = {
		{ "table",	't', 0, G_OPTION_ARG_INT,	&rtpe_config.kernel_table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&rtpe_config.no_fallback,	"Only start when kernel module is available", NULL },
		{ "interface",	'i', 0, G_OPTION_ARG_STRING_ARRAY,&if_a,	"Local interface for RTP",	"[NAME/]IP[!IP]"},
		{ "save-interface-ports",'S', 0, G_OPTION_ARG_NONE,	&rtpe_config.save_interface_ports,	"Bind ports only on first available interface of desired family", NULL },
		{ "subscribe-keyspace", 'k', 0, G_OPTION_ARG_STRING_ARRAY,&ks_a,	"Subscription keyspace list",	"INT INT ..."},
		{ "listen-tcp",	'l', 0, G_OPTION_ARG_STRING,	&listenps,	"TCP port to listen on",	"[IP:]PORT"	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING,	&listenudps,	"UDP port to listen on",	"[IP46|HOSTNAME:]PORT"	},
		{ "listen-ng",	'n', 0, G_OPTION_ARG_STRING,	&listenngs,	"UDP port to listen on, NG protocol", "[IP46|HOSTNAME:]PORT"	},
		{ "listen-tcp-ng",	'N', 0, G_OPTION_ARG_STRING,	&listenngtcps,	"TCP port to listen on, NG protocol", "[IP46|HOSTNAME:]PORT"	},
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
		{ "redis-delete-async", 'y', 0, G_OPTION_ARG_INT, &rtpe_config.redis_delete_async, "Enable asynchronous redis delete", NULL },
		{ "redis-delete-async-interval", 'y', 0, G_OPTION_ARG_INT, &rtpe_config.redis_delete_async_interval, "Set asynchronous redis delete interval (seconds)", NULL },
		{ "active-switchover", 0,0,G_OPTION_ARG_NONE,	&rtpe_config.active_switchover, "Use call activity as indicator of active/standby state", NULL },
		{ "b2b-url",	'b', 0, G_OPTION_ARG_STRING,	&rtpe_config.b2b_url,	"XMLRPC URL of B2B UA"	,	"STRING"	},
		{ "log-facility-cdr",0,  0, G_OPTION_ARG_STRING, &log_facility_cdr_s, "Syslog facility to use for logging CDRs", "daemon|local0|...|local7"},
		{ "log-facility-rtcp",0,  0, G_OPTION_ARG_STRING, &log_facility_rtcp_s, "Syslog facility to use for logging RTCP", "daemon|local0|...|local7"},
#ifdef WITH_TRANSCODING
		{ "log-facility-dtmf",0,  0, G_OPTION_ARG_STRING, &log_facility_dtmf_s, "Syslog facility to use for logging DTMF", "daemon|local0|...|local7"},
		{ "dtmf-log-dest", 0,0,	G_OPTION_ARG_STRING,	&dtmf_udp_ep,	"Destination address for DTMF logging via UDP",	"IP46|HOSTNAME:PORT"	},
		{ "dtmf-log-ng-tcp", 0,0,	G_OPTION_ARG_NONE,	&rtpe_config.dtmf_via_ng,	"DTMF logging via TCP NG protocol",	NULL },
		{ "dtmf-no-suppress", 0,0,G_OPTION_ARG_NONE,	&rtpe_config.dtmf_no_suppress,	"Disable audio suppression during DTMF events",	NULL },
#endif
		{ "log-format",	0, 0,	G_OPTION_ARG_STRING,	&log_format,	"Log prefix format",		"default|parsable"},
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
		{ "debug-srtp",0,0,	G_OPTION_ARG_NONE,	&debug_srtp,		"Log raw encryption details for SRTP",	NULL },
		{ "dtls-rsa-key-size",0, 0,	G_OPTION_ARG_INT,&rtpe_config.dtls_rsa_key_size,"Size of RSA key for DTLS",	"INT"		},
		{ "dtls-mtu",0, 0,	G_OPTION_ARG_INT,&rtpe_config.dtls_mtu,"DTLS MTU",	"INT"		},
		{ "dtls-ciphers",0,  0,	G_OPTION_ARG_STRING,	&rtpe_config.dtls_ciphers,"List of ciphers for DTLS",		"STRING"	},
		{ "dtls-signature",0,  0,G_OPTION_ARG_STRING,	&dtls_sig,		"Signature algorithm for DTLS",		"SHA-256|SHA-1"	},
		{ "listen-http", 0,0,	G_OPTION_ARG_STRING_ARRAY,&rtpe_config.http_ifs,"Interface for HTTP and WS",	"[IP46|HOSTNAME:]PORT"},
		{ "listen-https", 0,0,	G_OPTION_ARG_STRING_ARRAY,&rtpe_config.https_ifs,"Interface for HTTPS and WSS",	"[IP46|HOSTNAME:]PORT"},
		{ "https-cert", 0,0,	G_OPTION_ARG_STRING,	&rtpe_config.https_cert,"Certificate for HTTPS and WSS","FILE"},
		{ "https-key", 0,0,	G_OPTION_ARG_STRING,	&rtpe_config.https_key,	"Private key for HTTPS and WSS","FILE"},
		{ "http-threads", 0,0,	G_OPTION_ARG_INT,	&rtpe_config.http_threads,"Number of worker threads for HTTP and WS","INT"},
		{ "software-id", 0,0,	G_OPTION_ARG_STRING,	&rtpe_config.software_id,"Identification string of this software presented to external systems","STRING"},
		{ "poller-per-thread", 0,0,	G_OPTION_ARG_NONE,	&rtpe_config.poller_per_thread,	"Use poller per thread",	NULL },
#ifdef WITH_TRANSCODING
		{ "dtx-delay",	0,0,	G_OPTION_ARG_INT,	&rtpe_config.dtx_delay,	"Delay in milliseconds to trigger DTX handling","INT"},
		{ "max-dtx",	0,0,	G_OPTION_ARG_INT,	&rtpe_config.max_dtx,	"Maximum duration of DTX handling",	"INT"},
		{ "dtx-buffer",	0,0,	G_OPTION_ARG_INT,	&rtpe_config.dtx_buffer,"Maxmium number of packets held in DTX buffer",	"INT"},
		{ "dtx-lag",	0,0,	G_OPTION_ARG_INT,	&rtpe_config.dtx_lag,	"Maxmium time span in milliseconds held in DTX buffer",	"INT"},
		{ "dtx-shift",	0,0,	G_OPTION_ARG_INT,	&rtpe_config.dtx_shift,	"Length of time (in ms) to shift DTX buffer after over/underflow",	"INT"},
		{ "dtx-cn-params",0,0,	G_OPTION_ARG_STRING_ARRAY,&dtx_cn_params,	"Parameters for CN generated from DTX","INT INT INT ..."},
		{ "amr-dtx", 0,0,	G_OPTION_ARG_STRING,	&amr_dtx,		"DTX mechanism to use for AMR and AMR-WB","native|CN"},
		{ "silence-detect",0,0,	G_OPTION_ARG_DOUBLE,	&silence_detect,	"Audio level threshold in percent for silence detection","FLOAT"},
		{ "cn-payload",0,0,	G_OPTION_ARG_STRING_ARRAY,&cn_payload,		"Comfort noise parameters to replace silence with","INT INT INT ..."},
		{ "reorder-codecs",0,0,	G_OPTION_ARG_NONE,	&rtpe_config.reorder_codecs,"Reorder answer codecs based on sender preference",NULL},
#endif
#ifdef HAVE_MQTT
		{ "mqtt-host",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_host,	"Mosquitto broker host or address",	"HOST|IP"},
		{ "mqtt-port",0,0,	G_OPTION_ARG_INT,	&rtpe_config.mqtt_port,	"Mosquitto broker port number",		"INT"},
		{ "mqtt-id",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_id,	"Mosquitto client ID",			"STRING"},
		{ "mqtt-keepalive",0,0,	G_OPTION_ARG_INT,	&rtpe_config.mqtt_keepalive,"Seconds between mosquitto keepalives","INT"},
		{ "mqtt-user",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_user,	"Username for mosquitto auth",		"USERNAME"},
		{ "mqtt-pass",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_pass,	"Password for mosquitto auth",		"PASSWORD"},
		{ "mqtt-cafile",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_cafile,"CA file for mosquitto auth",		"FILE"},
		{ "mqtt-capath",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_capath,"CA path for mosquitto auth",		"PATH"},
		{ "mqtt-certfile",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_certfile,"Certificate file for mosquitto auth","FILE"},
		{ "mqtt-keyfile",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_keyfile,"Key file for mosquitto auth",	"FILE"},
		{ "mqtt-publish-qos",0,0,G_OPTION_ARG_INT,	&rtpe_config.mqtt_publish_qos,"Mosquitto publish QoS",		"0|1|2"},
		{ "mqtt-publish-topic",0,0,G_OPTION_ARG_STRING,	&rtpe_config.mqtt_publish_topic,"Mosquitto publish topic",	"STRING"},
		{ "mqtt-publish-interval",0,0,G_OPTION_ARG_INT,	&rtpe_config.mqtt_publish_interval,"Publish timer interval",	"MILLISECONDS"},
		{ "mqtt-publish-scope",0,0,G_OPTION_ARG_STRING,	&mqtt_publish_scope,	"Scope for published mosquitto messages","global|call|media"},
#endif
		{ "mos",0,0,		G_OPTION_ARG_STRING,	&mos,		"Type of MOS calculation","CQ|LQ"},
#ifdef SO_INCOMING_CPU
		{ "socket-cpu-affinity",0,0,G_OPTION_ARG_INT,	&rtpe_config.cpu_affinity,"CPU affinity for media sockets","INT"},
#endif
		{ "janus-secret", 0,0,	G_OPTION_ARG_STRING,	&rtpe_config.janus_secret,"Admin secret for Janus protocol","STRING"},

		{ NULL, }
	};

	config_load(argc, argv, e, " - next-generation media proxy",
			"/etc/rtpengine/rtpengine.conf", "rtpengine", &rtpe_config.common);

	// default values, if not configured
	if (rtpe_config.rec_method == NULL)
		rtpe_config.rec_method = g_strdup("pcap");

	if (rtpe_config.rec_format == NULL)
		rtpe_config.rec_format = g_strdup("raw");

	if (rtpe_config.dtls_ciphers == NULL)
		rtpe_config.dtls_ciphers = g_strdup("DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK");

	if (codecs) {
		codeclib_init(1);
		exit(0);
	}

	if (!if_a)
		die("Missing option --interface");
	if (!listenps && !listenudps && !listenngs && !listenngtcps
			&& !(rtpe_config.http_ifs && rtpe_config.http_ifs[0])
			&& !(rtpe_config.https_ifs && rtpe_config.https_ifs[0]))
		die("Missing option --listen-tcp, --listen-udp, --listen-ng, --listen-tcp-ng, "
				"--listen-http, or --listen-https");

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
				ilog(LOG_ERR, "Fail adding keyspace '" STR_FORMAT "' to redis notifications; errono=%d\n", STR_FMT(&str_keyspace_db), errno);
			} else if (endptr == str_keyspace_db.s) {
				ilog(LOG_ERR, "Fail adding keyspace '" STR_FORMAT "' to redis notifications; no digits found\n", STR_FMT(&str_keyspace_db));
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
	if (listenngtcps) {
		if (endpoint_parse_any_getaddrinfo(&rtpe_config.ng_tcp_listen_ep, listenngtcps))
			die("Invalid IP or port '%s' (--listen-tcp-ng)", listenngtcps);
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

	if (debug_srtp)
		rtpe_config.common.log_levels[log_level_index_srtp] = LOG_DEBUG;

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

	if (dtls_sig) {
		if (!strcasecmp(dtls_sig, "sha-1"))
			rtpe_config.dtls_signature = 1;
		else if (!strcasecmp(dtls_sig, "sha1"))
			rtpe_config.dtls_signature = 1;
		else if (!strcasecmp(dtls_sig, "sha-256"))
			rtpe_config.dtls_signature = 256;
		else if (!strcasecmp(dtls_sig, "sha256"))
			rtpe_config.dtls_signature = 256;
		else
			die("Invalid --dtls-signature option ('%s')", dtls_sig);
	}

	if (rtpe_config.dtls_rsa_key_size < 0)
		die("Invalid --dtls-rsa-key-size (%i)", rtpe_config.dtls_rsa_key_size);

	if (rtpe_config.dtls_mtu < 576)
		/* The Internet Protocol requires that hosts must be able to process IP datagrams of at least 576 bytes (for IPv4) or 1280 bytes (for IPv6).
		However, this does not preclude link layers with an MTU smaller than this minimum MTU from conveying IP data. Internet IPv4 path MTU is 68 bytes.*/
		die("Invalid --dtls-mtu (%i)", rtpe_config.dtls_mtu);

	if (rtpe_config.jb_length < 0)
		die("Invalid negative jitter buffer size");

	if (silence_detect > 0) {
		rtpe_config.silence_detect_double = silence_detect / 100.0;
		rtpe_config.silence_detect_int = (int) ((silence_detect / 100.0) * UINT32_MAX);
	}

	parse_cn_payload(&rtpe_config.cn_payload, cn_payload, "\x20", "cn-payload");
	parse_cn_payload(&rtpe_config.dtx_cn_params, dtx_cn_params, NULL, "dtx-cn-params");

	if (amr_dtx) {
		if (!strcasecmp(amr_dtx, "native")) {}
		else if (!strcasecmp(amr_dtx, "CN"))
			rtpe_config.amr_cn_dtx = 1;
		else
			die("Invalid --amr-dtx ('%s')", amr_dtx);
	}

	if (!rtpe_config.software_id)
		rtpe_config.software_id = g_strdup_printf("rtpengine-%s", RTPENGINE_VERSION);
	g_strcanon(rtpe_config.software_id, "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890-", '-');

#ifdef HAVE_MQTT
	if (mqtt_publish_scope) {
		if (!strcmp(mqtt_publish_scope, "global"))
			rtpe_config.mqtt_publish_scope = MPS_GLOBAL;
		else if (!strcmp(mqtt_publish_scope, "call"))
			rtpe_config.mqtt_publish_scope = MPS_CALL;
		else if (!strcmp(mqtt_publish_scope, "media"))
			rtpe_config.mqtt_publish_scope = MPS_MEDIA;
		else
			die("Invalid --mqtt-publish-scope option ('%s')", mqtt_publish_scope);
	}
#endif
	if (mos) {
		if (!strcasecmp(mos, "cq"))
			rtpe_config.mos = MOS_CQ;
		else if (!strcasecmp(mos, "lq"))
			rtpe_config.mos = MOS_LQ;
		else
			die("Invalid --mos option ('%s')", mos);
	}

	rwlock_unlock_w(&rtpe_config.config_lock);
}

void fill_initial_rtpe_cfg(struct rtpengine_config* ini_rtpe_cfg) {

	GList* l;
	struct intf_config* gptr_data;

	rwlock_lock_w(&rtpe_config.config_lock);

	for(l = rtpe_config.interfaces.head; l ; l=l->next) {
		gptr_data = g_slice_alloc0(sizeof(*gptr_data));
		memcpy(gptr_data, (struct intf_config*)(l->data), sizeof(*gptr_data));
		str_init_dup(&gptr_data->name, ((struct intf_config*)(l->data))->name.s);

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
	ini_rtpe_cfg->redis_delete_async = rtpe_config.redis_delete_async;
	ini_rtpe_cfg->redis_delete_async_interval = rtpe_config.redis_delete_async_interval;
	memcpy(&ini_rtpe_cfg->common.log_levels, &rtpe_config.common.log_levels, sizeof(ini_rtpe_cfg->common.log_levels));

	ini_rtpe_cfg->graphite_ep = rtpe_config.graphite_ep;
	ini_rtpe_cfg->tcp_listen_ep = rtpe_config.tcp_listen_ep;
	ini_rtpe_cfg->udp_listen_ep = rtpe_config.udp_listen_ep;
	ini_rtpe_cfg->ng_listen_ep = rtpe_config.ng_listen_ep;
	ini_rtpe_cfg->ng_tcp_listen_ep = rtpe_config.ng_tcp_listen_ep;
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

	rwlock_unlock_w(&rtpe_config.config_lock);
}

static void
free_config_interfaces (gpointer data)
{
	struct intf_config* gptr_data = data;

	str_free_dup(&gptr_data->name);
	g_slice_free1(sizeof(*gptr_data), gptr_data);
}

static void unfill_initial_rtpe_cfg(struct rtpengine_config* ini_rtpe_cfg) {
	// clear queues
	g_queue_clear_full(&ini_rtpe_cfg->interfaces, (GDestroyNotify)free_config_interfaces);
	g_queue_clear(&ini_rtpe_cfg->redis_subscribed_keyspaces);

	// free g_strdup
	g_free(ini_rtpe_cfg->b2b_url);
	g_free(ini_rtpe_cfg->redis_auth);
	g_free(ini_rtpe_cfg->redis_write_auth);
	g_free(ini_rtpe_cfg->spooldir);
	g_free(ini_rtpe_cfg->iptables_chain);
	g_free(ini_rtpe_cfg->rec_method);
	g_free(ini_rtpe_cfg->rec_format);
}

static void options_free(void) {
	// clear queues
	g_queue_clear_full(&rtpe_config.interfaces, (GDestroyNotify)free_config_interfaces);
	g_queue_clear(&rtpe_config.redis_subscribed_keyspaces);

	// free config options
	g_free(rtpe_config.b2b_url);
	g_free(rtpe_config.spooldir);
	g_free(rtpe_config.rec_method);
	g_free(rtpe_config.rec_format);
	g_free(rtpe_config.iptables_chain);
	g_free(rtpe_config.scheduling);
	g_free(rtpe_config.idle_scheduling);
	g_free(rtpe_config.mysql_host);
	g_free(rtpe_config.mysql_user);
	g_free(rtpe_config.mysql_pass);
	g_free(rtpe_config.mysql_query);
	g_free(rtpe_config.dtls_ciphers);
	g_strfreev(rtpe_config.http_ifs);
	g_strfreev(rtpe_config.https_ifs);
	g_free(rtpe_config.https_cert);
	g_free(rtpe_config.https_key);
	g_free(rtpe_config.software_id);
	if (rtpe_config.cn_payload.s)
		g_free(rtpe_config.cn_payload.s);
	if (rtpe_config.dtx_cn_params.s)
		g_free(rtpe_config.dtx_cn_params.s);
	g_free(rtpe_config.mqtt_user);
	g_free(rtpe_config.mqtt_pass);
	g_free(rtpe_config.mqtt_cafile);
	g_free(rtpe_config.mqtt_certfile);
	g_free(rtpe_config.mqtt_keyfile);
	g_free(rtpe_config.mqtt_publish_topic);
	g_free(rtpe_config.janus_secret);

	// free common config options
	config_load_free(&rtpe_config.common);
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

#ifdef HAVE_MQTT
	if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS)
		die("failed to init libmosquitto");
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
	t38_init();
	if (rtpe_config.mqtt_host && mqtt_init())
		abort();
	codecs_init();
	janus_init();
}


static void create_everything(void) {
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

	rtpe_poller_map = poller_map_new();
	if (!rtpe_poller_map)
		die("poller map creation failed");

	dtls_timer(rtpe_poller);

	if (call_init())
		abort();

        rwlock_init(&rtpe_config.config_lock);
	if (rtpe_config.max_sessions < -1) {
		rtpe_config.max_sessions = -1;
	}

	if (rtpe_config.redis_num_threads < 1)
		rtpe_config.redis_num_threads = num_cpu_cores(REDIS_RESTORE_NUM_THREADS);

	rtpe_tcp = NULL;
	if (rtpe_config.tcp_listen_ep.port) {
		rtpe_tcp = control_tcp_new(rtpe_poller, &rtpe_config.tcp_listen_ep);
		if (!rtpe_tcp)
			die("Failed to open TCP control connection port");
	}

	rtpe_udp = NULL;
	if (rtpe_config.udp_listen_ep.port) {
		interfaces_exclude_port(rtpe_config.udp_listen_ep.port);
		rtpe_udp = control_udp_new(rtpe_poller, &rtpe_config.udp_listen_ep);
		if (!rtpe_udp)
			die("Failed to open UDP control connection port");
	}

	rtpe_control_ng = NULL;
	if (rtpe_config.ng_listen_ep.port) {
		interfaces_exclude_port(rtpe_config.ng_listen_ep.port);
		rtpe_control_ng = control_ng_new(rtpe_poller, &rtpe_config.ng_listen_ep, rtpe_config.control_tos);
		if (!rtpe_control_ng)
			die("Failed to open UDP control connection port");
	}

	if (rtpe_config.ng_tcp_listen_ep.port) {
		rtpe_control_ng = control_ng_tcp_new(rtpe_poller, &rtpe_config.ng_tcp_listen_ep, rtpe_control_ng);
		if (!rtpe_control_ng)
			die("Failed to open TCP control connection port");
	}

	rtpe_cli = NULL;
	if (rtpe_config.cli_listen_ep.port) {
		interfaces_exclude_port(rtpe_config.cli_listen_ep.port);
	    rtpe_cli = cli_new(rtpe_poller, &rtpe_config.cli_listen_ep);
	    if (!rtpe_cli)
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

	if (rtpe_config.num_threads < 1)
		rtpe_config.num_threads = num_cpu_cores(4);

	if (rtpe_config.cpu_affinity < 0) {
		rtpe_config.cpu_affinity = num_cpu_cores(0);
		if (rtpe_config.cpu_affinity <= 0)
			die("Number of CPU cores is unknown, cannot auto-set socket CPU affinity");
	}

	if (websocket_init())
		die("Failed to init websocket listener");

	daemonize();
	wpidfile();

	homer_sender_init(&rtpe_config.homer_ep, rtpe_config.homer_protocol, rtpe_config.homer_id);

	rtcp_init(); // must come after Homer init

	if (rtpe_redis) {
		// start redis restore timer
		gettimeofday(&redis_start, NULL);

		// restore
		if (rtpe_redis_notify) {
			// active-active mode: the main DB has our own calls, while
			// the "notify" DB has the "foreign" calls. "foreign" DB goes
			// first as the "owned" DB can do a stray update back to Redis
			for (GList *l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
				int db = GPOINTER_TO_INT(l->data);
				if (redis_restore(rtpe_redis_notify, true, db))
					ilog(LOG_WARN, "Unable to restore calls from the active-active peer");
			}
			if (redis_restore(rtpe_redis_write, false, -1))
				die("Refusing to continue without working Redis database");
		}
		else {
			if (redis_restore(rtpe_redis, false, -1))
				die("Refusing to continue without working Redis database");
		}

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

	thread_create_detach(sighandler, NULL, "signal handler");
	thread_create_detach_prio(poller_timer_loop, rtpe_poller, rtpe_config.idle_scheduling,
			rtpe_config.idle_priority, "poller timer");
	thread_create_detach_prio(load_thread, NULL, rtpe_config.idle_scheduling, rtpe_config.idle_priority, "load monitor");

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && initial_rtpe_config.redis_delete_async)
		thread_create_detach(redis_delete_async_loop, NULL, "redis async");

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && rtpe_redis_notify)
		thread_create_detach(redis_notify_loop, NULL, "redis notify");

	if (!is_addr_unspecified(&rtpe_config.graphite_ep.address))
		thread_create_detach(graphite_loop, NULL, "graphite");

#ifdef HAVE_MQTT
	if (mqtt_publish_scope() != MPS_NONE)
		thread_create_detach(mqtt_loop, NULL, "mqtt");
#endif

	thread_create_detach(ice_thread_run, NULL, "ICE");

	websocket_start();

	service_notify("READY=1\n");

	for (idx = 0; idx < rtpe_config.num_threads; ++idx) {
		if (!rtpe_config.poller_per_thread)
			thread_create_detach_prio(poller_loop2, rtpe_poller, rtpe_config.scheduling, rtpe_config.priority, "poller");
		else
			thread_create_detach_prio(poller_loop, rtpe_poller_map, rtpe_config.scheduling, rtpe_config.priority, "poller");
	}

	if (!rtpe_config.poller_per_thread)
		thread_create_detach_prio(poller_loop2, rtpe_poller, rtpe_config.scheduling, rtpe_config.priority, "poller");

	if (rtpe_config.media_num_threads < 0)
		rtpe_config.media_num_threads = rtpe_config.num_threads;
	for (idx = 0; idx < rtpe_config.media_num_threads; ++idx) {
#ifdef WITH_TRANSCODING
		thread_create_detach_prio(media_player_loop, NULL, rtpe_config.scheduling,
				rtpe_config.priority, "media player");
#endif
		thread_create_detach_prio(send_timer_loop, NULL, rtpe_config.scheduling,
				rtpe_config.priority, "send timer");
		if (rtpe_config.jb_length > 0)
			thread_create_detach_prio(jitter_buffer_loop, NULL, rtpe_config.scheduling,
					rtpe_config.priority, "jitter buffer");
		thread_create_detach_prio(codec_timers_loop, NULL, rtpe_config.scheduling,
				rtpe_config.priority, "codec timer");
	}


	while (!rtpe_shutdown) {
		usleep(100000);
		threads_join_all(false);
	}

        // free libevent
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
        libevent_global_shutdown();
#endif

	service_notify("STOPPING=1\n");

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && initial_rtpe_config.redis_delete_async)
		redis_async_event_base_action(rtpe_redis_write, EVENT_BASE_LOOPBREAK);

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && rtpe_redis_notify)
		redis_async_event_base_action(rtpe_redis_notify, EVENT_BASE_LOOPBREAK);

	threads_join_all(true);

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && initial_rtpe_config.redis_delete_async)
		redis_async_event_base_action(rtpe_redis_write, EVENT_BASE_FREE);

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && rtpe_redis_notify)
		redis_async_event_base_action(rtpe_redis_notify, EVENT_BASE_FREE);

	ilog(LOG_INFO, "Version %s shutting down", RTPENGINE_VERSION);

	recording_fs_free();

	unfill_initial_rtpe_cfg(&initial_rtpe_config);

	call_free();

	jitter_buffer_init_free();
	media_player_free();
	codeclib_free();
	call_interfaces_free();
	ice_free();
	dtls_cert_free();
	control_ng_cleanup();
	codecs_cleanup();
	statistics_free();

	redis_close(rtpe_redis);
	if (rtpe_redis_write != rtpe_redis)
		redis_close(rtpe_redis_write);
	redis_close(rtpe_redis_notify);

	free_prefix();
	options_free();
	log_free();
	janus_free();

	obj_release(rtpe_cli);
	obj_release(rtpe_udp);
	obj_release(rtpe_tcp);
	obj_release(rtpe_control_ng);
	poller_free(&rtpe_poller);
	poller_map_free(&rtpe_poller_map);
	interfaces_free();

	return 0;
}
