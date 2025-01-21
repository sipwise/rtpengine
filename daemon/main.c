#include "main.h"

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
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
#ifndef WITHOUT_NFTABLES
#include <linux/netfilter.h>
#endif

#include "poller.h"
#include "control_tcp.h"
#include "control_udp.h"
#include "control_ng.h"
#include "helpers.h"
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
#include "nftables.h"
#include "bufferpool.h"
#include "log_funcs.h"
#include "uring.h"



struct poller **rtpe_pollers;
struct poller *rtpe_control_poller;
static unsigned int num_rtpe_pollers;
static unsigned int num_poller_threads;
unsigned int num_media_pollers;
unsigned int rtpe_poller_rr_iter;

struct rtpengine_config initial_rtpe_config;

static GQueue rtpe_tcp = G_QUEUE_INIT;
static GQueue rtpe_udp = G_QUEUE_INIT;
static GQueue rtpe_cli = G_QUEUE_INIT;

GQueue rtpe_control_ng = G_QUEUE_INIT;
GQueue rtpe_control_ng_tcp = G_QUEUE_INIT;
struct bufferpool *shm_bufferpool;

struct rtpengine_config rtpe_config = {
	// non-zero defaults
	.kernel_table = -1,
	.max_sessions = -1,
	.delete_delay = 30,
	.redis_subscribed_keyspaces = G_QUEUE_INIT,
	.redis_expires_secs = 86400,
	.interfaces = TYPED_GQUEUE_INIT,
	.homer_protocol = SOCK_DGRAM,
	.homer_id = 2001,
	.homer_ng_capt_proto = 0x3d, // first available value in HEP proto specification
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
	.max_dtx = 30,
	.dtx_shift = 5,
	.dtx_buffer = 10,
	.dtx_lag = 100,
	.audio_buffer_delay = 5,
	.audio_buffer_length = 500,
	.mqtt_port = 1883,
	.mqtt_keepalive = 30,
	.mqtt_publish_interval = 5000,
	.dtmf_digit_delay = 2500,
	.rtcp_interval = 5000,
	.moh_max_duration = -1, // disabled by default
	.moh_max_repeats = 999,
	.common = {
		.log_levels = {
			[log_level_index_internals] = -1,
		},
	},
	.max_recv_iters = MAX_RECV_ITERS,
	.kernel_player_media = 128,
};

static void sighandler(gpointer x) {
	sigset_t ss;
	int ret;
	struct timespec ts;

	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGHUP);
	sigaddset(&ss, SIGUSR1);
	sigaddset(&ss, SIGUSR2);

	ts.tv_sec = thread_sleep_time / 1000;
	ts.tv_nsec = (thread_sleep_time % 1000) * 1000 * 1000;

	while (!rtpe_shutdown) {
		thread_cancel_enable();
		ret = sigtimedwait(&ss, NULL, &ts);
		thread_cancel_disable();

		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			abort();
		}

		if (ret == SIGINT || ret == SIGTERM)
			rtpe_shutdown = true;
		else if (ret == SIGHUP)
			_exit(42);
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



static void __find_if_name(char *s, struct ifaddrs *ifas, GQueue *addrs) {
	sockaddr_t *addr;

	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!strcmp(s, "any")) {
			if ((ifa->ifa_flags & IFF_LOOPBACK))
				continue;
		}
		else if (strcmp(ifa->ifa_name, s))
			continue;

		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		if (!ifa->ifa_addr)
			continue;

		addr = g_slice_alloc(sizeof(*addr));
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin = (void *) ifa->ifa_addr;
			addr->family = get_socket_family_enum(SF_IP4);
			addr->ipv4 = sin->sin_addr;
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin = (void *) ifa->ifa_addr;
			if (sin->sin6_scope_id) {
				// link-local
				g_slice_free1(sizeof(*addr), addr);
				continue;
			}
			addr->family = get_socket_family_enum(SF_IP6);
			addr->ipv6 = sin->sin6_addr;
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
			addr->ipv4 = sin->sin_addr;
		}
		else if (r->ai_family == AF_INET6) {
			struct sockaddr_in6 *sin = (void *) r->ai_addr;
			assert(r->ai_addrlen >= sizeof(*sin));
			addr->family = __get_socket_family_enum(SF_IP6);
			addr->ipv6 = sin->sin6_addr;
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

static int if_addr_parse(intf_config_q *q, char *s, struct ifaddrs *ifas) {
	str name;
	char *c;
	sockaddr_t *addr, adv;
	GQueue addrs = G_QUEUE_INIT;
	struct intf_config *ifa;

	while (*s == ' ')
		s++;

	/* name */
	c = strpbrk(s, "/=");
	if (c) {
		char cc = *c;
		*c++ = 0;
		name = STR(s);
		s = c;
		if (cc == '=') {
			// foo=bar
			ifa = g_slice_alloc0(sizeof(*ifa));
			ifa->name = str_dup_str(&name);
			ifa->alias = STR_DUP(s);
			t_queue_push_tail(q, ifa);
			return 0;
		}
	}
	else
		name = STR("default");

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
		ifa->name = str_dup_str(&name);
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

		t_queue_push_tail(q, ifa);

		g_slice_free1(sizeof(*addr), addr);
	}

	return 0;
}



static int redis_ep_parse(endpoint_t *ep, int *db, char **hostname, char **auth, const char *auth_env, char *s) {
	char *sl, *sp;
	long l;

	sl = strrchr(s, '@');
	if (sl) {
		*sl = 0;
		*auth = g_strdup(s);
		s = sl+1;
	}
	else if ((sl = getenv(auth_env)))
		*auth = g_strdup(sl);

	if (db) {
		sl = strchr(s, '/');
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
	}

	/* copy for the case with re-resolve during re-connections */
	sp = strrchr(s, ':'); /* make sure to not take port into the value of hostname */
	if (sp)
		*hostname = g_strdup_printf("%.*s", (int)(sp - s), s);
	else
		*hostname = g_strdup(s);

	if (endpoint_parse_any_getaddrinfo_full(ep, s))
		return -1;
	return 0;
}


static void parse_cn_payload(str *out, char **in, const char *def, const char *name) {
	if (!in || !*in) {
		if (def)
			*out = STR_DUP(def);
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


static endpoint_t *endpoint_dup(const endpoint_t *e) {
	endpoint_t *r = g_slice_alloc(sizeof(*r));
	*r = *e;
	return r;
}
static void endpoint_list_dup(GQueue *out, const GQueue *in) {
	g_queue_init(out);
	for (GList *l = in->head; l; l = l->next)
		g_queue_push_tail(out, endpoint_dup(l->data));
}
static void endpoint_list_free(GQueue *q) {
	endpoint_t *ep;
	while ((ep = g_queue_pop_head(q)))
		g_slice_free1(sizeof(*ep), ep);
}
static void parse_listen_list(GQueue *out, char **epv, const char *option) {
	if (!epv)
		return;
	for (; *epv; epv++) {
		char *ep = *epv;
		endpoint_t x, y;
		if (endpoint_parse_any_getaddrinfo_alt(&x, &y, ep))
			die("Invalid IP or port '%s' ('%s')", ep, option);
		if (x.port)
			g_queue_push_tail(out, endpoint_dup(&x));
		if (y.port)
			g_queue_push_tail(out, endpoint_dup(&y));
	}
}

static void create_listeners(const GQueue *endpoints_in, GQueue *objects_out,
		void *(*constructor)(const endpoint_t *), bool exclude_port,
		const char *name)
{
	for (GList *l = endpoints_in->head; l; l = l->next) {
		endpoint_t *e = l->data;
		if (exclude_port)
			interfaces_exclude_port(e->port);
		void *o = constructor(e);
		if (!o)
			die("Failed to open %s connection port (%s): %s",
					name,
					endpoint_print_buf(e),
					strerror(errno));
		g_queue_push_tail(objects_out, o);
	}
}
static void release_listeners(GQueue *q) {
	while (q->length) {
		struct obj *o = g_queue_pop_head(q);
		obj_release(o);
	}
}


static void options(int *argc, char ***argv, GHashTable *templates) {
	g_autoptr(char_p) if_a = NULL;
	g_autoptr(char_p) ks_a = NULL;
	long int_keyspace_db;
	str str_keyspace_db;
	char **iter;
	g_autoptr(char_p) listenps = NULL;
	g_autoptr(char_p) listenudps = NULL;
	g_autoptr(char_p) listenngs = NULL;
	g_autoptr(char_p) listenngtcps = NULL;
	g_autoptr(char_p) listencli = NULL;
	g_autoptr(char) graphitep = NULL;
	g_autoptr(char) graphite_prefix_s = NULL;
	g_autoptr(char) redisps = NULL;
	g_autoptr(char) redisps_write = NULL;
	g_autoptr(char) redisps_subscribe = NULL;
	g_autoptr(char) log_facility_cdr_s = NULL;
	g_autoptr(char) log_facility_rtcp_s = NULL;
	g_autoptr(char) log_facility_dtmf_s = NULL;
	g_autoptr(char) log_format = NULL;
	bool sip_source = false;
	g_autoptr(char) homerp = NULL;
	g_autoptr(char) homerproto = NULL;
	char *endptr;
	bool codecs = false;
	double max_load = 0;
	double max_cpu = 0;
	g_autoptr(char) dtmf_udp_ep = NULL;
	g_autoptr(char) endpoint_learning = NULL;
	g_autoptr(char) dtls_sig = NULL;
	double silence_detect = 0;
	g_autoptr(char_p) cn_payload = NULL;
	g_autoptr(char_p) dtx_cn_params = NULL;
	bool debug_srtp = false;
	g_autoptr(char) amr_dtx = NULL;
#ifdef HAVE_MQTT
	g_autoptr(char) mqtt_publish_scope = NULL;
#endif
	g_autoptr(char_p) mos_options = NULL;
	g_autoptr(char) dcc = NULL;
	g_autoptr(char) use_audio_player = NULL;
	g_autoptr(char) control_pmtu = NULL;
#ifndef WITHOUT_NFTABLES
	bool nftables_start = false;
	bool nftables_stop = false;
	bool nftables_status = false;
	g_autoptr(char) nftables_family = NULL;
#endif
	g_autoptr(char) redis_format = NULL;
	g_autoptr(char) templates_section = NULL;

	GOptionEntry e[] = {
		{ "table",	't', 0, G_OPTION_ARG_INT,	&rtpe_config.kernel_table,		"Kernel table to use",		"INT"		},
		{ "no-fallback",'F', 0, G_OPTION_ARG_NONE,	&rtpe_config.no_fallback,	"Only start when kernel module is available", NULL },
#ifndef WITHOUT_NFTABLES
		{ "nftables-chain",0,0, G_OPTION_ARG_STRING,	&rtpe_config.nftables_chain,	"Name of nftables chain to manage", "STR" },
		{ "nftables-base-chain",0,0, G_OPTION_ARG_STRING,&rtpe_config.nftables_base_chain,"Name of nftables base chain to use", "STR" },
		{ "nftables-append",0,0, G_OPTION_ARG_NONE,	&rtpe_config.nftables_append,	"Append instead of prepend created rules", NULL },
		{ "nftables-family",0,0, G_OPTION_ARG_STRING,	&nftables_family,		"Address family/ies to manage via nftables", "ip|ip6|ip,ip6" },
		{ "nftables-start",0,0, G_OPTION_ARG_NONE,	&nftables_start,		"Just add nftables rules and exit", NULL },
		{ "nftables-stop",0, 0, G_OPTION_ARG_NONE,	&nftables_stop,			"Just remove nftables rules and exit", NULL },
		{ "nftables-status",0, 0, G_OPTION_ARG_NONE,	&nftables_status,		"Check nftables rules, print result and exit", NULL },
#endif
		{ "interface",	'i', 0, G_OPTION_ARG_STRING_ARRAY,&if_a,	"Local interface for RTP",	"[NAME/]IP[!IP]"},
		{ "templates", 0, 0,	G_OPTION_ARG_STRING,	&templates_section,	"Config section to read signalling templates from ",	"STR"},
		{ "save-interface-ports",'S', 0, G_OPTION_ARG_NONE,	&rtpe_config.save_interface_ports,	"Bind ports only on first available interface of desired family", NULL },
		{ "subscribe-keyspace", 'k', 0, G_OPTION_ARG_STRING_ARRAY,&ks_a,	"Subscription keyspace list",	"INT INT ..."},
		{ "listen-ng",	'n', 0, G_OPTION_ARG_STRING_ARRAY,	&listenngs,	"UDP ports to listen on, NG protocol","[IP46|HOSTNAME:]PORT ..."	},
		{ "listen-tcp-ng",	'N', 0, G_OPTION_ARG_STRING_ARRAY,&listenngtcps,"TCP ports to listen on, NG protocol","[IP46|HOSTNAME:]PORT ..."	},
		{ "listen-cli", 'c', 0, G_OPTION_ARG_STRING_ARRAY,	&listencli,	"TCP port to listen on, CLI",	"[IP46|HOSTNAME:]PORT ..."     },
		{ "listen-tcp",	'l', 0, G_OPTION_ARG_STRING_ARRAY,	&listenps,	"TCP ports to listen on, legacy","[IP:]PORT ..."	},
		{ "listen-udp",	'u', 0, G_OPTION_ARG_STRING_ARRAY,	&listenudps,	"UDP ports to listen on, legacy","[IP46|HOSTNAME:]PORT ..."	},
		{ "graphite", 'g', 0, G_OPTION_ARG_STRING,    &graphitep,     "Address of the graphite server",   "IP46|HOSTNAME:PORT"     },
		{ "graphite-interval",  'G', 0, G_OPTION_ARG_INT,    &rtpe_config.graphite_interval,  "Graphite send interval in seconds",    "INT"   },
		{ "graphite-prefix",0,  0,	G_OPTION_ARG_STRING, &graphite_prefix_s, "Prefix for graphite line", "STRING"},
		{ "graphite-timeout", 0, 0, G_OPTION_ARG_INT, &rtpe_config.graphite_timeout, "Graphite socket timeout interval in seconds", "INT" },
		{ "tos",	'T', 0, G_OPTION_ARG_INT,	&rtpe_config.default_tos,		"Default TOS value to set on streams",	"INT"		},
		{ "control-tos",0 , 0, G_OPTION_ARG_INT,	&rtpe_config.control_tos,		"Default TOS value to set on control-ng",	"INT"		},
		{ "control-pmtu", 0,0,	G_OPTION_ARG_STRING,	&control_pmtu,	"Path MTU discovery behaviour on UDP control sockets",	"want|dont"		},
		{ "timeout",	'o', 0, G_OPTION_ARG_INT,	&rtpe_config.timeout,	"RTP timeout",			"SECS"		},
		{ "silent-timeout",'s',0,G_OPTION_ARG_INT,	&rtpe_config.silent_timeout,"RTP timeout for muted",	"SECS"		},
		{ "final-timeout",'a',0,G_OPTION_ARG_INT,	&rtpe_config.final_timeout,	"Call timeout",			"SECS"		},
		{ "offer-timeout",0,0,	G_OPTION_ARG_INT,	&rtpe_config.offer_timeout,	"Timeout for incomplete one-sided calls",	"SECS"		},
		{ "port-min",	'm', 0, G_OPTION_ARG_INT,	&rtpe_config.port_min,	"Lowest port to use for RTP",	"INT"		},
		{ "port-max",	'M', 0, G_OPTION_ARG_INT,	&rtpe_config.port_max,	"Highest port to use for RTP",	"INT"		},
		{ "redis",	'r', 0, G_OPTION_ARG_STRING,	&redisps,	"Connect to Redis database",	"[PW@]IP:PORT/INT"	},
		{ "redis-write",'w', 0, G_OPTION_ARG_STRING,    &redisps_write, "Connect to Redis write database",      "[PW@]IP:PORT/INT"       },
		{ "redis-subscribe", 0, 0, G_OPTION_ARG_STRING, &redisps_subscribe, "Connect to Redis subscribe database",      "[PW@]IP:PORT[/INT]"       },
		{ "redis-resolve-on-reconnect", 0,0,	G_OPTION_ARG_NONE,	&rtpe_config.redis_resolve_on_reconnect,	"Re-resolve given FQDN on each re-connect to the redis server.",	NULL },
		{ "redis-num-threads", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_num_threads, "Number of Redis restore threads",      "INT"       },
		{ "redis-expires", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_expires_secs, "Expire time in seconds for redis keys",      "INT"       },
		{ "no-redis-required", 'q', 0, G_OPTION_ARG_NONE, &rtpe_config.no_redis_required, "Start no matter of redis connection state", NULL },
		{ "redis-allowed-errors", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_allowed_errors, "Number of allowed errors before redis is temporarily disabled", "INT" },
		{ "redis-disable-time", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_disable_time, "Number of seconds redis communication is disabled because of errors", "INT" },
		{ "redis-cmd-timeout", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_cmd_timeout, "Sets a timeout in milliseconds for redis commands", "INT" },
		{ "redis-connect-timeout", 0, 0, G_OPTION_ARG_INT, &rtpe_config.redis_connect_timeout, "Sets a timeout in milliseconds for redis connections", "INT" },
		{ "redis-format", 0, 0,	G_OPTION_ARG_STRING, &redis_format,		"Format for persistent storage in Redis/KeyDB", "native|bencode|JSON" },
#if 0
		// temporarily disabled, see discussion on https://github.com/sipwise/rtpengine/commit/2ebf5a1526c1ce8093b3011a1e23c333b3f99400
		// related to Change-Id: I83d9b9a844f4f494ad37b44f5d1312f272beff3f
		{ "redis-delete-async", 'y', 0, G_OPTION_ARG_INT, &rtpe_config.redis_delete_async, "Enable asynchronous redis delete", NULL },
		{ "redis-delete-async-interval", 'y', 0, G_OPTION_ARG_INT, &rtpe_config.redis_delete_async_interval, "Set asynchronous redis delete interval (seconds)", NULL },
#endif
		{ "active-switchover", 0,0,G_OPTION_ARG_NONE,	&rtpe_config.active_switchover, "Use call activity as indicator of active/standby state", NULL },
		{ "b2b-url",	'b', 0, G_OPTION_ARG_STRING,	&rtpe_config.b2b_url,	"XMLRPC URL of B2B UA"	,	"STRING"	},
		{ "log-facility-cdr",0,  0, G_OPTION_ARG_STRING, &log_facility_cdr_s, "Syslog facility to use for logging CDRs", "daemon|local0|...|local7"},
		{ "log-facility-rtcp",0,  0, G_OPTION_ARG_STRING, &log_facility_rtcp_s, "Syslog facility to use for logging RTCP", "daemon|local0|...|local7"},
#ifdef WITH_TRANSCODING
		{ "log-facility-dtmf",0,  0, G_OPTION_ARG_STRING, &log_facility_dtmf_s, "Syslog facility to use for logging DTMF", "daemon|local0|...|local7"},
		{ "dtmf-log-dest", 0,0,	G_OPTION_ARG_STRING,	&dtmf_udp_ep,	"Destination address for DTMF logging via UDP",	"IP46|HOSTNAME:PORT"	},
		{ "dtmf-log-ng-tcp", 0,0,	G_OPTION_ARG_NONE,	&rtpe_config.dtmf_via_ng,	"DTMF logging via TCP NG protocol",	NULL },
		{ "dtmf-no-suppress", 0,0,G_OPTION_ARG_NONE,	&rtpe_config.dtmf_no_suppress,	"Disable audio suppression during DTMF events",	NULL },
		{ "dtmf-digit-delay", 0,0,G_OPTION_ARG_INT,	&rtpe_config.dtmf_digit_delay,	"Delay in ms between DTMF digit for trigger detection",	NULL },
		{ "dtmf-no-log-injects", 0,0,G_OPTION_ARG_NONE, &rtpe_config.dtmf_no_log_injects,  "Disable DTMF logging for events created by inject-DTMF function", NULL},
#endif
		{ "log-format",	0, 0,	G_OPTION_ARG_STRING,	&log_format,	"Log prefix format",		"default|parsable"},
		{ "xmlrpc-format",'x', 0, G_OPTION_ARG_INT,	&rtpe_config.fmt,	"XMLRPC timeout request format to use. 0: SEMS DI, 1: call-id only, 2: Kamailio",	"INT"	},
		{ "num-threads",  0, 0, G_OPTION_ARG_INT,	&rtpe_config.num_threads,	"Number of worker threads to create",	"INT"	},
		{ "media-num-threads",  0, 0, G_OPTION_ARG_INT,	&rtpe_config.media_num_threads,	"Number of worker threads for media playback",	"INT"	},
#ifdef WITH_TRANSCODING
		{ "codec-num-threads",  0, 0, G_OPTION_ARG_INT,	&rtpe_config.codec_num_threads,	"Number of transcoding threads for asynchronous operation",	"INT"	},
#endif
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
		{ "homer-disable-rtcp-stats", 0, 0, G_OPTION_ARG_NONE,	&rtpe_config.homer_rtcp_off,	"Disable RTCP stats tracing to Homer (enabled by default if homer server enabled)", NULL	},
		{ "homer-enable-ng", 0, 0, G_OPTION_ARG_NONE,	&rtpe_config.homer_ng_on,	"Enable NG tracing to Homer", NULL	},
		{ "homer-ng-capture-proto", 0, 0, G_OPTION_ARG_INT,	&rtpe_config.homer_ng_capt_proto,	"'Capture protocol type' to use within the HEP protocol (default is 0x3d). Further used by the Homer capture and UI.", "UINT8"	},
		{ "recording-dir", 0, 0, G_OPTION_ARG_FILENAME,	&rtpe_config.spooldir,	"Directory for storing pcap and metadata files", "FILE"	},
		{ "recording-method",0, 0, G_OPTION_ARG_STRING,	&rtpe_config.rec_method,	"Strategy for call recording",		"pcap|proc|all"	},
		{ "recording-format",0, 0, G_OPTION_ARG_STRING,	&rtpe_config.rec_format,	"File format for stored pcap files",	"raw|eth"	},
		{ "record-egress",0, 0, G_OPTION_ARG_NONE,	&rtpe_config.rec_egress,	"Recording egress media instead of ingress",	NULL	},
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
		{ "reject-invalid-sdp",0,0,	G_OPTION_ARG_NONE,	&rtpe_config.reject_invalid_sdp,"Refuse to process SDP bodies with broken syntax",	NULL },
		{ "dtls-rsa-key-size",0, 0,	G_OPTION_ARG_INT,&rtpe_config.dtls_rsa_key_size,"Size of RSA key for DTLS",	"INT"		},
		{ "dtls-cert-cipher",0,  0,G_OPTION_ARG_STRING,	&dcc,			"Cipher to use for the DTLS certificate","prime256v1|RSA"	},
		{ "dtls-mtu",0, 0,	G_OPTION_ARG_INT,&rtpe_config.dtls_mtu,"DTLS MTU",	"INT"		},
		{ "dtls-ciphers",0,  0,	G_OPTION_ARG_STRING,	&rtpe_config.dtls_ciphers,"List of ciphers for DTLS",		"STRING"	},
		{ "dtls-signature",0,  0,G_OPTION_ARG_STRING,	&dtls_sig,		"Signature algorithm for DTLS",		"SHA-256|SHA-1"	},
		{ "listen-http", 0,0,	G_OPTION_ARG_STRING_ARRAY,&rtpe_config.http_ifs,"Interface for HTTP and WS",	"[IP46|HOSTNAME:]PORT"},
		{ "listen-https", 0,0,	G_OPTION_ARG_STRING_ARRAY,&rtpe_config.https_ifs,"Interface for HTTPS and WSS",	"[IP46|HOSTNAME:]PORT"},
		{ "https-cert", 0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.https_cert,"Certificate for HTTPS and WSS","FILE"},
		{ "https-key", 0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.https_key,	"Private key for HTTPS and WSS","FILE"},
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
		{ "player-cache",0,0,	G_OPTION_ARG_NONE,	&rtpe_config.player_cache,"Cache media files for playback in memory",NULL},
		{ "kernel-player",0,0,	G_OPTION_ARG_INT,	&rtpe_config.kernel_player,"Max number of kernel media player streams","INT"},
		{ "kernel-player-media",0,0,G_OPTION_ARG_INT,	&rtpe_config.kernel_player_media,"Max number of kernel media files","INT"},
		{ "preload-media-files",0,0,G_OPTION_ARG_FILENAME_ARRAY,&rtpe_config.preload_media_files,"Preload media file(s) for playback into memory","FILE"},
		{ "media-files-reload",0,0,G_OPTION_ARG_INT,	&rtpe_config.media_refresh,"Refresh/reload preloaded media files at a certain interval","SECONDS"},
		{ "media-files-expire",0,0,G_OPTION_ARG_INT,	&rtpe_config.media_expire,"Maximum age of unused cached media files","SECONDS"},
		{ "expiry-timer",0,0,G_OPTION_ARG_INT,		&rtpe_config.expiry_timer,"How often to check for expired media cache entries","SECONDS"},
		{ "preload-db-media",0,0,G_OPTION_ARG_STRING_ARRAY,&rtpe_config.preload_db_media,"Preload media from database for playback into memory","INT"},
		{ "db-media-reload",0,0,G_OPTION_ARG_INT,	&rtpe_config.db_refresh,"Reload preloaded media from DB at a certain interval","SECONDS"},
		{ "db-media-expire",0,0,G_OPTION_ARG_INT,	&rtpe_config.db_expire,"Maximum age of unused cached DB media entries","SECONDS"},
		{ "db-media-cache",0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.db_media_cache,"Directory to store media loaded from database","PATH"},
		{ "preload-db-cache",0,0,G_OPTION_ARG_STRING_ARRAY,&rtpe_config.preload_db_cache,"Preload media from database for playback into file cache","INT"},
		{ "db-cache-reload",0,0,G_OPTION_ARG_INT,	&rtpe_config.cache_refresh,"Refresh/reload cached media from DB at a certain interval","SECONDS"},
		{ "db-cache-expire",0,0,G_OPTION_ARG_INT,	&rtpe_config.cache_expire,"Maximum age of unused cached DB entries in files","SECONDS"},
		{ "audio-buffer-length",0,0,	G_OPTION_ARG_INT,&rtpe_config.audio_buffer_length,"Length in milliseconds of audio buffer","INT"},
		{ "audio-buffer-delay",0,0,	G_OPTION_ARG_INT,&rtpe_config.audio_buffer_delay,"Initial delay in milliseconds for buffered audio","INT"},
		{ "audio-player",0,0,	G_OPTION_ARG_STRING,	&use_audio_player,	"When to enable the internal audio player","on-demand|play-media|transcoding|always"},
#endif
#ifdef HAVE_MQTT
		{ "mqtt-host",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_host,	"Mosquitto broker host or address",	"HOST|IP"},
		{ "mqtt-port",0,0,	G_OPTION_ARG_INT,	&rtpe_config.mqtt_port,	"Mosquitto broker port number",		"INT"},
		{ "mqtt-tls-alpn",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_tls_alpn,	"Mosquitto broker TLS ALPN",	"STRING"},
		{ "mqtt-id",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_id,	"Mosquitto client ID",			"STRING"},
		{ "mqtt-keepalive",0,0,	G_OPTION_ARG_INT,	&rtpe_config.mqtt_keepalive,"Seconds between mosquitto keepalives","INT"},
		{ "mqtt-user",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_user,	"Username for mosquitto auth",		"USERNAME"},
		{ "mqtt-pass",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.mqtt_pass,	"Password for mosquitto auth",		"PASSWORD"},
		{ "mqtt-cafile",0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.mqtt_cafile,"CA file for mosquitto auth",		"FILE"},
		{ "mqtt-capath",0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.mqtt_capath,"CA path for mosquitto auth",		"PATH"},
		{ "mqtt-certfile",0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.mqtt_certfile,"Certificate file for mosquitto auth","FILE"},
		{ "mqtt-keyfile",0,0,	G_OPTION_ARG_FILENAME,	&rtpe_config.mqtt_keyfile,"Key file for mosquitto auth",	"FILE"},
		{ "mqtt-publish-qos",0,0,G_OPTION_ARG_INT,	&rtpe_config.mqtt_publish_qos,"Mosquitto publish QoS",		"0|1|2"},
		{ "mqtt-publish-topic",0,0,G_OPTION_ARG_STRING,	&rtpe_config.mqtt_publish_topic,"Mosquitto publish topic",	"STRING"},
		{ "mqtt-publish-interval",0,0,G_OPTION_ARG_INT,	&rtpe_config.mqtt_publish_interval,"Publish timer interval",	"MILLISECONDS"},
		{ "mqtt-publish-scope",0,0,G_OPTION_ARG_STRING,	&mqtt_publish_scope,	"Scope for published mosquitto messages","global|summary|call|media"},
#endif
		{ "mos",0,0,		G_OPTION_ARG_STRING_ARRAY,&mos_options,		"MOS calculation options",		"CQ|LQ"},
		{ "measure-rtp",0,0,	G_OPTION_ARG_NONE,	&rtpe_config.measure_rtp,"Enable measuring RTP statistics and VoIP metrics",NULL},
#ifdef SO_INCOMING_CPU
		{ "socket-cpu-affinity",0,0,G_OPTION_ARG_INT,	&rtpe_config.cpu_affinity,"CPU affinity for media sockets","INT"},
#endif
		{ "janus-secret", 0,0,	G_OPTION_ARG_STRING,	&rtpe_config.janus_secret,"Admin secret for Janus protocol","STRING"},
		{ "rtcp-interval", 0,0,	G_OPTION_ARG_INT,	&rtpe_config.rtcp_interval,"Delay in milliseconds between RTCP packets when generate-rtcp flag is on, where random dispersion < 1 sec is added on top","INT"},
		{ "moh-max-duration", 0,0,	G_OPTION_ARG_INT,	&rtpe_config.moh_max_duration, "Max possible duration (in milliseconds) that can be spent on playing a file. If set to 0 then will be ignored.", "INT"},
		{ "moh-max-repeats", 0,0,	G_OPTION_ARG_INT,	&rtpe_config.moh_max_repeats, "Max possible amount of playback repeats for the music on hold. player-max-duration always takes a precedence over it.", "INT"},
		{ "moh-attr-name", 0,0,	G_OPTION_ARG_STRING,	&rtpe_config.moh_attr_name, "Controls the value to be added to the session level of SDP whenever MoH is triggered.", "STRING"},
		{ "max-recv-iters", 0, 0, G_OPTION_ARG_INT,    &rtpe_config.max_recv_iters,  "Maximum continuous reading cycles in UDP poller loop.", "INT"},
		{ "vsc-start-rec",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.vsc_start_rec.s,"DTMF VSC to start recording.", "STRING"},
		{ "vsc-stop-rec",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.vsc_stop_rec.s,"DTMF VSC to stop recording.", "STRING"},
		{ "vsc-start-stop-rec",0,0,G_OPTION_ARG_STRING,	&rtpe_config.vsc_start_stop_rec.s,"DTMF VSC to start/stop recording.", "STRING"},
		{ "vsc-pause-rec",0,0,	G_OPTION_ARG_STRING,	&rtpe_config.vsc_pause_rec.s,"DTMF VSC to pause recording.", "STRING"},
		{ "vsc-pause-resume-rec",0,0,G_OPTION_ARG_STRING,&rtpe_config.vsc_pause_resume_rec.s,"DTMF VSC to pause/resume recording.", "STRING"},
		{ "vsc-start-pause-resume-rec",0,0,G_OPTION_ARG_STRING,&rtpe_config.vsc_start_pause_resume_rec.s,"DTMF VSC to start/pause/resume recording.", "STRING"},

		{ NULL, }
	};

	config_load_ext(argc, argv, e, " - next-generation media proxy",
			"/etc/rtpengine/rtpengine.conf", "rtpengine", &rtpe_config.common,
			&templates_section, templates);

	// default values, if not configured
	if (rtpe_config.rec_method == NULL)
		rtpe_config.rec_method = g_strdup("pcap");

	if (rtpe_config.rec_format == NULL)
		rtpe_config.rec_format = g_strdup("raw");

	if (rtpe_config.dtls_ciphers == NULL)
		rtpe_config.dtls_ciphers = g_strdup("DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK");

#ifndef WITHOUT_NFTABLES
	if (rtpe_config.nftables_chain == NULL)
		rtpe_config.nftables_chain = g_strdup("rtpengine");

	if (rtpe_config.nftables_base_chain == NULL)
		rtpe_config.nftables_base_chain = g_strdup("INPUT");

	if (!nftables_family
			|| !strcmp(nftables_family, "ip,ip6") || !strcmp(nftables_family, "ip4,ip6")
			|| !strcmp(nftables_family, "ip6,ip") || !strcmp(nftables_family, "ip6,ip4"))
		rtpe_config.nftables_family = 0; // default
	else if (!strcmp(nftables_family, "ip") || !strcmp(nftables_family, "ip4"))
		rtpe_config.nftables_family = NFPROTO_IPV4;
	else if (!strcmp(nftables_family, "ip6"))
		rtpe_config.nftables_family = NFPROTO_IPV6;
	else
		die("Invalid value for 'nftables-family' ('%s')", nftables_family);
#endif

	if (codecs) {
		codeclib_init(1);
		exit(0);
	}

#ifndef WITHOUT_NFTABLES
	int nftables_actions = nftables_start + nftables_stop + nftables_status;
	if (nftables_actions) {
		if (!rtpe_config.nftables_chain || !rtpe_config.nftables_chain[0])
			die("Cannot do nftables setup without knowing which nftables chain (--nftables-chain=...)");
		if (rtpe_config.kernel_table < 0)
			die("Cannot do nftables setup without configured kernel table number");
		if (nftables_actions > 1)
			die("Cannot do more than one of --nftables-start, --nftables-stop or --nftables-status");
		const char *err;
		if (nftables_status) {
			int xv = nftables_check(rtpe_config.nftables_chain, rtpe_config.nftables_base_chain,
					(nftables_args){.family = rtpe_config.nftables_family});
			exit(xv);
		}
		if (nftables_start)
			err = nftables_setup(rtpe_config.nftables_chain, rtpe_config.nftables_base_chain,
					(nftables_args) {.table = rtpe_config.kernel_table,
					.append = rtpe_config.nftables_append,
					.family = rtpe_config.nftables_family});
		else // nftables_stop
			err = nftables_shutdown(rtpe_config.nftables_chain, rtpe_config.nftables_base_chain,
					(nftables_args){.family = rtpe_config.nftables_family});
		if (err)
			die("Failed to perform nftables action: %s (%s)", err, strerror(errno));
		printf("Success\n");
		exit(0);
	}
#endif

	if (!if_a)
		die("Missing option --interface");

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
			str_keyspace_db = STR(*iter);
			int_keyspace_db = strtol(str_keyspace_db.s, &endptr, 10);

			if ((errno == ERANGE && (int_keyspace_db == ULONG_MAX)) || int_keyspace_db >= INT_MAX ||
			    (errno != 0 && int_keyspace_db == 0)) {
				ilog(LOG_ERR, "Fail adding keyspace '" STR_FORMAT "' to redis notifications; errno=%d\n", STR_FMT(&str_keyspace_db), errno);
			} else if (endptr == str_keyspace_db.s) {
				ilog(LOG_ERR, "Fail adding keyspace '" STR_FORMAT "' to redis notifications; no digits found\n", STR_FMT(&str_keyspace_db));
			} else {
				g_queue_push_tail(&rtpe_config.redis_subscribed_keyspaces, GINT_TO_POINTER(int_keyspace_db));
			}
		}
	}

	if (redis_format) {
		if (!strcasecmp(redis_format, "native"))
			rtpe_config.redis_format = 0;
		else if (!strcasecmp(redis_format, "bencode"))
			rtpe_config.redis_format = REDIS_FORMAT_BENCODE;
		else if (!strcasecmp(redis_format, "JSON"))
			rtpe_config.redis_format = REDIS_FORMAT_JSON;
		else
			die("Invalid --redis-format value given");
	}

	parse_listen_list(&rtpe_config.tcp_listen_ep,    listenps,     "listen-tcp");
	parse_listen_list(&rtpe_config.udp_listen_ep,    listenudps,   "listen-udp");
	parse_listen_list(&rtpe_config.ng_listen_ep,     listenngs,    "listen-ng");
	parse_listen_list(&rtpe_config.ng_tcp_listen_ep, listenngtcps, "listen-tcp-ng");
	parse_listen_list(&rtpe_config.cli_listen_ep,    listencli,    "listen-cli");

	if (!rtpe_config.tcp_listen_ep.length && !rtpe_config.udp_listen_ep.length && !rtpe_config.ng_listen_ep.length && !rtpe_config.ng_tcp_listen_ep.length
			&& !(rtpe_config.http_ifs && rtpe_config.http_ifs[0])
			&& !(rtpe_config.https_ifs && rtpe_config.https_ifs[0]))
		die("Missing option --listen-tcp, --listen-udp, --listen-ng, --listen-tcp-ng, "
				"--listen-http, or --listen-https");

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

	if (rtpe_config.homer_ng_capt_proto <0 || rtpe_config.homer_ng_capt_proto > 255)
		die("Invalid homer-ng-capture-proto value");

	if (rtpe_config.default_tos < 0 || rtpe_config.default_tos > 255)
		die("Invalid TOS value");

	if (rtpe_config.control_tos < 0 || rtpe_config.control_tos > 255)
		die("Invalid control-ng TOS value");

	if (rtpe_config.max_recv_iters < 1)
		die("Invalid max-recv-iters value");

	/* if not set, define by default to half an hour */
	if (rtpe_config.moh_max_duration <= 0)
		rtpe_config.moh_max_duration = 1800000;

	if (rtpe_config.timeout <= 0)
		rtpe_config.timeout = 60;

	if (rtpe_config.silent_timeout <= 0)
		rtpe_config.silent_timeout = 3600;

	if (rtpe_config.offer_timeout <= 0)
		rtpe_config.offer_timeout = 3600;

	if (rtpe_config.final_timeout <= 0)
		rtpe_config.final_timeout = 0;

	if (rtpe_config.rtcp_interval <= 0)
		rtpe_config.rtcp_interval = 5000;

	if (redisps) {
		if (redis_ep_parse(&rtpe_config.redis_ep, &rtpe_config.redis_db, &rtpe_config.redis_hostname,
				&rtpe_config.redis_auth, "RTPENGINE_REDIS_AUTH_PW", redisps))
		{
			die("Invalid Redis endpoint [IP:PORT/INT] '%s' (--redis)", redisps);
		}
	}

	if (redisps_write) {
		if (redis_ep_parse(&rtpe_config.redis_write_ep, &rtpe_config.redis_write_db, &rtpe_config.redis_write_hostname,
					&rtpe_config.redis_write_auth, "RTPENGINE_REDIS_WRITE_AUTH_PW", redisps_write))
		{
			die("Invalid Redis endpoint [IP:PORT/INT] '%s' (--redis-write)", redisps_write);
		}
	}

	if (redisps_subscribe)
		if (redis_ep_parse(&rtpe_config.redis_subscribe_ep, &rtpe_config.redis_subscribe_db, &rtpe_config.redis_subscribe_hostname,
					&rtpe_config.redis_subscribe_auth,"RTPENGINE_REDIS_SUBSCRIBE_AUTH_PW", redisps_subscribe))
		{
			rtpe_config.redis_subscribe_db = -1;
			if (redis_ep_parse(&rtpe_config.redis_subscribe_ep, NULL, &rtpe_config.redis_subscribe_hostname,
						&rtpe_config.redis_subscribe_auth,"RTPENGINE_REDIS_SUBSCRIBE_AUTH_PW", redisps_subscribe))
				die("Invalid Redis endpoint [IP:PORT/INT] '%s' (--redis-subscribe)", redisps_subscribe);
		}

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
		trust_address_def = true;

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
			rtpe_config.dtls_signature = DSIG_SHA1;
		else if (!strcasecmp(dtls_sig, "sha1"))
			rtpe_config.dtls_signature = DSIG_SHA1;
		else if (!strcasecmp(dtls_sig, "sha-256"))
			rtpe_config.dtls_signature = DSIG_SHA256;
		else if (!strcasecmp(dtls_sig, "sha256"))
			rtpe_config.dtls_signature = DSIG_SHA256;
		else
			die("Invalid --dtls-signature option ('%s')", dtls_sig);
	}

	if (rtpe_config.dtls_rsa_key_size < 0)
		die("Invalid --dtls-rsa-key-size (%i)", rtpe_config.dtls_rsa_key_size);

	if (rtpe_config.dtls_mtu < 576)
		/* The Internet Protocol requires that hosts must be able to process IP datagrams of at least 576 bytes (for IPv4) or 1280 bytes (for IPv6).
		However, this does not preclude link layers with an MTU smaller than this minimum MTU from conveying IP data. Internet IPv4 path MTU is 68 bytes.*/
		die("Invalid --dtls-mtu (%i)", rtpe_config.dtls_mtu);

	rtpe_config.dtls_mtu -= DTLS_MTU_OVERHEAD;

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

	if (use_audio_player) {
		if (!strcasecmp(use_audio_player, "on-demand")
				|| !strcasecmp(use_audio_player, "on demand")
				|| !strcasecmp(use_audio_player, "off")
				|| !strcasecmp(use_audio_player, "no")
				|| !strcasecmp(use_audio_player, "never"))
			rtpe_config.use_audio_player = UAP_ON_DEMAND;
		else if (!strcasecmp(use_audio_player, "play-media")
				|| !strcasecmp(use_audio_player, "play media")
				|| !strcasecmp(use_audio_player, "media player")
				|| !strcasecmp(use_audio_player, "media-player"))
			rtpe_config.use_audio_player = UAP_PLAY_MEDIA;
		else if (!strcasecmp(use_audio_player, "transcoding")
				|| !strcasecmp(use_audio_player, "transcode"))
			rtpe_config.use_audio_player = UAP_TRANSCODING;
		else if (!strcasecmp(use_audio_player, "always")
				|| !strcasecmp(use_audio_player, "everything")
				|| !strcasecmp(use_audio_player, "force")
				|| !strcasecmp(use_audio_player, "forced"))
			rtpe_config.use_audio_player = UAP_ALWAYS;
		else
			die("Invalid --audio-player option ('%s')", use_audio_player);
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
		else if (!strcmp(mqtt_publish_scope, "summary"))
			rtpe_config.mqtt_publish_scope = MPS_SUMMARY;
		else
			die("Invalid --mqtt-publish-scope option ('%s')", mqtt_publish_scope);
	}
#endif
	for (char **mosp = mos_options; mosp && *mosp; mosp++) {
		char *mos = *mosp;
		if (!strcasecmp(mos, "cq"))
			rtpe_config.mos = MOS_CQ;
		else if (!strcasecmp(mos, "lq"))
			rtpe_config.mos = MOS_LQ;
#ifdef WITH_TRANSCODING
		else if (!strcasecmp(mos, "legacy"))
			rtpe_config.common.mos_type = MOS_LEGACY;
		else if (!strcasecmp(mos, "g107") || !strcasecmp(mos, "g.107"))
			rtpe_config.common.mos_type = MOS_LEGACY;
		else if (!strcasecmp(mos, "g1072") || !strcasecmp(mos, "g.1072")
				|| !strcasecmp(mos, "g.107.2") || !strcasecmp(mos, "g107.2"))
			rtpe_config.common.mos_type = MOS_FB;
#endif
		else
			die("Invalid --mos option ('%s')", mos);
	}

	if (dcc) {
		if (!strcasecmp(dcc, "rsa"))
			rtpe_config.dtls_cert_cipher = DCC_RSA;
		else if (!strcasecmp(dcc, "prime256v1"))
			rtpe_config.dtls_cert_cipher = DCC_EC_PRIME256v1;
		else if (!strcasecmp(dcc, "ec_prime256v1"))
			rtpe_config.dtls_cert_cipher = DCC_EC_PRIME256v1;
		else if (!strcasecmp(dcc, "ec-prime256v1"))
			rtpe_config.dtls_cert_cipher = DCC_EC_PRIME256v1;
		else
			die("Invalid --dtls-cert-cipher option ('%s')", dcc);
	}

	if (control_pmtu) {
		if (!strcasecmp(control_pmtu, "want"))
			rtpe_config.control_pmtu = PMTU_DISC_WANT;
		else if (!strcasecmp(control_pmtu, "dont"))
			rtpe_config.control_pmtu = PMTU_DISC_DONT;
		else if (!strcasecmp(control_pmtu, "don't"))
			rtpe_config.control_pmtu = PMTU_DISC_DONT;
		else
			die("Invalid --control-pmtu option ('%s')", control_pmtu);
	}

#define STR_LEN_INIT(x) if (rtpe_config.x.s) rtpe_config.x.len = strlen(rtpe_config.x.s)
	STR_LEN_INIT(vsc_start_rec);
	STR_LEN_INIT(vsc_stop_rec);
	STR_LEN_INIT(vsc_start_stop_rec);
	STR_LEN_INIT(vsc_pause_rec);
	STR_LEN_INIT(vsc_pause_resume_rec);
	STR_LEN_INIT(vsc_start_pause_resume_rec);
#undef STR_LEN_INIT

	if (rtpe_config.num_threads < 1)
		rtpe_config.num_threads = num_cpu_cores(4);
	if (rtpe_config.media_num_threads < 0)
		rtpe_config.media_num_threads = rtpe_config.num_threads;
	if (rtpe_config.max_sessions < -1)
		rtpe_config.max_sessions = -1;
	if (rtpe_config.redis_num_threads < 1)
		rtpe_config.redis_num_threads = num_cpu_cores(REDIS_RESTORE_NUM_THREADS);

	if (rtpe_config.cpu_affinity < 0) {
		rtpe_config.cpu_affinity = num_cpu_cores(0);
		if (rtpe_config.cpu_affinity <= 0)
			die("Number of CPU cores is unknown, cannot auto-set socket CPU affinity");
	}

	// everything OK, do post-processing

}

static void fill_initial_rtpe_cfg(struct rtpengine_config* ini_rtpe_cfg) {

	struct intf_config* gptr_data;

	for (__auto_type l = rtpe_config.interfaces.head; l ; l=l->next) {
		gptr_data = g_slice_alloc0(sizeof(*gptr_data));
		memcpy(gptr_data, l->data, sizeof(*gptr_data));
		gptr_data->name = str_dup_str(&l->data->name);
		gptr_data->alias = str_dup_str(&l->data->alias);

		t_queue_push_tail(&ini_rtpe_cfg->interfaces, gptr_data);
	}

	for (__auto_type l = rtpe_config.redis_subscribed_keyspaces.head; l ; l = l->next) {
		// l->data has been assigned to a variable before being given into the queue structure not to get a shallow copy
		int num = GPOINTER_TO_INT(l->data);
		g_queue_push_tail(&ini_rtpe_cfg->redis_subscribed_keyspaces, GINT_TO_POINTER(num));
	}

#define X(s) ini_rtpe_cfg->s = rtpe_config.s;
RTPE_CONFIG_INT_PARAMS
RTPE_CONFIG_UINT64_PARAMS
RTPE_CONFIG_BOOL_PARAMS
RTPE_CONFIG_ENDPOINT_PARAMS
RTPE_CONFIG_ENUM_PARAMS
#undef X

#define X(s) ini_rtpe_cfg->s = g_strdup(rtpe_config.s);
RTPE_CONFIG_CHARP_PARAMS
#undef X

	memcpy(&ini_rtpe_cfg->common.log_levels, &rtpe_config.common.log_levels, sizeof(ini_rtpe_cfg->common.log_levels));

#define X(s) endpoint_list_dup(&ini_rtpe_cfg->s, &rtpe_config.s);
RTPE_CONFIG_ENDPOINT_QUEUE_PARAMS
#undef X

	ini_rtpe_cfg->silence_detect_double = rtpe_config.silence_detect_double;
	ini_rtpe_cfg->silence_detect_int = rtpe_config.silence_detect_int;
}

static void free_config_interfaces(struct intf_config *i) {
	str_free_dup(&i->name);
	str_free_dup(&i->alias);
	g_slice_free1(sizeof(*i), i);
}

static void unfill_initial_rtpe_cfg(struct rtpengine_config* ini_rtpe_cfg) {
	// clear queues
	t_queue_clear_full(&ini_rtpe_cfg->interfaces, free_config_interfaces);
	g_queue_clear(&ini_rtpe_cfg->redis_subscribed_keyspaces);

	// free g_strdup
#define X(s) g_free(ini_rtpe_cfg->s);
RTPE_CONFIG_CHARP_PARAMS
#undef X

#define X(x) g_free(ini_rtpe_cfg->x.s);
RTPE_CONFIG_STR_PARAMS
#undef X

#define X(s) endpoint_list_free(&ini_rtpe_cfg->s);
RTPE_CONFIG_ENDPOINT_QUEUE_PARAMS
#undef X

#define X(s) g_strfreev(ini_rtpe_cfg->s);
RTPE_CONFIG_CHARPP_PARAMS
#undef X
}

static void options_free(void) {
	// clear queues
	t_queue_clear_full(&rtpe_config.interfaces, free_config_interfaces);
	g_queue_clear(&rtpe_config.redis_subscribed_keyspaces);

	// free config options
#define X(s) g_free(rtpe_config.s);
RTPE_CONFIG_CHARP_PARAMS
#undef X

#define X(x) g_free(rtpe_config.x.s);
RTPE_CONFIG_STR_PARAMS
#undef X

#define X(s) endpoint_list_free(&rtpe_config.s);
RTPE_CONFIG_ENDPOINT_QUEUE_PARAMS
#undef X

#define X(s) g_strfreev(rtpe_config.s);
RTPE_CONFIG_CHARPP_PARAMS
#undef X

	// free common config options
	config_load_free(&rtpe_config.common);
}

static void early_init(void) {
	socket_init(); // needed for socktype_udp
}

#ifdef WITH_TRANSCODING
static void clib_init(void) {
	media_bufferpool = bufferpool_new(g_malloc, g_free, 64 * 65536);
#ifdef HAVE_LIBURING
	if (rtpe_config.common.io_uring)
		uring_thread_init();
#endif
}
static void clib_cleanup(void) {
	bufferpool_destroy(media_bufferpool);
#ifdef HAVE_LIBURING
	if (rtpe_config.common.io_uring)
		uring_thread_cleanup();
#endif
}
static void clib_loop(void) {
	uring_thread_loop();
	append_thread_lpr_to_glob_lpr();
}
#endif

static void kernel_setup(void) {
	if (rtpe_config.kernel_table < 0)
		goto fallback;
#ifndef WITHOUT_NFTABLES
	const char *err = nftables_setup(rtpe_config.nftables_chain, rtpe_config.nftables_base_chain,
			(nftables_args) {.table = rtpe_config.kernel_table,
			.append = rtpe_config.nftables_append,
			.family = rtpe_config.nftables_family});
	if (err) {
		if (rtpe_config.no_fallback)
			die("Failed to create nftables chains or rules: %s (%s)", err, strerror(errno));
		ilog(LOG_ERR, "FAILED TO CREATE NFTABLES CHAINS OR RULES, KERNEL FORWARDING POSSIBLY WON'T WORK: "
				"%s (%s)", err, strerror(errno));
	}
#endif
	if (!kernel_setup_table(rtpe_config.kernel_table)) {
		if (rtpe_config.no_fallback)
			die("Userspace fallback disallowed - exiting");
		goto fallback;
	}

	if (rtpe_config.player_cache && rtpe_config.kernel_player > 0 && rtpe_config.kernel_player_media > 0) {
	       if (!kernel_init_player(rtpe_config.kernel_player_media, rtpe_config.kernel_player))
		       die("Failed to initialise kernel media player");
	}

	return;

fallback:
	shm_bufferpool = bufferpool_new(g_malloc, g_free, 4096); // fallback userspace bufferpool
}


static void init_everything(GHashTable *templates) {
	bufferpool_init();
	gettimeofday(&rtpe_now, NULL);
	log_init(rtpe_common_config_ptr->log_name);
	log_format(rtpe_config.log_format);
	recording_fs_init(rtpe_config.spooldir, rtpe_config.rec_method, rtpe_config.rec_format);
	rtpe_ssl_init();

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
	kernel_setup();
	interfaces_init(&rtpe_config.interfaces);
	iptables_init();
	control_ng_init();
	if (call_interfaces_init(templates))
		abort();
	statistics_init();
#ifdef WITH_TRANSCODING
	codeclib_thread_init = clib_init;
	codeclib_thread_cleanup = clib_cleanup;
	codeclib_thread_loop = clib_loop;
#endif
	codeclib_init(0);
	media_player_init();
	if (!dtmf_init())
		die("DTMF init failed, see log");
	jitter_buffer_init();
	t38_init();
	if (rtpe_config.mqtt_host && mqtt_init())
		abort();
	codecs_init();
	janus_init();
	if (!kernel_init_table())
		die("Kernel module version mismatch or other fatal error");
}

static void create_everything(void) {
	struct timeval tmp_tv;

	gettimeofday(&rtpe_now, NULL);


	// either one global poller, or one per thread for media sockets plus one for control sockets
#ifdef HAVE_LIBURING
	if (rtpe_config.common.io_uring) {
		rtpe_config.poller_per_thread = true;
		rtpe_poller_add_item = uring_poller_add_item;
		rtpe_poller_del_item = uring_poller_del_item;
		rtpe_poller_del_item_callback = uring_poller_del_item_callback;
		rtpe_poller_blocked = uring_poller_blocked;
		rtpe_poller_isblocked = uring_poller_isblocked;
		rtpe_poller_error = uring_poller_error;
	}
#endif

	if (!rtpe_config.poller_per_thread) {
		num_media_pollers = num_rtpe_pollers = 1;
		num_poller_threads = rtpe_config.num_threads;
	}
	else {
		num_media_pollers = rtpe_config.num_threads;
		num_rtpe_pollers = num_media_pollers + 1;
		num_poller_threads = num_rtpe_pollers;
	}
	rtpe_pollers = g_malloc(sizeof(*rtpe_pollers) * num_rtpe_pollers);
	for (unsigned int i = 0; i < num_rtpe_pollers; i++) {
		rtpe_pollers[i] = 
#ifdef HAVE_LIBURING
			rtpe_config.common.io_uring ? uring_poller_new() :
#endif
			poller_new();
		if (!rtpe_pollers[i])
			die("poller creation failed");
	}
	rtpe_control_poller = rtpe_pollers[num_rtpe_pollers - 1];

	if (call_init())
		abort();

        rwlock_init(&rtpe_config.keyspaces_lock);

	create_listeners(&rtpe_config.tcp_listen_ep,     &rtpe_tcp,            (void *(*)(const endpoint_t *)) control_tcp_new,    false, "TCP control");
	create_listeners(&rtpe_config.udp_listen_ep,     &rtpe_udp,            (void *(*)(const endpoint_t *)) control_udp_new,    true,  "UDP control");
	create_listeners(&rtpe_config.ng_listen_ep,      &rtpe_control_ng,     (void *(*)(const endpoint_t *)) control_ng_new,     true,  "UDP NG control");
	create_listeners(&rtpe_config.ng_tcp_listen_ep,  &rtpe_control_ng_tcp, (void *(*)(const endpoint_t *)) control_ng_tcp_new, false, "TCP NG control");
	create_listeners(&rtpe_config.cli_listen_ep,     &rtpe_cli,            (void *(*)(const endpoint_t *)) cli_new,            false, "CLI");

	if (!is_addr_unspecified(&rtpe_config.redis_write_ep.address)) {
		rtpe_redis_write = redis_new(&rtpe_config.redis_write_ep,
				rtpe_config.redis_write_db,
				rtpe_config.redis_write_hostname,
				rtpe_config.redis_write_auth,
				ANY_REDIS_ROLE,
				rtpe_config.no_redis_required,
				rtpe_config.redis_resolve_on_reconnect);

		if (!rtpe_redis_write)
			die("Cannot start up without running Redis %s write database! See also NO_REDIS_REQUIRED parameter.",
				endpoint_print_buf(&rtpe_config.redis_write_ep));
	}

	if (!is_addr_unspecified(&rtpe_config.redis_subscribe_ep.address)) {
		rtpe_redis_notify = redis_new(&rtpe_config.redis_subscribe_ep,
				rtpe_config.redis_subscribe_db,
				rtpe_config.redis_subscribe_hostname,
				rtpe_config.redis_subscribe_auth,
				ANY_REDIS_ROLE,
				rtpe_config.no_redis_required,
				rtpe_config.redis_resolve_on_reconnect);

		if (!rtpe_redis_notify)
			die("Cannot start up without running Redis %s subscribe database! See also NO_REDIS_REQUIRED parameter.",
				endpoint_print_buf(&rtpe_config.redis_subscribe_ep));
		// subscribed-kespaces takes precedence over db in notify ep
		if (!rtpe_config.redis_subscribed_keyspaces.length) {
			g_queue_push_tail(&rtpe_config.redis_subscribed_keyspaces, GINT_TO_POINTER(rtpe_config.redis_subscribe_db));
		}
	}

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address)) {
		rtpe_redis = redis_new(&rtpe_config.redis_ep,
				rtpe_config.redis_db,
				rtpe_config.redis_hostname,
				rtpe_config.redis_auth,
				(rtpe_redis_write ? ANY_REDIS_ROLE : MASTER_REDIS_ROLE),
				rtpe_config.no_redis_required,
				rtpe_config.redis_resolve_on_reconnect);

		if (!rtpe_redis)
			die("Cannot start up without running Redis %s database! "
					"See also NO_REDIS_REQUIRED parameter.",
				endpoint_print_buf(&rtpe_config.redis_ep));

		if (rtpe_config.redis_subscribed_keyspaces.length && !rtpe_redis_notify) {
			rtpe_redis_notify = redis_new(&rtpe_config.redis_ep,
					rtpe_config.redis_db,
					rtpe_config.redis_hostname,
					rtpe_config.redis_auth,
					(rtpe_redis_write ? ANY_REDIS_ROLE : MASTER_REDIS_ROLE),
					rtpe_config.no_redis_required,
					rtpe_config.redis_resolve_on_reconnect);

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

	if (websocket_init())
		die("Failed to init websocket listener");

	homer_sender_init(&rtpe_config.homer_ep, rtpe_config.homer_protocol, rtpe_config.homer_id);

	rtcp_init(); // must come after Homer init
	init_ng_tracing(); // must come after Homer init

	gettimeofday(&rtpe_latest_graphite_interval_start, NULL);

	timeval_from_us(&tmp_tv, (long long) rtpe_config.graphite_interval*1000000);
	set_graphite_interval_tv(&tmp_tv);

	if (!media_player_preload_files(rtpe_config.preload_media_files))
		die("Failed to preload media files");

	if (!media_player_preload_db(rtpe_config.preload_db_media))
		die("Failed to preload media from database");

	if (rtpe_config.db_media_cache) {
		if (g_mkdir_with_parents(rtpe_config.db_media_cache, 0700))
			die("Failed to create cache directory for media loaded from DB: %s", strerror(errno));

		if (!media_player_preload_cache(rtpe_config.preload_db_cache))
			die("Failed to preload media from database into cache");

	}
}


static void do_redis_restore(void) {
	if (!rtpe_redis)
		return;

	struct timeval redis_start, redis_stop;
	double redis_diff = 0;

	// start redis restore timer
	gettimeofday(&redis_start, NULL);

	// restore
	if (rtpe_redis_notify) {
		// active-active mode: the main DB has our own calls, while
		// the "notify" DB has the "foreign" calls. "foreign" DB goes
		// first as the "owned" DB can do a stray update back to Redis

		// create new connection as notifications are already set up
		struct redis *r = redis_dup(rtpe_redis_notify, -1);

		for (GList *l = rtpe_config.redis_subscribed_keyspaces.head; l; l = l->next) {
			int db = GPOINTER_TO_INT(l->data);
			if (db < 0)
				continue;
			if (redis_restore(r, true, db))
				ilog(LOG_WARN, "Unable to restore calls from the active-active peer");
		}
		redis_close(r);
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


#ifdef HAVE_LIBURING
static void uring_thread_waker(struct thread_waker *wk) {
	struct poller *p = wk->arg;
	uring_poller_wake(p);
}
static void uring_poller_loop(void *ptr) {
	struct poller *p = ptr;

	uring_poller_add_waker(p);

	struct thread_waker wk = {.func = uring_thread_waker, .arg = p};
	thread_waker_add_generic(&wk);

	while (!rtpe_shutdown) {
		gettimeofday(&rtpe_now, NULL);
		uring_poller_poll(p);
		append_thread_lpr_to_glob_lpr();
		log_info_reset();
	}
	thread_waker_del(&wk);
	uring_poller_clear(p);
}
#endif


int main(int argc, char **argv) {
	early_init();
	{
		g_autoptr(GHashTable) templates = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		options(&argc, &argv, templates);
		init_everything(templates);
	}
	create_everything();
	fill_initial_rtpe_cfg(&initial_rtpe_config);

	ilog(LOG_INFO, "Startup complete, version %s", RTPENGINE_VERSION);

	thread_create_detach(sighandler, NULL, "signals");

	/* load monitoring thread */
	thread_create_looper(load_thread, rtpe_config.idle_scheduling,
			rtpe_config.idle_priority, "load monitor", 500000);

	/* separate thread for releasing ports (sockets), which are scheduled for clearing */
	thread_create_looper(release_closed_sockets, rtpe_config.idle_scheduling,
			rtpe_config.idle_priority, "release socks", 1000000);

	/* separate thread for update of running min/max call counters */
	thread_create_looper(call_rate_stats_updater, rtpe_config.idle_scheduling,
			rtpe_config.idle_priority, "call stats", 1000000);

	/* thread to close expired call */
	thread_create_looper(call_timer, rtpe_config.idle_scheduling,
			rtpe_config.idle_priority, "kill calls", 1000000);

	/* thread to refresh DTLS certificate */
	dtls_timer();

	if (rtpe_config.media_refresh > 0)
		thread_create_looper(media_player_refresh_timer, rtpe_config.idle_scheduling,
				rtpe_config.idle_priority, "media refresh", rtpe_config.media_refresh * 1000000LL);

	if (rtpe_config.db_refresh > 0)
		thread_create_looper(media_player_refresh_db, rtpe_config.idle_scheduling,
				rtpe_config.idle_priority, "db refresh", rtpe_config.db_refresh * 1000000LL);

	if (rtpe_config.cache_refresh > 0)
		thread_create_looper(media_player_refresh_cache, rtpe_config.idle_scheduling,
				rtpe_config.idle_priority, "cache refresh", rtpe_config.cache_refresh * 1000000LL);

	if (rtpe_config.expiry_timer > 0)
		thread_create_looper(media_player_expire, rtpe_config.idle_scheduling,
				rtpe_config.idle_priority, "cache expiry", rtpe_config.expiry_timer * 1000000LL);

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && initial_rtpe_config.redis_delete_async)
		thread_create_detach(redis_delete_async_loop, NULL, "redis async");

	if (rtpe_redis_notify)
		thread_create_detach(redis_notify_loop, NULL, "redis notify");

	do_redis_restore();

	if (graphite_is_enabled())
		thread_create_detach(graphite_loop, NULL, "graphite");

#ifdef HAVE_MQTT
	if (mqtt_publish_scope() != MPS_NONE)
		thread_create_detach(mqtt_loop, NULL, "mqtt");
#endif

	ice_thread_launch();

	websocket_start();

	service_notify("READY=1\n");

	for (unsigned int idx = 0; idx < num_poller_threads; ++idx)
		thread_create_detach_prio(
#ifdef HAVE_LIBURING
				rtpe_config.common.io_uring ? uring_poller_loop :
#endif
				poller_loop,
				rtpe_pollers[idx % num_rtpe_pollers],
				rtpe_config.scheduling, rtpe_config.priority,
				idx < rtpe_config.num_threads ? "poller" : "cpoller");

	media_player_launch();
	send_timer_launch();
	jitter_buffer_launch();
	codec_timers_launch();

	// reap threads as they shut down during run time
	threads_join_all(false);

	service_notify("STOPPING=1\n");

        // free libevent
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
        libevent_global_shutdown();
#endif

	websocket_stop();

	if (!is_addr_unspecified(&rtpe_config.redis_ep.address) && initial_rtpe_config.redis_delete_async)
		redis_async_event_base_action(rtpe_redis_write, EVENT_BASE_LOOPBREAK);

	if (rtpe_redis_notify)
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
	log_free();
	janus_free();

	release_listeners(&rtpe_cli);
	release_listeners(&rtpe_udp);
	release_listeners(&rtpe_tcp);
	release_listeners(&rtpe_control_ng);
	release_listeners(&rtpe_control_ng_tcp);
	for (unsigned int idx = 0; idx < num_rtpe_pollers; ++idx)
#ifdef HAVE_LIBURING
		if (rtpe_config.common.io_uring)
			uring_poller_free(&rtpe_pollers[idx]);
		else
#endif
			poller_free(&rtpe_pollers[idx]);
	g_free(rtpe_pollers);
	interfaces_free();
#ifndef WITHOUT_NFTABLES
	nftables_shutdown(rtpe_config.nftables_chain, rtpe_config.nftables_base_chain,
			(nftables_args){.family = rtpe_config.nftables_family});
#endif
	bufferpool_destroy(shm_bufferpool);
	kernel_shutdown_table();
	options_free();
	bufferpool_cleanup();

	return 0;
}
