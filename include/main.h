#ifndef _MAIN_H_
#define _MAIN_H_


#include "aux.h"
#include <glib.h>
#include "socket.h"
#include "auxlib.h"

enum xmlrpc_format {
	XF_SEMS = 0,
	XF_CALLID,
	XF_KAMAILIO,
};
enum log_format {
	LF_DEFAULT = 0,
	LF_PARSABLE,

	__LF_LAST
};
enum endpoint_learning {
	EL_DELAYED = 0,
	EL_IMMEDIATE = 1,
	EL_OFF = 2,
	EL_HEURISTIC = 3,

	__EL_LAST
};

struct rtpengine_config {
	/* everything below protected by config_lock */
	rwlock_t		config_lock;

	struct rtpengine_common_config common;

	int			kernel_table;
	int			max_sessions;
	int			timeout;
	int			silent_timeout;
	int			final_timeout;
	int			offer_timeout;
	int			delete_delay;
	GQueue		        redis_subscribed_keyspaces;
	int			redis_expires_secs;
	char			*b2b_url;
	int			default_tos;
	int			control_tos;
	enum xmlrpc_format	fmt;
	enum log_format		log_format;
	endpoint_t		graphite_ep;
	int			graphite_interval;
	int			redis_num_threads;
	GQueue			interfaces;
	endpoint_t		tcp_listen_ep;
	endpoint_t		udp_listen_ep;
	endpoint_t		ng_listen_ep;
	endpoint_t		ng_tcp_listen_ep;
	endpoint_t		cli_listen_ep;
	endpoint_t		redis_ep;
	endpoint_t		redis_write_ep;
	endpoint_t		homer_ep;
	int			homer_protocol;
	int			homer_id;
	int			no_fallback;
	int			save_interface_ports;
	int			port_min;
	int			port_max;
	int			redis_db;
	int			redis_write_db;
	int			no_redis_required;
	int			redis_allowed_errors;
	int			redis_disable_time;
	int			redis_cmd_timeout;
	int			redis_connect_timeout;
	int			redis_delete_async;
	int			redis_delete_async_interval;
	char			*redis_auth;
	char			*redis_write_auth;
	int			active_switchover;
	int			num_threads;
	int			media_num_threads;
	char			*spooldir;
	char			*rec_method;
	char			*rec_format;
	char			*iptables_chain;
	int			load_limit;
	int			cpu_limit;
	uint64_t		bw_limit;
	char			*scheduling;
	int			priority;
	char			*idle_scheduling;
	int			idle_priority;
	int			log_keys;
	char			*mysql_host;
	int			mysql_port;
	char			*mysql_user;
	char			*mysql_pass;
	char			*mysql_query;
	endpoint_t		dtmf_udp_ep;
	int			dtmf_via_ng;
	int			dtmf_no_suppress;
	enum endpoint_learning	endpoint_learning;
	int                     jb_length;
	int                     jb_clock_drift;
	int			dtls_rsa_key_size;
	int			dtls_mtu;
	char			*dtls_ciphers;
	int			dtls_signature;
	char			**http_ifs;
	char			**https_ifs;
	char			*https_cert;
	char			*https_key;
	int			http_threads;
	int			dtx_delay;
	int			max_dtx;
	int			dtx_buffer;
	int			dtx_lag;
	int			dtx_shift;
	str			dtx_cn_params;
	int			amr_cn_dtx;
	double			silence_detect_double;
	uint32_t		silence_detect_int;
	str			cn_payload;
	int			reorder_codecs;
	char			*software_id;
	int			poller_per_thread;
	char			*mqtt_host;
	int			mqtt_port;
	char			*mqtt_id;
	int			mqtt_keepalive;
	char			*mqtt_user;
	char			*mqtt_pass;
	char			*mqtt_cafile;
	char			*mqtt_capath;
	char			*mqtt_certfile;
	char			*mqtt_keyfile;
	int			mqtt_publish_qos;
	char			*mqtt_publish_topic;
	int			mqtt_publish_interval;
	enum {
		MPS_NONE = -1,
		MPS_GLOBAL = 0,
		MPS_CALL,
		MPS_MEDIA,
	}			mqtt_publish_scope;
	enum {
		MOS_CQ = 0,
		MOS_LQ,
	}			mos;
	int			cpu_affinity;
	char			*janus_secret;
};


struct poller;
struct poller_map;

extern struct poller *rtpe_poller; // main global poller instance XXX convert to struct instead of pointer?
extern struct poller_map *rtpe_poller_map;

extern struct rtpengine_config rtpe_config;
extern struct rtpengine_config initial_rtpe_config;



#endif
