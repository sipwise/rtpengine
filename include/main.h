#ifndef _MAIN_H_
#define _MAIN_H_

#include <glib.h>

#include "helpers.h"
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

#ifndef MAX_RECV_ITERS
#define MAX_RECV_ITERS 50
#endif

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
	enum {
		PMTU_DISC_DEFAULT = 0,
		PMTU_DISC_WANT,
		PMTU_DISC_DONT,
	}			control_pmtu;
	enum xmlrpc_format	fmt;
	enum log_format		log_format;
	endpoint_t		graphite_ep;
	int			graphite_interval;
	int			graphite_timeout;
	int			redis_num_threads;
	GQueue			interfaces;
	GQueue			tcp_listen_ep;
	GQueue			udp_listen_ep;
	GQueue			ng_listen_ep;
	GQueue			ng_tcp_listen_ep;
	GQueue			cli_listen_ep;
	endpoint_t		redis_ep;
	endpoint_t		redis_write_ep;
	endpoint_t		homer_ep;
	int			homer_protocol;
	int			homer_id;
	int			homer_ng_capt_proto;
	gboolean		homer_rtcp_off;
	gboolean		homer_ng_on;
	gboolean		no_fallback;
	gboolean		reject_invalid_sdp;
	gboolean		save_interface_ports;
	int			port_min;
	int			port_max;
	int			redis_db;
	int			redis_write_db;
	gboolean		no_redis_required;
	int			redis_allowed_errors;
	int			redis_disable_time;
	int			redis_cmd_timeout;
	int			redis_connect_timeout;
	int			redis_delete_async;
	int			redis_delete_async_interval;
	char			*redis_auth;
	char			*redis_write_auth;
	gboolean		active_switchover;
	int			num_threads;
	int			media_num_threads;
	char			*spooldir;
	char			*rec_method;
	char			*rec_format;
	gboolean		rec_egress;
	char			*iptables_chain;
	char			*nftables_chain;
	char			*nftables_base_chain;
	gboolean		nftables_append;
	int			nftables_family;
	int			load_limit;
	int			cpu_limit;
	uint64_t		bw_limit;
	char			*scheduling;
	int			priority;
	char			*idle_scheduling;
	int			idle_priority;
	gboolean		log_keys;
	char			*mysql_host;
	int			mysql_port;
	char			*mysql_user;
	char			*mysql_pass;
	char			*mysql_query;
	endpoint_t		dtmf_udp_ep;
	gboolean		dtmf_via_ng;
	gboolean		dtmf_no_suppress;
	int			dtmf_digit_delay;
	gboolean		dtmf_no_log_injects;
	enum endpoint_learning	endpoint_learning;
	int                     jb_length;
	gboolean		jb_clock_drift;
	enum {
		DCC_EC_PRIME256v1 = 0,
		DCC_RSA,
	}			dtls_cert_cipher;
	int			dtls_rsa_key_size;
	int			dtls_mtu;
	char			*dtls_ciphers;
	enum {
		DSIG_SHA256 = 0,
		DSIG_SHA1,
	}			dtls_signature;
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
	gboolean		player_cache;
	int			audio_buffer_length;
	int			audio_buffer_delay;
	enum {
		UAP_ON_DEMAND = 0,
		UAP_PLAY_MEDIA,
		UAP_TRANSCODING,
		UAP_ALWAYS,
	}			use_audio_player;
	char			*software_id;
	gboolean		poller_per_thread;
	char			*mqtt_host;
	int			mqtt_port;
	char			*mqtt_tls_alpn;
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
		MPS_SUMMARY,
	}			mqtt_publish_scope;
	enum {
		MOS_CQ = 0,
		MOS_LQ,
	}			mos;
	gboolean		measure_rtp;
	int			rtcp_interval;
	int			cpu_affinity;
	char			*janus_secret;
	int			max_recv_iters;
	str			vsc_start_rec;
	str			vsc_stop_rec;
	str			vsc_start_stop_rec;
	str			vsc_pause_rec;
	str			vsc_pause_resume_rec;
	str			vsc_start_pause_resume_rec;
};


struct poller;

/**
 * Main global poller instance.
 * This object is responsible for maintaining and holding the entry-point references.
 *
 *  TODO: convert to struct instead of pointer?
 */
extern struct poller **rtpe_pollers; // at least one poller, in an array
extern struct poller *rtpe_control_poller; // poller for control sockets (maybe rtpe_pollers[0])
extern unsigned int num_media_pollers; // for media sockets, >= 1
extern unsigned int rtpe_poller_rr_iter; // round-robin assignment of pollers to each thread

INLINE struct poller *rtpe_get_poller(void) {
	// XXX optimise this for num_media_pollers == 1 ?
	return rtpe_pollers[g_atomic_int_add(&rtpe_poller_rr_iter, 1) % num_media_pollers];
}

extern struct rtpengine_config rtpe_config;
extern struct rtpengine_config initial_rtpe_config;

extern GQueue rtpe_control_ng;
extern GQueue rtpe_control_ng_tcp;



#endif
