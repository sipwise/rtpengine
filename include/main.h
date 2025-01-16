#ifndef _MAIN_H_
#define _MAIN_H_

#include <glib.h>

#include "helpers.h"
#include "socket.h"
#include "auxlib.h"
#include "types.h"

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

#define RTPE_CONFIG_INT_PARAMS \
	X(kernel_table) \
	X(max_sessions) \
	X(timeout) \
	X(silent_timeout) \
	X(final_timeout) \
	X(offer_timeout) \
	X(moh_max_duration) \
	X(moh_max_repeats) \
	X(delete_delay) \
	X(redis_expires_secs) \
	X(default_tos) \
	X(control_tos) \
	X(graphite_interval) \
	X(graphite_timeout) \
	X(redis_num_threads) \
	X(homer_protocol) \
	X(homer_id) \
	X(homer_ng_capt_proto) \
	X(port_min) \
	X(port_max) \
	X(redis_db) \
	X(redis_write_db) \
	X(redis_subscribe_db) \
	X(redis_allowed_errors) \
	X(redis_disable_time) \
	X(redis_cmd_timeout) \
	X(redis_connect_timeout) \
	X(redis_delete_async) \
	X(redis_delete_async_interval) \
	X(num_threads) \
	X(media_num_threads) \
	X(codec_num_threads) \
	X(nftables_family) \
	X(load_limit) \
	X(cpu_limit) \
	X(priority) \
	X(idle_priority) \
	X(mysql_port) \
	X(dtmf_digit_delay) \
	X(jb_length) \
	X(dtls_rsa_key_size) \
	X(dtls_mtu) \
	X(http_threads) \
	X(dtx_delay) \
	X(max_dtx) \
	X(dtx_buffer) \
	X(dtx_lag) \
	X(dtx_shift) \
	X(amr_cn_dtx) \
	X(kernel_player) \
	X(kernel_player_media) \
	X(audio_buffer_length) \
	X(audio_buffer_delay) \
	X(mqtt_port) \
	X(mqtt_keepalive) \
	X(mqtt_publish_qos) \
	X(mqtt_publish_interval) \
	X(rtcp_interval) \
	X(cpu_affinity) \
	X(max_recv_iters) \
	X(media_refresh) \
	X(db_refresh) \
	X(cache_refresh) \
	X(expiry_timer) \
	X(media_expire) \
	X(db_expire) \
	X(cache_expire) \

#define RTPE_CONFIG_UINT64_PARAMS \
	X(bw_limit)

#define RTPE_CONFIG_BOOL_PARAMS \
	X(homer_rtcp_off) \
	X(homer_ng_on) \
	X(no_fallback) \
	X(reject_invalid_sdp) \
	X(save_interface_ports) \
	X(no_redis_required) \
	X(active_switchover) \
	X(rec_egress) \
	X(nftables_append) \
	X(log_keys) \
	X(dtmf_via_ng) \
	X(dtmf_no_suppress) \
	X(dtmf_no_log_injects) \
	X(jb_clock_drift) \
	X(player_cache) \
	X(poller_per_thread) \
	X(redis_resolve_on_reconnect) \
	X(measure_rtp)

#define RTPE_CONFIG_CHARP_PARAMS \
	X(b2b_url) \
	X(redis_auth) \
	X(redis_write_auth) \
	X(redis_subscribe_auth) \
	X(redis_hostname) \
	X(redis_write_hostname) \
	X(redis_subscribe_hostname) \
	X(moh_attr_name) \
	X(spooldir) \
	X(rec_method) \
	X(rec_format) \
	X(iptables_chain) \
	X(nftables_chain) \
	X(nftables_base_chain) \
	X(scheduling) \
	X(idle_scheduling) \
	X(mysql_host) \
	X(mysql_user) \
	X(mysql_pass) \
	X(mysql_query) \
	X(dtls_ciphers) \
	X(https_cert) \
	X(https_key) \
	X(software_id) \
	X(mqtt_host) \
	X(mqtt_tls_alpn) \
	X(mqtt_id) \
	X(mqtt_user) \
	X(mqtt_pass) \
	X(mqtt_cafile) \
	X(mqtt_capath) \
	X(mqtt_certfile) \
	X(mqtt_keyfile) \
	X(mqtt_publish_topic) \
	X(janus_secret) \
	X(db_media_cache) \

#define RTPE_CONFIG_ENDPOINT_PARAMS \
	X(graphite_ep) \
	X(redis_ep) \
	X(redis_write_ep) \
	X(redis_subscribe_ep) \
	X(homer_ep) \
	X(dtmf_udp_ep)

#define RTPE_CONFIG_ENDPOINT_QUEUE_PARAMS \
	X(tcp_listen_ep) \
	X(udp_listen_ep) \
	X(ng_listen_ep) \
	X(ng_tcp_listen_ep) \
	X(cli_listen_ep)

#define RTPE_CONFIG_STR_PARAMS \
	X(dtx_cn_params) \
	X(cn_payload) \
	X(vsc_start_rec) \
	X(vsc_stop_rec) \
	X(vsc_start_stop_rec) \
	X(vsc_pause_rec) \
	X(vsc_pause_resume_rec) \
	X(vsc_start_pause_resume_rec)

#define RTPE_CONFIG_CHARPP_PARAMS \
	X(http_ifs) \
	X(https_ifs) \
	X(preload_media_files) \
	X(preload_db_media) \
	X(preload_db_cache) \

// these are not automatically included in rtpe_config due to different types
#define RTPE_CONFIG_ENUM_PARAMS \
	X(control_pmtu) \
	X(fmt) \
	X(log_format) \
	X(redis_format) \
	X(endpoint_learning) \
	X(dtls_cert_cipher) \
	X(dtls_signature) \
	X(use_audio_player) \
	X(mqtt_publish_scope) \
	X(mos)

struct rtpengine_config {
	rwlock_t		keyspaces_lock;

	struct rtpengine_common_config common;

#define X(s) int s;
RTPE_CONFIG_INT_PARAMS
#undef X

#define X(s) uint64_t s;
RTPE_CONFIG_UINT64_PARAMS
#undef X

#define X(s) gboolean s;
RTPE_CONFIG_BOOL_PARAMS
#undef X

#define X(s) char *s;
RTPE_CONFIG_CHARP_PARAMS
#undef X

#define X(s) endpoint_t s;
RTPE_CONFIG_ENDPOINT_PARAMS
#undef X

#define X(s) GQueue s;
RTPE_CONFIG_ENDPOINT_QUEUE_PARAMS
#undef X

#define X(s) str s;
RTPE_CONFIG_STR_PARAMS
#undef X

#define X(s) char **s;
RTPE_CONFIG_CHARPP_PARAMS
#undef X

	GQueue		        redis_subscribed_keyspaces;
	enum {
		PMTU_DISC_DEFAULT = 0,
		PMTU_DISC_WANT,
		PMTU_DISC_DONT,
	}			control_pmtu;
	enum xmlrpc_format	fmt;
	enum log_format		log_format;
	intf_config_q		interfaces;
	enum {
		REDIS_FORMAT_BENCODE = 0,
		REDIS_FORMAT_JSON,

		__REDIS_FORMAT_MAX
	}			redis_format;
	enum endpoint_learning	endpoint_learning;
	enum {
		DCC_EC_PRIME256v1 = 0,
		DCC_RSA,
	}			dtls_cert_cipher;
	enum {
		DSIG_SHA256 = 0,
		DSIG_SHA1,
	}			dtls_signature;
	double			silence_detect_double;
	uint32_t		silence_detect_int;
	enum {
		UAP_ON_DEMAND = 0,
		UAP_PLAY_MEDIA,
		UAP_TRANSCODING,
		UAP_ALWAYS,
	}			use_audio_player;
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

extern struct bufferpool *shm_bufferpool;


#endif
