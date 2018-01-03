#ifndef _MAIN_H_
#define _MAIN_H_


#include "aux.h"
#include <glib.h>
#include "socket.h"

enum xmlrpc_format {
	XF_SEMS = 0,
	XF_CALLID,
};

struct rtpengine_config {
	/* everything below protected by config_lock */
	rwlock_t		config_lock;
	int			kernel_table;
	int			max_sessions;
	int			timeout;
	int			silent_timeout;
	int			final_timeout;
	int			delete_delay;
	GQueue		        redis_subscribed_keyspaces;
	int			redis_expires_secs;
	char			*b2b_url;
	int			default_tos;
	int			control_tos;
	enum xmlrpc_format	fmt;
	endpoint_t		graphite_ep;
	int			graphite_interval;
	int			redis_num_threads;
	GQueue			interfaces;
	endpoint_t		tcp_listen_ep;
	endpoint_t		udp_listen_ep;
	endpoint_t		ng_listen_ep;
	endpoint_t		cli_listen_ep;
	endpoint_t		redis_ep;
	endpoint_t		redis_write_ep;
	endpoint_t		homer_ep;
	int			homer_protocol;
	int			homer_id;
	int			no_fallback;
	int			port_min;
	int			port_max;
	int			redis_db;
	int			redis_write_db;
	int			no_redis_required;
	char			*redis_auth;
	char			*redis_write_auth;
	int			num_threads;
	char			*spooldir;
	char			*rec_method;
	char			*rec_format;
	char			*iptables_chain;
};


struct poller;
extern struct poller *rtpe_poller; // main global poller instance XXX convert to struct instead of pointer?


extern struct rtpengine_config rtpe_config;



#endif
