#ifndef __CALL_H__
#define __CALL_H__




#include <sys/types.h>
#include "ipt_MEDIAPROXY.h"



struct poller;
struct control_stream;



struct peer;
struct callstream;
struct call;
struct callmaster;
struct redis;




struct stream {
	u_int32_t		ip;
	u_int16_t		port;
	char			*mediatype;
};
struct streamrelay {
	int			fd;
	struct stream		peer;
	u_int16_t		localport;
	unsigned char		idx;
	struct peer		*up;
	struct mediaproxy_stats	stats;
	struct mediaproxy_stats	kstats;
	time_t			last;
};
struct peer {
	struct streamrelay	rtps[2];
	char			*tag;
	char			*mediatype;
	char			*codec;
	unsigned char		idx;
	struct callstream	*up;
	int			kernelized:1;
	int			filled:1;
	int			confirmed:1;
};
struct callstream {
	struct peer		peers[2];
	struct call		*call;
};

struct call {
	struct callmaster	*callmaster;

	GQueue			*callstreams;

	char			*callid;
	char			redis_uuid[37];
	time_t			created;
	char			*calling_agent;
	char			*called_agent;
	GHashTable		*infohash;
};

struct callmaster {
	GHashTable		*callhash;
	u_int16_t		lastport;
	struct mediaproxy_stats	statsps;
	struct mediaproxy_stats	stats;

	struct poller		*poller;
	struct redis		*redis;
	int			kernelfd;
	unsigned int		kernelid;
	u_int32_t		ip;
	u_int32_t		adv_ip;
	int			port_min;
	int			port_max;
	unsigned int		timeout;
	unsigned int		silent_timeout;
	unsigned char		tos;
};




struct callmaster *callmaster_new(struct poller *);



char *call_request(const char **, struct callmaster *);
char *call_update_udp(const char **, struct callmaster *);
char *call_lookup(const char **, struct callmaster *);
char *call_lookup_udp(const char **, struct callmaster *);
void call_delete(const char **, struct callmaster *);
char *call_delete_udp(const char **, struct callmaster *);

void calls_status(struct callmaster *, struct control_stream *);



#endif
