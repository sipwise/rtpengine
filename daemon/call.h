#ifndef __CALL_H__
#define __CALL_H__




#include <sys/types.h>
#include <glib.h>
#ifndef NO_REDIS
#include <hiredis.h>
#endif
#include "ipt_MEDIAPROXY.h"



struct poller;
struct control_stream;



struct peer;
struct callstream;
struct call;
struct callmaster;
#ifndef NO_REDIS
struct redis;
#endif




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
	int			used:1;
};
struct callstream {
	struct peer		peers[2];
	struct call		*call;
};

struct call {
	struct callmaster	*callmaster;

	GQueue			*callstreams;

	char			*callid;
#ifndef NO_REDIS
	char			redis_uuid[37];
#endif
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
#ifndef NO_REDIS
	struct redis		*redis;
#endif
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

#ifndef NO_REDIS
void call_restore(struct callmaster *, char *, redisReply **, GList *);
void calls_dump_redis(struct callmaster *);
#endif



#endif
