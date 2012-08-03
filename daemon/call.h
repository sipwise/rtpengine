#ifndef __CALL_H__
#define __CALL_H__




#include <sys/types.h>
#include <glib.h>
#include <time.h>
#include <pcre.h>

#include "control.h"
#include "control_udp.h"
#include "obj.h"
#include "aux.h"

struct poller;
struct control_stream;



struct peer;
struct callstream;
struct call;
struct callmaster;
struct redis;




struct stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
};

struct stream {
	struct in6_addr		ip46;
	u_int16_t		port;
	char			*mediatype;
	enum {
		DIR_UNKNOWN = 0,
		DIR_INTERNAL,
		DIR_EXTERNAL,
	}			direction[2];
	int			num;
};
struct streamrelay {
	int			fd;
	int			fd_family;
	struct stream		peer;
	struct stream		peer_advertised;
	u_int16_t		localport;
	unsigned char		idx;
	struct peer		*up;
	struct stats		stats;
	struct stats		kstats;
	time_t			last;
};
struct peer {
	struct streamrelay	rtps[2];
	char			*tag;
	char			*mediatype;
	char			*codec;
	unsigned char		idx;
	struct callstream	*up;
	int			desired_family;
	int			kernelized:1;
	int			filled:1;
	int			confirmed:1;
};
struct callstream {
	struct obj		obj;
	struct peer		peers[2];
	struct call		*call;
	int			num;
};

struct call {
	struct obj		obj;

	struct callmaster	*callmaster;

	GQueue			*callstreams;

	char			*callid;
	char			redis_uuid[37];
	time_t			created;
	char			*calling_agent;
	char			*called_agent;
	GHashTable		*infohash;
	GHashTable		*branches;
	time_t			lookup_done;

	const char		*log_info;	/* branch */
};

struct callmaster_config {
	int			kernelfd;
	unsigned int		kernelid;
	u_int32_t		ipv4;
	u_int32_t		adv_ipv4;
	struct in6_addr		ipv6;
	struct in6_addr		adv_ipv6;
	int			port_min;
	int			port_max;
	unsigned int		timeout;
	unsigned int		silent_timeout;
	struct redis		*redis;
	char			*b2b_url;
	unsigned char		tos;
};

struct callmaster;



struct callmaster *callmaster_new(struct poller *);
void callmaster_config(struct callmaster *m, struct callmaster_config *c);


char *call_request(const char **, struct callmaster *);
char *call_update_udp(const char **, struct callmaster *);
char *call_lookup(const char **, struct callmaster *);
char *call_lookup_udp(const char **, struct callmaster *);
void call_delete(const char **, struct callmaster *);
char *call_delete_udp(const char **, struct callmaster *);

void calls_status(struct callmaster *, struct control_stream *);

void calls_dump_redis(struct callmaster *);

struct call *call_get_or_create(const char *callid, const char *viabranch, struct callmaster *m);
void callstream_init(struct callstream *s, struct call *ca, int port1, int port2, int num);
void kernelize(struct callstream *c);



#endif
