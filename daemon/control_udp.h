#ifndef __CONTROL_UDP_H__
#define __CONTROL_UDP_H__





#include <pcre.h>
#include <glib.h>
#include <time.h>



struct poller;
struct callmaster;





struct control_udp {
	int			fd;

	struct poller		*poller;
	struct callmaster	*callmaster;

	pcre			*parse_re;
	pcre_extra		*parse_ree;
	pcre			*fallback_re;
	GHashTable		*fresh_cookies, *stale_cookies;
	GStringChunk		*fresh_chunks,  *stale_chunks;
	time_t			oven_time;
};





struct control_udp *control_udp_new(struct poller *, u_int32_t, u_int16_t, struct callmaster *);



#endif
