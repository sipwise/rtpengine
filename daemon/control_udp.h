#ifndef __CONTROL_UDP_H__
#define __CONTROL_UDP_H__





#include <pcre.h>
#include <glib.h>
#include <time.h>
#include <netinet/in.h>

#define RE_UDP_COOKIE 		1
#define RE_UDP_UL_CMD 		2
#define RE_UDP_UL_FLAGS 	3
#define RE_UDP_UL_CALLID 	4
#define RE_UDP_UL_VIABRANCH 	5
#define RE_UDP_UL_ADDR4 	6
#define RE_UDP_UL_ADDR6 	7
#define RE_UDP_UL_PORT 		8
#define RE_UDP_UL_FROMTAG 	9
#define RE_UDP_UL_NUM 		10
#define RE_UDP_UL_TOTAG 	11
#define RE_UDP_D_CMD 		12
#define RE_UDP_D_FLAGS 		13
#define RE_UDP_D_CALLID 	14
#define RE_UDP_D_VIABRANCH 	15
#define RE_UDP_V_CMD 		16
#define RE_UDP_V_FLAGS 		17
#define RE_UDP_V_PARMS 		18

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





struct control_udp *control_udp_new(struct poller *, struct in6_addr, u_int16_t, struct callmaster *);



#endif
