#ifndef __CONTROL_UDP_H__
#define __CONTROL_UDP_H__





#include <pcre.h>
#include <glib.h>
#include <time.h>
#include <netinet/in.h>
#include "obj.h"
#include "aux.h"
#include "cookie_cache.h"
#include "udp_listener.h"
#include "socket.h"



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
#define RE_UDP_DQ_CMD 		12
#define RE_UDP_DQ_FLAGS		13
#define RE_UDP_DQ_CALLID 	14
#define RE_UDP_DQ_VIABRANCH 	15
#define RE_UDP_DQ_FROMTAG	16
#define RE_UDP_DQ_TOTAG		17
#define RE_UDP_V_CMD 		18
#define RE_UDP_V_FLAGS 		19
#define RE_UDP_V_PARMS 		20

struct poller;





struct control_udp {
	struct obj		obj;

	struct cookie_cache	cookie_cache;
	socket_t		udp_listener;

	pcre			*parse_re;
	pcre_extra		*parse_ree;
	pcre			*fallback_re;
};





struct control_udp *control_udp_new(struct poller *, endpoint_t *);



#endif
