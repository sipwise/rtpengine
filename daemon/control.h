#ifndef __CONTROL_H__
#define __CONTROL_H__



#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <glib.h>

#include "obj.h"
#include "aux.h"


#define RE_TCP_RL_CMD 		1
#define RE_TCP_RL_CALLID 	2
#define RE_TCP_RL_STREAMS 	3
#define RE_TCP_RL_IP 		4
#define RE_TCP_RL_FROMDOM 	5
#define RE_TCP_RL_FROMTYPE 	6
#define RE_TCP_RL_TODOM 	7
#define RE_TCP_RL_TOTYPE 	8
#define RE_TCP_RL_AGENT 	9
#define RE_TCP_RL_INFO 		10
#define RE_TCP_D_CMD 		11
#define RE_TCP_D_CALLID		12
#define RE_TCP_D_INFO 		13
#define RE_TCP_DIV_CMD 		14

struct poller;
struct control;
struct streambuf;
struct callmaster;




struct control_stream {
	struct obj		obj;

	int			fd;
	mutex_t			lock;
	struct streambuf	*inbuf;
	struct streambuf	*outbuf;
	struct sockaddr_in	inaddr;

	struct control		*control;
	struct poller		*poller;
};


struct control {
	struct obj		obj;

	int			fd;

	mutex_t			lock;
	GList			*streams;

	struct poller		*poller;
	struct callmaster	*callmaster;
};



struct control *control_new(struct poller *, u_int32_t, u_int16_t, struct callmaster *);



#endif
