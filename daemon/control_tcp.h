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
struct callmaster;
struct control_tcp;
struct control_stream;



struct control_tcp *control_tcp_new(struct poller *, u_int32_t, u_int16_t, struct callmaster *);
void control_stream_printf(struct control_stream *, const char *, ...) __attribute__ ((format (printf, 2, 3)));



#endif
