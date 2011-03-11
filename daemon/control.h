#ifndef __CONTROL_H__
#define __CONTROL_H__



#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <glib.h>



struct poller;
struct control;
struct streambuf;
struct callmaster;



struct control_stream {
	GList			link;	/* must be first */

	int			fd;
	struct streambuf	*inbuf;
	struct streambuf	*outbuf;
	struct sockaddr_in	inaddr;

	struct control		*control;
	struct poller		*poller;
};


struct control {
	int			fd;

	GList			*stream_head;

	struct poller		*poller;
	struct callmaster	*callmaster;
};


struct control *control_new(struct poller *, u_int32_t, u_int16_t, struct callmaster *);



#endif
