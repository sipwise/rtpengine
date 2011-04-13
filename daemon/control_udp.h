#ifndef __CONTROL_UDP_H__
#define __CONTROL_UDP_H__




struct poller;
struct callmaster;





struct control_udp {
	int			fd;

	struct poller		*poller;
	struct callmaster	*callmaster;
};





struct control_udp *control_udp_new(struct poller *, u_int32_t, u_int16_t, struct callmaster *);



#endif
