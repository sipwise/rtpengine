#ifndef _STUN_H_
#define _STUN_H_


#include <string.h>
#include <arpa/inet.h>


static inline int is_stun(const char *bx, int len) {
	const unsigned char *b = (const void *) bx;
	const u_int32_t *u;

	if (len < 20)
		return 0;
	if ((b[0] & 0xb0) != 0x00)
		return 0;
	if ((b[3] & 0x3) != 0x0)
		return 0;
	u = (const void *) &b[4];
	if (*u != htonl(0x2112A442))
		return 0;

	return 1;
}


int stun(const char *buf, int len);


#endif
