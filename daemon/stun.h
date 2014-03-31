#ifndef _STUN_H_
#define _STUN_H_


#include <string.h>
#include <arpa/inet.h>
#include "compat.h"
#include "call.h"
#include "str.h"


#define STUN_COOKIE 0x2112A442UL


INLINE int is_stun(const str *s) {
	const unsigned char *b = (const void *) s->s;
	const u_int32_t *u;

	if (s->len < 20)
		return 0;
	if ((b[0] & 0xb0) != 0x00)
		return 0;
	if ((b[3] & 0x3) != 0x0)
		return 0;
	u = (const void *) &b[4];
	if (*u != htonl(STUN_COOKIE))
		return 0;

	return 1;
}


int stun(str *, struct packet_stream *, struct sockaddr_in6 *);


#endif
