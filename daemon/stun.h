#ifndef _STUN_H_
#define _STUN_H_


#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "compat.h"
#include "call.h"
#include "str.h"


#define STUN_COOKIE 0x2112A442UL



struct stun_attrs {
	str username;
	char *msg_integrity_attr;
	str msg_integrity;
	u_int32_t priority;
	char *fingerprint_attr;
	u_int32_t fingerprint;
	u_int64_t tiebreaker;
	struct in6_addr mapped_address;
	unsigned int mapped_port; /* XXX use struct endpoint */
	unsigned int error_code;
	int use:1,
	    controlled:1,
	    controlling:1;
};


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


int stun(str *, struct packet_stream *, struct sockaddr_in6 *, struct in6_addr *);

int stun_binding_request(struct sockaddr_in6 *dst, u_int32_t transaction[3], str *pwd,
		str ufrags[2], int controlling, u_int64_t tiebreaker, u_int32_t priority,
		struct in6_addr *src, int fd, int);

#endif
