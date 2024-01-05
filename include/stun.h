#ifndef _STUN_H_
#define _STUN_H_

#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "compat.h"
#include "call.h"
#include "str.h"
#include "socket.h"

#define STUN_COOKIE 0x2112A442UL

struct stun_attrs {
	str username;
	char *msg_integrity_attr;
	str msg_integrity;
	uint32_t priority;
	char *fingerprint_attr;
	uint32_t fingerprint;
	uint64_t tiebreaker;
	endpoint_t mapped;
	unsigned int error_code;
	unsigned int use:1,
	             controlled:1,
	             controlling:1;
};


INLINE int is_stun(const str *s) {
	const unsigned char *b = (const void *) s->s;
	const uint32_t *u;

	if (s->len < 20)
		return 0;
	if ((b[0] & 0xc0) != 0x00)
		return 0;
	if ((b[3] & 0x3) != 0x0)
		return 0;
	u = (const void *) &b[4];
	if (*u != htonl(STUN_COOKIE))
		return 0;

	return 1;
}


int stun(const str *, stream_fd *, const endpoint_t *);

int stun_binding_request(const endpoint_t *dst, uint32_t transaction[3], str *pwd,
		str ufrags[2], int controlling, uint64_t tiebreaker, uint32_t priority,
		socket_t *, int);

#endif
