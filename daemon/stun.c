#include "stun.h"
#include <sys/types.h>

struct stun {
	u_int16_t msg_type;
	u_int16_t msg_len;
	u_int32_t cookie;
	unsigned char transaction[12];
} __attribute__ ((packed));


int stun(const char *buf, int len) {
	const struct stun *s = (const void *) buf;
	int msglen, method, class;

	msglen = ntohs(s->msg_len);
	class = method = ntohl(s->msg_type);
	class = ((class & 0x10) >> 4) | ((class & 0x100) >> 7);
	method = (method & 0xf) | ((method & 0xe0) >> 1) | ((method & 0x3e00) >> 2);
	if (method != 0x1) /* binding */
		return -1;

	return 0;
}
