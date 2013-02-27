#include "stun.h"

#include <sys/types.h>

#include "str.h"
#include "aux.h"

struct stun {
	u_int16_t msg_type;
	u_int16_t msg_len;
	u_int32_t cookie;
	unsigned char transaction[12];
} __attribute__ ((packed));

struct tlv {
	u_int16_t type;
	u_int16_t len;
	char value[0];
} __attribute__ ((packed));

struct stun_attrs {
	str username;
	str msg_integrity;
	u_int32_t priority;
	int use:1,
	    controlled:1,
	    controlling:1;
};



static int stun_attributes(struct stun_attrs *out, str *s) {
	struct tlv *tlv;
	int len;
	str attr;

	ZERO(*out);

	while (1) {
		if (!s->len)
			return 0;

		tlv = (void *) s->s;
		if (str_shift(s, sizeof(*tlv)))
			return -1;

		len = ntohs(tlv->len);
		attr = *s;
		attr.len = len;

		len = (len + 3) & 0xfffc;
		if (str_shift(s, len))
			return -1;

		switch (ntohs(tlv->type)) {
			case 0x0006: /* username */
				out->username = attr;
				break;
			case 0x0008: /* message-integrity */
				out->msg_integrity = attr;
				break;

			case 0x0025: /* use-candidate */
				out->use = 1;
				break;
			case 0x8029: /* ice-controlled */
				out->controlled = 1;
				break;
			case 0x802a: /* ice-controlling */
				out->controlling = 1;
				break;

			case 0x0024: /* priority */
				if (attr.len != 4)
					return -1;
				out->priority = ntohl(*((u_int32_t *) attr.s));
				break;
		}
	}

	return 0;
}

/* XXX add error reporting */
int stun(char *buf, int len) {
	struct stun *s = (void *) buf;
	int msglen, method, class;
	str attr_str;
	struct stun_attrs attrs;

	msglen = ntohs(s->msg_len);
	if (msglen + 20 > len || msglen < 0)
		return -1;

	class = method = ntohl(s->msg_type);
	class = ((class & 0x10) >> 4) | ((class & 0x100) >> 7);
	method = (method & 0xf) | ((method & 0xe0) >> 1) | ((method & 0x3e00) >> 2);
	if (method != 0x1) /* binding */
		return -1;

	attr_str.s = &buf[20];
	attr_str.len = len;
	if (stun_attributes(&attrs, &attr_str))
		return -1;

	return 0;
}
