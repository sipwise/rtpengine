#include "stun.h"

#include <sys/types.h>
#include <string.h>
#include <sys/socket.h>
#include <zlib.h>
#include <openssl/hmac.h>

#include "str.h"
#include "aux.h"



#define STUN_CRC_XOR 0x5354554eUL
#define STUN_USERNAME 0x0006
#define STUN_MESSAGE_INTEGRITY 0x0008
#define STUN_FINGERPRINT 0x8028


struct stun {
	u_int16_t msg_type;
	u_int16_t msg_len;
	u_int32_t cookie;
	unsigned char transaction[12];
} __attribute__ ((packed));

struct tlv {
	u_int16_t type;
	u_int16_t len;
} __attribute__ ((packed));

struct stun_attrs {
	str username;
	char *msg_integrity_attr;
	str msg_integrity;
	u_int32_t priority;
	char *fingerprint_attr;
	u_int32_t fingerprint;
	int use:1,
	    controlled:1,
	    controlling:1;
};

struct stun_error {
	struct stun stun;
	struct tlv error_code;
	u_int32_t codes;
} __attribute__ ((packed));

struct stun_fingerprint {
	struct tlv tlv;
	u_int32_t crc;
} __attribute__ ((packed));



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

		if (out->msg_integrity.s && ntohs(tlv->type) != STUN_FINGERPRINT)
			return -1;

		switch (ntohs(tlv->type)) {
			case STUN_USERNAME:
				out->username = attr;
				break;
			case STUN_MESSAGE_INTEGRITY:
				if (attr.len != 20)
					return -1;
				out->msg_integrity_attr = (void *) tlv;
				out->msg_integrity = attr;
				break;
			case STUN_FINGERPRINT:
				if (attr.len != 4)
					return -1;
				out->fingerprint_attr = (void *) tlv;
				out->fingerprint = ntohl(*(u_int32_t *) attr.s);
				goto out;

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

out:
	return 0;
}

static inline void stun_error_len(int fd, struct sockaddr_in6 *sin, struct stun *req,
		int code, char *reason, int len)
{
	struct stun_error err;
	struct stun_fingerprint fp;
	struct msghdr mh;
	struct iovec iov[3];

	err.stun.msg_type = htons(0x0111); /* binding error response */
	err.stun.cookie = htonl(STUN_COOKIE);
	memcpy(&err.stun.transaction, &req->transaction, sizeof(err.stun.transaction));
	err.error_code.type = htons(0x0009); /* error-code */
	err.error_code.len = htons(len + sizeof(err.codes));
	err.codes = htonl(((code / 100) << 8) | (code % 100));

	ZERO(mh);
	ZERO(iov);

	iov[0].iov_base = &err;
	iov[0].iov_len = sizeof(err);
	iov[1].iov_base = reason;
	iov[1].iov_len = (len + 3) & 0xfffc;
	iov[2].iov_base = &fp;
	iov[2].iov_len = sizeof(fp);

	err.stun.msg_len = htons(iov[1].iov_len + sizeof(err.codes) + sizeof(err.error_code)
			+ iov[2].iov_len);

	fp.crc = crc32(0, iov[0].iov_base, iov[0].iov_len);
	fp.crc = crc32(fp.crc, iov[1].iov_base, iov[1].iov_len);
	fp.crc = htonl(fp.crc ^ STUN_CRC_XOR);
	fp.tlv.type = htons(STUN_FINGERPRINT);
	fp.tlv.len = htons(4);

	mh.msg_name = sin;
	mh.msg_namelen = sizeof(*sin);
	mh.msg_iov = iov;
	mh.msg_iovlen = 3;

	sendmsg(fd, &mh, 0);
}

#define stun_error(fd, sin, str, code, reason) \
	stun_error_len(fd, sin, str, code, reason "\0\0\0", strlen(reason))



static int check_fingerprint(str *msg, struct stun_attrs *attrs) {
	int len;
	u_int32_t crc;

	len = attrs->fingerprint_attr - msg->s;
	crc = crc32(0, (void *) msg->s, len);
	crc ^= STUN_CRC_XOR;
	if (crc != attrs->fingerprint)
		return -1;

	return 0;
}

static int check_auth(str *msg, struct stun_attrs *attrs, struct peer *peer) {
	HMAC_CTX ctx;
	u_int16_t lenX;
	unsigned char digest[20];
	int ret;
	str ufrag[2];

	if (!peer->ice_ufrag[0].s || !peer->ice_ufrag[0].len)
		return -1;
	if (!peer->ice_pwd.s || !peer->ice_pwd.len)
		return -1;

	ufrag[0] = attrs->username;
	str_chr_str(&ufrag[1], &ufrag[0], ':');
	if (!ufrag[1].s)
		return -1;
	ufrag[0].len -= ufrag[1].len;
	str_shift(&ufrag[1], 1);

	if (!ufrag[0].len || !ufrag[1].len)
		return -1;
	if (str_cmp_str(&ufrag[0], &peer->ice_ufrag[0]))
		return -1;

	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, peer->ice_pwd.s, peer->ice_pwd.len, EVP_sha1());
	HMAC_Update(&ctx, (void *) msg->s, OFFSET_OF(struct stun, msg_len));
	lenX = htons((attrs->msg_integrity_attr - msg->s) - 20 + 24);
	HMAC_Update(&ctx, (void *) &lenX, sizeof(lenX));
	HMAC_Update(&ctx, (void *) msg->s + OFFSET_OF(struct stun, cookie),
			ntohs(lenX) + - 24 + 20 - OFFSET_OF(struct stun, cookie));
	HMAC_Final(&ctx, digest, NULL);

	ret = memcmp(digest, attrs->msg_integrity.s, 20) ? -1 : 0;

	HMAC_CTX_cleanup(&ctx);

	return ret;
}

/* XXX add error reporting */
int stun(str *b, struct streamrelay *sr, struct sockaddr_in6 *sin) {
	struct stun *s = (void *) b->s;
	int msglen, method, class;
	str attr_str;
	struct stun_attrs attrs;

	msglen = ntohs(s->msg_len);
	if (msglen + 20 > b->len || msglen < 0)
		return -1;

	class = method = ntohs(s->msg_type);
	class = ((class & 0x10) >> 4) | ((class & 0x100) >> 7);
	method = (method & 0xf) | ((method & 0xe0) >> 1) | ((method & 0x3e00) >> 2);
	if (method != 0x1) /* binding */
		return -1;

	attr_str.s = &b->s[20];
	attr_str.len = b->len - 20;
	if (stun_attributes(&attrs, &attr_str))
		return -1;

	if (class != 0x0)
		return -1; /* XXX ? */

	/* request */
	if (!attrs.username.s || !attrs.msg_integrity.s || !attrs.fingerprint_attr)
		goto bad_req;

	if (check_fingerprint(b, &attrs))
		return -1;
	if (check_auth(b, &attrs, sr->up))
		goto unauth;

	return 0;

bad_req:
	stun_error(sr->fd.fd, sin, s, 400, "Bad request");
	return 0;
unauth:
	stun_error(sr->fd.fd, sin, s, 401, "Unauthorized");
	return 0;
}
