#include "stun.h"

#include <sys/types.h>
#include <string.h>
#include <sys/socket.h>
#include <zlib.h>
#include <openssl/hmac.h>
#include <glib.h>

#include "compat.h"
#include "str.h"
#include "aux.h"
#include "log.h"



#define STUN_CRC_XOR 0x5354554eUL

#define STUN_USERNAME 0x0006
#define STUN_MESSAGE_INTEGRITY 0x0008
#define STUN_ERROR_CODE 0x0009
#define STUN_UNKNOWN_ATTRIBUTES 0x000a
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_FINGERPRINT 0x8028

#define STUN_CLASS_REQUEST 0x00
#define STUN_CLASS_INDICATION 0x01
#define STUN_CLASS_SUCCESS 0x02
#define STUN_CLASS_ERROR 0x03

#define STUN_METHOD_BINDING 0x01

#define STUN_MESSAGE_TYPE(method, class) \
	(((method) & 0xf) | (((method) & 0x70) << 1) \
	 | (((method) & 0x0f80) << 2) | (((class) & 0x1) << 4) \
	 | (((class) & 0x2) << 7))

#define STUN_BINDING_SUCCESS_RESPONSE \
	STUN_MESSAGE_TYPE(STUN_METHOD_BINDING, STUN_CLASS_SUCCESS)
#define STUN_BINDING_ERROR_RESPONSE \
	STUN_MESSAGE_TYPE(STUN_METHOD_BINDING, STUN_CLASS_ERROR)

#define UNKNOWNS_COUNT 16



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

struct header {
	u_int16_t msg_type;
	u_int16_t msg_len;
	u_int32_t cookie;
	u_int32_t transaction[3];
} __attribute__ ((packed));

struct tlv {
	u_int16_t type;
	u_int16_t len;
} __attribute__ ((packed));

struct generic {
	struct tlv tlv;
} __attribute__ ((packed));

struct error_code {
	struct tlv tlv;
	u_int32_t codes;
} __attribute__ ((packed));

struct fingerprint {
	struct tlv tlv;
	u_int32_t crc;
} __attribute__ ((packed));

struct msg_integrity {
	struct tlv tlv;
	char digest[20];
} __attribute__ ((packed));

struct xor_mapped_address {
	struct tlv tlv;
	u_int16_t family;
	u_int16_t port;
	u_int32_t address[4];
} __attribute__ ((packed));



static int stun_attributes(struct stun_attrs *out, str *s, u_int16_t *unknowns) {
	struct tlv *tlv;
	int len, type, uc;
	str attr;

	ZERO(*out);
	uc = 0;
	unknowns[0] = 0xffff;

	while (1) {
		if (!s->len)
			break;

		tlv = (void *) s->s;
		if (str_shift(s, sizeof(*tlv)))
			return -1;

		len = ntohs(tlv->len);
		attr = *s;
		attr.len = len;

		len = (len + 3) & 0xfffc;
		if (str_shift(s, len))
			return -1;

		type = ntohs(tlv->type);
		if (out->msg_integrity.s && type != STUN_FINGERPRINT)
			return -1;

		switch (type) {
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

			default:
				ilog(LOG_INFO, "Unknown STUN attribute: 0x%04x", type);
				if ((type & 0x8000))
					break;
				unknowns[uc] = tlv->type;
				unknowns[++uc] = 0xffff;
				if (uc >= UNKNOWNS_COUNT - 1)
					return -1;
				break;
		}
	}

out:
	return uc ? -1 : 0;
}

static void output_init(struct msghdr *mh, struct iovec *iov, struct sockaddr_in6 *sin,
		struct header *hdr, unsigned short code, u_int32_t *transaction,
		unsigned char *buf, int buflen)
{
	ZERO(*mh);

	mh->msg_control = buf;
	mh->msg_controllen = buflen;

	mh->msg_name = sin;
	mh->msg_namelen = sizeof(*sin);
	mh->msg_iov = iov;
	mh->msg_iovlen = 1;

	iov->iov_base = hdr;
	iov->iov_len = sizeof(*hdr);

	hdr->msg_type = htons(code);
	hdr->msg_len = 0;
	hdr->cookie = htonl(STUN_COOKIE);
	memcpy(&hdr->transaction, transaction, sizeof(hdr->transaction));
}

INLINE void __output_add(struct msghdr *mh, struct tlv *tlv, unsigned int len, u_int16_t code,
		void *append, unsigned int append_len)
{
	struct iovec *iov;
	struct header *hdr;

	iov = &mh->msg_iov[mh->msg_iovlen++];
	iov->iov_base = tlv;
	iov->iov_len = len;

	tlv->type = htons(code);
	tlv->len = htons(len - sizeof(*tlv) + append_len);

	hdr = mh->msg_iov->iov_base;
	hdr->msg_len += len + ((append_len + 3) & 0xfffc);

	if (append_len) {
		iov = &mh->msg_iov[mh->msg_iovlen++];
		iov->iov_base = append; /* must have space for padding */
		iov->iov_len = (append_len + 3) & 0xfffc;
	}
}

#define output_add(mh, attr, code) \
	__output_add(mh, &(attr)->tlv, sizeof(*(attr)), code, NULL, 0)
#define output_add_len(mh, attr, code, len) \
	__output_add(mh, &(attr)->tlv, len + sizeof(struct tlv), code, NULL, 0)
#define output_add_data(mh, attr, code, data, len) \
	__output_add(mh, &(attr)->tlv, sizeof(*(attr)), code, data, len)


static void output_finish(struct msghdr *mh, struct callmaster *cm) {
	struct header *hdr;

	hdr = mh->msg_iov->iov_base;
	hdr->msg_len = htons(hdr->msg_len);

	callmaster_msg_mh_src(cm, mh);
}

static void fingerprint(struct msghdr *mh, struct fingerprint *fp) {
	int i;
	struct iovec *iov;
	struct header *hdr;

	output_add(mh, fp, STUN_FINGERPRINT);
	iov = mh->msg_iov;
	hdr = iov->iov_base;
	hdr->msg_len = htons(hdr->msg_len);

	fp->crc = crc32(0, NULL, 0);
	for (i = 0; i < mh->msg_iovlen - 1; i++)
		fp->crc = crc32(fp->crc, iov[i].iov_base, iov[i].iov_len);

	fp->crc = htonl(fp->crc ^ STUN_CRC_XOR);
	hdr->msg_len = ntohs(hdr->msg_len);
}

static void __integrity(struct iovec *iov, int iov_cnt, str *pwd, char *digest) {
	int i;
	HMAC_CTX ctx;

	HMAC_CTX_init(&ctx);
	/* do we need to SASLprep here? */
	HMAC_Init(&ctx, pwd->s, pwd->len, EVP_sha1());

	for (i = 0; i < iov_cnt; i++)
		HMAC_Update(&ctx, iov[i].iov_base, iov[i].iov_len);

	HMAC_Final(&ctx, (void *) digest, NULL);
	HMAC_CTX_cleanup(&ctx);
}

static void integrity(struct msghdr *mh, struct msg_integrity *mi, str *pwd) {
	struct iovec *iov;
	struct header *hdr;

	output_add(mh, mi, STUN_MESSAGE_INTEGRITY);
	iov = mh->msg_iov;
	hdr = iov->iov_base;
	hdr->msg_len = htons(hdr->msg_len);

	__integrity(mh->msg_iov, mh->msg_iovlen - 1, pwd, mi->digest);

	hdr->msg_len = ntohs(hdr->msg_len);
}

static void stun_error_len(int fd, struct sockaddr_in6 *sin, struct header *req,
		int code, char *reason, int len, u_int16_t add_attr, void *attr_cont,
		int attr_len, struct callmaster *cm)
{
	struct header hdr;
	struct error_code ec;
	struct fingerprint fp;
	struct generic aa;
	struct msghdr mh;
	struct iovec iov[6]; /* hdr, ec, reason, aa, attr_cont, fp */
	unsigned char buf[256];

	output_init(&mh, iov, sin, &hdr, STUN_BINDING_ERROR_RESPONSE, req->transaction, buf, sizeof(buf));

	ec.codes = htonl(((code / 100) << 8) | (code % 100));
	output_add_data(&mh, &ec, STUN_ERROR_CODE, reason, len);
	if (attr_cont)
		output_add_data(&mh, &aa, add_attr, attr_cont, attr_len);

	fingerprint(&mh, &fp);

	output_finish(&mh, cm);
	sendmsg(fd, &mh, 0);
}

#define stun_error(cm, fd, sin, str, code, reason) \
	stun_error_len(fd, sin, str, code, reason "\0\0\0", strlen(reason), \
			0, NULL, 0, cm)
#define stun_error_attrs(cm, fd, sin, str, code, reason, type, content, len) \
	stun_error_len(fd, sin, str, code, reason "\0\0\0", strlen(reason), \
			type, content, len, cm)



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

static int check_auth(str *msg, struct stun_attrs *attrs, struct call_media *media) {
	u_int16_t lenX;
	char digest[20];
	str ufrag[2];
	struct iovec iov[3];

	if (!media->ice_ufrag.s || !media->ice_ufrag.len)
		return -1;
	if (!media->ice_pwd.s || !media->ice_pwd.len)
		return -1;

	ufrag[0] = attrs->username;
	str_chr_str(&ufrag[1], &ufrag[0], ':');
	if (!ufrag[1].s)
		return -1;
	ufrag[0].len -= ufrag[1].len;
	str_shift(&ufrag[1], 1);

	if (!ufrag[0].len || !ufrag[1].len)
		return -1;
	if (str_cmp_str(&ufrag[0], &media->ice_ufrag))
		return -1;

	lenX = htons((attrs->msg_integrity_attr - msg->s) - 20 + 24);
	iov[0].iov_base = msg->s;
	iov[0].iov_len = OFFSET_OF(struct header, msg_len);
	iov[1].iov_base = &lenX;
	iov[1].iov_len = sizeof(lenX);
	iov[2].iov_base = msg->s + OFFSET_OF(struct header, cookie);
	iov[2].iov_len = ntohs(lenX) + - 24 + 20 - OFFSET_OF(struct header, cookie);

	__integrity(iov, G_N_ELEMENTS(iov), &media->ice_pwd, digest);

	return memcmp(digest, attrs->msg_integrity.s, 20) ? -1 : 0;
}

static int stun_binding_success(int fd, struct header *req, struct stun_attrs *attrs,
		struct sockaddr_in6 *sin, struct call_media *media)
{
	struct header hdr;
	struct xor_mapped_address xma;
	struct msg_integrity mi;
	struct fingerprint fp;
	struct msghdr mh;
	struct iovec iov[4]; /* hdr, xma, mi, fp */
	unsigned char buf[256];
	struct callmaster *cm = media->call->callmaster;

	output_init(&mh, iov, sin, &hdr, STUN_BINDING_SUCCESS_RESPONSE, req->transaction, buf, sizeof(buf));

	xma.port = sin->sin6_port ^ htons(STUN_COOKIE >> 16);
	if (IN6_IS_ADDR_V4MAPPED(&sin->sin6_addr)) {
		xma.family = htons(0x01);
		xma.address[0] = sin->sin6_addr.s6_addr32[3] ^ htonl(STUN_COOKIE);
		output_add_len(&mh, &xma, STUN_XOR_MAPPED_ADDRESS, 8);
	}
	else {
		xma.family = htons(0x02);
		xma.address[0] = sin->sin6_addr.s6_addr32[0] ^ htonl(STUN_COOKIE);
		xma.address[1] = sin->sin6_addr.s6_addr32[1] ^ req->transaction[0];
		xma.address[2] = sin->sin6_addr.s6_addr32[2] ^ req->transaction[1];
		xma.address[3] = sin->sin6_addr.s6_addr32[3] ^ req->transaction[2];
		output_add(&mh, &xma, STUN_XOR_MAPPED_ADDRESS);
	}

	integrity(&mh, &mi, &media->ice_pwd);
	fingerprint(&mh, &fp);

	output_finish(&mh, cm);
	sendmsg(fd, &mh, 0);

	return 0;
}

INLINE int u_int16_t_arr_len(u_int16_t *arr) {
	int i;
	for (i = 0; arr[i] != 0xffff; i++)
		;
	return i;
}


#define SLF " from %s"
#define SLP addr
/* return values:
 * 0  = stun packet processed successfully
 * -1 = stun packet not processed, processing should continue as non-stun packet
 * 1  = stun packet processed and "use candidate" was set
 */
int stun(str *b, struct packet_stream *ps, struct sockaddr_in6 *sin) {
	struct header *req = (void *) b->s;
	int msglen, method, class;
	str attr_str;
	struct stun_attrs attrs;
	u_int16_t unknowns[UNKNOWNS_COUNT];
	const char *err;
	char addr[64];
	struct callmaster *cm = ps->call->callmaster;

	smart_ntop_port(addr, sin, sizeof(addr));

	msglen = ntohs(req->msg_len);
	err = "message-length mismatch";
	if (msglen + 20 > b->len || msglen < 0)
		goto ignore;

	class = method = ntohs(req->msg_type);
	class = ((class & 0x10) >> 4) | ((class & 0x100) >> 7);
	method = (method & 0xf) | ((method & 0xe0) >> 1) | ((method & 0x3e00) >> 2);
	err = "unknown STUN method";
	if (method != STUN_METHOD_BINDING)
		goto ignore;
	if (class == STUN_CLASS_INDICATION)
		return 0;

	attr_str.s = &b->s[20];
	attr_str.len = b->len - 20;
	if (stun_attributes(&attrs, &attr_str, unknowns)) {
		err = "failed to parse attributes";
		if (unknowns[0] == 0xffff)
			goto ignore;
		ilog(LOG_WARNING, "STUN packet contained unknown "
				"\"comprehension required\" attribute(s)" SLF, SLP);
		stun_error_attrs(cm, ps->sfd->fd.fd, sin, req, 420, "Unknown attribute",
				STUN_UNKNOWN_ATTRIBUTES, unknowns,
				u_int16_t_arr_len(unknowns) * 2);
		return 0;
	}

	if (class != STUN_CLASS_REQUEST)
		return -1;

	err = "FINGERPRINT attribute missing";
	if (!attrs.fingerprint_attr)
		goto ignore;
	err = "USERNAME attribute missing";
	if (!attrs.username.s)
		goto bad_req;
	err = "MESSAGE_INTEGRITY attribute missing";
	if (!attrs.msg_integrity.s)
		goto bad_req;

	err = "FINGERPRINT mismatch";
	if (check_fingerprint(b, &attrs))
		goto ignore;
	if (check_auth(b, &attrs, ps->media))
		goto unauth;

	ilog(LOG_NOTICE, "Successful STUN binding request" SLF, SLP);
	stun_binding_success(ps->sfd->fd.fd, req, &attrs, sin, ps->media);

	return attrs.use ? 1 : 0;

bad_req:
	ilog(LOG_INFO, "Received invalid STUN packet" SLF ": %s", SLP, err);
	stun_error(cm, ps->sfd->fd.fd, sin, req, 400, "Bad request");
	return 0;
unauth:
	ilog(LOG_INFO, "STUN authentication mismatch" SLF, SLP);
	stun_error(cm, ps->sfd->fd.fd, sin, req, 401, "Unauthorized");
	return 0;
ignore:
	ilog(LOG_INFO, "Not handling potential STUN packet" SLF ": %s", SLP, err);
	return -1;
}
