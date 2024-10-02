#include "stun.h"

#include <sys/types.h>
#include <string.h>
#include <sys/socket.h>
#include <zlib.h>
#include <openssl/hmac.h>
#include <glib.h>
#include <endian.h>

#include "compat.h"
#include "str.h"
#include "helpers.h"
#include "log.h"
#include "ice.h"
#include "ssllib.h"
#include "uring.h"

#define STUN_CRC_XOR 0x5354554eUL

#define STUN_USERNAME 0x0006
#define STUN_MESSAGE_INTEGRITY 0x0008
#define STUN_ERROR_CODE 0x0009
#define STUN_UNKNOWN_ATTRIBUTES 0x000a
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_PRIORITY 0x0024
#define STUN_USE_CANDIDATE 0x0025
#define STUN_SOFTWARE 0x8022
#define STUN_FINGERPRINT 0x8028
#define STUN_ICE_CONTROLLED 0x8029
#define STUN_ICE_CONTROLLING 0x802a
#define STUN_GOOG_NETWORK_INFO 0xc057

#define STUN_CLASS_REQUEST 0x00
#define STUN_CLASS_INDICATION 0x01
#define STUN_CLASS_SUCCESS 0x02
#define STUN_CLASS_ERROR 0x03

#define STUN_METHOD_BINDING 0x01

#define STUN_MESSAGE_TYPE(method, class) \
	(((method) & 0xf) | (((method) & 0x70) << 1) \
	 | (((method) & 0x0f80) << 2) | (((class) & 0x1) << 4) \
	 | (((class) & 0x2) << 7))

#define STUN_BINDING_REQUEST \
	STUN_MESSAGE_TYPE(STUN_METHOD_BINDING, STUN_CLASS_REQUEST)
#define STUN_BINDING_SUCCESS_RESPONSE \
	STUN_MESSAGE_TYPE(STUN_METHOD_BINDING, STUN_CLASS_SUCCESS)
#define STUN_BINDING_ERROR_RESPONSE \
	STUN_MESSAGE_TYPE(STUN_METHOD_BINDING, STUN_CLASS_ERROR)

#define UNKNOWNS_COUNT 16



struct header {
	uint16_t msg_type;
	uint16_t msg_len;
	uint32_t cookie;
	uint32_t transaction[3];
} __attribute__ ((packed));

struct tlv {
	uint16_t type;
	uint16_t len;
} __attribute__ ((packed));

struct generic {
	struct tlv tlv;
} __attribute__ ((packed));

struct error_code {
	struct tlv tlv;
	uint32_t codes;
} __attribute__ ((packed));

struct fingerprint {
	struct tlv tlv;
	uint32_t crc;
} __attribute__ ((packed));

struct msg_integrity {
	struct tlv tlv;
	char digest[20];
} __attribute__ ((packed));

struct xor_mapped_address {
	struct tlv tlv;
	uint16_t family;
	uint16_t port;
	uint32_t address[4];
} __attribute__ ((packed));

struct controlled_ing {
	struct tlv tlv;
	uint64_t tiebreaker;
} __attribute__ ((packed));

struct priority {
	struct tlv tlv;
	uint32_t priority;
} __attribute__ ((packed));

struct software {
	struct tlv tlv;
	char str[128];
} __attribute__ ((packed));




/* XXX add const in functions */


static uint64_t be64toh_unaligned(const char *s) {
	uint64_t u;
	memcpy(&u, s, sizeof(u));
	return be64toh(u);
}

static int stun_attributes(struct stun_attrs *out, str *s, uint16_t *unknowns, struct header *req) {
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
				out->fingerprint = ntohl(*(uint32_t *) attr.s);
				goto out;

			case STUN_USE_CANDIDATE:
				out->use = 1;
				break;

			case STUN_ICE_CONTROLLED:
				if (out->controlling)
					return -1;
				if (attr.len != 8)
					return -1;
				out->tiebreaker = be64toh_unaligned(attr.s);
				out->controlled = 1;
				break;

			case STUN_ICE_CONTROLLING:
				if (out->controlled)
					return -1;
				if (attr.len != 8)
					return -1;
				out->tiebreaker = be64toh_unaligned(attr.s);
				out->controlling = 1;
				break;

			case STUN_PRIORITY:
				if (attr.len != 4)
					return -1;
				out->priority = ntohl(*((uint32_t *) attr.s));
				break;

			case STUN_SOFTWARE:
			case STUN_GOOG_NETWORK_INFO:
				break; /* ignore but suppress warning message */

			case STUN_XOR_MAPPED_ADDRESS:
				if (attr.len < 8)
					return -1;
				out->mapped.port = ntohs(*((uint16_t *) (&attr.s[2]))) ^ (STUN_COOKIE >> 16);
				if (attr.len == 8 && ntohs(*((uint16_t *) attr.s)) == 1) {
					out->mapped.address.family = get_socket_family_enum(SF_IP4);
					out->mapped.address.ipv4.s_addr =
							ntohl(*((uint32_t *) (&attr.s[4]))) ^ STUN_COOKIE;
				}
				else if (attr.len == 20 && ntohs(*((uint16_t *) attr.s)) == 1) {
					out->mapped.address.family = get_socket_family_enum(SF_IP6);
					out->mapped.address.ipv6.s6_addr32[0]
						= *((uint32_t *) (&attr.s[4])) ^ htonl(STUN_COOKIE);
					out->mapped.address.ipv6.s6_addr32[1]
						= *((uint32_t *) (&attr.s[8])) ^ req->transaction[0];
					out->mapped.address.ipv6.s6_addr32[2]
						= *((uint32_t *) (&attr.s[12])) ^ req->transaction[1];
					out->mapped.address.ipv6.s6_addr32[3]
						= *((uint32_t *) (&attr.s[16])) ^ req->transaction[2];
				}
				break;

			case STUN_ERROR_CODE:
				if (attr.len < 4)
					return -1;
				out->error_code = ntohl(*((uint32_t *) attr.s));
				out->error_code = ((out->error_code & 0x700) >> 8) * 100
					+ (out->error_code & 0x0ff);
				break;

			default:
				if ((type & 0x8000)) {
					// comprehension optional
					ilog(LOG_DEBUG, "Unknown STUN attribute: 0x%04x", type);
					break;
				}
				ilog(LOG_NOTICE | LOG_FLAG_LIMIT, "Unknown STUN attribute: 0x%04x", type);
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

static void output_init(struct msghdr *mh, struct iovec *iov,
		struct header *hdr, unsigned short code, void *transaction)
{
	ZERO(*mh);

	mh->msg_iov = iov;
	mh->msg_iovlen = 1;

	iov->iov_base = hdr;
	iov->iov_len = sizeof(*hdr);

	hdr->msg_type = htons(code);
	hdr->msg_len = 0;
	hdr->cookie = htonl(STUN_COOKIE);
	memcpy(&hdr->transaction, transaction, sizeof(hdr->transaction));
}

INLINE void __output_add(struct msghdr *mh, struct tlv *tlv, unsigned int len, uint16_t code,
		void *append, unsigned int append_len, int writable)
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

		if (writable && (append_len & 0x3)) // if not writable, buffer must have trailing \0\0\0
			memset(append + append_len, 0, 4 - (append_len & 0x3));
	}
}

#define output_add(mh, attr, code) \
	__output_add(mh, &(attr)->tlv, sizeof(*(attr)), code, NULL, 0, 0)
#define output_add_len(mh, attr, code, len) \
	__output_add(mh, &(attr)->tlv, len + sizeof(struct tlv), code, NULL, 0, 0)
#define output_add_data_wr(mh, attr, code, data, len) \
	__output_add(mh, &(attr)->tlv, sizeof(*(attr)), code, data, len, 1)
#define output_add_data_ro(mh, attr, code, data, len) \
	__output_add(mh, &(attr)->tlv, sizeof(*(attr)), code, data, len, 0)
#define output_add_data_len_pad(mh, attr, code, data, len) \
	__output_add(mh, &(attr)->tlv, sizeof((attr)->tlv), code, data, len, 1)


static void __output_finish(struct msghdr *mh) {
	struct header *hdr;

	hdr = mh->msg_iov->iov_base;
	hdr->msg_len = htons(hdr->msg_len);
}
static void output_finish_src(struct msghdr *mh) {
	__output_finish(mh);
}

static void software(struct msghdr *mh, struct software *sw) {
	int i;
	i = snprintf(sw->str, sizeof(sw->str), "%s", rtpe_config.software_id);
	output_add_data_len_pad(mh, sw, STUN_SOFTWARE, sw->str, i);
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC_CTX *ctx;

	ctx = EVP_MAC_CTX_dup(rtpe_hmac_sha1_base);
	EVP_MAC_init(ctx, (unsigned char *) pwd->s, pwd->len, NULL);

	for (i = 0; i < iov_cnt; i++)
		EVP_MAC_update(ctx, iov[i].iov_base, iov[i].iov_len);

	size_t outsize = 20;
	EVP_MAC_final(ctx, (unsigned char *) digest, &outsize, outsize);
	EVP_MAC_CTX_free(ctx);
#else // <3.0
	HMAC_CTX *ctx;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = HMAC_CTX_new();
#else
	HMAC_CTX ctx_s;
	HMAC_CTX_init(&ctx_s);
	ctx = &ctx_s;
#endif
	/* do we need to SASLprep here? */
	HMAC_Init_ex(ctx, pwd->s, pwd->len, EVP_sha1(), NULL);

	for (i = 0; i < iov_cnt; i++)
		HMAC_Update(ctx, iov[i].iov_base, iov[i].iov_len);

	HMAC_Final(ctx, (void *) digest, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	HMAC_CTX_free(ctx);
#else
	HMAC_CTX_cleanup(ctx);
#endif
#endif
}

static void integrity(struct msghdr *mh, struct msg_integrity *mi, str *pwd) {
	struct iovec *iov;
	struct header *hdr;

	if (!pwd || !pwd->s)
		return;

	output_add(mh, mi, STUN_MESSAGE_INTEGRITY);
	iov = mh->msg_iov;
	hdr = iov->iov_base;
	hdr->msg_len = htons(hdr->msg_len);

	__integrity(mh->msg_iov, mh->msg_iovlen - 1, pwd, mi->digest);

	hdr->msg_len = ntohs(hdr->msg_len);
}

static void stun_error_len(stream_fd *sfd, const endpoint_t *sin,
		struct header *req,
		int code, char *reason, int len, uint16_t add_attr, void *attr_cont,
		int attr_len)
{
	struct header hdr;
	struct error_code ec;
	struct msg_integrity mi;
	struct fingerprint fp;
	struct generic aa;
	struct msghdr mh;
	struct software sw;
	struct iovec iov[9]; /* hdr, ec, reason, aa, attr_cont, mi, fp, sw x2 */

	output_init(&mh, iov, &hdr, STUN_BINDING_ERROR_RESPONSE, req->transaction);
	software(&mh, &sw);

	ec.codes = htonl(((code / 100) << 8) | (code % 100));
	output_add_data_ro(&mh, &ec, STUN_ERROR_CODE, reason, len);
	if (attr_cont)
		output_add_data_wr(&mh, &aa, add_attr, attr_cont, attr_len);

	integrity(&mh, &mi, &sfd->stream->media->ice_agent->pwd[1]);
	fingerprint(&mh, &fp);

	output_finish_src(&mh);
	socket_sendmsg(&sfd->socket, &mh, sin);
}

#define stun_error(sfd, sin, req, code, reason) \
	stun_error_len(sfd, sin, req, code, reason "\0\0\0", strlen(reason), \
			0, NULL, 0)
#define stun_error_attrs(sfd, sin, req, code, reason, type, content, len) \
	stun_error_len(sfd, sin, req, code, reason "\0\0\0", strlen(reason), \
			type, content, len)



static int check_fingerprint(const str *msg, struct stun_attrs *attrs) {
	int len;
	uint32_t crc;

	len = attrs->fingerprint_attr - msg->s;
	crc = crc32(0, (void *) msg->s, len);
	crc ^= STUN_CRC_XOR;
	if (crc != attrs->fingerprint)
		return -1;

	return 0;
}

static int check_auth(const str *msg, struct stun_attrs *attrs, struct call_media *media, int dst, int src) {
	uint16_t lenX;
	char digest[20];
	str ufrag[2];
	struct iovec iov[3];
	struct ice_agent *ag;

	ag = media->ice_agent;
	if (!ag)
		return -1;
	if (!ag->ufrag[dst].s || !ag->ufrag[dst].len)
		return -1;
	if (!ag->pwd[dst].s || !ag->pwd[dst].len)
		return -1;

	if (attrs->username.s) {
		/* request */
		ufrag[dst] = attrs->username;
		if (!str_chr_str(&ufrag[src], &ufrag[dst], ':'))
			return -1;
		ufrag[dst].len -= ufrag[src].len;
		str_shift(&ufrag[src], 1);

		if (!ufrag[src].len || !ufrag[dst].len)
			return -1;
		if (str_cmp_str(&ufrag[dst], &ag->ufrag[dst]))
			return -1;
	}

	lenX = htons((attrs->msg_integrity_attr - msg->s) - 20 + 24);
	iov[0].iov_base = msg->s;
	iov[0].iov_len = G_STRUCT_OFFSET(struct header, msg_len);
	iov[1].iov_base = &lenX;
	iov[1].iov_len = sizeof(lenX);
	iov[2].iov_base = msg->s + G_STRUCT_OFFSET(struct header, cookie);
	iov[2].iov_len = ntohs(lenX) + - 24 + 20 - G_STRUCT_OFFSET(struct header, cookie);

	__integrity(iov, G_N_ELEMENTS(iov), &ag->pwd[dst], digest);

	return memcmp(digest, attrs->msg_integrity.s, 20) ? -1 : 0;
}

static int stun_binding_success(stream_fd *sfd, struct header *req, struct stun_attrs *attrs,
		const endpoint_t *sin)
{
	struct header hdr;
	struct xor_mapped_address xma;
	struct msg_integrity mi;
	struct fingerprint fp;
	struct msghdr mh;
	struct software sw;
	struct iovec iov[6]; /* hdr, xma, mi, fp, sw x2 */

	output_init(&mh, iov, &hdr, STUN_BINDING_SUCCESS_RESPONSE, req->transaction);
	software(&mh, &sw);

	xma.port = htons(sin->port ^ (STUN_COOKIE >> 16));
	if (sin->address.family->af == AF_INET) {
		xma.family = htons(0x01);
		xma.address[0] = sin->address.ipv4.s_addr ^ htonl(STUN_COOKIE);
		output_add_len(&mh, &xma, STUN_XOR_MAPPED_ADDRESS, 8);
	}
	else {
		xma.family = htons(0x02);
		xma.address[0] = sin->address.ipv6.s6_addr32[0] ^ htonl(STUN_COOKIE);
		xma.address[1] = sin->address.ipv6.s6_addr32[1] ^ req->transaction[0];
		xma.address[2] = sin->address.ipv6.s6_addr32[2] ^ req->transaction[1];
		xma.address[3] = sin->address.ipv6.s6_addr32[3] ^ req->transaction[2];
		output_add(&mh, &xma, STUN_XOR_MAPPED_ADDRESS);
	}

	integrity(&mh, &mi, &sfd->stream->media->ice_agent->pwd[1]);
	fingerprint(&mh, &fp);

	output_finish_src(&mh);
	socket_sendmsg(&sfd->socket, &mh, sin);

	return 0;
}

INLINE int uint16_t_arr_len(uint16_t *arr) {
	int i;
	for (i = 0; arr[i] != 0xffff; i++)
		;
	return i;
}



#define SLF " from %s%s%s"
#define SLP FMT_M(endpoint_print_buf(sin))
static int __stun_request(stream_fd *sfd, const endpoint_t *sin,
		struct header *req, struct stun_attrs *attrs)
{
	int ret;

	ret = ice_request(sfd, sin, attrs);

	if (ret == -2) {
		ilog(LOG_DEBUG, "ICE role conflict detected");
		stun_error(sfd, sin, req, 487, "Role conflict");
		return 0;
	}
	if (ret < 0)
		return -1;

	ilog(LOG_DEBUG, "Successful STUN binding request" SLF, SLP);
	stun_binding_success(sfd, req, attrs, sin);

	return ret;
}
static int __stun_success(stream_fd *sfd, const endpoint_t *sin,
		struct header *req, struct stun_attrs *attrs)
{
	return ice_response(sfd, sin, attrs, req->transaction);
}
static int __stun_error(stream_fd *sfd, const endpoint_t *sin,
		struct header *req, struct stun_attrs *attrs)
{
	return ice_response(sfd, sin, attrs, req->transaction);
}


/* return values:
 * 0  = stun packet processed successfully
 * -1 = stun packet not processed, processing should continue as non-stun packet
 * 1  = stun packet processed and ICE has completed
 *
 * call is locked in R
 */
int stun(const str *b, stream_fd *sfd, const endpoint_t *sin) {
	struct header *req = (void *) b->s;
	int msglen, method, class;
	str attr_str;
	struct stun_attrs attrs;
	uint16_t unknowns[UNKNOWNS_COUNT];
	const char *err;
	int dst_idx, src_idx;
	struct packet_stream *ps = sfd->stream;

	msglen = ntohs(req->msg_len);
	err = "message-length mismatch";
	if (msglen + 20 > b->len)
		goto ignore;

	class = method = ntohs(req->msg_type);
	class = ((class & 0x10) >> 4) | ((class & 0x100) >> 7);
	method = (method & 0xf) | ((method & 0xe0) >> 1) | ((method & 0x3e00) >> 2);
	err = "unknown STUN method";
	if (method != STUN_METHOD_BINDING)
		goto ignore;
	if (class == STUN_CLASS_INDICATION)
		return 0;

	attr_str = STR_LEN(&b->s[20], b->len - 20);
	if (stun_attributes(&attrs, &attr_str, unknowns, req)) {
		err = "failed to parse attributes";
		if (unknowns[0] == 0xffff)
			goto ignore;
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "STUN packet contained unknown "
				"\"comprehension required\" attribute(s)" SLF, SLP);
		stun_error_attrs(sfd, sin, req, 420, "Unknown attribute",
				STUN_UNKNOWN_ATTRIBUTES, unknowns,
				uint16_t_arr_len(unknowns) * 2);
		return 0;
	}

	err = "FINGERPRINT attribute missing";
	if (!attrs.fingerprint_attr)
		goto ignore;
	err = "MESSAGE_INTEGRITY attribute missing";
	if (!attrs.msg_integrity.s)
		goto bad_req;

	if (class == STUN_CLASS_REQUEST) {
		err = "USERNAME attribute missing";
		if (!attrs.username.s)
			goto bad_req;
		dst_idx = 1;
		src_idx = 0;
	}
	else {
		dst_idx = 0;
		src_idx = 1;
	}

	err = "FINGERPRINT mismatch";
	if (check_fingerprint(b, &attrs))
		goto ignore;
	if (check_auth(b, &attrs, ps->media, dst_idx, src_idx))
		goto unauth;

	switch (class) {
		case STUN_CLASS_REQUEST:
			return __stun_request(sfd, sin, req, &attrs);
		case STUN_CLASS_SUCCESS:
			return __stun_success(sfd, sin, req, &attrs);
		case STUN_CLASS_ERROR:
			return __stun_error(sfd, sin, req, &attrs);
		default:
			return -1;
	}
	/* notreached */

bad_req:
	ilog(LOG_NOTICE | LOG_FLAG_LIMIT, "Received invalid STUN packet" SLF ": %s", SLP, err);
	if (class == STUN_CLASS_REQUEST)
		stun_error(sfd, sin, req, 400, "Bad request");
	return 0;
unauth:
	ilog(LOG_NOTICE | LOG_FLAG_LIMIT, "STUN authentication mismatch" SLF, SLP);
	if (class == STUN_CLASS_REQUEST)
		stun_error(sfd, sin, req, 401, "Unauthorized");
	return 0;
ignore:
	ilog(LOG_NOTICE | LOG_FLAG_LIMIT, "Not handling potential STUN packet" SLF ": %s", SLP, err);
	return -1;
}

struct async_stun_req {
	struct uring_req req; // must be first
	struct header hdr;
	struct msghdr mh;
	struct iovec iov[10]; /* hdr, username x2, ice_controlled/ing, priority, uc, fp, mi, sw x2 */
	char username_buf[256];
	struct generic un_attr;
	struct controlled_ing cc;
	struct priority prio;
	struct generic uc;
	struct fingerprint fp;
	struct msg_integrity mi;
	struct software sw;
	struct sockaddr_storage sin;
};

int stun_binding_request(const endpoint_t *dst, uint32_t transaction[3], str *pwd,
		str ufrags[2], int controlling, uint64_t tiebreaker, uint32_t priority,
		socket_t *sock, int to_use)
{
	struct async_stun_req *r = uring_alloc_buffer_req(sizeof(*r));
	int i;

	output_init(&r->mh, r->iov, &r->hdr, STUN_BINDING_REQUEST, transaction);
	software(&r->mh, &r->sw);

	i = snprintf(r->username_buf, sizeof(r->username_buf), STR_FORMAT":"STR_FORMAT,
			STR_FMT(&ufrags[0]), STR_FMT(&ufrags[1]));
	if (i <= 0 || i >= sizeof(r->username_buf))
		return -1;
	output_add_data_wr(&r->mh, &r->un_attr, STUN_USERNAME, r->username_buf, i);

	r->cc.tiebreaker = htobe64(tiebreaker);
	output_add(&r->mh, &r->cc, controlling ? STUN_ICE_CONTROLLING : STUN_ICE_CONTROLLED);

	r->prio.priority = htonl(priority);
	output_add(&r->mh, &r->prio, STUN_PRIORITY);

	if (to_use)
		output_add(&r->mh, &r->uc, STUN_USE_CANDIDATE);

	integrity(&r->mh, &r->mi, pwd);
	fingerprint(&r->mh, &r->fp);

	output_finish_src(&r->mh);
	uring_sendmsg(sock, &r->mh, dst, &r->sin, &r->req);

	return 0;
}
