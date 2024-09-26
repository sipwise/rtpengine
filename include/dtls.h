#ifndef _DTLS_H_
#define _DTLS_H_

#include <time.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "compat.h"
#include "str.h"
#include "obj.h"
#include "socket.h"
#include "types.h"

#define DTLS_MAX_DIGEST_LEN 64
#define DTLS_MTU_OVERHEAD 48 // 40 bytes IPv6 + 8 bytes UDP

struct packet_stream;
struct sockaddr_in6;

struct dtls_hash_func {
	const char *name;
	unsigned int num_bytes;
	unsigned int (*__func)(unsigned char *, X509 *);
};

struct dtls_fingerprint {
	unsigned char digest[DTLS_MAX_DIGEST_LEN];
	unsigned int digest_len;
	const struct dtls_hash_func *hash_func;
};

struct dtls_cert {
	struct obj obj;
	GQueue fingerprints;
	EVP_PKEY *pkey;
	X509 *x509;
	time_t expires;
};

struct dtls_connection {
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *r_bio, *w_bio;
	void *ptr;
	unsigned char tls_id[16];
	unsigned int init:1,
	             active:1,
	             connected:1;
};




int dtls_init(void);
void dtls_timer(void);

int dtls_verify_cert(struct packet_stream *ps);
const struct dtls_hash_func *dtls_find_hash_func(const str *);
struct dtls_cert *dtls_cert(void);
void dtls_cert_free(void);

int dtls_connection_init(struct dtls_connection *, struct packet_stream *, int active, struct dtls_cert *cert);
int dtls(stream_fd *, const str *s, const endpoint_t *sin);
void dtls_connection_cleanup(struct dtls_connection *);
void dtls_shutdown(struct packet_stream *ps);




INLINE void __dtls_hash(const struct dtls_hash_func *hash_func, X509 *cert, unsigned char *out,
		unsigned int bufsize)
{
	unsigned int n;

	assert(bufsize >= hash_func->num_bytes);
	memset(out, 0, bufsize);
	n = hash_func->__func(out, cert);
	assert(n == hash_func->num_bytes);
	(void) n;
}
#define dtls_hash(hash_func, cert, outbuf) __dtls_hash(hash_func, cert, outbuf, sizeof(outbuf))

INLINE void dtls_fingerprint_hash(struct dtls_fingerprint *fp, X509 *cert) {
	__dtls_hash(fp->hash_func, cert, fp->digest, sizeof(fp->digest));
	fp->digest_len = fp->hash_func->num_bytes;
}

INLINE int is_dtls(const str *s) {
	const unsigned char *b = (const void *) s->s;

	if (s->len < 1)
		return 0;
	/* RFC 5764, 5.1.2 */
	if (b[0] >= 20 && b[0] <= 63)
		return 1;

	return 0;
}

// -1: not initialized, unknown or invalid
// 0 or 1: passive or active
INLINE int dtls_is_active(const struct dtls_connection *d) {
	if (!d || !d->init)
		return -1;
	return d->active ? 1 : 0;
}


struct dtls_connection *dtls_ptr(stream_fd *sfd);




#endif
