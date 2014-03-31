#ifndef _CRYPTO_H_
#define _CRYPTO_H_



#include <sys/types.h>
#include <glib.h>
#include "compat.h"
#include "str.h"



#define SRTP_MAX_MASTER_KEY_LEN 16
#define SRTP_MAX_MASTER_SALT_LEN 14
#define SRTP_MAX_SESSION_KEY_LEN 16
#define SRTP_MAX_SESSION_SALT_LEN 14
#define SRTP_MAX_SESSION_AUTH_LEN 20



struct crypto_context;
struct rtp_header;
struct rtcp_packet;

typedef int (*crypto_func_rtp)(struct crypto_context *, struct rtp_header *, str *, u_int64_t);
typedef int (*crypto_func_rtcp)(struct crypto_context *, struct rtcp_packet *, str *, u_int64_t);
typedef int (*hash_func_rtp)(struct crypto_context *, char *out, str *in, u_int64_t);
typedef int (*hash_func_rtcp)(struct crypto_context *, char *out, str *in);
typedef int (*session_key_init_func)(struct crypto_context *);
typedef int (*session_key_cleanup_func)(struct crypto_context *);

struct crypto_suite {
	const char *name;
	const char *dtls_name;
	unsigned int
		master_key_len,
		master_salt_len,
		session_key_len,	/* n_e */
		session_salt_len,	/* n_s */
		srtp_auth_tag,		/* n_a */
		srtcp_auth_tag,
		srtp_auth_key_len,	/* n_a */
		srtcp_auth_key_len;
	unsigned long long int
		srtp_lifetime,
		srtcp_lifetime;
	int kernel_cipher;
	int kernel_hmac;
	crypto_func_rtp encrypt_rtp,
			decrypt_rtp;
	crypto_func_rtcp encrypt_rtcp,
			 decrypt_rtcp;
	hash_func_rtp hash_rtp;
	hash_func_rtcp hash_rtcp;
	session_key_init_func session_key_init;
	session_key_cleanup_func session_key_cleanup;
	const char *dtls_profile_code;
};

struct crypto_params {
	const struct crypto_suite *crypto_suite;
	/* we only support one master key for now */
	unsigned char master_key[SRTP_MAX_MASTER_KEY_LEN];
	unsigned char master_salt[SRTP_MAX_MASTER_SALT_LEN];
	unsigned char *mki;
	unsigned int mki_len;
};

struct crypto_context {
	struct crypto_params params;

	char session_key[SRTP_MAX_SESSION_KEY_LEN]; /* k_e */
	char session_salt[SRTP_MAX_SESSION_SALT_LEN]; /* k_s */
	char session_auth_key[SRTP_MAX_SESSION_AUTH_LEN];

	u_int64_t last_index;
	/* XXX replay list */
	/* <from, to>? */

	void *session_key_ctx[2];

	int have_session_key:1;
};




extern const struct crypto_suite crypto_suites[];
extern const int num_crypto_suites;



const struct crypto_suite *crypto_find_suite(const str *);
int crypto_gen_session_key(struct crypto_context *, str *, unsigned char, int);

INLINE int crypto_encrypt_rtp(struct crypto_context *c, struct rtp_header *rtp,
		str *payload, u_int64_t index)
{
	return c->params.crypto_suite->encrypt_rtp(c, rtp, payload, index);
}
INLINE int crypto_decrypt_rtp(struct crypto_context *c, struct rtp_header *rtp,
		str *payload, u_int64_t index)
{
	return c->params.crypto_suite->decrypt_rtp(c, rtp, payload, index);
}
INLINE int crypto_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *rtcp,
		str *payload, u_int64_t index)
{
	return c->params.crypto_suite->encrypt_rtcp(c, rtcp, payload, index);
}
INLINE int crypto_decrypt_rtcp(struct crypto_context *c, struct rtcp_packet *rtcp,
		str *payload, u_int64_t index)
{
	return c->params.crypto_suite->decrypt_rtcp(c, rtcp, payload, index);
}
INLINE int crypto_init_session_key(struct crypto_context *c) {
	return c->params.crypto_suite->session_key_init(c);
}

INLINE void crypto_params_cleanup(struct crypto_params *p) {
	if (p->mki)
		free(p->mki);
	p->mki = NULL;
}
INLINE void crypto_cleanup(struct crypto_context *c) {
	if (!c->params.crypto_suite)
		return;
	if (c->params.crypto_suite->session_key_cleanup)
		c->params.crypto_suite->session_key_cleanup(c);
	c->have_session_key = 0;
	crypto_params_cleanup(&c->params);
}
INLINE void crypto_reset(struct crypto_context *c) {
	crypto_cleanup(c);
	c->last_index = 0;
}
INLINE void crypto_params_copy(struct crypto_params *o, const struct crypto_params *i) {
	crypto_params_cleanup(o);
	*o = *i;
	if (o->mki_len > 255)
		o->mki_len = 0;
	if (o->mki_len) {
		o->mki = malloc(i->mki_len);
		memcpy(o->mki, i->mki, i->mki_len);
	}
}
INLINE void crypto_init(struct crypto_context *c, const struct crypto_params *p) {
	crypto_cleanup(c);
	crypto_params_copy(&c->params, p);
}



#endif
