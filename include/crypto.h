#ifndef _CRYPTO_H_
#define _CRYPTO_H_



#include <sys/types.h>
#include <glib.h>
#include "compat.h"
#include "str.h"
#include "aux.h"



#define SRTP_MAX_MASTER_KEY_LEN 32
#define SRTP_MAX_MASTER_SALT_LEN 14
#define SRTP_MAX_SESSION_KEY_LEN 32
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
	const void *lib_cipher_ptr;
};

struct crypto_session_params {
	int unencrypted_srtcp:1,
	    unencrypted_srtp:1,
	    unauthenticated_srtp:1;
};

struct crypto_params {
	const struct crypto_suite *crypto_suite;
	/* we only support one master key for now */
	unsigned char master_key[SRTP_MAX_MASTER_KEY_LEN];
	unsigned char master_salt[SRTP_MAX_MASTER_SALT_LEN];
	unsigned char *mki;
	unsigned int mki_len;
	struct crypto_session_params session_params;
};

struct crypto_context {
	struct crypto_params params;

	char session_key[SRTP_MAX_SESSION_KEY_LEN]; /* k_e */
	char session_salt[SRTP_MAX_SESSION_SALT_LEN]; /* k_s */
	char session_auth_key[SRTP_MAX_SESSION_AUTH_LEN];

	/* XXX replay list */
	/* <from, to>? */

	void *session_key_ctx[2];

	int have_session_key:1;
};


extern const struct crypto_suite *crypto_suites;
extern const int num_crypto_suites;



void crypto_init_main();

const struct crypto_suite *crypto_find_suite(const str *);
int crypto_gen_session_key(struct crypto_context *, str *, unsigned char, int);
void crypto_dump_keys(struct crypto_context *in, struct crypto_context *out);



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
	crypto_params_cleanup(&c->params);
	if (!c->params.crypto_suite)
		return;
	if (c->params.crypto_suite->session_key_cleanup)
		c->params.crypto_suite->session_key_cleanup(c);
	c->have_session_key = 0;
	c->params.crypto_suite = NULL;
}
INLINE void crypto_reset(struct crypto_context *c) {
	// XXX reset details from ssrc_ctx?
	crypto_cleanup(c);
}
INLINE void crypto_params_copy(struct crypto_params *o, const struct crypto_params *i, int copy_sp) {
	struct crypto_session_params sp;

	crypto_params_cleanup(o);

	if (!copy_sp)
		sp = o->session_params;
	*o = *i;
	if (!copy_sp)
		o->session_params = sp;

	if (o->mki_len > 255)
		o->mki_len = 0;
	if (o->mki_len) {
		o->mki = malloc(i->mki_len);
		memcpy(o->mki, i->mki, i->mki_len);
	}
}
INLINE void crypto_init(struct crypto_context *c, const struct crypto_params *p) {
	crypto_cleanup(c);
	crypto_params_copy(&c->params, p, 1);
}
INLINE int crypto_params_cmp(const struct crypto_params *a, const struct crypto_params *b) {
       if (a->crypto_suite != b->crypto_suite)
               return 1;
       if (!a->crypto_suite)
               return 0;
       if (memcmp(a->master_key, b->master_key, a->crypto_suite->master_key_len))
               return 1;
       if (memcmp(a->master_salt, b->master_salt, a->crypto_suite->master_salt_len))
               return 1;
       if (a->mki_len != b->mki_len)
               return 1;
       if (a->mki_len && memcmp(a->mki, b->mki, a->mki_len))
               return 1;
       if (memcmp(&a->session_params, &b->session_params, sizeof(a->session_params)))
	       return 1;
       return 0;
}



#endif
