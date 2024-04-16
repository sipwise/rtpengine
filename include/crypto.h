#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <sys/types.h>
#include <glib.h>

#include "compat.h"
#include "str.h"
#include "helpers.h"
#include "containers.h"

#define SRTP_MAX_MASTER_KEY_LEN 32
#define SRTP_MAX_MASTER_SALT_LEN 14
#define SRTP_MAX_SESSION_KEY_LEN 32
#define SRTP_MAX_SESSION_SALT_LEN 14
#define SRTP_MAX_SESSION_AUTH_LEN 20

struct crypto_context;
struct rtp_header;
struct rtcp_packet;

typedef int (*crypto_func_rtp)(struct crypto_context *, struct rtp_header *, str *, uint32_t);
typedef int (*crypto_func_rtcp)(struct crypto_context *, struct rtcp_packet *, str *, uint32_t);
typedef int (*hash_func_rtp)(struct crypto_context *, char *out, str *in, uint32_t);
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
	//const char *dtls_profile_code; // unused
	const EVP_CIPHER *aes_evp;
	unsigned int idx; // filled in during crypto_init_main()
	str name_str; // same as `name`
	const EVP_CIPHER *(*aead_evp)(void);
};

struct crypto_session_params {
	unsigned int unencrypted_srtcp:1,
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

struct crypto_params_sdes {
	struct crypto_params params;
	unsigned int tag;
};

TYPED_GQUEUE(sdes, struct crypto_params_sdes)

struct crypto_context {
	struct crypto_params params;

	char session_key[SRTP_MAX_SESSION_KEY_LEN]; /* k_e */
	char session_salt[SRTP_MAX_SESSION_SALT_LEN]; /* k_s */
	char session_auth_key[SRTP_MAX_SESSION_AUTH_LEN];

	/* XXX replay list */
	/* <from, to>? */

	void *session_key_ctx[2];

	unsigned int have_session_key:1;
};


extern const struct crypto_suite *crypto_suites;
extern const unsigned int num_crypto_suites;

extern __thread GString *crypto_debug_string;



void crypto_init_main(void);

const struct crypto_suite *crypto_find_suite(const str *);
int crypto_gen_session_key(struct crypto_context *, str *, unsigned char, unsigned int);
void crypto_dump_keys(struct crypto_context *in, struct crypto_context *out);
char *crypto_params_sdes_dump(const struct crypto_params_sdes *, char **);

/**
 * A function which compares two crypto suite names in str format.
 * Recommended to be used in combination with:
 * g_queue_find_custom() or g_list_find_custom()
 */
INLINE int crypto_params_sdes_cmp(const struct crypto_params_sdes *cs, gconstpointer b)
{
	return str_cmp_str(&cs->params.crypto_suite->name_str, (str *) b);
}


INLINE int crypto_encrypt_rtp(struct crypto_context *c, struct rtp_header *rtp,
		str *payload, uint32_t index)
{
	return c->params.crypto_suite->encrypt_rtp(c, rtp, payload, index);
}
INLINE int crypto_decrypt_rtp(struct crypto_context *c, struct rtp_header *rtp,
		str *payload, uint32_t index)
{
	return c->params.crypto_suite->decrypt_rtp(c, rtp, payload, index);
}
INLINE int crypto_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *rtcp,
		str *payload, uint32_t index)
{
	return c->params.crypto_suite->encrypt_rtcp(c, rtcp, payload, index);
}
INLINE int crypto_decrypt_rtcp(struct crypto_context *c, struct rtcp_packet *rtcp,
		str *payload, uint32_t index)
{
	return c->params.crypto_suite->decrypt_rtcp(c, rtcp, payload, index);
}
INLINE int crypto_init_session_key(struct crypto_context *c) {
	return c->params.crypto_suite->session_key_init(c);
}
INLINE int crypto_cleanup_session_key(struct crypto_context *c) {
	if (c->params.crypto_suite->session_key_cleanup)
		return c->params.crypto_suite->session_key_cleanup(c);
	return 0;
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
	crypto_cleanup_session_key(c);
	c->have_session_key = 0;
	c->params.crypto_suite = NULL;
}
INLINE void crypto_reset(struct crypto_context *c) {
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
	if (p)
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
INLINE void crypto_params_sdes_free(struct crypto_params_sdes *cps) {
	crypto_params_cleanup(&cps->params);
	g_slice_free1(sizeof(*cps), cps);
}
INLINE void crypto_params_sdes_queue_clear(sdes_q *q) {
	t_queue_clear_full(q, crypto_params_sdes_free);
}
INLINE void crypto_params_sdes_queue_copy(sdes_q *dst, const sdes_q *src) {
	for (auto_iter(l, src->head); l; l = l->next) {
		struct crypto_params_sdes *cps = l->data;
		struct crypto_params_sdes *cpy = g_slice_alloc(sizeof(*cpy));
		*cpy = *cps;
		cpy->params.mki = NULL;
		crypto_params_copy(&cpy->params, &cps->params, 1);
		t_queue_push_tail(dst, cpy);
	}
}
/**
 * Checks whether to apply policies according to: sdes_no / sdes_only
 * returns: 1 - to not apply / 0 - to apply
 */
INLINE int crypto_params_sdes_check_limitations(str_case_ht sdes_only,
			str_case_ht sdes_no,
			const struct crypto_suite *cps) {

	/* if 'SDES-only-' flag(s) present, then
	 * accept only those SDES suites mentioned in the 'SDES-only-',
	 * all the rest will be dropped / not added.
	 * This takes precedence over 'SDES-no-'.
	 *
	 * We mustn't check the 'flags->sdes_no' at all, if 'flags->sdes_only' is set. */
	if (t_hash_table_is_set(sdes_only))
	{
		if (!t_hash_table_lookup(sdes_only, &cps->name_str))
			return 1;
	}

	/* if 'SDES-no-' flag(s) present, then
		* remove SDES-no suites from offered ones */
	else if (t_hash_table_is_set(sdes_no) &&
		t_hash_table_lookup(sdes_no, &cps->name_str))
	{
		return 1;
	}

	return 0;
}

#include "main.h"
#include "log.h"
#include <inttypes.h>


INLINE void crypto_debug_init(int flag) {
	if (rtpe_config.common.log_levels[log_level_index_srtp] < LOG_DEBUG)
		return;
	if (crypto_debug_string)
		g_string_free(crypto_debug_string, TRUE);
	crypto_debug_string = NULL;
	if (!flag)
		return;
	crypto_debug_string = g_string_new("");
}
void __crypto_debug_printf(const char *fmt, ...) __attribute__((format(printf,1,2)));
#define crypto_debug_printf(f, ...) \
	if (crypto_debug_string) \
		__crypto_debug_printf(f, ##__VA_ARGS__)
INLINE void crypto_debug_dump_raw(const char *b, int len) {
	for (int i = 0; i < len; i++)
		crypto_debug_printf("%02" PRIx8, (unsigned char) b[i]);
}
INLINE void crypto_debug_dump(const str *s) {
	crypto_debug_dump_raw(s->s, s->len);
}
INLINE void crypto_debug_finish(void) {
	if (!crypto_debug_string)
		return;
	ilogs(srtp, LOG_NOTICE, "Crypto debug: %.*s", (int) crypto_debug_string->len, crypto_debug_string->str);
	g_string_free(crypto_debug_string, TRUE);
	crypto_debug_string = NULL;
}



#endif
