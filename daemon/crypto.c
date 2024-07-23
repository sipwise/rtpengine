#include "crypto.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <glib.h>

#include "str.h"
#include "helpers.h"
#include "rtp.h"
#include "rtcp.h"
#include "log.h"
#include "rtplib.h"
#include "rtcplib.h"
#include "main.h"
#include "ssllib.h"
#include "types.h"

#include "xt_RTPENGINE.h"

__thread GString *crypto_debug_string;

static int aes_cm_encrypt_rtp(struct crypto_context *, struct rtp_header *, str *, uint32_t);
static int aes_cm_encrypt_rtcp(struct crypto_context *, struct rtcp_packet *, str *, uint32_t);
static int aes_gcm_encrypt_rtp(struct crypto_context *, struct rtp_header *, str *, uint32_t);
static int aes_gcm_decrypt_rtp(struct crypto_context *, struct rtp_header *, str *, uint32_t);
static int aes_gcm_encrypt_rtcp(struct crypto_context *, struct rtcp_packet *, str *, uint32_t);
static int aes_gcm_decrypt_rtcp(struct crypto_context *, struct rtcp_packet *, str *, uint32_t);
static int hmac_sha1_rtp(struct crypto_context *, char *out, str *in, uint32_t);
static int hmac_sha1_rtcp(struct crypto_context *, char *out, str *in);
static int aes_f8_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx);
static int aes_f8_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx);
static int aes_cm_session_key_init(struct crypto_context *c);
static int aes_gcm_session_key_init(struct crypto_context *c);
static int aes_f8_session_key_init(struct crypto_context *c);
static int evp_session_key_cleanup(struct crypto_context *c);
static int null_crypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx);
static int null_crypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx);

/* all lengths are in bytes */
struct crypto_suite __crypto_suites[] = {
	{
		.name			= "AEAD_AES_256_GCM",
		.dtls_name		= "SRTP_AEAD_AES_256_GCM",
		.master_key_len		= 32,
		.master_salt_len	= 12,
		.session_key_len	= 32,
		.session_salt_len	= 12,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AEAD_AES_GCM_256,
		.kernel_hmac		= REH_NULL,
		.srtp_auth_tag		= 0,
		.srtcp_auth_tag		= 0,
		.srtp_auth_key_len	= 0,
		.srtcp_auth_key_len	= 0,
		.encrypt_rtp		= aes_gcm_encrypt_rtp,
		.decrypt_rtp		= aes_gcm_decrypt_rtp,
		.encrypt_rtcp		= aes_gcm_encrypt_rtcp,
		.decrypt_rtcp		= aes_gcm_decrypt_rtcp,
		.session_key_init	= aes_gcm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
		.aead_evp		= EVP_aes_256_gcm,
	},
	{
		.name			= "AEAD_AES_128_GCM",
		.dtls_name		= "SRTP_AEAD_AES_128_GCM",
		.master_key_len		= 16,
		.master_salt_len	= 12,
		.session_key_len	= 16,
		.session_salt_len	= 12,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AEAD_AES_GCM_128,
		.kernel_hmac		= REH_NULL,
		.srtp_auth_tag		= 0,
		.srtcp_auth_tag		= 0,
		.srtp_auth_key_len	= 0,
		.srtcp_auth_key_len	= 0,
		.encrypt_rtp		= aes_gcm_encrypt_rtp,
		.decrypt_rtp		= aes_gcm_decrypt_rtp,
		.encrypt_rtcp		= aes_gcm_encrypt_rtcp,
		.decrypt_rtcp		= aes_gcm_decrypt_rtcp,
		.session_key_init	= aes_gcm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
		.aead_evp		= EVP_aes_128_gcm,
	},
	{
		.name			= "AES_256_CM_HMAC_SHA1_80",
		//.dtls_name		= "SRTP_AES128_CM_SHA1_80",
		.master_key_len		= 32,
		.master_salt_len	= 14,
		.session_key_len	= 32,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_CM_256,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 10,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_cm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "AES_256_CM_HMAC_SHA1_32",
		//.dtls_name		= "SRTP_AES128_CM_SHA1_32",
		.master_key_len		= 32,
		.master_salt_len	= 14,
		.session_key_len	= 32,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_CM_256,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 4,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_cm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "AES_192_CM_HMAC_SHA1_80",
		//.dtls_name		= "SRTP_AES128_CM_SHA1_80",
		.master_key_len		= 24,
		.master_salt_len	= 14,
		.session_key_len	= 24,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_CM_192,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 10,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_cm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "AES_192_CM_HMAC_SHA1_32",
		//.dtls_name		= "SRTP_AES128_CM_SHA1_32",
		.master_key_len		= 24,
		.master_salt_len	= 14,
		.session_key_len	= 24,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_CM_192,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 4,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_cm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "AES_CM_128_HMAC_SHA1_80",
		.dtls_name		= "SRTP_AES128_CM_SHA1_80",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 16,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_CM_128,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 10,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_cm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "AES_CM_128_HMAC_SHA1_32",
		.dtls_name		= "SRTP_AES128_CM_SHA1_32",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 16,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_CM_128,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 4,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_cm_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "F8_128_HMAC_SHA1_80",
//		.dtls_name		= "SRTP_AES128_F8_SHA1_80",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 16,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_F8,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 10,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_f8_encrypt_rtp,
		.decrypt_rtp		= aes_f8_encrypt_rtp,
		.encrypt_rtcp		= aes_f8_encrypt_rtcp,
		.decrypt_rtcp		= aes_f8_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_f8_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "F8_128_HMAC_SHA1_32",
//		.dtls_name		= "SRTP_AES128_F8_SHA1_32",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 16,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_AES_F8,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 4,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= aes_f8_encrypt_rtp,
		.decrypt_rtp		= aes_f8_encrypt_rtp,
		.encrypt_rtcp		= aes_f8_encrypt_rtcp,
		.decrypt_rtcp		= aes_f8_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_init	= aes_f8_session_key_init,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "NULL_HMAC_SHA1_80",
//		.dtls_name		= "SRTP_NULL_SHA1_80",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 0,
		.session_salt_len	= 0,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_NULL,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 10,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= null_crypt_rtp,
		.decrypt_rtp		= null_crypt_rtp,
		.encrypt_rtcp		= null_crypt_rtcp,
		.decrypt_rtcp		= null_crypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
	{
		.name			= "NULL_HMAC_SHA1_32",
//		.dtls_name		= "SRTP_NULL_SHA1_32",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 0,
		.session_salt_len	= 0,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= REC_NULL,
		.kernel_hmac		= REH_HMAC_SHA1,
		.srtp_auth_tag		= 4,
		.srtcp_auth_tag		= 10,
		.srtp_auth_key_len	= 20,
		.srtcp_auth_key_len	= 20,
		.encrypt_rtp		= null_crypt_rtp,
		.decrypt_rtp		= null_crypt_rtp,
		.encrypt_rtcp		= null_crypt_rtcp,
		.decrypt_rtcp		= null_crypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
		.session_key_cleanup	= evp_session_key_cleanup,
	},
};

/* those crypto suites we can */
const struct crypto_suite *crypto_suites = __crypto_suites;
const unsigned int num_crypto_suites = G_N_ELEMENTS(__crypto_suites);




const struct crypto_suite * crypto_find_suite(const str *s) {
	int i;
	const struct crypto_suite *cs;

	for (i = 0; i < num_crypto_suites; i++) {
		cs = &crypto_suites[i];

		if (str_casecmp_str(&cs->name_str, s) == 0)
			return cs;
	}

	return NULL;
}

/* rfc 3711 section 4.1 and 4.1.1
 * "in" and "out" MAY point to the same buffer */
static void aes_ctr(unsigned char *out, str *in, EVP_CIPHER_CTX *ecc, const unsigned char *iv) {
	unsigned char ivx[16];
	unsigned char key_block[16];
	unsigned char *p, *q;
	unsigned int left;
	int outlen, i;
	gboolean aligned = TRUE;
	uint64_t *pi, *qi, *ki;

	if (!ecc)
		return;

	memcpy(ivx, iv, 16);
	pi = (void *) in->s;
	qi = (void *) out;
	ki = (void *) key_block;
	left = in->len;

	if ((GPOINTER_TO_UINT(pi) % sizeof(*pi)) != 0)
		aligned = FALSE;
	if ((GPOINTER_TO_UINT(qi) % sizeof(*qi)) != 0)
		aligned = FALSE;

	while (left) {
		EVP_EncryptUpdate(ecc, key_block, &outlen, ivx, 16);
		assert(outlen == 16);

		if (left < 16 || !aligned) {
			p = (void *) pi;
			q = (void *) qi;
			for (i = 0; i < 16; i++) {
				*q++ = *p++ ^ key_block[i];
				left--;
				if (!left)
					goto done;
			}
		}
		else {
			qi[0] = pi[0] ^ ki[0];
			qi[1] = pi[1] ^ ki[1];
			left -= 16;
		}
		qi += 2;
		pi += 2;

		for (i = 15; i >= 0; i--) {
			ivx[i]++;
			if (G_LIKELY(ivx[i]))
				break;
		}
	}

done:
	;
}

static void aes_ctr_no_ctx(unsigned char *out, str *in, const unsigned char *key, const EVP_CIPHER *ciph,
		const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx;
	unsigned char block[16];
	int len;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = EVP_CIPHER_CTX_new();
#else
	EVP_CIPHER_CTX ctx_s;
	ctx = &ctx_s;
	EVP_CIPHER_CTX_init(ctx);
#endif
	EVP_EncryptInit_ex(ctx, ciph, NULL, key, NULL);
	aes_ctr(out, in, ctx, iv);
	EVP_EncryptFinal_ex(ctx, block, &len);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(ctx);
#else
	EVP_CIPHER_CTX_cleanup(ctx);
#endif
}

/* rfc 3711 section 4.3.1 and 4.3.3
 * key: 128 bits
 * x: 112 bits
 * n <= 256
 * out->len := n / 8 */
static void prf_n(str *out, const unsigned char *key, const EVP_CIPHER *ciph, const unsigned char *x) {
	unsigned char iv[16];
	unsigned char o[32];
	unsigned char in[32];
	str in_s;

	assert(sizeof(o) >= out->len);

	ZERO(iv);
	memcpy(iv, x, 14);
	/* iv[14] = iv[15] = 0;   := x << 16 */
	ZERO(in); /* outputs the key stream */
	in_s = STR_LEN(in, out->len > 16 ? 32 : 16);
	aes_ctr_no_ctx(o, &in_s, key, ciph, iv);

	memcpy(out->s, o, out->len);
}



/* rfc 3711 section 4.3.1 */
int crypto_gen_session_key(struct crypto_context *c, str *out, unsigned char label, unsigned int index_len) {
	unsigned char key_id[7]; /* [ label, 48-bit ROC || SEQ ] */
	unsigned char x[14];
	int i;

	if (!out->len)
		return 0;

	ZERO(key_id);
	/* key_id[1..6] := r; or 1..4 for rtcp
	 * key_derivation_rate == 0 --> r == 0 */

	key_id[0] = label;
	assert(sizeof(x) >= c->params.crypto_suite->master_salt_len);
	memcpy(x, c->params.master_salt, c->params.crypto_suite->master_salt_len);
	// AEAD uses 12 bytes master salt; pad on the right to get 14
	// Errata: https://www.rfc-editor.org/errata_search.php?rfc=7714
	if (c->params.crypto_suite->master_salt_len == 12)
		x[12] = x[13] = '\x00';
	for (i = 13 - index_len; i < 14; i++)
		x[i] = key_id[i - (13 - index_len)] ^ x[i];

	prf_n(out, c->params.master_key, c->params.crypto_suite->aes_evp, x);

	ilogs(srtp, LOG_DEBUG, "Generated session key: master key "
			"%02x%02x%02x%02x..., "
			"master salt "
			"%02x%02x%02x%02x..., "
			"label %02x, length %zu, result "
			"%02x%02x%02x%02x...",
			c->params.master_key[0],
			c->params.master_key[1],
			c->params.master_key[2],
			c->params.master_key[3],
			c->params.master_salt[0],
			c->params.master_salt[1],
			c->params.master_salt[2],
			c->params.master_salt[3],
			label, out->len,
			(unsigned char) out->s[0],
			(unsigned char) out->s[1],
			(unsigned char) out->s[2],
			(unsigned char) out->s[3]);

	return 0;
}

/*
 * All versions of libsrtp w/openssl prior to 1.6 and 2.1 have
 * a bug in iv generation for AES-256 SRTCP only (SRTP is ok).
 * https://github.com/cisco/libsrtp/issues/264
 * Example: FreeSWITCH 1.6.x.
 * The bug is equivalent to:
 *
 * // idx <= 16 - no left shift
 * // ivi[1] ^= ssrc - don't use ssrc
 * // ivi[2] ^= idxh - don't use idxh
 */

/* rfc 3711 section 4.1.1 */
static int aes_cm_encrypt(struct crypto_context *c, uint32_t ssrc, str *s, uint32_t idx) {
	unsigned char iv[16];
	uint32_t *ivi;
	uint32_t idxh, idxl;

	memcpy(iv, c->session_salt, 14);
	iv[14] = iv[15] = '\0';
	ivi = (void *) iv;
	idxh = htonl((idx & 0xffff0000ULL) >> 16);
	idxl = htonl((idx & 0x0000ffffULL) << 16);

	ivi[1] ^= ssrc;
	ivi[2] ^= idxh;
	ivi[3] ^= idxl;

	aes_ctr((void *) s->s, s, c->session_key_ctx[0], iv);

	return 0;
}

/* rfc 3711 section 4.1 */
static int aes_cm_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx) {
	return aes_cm_encrypt(c, r->ssrc, s, idx);
}

/* rfc 3711 sections 3.4 and 4.1 */
static int aes_cm_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx) {
	return aes_cm_encrypt(c, r->ssrc, s, idx);
}

/* rfc 7714 section 8 */

union aes_gcm_rtp_iv {
	unsigned char bytes[12];
	struct {
		uint16_t zeros;
		uint32_t ssrc;
		uint32_t roq;
		uint16_t seq;
	} __attribute__((__packed__));
} __attribute__((__packed__));

_Static_assert(offsetof(union aes_gcm_rtp_iv, seq) == 10,
               "union aes_gcm_rtp_iv not packed");

static int aes_gcm_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx) {
	union aes_gcm_rtp_iv iv;
	int len, ciphertext_len;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->ssrc;
	iv.roq ^= htonl((idx & 0xffffff0000ULL) >> 16);
	iv.seq ^= htons( idx & 0x000000ffffULL);

	EVP_EncryptInit_ex(c->session_key_ctx[0], c->params.crypto_suite->aead_evp(), NULL,
			(const unsigned char *) c->session_key, iv.bytes);

	// nominally 12 bytes of AAD
	EVP_EncryptUpdate(c->session_key_ctx[0], NULL, &len, (void *)r, s->s - (char *)r);

	EVP_EncryptUpdate(c->session_key_ctx[0], (unsigned char *) s->s, &len,
			(const unsigned char *) s->s, s->len);
	ciphertext_len = len;
	if (!EVP_EncryptFinal_ex(c->session_key_ctx[0], (unsigned char *) s->s+len, &len))
		return 1;
	ciphertext_len += len;
	// append the tag to the str buffer
	EVP_CIPHER_CTX_ctrl(c->session_key_ctx[0], EVP_CTRL_GCM_GET_TAG, 16, s->s+ciphertext_len);
	s->len = ciphertext_len + 16;

	return 0;
}

static int aes_gcm_decrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx) {
	union aes_gcm_rtp_iv iv;
	int len, plaintext_len;

	if (s->len < 16)
		return -1;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->ssrc;
	iv.roq ^= htonl((idx & 0xffff0000ULL) >> 16);
	iv.seq ^= htons( idx & 0x0000ffffULL);

	EVP_DecryptInit_ex(c->session_key_ctx[0], c->params.crypto_suite->aead_evp(), NULL,
			(const unsigned char *) c->session_key, iv.bytes);

	// nominally 12 bytes of AAD
	EVP_DecryptUpdate(c->session_key_ctx[0], NULL, &len, (void *)r, s->s - (char *)r);

	// decrypt partial buffer - the last 16 bytes are the tag
	EVP_DecryptUpdate(c->session_key_ctx[0], (unsigned char *) s->s, &len,
			(const unsigned char *) s->s, s->len-16);
	plaintext_len = len;
	EVP_CIPHER_CTX_ctrl(c->session_key_ctx[0], EVP_CTRL_GCM_SET_TAG, 16, s->s + s->len-16);
	if (!EVP_DecryptFinal_ex(c->session_key_ctx[0], (unsigned char *) s->s+len, &len))
		return 1;
	plaintext_len += len;
	s->len = plaintext_len;

	return 0;
}

/* rfc 7714 section 9 */

union aes_gcm_rtcp_iv {
	unsigned char bytes[12];
	struct {
		uint16_t zeros_a;
		uint32_t ssrc;
		uint16_t zeros_b;
		uint32_t srtcp;
	} __attribute__((__packed__));
} __attribute__((__packed__));

_Static_assert(offsetof(union aes_gcm_rtcp_iv, srtcp) == 8,
               "union aes_gcm_rtcp_iv not packed");

static int aes_gcm_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx) {
	union aes_gcm_rtcp_iv iv;
	uint32_t e_idx;
	int len, ciphertext_len;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->ssrc;
	iv.srtcp ^= htonl(idx & 0x007fffffffULL);
	e_idx = htonl((idx & 0x007fffffffULL) | 0x80000000ULL);

	EVP_EncryptInit_ex(c->session_key_ctx[0], c->params.crypto_suite->aead_evp(), NULL,
			(const unsigned char *) c->session_key, iv.bytes);

	// nominally 8 + 4 bytes of AAD
	EVP_EncryptUpdate(c->session_key_ctx[0], NULL, &len, (void *)r, s->s - (char *)r);
	EVP_EncryptUpdate(c->session_key_ctx[0], NULL, &len, (void *)&e_idx, 4);

	EVP_EncryptUpdate(c->session_key_ctx[0], (unsigned char *) s->s, &len,
			(const unsigned char *) s->s, s->len);
	ciphertext_len = len;
	if (!EVP_EncryptFinal_ex(c->session_key_ctx[0], (unsigned char *) s->s+len, &len))
		return 1;
	ciphertext_len += len;
	// append the tag to the str buffer
	EVP_CIPHER_CTX_ctrl(c->session_key_ctx[0], EVP_CTRL_GCM_GET_TAG, 16, s->s+ciphertext_len);
	s->len = ciphertext_len + 16;

	return 0;
}

static int aes_gcm_decrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx) {
	union aes_gcm_rtcp_iv iv;
	uint32_t e_idx;
	int len, plaintext_len;

	if (s->len < 16)
		return -1;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->ssrc;
	iv.srtcp ^= htonl(idx & 0x007fffffffULL);
	e_idx = htonl((idx & 0x007fffffffULL) | 0x80000000ULL);

	EVP_DecryptInit_ex(c->session_key_ctx[0], c->params.crypto_suite->aead_evp(), NULL,
			(const unsigned char *) c->session_key, iv.bytes);

	// nominally 8 + 4 bytes of AAD
	EVP_DecryptUpdate(c->session_key_ctx[0], NULL, &len, (void *)r, s->s - (char *)r);
	EVP_DecryptUpdate(c->session_key_ctx[0], NULL, &len, (void *)&e_idx, 4);

	// decrypt partial buffer - the last 16 bytes are the tag
	EVP_DecryptUpdate(c->session_key_ctx[0], (unsigned char *) s->s, &len,
			(const unsigned char *) s->s, s->len-16);
	plaintext_len = len;
	EVP_CIPHER_CTX_ctrl(c->session_key_ctx[0], EVP_CTRL_GCM_SET_TAG, 16, s->s + s->len-16);
	if (!EVP_DecryptFinal_ex(c->session_key_ctx[0], (unsigned char *) s->s+len, &len))
		return 1;
	plaintext_len += len;
	s->len = plaintext_len;

	return 0;
}

/* rfc 3711 sections 4.1.2 and 4.1.2.1
 * encrypts in place */
static void aes_128_f8_encrypt(struct crypto_context *c, unsigned char *iv, str *s) {
	unsigned char key_block[16], last_key_block[16], /* S(j), S(j-1) */
		      ivx[16], /* IV' */
		      x[16];
	int i, outlen, left;
	uint32_t j;
	unsigned char *p;
	uint64_t *pi, *ki, *lki, *xi;
	uint32_t *xu;

	EVP_EncryptUpdate(c->session_key_ctx[1], ivx, &outlen, iv, 16);
	assert(outlen == 16);

	pi = (void *) s->s;
	ki = (void *) key_block;
	lki = (void *) last_key_block;
	xi = (void *) x;
	xu = (void *) x;
	left = s->len;
	j = 0;
	ZERO(last_key_block);

	while (left) {
		/* S(j) = E(k_e, IV' XOR j XOR S(j-1)) */
		memcpy(x, ivx, 16);

		xu[3] ^= htonl(j);

		xi[0] ^= lki[0];
		xi[1] ^= lki[1];

		EVP_EncryptUpdate(c->session_key_ctx[0], key_block, &outlen, x, 16);
		assert(outlen == 16);

		if (G_UNLIKELY(left < 16)) {
			p = (void *) pi;
			for (i = 0; i < 16; i++) {
				*p++ ^= key_block[i];
				left--;
				if (!left)
					goto done;
			}
			abort();
		}

		*pi++ ^= ki[0];
		*pi++ ^= ki[1];
		left -= 16;
		if (!left)
			break;

		j++;
		memcpy(last_key_block, key_block, 16);
	}

done:
	;
}

/* rfc 3711 section 4.1.2.2 */
static int aes_f8_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx) {
	unsigned char iv[16];
	uint32_t roc;

	iv[0] = '\0';
	memcpy(&iv[1], &r->m_pt, 11); /* m, pt, seq, ts, ssrc */
	roc = htonl((idx & 0xffffffff0000ULL) >> 16);
	memcpy(&iv[12], &roc, sizeof(roc));

	aes_128_f8_encrypt(c, iv, s);

	return 0;
}

/* rfc 3711 section 4.1.2.3 */
static int aes_f8_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx) {
	unsigned char iv[16];
	uint32_t i;

	memset(iv, 0, 4);
	i = htonl(0x80000000ULL | idx);
	memcpy(&iv[4], &i, 4);
	memcpy(&iv[8], r, 8); /* v, p, rc, pt, length, ssrc */

	aes_128_f8_encrypt(c, iv, s);

	return 0;
}
/* rfc 3711, sections 4.2 and 4.2.1 */
static int hmac_sha1_rtp(struct crypto_context *c, char *out, str *in, uint32_t index) {
	unsigned char hmac[20];
	uint32_t roc;

	roc = htonl((index & 0xffffffff0000ULL) >> 16);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC_CTX *hc;

	hc = EVP_MAC_CTX_dup(rtpe_hmac_sha1_base);
	EVP_MAC_init(hc, (unsigned char *) c->session_auth_key,
			c->params.crypto_suite->srtp_auth_key_len, NULL);
	EVP_MAC_update(hc, (unsigned char *) in->s, in->len);
	EVP_MAC_update(hc, (unsigned char *) &roc, sizeof(roc));
	size_t outsize = sizeof(hmac);
	EVP_MAC_final(hc, hmac, &outsize, outsize);
	EVP_MAC_CTX_free(hc);
#else // <3.0
	HMAC_CTX *hc;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	hc = HMAC_CTX_new();
#else
	HMAC_CTX hc_s;
	HMAC_CTX_init(&hc_s);
	hc = &hc_s;
#endif

	HMAC_Init_ex(hc, c->session_auth_key, c->params.crypto_suite->srtp_auth_key_len, EVP_sha1(), NULL);
	HMAC_Update(hc, (unsigned char *) in->s, in->len);
	HMAC_Update(hc, (unsigned char *) &roc, sizeof(roc));
	HMAC_Final(hc, hmac, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	HMAC_CTX_free(hc);
#else
	HMAC_CTX_cleanup(hc);
#endif
#endif

	assert(sizeof(hmac) >= c->params.crypto_suite->srtp_auth_tag);
	memcpy(out, hmac, c->params.crypto_suite->srtp_auth_tag);

	return 0;
}

/* rfc 3711, sections 4.2 and 4.2.1 */
static int hmac_sha1_rtcp(struct crypto_context *c, char *out, str *in) {
	unsigned char hmac[20];

	if (!HMAC(EVP_sha1(), c->session_auth_key, c->params.crypto_suite->srtcp_auth_key_len,
			(unsigned char *) in->s, in->len, hmac, NULL))
	{
		memset(out, 0, c->params.crypto_suite->srtcp_auth_tag);
		return 1;
	}

	assert(sizeof(hmac) >= c->params.crypto_suite->srtcp_auth_tag);
	memcpy(out, hmac, c->params.crypto_suite->srtcp_auth_tag);

	return 0;
}

static int aes_cm_session_key_init(struct crypto_context *c) {
	evp_session_key_cleanup(c);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	c->session_key_ctx[0] = EVP_CIPHER_CTX_new();
#else
	c->session_key_ctx[0] = g_slice_alloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(c->session_key_ctx[0]);
#endif
	EVP_EncryptInit_ex(c->session_key_ctx[0], c->params.crypto_suite->aes_evp, NULL,
			(unsigned char *) c->session_key, NULL);
	return 0;
}

static int aes_gcm_session_key_init(struct crypto_context *c) {
	evp_session_key_cleanup(c);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	c->session_key_ctx[0] = EVP_CIPHER_CTX_new();
#else
	c->session_key_ctx[0] = g_slice_alloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(c->session_key_ctx[0]);
#endif
	return 0;
}

static int aes_f8_session_key_init(struct crypto_context *c) {
	unsigned char m[16];
	int i;
	int k_e_len, k_s_len; /* n_e, n_s */
	unsigned char *key;

	aes_cm_session_key_init(c);

	k_e_len = c->params.crypto_suite->session_key_len;
	k_s_len = c->params.crypto_suite->session_salt_len;
	key = (unsigned char *) c->session_key;

	/* m = k_s || 0x555..5 */
	memcpy(m, c->session_salt, k_s_len);
	for (i = k_s_len; i < k_e_len; i++)
		m[i] = 0x55;
	/* IV' = E(k_e XOR m, IV) */
	for (i = 0; i < k_e_len; i++)
		m[i] ^= key[i];

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	c->session_key_ctx[1] = EVP_CIPHER_CTX_new();
#else
	c->session_key_ctx[1] = g_slice_alloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(c->session_key_ctx[1]);
#endif
	EVP_EncryptInit_ex(c->session_key_ctx[1], EVP_aes_128_ecb(), NULL, m, NULL);

	return 0;
}

static int evp_session_key_cleanup(struct crypto_context *c) {
	unsigned char block[16];
	int len, i;

	for (i = 0; i < G_N_ELEMENTS(c->session_key_ctx); i++) {
		if (!c->session_key_ctx[i])
			continue;

		EVP_EncryptFinal_ex(c->session_key_ctx[i], block, &len);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		EVP_CIPHER_CTX_free(c->session_key_ctx[i]);
#else
		EVP_CIPHER_CTX_cleanup(c->session_key_ctx[i]);
		g_slice_free1(sizeof(EVP_CIPHER_CTX), c->session_key_ctx[i]);
#endif
		c->session_key_ctx[i] = NULL;
	}

	return 0;
}

static int null_crypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, uint32_t idx) {
	return 0;
}
static int null_crypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, uint32_t idx) {
	return 0;
}

static void dump_key(struct crypto_context *c, int log_level) {
	char *k, *s;

	if (!c->params.crypto_suite)
		return;

	k = g_base64_encode(c->params.master_key, c->params.crypto_suite->master_key_len);
	s = g_base64_encode(c->params.master_salt, c->params.crypto_suite->master_salt_len);

	ilogs(srtp, log_level, "--- %s key %s%s%s salt %s%s%s", c->params.crypto_suite->name, FMT_M(k), FMT_M(s));

	g_free(k);
	g_free(s);
}

void crypto_dump_keys(struct crypto_context *in, struct crypto_context *out) {
	int log_level = LOG_DEBUG;
	
	if (rtpe_config.log_keys)
	    log_level = LOG_ERROR;
	    
	if (get_log_level(core) < log_level)
		return;

	ilogs(srtp, log_level, "SRTP keys, incoming:");
	dump_key(in, log_level);
	ilogs(srtp, log_level, "SRTP keys, outgoing:");
	dump_key(out, log_level);
}

char *crypto_params_sdes_dump(const struct crypto_params_sdes *cps, char **buf) {
	if (*buf)
		g_free(*buf);

	GString *s = g_string_new("");
	if (!cps || !cps->params.crypto_suite) {
		g_string_append(s, "<none>");
		goto out;
	}

	g_string_append_printf(s, "suite %s, tag %u, key ", cps->params.crypto_suite->name, cps->tag);
	char *b = g_base64_encode(cps->params.master_key, cps->params.crypto_suite->master_key_len);
	g_string_append_printf(s, "%s salt ", b);
	g_free(b);
	b = g_base64_encode(cps->params.master_salt, cps->params.crypto_suite->master_salt_len);
	g_string_append_printf(s, "%s", b);
	g_free(b);

out:
	*buf = g_string_free(s, FALSE);
	return *buf;
}

void crypto_init_main(void) {
	struct crypto_suite *cs;
	for (unsigned int i = 0; i < num_crypto_suites; i++) {
		cs = &__crypto_suites[i];
		cs->idx = i;
		cs->name_str = STR(cs->name);
		switch(cs->master_key_len) {
		case 16:
			cs->aes_evp = EVP_aes_128_ecb();
			break;
		case 24:
			cs->aes_evp = EVP_aes_192_ecb();
			break;
		case 32:
			cs->aes_evp = EVP_aes_256_ecb();
			break;
		}
	}
}

void __crypto_debug_printf(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	g_string_append_vprintf(crypto_debug_string, fmt, va);
	va_end(va);
}
