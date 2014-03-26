#include "crypto.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <glib.h>

#include "xt_MEDIAPROXY.h"

#include "str.h"
#include "aux.h"
#include "rtp.h"
#include "rtcp.h"
#include "log.h"




#define CRYPTO_DEBUG 0



static int aes_cm_encrypt_rtp(struct crypto_context *, struct rtp_header *, str *, u_int64_t);
static int aes_cm_encrypt_rtcp(struct crypto_context *, struct rtcp_packet *, str *, u_int64_t);
static int hmac_sha1_rtp(struct crypto_context *, char *out, str *in, u_int64_t);
static int hmac_sha1_rtcp(struct crypto_context *, char *out, str *in);
static int aes_f8_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, u_int64_t idx);
static int aes_f8_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, u_int64_t idx);
static int aes_cm_session_key_init(struct crypto_context *c);
static int aes_f8_session_key_init(struct crypto_context *c);
static int evp_session_key_cleanup(struct crypto_context *c);
static int null_crypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, u_int64_t idx);
static int null_crypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, u_int64_t idx);

/* all lengths are in bytes */
const struct crypto_suite crypto_suites[] = {
	{
		.name			= "AES_CM_128_HMAC_SHA1_80",
		.dtls_name		= "SRTP_AES128_CM_SHA1_80",
		.master_key_len		= 16,
		.master_salt_len	= 14,
		.session_key_len	= 16,
		.session_salt_len	= 14,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.kernel_cipher		= MPC_AES_CM,
		.kernel_hmac		= MPH_HMAC_SHA1,
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
		.kernel_cipher		= MPC_AES_CM,
		.kernel_hmac		= MPH_HMAC_SHA1,
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
		.kernel_cipher		= MPC_AES_F8,
		.kernel_hmac		= MPH_HMAC_SHA1,
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
		.kernel_cipher		= MPC_AES_F8,
		.kernel_hmac		= MPH_HMAC_SHA1,
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
		.kernel_cipher		= MPC_NULL,
		.kernel_hmac		= MPH_HMAC_SHA1,
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
		.kernel_cipher		= MPC_NULL,
		.kernel_hmac		= MPH_HMAC_SHA1,
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

const int num_crypto_suites = G_N_ELEMENTS(crypto_suites);




const struct crypto_suite *crypto_find_suite(const str *s) {
	int i, l;
	const struct crypto_suite *cs;

	for (i = 0; i < num_crypto_suites; i++) {
		cs = &crypto_suites[i];
		if (!cs->name)
			continue;

		l = strlen(cs->name);
		if (l != s->len)
			continue;

		if (strncasecmp(cs->name, s->s, s->len))
			continue;

		return cs;
	}

	return NULL;
}



/* rfc 3711 section 4.1 and 4.1.1
 * "in" and "out" MAY point to the same buffer */
static void aes_ctr_128(unsigned char *out, str *in, EVP_CIPHER_CTX *ecc, const unsigned char *iv) {
	unsigned char ivx[16];
	unsigned char key_block[16];
	unsigned char *p, *q;
	unsigned int left;
	int outlen, i;
	u_int64_t *pi, *qi, *ki;

	if (!ecc)
		return;

	memcpy(ivx, iv, 16);
	pi = (void *) in->s;
	qi = (void *) out;
	ki = (void *) key_block;
	left = in->len;

	while (left) {
		EVP_EncryptUpdate(ecc, key_block, &outlen, ivx, 16);
		assert(outlen == 16);

		if (G_UNLIKELY(left < 16)) {
			p = (void *) pi;
			q = (void *) qi;
			for (i = 0; i < 16; i++) {
				*q++ = *p++ ^ key_block[i];
				left--;
				if (!left)
					goto done;
			}
			abort();
		}

		*qi++ = *pi++ ^ ki[0];
		*qi++ = *pi++ ^ ki[1];
		left -= 16;

		for (i = 15; i >= 0; i--) {
			ivx[i]++;
			if (G_LIKELY(ivx[i]))
				break;
		}
	}

done:
	;
}

static void aes_ctr_128_no_ctx(unsigned char *out, str *in, const unsigned char *key, const unsigned char *iv) {
	EVP_CIPHER_CTX ctx;
	unsigned char block[16];
	int len;

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	aes_ctr_128(out, in, &ctx, iv);
	EVP_EncryptFinal_ex(&ctx, block, &len);
	EVP_CIPHER_CTX_cleanup(&ctx);
}

/* rfc 3711 section 4.3.1 and 4.3.3
 * key: 128 bits
 * x: 112 bits
 * n <= 256
 * out->len := n / 8 */
static void prf_n(str *out, const unsigned char *key, const unsigned char *x) {
	unsigned char iv[16];
	unsigned char o[32];
	unsigned char in[32];
	str in_s;

	assert(sizeof(o) >= out->len);

	ZERO(iv);
	memcpy(iv, x, 14);
	/* iv[14] = iv[15] = 0;   := x << 16 */
	ZERO(in); /* outputs the key stream */
	str_init_len(&in_s, (void *) in, out->len > 16 ? 32 : 16);
	aes_ctr_128_no_ctx(o, &in_s, key, iv);

	memcpy(out->s, o, out->len);
}



/* rfc 3711 section 4.3.1 */
int crypto_gen_session_key(struct crypto_context *c, str *out, unsigned char label, int index_len) {
	unsigned char key_id[7]; /* [ label, 48-bit ROC || SEQ ] */
	unsigned char x[14];
	int i;

	ZERO(key_id);
	/* key_id[1..6] := r; or 1..4 for rtcp
	 * key_derivation_rate == 0 --> r == 0 */

	key_id[0] = label;
	memcpy(x, c->params.master_salt, 14);
	for (i = 13 - index_len; i < 14; i++)
		x[i] = key_id[i - (13 - index_len)] ^ x[i];

	prf_n(out, c->params.master_key, x);

#if CRYPTO_DEBUG
	ilog(LOG_DEBUG, "Generated session key: master key "
			"%02x%02x%02x%02x..., "
			"master salt "
			"%02x%02x%02x%02x..., "
			"label %02x, length %i, result "
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
#endif

	return 0;
}

/* rfc 3711 section 4.1.1 */
static int aes_cm_encrypt(struct crypto_context *c, u_int32_t ssrc, str *s, u_int64_t idx) {
	unsigned char iv[16];
	u_int32_t *ivi;
	u_int32_t idxh, idxl;

	memcpy(iv, c->session_salt, 14);
	iv[14] = iv[15] = '\0';
	ivi = (void *) iv;
	idx <<= 16;
	idxh = htonl((idx & 0xffffffff00000000ULL) >> 32);
	idxl = htonl(idx & 0xffffffffULL);

	ivi[1] ^= ssrc;
	ivi[2] ^= idxh;
	ivi[3] ^= idxl;

	aes_ctr_128((void *) s->s, s, c->session_key_ctx[0], iv);

	return 0;
}

/* rfc 3711 section 4.1 */
static int aes_cm_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, u_int64_t idx) {
	return aes_cm_encrypt(c, r->ssrc, s, idx);
}

/* rfc 3711 sections 3.4 and 4.1 */
static int aes_cm_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, u_int64_t idx) {
	return aes_cm_encrypt(c, r->ssrc, s, idx);
}

/* rfc 3711 sections 4.1.2 and 4.1.2.1
 * encrypts in place */
static void aes_128_f8_encrypt(struct crypto_context *c, unsigned char *iv, str *s) {
	unsigned char key_block[16], last_key_block[16], /* S(j), S(j-1) */
		      ivx[16], /* IV' */
		      x[16];
	int i, outlen, left;
	u_int32_t j;
	unsigned char *p;
	u_int64_t *pi, *ki, *lki, *xi;
	u_int32_t *xu;

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
static int aes_f8_encrypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, u_int64_t idx) {
	unsigned char iv[16];
	u_int32_t roc;

	iv[0] = '\0';
	memcpy(&iv[1], &r->m_pt, 11); /* m, pt, seq, ts, ssrc */
	roc = htonl((idx & 0xffffffff0000ULL) >> 16);
	memcpy(&iv[12], &roc, sizeof(roc));

	aes_128_f8_encrypt(c, iv, s);

	return 0;
}

/* rfc 3711 section 4.1.2.3 */
static int aes_f8_encrypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, u_int64_t idx) {
	unsigned char iv[16];
	u_int32_t i;

	memset(iv, 0, 4);
	i = htonl(0x80000000ULL | idx);
	memcpy(&iv[4], &i, 4);
	memcpy(&iv[8], &r->header.v_p_x, 8); /* v, p, rc, pt, length, ssrc */

	aes_128_f8_encrypt(c, iv, s);

	return 0;
}
/* rfc 3711, sections 4.2 and 4.2.1 */
static int hmac_sha1_rtp(struct crypto_context *c, char *out, str *in, u_int64_t index) {
	unsigned char hmac[20];
	HMAC_CTX hc;
	u_int32_t roc;

	HMAC_Init(&hc, c->session_auth_key, c->params.crypto_suite->srtp_auth_key_len, EVP_sha1());
	HMAC_Update(&hc, (unsigned char *) in->s, in->len);
	roc = htonl((index & 0xffffffff0000ULL) >> 16);
	HMAC_Update(&hc, (unsigned char *) &roc, sizeof(roc));
	HMAC_Final(&hc, hmac, NULL);
	HMAC_CTX_cleanup(&hc);

	assert(sizeof(hmac) >= c->params.crypto_suite->srtp_auth_tag);
	memcpy(out, hmac, c->params.crypto_suite->srtp_auth_tag);

	return 0;
}

/* rfc 3711, sections 4.2 and 4.2.1 */
static int hmac_sha1_rtcp(struct crypto_context *c, char *out, str *in) {
	unsigned char hmac[20];

	HMAC(EVP_sha1(), c->session_auth_key, c->params.crypto_suite->srtcp_auth_key_len,
			(unsigned char *) in->s, in->len, hmac, NULL);

	assert(sizeof(hmac) >= c->params.crypto_suite->srtcp_auth_tag);
	memcpy(out, hmac, c->params.crypto_suite->srtcp_auth_tag);

	return 0;
}

static int aes_cm_session_key_init(struct crypto_context *c) {
	evp_session_key_cleanup(c);

	c->session_key_ctx[0] = g_slice_alloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(c->session_key_ctx[0]);
	EVP_EncryptInit_ex(c->session_key_ctx[0], EVP_aes_128_ecb(), NULL,
			(unsigned char *) c->session_key, NULL);
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

	c->session_key_ctx[1] = g_slice_alloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(c->session_key_ctx[1]);
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
		EVP_CIPHER_CTX_cleanup(c->session_key_ctx[i]);
		g_slice_free1(sizeof(EVP_CIPHER_CTX), c->session_key_ctx[i]);
		c->session_key_ctx[i] = NULL;
	}

	return 0;
}

static int null_crypt_rtp(struct crypto_context *c, struct rtp_header *r, str *s, u_int64_t idx) {
	return 0;
}
static int null_crypt_rtcp(struct crypto_context *c, struct rtcp_packet *r, str *s, u_int64_t idx) {
	return 0;
}
