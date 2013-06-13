#include "crypto.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "str.h"
#include "aux.h"
#include "rtp.h"
#include "rtcp.h"



static int aes_cm_encrypt_rtp(struct crypto_context *, struct rtp_header *, str *, u_int64_t);
static int aes_cm_encrypt_rtcp(struct crypto_context *, struct rtcp_packet *, str *, u_int64_t);
static int hmac_sha1_rtp(struct crypto_context *, char *out, str *in, u_int64_t);
static int hmac_sha1_rtcp(struct crypto_context *, char *out, str *in);

/* all lengths are in bits, some code assumes everything to be multiples of 8 */
const struct crypto_suite crypto_suites[] = {
	{
		.name			= "AES_CM_128_HMAC_SHA1_80",
		.master_key_len		= 128,
		.master_salt_len	= 112,
		.session_key_len	= 128,
		.session_salt_len	= 112,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.cipher			= CIPHER_AES_CM,
		.encryption_key		= 128,
		.mac			= MAC_HMAC_SHA1,
		.srtp_auth_tag		= 80,
		.srtcp_auth_tag		= 80,
		.srtp_auth_key_len	= 160,
		.srtcp_auth_key_len	= 160,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
	},
	{
		.name			= "AES_CM_128_HMAC_SHA1_32",
		.master_key_len		= 128,
		.master_salt_len	= 112,
		.session_key_len	= 128,
		.session_salt_len	= 112,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.cipher			= CIPHER_AES_CM,
		.encryption_key		= 128,
		.mac			= MAC_HMAC_SHA1,
		.srtp_auth_tag		= 32,
		.srtcp_auth_tag		= 80,
		.srtp_auth_key_len	= 160,
		.srtcp_auth_key_len	= 160,
		.encrypt_rtp		= aes_cm_encrypt_rtp,
		.decrypt_rtp		= aes_cm_encrypt_rtp,
		.encrypt_rtcp		= aes_cm_encrypt_rtcp,
		.decrypt_rtcp		= aes_cm_encrypt_rtcp,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
	},
	{
		.name			= "F8_128_HMAC_SHA1_80",
		.master_key_len		= 128,
		.master_salt_len	= 112,
		.session_key_len	= 128,
		.session_salt_len	= 112,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.cipher			= CIPHER_AES_F8,
		.encryption_key		= 128,
		.mac			= MAC_HMAC_SHA1,
		.srtp_auth_tag		= 80,
		.srtcp_auth_tag		= 80,
		.srtp_auth_key_len	= 160,
		.srtcp_auth_key_len	= 160,
		.hash_rtp		= hmac_sha1_rtp,
		.hash_rtcp		= hmac_sha1_rtcp,
	},
};

const int num_crypto_suites = ARRAYSIZE(crypto_suites);




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
static void aes_ctr_128(char *out, str *in, char *key, char *iv) {
	EVP_CIPHER_CTX ecc;
	unsigned char ivx[16];
	unsigned char key_block[16];
	unsigned char *p, *q;
	unsigned int left;
	int outlen, i;

	memcpy(ivx, iv, 16);
	p = (unsigned char *) in->s;
	q = (unsigned char *) out;
	left = in->len;

	/* XXX do this only once per thread or maybe once per stream/key? */
	EVP_CIPHER_CTX_init(&ecc);

	EVP_EncryptInit_ex(&ecc, EVP_aes_128_ecb(), NULL, (unsigned char *) key, NULL);

	while (left) {
		EVP_EncryptUpdate(&ecc, key_block, &outlen, ivx, 16);
		assert(outlen == 16);

		for (i = 0; i < 16; i++) {
			*q = *p ^ key_block[i];
			q++;
			p++;
			left--;
			if (!left)
				goto done;
		}

		for (i = 15; i >= 0; i--) {
			ivx[i]++;
			if (G_LIKELY(ivx[i]))
				break;
		}
	}

done:

	EVP_EncryptFinal_ex(&ecc, key_block, &outlen);

	EVP_CIPHER_CTX_cleanup(&ecc);
}

/* rfc 3711 section 4.3.1 and 4.3.3
 * key: 128 bits
 * x: 112 bits
 * n <= 256
 * out->len := n / 8 */
static void prf_n(str *out, char *key, char *x) {
	char iv[16];
	char o[32];
	char in[32];
	str in_s;

	assert(sizeof(o) >= out->len);

	ZERO(iv);
	memcpy(iv, x, 14);
	/* iv[14] = iv[15] = 0;   := x << 16 */
	ZERO(in); /* outputs the key stream */
	str_init_len(&in_s, in, 16);
	aes_ctr_128(o, &in_s, key, iv);

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
	memcpy(x, c->master_salt, 14);
	for (i = 13 - index_len; i < 14; i++)
		x[i] = key_id[i - (13 - index_len)] ^ x[i];

	prf_n(out, c->master_key, (char *) x);

	return 0;
}

/* rfc 3711 section 4.1.1 */
static int aes_cm_encrypt(struct crypto_context *c, u_int32_t ssrc, str *s, u_int64_t idx) {
	unsigned char iv[16];
	unsigned char *p;
	int i;

	ZERO(iv);
	memcpy(iv, c->session_salt, 14);

	p = (void *) &ssrc;
	for (i = 0; i < 4; i++)
		iv[i + 4] = iv[i + 4] ^ p[i];

	for (i = 0; i < 6; i++)
		iv[i + 8] = iv[i + 8] ^ ((idx >> ((5 - i) * 8)) & 0xff);

	aes_ctr_128(s->s, s, c->session_key, (char *) iv);

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

/* rfc 3711, sections 4.2 and 4.2.1 */
static int hmac_sha1_rtp(struct crypto_context *c, char *out, str *in, u_int64_t index) {
	unsigned char hmac[20];
	HMAC_CTX hc;
	u_int32_t roc;

	HMAC_Init(&hc, c->session_auth_key, c->crypto_suite->srtp_auth_key_len / 8, EVP_sha1());
	HMAC_Update(&hc, (unsigned char *) in->s, in->len);
	roc = htonl((index & 0xffffffff0000ULL) >> 16);
	HMAC_Update(&hc, (unsigned char *) &roc, sizeof(roc));
	HMAC_Final(&hc, hmac, NULL);
	HMAC_CTX_cleanup(&hc);

	assert(sizeof(hmac) >= c->crypto_suite->srtp_auth_tag / 8);
	memcpy(out, hmac, c->crypto_suite->srtp_auth_tag / 8);

	return 0;
}

/* rfc 3711, sections 4.2 and 4.2.1 */
static int hmac_sha1_rtcp(struct crypto_context *c, char *out, str *in) {
	unsigned char hmac[20];

	HMAC(EVP_sha1(), c->session_auth_key, c->crypto_suite->srtcp_auth_key_len / 8,
			(unsigned char *) in->s, in->len, hmac, NULL);

	assert(sizeof(hmac) >= c->crypto_suite->srtcp_auth_tag / 8);
	memcpy(out, hmac, c->crypto_suite->srtcp_auth_tag / 8);

	return 0;
}
