#include <assert.h>
#include <stdio.h>

#include "crypto.h"
#include "rtplib.h"
#include "log.h"
#include "main.h"
#include "ssllib.h"

struct rtpengine_config rtpe_config;

uint8_t test_key[46] = {
	0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
	0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
	0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
	0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6, 0xc1, 0x73,
	0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77, 0x93,
	0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};



uint8_t rtp_plaintext_ref[28] = {
	0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
	0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab
};


uint8_t rtcp_plaintext_ref[24] = {
	0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
};

// SRTP Test Vectors
// ROC = 0, SSRC = 0xcafebabe, SEQ_NUM = 0x1234
uint8_t srtp_ciphertext_128[38] = {
	0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
	0xca, 0xfe, 0xba, 0xbe, 0x4e, 0x55, 0xdc, 0x4c,
	0xe7, 0x99, 0x78, 0xd8, 0x8c, 0xa4, 0xd2, 0x15,
	0x94, 0x9d, 0x24, 0x02, 0xb7, 0x8d, 0x6a, 0xcc,
	0x99, 0xea, 0x17, 0x9b, 0x8d, 0xbb
};

uint8_t srtp_ciphertext_192[38] = {
	0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
	0xca, 0xfe, 0xba, 0xbe, 0x01, 0x57, 0x81, 0x89,
	0x44, 0x62, 0x52, 0x9d, 0x91, 0xcf, 0x36, 0x59,
	0xd2, 0x46, 0x2d, 0xb3, 0x08, 0xd9, 0xa0, 0x44,
	0xc5, 0xd7, 0xd6, 0x8b, 0x26, 0xba
};

uint8_t srtp_ciphertext_256[38] = {
	0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
	0xca, 0xfe, 0xba, 0xbe, 0x00, 0x98, 0x21, 0x9f,
	0x7e, 0xbd, 0xba, 0x1c, 0x3d, 0x22, 0xf4, 0x93,
	0x6f, 0x1e, 0xac, 0x99, 0x06, 0xf6, 0xb2, 0x27,
	0xc8, 0x49, 0x61, 0xa7, 0xb4, 0x28
};


// SRTCP Test Vectors
// SSRC = 0xcafebabe
uint8_t srtcp_ciphertext_128[38] = {
	0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
	0x71, 0x28, 0x03, 0x5b, 0xe4, 0x87, 0xb9, 0xbd,
	0xbe, 0xf8, 0x90, 0x41, 0xf9, 0x77, 0xa5, 0xa8,
	0x80, 0x00, 0x00, 0x01, 0x99, 0x3e, 0x08, 0xcd,
	0x54, 0xd6, 0xc1, 0x23, 0x07, 0x98
};

uint8_t srtcp_ciphertext_192[38] = {
        0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
        0x96, 0x6d, 0x60, 0x3e, 0x71, 0xf9, 0xaf, 0x33,
        0x5c, 0xf9, 0x09, 0x1a, 0x50, 0xca, 0x4d, 0x3a,
        0x80, 0x00, 0x00, 0x01, 0xd4, 0x2b, 0x40, 0x21,
        0x8d, 0xde, 0x49, 0x90, 0xbd, 0xef
};

uint8_t srtcp_ciphertext_256[38] = {
	0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
        0x0a, 0x86, 0x5d, 0x33, 0x9e, 0x31, 0x26, 0x93,
        0x59, 0x23, 0x87, 0xd4, 0x5b, 0x99, 0xa5, 0x57,
        0x80, 0x00, 0x00, 0x01, 0x84, 0xf3, 0xb4, 0xf2,
        0xb5, 0x95, 0x61, 0x5a, 0xf9, 0xb5
};

// Another set of AES-256 test vectors from libsrtp
uint8_t aes_256_test_key[46] = {
	0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76,
        0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1, 0x0e, 0x29,
        0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1,
        0xe6, 0x22, 0xa0, 0xe3, 0x32, 0xb9, 0xf1, 0xb6,

        0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9,
        0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2
};
uint8_t aes_256_rtp_plaintext_ref[28] = {
	0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
};

uint8_t aes_256_srtp_ciphertext[38] = {
	0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xf1, 0xd9, 0xde, 0x17,
        0xff, 0x25, 0x1f, 0xf1, 0xaa, 0x00, 0x77, 0x74,
        0xb0, 0xb4, 0xb4, 0x0d, 0xa0, 0x8d, 0x9d, 0x9a,
        0x5b, 0x3a, 0x55, 0xd8, 0x87, 0x3b
};


#define RTP_HEADER_LEN 12
#define RTCP_HEADER_LEN 8
// Test: AES-128 CM
void srtp_validate (struct crypto_context *c, struct crypto_context *c2, char* message, uint8_t *plaintext, uint8_t *ciphertext,
		    uint8_t *rtcp_plaintext, uint8_t *rtcp_ciphertext)
{
	str payload, hash;
	char o_hash[10];
	
	char srtp_plaintext[38];
	char srtp_ciphertext[38];
	
	char srtcp_plaintext[38];
	char srtcp_ciphertext[38];

	memcpy(srtp_plaintext, plaintext, 28);
	memcpy(srtp_ciphertext, ciphertext, 38);
	// in-place crypto so we must encrypt first
	payload = STR_LEN(srtp_plaintext+RTP_HEADER_LEN, 16);
	crypto_encrypt_rtp(c, (struct rtp_header *)srtp_plaintext, &payload, ntohs(((struct rtp_header *)srtp_plaintext)->seq_num));

	hash = STR_LEN(srtp_plaintext, 28);
	c->params.crypto_suite->hash_rtp(c, srtp_plaintext+28, &hash, ntohs(((struct rtp_header *)srtp_plaintext)->seq_num));
	assert( memcmp(payload.s, srtp_ciphertext+RTP_HEADER_LEN, 26)  == 0 );

	printf("%s RTP encrypt: PASS\n", message);
	
	hash.s = srtp_ciphertext;
	c->params.crypto_suite->hash_rtp(c, o_hash, &hash, ntohs(((struct rtp_header *)srtp_plaintext)->seq_num));
	payload = STR_LEN(srtp_ciphertext+RTP_HEADER_LEN, 16);
	crypto_decrypt_rtp(c, (struct rtp_header *)srtp_ciphertext, &payload, ntohs(((struct rtp_header *)srtp_ciphertext)->seq_num));
	assert( memcmp(payload.s, rtp_plaintext_ref+RTP_HEADER_LEN, 16)  == 0 );
	assert( memcmp(o_hash, srtp_ciphertext+RTP_HEADER_LEN+16, 10)  == 0 );

	printf("%s RTP decrypt: PASS\n", message);

	// in-place crypto so we must encrypt first
	if (!c2) return;
	memcpy(srtcp_plaintext, rtcp_plaintext, 24);
	memcpy(srtcp_ciphertext, rtcp_ciphertext, 38);
	memcpy(srtcp_plaintext+24, srtcp_ciphertext+24, 4);
	payload = STR_LEN(srtcp_plaintext+RTCP_HEADER_LEN, 16);
	crypto_encrypt_rtcp(c2, (struct rtcp_packet *)srtcp_plaintext, &payload, 1);

	hash = STR_LEN(srtcp_plaintext, 28);
	c->params.crypto_suite->hash_rtcp(c2, srtcp_plaintext+28, &hash);
	assert( memcmp(payload.s, srtcp_ciphertext+RTCP_HEADER_LEN, 30)  == 0 );

	printf("%s RTCP encrypt: PASS\n", message);
	
	hash.s = srtcp_ciphertext;
	c->params.crypto_suite->hash_rtcp(c2, o_hash, &hash);
	payload = STR_LEN(srtcp_ciphertext+RTCP_HEADER_LEN, 16);
	crypto_decrypt_rtcp(c2, (struct rtcp_packet *)srtcp_ciphertext, &payload, 1);
	assert( memcmp(payload.s, rtcp_plaintext_ref+RTCP_HEADER_LEN, 16)  == 0 );
	assert( memcmp(o_hash, srtcp_ciphertext+RTCP_HEADER_LEN+16+4, 10)  == 0 );

	printf("%s RTCP decrypt: PASS\n", message);
}

extern void crypto_init_main(void);

void check_session_keys(struct crypto_context *c, int i) {
	str s;
        s = STR_LEN_ASSERT(c->session_key, c->params.crypto_suite->session_key_len);
        if (crypto_gen_session_key(c, &s, i++, 6))
                goto error;
        s = STR_LEN_ASSERT(c->session_auth_key, c->params.crypto_suite->srtp_auth_key_len);
        if (crypto_gen_session_key(c, &s, i++, 6))
                goto error;
        s = STR_LEN_ASSERT(c->session_salt, c->params.crypto_suite->session_salt_len);
        if (crypto_gen_session_key(c, &s, i, 6))
                goto error;

        c->have_session_key = 1;
        crypto_init_session_key(c);

error:
	return;
}

int main(int argc, char** argv) {

	str suite;
	const struct crypto_suite *c;
	struct crypto_context ctx, ctx2;

	crypto_init_main();
	rtpe_ssl_init();
	
	suite = STR("AES_CM_128_HMAC_SHA1_80");
	c = crypto_find_suite(&suite);
	assert(c);

	memset(&ctx, 0, sizeof(ctx));
	ctx.params.crypto_suite = c;
	memcpy(ctx.params.master_key, test_key, 16);
	memcpy(ctx.params.master_salt, (uint8_t*)test_key+16, 14);
	ctx.params.mki_len = 0;
	
	check_session_keys(&ctx, 0);

	memset(&ctx2, 0, sizeof(ctx2));
	ctx2.params.crypto_suite = c;
	memcpy(ctx2.params.master_key, test_key, 16);
	memcpy(ctx2.params.master_salt, (uint8_t*)test_key+16, 14);
	ctx2.params.mki_len = 0;
	
	check_session_keys(&ctx2, 3);
	
	srtp_validate(&ctx, &ctx2, "SRTP AES-CM-128", rtp_plaintext_ref, srtp_ciphertext_128,
		      rtcp_plaintext_ref, srtcp_ciphertext_128);
	
	suite = STR("AES_192_CM_HMAC_SHA1_80");
	c = crypto_find_suite(&suite);
	assert(c);

	crypto_cleanup_session_key(&ctx);
	crypto_cleanup_session_key(&ctx2);

	memset(&ctx, 0, sizeof(ctx));
	ctx.params.crypto_suite = c;
	memcpy(ctx.params.master_key, test_key, 24);
	memcpy(ctx.params.master_salt, (uint8_t*)test_key+24, 14);
	ctx.params.mki_len = 0;

	check_session_keys(&ctx, 0);
	
	memset(&ctx2, 0, sizeof(ctx2));
	ctx2.params.crypto_suite = c;
	memcpy(ctx2.params.master_key, test_key, 24);
	memcpy(ctx2.params.master_salt, (uint8_t*)test_key+24, 14);
	ctx2.params.mki_len = 0;

	check_session_keys(&ctx2, 3);

	srtp_validate(&ctx, &ctx2, "SRTP AES-CM-192", rtp_plaintext_ref, srtp_ciphertext_192,
		      rtcp_plaintext_ref, srtcp_ciphertext_192);
	
	suite = STR("AES_256_CM_HMAC_SHA1_80");
	c = crypto_find_suite(&suite);
	assert(c);

	crypto_cleanup_session_key(&ctx);
	crypto_cleanup_session_key(&ctx2);

	memset(&ctx, 0, sizeof(ctx));
	ctx.params.crypto_suite = c;
	memcpy(ctx.params.master_key, test_key, 32);
	memcpy(ctx.params.master_salt, (uint8_t*)test_key+32, 14);
	ctx.params.mki_len = 0;

	check_session_keys(&ctx, 0);
	
	memset(&ctx2, 0, sizeof(ctx2));
	ctx2.params.crypto_suite = c;
	memcpy(ctx2.params.master_key, test_key, 32);
	memcpy(ctx2.params.master_salt, (uint8_t*)test_key+32, 14);
	ctx2.params.mki_len = 0;

	check_session_keys(&ctx2, 3);

	srtp_validate(&ctx, &ctx2, "SRTP AES-CM-256", rtp_plaintext_ref, srtp_ciphertext_256,
		      rtcp_plaintext_ref, srtcp_ciphertext_256);

	crypto_cleanup_session_key(&ctx);
	crypto_cleanup_session_key(&ctx2);

	memset(&ctx, 0, sizeof(ctx));
	ctx.params.crypto_suite = c;
	memcpy(ctx.params.master_key, aes_256_test_key, 32);
	memcpy(ctx.params.master_salt, (uint8_t*)aes_256_test_key+32, 14);
	ctx.params.mki_len = 0;

	check_session_keys(&ctx, 0);

	srtp_validate(&ctx, NULL, "extra AES-CM-256", aes_256_rtp_plaintext_ref, aes_256_srtp_ciphertext,
		      NULL, NULL);

	crypto_cleanup_session_key(&ctx);
}

int get_local_log_level(unsigned int u) {
	return -1;
}
