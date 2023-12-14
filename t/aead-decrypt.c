#include <assert.h>

#include "crypto.h"
#include "rtplib.h"
#include "log.h"
#include "main.h"
#include "ssrc.h"
#include "rtp.h"
#include "../kernel-module/common_stats.h"


struct rtpengine_config rtpe_config = {
};
int get_local_log_level(unsigned int u) {
	return -1;
}

int main(int argc, char **argv) {
	if (argc < 5) {
		printf("Usage: %s <suite> <key> <salt> <packet>\n", argv[0]);
		printf("Example: %s AEAD_AES_256_GCM \\\n", argv[0]);
		printf("  F4mVFvZGU/S50OXT17xvKHCC/8CV5vgp8OgmAlFpKcc= \\\n");
		printf("  fNAN6151Wc6DgFEZ gAhqUYthx4ivfuWtbtq...\n");
		return 1;
	}

	crypto_init_main();

	str suite;
	suite = STR(argv[1]);
	struct crypto_context cc = {0};
	cc.params.crypto_suite = crypto_find_suite(&suite);
	assert(cc.params.crypto_suite);

	const char *key64 = argv[2];
	const char *salt64 = argv[3];

	size_t len;
	uint8_t *key = g_base64_decode(key64, &len);
	assert(len == cc.params.crypto_suite->master_key_len);
	uint8_t *salt = g_base64_decode(salt64, &len);
	assert(len == cc.params.crypto_suite->master_salt_len);

	memcpy(cc.params.master_key, key, cc.params.crypto_suite->master_key_len);
	memcpy(cc.params.master_salt, salt, cc.params.crypto_suite->master_salt_len);

	const char *pack64 = argv[4];
	uint8_t *pack = g_base64_decode(pack64, &len);
	str s = STR_LEN((char *) pack, len);

	unsigned int roc = 0;

	if (argc >= 6)
		roc = atoi(argv[5]);

	struct ssrc_stats stats = {
		.ext_seq = roc << 16,
	};

	struct ssrc_entry_call se = {
		.input_ctx = {
			.parent = &se,
			.stats = &stats,
		},
	};

	int ret = rtp_savp2avp(&s, &cc, &se.input_ctx);
	assert(ret == 0);
	printf("idx %d ROC %d\n", se.input_ctx.stats->ext_seq, se.input_ctx.stats->ext_seq >> 16);
	return 0;
}
