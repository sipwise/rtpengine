#include "crypto.h"

#include <string.h>

#include "str.h"
#include "aux.h"



/* all lengths are in bits, some code assumes everything to be multiples of 8 */
const struct crypto_suite crypto_suites[] = {
	{
		.name			= "AES_CM_128_HMAC_SHA1_80",
		.master_key_len		= 128,
		.master_salt_len	= 112,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.cipher			= CIPHER_AES_CM,
		.encryption_key		= 128,
		.mac			= MAC_HMAC_SHA1,
		.srtp_auth_tag		= 80,
		.srtcp_auth_tag		= 80,
		.srtp_auth_key_len	= 160,
		.srtcp_auth_key_len	= 160,
	},
	{
		.name			= "AES_CM_128_HMAC_SHA1_32",
		.master_key_len		= 128,
		.master_salt_len	= 112,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.cipher			= CIPHER_AES_CM,
		.encryption_key		= 128,
		.mac			= MAC_HMAC_SHA1,
		.srtp_auth_tag		= 32,
		.srtcp_auth_tag		= 80,
		.srtp_auth_key_len	= 160,
		.srtcp_auth_key_len	= 160,
	},
	{
		.name			= "F8_128_HMAC_SHA1_80",
		.master_key_len		= 128,
		.master_salt_len	= 112,
		.srtp_lifetime		= 1ULL << 48,
		.srtcp_lifetime		= 1ULL << 31,
		.cipher			= CIPHER_AES_F8,
		.encryption_key		= 128,
		.mac			= MAC_HMAC_SHA1,
		.srtp_auth_tag		= 80,
		.srtcp_auth_tag		= 80,
		.srtp_auth_key_len	= 160,
		.srtcp_auth_key_len	= 160,
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
