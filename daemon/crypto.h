#ifndef _CRYPTO_H_
#define _CRYPTO_H_



#include "str.h"



/* XXX get rid of the enums and replace with struct pointers? */
enum crypto_suite {
	CS_UNKNOWN = 0,
	CS_AES_CM_128_HMAC_SHA1_80,
	CS_AES_CM_128_HMAC_SHA1_32,
	CS_F8_128_HMAC_SHA1_80,

	__CS_LAST
};

enum cipher {
	CIPHER_UNKNOWN = 0,
	CIPHER_AES_CM,
	CIPHER_AES_F8,

	__CIPHER_LAST
};

enum mac {
	MAC_UNKNOWN = 0,
	MAC_HMAC_SHA1,

	__MAC_LAST
};

struct crypto_suite_params {
	const char *name;
	unsigned int
		master_key_len,
		master_salt_len,
		encryption_key,
		srtp_auth_tag,
		srtcp_auth_tag,
		srtp_auth_key_len,
		srtcp_auth_key_len;
	unsigned long long int
		srtp_lifetime,
		srtcp_lifetime;
	enum cipher cipher;
	enum mac mac;
};




extern const struct crypto_suite_params crypto_suite_params[__CS_LAST];



enum crypto_suite crypto_find_suite(const str *);



#endif
