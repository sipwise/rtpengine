#ifndef _CRYPTO_H_
#define _CRYPTO_H_



#include "str.h"



/* XXX get rid of the enums and replace with struct pointers? */
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

struct crypto_suite {
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




extern const struct crypto_suite crypto_suites[];
extern const int num_crypto_suites;



const struct crypto_suite *crypto_find_suite(const str *);



#endif
