#ifndef _CRYPTO_H_
#define _CRYPTO_H_



#include <sys/types.h>
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
		session_key_len,	/* n_e */
		session_salt_len,	/* n_s */
		encryption_key,
		srtp_auth_tag,		/* n_a */
		srtcp_auth_tag,
		srtp_auth_key_len,	/* n_a */
		srtcp_auth_key_len;
	unsigned long long int
		srtp_lifetime,
		srtcp_lifetime;
	enum cipher cipher;
	enum mac mac;
};

struct crypto_context {
	const struct crypto_suite *crypto_suite;
	/* we only support one master key for now */
	char master_key[16];
	char master_salt[14];
	u_int64_t mki;
	unsigned int mki_len;

	/* from rfc 3711 */
	u_int32_t roc;
	u_int16_t s_l;
	/* XXX replay list */
	u_int64_t num_packets;
	/* <from, to>? */

	char session_key[16];
	char session_salt[14];
	char session_auth_key[20];

	int have_session_key:1;
};




extern const struct crypto_suite crypto_suites[];
extern const int num_crypto_suites;



const struct crypto_suite *crypto_find_suite(const str *);
int crypto_gen_session_key(struct crypto_context *, str *, unsigned char);



#endif
