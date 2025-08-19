#ifndef _S3UTILS_H_
#define _S3UTILS_H_

#include <glib.h>
#include <time.h>
#include <openssl/sha.h>


GString *s3_make_auth(const char *host,
		const char *path, const char *key,
		const char *region,
		const struct tm *now,
		const char *content_sha256_hex,
		const char *access_key,
		const char *secret_key);

void sha256_digest_hex(char output[SHA256_DIGEST_LENGTH * 2 + 1],
		const char *input,
		size_t len);


#endif
