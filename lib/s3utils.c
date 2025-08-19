#include "s3utils.h"
#include "log.h"
#include <glib.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


static void sha256_digest(unsigned char output[SHA256_DIGEST_LENGTH],
		const char *input,
		size_t len)
{
	const EVP_MD *md = EVP_sha256(); // XXX cache this
	// XXX error checking
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, input, len);
	EVP_DigestFinal_ex(ctx, output, NULL);
	EVP_MD_CTX_free(ctx);
}


static void hex_print(char *output,
		const unsigned char *buf,
		size_t len)
{
	for (unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(output + i * 2, "%02x", buf[i]);
}


static void hex_append(GString *s,
		const unsigned char *buf,
		size_t len)
{
	size_t pos = s->len;
	g_string_set_size(s, s->len + len * 2);
	hex_print(s->str + pos, buf, len);
}


void sha256_digest_hex(char output[SHA256_DIGEST_LENGTH * 2 + 1],
		const char *input,
		size_t len)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	sha256_digest(digest, input, len); // XXX error check?
	hex_print(output, digest, SHA256_DIGEST_LENGTH);
}


static void sha256_digest_hex_append(GString *s,
		const char *input,
		size_t len)
{
	printf("sha len %zu\n", len);
	unsigned char digest[SHA256_DIGEST_LENGTH];
	sha256_digest(digest, input, len); // XXX error check?
	hex_append(s, digest, SHA256_DIGEST_LENGTH);
}


GString *s3_make_auth(const char *host,
		const char *path, const char *key,
		const char *region,
		const struct tm *now,
		const char *content_sha256_hex,
		const char *access_key,
		const char *secret_key)
{
	// use much larger buffers than necessary to make gcc happy
	char date[64];
	sprintf(date, "%04d%02d%02d",
			now->tm_year + 1900,
			now->tm_mon + 1,
			now->tm_mday);

	char time[64];
	sprintf(time, "%02d%02d%02d",
			now->tm_hour,
			now->tm_min,
			now->tm_sec);

	g_autoptr(GString) canon_req = g_string_new("PUT\n");
	g_string_append(canon_req, path);
	g_string_append(canon_req, key);
	g_string_append(canon_req, "\n");
	g_string_append(canon_req, "\n"); // empty query string

	// hard coded list of canonical headers
	g_string_append_printf(canon_req, "host:%s\n", host);
	g_string_append_printf(canon_req, "x-amz-content-sha256:%s\n", content_sha256_hex);
	g_string_append_printf(canon_req, "x-amz-date:%sT%sZ\n",
			date, time);

	g_string_append(canon_req, "\n");

	// signed headers
	g_string_append(canon_req, "host;x-amz-content-sha256;x-amz-date\n");

	g_string_append(canon_req, content_sha256_hex);


	g_autoptr(GString) string_to_sign = g_string_new("AWS4-HMAC-SHA256\n");
	g_string_append_printf(string_to_sign, "%sT%sZ\n",
			date, time);
	g_string_append_printf(string_to_sign, "%s/%s/s3/aws4_request\n",
			date, region);
	sha256_digest_hex_append(string_to_sign, canon_req->str, canon_req->len);


	unsigned char x1[SHA256_DIGEST_LENGTH];
	unsigned char x2[SHA256_DIGEST_LENGTH];
	unsigned char x3[SHA256_DIGEST_LENGTH];
	unsigned char x4[SHA256_DIGEST_LENGTH];
	unsigned char x5[SHA256_DIGEST_LENGTH];

	g_autoptr(GString) akey = g_string_new("AWS4");
	g_string_append(akey, secret_key);

	HMAC(EVP_sha256(), akey->str, akey->len,
			(unsigned char *) date, strlen(date), x1, NULL);
	HMAC(EVP_sha256(), x1, sizeof(x1),
			(unsigned char *) region, strlen(region), x2, NULL);
	HMAC(EVP_sha256(), x2, sizeof(x2),
			(unsigned char *) "s3", strlen("s3"), x3, NULL);
	HMAC(EVP_sha256(), x3, sizeof(x3),
			(unsigned char *) "aws4_request", strlen("aws4_request"), x4, NULL);
	HMAC(EVP_sha256(), x4, sizeof(x4),
			(unsigned char *) string_to_sign->str, string_to_sign->len, x5, NULL);

	GString *ret = g_string_new("AWS4-HMAC-SHA256 Credential=");
	g_string_append(ret, access_key);
	g_string_append_c(ret, '/');
	g_string_append(ret, date);
	g_string_append_c(ret, '/');
	g_string_append(ret, region);
	g_string_append(ret, "/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;"
			"x-amz-date,Signature=");
	hex_append(ret, x5, sizeof(x5));

	return ret;
}
