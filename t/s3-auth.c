#include <glib.h>
#include <assert.h>
#include <stdio.h>
#include "s3utils.h"

int main(void) {
	// date from S3 example
	struct tm now = {
		.tm_year = 113, // 2013
		.tm_mon = 4, // May
		.tm_mday = 24,
		.tm_hour = 0,
		.tm_min = 0,
		.tm_sec = 0,
		.tm_gmtoff = 0,
	};

	// empty body
	char digest[SHA256_DIGEST_LENGTH * 2 + 1];
	sha256_digest_hex(digest, "", 0);

	assert(strcmp(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);

	// S3 example auth
	g_autoptr(GString) s = s3_make_auth("examplebucket.s3.amazonaws.com",
			"/", "test.txt", "us-east-1", &now,
			digest, "AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

	// S3 example result, minus the "range" header and with PUT
	printf("calculated auth string:\n%s\n", s->str);

	assert(strcmp(s->str, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/"
				"s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;"
				"x-amz-date,Signature="
				"ea04dce2c5225534613582aa88f3fa9164370b73f396ad0e8cfeda0e9ef6669e") == 0);

	printf("auth matches\n");

	return 0;
}
