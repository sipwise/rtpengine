#ifndef _OAUTH_H_
#define _OAUTH_H_

#include <jwt.h>
#include <stdbool.h>
#include <curl/curl.h>
#include "auxlib.h"


typedef struct {
	const char *service_account_file;
	const char *scope; // https://www.googleapis.com/auth/cloud-platform
	const char *algorithm; // RS256

	// fields below here get filled in and are private,
	// but must be initialised to zero

	jwt_alg_t _alg;
	char *_iss; // client_email
	char *_aud; // token_uri
	char *_private_key; // PEM

	mutex_t _lock;
	char *_token;
	time_t _expires;
} oauth_context_t;


char *oauth_init(oauth_context_t *);
void oauth_cleanup(oauth_context_t *);

void oauth_add_auth(struct curl_slist **headers, oauth_context_t *ctx, char **errp);


#endif
