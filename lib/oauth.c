#include "oauth.h"
#include <glib.h>
#include <curl/curl.h>
#include <jwt.h>
#include <json-glib/json-glib.h>
#include "auxlib.h"
#include "http.h"


G_DEFINE_AUTOPTR_CLEANUP_FUNC(jwt_t, jwt_free)


// called during init
// returns g_strdup'd error
static char *oauth_service_account(oauth_context_t *ctx) {
	g_autoptr(JsonParser) parser = json_parser_new();
	g_autoptr(GError) error = NULL;
	json_parser_load_from_file(parser, ctx->service_account_file, &error);
	if (error)
		return g_strdup(error->message);

	const char *err;

	err = "Failed to get JSON root node";
	JsonNode *root = json_parser_get_root(parser);
	if (!root)
		goto err;
	err = "JSON root node is not an object";
	JsonObject *o = json_node_get_object(root);
	if (!o)
		goto err;


	err = "No 'client_email' in service account file";
	JsonNode *c = json_object_get_member(o, "client_email");
	if (!c)
		goto err;

	err = "JSON 'client_email' is not a string";
	const char *s = json_node_get_string(c);
	if (!s)
		goto err;
	ctx->_iss = g_strdup(s);


	err = "No 'token_uri' in service account file";
	c = json_object_get_member(o, "token_uri");
	if (!c)
		goto err;

	err = "JSON 'token_uri' is not a string";
	s = json_node_get_string(c);
	if (!s)
		goto err;
	ctx->_aud = g_strdup(s);


	err = "No 'private_key' in service account file";
	c = json_object_get_member(o, "private_key");
	if (!c)
		goto err;

	err = "JSON 'private_key' is not a string";
	s = json_node_get_string(c);
	if (!s)
		goto err;
	ctx->_private_key = g_strdup(s);


	err = "algorithm not supported by JWT library";
	ctx->_alg = jwt_str_alg(ctx->algorithm);
	if (ctx->_alg == JWT_ALG_INVAL)
		goto err;


	return NULL;

err:
	return g_strdup(err);
}


// lock is held
// returns g_strdup'd token
static char *oauth_set_token(oauth_context_t *ctx, const char *token, int64_t expires_in, time_t now) {
	g_clear_pointer(&ctx->_token, g_free);
	ctx->_token = g_strdup(token);
	ctx->_expires = now + expires_in;

	return g_strdup(token);
}


// lock is held
// returns g_strdup'd token
static char *oauth_decode_token(oauth_context_t *ctx, GString *json, time_t now, char **errp) {
	g_autoptr(JsonParser) parser = json_parser_new();
	g_autoptr(GError) error = NULL;
	json_parser_load_from_data(parser, json->str, json->len, &error);
	if (error) {
		*errp = g_strdup(error->message);
		return NULL;
	}

	const char *err;

	err = "Failed to get JSON root node";
	JsonNode *root = json_parser_get_root(parser);
	if (!root)
		goto err;
	err = "JSON root node is not an object";
	JsonObject *o = json_node_get_object(root);
	if (!o)
		goto err;


	err = "No 'access_token' in OAuth response";
	JsonNode *c = json_object_get_member(o, "access_token");
	if (!c)
		goto err;

	err = "JSON 'access_token' is not a string";
	const char *s = json_node_get_string(c);
	if (!s)
		goto err;


	err = "No 'expires_in' in OAuth response";
	c = json_object_get_member(o, "expires_in");
	if (!c)
		goto err;

	err = "JSON 'expires_in' is not valid";
	int64_t i = json_node_get_int(c);
	if (!i)
		goto err;


	return oauth_set_token(ctx, s, i, now);

err:
	*errp = g_strdup(err);
	return false;}


// lock is held
// returns g_strdup'd token
static char *oauth_request(oauth_context_t *ctx, const char *jwt, time_t now, char **errp) {
	g_autoptr(char) req = g_strdup_printf("{'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', "
			"'assertion': '%s'}", jwt);
	size_t req_len = strlen(req);

	struct curl_slist *headers = NULL;

	http_add_header(&headers, "Content-type: application/json");
	http_add_header(&headers, "Content-length: %zu", req_len);

	const char *err;
	CURLcode curl_code = CURLE_OK;
	g_autoptr(GString) resp = g_string_new("");
	err = "internal cURL error";
	CURL *c = http_create_req(ctx->_aud,
			http_download_write, resp,
			http_upload_read,
			&(http_upload) {.s = { .s = req, .len = req_len } },
			headers, true, &curl_code, &err);

	if (!c)
		goto err;

	// POST
	err = "setting CURLOPT_POST";
	if ((curl_code = curl_easy_setopt(c, CURLOPT_POST, 1L)) != CURLE_OK)
		goto err;

	err = "performing request";
	if ((curl_code = curl_easy_perform(c)) != CURLE_OK)
		goto err;

	long code;
	err = "getting CURLINFO_RESPONSE_CODE";
	if ((curl_code = curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code)) != CURLE_OK)
		goto err;

	err = "checking response code (not 2xx)";
	if (code < 200 || code >= 300) {
		*errp = g_strdup_printf("Request OAuth/JWT token failed with code %ld: %s%.*s%s",
				code, FMT_M((int) resp->len, resp->str));
		return NULL;
	}

	return oauth_decode_token(ctx, resp, now, errp);

err:
	*errp = g_strdup_printf("Failed to request OAuth token: %s / %s", err, curl_easy_strerror(curl_code));
	return NULL;
}


// lock is held
// returns g_strdup'd token
static char *oauth_request_token(oauth_context_t *ctx, time_t now, char **errp) {
	const char *err;

	err = "failed to create libjwt object";
	g_autoptr(jwt_t) jwt = NULL;
	int ret = jwt_new(&jwt);
	if (ret)
		goto err;

	err = "failed to add 'iss' grant";
	ret = jwt_add_grant(jwt, "iss", ctx->_iss);
	if (ret)
		goto err;

	err = "failed to add 'scope' grant";
	ret = jwt_add_grant(jwt, "scope", ctx->scope);
	if (ret)
		goto err;

	err = "failed to add 'aud' grant";
	ret = jwt_add_grant(jwt, "aud", ctx->_aud);
	if (ret)
		goto err;

	err = "failed to add 'iat' grant";
	ret = jwt_add_grant_int(jwt, "iat", now);
	if (ret)
		goto err;

	time_t expiry = now + 3600;
	err = "failed to add 'exp' grant";
	ret = jwt_add_grant_int(jwt, "exp", expiry);
	if (ret)
		goto err;

	err = "failed to set algorithm or key";
	ret = jwt_set_alg(jwt, ctx->_alg, (unsigned char *) ctx->_private_key, strlen(ctx->_private_key));
	if (ret)
		goto err;

	err = "failed encode JWT";
	char *j = jwt_encode_str(jwt);
	if (!j)
		goto err;

	char *token = oauth_request(ctx, j, now, errp);
	free(j);

	return token;

err:
	*errp = g_strdup(err);
	return NULL;
}


// returns g_strdup'd token
static char *oauth_get_token(oauth_context_t *ctx, char **errp) {
	time_t now = time(NULL);
	time_t cutoff = now - 10;

	LOCK(&ctx->_lock);

	if (ctx->_token && ctx->_expires > cutoff)
		return g_strdup(ctx->_token);

	return oauth_request_token(ctx, now, errp);
}


void oauth_add_auth(struct curl_slist **headers, oauth_context_t *ctx, char **errp) {
	g_autoptr(char) jwt = oauth_get_token(ctx, errp);
	if (!jwt)
		return;

	http_add_header(headers, "Authorization: Bearer %s", jwt);
}


char *oauth_init(oauth_context_t *ctx) {
	mutex_init(&ctx->_lock);
	return oauth_service_account(ctx);
}


void oauth_cleanup(oauth_context_t *ctx) {
	g_clear_pointer(&ctx->_aud, g_free);
	g_clear_pointer(&ctx->_iss, g_free);
	g_clear_pointer(&ctx->_private_key, g_free);
	g_clear_pointer(&ctx->_token, g_free);
	mutex_destroy(&ctx->_lock);
}
