#include "gcs.h"
#include "notify.h"
#include "main.h"
#include "output.h"
#include "http.h"
#include "oauth.h"


static oauth_context_t auth_ctx;


static void gcs_setup(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
	req->object_name = g_strdup_printf("%s.%s", o->file_name, o->file_format);
	req->content = output_get_content(o);
}


static void gcs_failed(notif_req_t *req) {
	if (req->content)
		output_content_failure(req->content);
}


static void gcs_cleanup(notif_req_t *req) {
	obj_release(req->content);
	g_free(req->object_name);
}


static bool gcs_perform(notif_req_t *req) {
	if (!req->content) {
		ilog(LOG_ERR, "Content for GCS upload unavailable ('%s%s%s')", FMT_M(req->name));
		return true; // no point in retrying
	}

	ilog(LOG_DEBUG, "Launching GCS upload for '%s%s%s' as '%s'", FMT_M(req->name),
			req->object_name);

	const char *err = NULL;
	CURLcode ret;

	struct curl_slist *headers = NULL;

	if (gcs_service_account && gcs_service_account[0]) {
		g_autoptr(char) jwt_err = NULL;
		oauth_add_auth(&headers, &auth_ctx, &jwt_err);
		if (jwt_err) {
			ilog(LOG_ERR, "Failed to obtain OAuth/JWT token: %s", jwt_err);
			return false;
		}
	}

	http_add_header(&headers, "Content-length: %zu", req->content->s->len);
	http_add_header(&headers, "Content-type: application/data");

	g_autoptr(GString) response = g_string_new("");

	g_autoptr(char) uri;

	if (gcs_key && gcs_key[0])
		uri = g_strdup_printf("%s?name=%s&uploadType=media&key=%s",
				gcs_uri, req->object_name, gcs_key);
	else
		uri = g_strdup_printf("%s?name=%s&uploadType=media",
				gcs_uri, req->object_name);

	g_autoptr(CURL) c = http_create_req(uri,
			http_download_write,
			response,
			http_upload_read,
			&(http_upload) {.s = STR_GS(req->content->s) },
			headers, !gcs_nverify, &ret, &err);
	if (!c)
		goto err;


	// POST
	err = "setting CURLOPT_POST";
	if ((ret = curl_easy_setopt(c, CURLOPT_POST, 1L)) != CURLE_OK)
		goto err;

	err = "performing request";
	if ((ret = curl_easy_perform(c)) != CURLE_OK)
		goto err;

	long code;
	err = "getting CURLINFO_RESPONSE_CODE";
	if ((ret = curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code)) != CURLE_OK)
		goto err;

	err = "checking response code (not 2xx)";
	if (code < 200 || code >= 300) {
		ilog(LOG_ERR, "GCS upload returned code %ld, with body: '%s%.*s%s'",
				code, FMT_M((int) response->len, response->str));
		goto err;
	}

	ilog(LOG_DEBUG, "GCS upload for '%s%s%s' successful", FMT_M(req->name));

	return true;

err:
	ilog(LOG_ERR, "Failed to perform GCS upload for '%s%s%s': "
			"Error while %s: %s",
			FMT_M(req->name),
			err, curl_easy_strerror(ret));

	curl_slist_free_all(headers);

	return false;
}


static const notif_action_t action = {
	.name = "GCS",
	.setup = gcs_setup,
	.perform = gcs_perform,
	.failed = gcs_failed,
	.cleanup = gcs_cleanup,
};


void gcs_store(output_t *o, metafile_t *mf) {
	if ((output_storage & OUTPUT_STORAGE_GCS))
		notify_push_setup(&action, o, mf, NULL);
}


bool gcs_init(void) {
	if (!(output_storage & OUTPUT_STORAGE_GCS))
		return true;

	if (gcs_service_account && gcs_service_account[0]) {
		if (gcs_key && gcs_key[0]) {
			ilog(LOG_ERR, "Both GCS service account file and API key are configured");
			return false;
		}

		auth_ctx = (oauth_context_t) {
			.service_account_file = gcs_service_account,
			.scope = gcs_scope,
			.algorithm = "RS256",
		};

		g_autoptr(char) err = oauth_init(&auth_ctx);
		if (err) {
			ilog(LOG_ERR, "Failed to initialise OAuth/JWT context: %s", err);
			return false;
		}
	}
	else if (!gcs_key || !gcs_key[0]) {
		ilog(LOG_ERR, "No GCS service account file and no API key configured");
		return false;
	}

	return true;
}


void gcs_shutdown(void) {
	oauth_cleanup(&auth_ctx);
}
