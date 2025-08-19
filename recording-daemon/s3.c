#include "s3.h"
#include "output.h"
#include "main.h"
#include "notify.h"
#include "http.h"
#include "s3utils.h"


static void s3_setup(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
	req->object_name = g_strdup_printf("%s.%s", o->file_name, o->file_format);
	req->content = output_get_content(o);
}


static bool s3_perform(notif_req_t *req) {
	const char *err = NULL;
	CURLcode ret;

	if (!req->content) {
		ilog(LOG_ERR, "Content for S3 upload unavailable ('%s%s%s')", FMT_M(req->name));
		return true; // no point in retrying
	}

	if (!req->content_sha256) {
		// do this here, in a separate thread
		req->content_sha256 = g_string_sized_new(SHA256_DIGEST_LENGTH * 2 + 1);
		g_string_set_size(req->content_sha256, SHA256_DIGEST_LENGTH * 2);
		sha256_digest_hex(req->content_sha256->str,
				req->content->s->str, req->content->s->len);
	}

	ilog(LOG_DEBUG, "Launching S3 upload for '%s%s%s' as '%s'", FMT_M(req->name),
			req->object_name);

	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);

	g_autoptr(GString) auth = s3_make_auth(s3_host, s3_path, req->object_name,
			s3_region, &tm, req->content_sha256->str,
			s3_access_key, s3_secret_key);

	if (!auth) {
		ilog(LOG_ERR, "Failed to create S3 authentication string "
				"for '%s%s%s'", FMT_M(req->name));
		return false;
	}

	// build headers
	struct curl_slist *headers = NULL;

	// hard coded S3 header list, must match s3_make_auth()
	http_add_header(&headers, "x-amz-content-sha256: %s", req->content_sha256->str);
	http_add_header(&headers, "x-amz-date: %04d%02d%02dT%02d%02d%02dZ",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec);

	http_add_header(&headers, "Authorization: %s", auth->str);

	http_add_header(&headers, "Content-length: %zu", req->content->s->len);
	http_add_header(&headers, "Content-type: application/data");

	g_autoptr(char) uri = NULL;

	if (s3_port)
		uri = g_strdup_printf("https://%s:%d%s%s",
			s3_host,
			s3_port,
			s3_path,
			req->object_name);
	else
		uri = g_strdup_printf("https://%s%s%s",
			s3_host,
			s3_path,
			req->object_name);

	g_autoptr(GString) response = g_string_new("");

	g_autoptr(CURL) c = http_create_req(uri,
			http_download_write,
			response,
			http_upload_read,
			&(http_upload) {.s = STR_GS(req->content->s) },
			headers, !s3_nverify, &ret, &err);
	if (!c)
		goto fail;

	// PUT
	err = "setting CURLOPT_UPLOAD";
	if ((ret = curl_easy_setopt(c, CURLOPT_UPLOAD, 1L)) != CURLE_OK)
		goto fail;

	err = "setting CURLOPT_INFILESIZE_LARGE";
	if ((ret = curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE,
					(curl_off_t) req->content->s->len)) != CURLE_OK)
		goto fail;


	err = "performing request";
	if ((ret = curl_easy_perform(c)) != CURLE_OK)
		goto fail;

	long code;
	err = "getting CURLINFO_RESPONSE_CODE";
	if ((ret = curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code)) != CURLE_OK)
		goto fail;

	err = "checking response code (not 2xx)";
	if (code < 200 || code >= 300) {
		ilog(LOG_ERR, "S3 upload returned code %ld, with body: '%s%.*s%s'",
				code, FMT_M((int) response->len, response->str));
		goto fail;
	}

	ilog(LOG_DEBUG, "S3 upload for '%s%s%s' successful", FMT_M(req->name));

	curl_slist_free_all(headers);

	return true;

fail:
	ilog(LOG_ERR, "Failed to perform S3 upload for '%s%s%s': "
			"Error while %s: %s",
			FMT_M(req->name),
			err, curl_easy_strerror(ret));

	curl_slist_free_all(headers);

	return false;
}


static void s3_failed(notif_req_t *req) {
	if (req->content)
		output_content_failure(req->content);
}


static void s3_cleanup(notif_req_t *req) {
	obj_release(req->content);
	if (req->content_sha256)
		g_string_free(req->content_sha256, TRUE);
	g_free(req->object_name);
}


static const notif_action_t action = {
	.name = "S3",
	.setup = s3_setup,
	.perform = s3_perform,
	.failed = s3_failed,
	.cleanup = s3_cleanup,
};


void s3_store(output_t *o, metafile_t *mf) {
	if ((output_storage & OUTPUT_STORAGE_S3))
		notify_push_setup(&action, o, mf, NULL);
}
