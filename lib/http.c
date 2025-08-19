#include "http.h"
#include "log.h"
#include <assert.h>

CURL *http_create_req(const char *uri,
		size_t (*write_fn)(char *, size_t, size_t, void *),
		GString *download,
		size_t (*read_fn)(char *, size_t, size_t, void *),
		http_upload *upload,
		const struct curl_slist *headers,
		bool tls_verify,
		CURLcode *errcode,
		const char **errmsg)
{
	CURLcode ret = CURLE_FAILED_INIT;

	const char *err = "failed to create cURL object";
	g_autoptr(CURL) c = curl_easy_init();
	if (!c)
		goto fail;

	err = "setting CURLOPT_URL";
	if ((ret = curl_easy_setopt(c, CURLOPT_URL, uri)) != CURLE_OK)
		goto fail;

	err = "setting CURLOPT_WRITEFUNCTION";
	if ((ret = curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_fn)) != CURLE_OK)
		goto fail;

	err = "setting CURLOPT_WRITEDATA";
	if ((ret = curl_easy_setopt(c, CURLOPT_WRITEDATA, download)) != CURLE_OK)
		goto fail;

	err = "setting CURLOPT_READFUNCTION";
	if ((ret = curl_easy_setopt(c, CURLOPT_READFUNCTION, read_fn)) != CURLE_OK)
		goto fail;

	err = "setting CURLOPT_READDATA";
	if ((ret = curl_easy_setopt(c, CURLOPT_READDATA, upload)) != CURLE_OK)
		goto fail;

	/* allow redirects */
	err = "setting CURLOPT_FOLLOWLOCATION";
	if ((ret = curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L)) != CURLE_OK)
		goto fail;

	/* max 5 redirects */
	err = "setting CURLOPT_MAXREDIRS";
	if ((ret = curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L)) != CURLE_OK)
		goto fail;

	/* add headers */
	err = "setting CURLOPT_HTTPHEADER";
	if ((ret = curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers)) != CURLE_OK)
		goto fail;

	/* cert verify (enabled by default) */
	if (!tls_verify) {
		err = "setting CURLOPT_SSL_VERIFYPEER";
		if ((ret = curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L)) != CURLE_OK)
			goto fail;
	}

	// all ok
	*errmsg = NULL;
	*errcode = CURLE_OK;

	CURL *o = c;
	c = NULL; // prevent auto cleanup
	return o;

fail:
	*errmsg = err;
	*errcode = ret;
	return NULL;
}


void http_add_header(struct curl_slist **hdrs, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	char *s = g_strdup_vprintf(fmt, ap);
	*hdrs = curl_slist_append(*hdrs, s);
	g_free(s);
	va_end(ap);
}


size_t http_dummy_write(char *ptr, size_t size, size_t nmemb, void *userdata) {
	return size * nmemb;
}
size_t http_dummy_read(char *ptr, size_t size, size_t nmemb, void *userdata) {
	return 0;
}


size_t http_upload_read(char *ptr, size_t size, size_t nmemb, void *userdata) {
	http_upload *u = userdata;
	assert(size == 1); // as per docs
	size_t len = MIN(nmemb, u->s.len);
	memcpy(ptr, u->s.s, len);
	str_shift(&u->s, len);
	return len;
}

size_t http_download_write(char *ptr, size_t size, size_t nmemb, void *userdata) {
	assert(size == 1); // as per docs
	GString *s = userdata;
	g_string_append_len(s, ptr, nmemb);
	return nmemb;
}
