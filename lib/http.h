#ifndef _HTTP_H_
#define _HTTP_H_

#include "str.h"
#include <curl/curl.h>
#include <stdbool.h>
#include <glib.h>


typedef struct {
	str s;
} http_upload;

CURL *http_create_req(const char *uri,
		size_t (*write_fn)(char *, size_t, size_t, void *),
		GString *,
		size_t (*read_fn)(char *, size_t, size_t, void *),
		http_upload *,
		const struct curl_slist *headers,
		bool tls_verify,
		CURLcode *errcode,
		const char **errmsg);


__attribute__ ((format (printf, 2, 3)))
void http_add_header(struct curl_slist **, const char *fmt, ...);

size_t http_dummy_write(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t http_dummy_read(char *ptr, size_t size, size_t nmemb, void *userdata);

size_t http_download_write(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t http_upload_read(char *ptr, size_t size, size_t nmemb, void *userdata);


G_DEFINE_AUTOPTR_CLEANUP_FUNC(CURL, curl_easy_cleanup)
#if CURL_AT_LEAST_VERSION(7,56,0)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(curl_mime, curl_mime_free)
#endif


#endif
