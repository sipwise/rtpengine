#include "notify.h"
#include <stdbool.h>
#include <curl/curl.h>
#include "main.h"
#include "log.h"
#include "recaux.h"
#include "output.h"


struct notif_req {
	char *name; // just for logging
	struct curl_slist *headers; // NULL = nothing to send
	char *full_filename_path;
	GString *content;
	unsigned long long db_id;

	char **argv;

	int64_t retry_time;
	unsigned int retries;
	int64_t falloff_us;
};


static GThreadPool *notify_threadpool;

static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_t notify_waiter;
static GTree *notify_timers;


static size_t dummy_write(char *ptr, size_t size, size_t nmemb, void *userdata) {
	return size * nmemb;
}
static size_t dummy_read(char *ptr, size_t size, size_t nmemb, void *userdata) {
	return 0;
}

static bool do_notify_http(struct notif_req *req) {
	if (!req->headers)
		return true;

	const char *err = NULL;
	CURLcode ret;
	bool success = false;

	ilog(LOG_DEBUG, "Launching HTTP notification for '%s%s%s'", FMT_M(req->name));

	/* set up the CURL request */

#if CURL_AT_LEAST_VERSION(7,56,0)
	curl_mime *mime = NULL;
#endif
	CURL *c = curl_easy_init();
	if (!c)
		goto fail;

	err = "setting CURLOPT_URL";
	if ((ret = curl_easy_setopt(c, CURLOPT_URL, notify_uri)) != CURLE_OK)
		goto fail;

	/* no output */
	err = "setting CURLOPT_WRITEFUNCTION";
	if ((ret = curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, dummy_write)) != CURLE_OK)
		goto fail;

	/* no input */
	err = "setting CURLOPT_READFUNCTION";
	if ((ret = curl_easy_setopt(c, CURLOPT_READFUNCTION, dummy_read)) != CURLE_OK)
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
	if ((ret = curl_easy_setopt(c, CURLOPT_HTTPHEADER, req->headers)) != CURLE_OK)
		goto fail;

	/* POST vs GET */
	if (notify_post) {
		err = "setting CURLOPT_POST";
		if ((ret = curl_easy_setopt(c, CURLOPT_POST, 1L)) != CURLE_OK)
			goto fail;
	}

	/* cert verify (enabled by default) */
	if (notify_nverify) {
		err = "setting CURLOPT_SSL_VERIFYPEER";
		if ((ret = curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L)) != CURLE_OK)
			goto fail;
	}

#if CURL_AT_LEAST_VERSION(7,56,0)
	if (req->content) {
		err = "initializing curl mime&part";
		curl_mimepart *part;
		mime = curl_mime_init(c);
		part = curl_mime_addpart(mime);

		if ((ret = curl_mime_name(part, "ngfile")) != CURLE_OK)
			goto fail;

		if ((ret = curl_mime_data(part, req->content->str, req->content->len)) != CURLE_OK)
			goto fail;

		if ((ret = curl_easy_setopt(c, CURLOPT_MIMEPOST, mime)) != CURLE_OK)
			goto fail;
	}
#endif

	err = "performing request";
	if ((ret = curl_easy_perform(c)) != CURLE_OK)
		goto fail;

	long code;
	err = "getting CURLINFO_RESPONSE_CODE";
	if ((ret = curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code)) != CURLE_OK)
		goto fail;

	err = "checking response code (not 2xx)";
	if (code < 200 || code >= 300)
		goto fail;

	/* success */

	success = true;

	ilog(LOG_NOTICE, "HTTP notification for '%s%s%s' was successful", FMT_M(req->name));

	curl_slist_free_all(req->headers);
	req->headers = NULL;

	goto cleanup;

fail:
	if (c)
		ilog(LOG_ERR, "Failed to perform HTTP notification for '%s%s%s': "
				"Error while %s: %s",
				FMT_M(req->name),
				err, curl_easy_strerror(ret));
	else
		ilog(LOG_ERR, "Failed to perform HTTP notification for '%s%s%s': "
				"Failed to create CURL object",
				FMT_M(req->name));

cleanup:
	if (c)
		curl_easy_cleanup(c);

#if CURL_AT_LEAST_VERSION(7,56,0)
	if (mime)
		curl_mime_free(mime);
#endif

	return success;
}

static bool do_notify_command(struct notif_req *req) {
	if (!req->argv)
		return true;

	ilog(LOG_DEBUG, "Executing notification command for '%s%s%s'", FMT_M(req->name));

	GError *err = NULL;
	bool success = g_spawn_sync(NULL, req->argv, NULL,
			G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
			NULL, NULL, NULL, NULL, NULL, &err);

	if (success) {
		g_strfreev(req->argv);
		req->argv = NULL;
	}
	else {
		ilog(LOG_ERR, "Failed to execute notification command for '%s%s%s': %s",
			FMT_M(req->name), err->message);
		g_error_free(err);
	}

	return success;
}

static void do_notify(void *p, void *u) {
	struct notif_req *req = p;

	unsigned int fails = 0;

	fails += do_notify_http(req) == false;
	fails += do_notify_command(req) == false;

	if (fails) {
		if (notify_retries >= 0 && req->retries < notify_retries) {
			/* schedule retry */
			req->retries++;

			ilog(LOG_INFO, "Failure while sending notification for '%s%s%s': "
					"Will retry in %" PRId64 " seconds (#%u)",
					FMT_M(req->name),
					req->falloff_us / 1000000L, req->retries);

			req->retry_time = now_us() + req->falloff_us;
			req->falloff_us *= 2;

			pthread_mutex_lock(&timer_lock);
			g_tree_insert(notify_timers, req, req);
			pthread_cond_signal(&timer_cond);
			pthread_mutex_unlock(&timer_lock);

			return; // skip cleanup
		}

		ilog(LOG_ERR, "Failure while sending notification for '%s%s%s' after %u retries. "
				"Giving up",
				FMT_M(req->name),
				req->retries);
	}

	curl_slist_free_all(req->headers);
	g_strfreev(req->argv);
	g_free(req->name);
	g_free(req->full_filename_path);
	if (req->content)
		g_string_free(req->content, TRUE);
	g_free(req);
}


static void *notify_timer(void *p) {
	pthread_mutex_lock(&timer_lock);

	// notify_timers being NULL acts as our shutdown flag
	while (notify_timers) {
		ilog(LOG_DEBUG, "Notification timer thread looping");

		// grab first entry in list, check retry time, sleep if it's in the future

		struct notif_req *first = rtpe_g_tree_first(notify_timers);
		if (!first) {
			ilog(LOG_DEBUG, "No scheduled notification retries, sleeping");
			pthread_cond_wait(&timer_cond, &timer_lock);
			continue;
		}
		int64_t now = now_us();
		if (now < first->retry_time) {
			ilog(LOG_DEBUG, "Sleeping until next scheduled notification retry in %" PRId64 " seconds",
					(first->retry_time - now) / 1000000L);
			cond_timedwait(&timer_cond, &timer_lock, first->retry_time);
			continue;
		}

		// first entry is ready to run

		g_tree_remove(notify_timers, first);
		ilog(LOG_DEBUG, "Notification retry for '%s%s%s' is scheduled now", FMT_M(first->name));
		g_thread_pool_push(notify_threadpool, first, NULL);
	}

	// clean up

	pthread_mutex_unlock(&timer_lock);
	pthread_mutex_destroy(&timer_lock);
	pthread_cond_destroy(&timer_cond);

	return NULL;
}


static int notify_req_cmp(const void *A, const void *B) {
	const struct notif_req *a = A, *b = B;

	if (a->retry_time < b->retry_time)
		return -1;
	if (a->retry_time > b->retry_time)
		return 1;
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}


void notify_setup(void) {
	if ((!notify_uri && !notify_command) || notify_threads <= 0)
		return;

	notify_threadpool = g_thread_pool_new(do_notify, NULL, notify_threads, false, NULL);

	notify_timers = g_tree_new(notify_req_cmp);
	int ret = pthread_create(&notify_waiter, NULL, notify_timer, NULL);
	if (ret)
		ilog(LOG_ERR, "Failed to launch thread for HTTP notification");
}

void notify_cleanup(void) {
	if (notify_waiter && notify_timers) {
		// get lock, free GTree, signal thread to shut down
		pthread_mutex_lock(&timer_lock);
		g_tree_destroy(notify_timers);
		notify_timers = NULL;
		pthread_cond_signal(&timer_cond);
		pthread_mutex_unlock(&timer_lock);
	}
	if (notify_threadpool)
		g_thread_pool_free(notify_threadpool, true, false);
	notify_threadpool = NULL;
}

__attribute__ ((format (printf, 2, 3)))
static void notify_add_header(struct notif_req *req, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	char *s = g_strdup_vprintf(fmt, ap);
	req->headers = curl_slist_append(req->headers, s);
	g_free(s);
	va_end(ap);
}

static void notify_req_setup_http(struct notif_req *req, output_t *o, metafile_t *mf, tag_t *tag) {
	if (!notify_uri)
		return;

	double now = (double) now_us() / 1000000.;

	notify_add_header(req, "X-Recording-Call-ID: %s", mf->call_id);
	notify_add_header(req, "X-Recording-File-Name: %s.%s", o->file_name, o->file_format);
	notify_add_header(req, "X-Recording-Full-File-Name: %s.%s", o->full_filename, o->file_format);
	notify_add_header(req, "X-Recording-File-Format: %s", o->file_format);
	notify_add_header(req, "X-Recording-Kind: %s", o->kind);
	notify_add_header(req, "X-Recording-Call-Start-Time: %.06f", (double) mf->start_time_us / 1000000.);
	notify_add_header(req, "X-Recording-Stream-Start-Time: %.06f", (double) o->start_time_us / 1000000.);
	notify_add_header(req, "X-Recording-Call-End-Time: %.06f", now);
	notify_add_header(req, "X-Recording-Stream-End-Time: %.06f", now);

	if (mf->db_id)
		notify_add_header(req, "X-Recording-Call-DB-ID: %llu", mf->db_id);
	if (o->db_id)
		notify_add_header(req, "X-Recording-Stream-DB-ID: %llu", o->db_id);
	if (mf->metadata)
		notify_add_header(req, "X-Recording-Call-Metadata: %s", mf->metadata);
	if (mf->metadata)
		notify_add_header(req, "X-Recording-DB-Metadata: %s", mf->metadata);

	if (tag) {
		notify_add_header(req, "X-Recording-Tag: %s", tag->name);
		if (tag->label)
			notify_add_header(req, "X-Recording-Label: %s", tag->label);
		if (tag->metadata)
			notify_add_header(req, "X-Recording-Tag-Metadata: %s", tag->metadata);
	}

}

static void notify_req_setup_command(struct notif_req *req, output_t *o, metafile_t *mf, tag_t *tag) {
	if (!notify_command)
		return;

	req->argv = g_new(char *, 4);
	req->argv[0] = g_strdup(notify_command);
	req->argv[1] = g_strdup(req->full_filename_path ?: "");
	req->argv[2] = g_strdup_printf("%llu", req->db_id);
	req->argv[3] = NULL;
}

void notify_push_output(output_t *o, metafile_t *mf, tag_t *tag) {
	if (!notify_threadpool)
		return;

	struct notif_req *req = g_new0(__typeof(*req), 1);

	req->name = g_strdup(o->file_name);
	if ((output_storage & OUTPUT_STORAGE_FILE))
		req->full_filename_path = g_strdup_printf("%s.%s", o->full_filename, o->file_format);
	if ((output_storage & OUTPUT_STORAGE_NOTIFY)) {
		req->content = output_get_content(o);
		o->content = NULL; // take over ownership
	}
	req->db_id = o->db_id;

	notify_req_setup_http(req, o, mf, tag);
	notify_req_setup_command(req, o, mf, tag);

	req->falloff_us = 5000000LL; // initial retry time

	g_thread_pool_push(notify_threadpool, req, NULL);
}
