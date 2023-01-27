#include "notify.h"
#include <stdbool.h>
#include <curl/curl.h>
#include "main.h"
#include "log.h"
#include "recaux.h"


struct notif_req {
	char *name; // just for logging
	struct curl_slist *headers;

	time_t retry_time;
	unsigned int retries;
	unsigned int falloff;
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

static void do_notify(void *p, void *u) {
	struct notif_req *req = p;
	const char *err = NULL;
	CURLcode ret;

	ilog(LOG_DEBUG, "Launching HTTP notification for '%s%s%s'", FMT_M(req->name));

	// set up the CURL request

	CURL *c = curl_easy_init();
	if (!c)
		goto fail;

	err = "setting CURLOPT_URL";
	ret = curl_easy_setopt(c, CURLOPT_URL, notify_uri);
	if (ret != CURLE_OK)
		goto fail;

	// no output
	err = "setting CURLOPT_WRITEFUNCTION";
	ret = curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, dummy_write);
	if (ret != CURLE_OK)
		goto fail;

	// no input
	err = "setting CURLOPT_READFUNCTION";
	ret = curl_easy_setopt(c, CURLOPT_READFUNCTION, dummy_read);
	if (ret != CURLE_OK)
		goto fail;

	// allow redirects
	err = "setting CURLOPT_FOLLOWLOCATION";
	ret = curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1);
	if (ret != CURLE_OK)
		goto fail;

	// max 5 redirects
	err = "setting CURLOPT_MAXREDIRS";
	ret = curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5);
	if (ret != CURLE_OK)
		goto fail;

	// add headers
	err = "setting CURLOPT_HTTPHEADER";
	ret = curl_easy_setopt(c, CURLOPT_HTTPHEADER, req->headers);
	if (ret != CURLE_OK)
		goto fail;

	// POST vs GET
	if (notify_post) {
		err = "setting CURLOPT_POST";
		ret = curl_easy_setopt(c, CURLOPT_POST, 1);
		if (ret != CURLE_OK)
			goto fail;
	}

	// cert verify (enabled by default)
	if (notify_nverify) {
		err = "setting CURLOPT_SSL_VERIFYPEER";
		ret = curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0);
		if (ret != CURLE_OK)
			goto fail;
	}

	err = "performing request";
	ret = curl_easy_perform(c);
	if (ret != CURLE_OK)
		goto fail;

	long code;
	err = "getting CURLINFO_RESPONSE_CODE";
	ret = curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
	if (ret != CURLE_OK)
		goto fail;

	err = "checking response code (not 2xx)";
	if (code < 200 || code >= 300)
		goto fail;

	// success

	ilog(LOG_NOTICE, "HTTP notification for '%s%s%s' was successful", FMT_M(req->name));
	goto cleanup;

fail:
	if (c)
		curl_easy_cleanup(c);

	if (notify_retries >= 0 && req->retries < notify_retries) {
		// schedule retry
		req->retries++;
		if (c)
			ilog(LOG_DEBUG, "Failed to perform HTTP notification for '%s%s%s': "
					"Error while %s: %s. Will retry in %u seconds (#%u)",
					FMT_M(req->name),
					err, curl_easy_strerror(ret),
					req->falloff, req->retries);
		else
			ilog(LOG_DEBUG, "Failed to perform HTTP notification for '%s%s%s': "
					"Failed to create CURL object. Will retry in %u seconds (#%u)",
					FMT_M(req->name),
					req->falloff, req->retries);
		req->retry_time = time(NULL) + req->falloff;
		req->falloff *= 2;

		pthread_mutex_lock(&timer_lock);
		g_tree_insert(notify_timers, req, req);
		pthread_cond_signal(&timer_cond);
		pthread_mutex_unlock(&timer_lock);

		return;
	}

	if (c)
		ilog(LOG_ERR, "Failed to perform HTTP notification for '%s%s%s' after %u retries: "
				"Error while %s: %s",
				FMT_M(req->name),
				req->retries, err, curl_easy_strerror(ret));
	else
		ilog(LOG_ERR, "Failed to perform HTTP notification for '%s%s%s' after %u retries: "
				"Failed to create CURL object",
				FMT_M(req->name),
				req->retries);

	c = NULL;
	goto cleanup;

cleanup:
	if (c)
		curl_easy_cleanup(c);
	curl_slist_free_all(req->headers);
	g_free(req->name);
	g_slice_free1(sizeof(*req), req);
}


static void *notify_timer(void *p) {
	pthread_mutex_lock(&timer_lock);

	// notify_timers being NULL acts as our shutdown flag
	while (notify_timers) {
		ilog(LOG_DEBUG, "HTTP notification timer thread looping");

		// grab first entry in list, check retry time, sleep if it's in the future

		struct notif_req *first = g_tree_find_first(notify_timers, NULL, NULL);
		if (!first) {
			ilog(LOG_DEBUG, "No scheduled HTTP notification retries, sleeping");
			pthread_cond_wait(&timer_cond, &timer_lock);
			continue;
		}
		struct timeval now;
		gettimeofday(&now, NULL);
		if (now.tv_sec < first->retry_time) {
			ilog(LOG_DEBUG, "Sleeping until next scheduled HTTP notification retry in %lu seconds",
					(unsigned long) first->retry_time - now.tv_sec);
			struct timespec ts = {.tv_sec = first->retry_time, .tv_nsec = 0};
			pthread_cond_timedwait(&timer_cond, &timer_lock, &ts);
			continue;
		}

		// first entry is ready to run

		g_tree_remove(notify_timers, first);
		ilog(LOG_DEBUG, "HTTP notification retry for '%s%s%s' is scheduled now", FMT_M(first->name));
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
	if (!notify_uri || notify_threads <= 0)
		return;

	notify_threadpool = g_thread_pool_new(do_notify, NULL, notify_threads, false, NULL);

	notify_timers = g_tree_new(notify_req_cmp);
	pthread_create(&notify_waiter, NULL, notify_timer, NULL);
}

void notify_cleanup(void) {
	if (notify_threadpool)
		g_thread_pool_free(notify_threadpool, true, false);
	if (notify_waiter && notify_timers) {
		// get lock, free GTree, signal thread to shut down
		pthread_mutex_lock(&timer_lock);
		g_tree_destroy(notify_timers);
		notify_timers = NULL;
		pthread_cond_signal(&timer_cond);
		pthread_mutex_unlock(&timer_lock);
	}
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

void notify_push_output(output_t *o, metafile_t *mf, tag_t *tag) {
	if (!notify_threadpool)
		return;

	struct notif_req *req = g_slice_alloc0(sizeof(*req));

	req->name = g_strdup(o->file_name);
	double now = now_double();

	notify_add_header(req, "X-Recording-Call-ID: %s", mf->call_id);
	notify_add_header(req, "X-Recording-File-Name: %s.%s", o->file_name, o->file_format);
	notify_add_header(req, "X-Recording-Full-File-Name: %s.%s", o->full_filename, o->file_format);
	notify_add_header(req, "X-Recording-File-Format: %s", o->file_format);
	notify_add_header(req, "X-Recording-Kind: %s", o->kind);
	notify_add_header(req, "X-Recording-Call-Start-Time: %.06f", mf->start_time);
	notify_add_header(req, "X-Recording-Stream-Start-Time: %.06f", o->start_time);
	notify_add_header(req, "X-Recording-Call-End-Time: %.06f", now);
	notify_add_header(req, "X-Recording-Stream-End-Time: %.06f", now);

	if (mf->db_id)
		notify_add_header(req, "X-Recording-Call-DB-ID: %llu", mf->db_id);
	if (o->db_id)
		notify_add_header(req, "X-Recording-Stream-DB-ID: %llu", o->db_id);
	if (mf->metadata)
		notify_add_header(req, "X-Recording-Call-Metadata: %s", mf->metadata);
	if (mf->metadata_db)
		notify_add_header(req, "X-Recording-DB-Metadata: %s", mf->metadata_db);

	if (tag) {
		notify_add_header(req, "X-Recording-Tag: %s", tag->name);
		if (tag->label)
			notify_add_header(req, "X-Recording-Label: %s", tag->label);
		if (tag->metadata)
			notify_add_header(req, "X-Recording-Tag-Metadata: %s", tag->metadata);
	}

	req->falloff = 5; // initial retry time

	g_thread_pool_push(notify_threadpool, req, NULL);
}
