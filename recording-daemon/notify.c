#include "notify.h"
#include <stdbool.h>
#include <curl/curl.h>
#include "main.h"
#include "log.h"
#include "recaux.h"
#include "output.h"
#include "http.h"


static GThreadPool *notify_threadpool;

static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_t notify_waiter;
static GTree *notify_timers;


static bool do_notify_http(notif_req_t *req) {
	const char *err = NULL;
	CURLcode ret;

	ilog(LOG_DEBUG, "Launching HTTP notification for '%s%s%s'", FMT_M(req->name));

#if CURL_AT_LEAST_VERSION(7,56,0)
	g_autoptr(curl_mime) mime = NULL;
#endif

	g_autoptr(CURL) c = http_create_req(notify_uri,
			http_dummy_write, NULL, http_dummy_read, NULL,
			req->headers, !notify_nverify, &ret, &err);
	if (!c)
		goto fail;

	/* POST vs GET */
	if (notify_post) {
		err = "setting CURLOPT_POST";
		if ((ret = curl_easy_setopt(c, CURLOPT_POST, 1L)) != CURLE_OK)
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

		if ((ret = curl_mime_data(part, req->content->s->str, req->content->s->len)) != CURLE_OK)
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

	ilog(LOG_NOTICE, "HTTP notification for '%s%s%s' was successful", FMT_M(req->name));

	return true;

fail:
	ilog(LOG_ERR, "Failed to perform HTTP notification for '%s%s%s': "
			"Error while %s: %s",
			FMT_M(req->name),
			err, curl_easy_strerror(ret));

	return false;
}

static void failed_http(notif_req_t *req) {
	if (req->content)
		output_content_failure(req->content);
}

static bool do_notify_command(notif_req_t *req) {
	ilog(LOG_DEBUG, "Executing notification command for '%s%s%s'", FMT_M(req->name));

	GError *err = NULL;
	bool success = g_spawn_sync(NULL, req->argv, NULL,
			G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
			NULL, NULL, NULL, NULL, NULL, &err);

	if (!success) {
		ilog(LOG_ERR, "Failed to execute notification command for '%s%s%s': %s",
			FMT_M(req->name), err->message);
		g_error_free(err);
	}

	return success;
}

static void do_notify(void *p, void *u) {
	notif_req_t *req = p;

	bool ok = req->action->perform(req);

	if (!ok) {
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

		if (req->action->failed)
			req->action->failed(req);
	}

	req->action->cleanup(req);
	g_free(req->name);
	g_free(req);
}


static void *notify_timer(void *p) {
	pthread_mutex_lock(&timer_lock);

	// notify_timers being NULL acts as our shutdown flag
	while (notify_timers) {
		ilog(LOG_DEBUG, "Notification timer thread looping");

		// grab first entry in list, check retry time, sleep if it's in the future

		notif_req_t *first = rtpe_g_tree_first(notify_timers);
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
	const notif_req_t *a = A, *b = B;

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
	if (notify_threads <= 0)
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



#define notify_add_header(req, f, ...) http_add_header(&(req)->headers, f, __VA_ARGS__)


static void notify_req_setup_http(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
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

	if ((output_storage & OUTPUT_STORAGE_NOTIFY))
		req->content = output_get_content(o);
}

static void cleanup_http(notif_req_t *req) {
	curl_slist_free_all(req->headers);
	obj_release(req->content);
}

static const notif_action_t http_action = {
	.name = "HTTP",
	.setup = notify_req_setup_http,
	.perform = do_notify_http,
	.cleanup = cleanup_http,
	.failed = failed_http,
};



static void notify_req_setup_command(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
	req->argv = g_new(char *, 4);
	req->argv[0] = g_strdup(notify_command);
	if ((output_storage & OUTPUT_STORAGE_FILE))
		req->argv[1] = g_strdup_printf("%s.%s", o->full_filename, o->file_format);
	else
		req->argv[1] = g_strdup("");
	req->argv[2] = g_strdup_printf("%llu", req->db_id);
	req->argv[3] = NULL;
}

static void cleanup_command(notif_req_t *req) {
	g_strfreev(req->argv);
}

static const notif_action_t command_action = {
	.name = "command",
	.setup = notify_req_setup_command,
	.perform = do_notify_command,
	.cleanup = cleanup_command,
};



void notify_push_setup(const notif_action_t *action, output_t *o, metafile_t *mf, tag_t *tag) {
	notif_req_t *req = g_new0(__typeof(*req), 1);

	req->name = g_strdup_printf("%s for '%s'", action->name, o->file_name);
	req->action = action;

	req->db_id = o->db_id;

	action->setup(req, o, mf, tag);

	req->falloff_us = 5000000LL; // initial retry time

	g_thread_pool_push(notify_threadpool, req, NULL);
}

void notify_push_output(output_t *o, metafile_t *mf, tag_t *tag) {
	if (notify_uri)
		notify_push_setup(&http_action, o, mf, tag);

	if (notify_command)
		notify_push_setup(&command_action, o, mf, tag);
}
