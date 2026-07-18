#include "notify.h"
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include "main.h"
#include "log_r.h"
#include "recaux.h"
#include "output.h"
#include "http.h"
#include "helpers.h"
#include "str.h"
#include "notify_events.h"


static GThreadPool *notify_threadpool;

static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t timer_cond = PTHREAD_COND_INITIALIZER;
static pthread_t notify_waiter;
static GTree *notify_timers;

static unsigned int notify_nont_inflight;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long notify_metric_enqueued;
static unsigned long notify_metric_success;
static unsigned long notify_metric_retry;
static unsigned long notify_metric_giveup;
static unsigned long notify_metric_dropped;


static void metric_inc(unsigned long *m) {
	__atomic_add_fetch(m, 1, __ATOMIC_RELAXED);
}

static void nont_inflight_dec(notif_req_t *req) {
	if (!req || req->terminal)
		return;
	pthread_mutex_lock(&queue_lock);
	if (notify_nont_inflight > 0)
		notify_nont_inflight--;
	pthread_mutex_unlock(&queue_lock);
}

static bool nont_inflight_try_inc(void) {
	bool ok = true;
	pthread_mutex_lock(&queue_lock);
	if (notify_queue_limit > 0 && notify_nont_inflight >= (unsigned int) notify_queue_limit)
		ok = false;
	else
		notify_nont_inflight++;
	pthread_mutex_unlock(&queue_lock);
	return ok;
}

static void req_free_fields(notif_req_t *req) {
	if (!req)
		return;
	g_free(req->call_id);
	g_free(req->file_name);
	g_free(req->file_format);
	g_free(req->kind);
	g_free(req->full_filename);
	g_free(req->output_id);
	g_free(req->metadata);
	g_free(req->tag_name);
	g_free(req->tag_label);
	g_free(req->tag_metadata);
	g_free(req->error_code);
	g_free(req->error_message);
	g_free(req->json_body);
	g_free(req->object_name);
}

static bool do_notify_http(notif_req_t *req) {
	const char *err = NULL;
	CURLcode ret = CURLE_OK;

	ilog(LOG_DEBUG, "Launching HTTP notification (%s) for '%s%s%s'",
			notify_event_name(req->event), FMT_M(req->name));

#if CURL_AT_LEAST_VERSION(7,56,0)
	g_autoptr(curl_mime) mime = NULL;
#endif

	g_autoptr(CURL) c = http_create_req(notify_uri,
			http_dummy_write, NULL, http_dummy_read, NULL,
			req->headers, !notify_nverify, &ret, &err);
	if (!c)
		goto fail;

	bool do_post = notify_post || req->json_body || req->content;
	if (do_post) {
		err = "setting CURLOPT_POST";
		if ((ret = curl_easy_setopt(c, CURLOPT_POST, 1L)) != CURLE_OK)
			goto fail;
	}

	if (req->json_body) {
		err = "setting CURLOPT_POSTFIELDS";
		if ((ret = curl_easy_setopt(c, CURLOPT_POSTFIELDS, req->json_body)) != CURLE_OK)
			goto fail;
		err = "setting CURLOPT_POSTFIELDSIZE";
		if ((ret = curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE,
						(long) strlen(req->json_body))) != CURLE_OK)
			goto fail;
	}

#if CURL_AT_LEAST_VERSION(7,56,0)
	if (req->content && req->event == NOTIFY_EVT_FINISHED && !req->json_body) {
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

	ilog(LOG_NOTICE, "HTTP notification (%s) for '%s%s%s' was successful",
			notify_event_name(req->event), FMT_M(req->name));
	return true;

fail:
	ilog(LOG_ERR, "Failed to perform HTTP notification (%s) for '%s%s%s': "
			"Error while %s: %s",
			notify_event_name(req->event), FMT_M(req->name),
			err, curl_easy_strerror(ret));
	return false;
}

static void failed_http(notif_req_t *req) {
	if (req->content)
		output_content_failure(req->content);
}

static bool do_notify_command(notif_req_t *req) {
	if (!req->argv)
		return true;
	ilog(LOG_DEBUG, "Executing notification command (%s) for '%s%s%s'",
			notify_event_name(req->event), FMT_M(req->name));
	GError *err = NULL;
	bool success = g_spawn_sync(NULL, req->argv, req->envp,
			G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
			NULL, NULL, NULL, NULL, NULL, &err);
	if (!success) {
		ilog(LOG_ERR, "Failed to execute notification command (%s) for '%s%s%s': %s",
			notify_event_name(req->event), FMT_M(req->name), err->message);
		g_error_free(err);
	}
	return success;
}

static void do_notify(void *p, void *u) {
	notif_req_t *req = p;
	bool ok = req->action->perform(req);

	if (!ok) {
		if (notify_retries >= 0 && req->retries < (unsigned int) notify_retries) {
			req->retries++;
			metric_inc(&notify_metric_retry);
			ilog(LOG_INFO, "Failure while sending notification (%s) for '%s%s%s': "
					"Will retry in %" PRId64 " seconds (#%u)",
					notify_event_name(req->event), FMT_M(req->name),
					req->falloff_us / 1000000L, req->retries);
			req->retry_time = now_us() + req->falloff_us;
			req->falloff_us *= 2;
			pthread_mutex_lock(&timer_lock);
			if (notify_timers) {
				g_tree_insert(notify_timers, req, req);
				pthread_cond_signal(&timer_cond);
				pthread_mutex_unlock(&timer_lock);
				return;
			}
			pthread_mutex_unlock(&timer_lock);
		}
		metric_inc(&notify_metric_giveup);
		ilog(LOG_ERR, "Failure while sending notification (%s) for '%s%s%s' after %u retries. "
				"Giving up", notify_event_name(req->event), FMT_M(req->name), req->retries);
		if (req->action->failed)
			req->action->failed(req);
	}
	else
		metric_inc(&notify_metric_success);

	nont_inflight_dec(req);
	req->action->cleanup(req);
	req_free_fields(req);
	g_free(req->name);
	g_free(req);
}

static void *notify_timer(void *p) {
	pthread_mutex_lock(&timer_lock);
	while (notify_timers) {
		notif_req_t *first = rtpe_g_tree_first(notify_timers);
		if (!first) {
			pthread_cond_wait(&timer_cond, &timer_lock);
			continue;
		}
		int64_t now = now_us();
		if (now < first->retry_time) {
			cond_timedwait(&timer_cond, &timer_lock, first->retry_time);
			continue;
		}
		g_tree_remove(notify_timers, first);
		g_thread_pool_push(notify_threadpool, first, NULL);
	}
	pthread_mutex_unlock(&timer_lock);
	pthread_mutex_destroy(&timer_lock);
	pthread_cond_destroy(&timer_cond);
	return NULL;
}

static int notify_req_cmp(const void *A, const void *B) {
	const notif_req_t *a = A, *b = B;
	if (a->retry_time < b->retry_time) return -1;
	if (a->retry_time > b->retry_time) return 1;
	if (a < b) return -1;
	if (a > b) return 1;
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
	ilog(LOG_INFO, "Recording notify enabled (events mask=0x%x json=%s cmd_fmt=%d queue_limit=%d)",
			notify_events_mask, notify_json ? "true" : "false",
			notify_command_format, notify_queue_limit);
}

void notify_cleanup(void) {
	if (notify_waiter && notify_timers) {
		pthread_mutex_lock(&timer_lock);
		if (notify_timers) {
			while (true) {
				notif_req_t *first = rtpe_g_tree_first(notify_timers);
				if (!first)
					break;
				g_tree_remove(notify_timers, first);
				nont_inflight_dec(first);
				if (first->action && first->action->cleanup)
					first->action->cleanup(first);
				req_free_fields(first);
				g_free(first->name);
				g_free(first);
			}
			g_tree_destroy(notify_timers);
			notify_timers = NULL;
		}
		pthread_cond_signal(&timer_cond);
		pthread_mutex_unlock(&timer_lock);
	}
	if (notify_threadpool)
		g_thread_pool_free(notify_threadpool, true, false);
	notify_threadpool = NULL;
	ilog(LOG_INFO, "Notify metrics: enqueued=%lu success=%lu retry=%lu giveup=%lu dropped=%lu",
			__atomic_load_n(&notify_metric_enqueued, __ATOMIC_RELAXED),
			__atomic_load_n(&notify_metric_success, __ATOMIC_RELAXED),
			__atomic_load_n(&notify_metric_retry, __ATOMIC_RELAXED),
			__atomic_load_n(&notify_metric_giveup, __ATOMIC_RELAXED),
			__atomic_load_n(&notify_metric_dropped, __ATOMIC_RELAXED));
}

#define notify_add_header(req, f, ...) http_add_header(&(req)->headers, f, __VA_ARGS__)

static void notify_req_setup_http(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
	double now = (double) now_us() / 1000000.;
	bool terminal = notify_event_is_terminal(req->event);

	const char *call_id = req->call_id ? req->call_id : (mf && mf->call_id ? mf->call_id : NULL);
	const char *file_name = req->file_name ? req->file_name : (o && o->file_name ? o->file_name : NULL);
	const char *file_format = req->file_format ? req->file_format : (o && o->file_format ? o->file_format : NULL);
	const char *kind = req->kind ? req->kind : (o && o->kind ? o->kind : NULL);
	const char *full_filename = req->full_filename ? req->full_filename :
		(o && o->full_filename ? o->full_filename : NULL);
	const char *output_id = req->output_id ? req->output_id : (o && o->output_id ? o->output_id : NULL);
	const char *metadata = req->metadata ? req->metadata :
		(!notify_no_metadata && mf && mf->metadata ? mf->metadata : NULL);
	double call_start = req->call_start > 0 ? req->call_start :
		(mf ? (double) mf->start_time_us / 1000000. : 0);
	double stream_start = req->stream_start > 0 ? req->stream_start :
		(o ? (double) o->start_time_us / 1000000. : call_start);
	unsigned long long call_db_id = req->call_db_id ? req->call_db_id : (mf ? mf->db_id : 0);
	unsigned long long stream_db_id = req->db_id ? req->db_id : (o ? o->db_id : 0);

	notify_add_header(req, "X-Recording-Event: %s", notify_event_name(req->event));
	notify_add_header(req, "X-Recording-Status: %s", notify_event_status(req->event));
	notify_add_header(req, "X-Recording-Event-Time: %.06f", now);

	if (call_id)
		notify_add_header(req, "X-Recording-Call-ID: %s", call_id);
	if (output_id)
		notify_add_header(req, "X-Recording-Output-Id: %s", output_id);
	if (file_name && file_format)
		notify_add_header(req, "X-Recording-File-Name: %s.%s", file_name, file_format);
	else if (file_name)
		notify_add_header(req, "X-Recording-File-Name: %s", file_name);
	if (full_filename)
		notify_add_header(req, "X-Recording-Full-File-Name: %s", full_filename);
	if (file_format)
		notify_add_header(req, "X-Recording-File-Format: %s", file_format);
	if (kind)
		notify_add_header(req, "X-Recording-Kind: %s", kind);

	notify_add_header(req, "X-Recording-Call-Start-Time: %.06f", call_start);
	notify_add_header(req, "X-Recording-Stream-Start-Time: %.06f", stream_start);
	if (terminal) {
		notify_add_header(req, "X-Recording-Call-End-Time: %.06f", now);
		notify_add_header(req, "X-Recording-Stream-End-Time: %.06f", now);
	}

	if (call_db_id)
		notify_add_header(req, "X-Recording-Call-DB-ID: %llu", call_db_id);
	if (stream_db_id)
		notify_add_header(req, "X-Recording-Stream-DB-ID: %llu", stream_db_id);
	if (metadata) {
		notify_add_header(req, "X-Recording-Call-Metadata: %s", metadata);
		notify_add_header(req, "X-Recording-DB-Metadata: %s", metadata);
	}

	const char *tag_name = req->tag_name ? req->tag_name : (tag && tag->name ? tag->name : NULL);
	const char *tag_label = req->tag_label ? req->tag_label : (tag && tag->label ? tag->label : NULL);
	const char *tag_metadata = req->tag_metadata ? req->tag_metadata :
		(tag && tag->metadata ? tag->metadata : NULL);
	if (tag_name)
		notify_add_header(req, "X-Recording-Tag: %s", tag_name);
	if (tag_label)
		notify_add_header(req, "X-Recording-Label: %s", tag_label);
	if (tag_metadata)
		notify_add_header(req, "X-Recording-Tag-Metadata: %s", tag_metadata);

	if (req->error_code && req->error_code[0])
		notify_add_header(req, "X-Recording-Error-Code: %s", req->error_code);
	if (req->error_message && req->error_message[0])
		notify_add_header(req, "X-Recording-Error-Message: %s", req->error_message);
	if (req->file_size > 0)
		notify_add_header(req, "X-Recording-File-Size: %" PRId64, req->file_size);
	if (req->duration_ms > 0)
		notify_add_header(req, "X-Recording-Duration-MS: %" PRId64, req->duration_ms);
	if (req->sample_rate > 0)
		notify_add_header(req, "X-Recording-Sample-Rate: %d", req->sample_rate);
	if (req->channels > 0)
		notify_add_header(req, "X-Recording-Channels: %d", req->channels);
	if (req->json_body)
		notify_add_header(req, "%s", "Content-Type: application/json");

	if (o && req->event == NOTIFY_EVT_FINISHED && (output_storage & OUTPUT_STORAGE_NOTIFY) && !req->content)
		req->content = output_get_content(o);
}

static void cleanup_http(notif_req_t *req) {
	curl_slist_free_all(req->headers);
	req->headers = NULL;
	obj_release(req->content);
	req->content = NULL;
}

static const notif_action_t http_action = {
	.name = "HTTP",
	.setup = notify_req_setup_http,
	.perform = do_notify_http,
	.cleanup = cleanup_http,
	.failed = failed_http,
};

static void notify_req_setup_command(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
	const char *path = req->full_filename ? req->full_filename : "";
	const char *call_id = req->call_id ? req->call_id : (mf && mf->call_id ? mf->call_id : "");
	const char *kind = req->kind ? req->kind : (o && o->kind ? o->kind : "");

	if (!path[0] && o) {
		if (o->filename)
			path = o->filename;
		else if ((output_storage & OUTPUT_STORAGE_FILE) && o->full_filename && o->file_format) {
			req->full_filename = g_strdup_printf("%s.%s", o->full_filename, o->file_format);
			path = req->full_filename;
		}
	}

	switch ((enum notify_command_format) notify_command_format) {
	case NOTIFY_CMD_EXTENDED:
		req->argv = g_new0(char *, 8);
		req->argv[0] = g_strdup(notify_command);
		req->argv[1] = g_strdup(notify_event_name(req->event));
		req->argv[2] = g_strdup(path);
		req->argv[3] = g_strdup_printf("%llu", req->db_id);
		req->argv[4] = g_strdup(call_id);
		req->argv[5] = g_strdup(kind);
		req->argv[6] = g_strdup(path);
		req->argv[7] = NULL;
		break;
	case NOTIFY_CMD_JSON_ENV: {
		req->argv = g_new0(char *, 2);
		req->argv[0] = g_strdup(notify_command);
		req->argv[1] = NULL;
		gchar **env = g_get_environ();
		const char *payload = req->json_body ? req->json_body : "{}";
		env = g_environ_setenv(env, "NOTIFY_PAYLOAD", payload, TRUE);
		env = g_environ_setenv(env, "NOTIFY_EVENT", notify_event_name(req->event), TRUE);
		req->envp = env;
		break;
	}
	case NOTIFY_CMD_LEGACY:
	default:
		req->argv = g_new0(char *, 4);
		req->argv[0] = g_strdup(notify_command);
		if (path[0])
			req->argv[1] = g_strdup(path);
		else if (o && (output_storage & OUTPUT_STORAGE_FILE) && o->full_filename && o->file_format)
			req->argv[1] = g_strdup_printf("%s.%s", o->full_filename, o->file_format);
		else
			req->argv[1] = g_strdup("");
		req->argv[2] = g_strdup_printf("%llu", req->db_id);
		req->argv[3] = NULL;
		break;
	}
}

static void cleanup_command(notif_req_t *req) {
	g_strfreev(req->argv);
	req->argv = NULL;
	g_strfreev(req->envp);
	req->envp = NULL;
}

static const notif_action_t command_action = {
	.name = "command",
	.setup = notify_req_setup_command,
	.perform = do_notify_command,
	.cleanup = cleanup_command,
};

static char *notify_build_json(notif_req_t *req) {
	double now = (double) now_us() / 1000000.;
	bool terminal = notify_event_is_terminal(req->event);
	JsonBuilder *b = json_builder_new();
	json_builder_begin_object(b);

	json_builder_set_member_name(b, "event");
	json_builder_add_string_value(b, notify_event_name(req->event));
	json_builder_set_member_name(b, "event_time");
	json_builder_add_double_value(b, now);
	json_builder_set_member_name(b, "status");
	json_builder_add_string_value(b, notify_event_status(req->event));
	json_builder_set_member_name(b, "call_id");
	json_builder_add_string_value(b, req->call_id ? req->call_id : "");

	json_builder_set_member_name(b, "kind");
	if (req->kind)
		json_builder_add_string_value(b, req->kind);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "file_name");
	if (req->file_name && req->file_format) {
		char *fn = g_strdup_printf("%s.%s", req->file_name, req->file_format);
		json_builder_add_string_value(b, fn);
		g_free(fn);
	}
	else if (req->file_name)
		json_builder_add_string_value(b, req->file_name);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "full_file_name");
	if (req->full_filename)
		json_builder_add_string_value(b, req->full_filename);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "file_format");
	if (req->file_format)
		json_builder_add_string_value(b, req->file_format);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "output_id");
	if (req->output_id)
		json_builder_add_string_value(b, req->output_id);
	else
		json_builder_add_null_value(b);

	json_builder_set_member_name(b, "db");
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "call_id");
	if (req->call_db_id)
		json_builder_add_int_value(b, (gint64) req->call_db_id);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "stream_id");
	if (req->db_id)
		json_builder_add_int_value(b, (gint64) req->db_id);
	else
		json_builder_add_null_value(b);
	json_builder_end_object(b);

	json_builder_set_member_name(b, "times");
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "call_start");
	json_builder_add_double_value(b, req->call_start);
	json_builder_set_member_name(b, "stream_start");
	json_builder_add_double_value(b, req->stream_start > 0 ? req->stream_start : req->call_start);
	json_builder_set_member_name(b, "stream_end");
	if (terminal)
		json_builder_add_double_value(b, now);
	else
		json_builder_add_null_value(b);
	json_builder_end_object(b);

	json_builder_set_member_name(b, "media");
	json_builder_begin_object(b);
	json_builder_set_member_name(b, "sample_rate");
	if (req->sample_rate > 0)
		json_builder_add_int_value(b, req->sample_rate);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "channels");
	if (req->channels > 0)
		json_builder_add_int_value(b, req->channels);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "duration_ms");
	if (req->duration_ms > 0)
		json_builder_add_int_value(b, req->duration_ms);
	else
		json_builder_add_null_value(b);
	json_builder_set_member_name(b, "file_size");
	if (req->file_size > 0)
		json_builder_add_int_value(b, req->file_size);
	else
		json_builder_add_null_value(b);
	json_builder_end_object(b);

	json_builder_set_member_name(b, "tag");
	if (req->tag_name || req->tag_label) {
		json_builder_begin_object(b);
		json_builder_set_member_name(b, "name");
		json_builder_add_string_value(b, req->tag_name ? req->tag_name : "");
		json_builder_set_member_name(b, "label");
		json_builder_add_string_value(b, req->tag_label ? req->tag_label : "");
		json_builder_end_object(b);
	}
	else
		json_builder_add_null_value(b);

	json_builder_set_member_name(b, "metadata");
	if (!notify_no_metadata && req->metadata)
		json_builder_add_string_value(b, req->metadata);
	else
		json_builder_add_null_value(b);

	json_builder_set_member_name(b, "error");
	if (req->error_code || req->error_message) {
		json_builder_begin_object(b);
		json_builder_set_member_name(b, "code");
		json_builder_add_string_value(b, req->error_code ? req->error_code : "");
		json_builder_set_member_name(b, "message");
		json_builder_add_string_value(b, req->error_message ? req->error_message : "");
		json_builder_end_object(b);
	}
	else
		json_builder_add_null_value(b);

	json_builder_end_object(b);
	return glib_json_print(b);
}

static void notify_fill_media_extras(notif_req_t *req, output_t *o) {
	if (!o)
		return;
	if (req->sample_rate <= 0 && o->actual_format.clockrate > 0)
		req->sample_rate = o->actual_format.clockrate;
	if (req->channels <= 0 && o->actual_format.channels > 0)
		req->channels = o->actual_format.channels;
	if (req->duration_ms <= 0) {
		int64_t start = o->first_write_time_us ? o->first_write_time_us : o->start_time_us;
		if (start > 0) {
			int64_t end = now_us();
			if (end > start)
				req->duration_ms = (end - start) / 1000;
		}
	}
	if (req->file_size <= 0 && o->filename) {
		struct stat st;
		if (stat(o->filename, &st) == 0)
			req->file_size = (int64_t) st.st_size;
	}
}

static void notify_req_snapshot(notif_req_t *req, enum notify_event event,
		output_t *o, metafile_t *mf, tag_t *tag,
		const char *error_code, const char *error_message)
{
	req->event = event;
	req->terminal = notify_event_is_terminal(event) ? 1 : 0;

	if (mf) {
		req->call_id = g_strdup(mf->call_id);
		req->call_start = (double) mf->start_time_us / 1000000.;
		req->call_db_id = mf->db_id;
		if (!notify_no_metadata && mf->metadata)
			req->metadata = g_strdup(mf->metadata);
	}
	if (o) {
		req->db_id = o->db_id;
		req->file_name = g_strdup(o->file_name);
		req->file_format = g_strdup(o->file_format);
		req->kind = g_strdup(o->kind);
		req->output_id = g_strdup(o->output_id);
		req->stream_start = (double) o->start_time_us / 1000000.;
		if (o->filename)
			req->full_filename = g_strdup(o->filename);
		else if (o->full_filename && o->file_format)
			req->full_filename = g_strdup_printf("%s.%s", o->full_filename, o->file_format);
		else if (o->full_filename)
			req->full_filename = g_strdup(o->full_filename);
	}
	else if (mf) {
		req->db_id = mf->db_id;
		req->stream_start = req->call_start;
	}
	if (tag) {
		req->tag_name = g_strdup(tag->name);
		req->tag_label = g_strdup(tag->label);
		req->tag_metadata = g_strdup(tag->metadata);
	}
	if (error_code)
		req->error_code = g_strdup(error_code);
	if (error_message)
		req->error_message = g_strdup(error_message);
	if (req->terminal && o)
		notify_fill_media_extras(req, o);
	if (notify_json || notify_command_format == (int) NOTIFY_CMD_JSON_ENV)
		req->json_body = notify_build_json(req);
}

static void notify_enqueue(const notif_action_t *action, notif_req_t *snap,
		output_t *o, metafile_t *mf, tag_t *tag)
{
	if (!notify_threadpool || !action)
		return;

	notif_req_t *req = g_new0(__typeof(*req), 1);
	req->event = snap->event;
	req->terminal = snap->terminal;
	req->db_id = snap->db_id;
	req->call_db_id = snap->call_db_id;
	req->call_start = snap->call_start;
	req->stream_start = snap->stream_start;
	req->file_size = snap->file_size;
	req->duration_ms = snap->duration_ms;
	req->sample_rate = snap->sample_rate;
	req->channels = snap->channels;
	req->call_id = g_strdup(snap->call_id);
	req->file_name = g_strdup(snap->file_name);
	req->file_format = g_strdup(snap->file_format);
	req->kind = g_strdup(snap->kind);
	req->full_filename = g_strdup(snap->full_filename);
	req->output_id = g_strdup(snap->output_id);
	req->metadata = g_strdup(snap->metadata);
	req->tag_name = g_strdup(snap->tag_name);
	req->tag_label = g_strdup(snap->tag_label);
	req->tag_metadata = g_strdup(snap->tag_metadata);
	req->error_code = g_strdup(snap->error_code);
	req->error_message = g_strdup(snap->error_message);
	req->json_body = g_strdup(snap->json_body);

	req->name = g_strdup_printf("%s/%s for '%s'", action->name,
			notify_event_name(req->event),
			req->file_name ? req->file_name :
			(req->call_id ? req->call_id : "unknown"));
	req->action = action;
	req->falloff_us = 5000000LL;

	action->setup(req, o, mf, tag);

	if (action == &http_action && !notify_json)
		g_clear_pointer(&req->json_body, g_free);

	metric_inc(&notify_metric_enqueued);
	g_thread_pool_push(notify_threadpool, req, NULL);
}

static void notify_push_event(enum notify_event event, output_t *o, metafile_t *mf,
		tag_t *tag, const char *error_code, const char *error_message)
{
	if (!notify_threadpool || !mf)
		return;
	if (!notify_event_enabled(event))
		return;
	if (!notify_uri && !notify_command)
		return;

	bool terminal = notify_event_is_terminal(event);
	if (!terminal) {
		if (!nont_inflight_try_inc()) {
			metric_inc(&notify_metric_dropped);
			ilog(LOG_DEBUG, "Dropping non-terminal notify %s (queue limit %d)",
					notify_event_name(event), notify_queue_limit);
			return;
		}
	}

	notif_req_t snap = {0};
	notify_req_snapshot(&snap, event, o, mf, tag, error_code, error_message);

	ilog(LOG_DEBUG, "Queueing notification event %s for '%s%s%s'",
			notify_event_name(event),
			FMT_M(snap.file_name ? snap.file_name :
				(snap.call_id ? snap.call_id : "unknown")));

	/* One non-terminal slot covers both actions when both are enabled. */
	if (notify_uri)
		notify_enqueue(&http_action, &snap, o, mf, tag);
	if (notify_command) {
		/* Avoid double nont_inflight_dec when both HTTP and command run. */
		if (notify_uri && !terminal)
			snap.terminal = 1;
		notify_enqueue(&command_action, &snap, o, mf, tag);
	}

	req_free_fields(&snap);
}

void notify_push_setup(const notif_action_t *action, output_t *o, metafile_t *mf, tag_t *tag) {
	/* Compatibility entry used by other modules (S3/GCS share pattern). */
	if (!notify_threadpool || !action || !o)
		return;
	notif_req_t *req = g_new0(__typeof(*req), 1);
	req->name = g_strdup_printf("%s for '%s'", action->name, o->file_name ? o->file_name : "unknown");
	req->action = action;
	req->event = NOTIFY_EVT_FINISHED;
	req->terminal = 1;
	req->db_id = o->db_id;
	req->falloff_us = 5000000LL;
	action->setup(req, o, mf, tag);
	metric_inc(&notify_metric_enqueued);
	g_thread_pool_push(notify_threadpool, req, NULL);
}

void notify_push_output(output_t *o, metafile_t *mf, tag_t *tag) {
	if (o)
		o->notify_terminal = 1;
	notify_push_event(NOTIFY_EVT_FINISHED, o, mf, tag, NULL, NULL);
}

void notify_push_output_event(enum notify_event event, output_t *o, metafile_t *mf,
		tag_t *tag, const char *error_code, const char *error_message)
{
	notify_push_event(event, o, mf, tag, error_code, error_message);
}

void notify_push_call_event(enum notify_event event, metafile_t *mf) {
	if (!mf)
		return;
	notify_push_event(event, NULL, mf, NULL, NULL, NULL);
}

void notify_push_call(metafile_t *mf) {
	if (!mf)
		return;
	if (mf->notify_call_terminal)
		return;
	mf->notify_call_terminal = 1;
	notify_push_call_event(mf->discard ? NOTIFY_EVT_CALL_DISCARDED : NOTIFY_EVT_CALL_FINISHED, mf);
}
