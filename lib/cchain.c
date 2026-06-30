#include "cchain.h"
#ifdef HAVE_CODEC_CHAIN
#include <codec-chain/types.h>
#include <codec-chain/client.h>
#include "codeclib.h"
#include "str.h"
#include "containers.h"
#include "loglib.h"
#include <dlfcn.h>
#endif


#ifdef HAVE_CODEC_CHAIN

static void *cc_lib_handle;

static __typeof__(codec_chain_client_connect) *cc_client_connect;
static __typeof__(codec_chain_set_thread_funcs) *cc_set_thread_funcs;
static __typeof__(codec_chain_get) *cc_get;

static __typeof__(codec_chain_client_runner_new) *cc_client_runner_new;
static __typeof__(codec_chain_client_runner_free) *cc_client_runner_free;
static __typeof__(codec_chain_client_async_runner_new) *cc_client_async_runner_new;
static __typeof__(codec_chain_client_async_runner_free) *cc_client_async_runner_free;
static __typeof__(codec_chain_runner_do) *cc_runner_do;
static __typeof__(codec_chain_async_runner_do) *cc_async_runner_do;

static __typeof__(codec_chain_client_codec_new) *cc_client_codec_new;
static __typeof__(codec_chain_client_codec_free) *cc_client_codec_free;

static __typeof__(*codec_chain_defs) *cc_defs;

static codec_chain_client *cc_client;


static union {
	codec_chain_runner *sync;
	codec_chain_async_runner *async;
} cc_runners[CODEC_CHAIN_ID_MAX];

static struct {
	unsigned int async_busy;
	unsigned int async_blocked;
	unsigned int async_retry;
} cc_stats[CODEC_CHAIN_ID_MAX];


typedef enum {
	CCC_OK,
	CCC_ASYNC,
	CCC_ERR,
} codec_cc_state;

struct async_job {
	str data;
	unsigned long ts;
	void *async_cb_obj;
};
TYPED_GQUEUE(async_job, struct async_job);

struct codec_cc_s {
	union {
		codec_chain_runner *runner;
		codec_chain_async_runner *async_runner;
	};
	__typeof(&cc_stats[0]) stats;
	codec_chain_def *def;
	codec_chain_codec *codec;

	AVPacket *avpkt;
	codec_cc_state (*run)(codec_cc_t *c, const str *data, unsigned long ts, void *);
	void (*clear)(void *);
	void *clear_arg;

	mutex_t async_lock;
	AVPacket *avpkt_async;
	size_t data_len;
	bool async_busy; // currently processing a packet
	bool async_blocked; // couldn't find context
	bool async_shutdown; // shutdown/free happened while busy
	async_job_q async_jobs;
	unsigned long ts;
	void *(*async_init)(void *, void *, void *);
	void (*async_callback)(AVPacket *, void *);
	void *async_cb_obj;
};

static codec_cc_t *codec_cc_new_sync(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *));
static codec_cc_t *codec_cc_new_async(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *));


static bool __cc_run_async(codec_cc_t *, const str *, unsigned long, void *);


codec_cc_t *(*codec_cc_new)(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *));



static void cc_dlsym_resolve(const char *fn) {
	cc_client_connect = dlsym_assert(cc_lib_handle, "codec_chain_client_connect", fn);
	cc_set_thread_funcs = dlsym_assert(cc_lib_handle, "codec_chain_set_thread_funcs", fn);
	cc_get = dlsym_assert(cc_lib_handle, "codec_chain_get", fn);

	cc_client_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_runner_new", fn);

	cc_client_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_runner_free", fn);

	cc_client_async_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_async_runner_new", fn);

	cc_client_async_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_async_runner_free", fn);

	cc_runner_do = dlsym_assert(cc_lib_handle,
			"codec_chain_runner_do", fn);

	if (!rtpe_common_config_ptr->codec_chain_nonblock) {
		cc_async_runner_do = dlsym_assert(cc_lib_handle,
				"codec_chain_async_runner_do", fn);
	}
	else {
		__typeof__(codec_chain_async_runner_do_nonblock) *nb = dlsym_assert(cc_lib_handle,
				"codec_chain_async_runner_do_nonblock", fn);
		cc_async_runner_do = nb;
	}

	cc_client_codec_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_codec_new", fn);

	cc_client_codec_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_codec_free", fn);

	cc_defs = dlsym_assert(cc_lib_handle,
			"codec_chain_defs", fn);
}


static codec_cc_t *codec_cc_new_dummy(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *))
{
	return NULL;
}

void cc_init(void) {
	codec_cc_new = codec_cc_new_dummy;

	if (!rtpe_common_config_ptr->codec_chain_lib_path)
		return;

	cc_lib_handle = dlopen(rtpe_common_config_ptr->codec_chain_lib_path, RTLD_NOW | RTLD_LOCAL);
	if (!cc_lib_handle)
		die("Failed to load libcodec-chain.so '%s': %s",
				rtpe_common_config_ptr->codec_chain_lib_path,
				dlerror());

	cc_dlsym_resolve(rtpe_common_config_ptr->codec_chain_lib_path);

	cc_set_thread_funcs(codeclib_thread_init, codeclib_thread_cleanup, codeclib_thread_loop);

	cc_client = cc_client_connect(4);
	if (!cc_client)
		die("Failed to connect to cudecsd");

	if (!rtpe_common_config_ptr->codec_chain_async)
		codec_cc_new = codec_cc_new_sync;
	else
		codec_cc_new = codec_cc_new_async;

	ilog(LOG_DEBUG, "CUDA codecs initialised");
}

void cc_init_chain(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format)
{
	if (!cc_get) {
		ilog(LOG_WARN, "No codec-chain support loaded");
		return;
	}

	codec_chain_id id = cc_get(
			(codec_chain_params) {
				.name = src->rtpname,
				.clock_rate = src_format->clockrate,
				.channels = src_format->channels,
				.ptime = 20, // XXX
			},
			(codec_chain_params) {
				.name = dst->rtpname,
				.clock_rate = dst_format->clockrate,
				.channels = dst_format->channels,
				.ptime = 20, // XXX
			}
	);
	if (id == 0) {
		ilog(LOG_WARN, "Codec chain %s -> %s not supported by library",
				src->rtpname, dst->rtpname);
		return;
	}
	if (id >= CODEC_CHAIN_ID_MAX) {
		ilog(LOG_WARN, "Codec chain %s -> %s requires rebuild",
				src->rtpname, dst->rtpname);
		return;
	}

	if (rtpe_common_config_ptr->codec_chain_async) {
		if (cc_runners[id].async)
			return;
		cc_runners[id].async = cc_client_async_runner_new(cc_client, id,
				rtpe_common_config_ptr->codec_chain_async,
				rtpe_common_config_ptr->codec_chain_interval,
				rtpe_common_config_ptr->codec_chain_runners,
				rtpe_common_config_ptr->codec_chain_concurrency);
		if (cc_runners[id].async)
			ilog(LOG_DEBUG, "Created async chain runner for %s", cc_defs[id].name);
		else
			ilog(LOG_WARN, "Failed to create async chain runner for %s", cc_defs[id].name);
	}
	else {
		if (cc_runners[id].sync)
			return;
		cc_runners[id].sync = cc_client_runner_new(cc_client, id,
				rtpe_common_config_ptr->codec_chain_interval,
				rtpe_common_config_ptr->codec_chain_runners,
				rtpe_common_config_ptr->codec_chain_concurrency);
		if (cc_runners[id].sync)
			ilog(LOG_DEBUG, "Created chain runner for %s", cc_defs[id].name);
		else
			ilog(LOG_WARN, "Failed to create chain runner for %s", cc_defs[id].name);
	}
}

void cc_cleanup(void) {
	if (!cc_lib_handle)
		return;

	for (codec_chain_id id = 1; id < CODEC_CHAIN_ID_MAX; id++) {
		if (!rtpe_common_config_ptr->codec_chain_async)
			cc_client_runner_free(cc_client, &cc_runners[id].sync);
		else
			cc_client_async_runner_free(cc_client, &cc_runners[id].async);
	}
}


static codec_cc_state cc_run(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt;
	ssize_t ret = cc_runner_do(c->runner, c->codec,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size);
	if (ret <= 0)
		return CCC_ERR;
	// XXX handle input frame sizes != 160

	pkt->size = ret;
	pkt->duration = c->def->duration(data->s, data->len);
	pkt->pts = c->def->timestamp(ts, c->codec);

	return CCC_OK;
}

static void __cc_async_job_free(struct async_job *j) {
	g_free(j->data.s);
	g_free(j);
}

static void __codec_cc_free(codec_cc_t *c) {
	c->clear(c->clear_arg);
	while (c->async_jobs.length) {
		__auto_type j = t_queue_pop_head(&c->async_jobs);
		c->async_callback(NULL, j->async_cb_obj);
		__cc_async_job_free(j);
	}
	av_packet_free(&c->avpkt);
	av_packet_free(&c->avpkt_async);
	g_free(c);
}


// lock must be held
// append job to queue
static void __cc_async_do_add_queue(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	struct async_job *j = g_new0(__typeof__(*j), 1);
	j->data = str_dup_str(data);
	j->async_cb_obj = async_cb_obj;
	j->ts = ts;
	t_queue_push_tail(&c->async_jobs, j);
}
// check busy flag and append to queue if set
// if not busy, sets busy flag
// also check blocked flag if busy: if set, try running first job
static bool __cc_async_check_busy_blocked_queue(codec_cc_t *c, const str *data, unsigned long ts,
		void *async_cb_obj, __typeof__(__cc_run_async) run_async)
{
	struct async_job *j = NULL;
	async_job_q overflow = TYPED_GQUEUE_INIT;

	{
		LOCK(&c->async_lock);

		if (!c->async_busy) {
			// we can try running
			c->async_busy = true;
			return false;
		}

		atomic_inc_na(&c->stats->async_busy);

		// codec is busy (either currently running or was blocked)
		// append to queue
		__cc_async_do_add_queue(c, data, ts, async_cb_obj);

		if (c->async_jobs.length > 20) {
			ilog(LOG_WARN | LOG_FLAG_LIMIT, "Async job queue overflow (%u @ %s), dropping frames",
					c->async_jobs.length,
					c->def->name);
			do {
				__auto_type jj = t_queue_pop_head(&c->async_jobs);
				t_queue_push_tail(&overflow, jj);
			} while (c->async_jobs.length > 20);
		}

		// if we were blocked (not currently running), try running now
		if (c->async_blocked)
			j = t_queue_pop_head(&c->async_jobs);
	}

	while (overflow.length) {
		__auto_type jj = t_queue_pop_head(&overflow);
		c->async_callback(NULL, jj->async_cb_obj);
		__cc_async_job_free(jj);
	}

	if (j) {
		atomic_inc_na(&c->stats->async_retry);

		if (!run_async(c, &j->data, j->ts, j->async_cb_obj)) {
			// still blocked. return to queue
			atomic_inc_na(&c->stats->async_blocked);
			LOCK(&c->async_lock);
			t_queue_push_head(&c->async_jobs, j);
		}
		else {
			// unblocked, running now
			__cc_async_job_free(j);
			LOCK(&c->async_lock);
			c->async_blocked = false;
		}
	}

	return true;
}
// runner failed, needed to block (no available context)
// set blocked flag and append to queue
// queue is guaranteed to be empty
static void __cc_async_blocked_queue(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	LOCK(&c->async_lock);
	__cc_async_do_add_queue(c, data, ts, async_cb_obj);
	c->async_blocked = true;
	// busy == true
}

static codec_cc_state cc_X_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj,
		__typeof__(__cc_run_async) run_async)
{
	if (__cc_async_check_busy_blocked_queue(c, data, ts, async_cb_obj, run_async))
		return CCC_ASYNC;
	if (!run_async(c, data, ts, async_cb_obj))
		__cc_async_blocked_queue(c, data, ts, async_cb_obj);
	return CCC_ASYNC;
}

static codec_cc_state cc_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	return cc_X_run_async(c, data, ts, async_cb_obj, __cc_run_async);
}

static void cc_X_pkt_callback(codec_cc_t *c, ssize_t size, __typeof__(__cc_run_async) run_async) {
	AVPacket *pkt = c->avpkt_async;
	void *async_cb_obj = c->async_cb_obj;
	c->async_cb_obj = NULL;

	c->async_callback(size >= 0 ? pkt : NULL, async_cb_obj);

	pkt->size = 0;

	struct async_job *j = NULL;
	bool shutdown = false;
	{
		LOCK(&c->async_lock);
		j = t_queue_pop_head(&c->async_jobs);
		if (!j) {
			if (c->async_shutdown)
				shutdown = true;
			else
				c->async_busy = false;
		}
	}

	if (shutdown) {
		__codec_cc_free(c);
		return;
	}

	if (j) {
		if (!run_async(c, &j->data, j->ts, j->async_cb_obj)) {
			LOCK(&c->async_lock);
			t_queue_push_head(&c->async_jobs, j);
			c->async_blocked = true;
		}
		else {
			g_free(j->data.s);
			g_free(j);
			LOCK(&c->async_lock);
			c->async_blocked = false;
		}
	}
}

static void cc_run_callback(void *p, ssize_t size) {
	codec_cc_t *c = p;

	AVPacket *pkt = c->avpkt_async;

	if (size >= 0) {
		pkt->size = size;
		pkt->duration = c->data_len * 6L; // XXX
		pkt->pts = c->ts * 6L; // XXX
	}

	cc_X_pkt_callback(c, size, __cc_run_async);
}

static bool __cc_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt_async;
	pkt->size = 2048;

	c->data_len = data->len;
	c->ts = ts;
	c->async_cb_obj = async_cb_obj;

	return cc_async_runner_do(&c->async_runner->runner,
			&c->async_runner->async,
			c->codec,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size, cc_run_callback, c);
}



static void cc_clear(void *a) {
	codec_chain_codec *c = a;
	cc_client_codec_free(cc_client, &c);
}

static codec_cc_t *codec_cc_new_sync(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *))
{
	if (!cc_get)
		return NULL;

	codec_chain_id id = cc_get(
			(codec_chain_params) {
				.name = src->rtpname,
				.clock_rate = src_format->clockrate,
				.channels = src_format->channels,
				.ptime = 20, // XXX
			},
			(codec_chain_params) {
				.name = dst->rtpname,
				.clock_rate = dst_format->clockrate,
				.channels = dst_format->channels,
				.ptime = 20, // XXX
			}
	);
	if (id == 0)
		return NULL;
	if (id >= CODEC_CHAIN_ID_MAX)
		return NULL;
	if (!cc_runners[id].sync)
		return NULL;

	codec_cc_t *ret = g_new0(codec_cc_t, 1);
	codec_chain_codec_args args = {0};
	ret->def = &cc_defs[id];
	if (ret->def->args == CC_ARGS_OPUS) {
		args.opus = (codec_chain_opus_args) {
			.bitrate = bitrate,
			.complexity = rtpe_common_config_ptr->codec_chain_opus_complexity,
			.application = rtpe_common_config_ptr->codec_chain_opus_application,
		};
	}
	ret->codec = cc_client_codec_new(cc_client, id, args);
	ret->clear = cc_clear;
	ret->clear_arg = ret->codec;
	ret->runner = cc_runners[id].sync;
	ret->stats = &cc_stats[id];
	ret->avpkt = av_packet_alloc();
	ret->run = cc_run;

	return ret;
}

static codec_cc_t *codec_cc_new_async(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *))
{
	if (!cc_get)
		return NULL;

	codec_chain_id id = cc_get(
			(codec_chain_params) {
				.name = src->rtpname,
				.clock_rate = src_format->clockrate,
				.channels = src_format->channels,
				.ptime = 20, // XXX
			},
			(codec_chain_params) {
				.name = dst->rtpname,
				.clock_rate = dst_format->clockrate,
				.channels = dst_format->channels,
				.ptime = 20, // XXX
			}
	);
	if (id == 0)
		return NULL;
	if (id >= CODEC_CHAIN_ID_MAX)
		return NULL;
	if (!cc_runners[id].async)
		return NULL;

	codec_cc_t *ret = g_new0(codec_cc_t, 1);
	codec_chain_codec_args args = {0};
	ret->def = &cc_defs[id];
	if (ret->def->args == CC_ARGS_OPUS) {
		args.opus = (codec_chain_opus_args) {
			.bitrate = bitrate,
			.complexity = rtpe_common_config_ptr->codec_chain_opus_complexity,
			.application = rtpe_common_config_ptr->codec_chain_opus_application,
		};
	}
	ret->codec = cc_client_codec_new(cc_client, id, args);
	ret->clear = cc_clear;
	ret->clear_arg = ret->codec;
	ret->async_runner = cc_runners[id].async;
	ret->stats = &cc_stats[id];
	ret->run = cc_run_async;
	ret->avpkt_async = av_packet_alloc();
	av_new_packet(ret->avpkt_async, 2048);
	mutex_init(&ret->async_lock);
	t_queue_init(&ret->async_jobs);
	ret->async_init = async_init;
	ret->async_callback = async_callback;

	return ret;
}

void codec_cc_stop(codec_cc_t *c) {
	if (!c)
		return;

	// steal and fire all callbacks to release any references

	async_job_q q;

	{
		LOCK(&c->async_lock);
		q = c->async_jobs;
		t_queue_init(&c->async_jobs);
	}

	while (q.length) {
		__auto_type j = t_queue_pop_head(&q);
		c->async_callback(NULL, j->async_cb_obj);
		__cc_async_job_free(j);
	}
}

void codec_cc_free(codec_cc_t **ccp) {
	codec_cc_t *c = *ccp;
	if (!c)
		return;
	*ccp = NULL;

	{
		LOCK(&c->async_lock);
		if (c->async_busy && !c->async_blocked) {
			c->async_shutdown = true;
			return; // wait for callback
		}
	}
	__codec_cc_free(c);
}


codec_cc_stats_q codec_cc_stats(void) {
	codec_cc_stats_q ret = TYPED_GQUEUE_INIT;

	for (unsigned int i = 0; i < CODEC_CHAIN_ID_MAX; i++) {
		codec_chain_runner *r;

		if (rtpe_common_config_ptr->codec_chain_async) {
			if (!cc_runners[i].async)
				continue;
			r = &cc_runners[i].async->runner;
		}
		else {
			if (!cc_runners[i].sync)
				continue;
			r = cc_runners[i].sync;
		}

		__auto_type q = r->queuer;

		__auto_type e = g_new0(codec_cc_stats_entry, 1);
		t_queue_push_tail(&ret, e);

		g_strlcpy(e->name, r->def->name, sizeof(e->name));

#define LA(v) e->v = atomic_get_na(&cc_stats[i].v)
		LA(async_busy);
		LA(async_blocked);
		LA(async_retry);
#undef LA

		for (unsigned int j = 0; j < r->num_contexts; j++) {
			__auto_type c = g_new0(codec_cc_context_stats, 1);
			t_queue_push_tail(&e->contexts, c);

			c->ctx_idx = j;

#define LA(v) c->v = atomic_get_na(&q->contexts[j].v)
			LA(runs);
			LA(slots);
			LA(run_wait);
			LA(writers_wait);
			LA(compute_wait);
			LA(readers_wait);

			LA(run_busy);
			LA(write_busy);
			LA(slots_full);
			LA(buf_full);

			LA(ready_wait);
			LA(callbacks_preempt);
			LA(callbacks_fetch);
			LA(callbacks_run);
			LA(loop_barrier);
#undef LA
		}
	}

	return ret;
}


AVPacket *codec_cc_input_data(codec_cc_t *c, const str *data, unsigned long ts, void *x, void *y, void *z) {
	if (c->avpkt)
		av_new_packet(c->avpkt, 2048);
	void *async_cb_obj = NULL;
	if (c->async_init)
		async_cb_obj = c->async_init(x, y, z);

	codec_cc_state ret = c->run(c, data, ts, async_cb_obj);

	if (ret == CCC_ERR) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received error from codec-chain job");
		return c->avpkt; // return empty packet in case of error
	}
	if (ret == CCC_OK)
		return c->avpkt;

	// CCC_ASYNC
	return NULL;
}

#else

void cc_init(void) { }
void cc_cleanup(void) { }


AVPacket *codec_cc_input_data(codec_cc_t *c, const str *data, unsigned long ts, void *x, void *y, void *z) {
	return NULL;
}

#endif

