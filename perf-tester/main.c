#include <locale.h>
#include <ncurses.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdarg.h>
#include <libavformat/avformat.h>

#include "auxlib.h"
#include "codeclib.h"
#include "poller.h"
#include "ssllib.h"
#include "obj.h"
#include "fix_frame_channel_layout.h"



#define COMM_SIZE 25 // including null byte
#define COMM_SIZE_SCAN "24" // COMM_SIZE without null byte as string



struct testparams {
	const char *name;
	const char *file;
	GPtrArray *fixture; // not a reference
	void (*read_fn)(GPtrArray *, struct testparams *);
	int clock_rate;
	int channels;
	enum AVCodecID codec_id;
};

struct stream {
	struct obj obj;
	int timer_fd;
	int output_fd;
	char *type;

	mutex_t lock;
	unsigned long long input_ts;
	unsigned long long output_ts;
	decoder_t *decoder;
	encoder_t *encoder;
	codec_cc_t *chain;
	struct testparams in_params;
	struct testparams out_params;
	uint fixture_idx;
	long long encoding_start;

	uint dump_count;
	AVFormatContext *fmtctx;
	AVStream *avst;
};

struct stats {
	long long iv; // last interval, or sum of all intervals
	long long ucpu; // CPU time, or sum of all user CPU times
	long long scpu; // CPU time, or sum of all system CPU times
	long long comput; // compute real time, or sum of all compute times

	bool blocked; // copied from worker->blocked
};

struct stats_sample {
	long long ts; // last time stats were sampled
	struct stats stats; // last sampled stats
};

struct worker {
	pthread_t thr;
	pid_t pid;

	bool blocked; // not locked, not critical. set by worker, cleared by output

	struct stats_sample sample; // owned by output thread

	mutex_t comput_lock;
	long long comput; // sum of time spent computing in us, reset to 0 at reading
};

struct other_thread {
	char comm[COMM_SIZE];
	struct stats_sample sample; // owned by output thread
	struct stats stats; // temp storage, owned by output thread
};

struct freq_stats {
	long min;
	long max;
	long sum;
	long samples;
};

struct thread_freq_stats {
	mutex_t lock;
	struct freq_stats stats;
};

struct delay_stats {
	long long max_actual;
	long long max_allowed;
	uint slots;
	uint *counts;
};


typedef void render_fn(const struct stats *stats, int line, int x, int breadth, int width,
		int color,
		const char *titlefmt, ...);
typedef void delay_fn(const struct delay_stats *stats, int line, int x, int breadth, int width);



static struct rtpengine_common_config rtpe_common_config = {
	.log_levels = {
		[log_level_index_ffmpeg] = 6,
		[log_level_index_internals] = 6,
		[log_level_index_core] = 6,
	},
};


static void fixture_read_avio(GPtrArray *, struct testparams *);
static void fixture_read_raw(GPtrArray *, struct testparams *);


static const struct testparams testparams[] = {
	{
		.name = "PCMA",
		.file = "pcma.1.8k.raw",
		.read_fn = fixture_read_raw,
		.clock_rate = 8000,
		.channels = 1,
		.codec_id = AV_CODEC_ID_PCM_ALAW,
	},
	{
		.name = "PCMU",
		.file = "pcmu.1.8k.raw",
		.read_fn = fixture_read_raw,
		.clock_rate = 8000,
		.channels = 1,
		.codec_id = AV_CODEC_ID_PCM_MULAW,
	},
	{
		.name = "opus",
		.file = "opus.1.8k.11k.speech.ogg",
		.read_fn = fixture_read_avio,
		.clock_rate = 48000,
		.channels = 2,
		.codec_id = AV_CODEC_ID_OPUS,
	},
};


// settings
static char *source_codec = "PCMA";
static char *dest_codec = "opus";
static int init_threads = 0;
static gboolean bidirectional = false;
static int max_cpu = 0;
static gboolean system_cpu;
static int break_in = 200;
static int measure_time = 500;
static int repeats = 1;
static gboolean cpu_freq;
static int freq_granularity = 50;


#define BLOCKED_COLOR 1
#define SUMMARY_COLOR 2
#define CPU_COLOR 3
#define THREAD_COLOR 4


static long ticks_per_sec;
static uint num_cpus;
static struct stats_sample *cpu_stats;

static struct poller *rtpe_poller;

static codec_def_t *decoder_def;
static codec_def_t *encoder_def;

static struct testparams in_params;
static struct testparams out_params;

static mutex_t workers_lock = MUTEX_STATIC_INIT;
static GQueue workers = G_QUEUE_INIT;

static __thread struct worker *worker_self;

static mutex_t streams_lock = MUTEX_STATIC_INIT;
static GPtrArray *streams;
static GHashTable *stream_types;

static mutex_t other_threads_lock = MUTEX_STATIC_INIT;
static GHashTable *other_threads;
static GHashTable *worker_threads;

static mutex_t curses_lock = MUTEX_STATIC_INIT;
static WINDOW *popup;

static long long ptime = 20000; // us TODO: support different ptimes

static mutex_t delay_stats_lock = MUTEX_STATIC_INIT;
static struct delay_stats delay_stats;



static render_fn usage_bar;
static render_fn time_bar;
static render_fn no_bar;

static delay_fn delay_bar;
static delay_fn no_delay;

static render_fn *output_fn = usage_bar; // startup default
static delay_fn *delay_out_fn = no_delay; // startup default
static bool do_cpu_stats = false;
static bool do_thread_stats = false;


G_DEFINE_AUTOPTR_CLEANUP_FUNC(FILE, fclose)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(DIR, closedir)



static pthread_t thread_new(const char *name, void *(*fn)(void *), void *p) {
	pthread_t ret;
	int s = pthread_create(&ret, NULL, fn, p);
	if (s != 0)
		abort();
#ifdef __GLIBC__
	if (name)
		pthread_setname_np(ret, name);
#endif
	return ret;
}


static inline long long us_ticks_scale(long long val) {
	return val * ticks_per_sec / 1000000;
}
static inline long long now_us(void) {
	struct timeval now;
	gettimeofday(&now, NULL);
	return timeval_us(&now);
}


// stream is locked
static void dump_close(struct stream *s) {
	if (!s->fmtctx)
		return;

	av_write_trailer(s->fmtctx);
	avio_closep(&s->fmtctx->pb);
	avformat_free_context(s->fmtctx);
	s->fmtctx = NULL;
}

// stream is locked
static int got_packet_pkt(struct stream *s, AVPacket *pkt) {
	pkt->pts = pkt->dts = s->output_ts;
	s->output_ts += pkt->duration;

	ssize_t ret = write(s->output_fd, pkt->data, pkt->size);
	(void)ret;

	long long now = now_us();
	long long diff = now - s->encoding_start;

	{
		LOCK(&delay_stats_lock);
		if (delay_stats.max_actual < diff)
			delay_stats.max_actual = diff;
		if (delay_stats.max_allowed && diff < delay_stats.max_allowed) {
			uint slot = diff * delay_stats.slots / delay_stats.max_allowed;
			delay_stats.counts[slot]++;
		}
	}

	if (s->fmtctx) {
		// mkv uses millisecond timestamps
		pkt->pts = pkt->dts = av_rescale(pkt->pts, 1000, out_params.clock_rate);
		av_write_frame(s->fmtctx, pkt);
		avio_flush(s->fmtctx->pb);

		s->dump_count++;
		if (s->dump_count >= s->in_params.fixture->len) {
			// not technically correct as input frames may not match output frames
			dump_close(s);
		}
	}

	av_packet_unref(pkt);

	return 0;
}

// stream is locked
static int got_packet(encoder_t *encoder, void *p1, void *p2) {
	AVPacket *pkt = encoder->avpkt;
	return got_packet_pkt(p1, pkt);
}

static int got_frame(decoder_t *decoder, AVFrame *frame, void *p1, void *b) {
	struct stream *s = p1;
	encoder_input_fifo(s->encoder, frame, got_packet, s, NULL);
	av_frame_free(&frame);
	return 0;
}


static void *worker(void *p) {
	thread_cancel_disable();
	worker_self = p;
	worker_self->pid = gettid();
	{
		LOCK(&other_threads_lock);
		g_hash_table_insert(worker_threads, GINT_TO_POINTER(worker_self->pid), NULL);
	}
	poller_loop(rtpe_poller);
	return NULL;
}

static void readable(int fd, void *o) {
	struct stream *s = o;
	obj_hold(s);

	long long start = now_us();

	static const uint64_t max_iters = 10; // hard upper limit for iterations
	uint64_t total_iters = 0;

	while (true) {
		uint64_t exp;
		ssize_t ret = read(fd, &exp, sizeof(exp));
		if (ret != sizeof(exp)) {
			if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;
			abort();
		}

		// workers falling behind timer?
		if (exp >= 2) {
			worker_self->blocked = true;
			if (exp > max_iters)
				exp = max_iters;
		}
		if (total_iters++ > max_iters)
			break; // bail

		while (exp) {
			LOCK(&s->lock);

			s->encoding_start = start;

			AVPacket *data = s->in_params.fixture->pdata[s->fixture_idx++];
			if (s->fixture_idx >= s->in_params.fixture->len)
				s->fixture_idx = 0;

			str frame;
			frame = STR_LEN(data->data, data->size);

			if (!s->chain)
				decoder_input_data(s->decoder, &frame, s->input_ts, got_frame, s, NULL);
			else {
				AVPacket *pkt = codec_cc_input_data(s->chain, &frame, s->input_ts, s, NULL, NULL);
				if (pkt)
					got_packet_pkt(s, pkt);
				else
					mutex_lock(&s->lock); // was unlocked by async_init
			}

			s->input_ts += data->duration;

			exp--;
		}
	}

	obj_put(s);

	long long end = now_us();

	LOCK(&worker_self->comput_lock);
	worker_self->comput += end - start;
}

static void closed(int fd, void *o) {
	abort();
}


static void new_threads(uint num) {
	while (num--) {
		struct worker *w = g_slice_alloc0(sizeof(*w));

		mutex_init(&w->comput_lock);

		w->thr = thread_new("worker", worker, w);

		LOCK(&workers_lock);
		g_queue_push_tail(&workers, w);
	}
}
static void kill_threads(uint num) {
	GQueue to_join = G_QUEUE_INIT;

	struct worker *w;

	while (num--) {
		{
			LOCK(&workers_lock);
			w = g_queue_pop_tail(&workers);
			if (!w)
				break;
		}

		pthread_cancel(w->thr);
		g_queue_push_tail(&to_join, w);
	}

	while ((w = g_queue_pop_head(&to_join))) {
		pthread_join(w->thr, NULL);
		g_slice_free1(sizeof(*w), w);
	}
}


static void stream_free(struct stream *s) {
	close(s->output_fd);
	dump_close(s);
	if (s->encoder)
		encoder_free(s->encoder);
	if (s->decoder)
		decoder_close(s->decoder);
	g_free(s->type);
}


static void *async_init(void *x, void *y, void *z) {
	struct stream *s = x;
	// unlock in case the chain is busy and this blocks, so that whoever keeps the chain
	// busy can lock the stream once the result is in
	mutex_unlock(&s->lock);
	return obj_hold(s);
}
static void async_finish(AVPacket *pkt, void *async_cb_obj) {
	struct stream *s = async_cb_obj;
	{
		LOCK(&s->lock);
		got_packet_pkt(s, pkt);
	}
	obj_put(s);
	av_packet_free(&pkt);
}

static void new_stream_params(
		const codec_def_t *in_def,
		const struct testparams *inprm,
		const codec_def_t *out_def,
		const struct testparams *outprm
) {
	__auto_type s = obj_alloc0(struct stream, stream_free);

	// create timerfd
	s->timer_fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	if (s->timer_fd == -1)
		abort();

	// create dummy output fd
	s->output_fd = open("/dev/null", O_WRONLY);
	if (s->output_fd == -1)
		abort();

	// init contents
	s->in_params = *inprm;
	s->out_params = *outprm;
	s->fixture_idx = ssl_random() % s->in_params.fixture->len;
	mutex_init(&s->lock);
	s->type = g_strdup_printf("%s -> %s", inprm->name, outprm->name);

	// create decoder and encoder

	format_t dec_format = {
		.clockrate = inprm->clock_rate,
		.channels = inprm->channels,
		.format = -1,
	};

	format_t enc_format = {
		.clockrate = outprm->clock_rate,
		.channels = outprm->channels,
		.format = -1,
	};

	int bitrate = encoder_def->default_bitrate;

	format_t actual_enc_format;

	s->chain = codec_cc_new(in_def, &dec_format, out_def, &enc_format, bitrate, 20, async_init, async_finish);

	if (!s->chain) {
		s->encoder = encoder_new();
		int res = encoder_config_fmtp(s->encoder, out_def, bitrate, 20, &dec_format, &enc_format,
				&actual_enc_format,
				NULL, NULL, NULL);
		assert(res == 0); // TODO: handle failures gracefully

		s->decoder = decoder_new_fmtp(in_def, dec_format.clockrate, dec_format.channels, 20,
				&actual_enc_format, NULL, NULL, NULL); // TODO: support different options (fmtp etc)
		assert(s->decoder != NULL); // TODO: handle failures gracefully
	}

	// arm timer
	struct itimerspec timer = {
		.it_interval = {
			.tv_sec = 0,
			.tv_nsec = ptime * 1000,
		},
		.it_value = {
			.tv_sec = 0,
			(ssl_random() % ptime) * 1000,
		},
	};
	int res = timerfd_settime(s->timer_fd, 0, &timer, NULL);
	if (res != 0)
		abort();

	struct poller_item pi = {
		.fd = s->timer_fd,
		.obj = &s->obj,
		.readable = readable,
		.closed = closed,
	};

	bool ok = poller_add_item(rtpe_poller, &pi);
	assert(ok == true);

	LOCK(&streams_lock);
	g_ptr_array_add(streams, s);
	uint *count = g_hash_table_lookup(stream_types, s->type);
	if (!count) {
		count = g_malloc0(sizeof(*count));
		g_hash_table_insert(stream_types, g_strdup(s->type), count);
	}
	(*count)++;
}


static void new_stream(void) {
	new_stream_params(decoder_def, &in_params, encoder_def, &out_params);
	if (bidirectional)
		new_stream_params(encoder_def, &out_params, decoder_def, &in_params);
}


static void new_streams(uint num) {
	while (num--)
		new_stream();
}


static void del_stream(void) {
	struct stream *s = NULL;
	{
		LOCK(&streams_lock);
		if (streams->len) {
			s = streams->pdata[streams->len - 1];
			g_ptr_array_set_size(streams, streams->len - 1);
			uint *count = g_hash_table_lookup(stream_types, s->type);
			if (count) {
				(*count)--;
				if (!*count)
					g_hash_table_remove(stream_types, s->type);
			}
		}
	}
	if (!s)
		return;

	poller_del_item(rtpe_poller, s->timer_fd);
	s->timer_fd = -1;

	obj_put(s);
}

static void del_streams_raw(uint num) {
	while (num--)
		del_stream();
}


static void del_streams(uint num) {
	if (bidirectional)
		num *= 2;
	del_streams_raw(num);
}


static void set_streams(uint num) {
	if (bidirectional)
		num *= 2;

	while (true) {
		uint cur;
		{
			LOCK(&streams_lock);
			cur = streams->len;
		}
		if (cur == num)
			break;
		if (cur < num)
			new_stream();
		else
			del_stream();
	}
}


// curses_lock must be held
static void kill_popup(void) {
	if (!popup)
		return;
	delwin(popup);
	popup = NULL;
}


// curses_lock must be held
static void refresh_all(void) {
	wnoutrefresh(stdscr);
	if (popup) {
		touchwin(popup);
		wnoutrefresh(popup);
	}
	doupdate();
}


__attribute__((format(printf,1,2)))
static void show_popup(const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	char *s = g_strdup_vprintf(fmt, va);
	va_end(va);

	// split into lines and get max line length
	GQueue lines = G_QUEUE_INIT;
	str st = STR(s);
	str token;
	uint llen = 0;
	while (str_token_sep(&token, &st, '\n')) {
		g_queue_push_tail(&lines, str_dup(&token));
		llen = MAX(token.len, llen);
	}

	// render window

	{
		LOCK(&curses_lock);

		kill_popup();

		int maxx, maxy;
		getmaxyx(stdscr, maxy, maxx);

		int w = llen + 4, h = lines.length + 2;

		popup = newwin(h, w, (maxy - h) / 2, (maxx - w) / 2);
		box(popup, 0, 0);

		int linenum = 1;
		while (lines.length) {
			str *line = g_queue_pop_head(&lines);
			mvwprintw(popup, linenum++, 2, "%s", line->s);
			g_free(line);
		}

		refresh_all();
	}

	// wait for key and then kill it
	getch();

	{
		LOCK(&curses_lock);
		kill_popup();
		refresh_all();
	}
}


// streams_lock must be held
// returns g_malloc'd string
static char *start_dump_stream(struct stream *s, const char *suffix) {
	char *msg = NULL;
	const char *err = NULL;

	{
		LOCK(&s->lock);

		err = "Stream is already dumping";
		if (s->fmtctx)
			goto out;

		s->dump_count = 0;

		err = "Failed to allocate AVFormat";
		s->fmtctx = avformat_alloc_context();
		if (!s->fmtctx)
			goto out;
		g_autoptr(char) fn
			= g_strdup_printf("stream-dump-%llu%s.mkv",
					(long long unsigned) time(NULL),
					suffix ?: "");
		s->fmtctx->oformat = av_guess_format(NULL, fn, NULL);
		err = "Output format unknown to ffmpeg";
		if (!s->fmtctx->oformat)
			goto out;
		err = "Failed to add output audio stream";
		s->avst = avformat_new_stream(s->fmtctx, avcodec_find_encoder(s->out_params.codec_id));
		if (!s->avst)
			goto out;

		s->avst->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
		s->avst->codecpar->codec_id = s->out_params.codec_id;
		DEF_CH_LAYOUT(&s->avst->codecpar->CH_LAYOUT, s->out_params.channels);
		s->avst->codecpar->sample_rate = s->out_params.clock_rate;
		s->avst->time_base = (AVRational) {1, s->out_params.clock_rate}; // TODO: is this the correct time base?

		err = NULL;
		int ret = avio_open(&s->fmtctx->pb, fn, AVIO_FLAG_WRITE);
		if (ret < 0) {
			msg = g_strdup_printf("Failed to open output file '%s'", fn);
			goto out;
		}
		err = "Failed to write file header";
		ret = avformat_write_header(s->fmtctx, NULL);
		if (ret < 0)
			goto out;

		msg = g_strdup_printf("Started dumping to file '%s'", fn);
		err = NULL;
	}

out:
	if (err) {
		g_free(msg);
		return g_strdup(err);
	}

	return msg;
}


static void start_dump(void) {
	char *msg1 = NULL, *msg2 = NULL;
	const char *err = NULL;
	uint idx;

	{
		LOCK(&streams_lock);
		err = "No active streams to dump";
		if (!streams->len)
			goto out;

		uint len = streams->len;
		if (bidirectional) {
			assert((len % 2) == 0); // must be an even number
			len /= 2;
		}

		err = NULL;

		idx = ssl_random() % len;
		if (!bidirectional)
			msg1 = start_dump_stream(streams->pdata[idx], NULL);
		else {
			msg1 = start_dump_stream(streams->pdata[idx],     "-fwd");
			msg2 = start_dump_stream(streams->pdata[idx + 1], "-rev");
		}
	}

out:
	if (err)
		show_popup("%s", err);
	else {
		assert(msg1 != NULL);
		if (msg2)
			show_popup("Stream %u: %s\nStream %u: %s", idx, msg1, idx + 1, msg2);
		else
			show_popup("Stream %u: %s", idx, msg1);
	}

	g_free(msg1);
	g_free(msg2);
}


static void show_help(void) {
	show_popup(
		"ESC     exit                     1    CPU usage\n"
		"[ ]     -/+ 1 thread             2    realtime\n"
		"{ }     -/+ 10 threads           c    CPU stats\n"
		"q w e   +1/10/100 streams        t    other threads\n"
		"a s d   -1/10/100 streams        o    start dump\n"
		"                                 l    show log"
	);
}


static void show_log(void) {
	int h, w;

	{
		LOCK(&curses_lock);

		kill_popup();

		int maxx, maxy;
		getmaxyx(stdscr, maxy, maxx);

		w = maxx - 4;
		h = maxy - 4;

		popup = newwin(h, w, (maxy - h) / 2, (maxx - w) / 2);
		box(popup, 0, 0);

		GQueue *log = get_log_lines(h - 2, 0);
		char *line;
		int y = 1;
		while ((line = g_queue_pop_head(log))) {
			mvwprintw(popup, y++, 2, "%.*s", w - 2, line);
			g_free(line);
		}

		refresh_all();
	}

	getch();

	{
		LOCK(&curses_lock);
		kill_popup();
		refresh_all();
	}
}


static void *do_input(void *p) {
	while (true) {
		thread_cancel_enable();
		int ch = getch();
		thread_cancel_disable();

		switch (ch) {
			case 27: // escape
				return NULL;

			case ']':
				new_threads(1);
				break;

			case '[':
				kill_threads(1);
				break;

			case '}':
				new_threads(10);
				break;

			case '{':
				kill_threads(10);
				break;

			case 'q':
				new_streams(1);
				break;

			case 'w':
				new_streams(10);
				break;

			case 'e':
				new_streams(100);
				break;

			case 'a':
				del_streams(1);
				break;

			case 's':
				del_streams(10);
				break;

			case 'd':
				del_streams(100);
				break;

			case '1':
				output_fn = usage_bar;
				delay_out_fn = no_delay;
				break;

			case '2':
				output_fn = time_bar;
				delay_out_fn = no_delay;
				break;

			case '3':
				output_fn = no_bar;
				delay_out_fn = delay_bar;
				break;

			case 'o':
				start_dump();
				break;

			case 'c':
				do_cpu_stats = !do_cpu_stats;
				break;

			case 't':
				do_thread_stats = !do_thread_stats;
				break;

			case KEY_F(1):
			case 'h':
			case 'H':
			case '?':
				show_help();
				break;

			case 'l':
				show_log();
				break;
		}
	}

	return NULL;
}


static void head_tail_bar(int x, int line, int *width, int head, int tail, int *col0, int *colt) {
	*col0 = x + head;
	*width -= tail;
	*colt = x + *width;
	*width -= head;
}


static void usage_bar(const struct stats *stats, int line, int x, int breadth, int width, int color,
		const char *titlefmt, ...)
{
	static const int head = 13;
	static const int tail = 15;

	int col0, colt;
	head_tail_bar(x, line, &width, head, tail, &col0, &colt);

	int uw = stats->iv ? stats->ucpu * width / stats->iv : 0;
	int sw = stats->iv ? stats->scpu * width / stats->iv : 0;
	int iw = MAX(width - uw - sw, 0);

	int up = stats->iv ? stats->ucpu * 100 / stats->iv : 0;
	int sp = stats->iv ? stats->scpu * 100 / stats->iv : 0;
	int ip = MAX(100 - up - sp, 0);

	va_list vp;
	va_start(vp, titlefmt);

	move(line, x);
	vw_printw(stdscr, titlefmt, vp);

	va_end(vp);

	int extra_bits = 0;
	if (stats->blocked)
		extra_bits |= COLOR_PAIR(BLOCKED_COLOR);
	else if (color)
		extra_bits |= COLOR_PAIR(color);

	for (int br = 0; br < breadth; br++) {
		move(line + br, col0);

		attron(A_BOLD | extra_bits);
		for (int i = 0; i < uw; i++)
			addstr("▓");
		attroff(A_BOLD | extra_bits);

		attron(A_DIM | extra_bits);
		for (int i = 0; i < sw; i++)
			addstr("░");
		attroff(A_DIM | extra_bits);

		attron(A_DIM | extra_bits);
		for (int i = 0; i < iw; i++)
			addstr("·");
		attroff(A_DIM | extra_bits);
	}

	mvprintw(line, colt, "%3u%%/%3u%%/%3u%%", up, sp, ip);
}

static void time_bar(const struct stats *stats, int line, int x, int breadth, int width, int color,
		const char *titlefmt, ...)
{
	static const int head = 13;
	static const int tail = 10;

	int col0, colt;
	head_tail_bar(x, line, &width, head, tail, &col0, &colt);

	long long comput = us_ticks_scale(stats->comput);

	int uw = stats->iv ? comput * width / stats->iv : 0;
	int iw = MAX(width - uw, 0);

	int up = stats->iv ? comput * 100 / stats->iv : 0;
	int ip = MAX(100 - up, 0);

	va_list vp;
	va_start(vp, titlefmt);

	move(line, x);
	vw_printw(stdscr, titlefmt, vp);

	va_end(vp);

	int extra_bits = 0;
	if (stats->blocked)
		extra_bits |= COLOR_PAIR(BLOCKED_COLOR);
	else if (color)
		extra_bits |= COLOR_PAIR(color);

	for (int br = 0; br < breadth; br++) {
		move(line + br, col0);

		attron(A_BOLD | extra_bits);
		for (int i = 0; i < uw; i++)
			addstr("▓");
		attroff(A_BOLD | extra_bits);

		attron(A_DIM | extra_bits);
		for (int i = 0; i < iw; i++)
			addstr("·");
		attroff(A_DIM | extra_bits);
	}

	mvprintw(line, colt, "%3u%%/%3u%%", up, ip);
}


static void no_bar(const struct stats *stats, int line, int x, int breadth, int width, int color,
		const char *titlefmt, ...)
{
}


static bool thread_collect(pid_t pid, struct stats *outp, struct stats_sample *sample,
		char comm_out[COMM_SIZE])
{
	if (!pid)
		return false;

	g_autoptr(char) fn
		= g_strdup_printf("/proc/%i/task/%i/stat", (int) pid, (int) pid);
	g_autoptr(FILE) fp = fopen(fn, "r");
	if (!fp)
		return false;

	long long now = now_us();

	long long utime, stime;
	char comm[COMM_SIZE];
	int rets = fscanf(fp, "%*d (%" COMM_SIZE_SCAN "[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lld %lld ",
			comm, &utime, &stime);
	if (rets != 3)
		return false;

	if (sample->ts) {
		outp->iv = us_ticks_scale(now - sample->ts);
		outp->ucpu = utime - sample->stats.ucpu;
		outp->scpu = stime - sample->stats.scpu;
	}

	sample->ts = now;
	sample->stats.ucpu = utime;
	sample->stats.scpu = stime;

	if (comm_out)
		strcpy(comm_out, comm);

	return true;
}


// worker_lock is held
static void worker_collect(struct worker *w, struct stats *outp) {
	if (!thread_collect(w->pid, outp, &w->sample, NULL))
		return;

	outp->blocked = w->blocked;
	w->blocked = false;

	LOCK(&w->comput_lock);
	outp->comput = w->comput;
	w->comput = 0;
}


static void bar_grid(uint num, int maxx, int *height, int *width) {
	if (maxx < 104) {
		*height = num;
		*width = maxx;
		return;
	}

	*height = (num + 1) / 2;
	*width = maxx / 2 - 1;
}

static void grid_line(int *y, int *x, int starty, int height, int maxx) {
	if (*y > height + starty - 1) {
		*y = starty;
		*x = (maxx + 1) / 2 + 1;
	}
	(*y)++;
}


static void workers_totals(const struct stats *stats, struct stats *totals) {
	if (!totals)
		return;

	totals->iv += stats->iv;
	totals->ucpu += stats->ucpu;
	totals->scpu += stats->scpu;
	totals->comput += stats->comput;
}


// worker_lock is held
static void worker_stats(struct worker *w, int idx, int starty, int height, int width,
		int breadth,
		int *y,
		int *x,
		int maxy,
		int maxx,
		struct stats *totals)
{
	struct stats stats = {0};

	worker_collect(w, &stats);
	workers_totals(&stats, totals);

	grid_line(y, x, starty, height, maxx);

	if (*y < maxy)
		output_fn(&stats, *y, *x, breadth, width, 0, "Thread %2u:", idx);
}


TYPED_GQUEUE(stats, struct stats)

static void stats_queue_free(stats_q *q) {
	struct stats *sp;
	while ((sp = t_queue_pop_head(q)))
		g_slice_free1(sizeof(*sp), sp);
	t_queue_free(q);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(stats_q, stats_queue_free)


static bool cpu_collect(stats_q *outp, struct stats *totals) {
	g_autoptr(FILE) fp = fopen("/proc/stat", "r");
	if (!fp)
		return false;

	while (!feof(fp)) {
		long long now = now_us();

		char cpu[7];
		long long utime, nice, stime;
		int rets = fscanf(fp, "%6s %lld %lld %lld ", cpu, &utime, &nice, &stime);
		if (rets != 4)
			continue;
		utime += nice;
		uint idx;
		rets = sscanf(cpu, "cpu%u", &idx);
		if (rets != 1)
			continue;
		if (idx >= num_cpus)
			break;

		struct stats stats = {0};

		if (cpu_stats[idx].ts) {
			stats.iv = us_ticks_scale(now - cpu_stats[idx].ts);
			stats.ucpu = utime - cpu_stats[idx].stats.ucpu;
			stats.scpu = stime - cpu_stats[idx].stats.scpu;
		}

		cpu_stats[idx].ts = now;
		cpu_stats[idx].stats.ucpu = utime;
		cpu_stats[idx].stats.scpu = stime;

		if (totals) {
			totals->iv += stats.iv;
			totals->ucpu += stats.ucpu;
			totals->scpu += stats.scpu;
		}

		if (outp) {
			struct stats *sp = g_slice_alloc(sizeof(*sp));
			*sp = stats;
			t_queue_push_tail(outp, sp);
		}
	}

	return true;
}


static int cpu_collect_stats(const bool do_output, int starty, int maxy, int maxx, struct stats *totals) {
	g_autoptr(stats_q) stats = do_output ? stats_q_new() : NULL;

	if (!cpu_collect(stats, totals))
		return starty;

	if (!do_output)
		return starty;

	int height, width;
	bar_grid(num_cpus, maxx, &height, &width);

	int y = starty;
	int x = 0;

	uint idx = 0;
	for (__auto_type l = stats->head; l; l = l->next) {
		struct stats *sp = l->data;
		grid_line(&y, &x, starty, height, maxx);
		if (y < maxy)
			usage_bar(sp, y, x, 1, width, CPU_COLOR, "CPU %2u:", idx);
		idx++;
	}

	return starty + height;
}


static void delay_stats_collect(struct delay_stats *local, uint slots, long long max_allowed) {
	{
		// copy out and reset to zero
		LOCK(&delay_stats_lock);
		*local = delay_stats;

		delay_stats = (struct delay_stats) {0};
		delay_stats.slots = slots;
		delay_stats.counts = g_new0(__typeof__(*delay_stats.counts), delay_stats.slots);
		delay_stats.max_allowed = max_allowed;
	}
}

static void delay_stats_free(struct delay_stats *local) {
	g_free(local->counts);
}


static void no_delay(const struct delay_stats *stats, int line, int x, int breadth, int width) {
}

static void delay_bar(const struct delay_stats *stats, int line, int x, int breadth, int width) {
	if (!stats->slots)
		return;

	uint per_slot = stats->max_allowed / stats->slots;

	for (uint i = 0; i < stats->slots; i++) {
		move(line, x);
		uint start = i * stats->max_allowed / stats->slots;
		printw("%3.1f ms - %3.1f ms: %u", start / 1000., (start + per_slot) / 1000., stats->counts[i]);
		line++;
	}
}


static void other_thread_free(struct other_thread *thr) {
	g_slice_free1(sizeof(*thr), thr);
}

static int pid_compare(const void *a, const void *b) {
	pid_t A = GPOINTER_TO_INT(a);
	pid_t B = GPOINTER_TO_INT(b);
	if (A < B)
		return -1;
	if (B < A)
		return 1;
	return 0;
}

static int other_threads_collect(const bool do_output, int starty, int maxy, int maxx,
		struct stats *totals)
{
	g_autoptr(char) dn = g_strdup_printf("/proc/%u/task", getpid());
	g_autoptr(DIR) dp = opendir(dn);
	if (!dp)
		return starty;

	int y = starty;

	LOCK(&other_threads_lock);

	// track which threads we should delete
	GHashTable *tracker = g_hash_table_new(g_direct_hash, g_direct_equal);
	// and a sorted list for output
	GTree *tree = g_tree_new(pid_compare);

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, other_threads);
	void *p;
	while (g_hash_table_iter_next(&iter, &p, NULL))
		g_hash_table_insert(tracker, p, NULL);

	struct dirent *ent;
	while ((ent = readdir(dp))) {
		if (ent->d_name[0] == '.')
			continue;
		pid_t pid = strtol(ent->d_name, NULL, 10);
		if (!pid)
			continue;

		// skip excluded threads (workers)
		if (g_hash_table_contains(worker_threads, GINT_TO_POINTER(pid)))
			continue;

		// skip PIDs already seen. (shouldn't happen)
		if (g_tree_lookup_extended(tree, GINT_TO_POINTER(pid), NULL, NULL))
			continue;

		// object already exists?
		struct other_thread *thr = g_hash_table_lookup(other_threads, GINT_TO_POINTER(pid));
		if (!thr) {
			thr = g_slice_alloc0(sizeof(*thr));
			g_hash_table_insert(other_threads, GINT_TO_POINTER(pid), thr);
		}

		// collect stats
		if (!thread_collect(pid, &thr->stats, &thr->sample, thr->comm))
			continue;

		// track as active thread
		g_hash_table_remove(tracker, GINT_TO_POINTER(pid));
		g_tree_insert(tree, GINT_TO_POINTER(pid), thr);
	}

	// finally delete leftovers
	g_hash_table_iter_init(&iter, tracker);
	while (g_hash_table_iter_next(&iter, &p, NULL))
		g_hash_table_remove(other_threads, p);

	int height = 0;

	if (do_output) {
		// output based on sorted list
		GQueue threads = G_QUEUE_INIT;
		g_tree_get_values(&threads, tree);

		int width;
		bar_grid(threads.length, maxx, &height, &width);

		int x = 0;

		struct other_thread *thr;
		while ((thr = g_queue_pop_head(&threads))) {
			grid_line(&y, &x, starty, height, maxx);
			if (y < maxy)
				usage_bar(&thr->stats, y, x, 1, width, THREAD_COLOR, "%s:", thr->comm);
		}
	}

	g_hash_table_destroy(tracker);
	g_tree_destroy(tree);

	return starty + height;
}


static void *do_stats(void *p) {
	thread_cancel_disable();

	while (true) {
		{
			// init
			LOCK(&curses_lock);

			erase();

			int maxx, maxy;
			getmaxyx(stdscr, maxy, maxx);

			// top line summary
			mvprintw(0, 0, "Threads: %u | ", workers.length);

			{
				LOCK(&streams_lock);
				addstr("Streams: ");
				if (streams->len == 0)
					addstr("0");
				else {
					GHashTableIter iter;
					g_hash_table_iter_init(&iter, stream_types);
					char *t;
					uint *n;
					while (g_hash_table_iter_next(&iter, (gpointer *) &t, (gpointer *) &n))
						printw("%s: %u | ", t, *n);
					if (g_hash_table_size(stream_types) > 1) {
						if (bidirectional)
							printw("Total: %u streams (%u bidirectional calls)",
									streams->len, streams->len / 2);
						else
							printw("Total: %u unidirectional streams",
									streams->len);
					}
					else {
						int y, x;
						getyx(stdscr, y, x);
						mvaddstr(y, x - 2, "  ");
					}
				}
			}

			// CPU stats, collect and display if enabled
			int line = 2;

			int totals_line = line;
			struct stats cpu_totals = {0};

			line = cpu_collect_stats(do_cpu_stats, line, maxy, maxx, &cpu_totals);

			if (do_cpu_stats) {
				output_fn(&cpu_totals, totals_line, 0, 1, maxx, SUMMARY_COLOR, "CPUs:");
				line += 2;
			}

			// other threads stats, collect and display if enabled
			totals_line = line;
			struct stats thread_totals = {0};
			line = other_threads_collect(do_thread_stats, line, maxy, maxx, &thread_totals);

			if (do_thread_stats) {
				output_fn(&thread_totals, totals_line, 0, 1, maxx, SUMMARY_COLOR, "Threads:");
				line += 2;
			}

			// collect delay stats
			struct delay_stats delay_stats_local;
			delay_stats_collect(&delay_stats_local, maxy - 3, 20000);

			// worker thread stats
			totals_line = line;
			struct stats worker_totals = {0};

			int breadth = 1;
			int double_thresh = (maxy - line) / 3;

			{
				LOCK(&workers_lock);
				uint idx = 0;

				int height = maxy - line;
				int width = maxx;
				int inc = 0;

				if (workers.length < double_thresh) {
					inc = 2;
					breadth = 2;
					line += 2;
				}
				else if (workers.length < height)
					inc = 0;
				else
					bar_grid(workers.length, maxx, &height, &width);

				int y = line;
				int x = 0;

				for (GList *l = workers.head; l; l = l->next) {
					struct worker *w = l->data;
					worker_stats(w, idx, line, height, width, breadth, &y, &x, maxy, maxx,
							&worker_totals);
					idx++;
					y += inc;
				}
			}

			output_fn(&worker_totals, totals_line, 0, breadth, maxx, SUMMARY_COLOR, "Threads:");

			delay_out_fn(&delay_stats_local, totals_line, 0, breadth, maxx);

			refresh_all();

			delay_stats_free(&delay_stats_local);
		}

		thread_cancel_enable();
		usleep(500000);
		thread_cancel_disable();
	}

	return NULL;
}

static char *fixture_path_file(const char *base_fn) {
	if (base_fn[0] == '/')
		return g_strdup(base_fn);
	return g_strdup_printf("%s/%s", FIXTURES_PATH, base_fn);
}

static void fixture_read_avio(GPtrArray *fixture, struct testparams *prm) {
	AVFormatContext *fctx = NULL;
	g_autoptr(char) fn = fixture_path_file(prm->file);
	int ret = avformat_open_input(&fctx, fn, NULL, NULL);
	if (ret < 0)
		die("Failed to open input fixture");

	avformat_find_stream_info(fctx, NULL);

	AVStream *avst = fctx->streams[0];
	if (!avst)
		die("No streams found in input fixture");

	while (true) {
		AVPacket *pkt = av_packet_alloc();
		if (!pkt)
			die("Failed to allocate AVPacket");
		ret = av_read_frame(fctx, pkt);
		if (ret < 0) {
			if (ret == AVERROR_EOF)
				break;
			die("Read error while reading input fixture");
		}
		g_ptr_array_add(fixture, pkt);
	}

	avformat_close_input(&fctx);
}


static void fixture_read_raw(GPtrArray *fixture, struct testparams *prm) {
	g_autoptr(char) fn = fixture_path_file(prm->file);
	FILE *fp = fopen(fn, "r");
	if (!fp)
		die("Failed to open input fixture");

	while (true) {
		AVPacket *pkt = av_packet_alloc();
		if (!pkt)
			die("Failed to allocate AVPacket");
		void *buf = av_malloc(160); // TODO: adapt for different ptimes/sample rates
		if (!buf)
			die("Out of memory");
		size_t ret = fread(buf, 160, 1, fp); // TODO: adapt for different ptimes/sample rates
		if (ret != 1) {
			if (feof(fp))
				break;
			die("Read error while reading input fixture");
		}
		pkt->duration = 160; // TODO: adapt for different ptimes/sample rates
		av_packet_from_data(pkt, buf, 160); // TODO: adapt for different ptimes/sample rates
		g_ptr_array_add(fixture, pkt);
	}

	fclose(fp);
}


static void load_fixture(struct testparams *prm) {
	prm->fixture = g_ptr_array_new();
	prm->read_fn(prm->fixture, prm);
}


static void free_fixture(GPtrArray *fixture) {
	if (!fixture)
		return;
	for (uint idx = 0; idx < fixture->len; idx++)
		av_packet_free((AVPacket **) &fixture->pdata[idx]);
	g_ptr_array_free(fixture, TRUE);
}


static void options(int *argc, char ***argv) {
	GOptionEntry e[] = {
		{
			.long_name = "source",
			.short_name = 's',
			.arg = G_OPTION_ARG_STRING,
			.arg_data = &source_codec,
			.description = "Source (input) codec",
			.arg_description = "PCMA|opus",
		},
		{
			.long_name = "dest",
			.short_name = 'd',
			.arg = G_OPTION_ARG_STRING,
			.arg_data = &dest_codec,
			.description = "Destination (output) codec",
			.arg_description = "opus|PCMA",
		},
		{
			.long_name = "threads",
			.short_name = 't',
			.arg = G_OPTION_ARG_INT,
			.arg_data = &init_threads,
			.description = "initial number of worker threads",
			.arg_description = "INT",
		},
		{
			.long_name = "bidirectional",
			.short_name = 'b',
			.arg = G_OPTION_ARG_NONE,
			.arg_data = &bidirectional,
			.description = "Create transcoding streams both ways",
		},
		{
			.long_name = "max-cpu",
			.short_name = 'm',
			.arg = G_OPTION_ARG_INT,
			.arg_data = &max_cpu,
			.description = "Automated test up to x% CPU",
			.arg_description = "INT",
		},
		{
			.long_name = "system-cpu",
			.short_name = 's',
			.arg = G_OPTION_ARG_NONE,
			.arg_data = &system_cpu,
			.description = "Consider system CPU usage for automated tests",
		},
		{
			.long_name = "break-in",
			.arg = G_OPTION_ARG_INT,
			.arg_data = &break_in,
			.description = "Break-in time in ms before measuring for automated tests",
			.arg_description = "INT",
		},
		{
			.long_name = "measure-time",
			.arg = G_OPTION_ARG_INT,
			.arg_data = &measure_time,
			.description = "Duration of automated tests in ms",
			.arg_description = "INT",
		},
		{
			.long_name = "repeats",
			.arg = G_OPTION_ARG_INT,
			.arg_data = &repeats,
			.description = "Number of times to repeat automated test",
			.arg_description = "INT",
		},
		{
			.long_name = "cpu-freq",
			.arg = G_OPTION_ARG_NONE,
			.arg_data = &cpu_freq,
			.description = "Monitor CPU frequencies during automated test",
		},
		{
			.long_name = "freq-granularity",
			.arg = G_OPTION_ARG_INT,
			.arg_data = &freq_granularity,
			.description = "Granularity in ms for measuring CPU frequencies",
			.arg_description = "INT",
		},
		{ NULL, }
	};

	config_load(argc, argv, e, " - rtpengine performance tester",
			"/etc/rtpengine/rtpengine-perftest.conf", "rtpengine-perftest", &rtpe_common_config);

	if (init_threads <= 0)
		init_threads = num_cpus;
	if (init_threads <= 0)
		init_threads = 1;

	if (max_cpu > 100 || max_cpu < 0)
		die("Invalid `max-cpu` number given");
	if (freq_granularity <= 0)
		die("Invalid `freq-granularity` number given");
}


static bool find_params(struct testparams *prm, const char *name) {
	const struct testparams *p;
	for (int i = 0; i < G_N_ELEMENTS(testparams); i++) {
		p = &testparams[i];
		if (strcmp(p->name, name))
			continue;
		*prm = *p;
		return true;
	}
	return false;
}


static void interactive(void) {
	initscr();
	start_color();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	curs_set(0);
	set_escdelay(25);
	init_pair(BLOCKED_COLOR, COLOR_RED, COLOR_BLACK);
	init_pair(SUMMARY_COLOR, COLOR_GREEN, COLOR_BLACK);
	init_pair(CPU_COLOR, COLOR_BLUE, COLOR_BLACK);
	init_pair(THREAD_COLOR, COLOR_CYAN, COLOR_BLACK);

	refresh();

	new_threads(init_threads);

	pthread_t input_thread = thread_new("term input", do_input, NULL);
	pthread_t stats_thread = thread_new("stats", do_stats, NULL);

	// input handler is in control, wait for shutdown
	pthread_join(input_thread, NULL);

	pthread_cancel(stats_thread);
	pthread_join(stats_thread, NULL);
}


static void delay_measure_workers(uint milliseconds, struct stats *totals) {
	usleep(milliseconds * 1000);

	LOCK(&workers_lock);
	for (GList *l = workers.head; l; l = l->next) {
		struct worker *w = l->data;
		struct stats stats = {0};
		worker_collect(w, &stats);
		workers_totals(&stats, totals);
	}
}


static void *cpu_freq_monitor(void *p) {
	struct thread_freq_stats *freq_stats = p;

	while (true) {
		struct freq_stats iter_stats = {0};

		{
			g_autoptr(DIR) dp = opendir("/sys/devices/system/cpu/cpufreq");
			if (!dp)
				break; // bail out


			struct dirent *ent;
			while ((ent = readdir(dp))) {
				if (strncmp(ent->d_name, "policy", 6) != 0)
					continue; // skip

				g_autoptr(char) fn
					= g_strdup_printf("/sys/devices/system/cpu/cpufreq/%s/scaling_cur_freq",
							ent->d_name);
				g_autoptr(FILE) fp  = fopen(fn, "r");
				if (!fp)
					continue; // ignore

				long long freq;
				int rets = fscanf(fp, "%lld", &freq);
				if (rets != 1)
					continue; // ignore

				iter_stats.max = iter_stats.max ? MAX(iter_stats.max, freq) : freq;
				iter_stats.min = iter_stats.min ? MIN(iter_stats.min, freq) : freq;
				iter_stats.sum += freq;
				iter_stats.samples++;
			}
		}

		// done collecting, add to shared struct

		{
			LOCK(&freq_stats->lock);
			freq_stats->stats.max = freq_stats->stats.max
				? MAX(freq_stats->stats.max, iter_stats.max) : iter_stats.max;
			freq_stats->stats.min = freq_stats->stats.min
				? MIN(freq_stats->stats.min, iter_stats.min) : iter_stats.min;
			freq_stats->stats.sum += iter_stats.sum;
			freq_stats->stats.samples += iter_stats.samples;
		}

		thread_cancel_enable();
		usleep(freq_granularity * 1000);
		thread_cancel_disable();
	}

	return NULL;
}


static void max_cpu_test(void) {
	int max_cpu_scaled = max_cpu * 100000;

	new_threads(init_threads);

	uint test_num = 1;
	set_streams(test_num);

	pthread_t cpu_thread = 0;
	struct thread_freq_stats freq_stats = {.lock = MUTEX_STATIC_INIT};
	if (cpu_freq)
		cpu_thread = thread_new("CPU freq", cpu_freq_monitor, &freq_stats);

	int count = repeats;

	while (count > 0) {
		// initial break-in
		delay_measure_workers(break_in, NULL);
		cpu_collect(NULL, NULL);

		// measure
		struct stats totals = {0};
		if (!system_cpu)
			delay_measure_workers(measure_time, &totals);
		else {
			delay_measure_workers(measure_time, NULL);
			cpu_collect(NULL, &totals);
		}

		// CPU% x 100000
		int cpu = (totals.scpu + totals.ucpu) * 100 * 100000 / totals.iv;

		// CPU load per stream (% x 100000)
		int cps = cpu / test_num;

		if (cps == 0) {
			// not enough to have a useful value - double it
			test_num *= 2;
		}
		else {
			// predicted # streams for target CPU usage
			int target = max_cpu_scaled / cps;

			// how close are we to the target?
			int acc = test_num * 100 / target;

			if (acc >= 99 && acc <= 101) {
				printf("%.1f%% CPU usage doing %s %s %s with %u %s on %u threads\n",
						(float) cpu / 100000.0,
						in_params.name,
						bidirectional ? "<>" : "->",
						out_params.name,
						test_num,
						bidirectional
						? "bidirectional calls"
						: "unidirectional streams",
						workers.length);

				if (cpu_freq) {
					// retrieve stats and reset
					struct freq_stats stats;
					{
						LOCK(&freq_stats.lock);
						stats = freq_stats.stats;
						freq_stats.stats = (__typeof__(freq_stats.stats)) {0};
					}
					if (!stats.samples)
						printf("          (no CPU frequency stats collected)\n");
					else {
						printf("          CPU frequencies: "
								"%.2f <> %.2f GHz, avg %.2f GHz\n",
								(float) stats.min / 1000000.,
								(float) stats.max / 1000000.,
								(float) stats.sum / (float) stats.samples
									/ 1000000.);
					}
				}

				count--;
			}

			// scale to 50..100
			int factor = 50 + acc / 2;

			test_num = target * factor / 100;
		}

		set_streams(test_num);
	}

	if (cpu_thread) {
		pthread_cancel(cpu_thread);
		pthread_join(cpu_thread, NULL);
	}
}


int main(int argc, char **argv) {
	setlocale(LC_ALL, "");

	ticks_per_sec = sysconf(_SC_CLK_TCK);
	num_cpus = num_cpu_cores(1);
	cpu_stats = g_malloc0(sizeof(*cpu_stats) * num_cpus);
	other_threads = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			(GDestroyNotify) other_thread_free);
	worker_threads = g_hash_table_new(g_direct_hash, g_direct_equal);

	options(&argc, &argv);
	codeclib_init(0);
	rtpe_ssl_init();
	resources();

	streams = g_ptr_array_new();
	stream_types = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	rtpe_poller = poller_new();
	if (!rtpe_poller)
		die("Failed to create poller");

	decoder_def = codec_find(STR_PTR(source_codec), MT_AUDIO);
	if (!decoder_def)
		die("Codec definition for source codec not found");
	encoder_def = codec_find(STR_PTR(dest_codec), MT_AUDIO);
	if (!encoder_def)
		die("Codec definition for destination codec not found");

	if (!find_params(&in_params, source_codec))
		die("Definition for input fixture not found");
	if (!find_params(&out_params, dest_codec))
		die("Definition for output fixture not found");

	load_fixture(&in_params);
	if (bidirectional)
		load_fixture(&out_params);

	if (max_cpu)
		max_cpu_test();
	else
		interactive();

	kill_threads(workers.length);
	del_streams_raw(streams->len);
	g_ptr_array_free(streams, TRUE);
	g_hash_table_destroy(stream_types);
	g_hash_table_destroy(other_threads);
	g_hash_table_destroy(worker_threads);

	free_fixture(in_params.fixture);
	free_fixture(out_params.fixture);

	log_clear();

	endwin();

	return 0;
}
