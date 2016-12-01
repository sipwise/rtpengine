#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <glib.h>
#include <unistd.h>
#include <signal.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "log.h"
#include "epoll.h"
#include "inotify.h"
#include "metafile.h"
#include "garbage.h"
#include "loglib.h"
#include "auxlib.h"
#include "decoder.h"
#include "output.h"



int ktable = 0;
int num_threads = 8;
const char *spool_dir = "/var/spool/rtpengine";
const char *output_dir = "/var/lib/rtpengine-recording";
static const char *output_format = "wav";


static GQueue threads = G_QUEUE_INIT; // only accessed from main thread

volatile int shutdown_flag;


static void signals(void) {
	sigset_t ss;

	sigfillset(&ss);
	sigdelset(&ss, SIGABRT);
	sigdelset(&ss, SIGSEGV);
	sigdelset(&ss, SIGQUIT);
	sigprocmask(SIG_SETMASK, &ss, NULL);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);
}


static void avlog_ilog(void *ptr, int loglevel, const char *fmt, va_list ap) {
	char *msg;
	if (vasprintf(&msg, fmt, ap) <= 0)
		ilog(LOG_ERR, "av_log message dropped");
	else {
		ilog(MAX(LOG_ERR, loglevel), "av_log: %s", msg);
		free(msg);
	}
}


static void setup(void) {
	openlog("rtpengine-recording", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	log_init();
	av_register_all();
	avcodec_register_all();
	avformat_network_init();
	signals();
	metafile_setup();
	epoll_setup();
	inotify_setup();
	av_log_set_callback(avlog_ilog);
	output_init(output_format);

	if (!g_file_test(output_dir, G_FILE_TEST_IS_DIR)) {
		ilog(LOG_INFO, "Creating output dir '%s'", output_dir);
		if (mkdir(output_dir, 0700))
			die_errno("Failed to create output dir '%s'");
	}
}


static void start_poller_thread(void) {
	pthread_t *thr = g_slice_alloc(sizeof(*thr));
	int ret = pthread_create(thr, NULL, poller_thread,
			GUINT_TO_POINTER(garbage_new_thread_num()));
	if (ret)
		die_errno("pthread_create failed");

	g_queue_push_tail(&threads, thr);
}


static void wait_threads_finish(void) {
	pthread_t *thr;
	while ((thr = g_queue_pop_head(&threads))) {
		pthread_cancel(*thr);
		pthread_join(*thr, NULL);
		g_slice_free1(sizeof(*thr), thr);
	}
}


static void wait_for_signal(void) {
	sigset_t ss;
	int ret, sig;

	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);

	while (1) {
		ret = sigwait(&ss, &sig);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			abort();
		}
		shutdown_flag = 1;
		break;
	}
}


static void cleanup(void) {
	garbage_collect_all();
	metafile_cleanup();
	inotify_cleanup();
	epoll_cleanup();
}


static void options(int *argc, char ***argv) {
	GOptionEntry e[] = {
		{ "table",		't', 0, G_OPTION_ARG_INT,	&ktable,	"Kernel table rtpengine uses",		"INT"		},
		{ "spool-dir",		0,   0, G_OPTION_ARG_STRING,	&spool_dir,	"Directory containing rtpengine metadata files", "PATH" },
		{ "output-dir",		0,   0, G_OPTION_ARG_STRING,	&output_dir,	"Where to write media files to",	"PATH"		},
		{ "output-format",	0,   0, G_OPTION_ARG_STRING,	&output_format,	"Write audio files of this type",	"wav|mp3"	},
		{ "num-threads",	0,   0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads",		"INT"		},
		{ NULL, }
	};

	config_load(argc, argv, e, " - rtpengine recording daemon",
			"/etc/rtpengine/rtpengine-recording.conf", "rtpengine-recording");
}


int main(int argc, char **argv) {
	options(&argc, &argv);
	setup();
	daemonize();
	wpidfile();

	for (int i = 0; i < num_threads; i++)
		start_poller_thread();

	wait_for_signal();

	dbg("shutting down");

	wait_threads_finish();

	cleanup();
}
