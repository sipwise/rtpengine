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
#include "log.h"
#include "epoll.h"
#include "inotify.h"
#include "metafile.h"
#include "garbage.h"
#include "loglib.h"
#include "auxlib.h"



int ktable = 0;
int num_threads = 8;
const char *spool_dir = "/var/spool/rtpengine";
const char *output_dir = "/var/lib/rtpengine-recording";

static const char *pidfile;
static int foreground;


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
	__vpilog(loglevel, NULL, fmt, ap);
}


static void setup(void) {
	log_init();
	av_register_all();
	avcodec_register_all();
	avformat_network_init();
	signals();
	metafile_setup();
	epoll_setup();
	inotify_setup();
	av_log_set_callback(avlog_ilog);
	openlog("rtpengine-recording", LOG_PID | LOG_NDELAY, LOG_DAEMON);
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
	char *configfile = NULL;
	char *configsection = "rtpengine-recording";

	GOptionEntry e[] = {
		{ "config-file",	0,   0, G_OPTION_ARG_STRING,	&configfile,	"Load config from this file",		"FILE"		},
		{ "config-section",	0,   0, G_OPTION_ARG_STRING,	&configsection,	"Config file section to use",		"STRING"	},
		{ "table",		't', 0, G_OPTION_ARG_INT,	&ktable,	"Kernel table rtpengine uses",		"INT"		},
		{ "spool-dir",		0,   0, G_OPTION_ARG_STRING,	&spool_dir,	"Directory containing rtpengine metadata files", "PATH" },
		{ "output-dir",		0,   0, G_OPTION_ARG_STRING,	&output_dir,	"Where to write media files to",	"PATH"		},
		{ "num-threads",	0,   0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads",		"INT"		},
		{ "log-level",		'L', 0, G_OPTION_ARG_INT,	(void *)&log_level,"Mask log priorities above this level","INT"		},
		{ "pidfile",		'p', 0, G_OPTION_ARG_FILENAME,	&pidfile,	"Write PID to file",			"FILE"		},
		{ "foreground",		'f', 0, G_OPTION_ARG_NONE,	&foreground,	"Don't fork to background",		NULL		},
		{ NULL, }
	};

	const char *errstr = config_load(argc, argv, e, " - rtpengine recording daemon", &configfile,
			"/etc/rtpengine/rtpengine-recording.conf", &configsection);
	if (errstr)
		die("Bad command line: %s", errstr);
}


int main(int argc, char **argv) {
	options(&argc, &argv);
	setup();
	if (!foreground)
		daemonize();
	wpidfile(pidfile);

	for (int i = 0; i < num_threads; i++)
		start_poller_thread();

	wait_for_signal();

	dbg("shutting down");

	wait_threads_finish();

	cleanup();
}
