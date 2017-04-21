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
#include <libavfilter/avfilter.h>
#include <libavutil/log.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mysql.h>
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
int output_mixed;
int output_single;
const char *c_mysql_host,
      *c_mysql_user,
      *c_mysql_pass,
      *c_mysql_db;
int c_mysql_port;


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
#ifdef AV_LOG_PANIC
		// translate AV_LOG_ constants to LOG_ levels
		if (loglevel >= AV_LOG_VERBOSE)
			loglevel = LOG_DEBUG;
		else if (loglevel >= AV_LOG_INFO)
			loglevel = LOG_NOTICE;
		else if (loglevel >= AV_LOG_WARNING)
			loglevel = LOG_WARNING;
		else if (loglevel >= AV_LOG_ERROR)
			loglevel = LOG_ERROR;
		else if (loglevel >= AV_LOG_FATAL)
			loglevel = LOG_CRIT;
		else
			loglevel = LOG_ALERT;
#else
		// defuse avlog log levels to be either DEBUG or ERR
		if (loglevel <= LOG_ERR)
			loglevel = LOG_ERR;
		else
			loglevel = LOG_DEBUG;
#endif
		ilog(loglevel, "av_log: %s", msg);
		free(msg);
	}
}


static void setup(void) {
	log_init("rtpengine-recording");
	av_register_all();
	avcodec_register_all();
	avfilter_register_all();
	avformat_network_init();
	mysql_library_init(0, NULL, NULL);
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
	mysql_library_end();
}


static void options(int *argc, char ***argv) {
	GOptionEntry e[] = {
		{ "table",		't', 0, G_OPTION_ARG_INT,	&ktable,	"Kernel table rtpengine uses",		"INT"		},
		{ "spool-dir",		0,   0, G_OPTION_ARG_STRING,	&spool_dir,	"Directory containing rtpengine metadata files", "PATH" },
		{ "num-threads",	0,   0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads",		"INT"		},
		{ "output-dir",		0,   0, G_OPTION_ARG_STRING,	&output_dir,	"Where to write media files to",	"PATH"		},
		{ "output-format",	0,   0, G_OPTION_ARG_STRING,	&output_format,	"Write audio files of this type",	"wav|mp3"	},
		{ "resample-to",	0,   0, G_OPTION_ARG_INT,	&resample_audio,"Resample all output audio",		"INT"		},
		{ "mp3-bitrate",	0,   0, G_OPTION_ARG_INT,	&mp3_bitrate,	"Bits per second for MP3 encoding",	"INT"		},
		{ "output-mixed",	0,   0, G_OPTION_ARG_NONE,	&output_mixed,	"Mix participating sources into a single output",NULL	},
		{ "output-single",	0,   0, G_OPTION_ARG_NONE,	&output_single,	"Create one output file for each source",NULL		},
		{ "mysql-host",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_host,	"MySQL host for storage of call metadata","HOST|IP"	},
		{ "mysql-port",		0,   0,	G_OPTION_ARG_INT,	&c_mysql_port,	"MySQL port"				,"INT"		},
		{ "mysql-user",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_user,	"MySQL connection credentials",		"USERNAME"	},
		{ "mysql-pass",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_pass,	"MySQL connection credentials",		"PASSWORD"	},
		{ "mysql-db",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_db,	"MySQL database name",			"STRING"	},
		{ NULL, }
	};

	config_load(argc, argv, e, " - rtpengine recording daemon",
			"/etc/rtpengine/rtpengine-recording.conf", "rtpengine-recording");

	if (!output_mixed && !output_single)
		output_mixed = output_single = 1;
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
