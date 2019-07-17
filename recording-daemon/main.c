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
#include "forward.h"
#include "codeclib.h"
#include "socket.h"
#include "ssllib.h"



int ktable = 0;
int num_threads = 8;
enum output_storage_enum output_storage = OUTPUT_STORAGE_FILE;
const char *spool_dir = "/var/spool/rtpengine";
const char *output_dir = "/var/lib/rtpengine-recording";
static const char *output_format = "wav";
int output_mixed;
int output_single;
int output_enabled = 1;
int decoding_enabled;
const char *c_mysql_host,
      *c_mysql_user,
      *c_mysql_pass,
      *c_mysql_db;
int c_mysql_port;
const char *forward_to = NULL;
static const char *tls_send_to = NULL;
endpoint_t tls_send_to_ep;
int tls_resample = 8000;

static GQueue threads = G_QUEUE_INIT; // only accessed from main thread

volatile int shutdown_flag;

struct rtpengine_common_config rtpe_common_config;



static void signals(void) {
	sigset_t ss;

	sigfillset(&ss);
	sigdelset(&ss, SIGABRT);
	sigdelset(&ss, SIGSEGV);
	sigdelset(&ss, SIGQUIT);
	sigprocmask(SIG_SETMASK, &ss, NULL);
	pthread_sigmask(SIG_SETMASK, &ss, NULL);
}


static void setup(void) {
	log_init("rtpengine-recording");
	rtpe_ssl_init();
	socket_init();
	if (decoding_enabled)
		codeclib_init(0);
	if (output_enabled) {
		output_init(output_format);
		if (!g_file_test(output_dir, G_FILE_TEST_IS_DIR)) {
			ilog(LOG_INFO, "Creating output dir '%s'", output_dir);
			if (mkdir(output_dir, 0700))
				die_errno("Failed to create output dir '%s'", output_dir);
		}
	}
	mysql_library_init(0, NULL, NULL);
	signals();
	metafile_setup();
	epoll_setup();
	inotify_setup();

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
	const char *os_str = NULL;

	GOptionEntry e[] = {
		{ "table",		't', 0, G_OPTION_ARG_INT,	&ktable,	"Kernel table rtpengine uses",		"INT"		},
		{ "spool-dir",		0,   0, G_OPTION_ARG_STRING,	&spool_dir,	"Directory containing rtpengine metadata files", "PATH" },
		{ "num-threads",	0,   0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads",		"INT"		},
		{ "output-storage",	0,   0, G_OPTION_ARG_STRING,	&os_str,	"Where to store audio streams",	        "file|db|both"	},
		{ "output-dir",		0,   0, G_OPTION_ARG_STRING,	&output_dir,	"Where to write media files to",	"PATH"		},
		{ "output-format",	0,   0, G_OPTION_ARG_STRING,	&output_format,	"Write audio files of this type",	"wav|mp3|none"	},
		{ "resample-to",	0,   0, G_OPTION_ARG_INT,	&resample_audio,"Resample all output audio",		"INT"		},
		{ "mp3-bitrate",	0,   0, G_OPTION_ARG_INT,	&mp3_bitrate,	"Bits per second for MP3 encoding",	"INT"		},
		{ "output-mixed",	0,   0, G_OPTION_ARG_NONE,	&output_mixed,	"Mix participating sources into a single output",NULL	},
		{ "output-single",	0,   0, G_OPTION_ARG_NONE,	&output_single,	"Create one output file for each source",NULL		},
		{ "mysql-host",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_host,	"MySQL host for storage of call metadata","HOST|IP"	},
		{ "mysql-port",		0,   0,	G_OPTION_ARG_INT,	&c_mysql_port,	"MySQL port"				,"INT"		},
		{ "mysql-user",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_user,	"MySQL connection credentials",		"USERNAME"	},
		{ "mysql-pass",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_pass,	"MySQL connection credentials",		"PASSWORD"	},
		{ "mysql-db",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_db,	"MySQL database name",			"STRING"	},
		{ "forward-to", 	0,   0, G_OPTION_ARG_STRING,	&forward_to,	"Where to forward to (unix socket)",	"PATH"		},
		{ "tls-send-to", 	0,   0, G_OPTION_ARG_STRING,	&tls_send_to,	"Where to send to (TLS destination)",	"IP:PORT"	},
		{ "tls-resample", 	0,   0, G_OPTION_ARG_INT,	&tls_resample,	"Sampling rate for TLS PCM output",	"INT"		},
		{ NULL, }
	};

	config_load(argc, argv, e, " - rtpengine recording daemon",
			"/etc/rtpengine/rtpengine-recording.conf", "rtpengine-recording", &rtpe_common_config);

	if (tls_send_to) {
		if (endpoint_parse_any_getaddrinfo_full(&tls_send_to_ep, tls_send_to))
			die("Failed to parse 'tls-send-to' option");
	}

	if (!strcmp(output_format, "none")) {
		output_enabled = 0;
		if (output_mixed || output_single)
			die("Output is disabled, but output-mixed or output-single is set");
		if (!forward_to && !tls_send_to_ep.port) {
			//the daemon has no function
			die("Both output and forwarding are disabled");
		}
		output_format = NULL;
	} else if (!output_mixed && !output_single)
		output_mixed = output_single = 1;

	if (output_enabled || tls_send_to_ep.port)
		decoding_enabled = 1;

	if (!os_str || !strcmp(os_str, "file"))
		output_storage = OUTPUT_STORAGE_FILE;
	else if (!strcmp(os_str, "db"))
		output_storage = OUTPUT_STORAGE_DB;
	else if (!strcmp(os_str, "both"))
		output_storage = OUTPUT_STORAGE_BOTH;
	else
		die("Invalid 'output-storage' option");

	if ((output_storage & OUTPUT_STORAGE_FILE) && !strcmp(output_dir, spool_dir))
		die("The spool-dir cannot be the same as the output-dir");
}


int main(int argc, char **argv) {
	options(&argc, &argv);
	setup();
	daemonize();
	wpidfile();

	service_notify("READY=1\n");

	for (int i = 0; i < num_threads; i++)
		start_poller_thread();

	wait_for_signal();

	service_notify("STOPPING=1\n");
	dbg("shutting down");

	wait_threads_finish();

	cleanup();
}
