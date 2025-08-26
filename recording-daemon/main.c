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
#include <pwd.h>
#include <grp.h>
#include <curl/curl.h>
#include "log.h"
#include "epoll.h"
#include "inotify.h"
#include "metafile.h"
#include "mix.h"
#include "garbage.h"
#include "auxlib.h"
#include "decoder.h"
#include "output.h"
#include "forward.h"
#include "codeclib.h"
#include "socket.h"
#include "ssllib.h"
#include "notify.h"
#include "gcs.h"



int ktable = 0;
int num_threads;
enum output_storage_enum output_storage;
char *spool_dir = NULL;
char *output_dir = NULL;
static char *output_format = NULL;
gboolean output_mixed;
enum mix_method mix_method;
int mix_num_inputs = MIX_MAX_INPUTS;
gboolean output_single;
mode_t output_chmod;
mode_t output_chmod_dir;
uid_t output_chown = -1;
gid_t output_chgrp = -1;
char *output_pattern = NULL;
int output_buffer = 1<<18;
gboolean decoding_enabled;
char *c_mysql_host,
      *c_mysql_user,
      *c_mysql_pass,
      *c_mysql_db;
int c_mysql_port;
char *forward_to = NULL;
static char *tls_send_to = NULL;
endpoint_t tls_send_to_ep;
int tls_resample = 8000;
bool tls_disable = false;
gboolean tls_mixed = false;
char *notify_uri;
gboolean notify_post;
gboolean notify_nverify;
int notify_threads = 5;
int notify_retries = 10;
char *notify_command;
gboolean mix_output_per_media = 0;
gboolean flush_packets = 0;
int resample_audio;
char *s3_host;
unsigned int s3_port;
char *s3_path;
char *s3_access_key;
char *s3_secret_key;
char *s3_region;
gboolean s3_nverify;
char *gcs_uri;
char *gcs_key;
char *gcs_service_account;
char *gcs_scope;
gboolean gcs_nverify;


static GQueue threads = G_QUEUE_INIT; // only accessed from main thread

volatile int shutdown_flag;

struct rtpengine_common_config rtpe_common_config = {
	.log_levels = {
		[log_level_index_internals] = -1,
	},
};



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
	if ((output_storage & OUTPUT_STORAGE_MASK))
		output_init(output_format);
	mysql_library_init(0, NULL, NULL);
	signals();
	metafile_setup();
	epoll_setup();
	inotify_setup();
	if (!gcs_init())
		die("GCS failure");
}


static void start_poller_thread(void) {
	pthread_attr_t att;
	if (pthread_attr_init(&att))
		abort();
	if (rtpe_common_config.thread_stack > 0) {
		if (pthread_attr_setstacksize(&att, rtpe_common_config.thread_stack * 1024)) {
			ilog(LOG_ERR, "Failed to set thread stack size to %llu",
					(unsigned long long) rtpe_common_config.thread_stack * 1024);
			abort();
		}
	}

	pthread_t *thr = g_new(__typeof(*thr), 1);
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
		g_free(thr);
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
	notify_cleanup();
	inotify_cleanup();
	epoll_cleanup();
	mysql_library_end();
}


static mode_t chmod_parse(const char *s) {
	if (!s || !*s)
		return 0;
	char *errp;
	unsigned long m = strtoul(s, &errp, 8);
	if (*errp || m > 077777)
		die("Invalid mode value '%s'", s);
	return m;
}


static void options(int *argc, char ***argv) {
	g_autoptr(char_p) os_a = NULL;
	g_autoptr(char) chmod_mode = NULL;
	g_autoptr(char) chmod_dir_mode = NULL;
	g_autoptr(char) user_uid = NULL;
	g_autoptr(char) group_gid = NULL;
	g_autoptr(char) mix_method_str = NULL;
	g_autoptr(char) tcp_send_to = NULL;
	gboolean notify_record = FALSE;
	bool no_output_allowed = false;
	gboolean notify_purge = false;

	GOptionEntry e[] = {
		{ "table",		't', 0, G_OPTION_ARG_INT,	&ktable,	"Kernel table rtpengine uses",		"INT"		},
		{ "spool-dir",		0,   0, G_OPTION_ARG_FILENAME,	&spool_dir,	"Directory containing rtpengine metadata files", "PATH" },
		{ "num-threads",	0,   0, G_OPTION_ARG_INT,	&num_threads,	"Number of worker threads",		"INT"		},
		{ "output-storage",	0,   0, G_OPTION_ARG_STRING_ARRAY,&os_a,	"Where to store audio streams",	        "file|db|notify|s3|gcs|memory"},
		{ "output-dir",		0,   0, G_OPTION_ARG_STRING,	&output_dir,	"Where to write media files to",	"PATH"		},
		{ "output-pattern",	0,   0, G_OPTION_ARG_STRING,	&output_pattern,"File name pattern for recordings",	"STRING"	},
		{ "output-format",	0,   0, G_OPTION_ARG_STRING,	&output_format,	"Write audio files of this type",	"wav|mp3|none"	},
		{ "resample-to",	0,   0, G_OPTION_ARG_INT,	&resample_audio,"Resample all output audio",		"INT"		},
		{ "mp3-bitrate",	0,   0, G_OPTION_ARG_INT,	&mp3_bitrate,	"Bits per second for MP3 encoding",	"INT"		},
		{ "output-mixed",	0,   0, G_OPTION_ARG_NONE,	&output_mixed,	"Mix participating sources into a single output",NULL	},
		{ "mix-method",		0,   0, G_OPTION_ARG_STRING,	&mix_method_str,"How to mix multiple sources",		"direct|channels"},
		{ "mix-num-inputs",	0,   0, G_OPTION_ARG_INT,	&mix_num_inputs, "Number of channels for recordings",	"INT"		},
		{ "output-single",	0,   0, G_OPTION_ARG_NONE,	&output_single,	"Create one output file for each source",NULL		},
		{ "output-chmod",	0,   0, G_OPTION_ARG_STRING,	&chmod_mode,	"File mode for recordings",		"OCTAL"		},
		{ "output-chmod-dir",	0,   0, G_OPTION_ARG_STRING,	&chmod_dir_mode,"Directory mode for recordings",	"OCTAL"		},
		{ "output-chown",	0,   0, G_OPTION_ARG_STRING,	&user_uid,	"File owner for recordings",		"USER|UID"	},
		{ "output-chgrp",	0,   0, G_OPTION_ARG_STRING,	&group_gid,	"File group for recordings",		"GROUP|GID"	},
		{ "output-buffer",	0,   0, G_OPTION_ARG_INT,	&output_buffer,	"I/O buffer size for writing files",	"INT"		},
		{ "mysql-host",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_host,	"MySQL host for storage of call metadata","HOST|IP"	},
		{ "mysql-port",		0,   0,	G_OPTION_ARG_INT,	&c_mysql_port,	"MySQL port"				,"INT"		},
		{ "mysql-user",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_user,	"MySQL connection credentials",		"USERNAME"	},
		{ "mysql-pass",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_pass,	"MySQL connection credentials",		"PASSWORD"	},
		{ "mysql-db",		0,   0,	G_OPTION_ARG_STRING,	&c_mysql_db,	"MySQL database name",			"STRING"	},
		{ "forward-to", 	0,   0, G_OPTION_ARG_FILENAME,	&forward_to,	"Where to forward to (unix socket)",	"PATH"		},
		{ "tcp-send-to", 	0,   0, G_OPTION_ARG_STRING,	&tcp_send_to,	"Where to send to (TCP destination)",	"IP:PORT"	},
		{ "tls-send-to", 	0,   0, G_OPTION_ARG_STRING,	&tls_send_to,	"Where to send to (TLS destination)",	"IP:PORT"	},
		{ "tcp-resample", 	0,   0, G_OPTION_ARG_INT,	&tls_resample,	"Sampling rate for TCP/TLS PCM output",	"INT"		},
		{ "tls-resample", 	0,   0, G_OPTION_ARG_INT,	&tls_resample,	"Sampling rate for TCP/TLS PCM output",	"INT"		},
		{ "tcp-mixed", 		0,   0, G_OPTION_ARG_NONE,	&tls_mixed,	"Deliver mixed TCP/TLS PCM output",	NULL		},
		{ "tls-mixed", 		0,   0, G_OPTION_ARG_NONE,	&tls_mixed,	"Deliver mixed TCP/TLS PCM output",	NULL		},
		{ "notify-uri", 	0,   0, G_OPTION_ARG_STRING,	&notify_uri,	"Notify destination for finished outputs","URI"		},
		{ "notify-post", 	0,   0, G_OPTION_ARG_NONE,	&notify_post,	"Use POST instead of GET",		NULL		},
		{ "notify-no-verify", 	0,   0, G_OPTION_ARG_NONE,	&notify_nverify,"Don't verify HTTPS peer certificate",	NULL		},
		{ "notify-concurrency",	0,   0, G_OPTION_ARG_INT,	&notify_threads,"How many simultaneous requests",	"INT"		},
		{ "notify-retries",	0,   0, G_OPTION_ARG_INT,	&notify_retries,"How many times to retry failed requests","INT"	},
		{ "notify-command",	0,   0, G_OPTION_ARG_STRING,	&notify_command,"External command to execute for notifications","PATH"	},
		{ "output-mixed-per-media",0,0,	G_OPTION_ARG_NONE,	&mix_output_per_media,"Mix participating sources into a single output", NULL },
#if CURL_AT_LEAST_VERSION(7,56,0)
		{ "notify-record", 	0,   0, G_OPTION_ARG_NONE,	&notify_record, "Also attach recorded file to request", NULL		},
		{ "notify-purge", 	0,   0, G_OPTION_ARG_NONE,	&notify_purge,	"Remove the local file if notify success", NULL		},
#endif
		{ "flush-packets", 	0,   0, G_OPTION_ARG_NONE,	&flush_packets,	"Output buffer will be flushed after every packet", NULL },
		{ "s3-host", 		0,   0, G_OPTION_ARG_STRING,	&s3_host,	"Host name of S3 service",		"HOST"		},
		{ "s3-port", 		0,   0, G_OPTION_ARG_INT,	&s3_port,	"S3 service port if non-standard",	"INT"		},
		{ "s3-path", 		0,   0, G_OPTION_ARG_STRING,	&s3_path,	"Path prefix for S3 storage or bucket",	"STRING"	},
		{ "s3-access-key", 	0,   0, G_OPTION_ARG_STRING,	&s3_access_key,	"Access key for S3 storage",		"STRING"	},
		{ "s3-secret-key", 	0,   0, G_OPTION_ARG_STRING,	&s3_secret_key,	"Secret key for S3 authentication",	"STRING"	},
		{ "s3-region", 		0,   0, G_OPTION_ARG_STRING,	&s3_region,	"Region configuration for S3 storage",	"STRING"	},
		{ "s3-no-verify", 	0,   0, G_OPTION_ARG_NONE,	&s3_nverify,	"Disable TLS verification for S3",	NULL		},
		{ "gcs-uri", 		0,   0, G_OPTION_ARG_STRING,	&gcs_uri,	"URI for GCS uploads",			"STRING"	},
		{ "gcs-key",		0,   0, G_OPTION_ARG_STRING,	&gcs_key,	"API key for GCS uploads",		"STRING"	},
		{ "gcs-service-account", 0,   0, G_OPTION_ARG_FILENAME,	&gcs_service_account,"Service account JSON file for GCS JWT authentication","FILE"	},
		{ "gcs-scope", 		0,   0, G_OPTION_ARG_STRING,	&gcs_scope,	"Scope for GCS JWT authentication",	"STRING"	},
		{ "gcs-no-verify", 	0,   0, G_OPTION_ARG_NONE,	&gcs_nverify,	"Disable TLS verification for GCS",	NULL		},
		{ NULL, }
	};

	config_load(argc, argv, e, " - rtpengine recording daemon",
			"/etc/rtpengine/rtpengine-recording.conf", "rtpengine-recording", &rtpe_common_config);

	// default config, if not configured
	if (spool_dir == NULL)
		spool_dir = g_strdup("/var/spool/rtpengine");

	if (output_dir == NULL)
		output_dir = g_strdup("/var/lib/rtpengine-recording");

	if (output_format == NULL)
		output_format = g_strdup("wav");

	if (tcp_send_to) {
		if (tls_send_to)
			die("Cannot have both 'tcp-send-to' and 'tls-send-to' active at the same time");
		tls_send_to = tcp_send_to;
		tls_disable = true;
		tcp_send_to = NULL;
	}

	if (tls_send_to) {
		if (!endpoint_parse_any_getaddrinfo_full(&tls_send_to_ep, tls_send_to))
			die("Failed to parse 'tcp-send-to' or 'tls-send-to' option");
	}

	if (!strcmp(output_format, "none"))
		no_output_allowed = true;

	if (!tls_send_to && !tcp_send_to)
		tls_mixed = false;

	// output config
	for (char *const *iter = os_a; iter && *iter; iter++) {
		if (!strcmp(*iter, "file"))
			output_storage |= OUTPUT_STORAGE_FILE;
		else if (!strcmp(*iter, "notify"))
#if CURL_AT_LEAST_VERSION(7,56,0)
			output_storage |= OUTPUT_STORAGE_NOTIFY;
#else
			die("cURL version too old to support notify storage");
#endif
		else if (!strcmp(*iter, "s3"))
			output_storage |= OUTPUT_STORAGE_S3;
		else if (!strcmp(*iter, "gcs"))
			output_storage |= OUTPUT_STORAGE_GCS;
		else if (!strcmp(*iter, "db"))
			output_storage |= OUTPUT_STORAGE_DB;
		else if (!strcmp(*iter, "db-mem"))
			output_storage |= OUTPUT_STORAGE_DB | OUTPUT_STORAGE_MEMORY;
		else if (!strcmp(*iter, "mem") || !strcmp(*iter, "memory"))
			output_storage |= OUTPUT_STORAGE_MEMORY;
		else if (!strcmp(*iter, "both"))
			output_storage |= OUTPUT_STORAGE_FILE | OUTPUT_STORAGE_DB;
		else if (!strcmp(*iter, "none"))
			no_output_allowed = true;
		else
			die("Invalid 'output-storage' option '%s'", *iter);
	}

	// default:
	if (output_storage == 0 && !no_output_allowed)
		output_storage = OUTPUT_STORAGE_FILE;

	output_storage |= notify_record ? OUTPUT_STORAGE_NOTIFY : 0;

	// sane config?
	if ((output_storage & OUTPUT_STORAGE_MASK) == 0 && !no_output_allowed)
		die("No output storage configured");
	if ((output_storage & OUTPUT_STORAGE_DB) && (!c_mysql_host || !c_mysql_db))
		die("DB output storage is enabled but no DB is configured");
	if ((output_storage & OUTPUT_STORAGE_NOTIFY) && !notify_uri)
		die("Notify storage is enabled but notify URI is not set");
	if ((output_storage & OUTPUT_STORAGE_S3) && (!s3_host || !s3_access_key || !s3_secret_key || !s3_path || !s3_region))
		die("S3 storage is enabled but S3 config is incomplete");
	if ((output_storage & OUTPUT_STORAGE_GCS) && !gcs_uri)
		die("GCS storage is enabled but GCS config is incomplete");

	if ((output_storage & OUTPUT_STORAGE_MASK) == 0) {
		if (output_mixed || output_single)
			die("Output is disabled, but output-mixed or output-single is set");
		if (!forward_to && !tls_send_to_ep.port) {
			//the daemon has no function
			die("Both output and forwarding are disabled");
		}
		g_free(output_format);
		output_format = NULL;
	} else if (!output_mixed && !output_single)
		output_mixed = output_single = true;

	if ((output_storage & OUTPUT_STORAGE_MASK) || tls_send_to_ep.port)
		decoding_enabled = true;

	// make sure S3 path always leads with a slash and always ends with one
	if (!s3_path)
		s3_path = g_strdup("/");
	else {
		char *tail = s3_path;
		// skip heading slashes
		while (tail[0] == '/')
			tail++;

		size_t len = strlen(tail);

		// trim trailing slashes
		while (len > 0 && tail[len - 1] == '/')
			len--;

		char *np;
		if (len == 0)
			np = g_strdup("/"); // nothing left, blank path
		else
			np = g_strdup_printf("/%.*s/", (int) len, tail);

		g_free(s3_path);
		s3_path = np;

	}

	if (notify_purge && (output_storage & OUTPUT_STORAGE_FILE))
		output_storage &= ~OUTPUT_STORAGE_FILE;

	if (!gcs_scope || !gcs_scope[0])
		gcs_scope = g_strdup("https://www.googleapis.com/auth/cloud-platform");

	if (!mix_method_str || !mix_method_str[0] || !strcmp(mix_method_str, "direct"))
		mix_method = MM_DIRECT;
	else if (!strcmp(mix_method_str, "channels"))
		mix_method = MM_CHANNELS;
	else
		die("Invalid 'mix-method' option");

	if (mix_num_inputs <= 0 || mix_num_inputs > MIX_MAX_INPUTS)
		die("Invalid mix_num_inputs value, it must be between 1 and %d", MIX_MAX_INPUTS);

	if ((output_storage & OUTPUT_STORAGE_FILE) && !strcmp(output_dir, spool_dir))
		die("The spool-dir cannot be the same as the output-dir");
	if ((output_storage & OUTPUT_STORAGE_FILE) && (output_storage & OUTPUT_STORAGE_MEMORY))
		die("Memory storage and file storage are mutually exclusive");

	// no threads here, so safe to use the non-_r versions of these lookups
	if (user_uid && *user_uid) {
		char *errp;
		long uid = strtol(user_uid, &errp, 0);
		if (*user_uid && !*errp)
			output_chown = uid;
		else {
			struct passwd *pw = getpwnam(user_uid);
			if (!pw)
				die("Unknown user name '%s'", user_uid);
			output_chown = pw->pw_uid;
		}
	}
	if (group_gid && *group_gid) {
		char *errp;
		long gid = strtol(group_gid, &errp, 0);
		if (*group_gid && !*errp)
			output_chgrp = gid;
		else {
			struct group *gr = getgrnam(group_gid);
			if (!gr)
				die("Unknown group name '%s'", group_gid);
			output_chgrp = gr->gr_gid;
		}
	}

	output_chmod = chmod_parse(chmod_mode);
	output_chmod_dir = chmod_parse(chmod_dir_mode);

	if (num_threads <= 0)
		num_threads = num_cpu_cores(8);

	if (!output_pattern)
		output_pattern = g_strdup("%c-%r-%t");
	if (!strstr(output_pattern, "%c"))
		die("Invalid output pattern '%s' (no '%%c' format present)", output_pattern);
	if (!strstr(output_pattern, "%t"))
		die("Invalid output pattern '%s' (no '%%t' format present)", output_pattern);

	if (output_buffer < 0)
		die("Invalid negative output-buffer value");
}

static void options_free(void) {
	// free config options	
	g_free(spool_dir);
	g_free(output_dir);
	g_free(output_format);
	g_free(c_mysql_host);
	g_free(c_mysql_user);
	g_free(c_mysql_pass);
	g_free(c_mysql_db);
	g_free(forward_to);
	g_free(tls_send_to);
	g_free(output_pattern);

	// free common config options
	config_load_free(&rtpe_common_config);
}

int main(int argc, char **argv) {
	options(&argc, &argv);
	setup();
	daemonize();
	wpidfile();
	notify_setup();

	service_notify("READY=1\n");

	for (int i = 0; i < num_threads; i++)
		start_poller_thread();

	wait_for_signal();

	service_notify("STOPPING=1\n");
	dbg("shutting down");

	wait_threads_finish();

	if (decoding_enabled)
		codeclib_free();

	gcs_shutdown();
	cleanup();
	log_free();
	options_free();
}
