#include "auxlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include "log.h"
#include "loglib.h"

struct thread_buf {
	char buf[THREAD_BUF_SIZE];
};

static int version;
struct rtpengine_common_config *rtpe_common_config_ptr;
__thread struct timeval rtpe_now;

static __thread struct thread_buf t_bufs[NUM_THREAD_BUFS];
static __thread int t_buf_idx;


void daemonize(void) {
	if (rtpe_common_config_ptr->foreground)
		return;
	if (fork())
		_exit(0);
	write_log = (write_log_t *) syslog;
#ifdef __GLIBC__
	stdin = freopen("/dev/null", "r", stdin);
	stdout = freopen("/dev/null", "w", stdout);
	stderr = freopen("/dev/null", "w", stderr);
#else
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
#endif
	setpgrp();
}

void wpidfile() {
	FILE *fp;

	if (!rtpe_common_config_ptr->pidfile)
		return;

	fp = fopen(rtpe_common_config_ptr->pidfile, "w");
	if (!fp) {
		ilog(LOG_CRIT, "Failed to create PID file (%s), aborting startup", strerror(errno));
		exit(-1);
	}

	fprintf(fp, "%u\n", getpid());
	fclose(fp);
}

void service_notify(const char *message) {
#ifdef HAVE_LIBSYSTEMD
	sd_notify(0, message);
#endif
}


static unsigned int options_length(const GOptionEntry *arr) {
	unsigned int len = 0;
	for (const GOptionEntry *p = arr; p->long_name; p++)
		len++;
	return len;
}


#define CONF_OPTION_GLUE(get_func, data_type, ...) 							\
	{												\
		data_type *varptr = e->arg_data;							\
		data_type var = g_key_file_get_ ## get_func(kf, use_section, e->long_name,		\
			##__VA_ARGS__, &er);								\
		if (er && g_error_matches(er, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {	\
			g_error_free(er);								\
			er = NULL;									\
			break;										\
		}											\
		if (er)											\
			goto err;									\
		*varptr = var;										\
	}

void config_load_free(struct rtpengine_common_config *cconfig) {
	// free common config options
	g_free(cconfig->config_file);
	g_free(cconfig->config_section);
	g_free(cconfig->log_facility);
	g_free(cconfig->log_mark_prefix);
	g_free(cconfig->log_mark_suffix);
	g_free(cconfig->pidfile);
}

static void free_gkeyfile(GKeyFile **k) {
	if (k && *k)
		g_key_file_free(*k);
}
static void free_gopte(GOptionEntry **k) {
	if (k && *k)
		free(*k);
}
static void free_goptc(GOptionContext **k) {
	if (k && *k)
		g_option_context_free(*k);
}
static void free_gerror(GError **k) {
	if (k && *k)
		g_error_free(*k);
}

void config_load(int *argc, char ***argv, GOptionEntry *app_entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *cconfig)
{
	AUTO_CLEANUP_NULL(GOptionContext *c, free_goptc);
	AUTO_CLEANUP_NULL(GError *er, free_gerror);
	AUTO_CLEANUP_GBUF(use_section);
	const char *use_config;
	int fatal = 0;
	AUTO_CLEANUP(char **saved_argv, free_gvbuf) = g_strdupv(*argv);
	int saved_argc = *argc;

	rtpe_common_config_ptr = cconfig;

	// defaults
#ifndef __DEBUG
	rtpe_common_config_ptr->default_log_level = LOG_INFO;
#else
	rtpe_common_config_ptr->default_log_level = LOG_DEBUG;
#endif

	AUTO_CLEANUP(GKeyFile *kf, free_gkeyfile) = g_key_file_new();

#define ll(system, descr) \
		{ "log-level-" #system,	0, 0, G_OPTION_ARG_INT,	&rtpe_common_config_ptr->log_levels[log_level_index_ ## system],"Log level for: " descr,"INT"		},

	GOptionEntry shared_options[] = {
		{ "version",		'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",		NULL		},
		{ "config-file",	0,   0, G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->config_file,	"Load config from this file",		"FILE"		},
		{ "config-section",	0,   0, G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->config_section,"Config file section to use",		"STRING"	},
		{ "log-facility",	0,   0,	G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->log_facility,	"Syslog facility to use for logging",	"daemon|local0|...|local7"},
		{ "log-level",		'L', 0, G_OPTION_ARG_INT,	&rtpe_common_config_ptr->default_log_level,"Default log level",			"INT"		},
#include "loglevels.h"
		{ "log-stderr",		'E', 0, G_OPTION_ARG_NONE,	&rtpe_common_config_ptr->log_stderr,	"Log on stderr instead of syslog",	NULL		},
		{ "split-logs",		0, 0,	G_OPTION_ARG_NONE,	&rtpe_common_config_ptr->split_logs,	"Split multi-line log messages",	NULL		},
		{ "max-log-line-length",0,   0,	G_OPTION_ARG_INT,	&rtpe_common_config_ptr->max_log_line_length,	"Break log lines at this length","INT"		},
		{ "no-log-timestamps",	0,   0, G_OPTION_ARG_NONE,	&rtpe_common_config_ptr->no_log_timestamps,"Drop timestamps from log lines to stderr",NULL	},
		{ "log-mark-prefix",	0,   0, G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->log_mark_prefix,"Prefix for sensitive log info",	NULL		},
		{ "log-mark-suffix",	0,   0, G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->log_mark_suffix,"Suffix for sensitive log info",	NULL		},
		{ "pidfile",		'p', 0, G_OPTION_ARG_FILENAME,	&rtpe_common_config_ptr->pidfile,	"Write PID to file",			"FILE"		},
		{ "foreground",		'f', 0, G_OPTION_ARG_NONE,	&rtpe_common_config_ptr->foreground,	"Don't fork to background",		NULL		},
		{ "thread-stack",	0,0,	G_OPTION_ARG_INT,	&rtpe_common_config_ptr->thread_stack,	"Thread stack size in kB",		"INT"		},
		{ NULL, }
	};
#undef ll

	// prepend shared CLI options
	unsigned int shared_len = options_length(shared_options);
	unsigned int app_len = options_length(app_entries);
	size_t entries_size = sizeof(GOptionEntry) * (shared_len + app_len + 1);

	AUTO_CLEANUP(GOptionEntry *entries, free_gopte) = malloc(entries_size);
	memcpy(entries, shared_options, sizeof(*entries) * shared_len);
	memcpy(&entries[shared_len], app_entries, sizeof(*entries) * (app_len + 1));
	AUTO_CLEANUP(GOptionEntry *entries_copy, free_gopte) = malloc(entries_size);
	memcpy(entries_copy, entries, entries_size);

	c = g_option_context_new(description);
	g_option_context_add_main_entries(c, entries, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		goto err;
	if (rtpe_common_config_ptr->config_section) {
		use_section = g_strdup(rtpe_common_config_ptr->config_section);
	} else {
		use_section = g_strdup(default_section);
	}
	// is there a config file to load?
	use_config = default_config;
	if (rtpe_common_config_ptr->config_file) {
		use_config = rtpe_common_config_ptr->config_file;
		if (!strcmp(use_config, "none"))
			goto out;
		fatal = 1;
	}
	if (!g_key_file_load_from_file(kf, use_config, G_KEY_FILE_NONE, &er)) {
		if (!fatal && (g_error_matches(er, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)
					|| g_error_matches(er, G_FILE_ERROR, G_FILE_ERROR_NOENT)))
			goto out;
		goto err;
	}
	// destroy the option context to reset - we'll do it again later
	g_option_context_free(c);
	c = NULL;
	// iterate the options list and see if the config file defines any.
	// free any strings we come across, as we'll load argv back in.
	// also keep track of any returned strings so we can free them if
	// they were overwritten. we abuse the description field for this.
	for (GOptionEntry *e = entries_copy; e->long_name; e++) {
		switch (e->arg) {
			case G_OPTION_ARG_NONE:
				CONF_OPTION_GLUE(boolean, int);
				break;

			case G_OPTION_ARG_INT:
				CONF_OPTION_GLUE(integer, int);
				break;

			case G_OPTION_ARG_INT64:
				CONF_OPTION_GLUE(uint64, uint64_t);
				break;

			case G_OPTION_ARG_DOUBLE:
				CONF_OPTION_GLUE(double, double);
				break;

			case G_OPTION_ARG_STRING:
			case G_OPTION_ARG_FILENAME: {
				char **s = e->arg_data;
				g_free(*s);
				*s = NULL;
				e->description = NULL;
				CONF_OPTION_GLUE(string, char *);
				e->description = (void *) *s;
				break;
			}

			case G_OPTION_ARG_STRING_ARRAY: {
				char ***s = e->arg_data;
				g_strfreev(*s);
				*s = NULL;
				e->description = NULL;
				CONF_OPTION_GLUE(string_list, char **, NULL);
				e->description = (void *) *s;
				break;
			}

			default:
				config_load_free(rtpe_common_config_ptr);

				abort();
		}
	}

	// process CLI arguments again so they override options from the config file
	c = g_option_context_new(description);
	g_option_context_add_main_entries(c, entries, NULL);
#if !GLIB_CHECK_VERSION(2,40,0)
	g_option_context_parse_strv(c, &saved_argv, &er);
#else
	g_option_context_parse(c, &saved_argc, &saved_argv, &er);
#endif

	// finally go through our list again to look for strings that were
	// overwritten, and free the old values.
	// this is also a good opportunity to trim off stray spaces.
	for (GOptionEntry *e = entries_copy; e->long_name; e++) {
		switch (e->arg) {
			case G_OPTION_ARG_STRING:
			case G_OPTION_ARG_FILENAME: {
				char **s = e->arg_data;
				if (*s != e->description)
					g_free((void *) e->description);
				if (*s) {
					size_t len = strlen(*s);
					while (len && (*s)[len-1] == ' ')
						(*s)[--len] = '\0';
				}
				break;
			}

			case G_OPTION_ARG_STRING_ARRAY: {
				char ***s = e->arg_data;
				if (*s != (void *) e->description)
					g_strfreev((void *) e->description);
				if (*s) {
					for (int i = 0; (*s)[i]; i++) {
						char *ss = (*s)[i];
						size_t len = strlen(ss);
						while (len && ss[len-1] == ' ')
							ss[--len] = '\0';
					}
				}
				break;
			}

			default:
				break;
		}
	}

out:
	// default common values, if not configured
	if (rtpe_common_config_ptr->log_mark_prefix == NULL)
		rtpe_common_config_ptr->log_mark_prefix = g_strdup("");

	if (rtpe_common_config_ptr->log_mark_suffix == NULL)
		rtpe_common_config_ptr->log_mark_suffix = g_strdup("");

	if (version) {
		fprintf(stderr, "Version: %s\n", RTPENGINE_VERSION);
		exit(0);
	}


	if (rtpe_common_config_ptr->log_facility) {
		if (!parse_log_facility(rtpe_common_config_ptr->log_facility, &ilog_facility)) {
			print_available_log_facilities();
			die ("Invalid log facility '%s' (--log-facility)", rtpe_common_config_ptr->log_facility);
		}
	}

	for (unsigned int i = 0; i < num_log_levels; i++) {
		if (!rtpe_common_config_ptr->log_levels[i])
			rtpe_common_config_ptr->log_levels[i] = rtpe_common_config_ptr->default_log_level;
	}

	if (rtpe_common_config_ptr->log_stderr)
		write_log = log_to_stderr;
	else if (rtpe_common_config_ptr->max_log_line_length == 0)
		rtpe_common_config_ptr->max_log_line_length = 500;

	if (rtpe_common_config_ptr->max_log_line_length < 0)
		rtpe_common_config_ptr->max_log_line_length = 0;

	if (rtpe_common_config_ptr->thread_stack == 0)
		rtpe_common_config_ptr->thread_stack = 2048;


	return;

err:
	config_load_free(rtpe_common_config_ptr);

	die("Bad command line: %s", er->message);
}

char *get_thread_buf(void) {
	char *ret;
	ret = t_bufs[t_buf_idx].buf;
	t_buf_idx++;
	if (t_buf_idx >= G_N_ELEMENTS(t_bufs))
		t_buf_idx = 0;
	return ret;
}

unsigned int in6_addr_hash(const void *p) {
	const struct in6_addr *a = p;
	return a->s6_addr32[0] ^ a->s6_addr32[3];
}

int in6_addr_eq(const void *a, const void *b) {
	const struct in6_addr *A = a, *B = b;
	return !memcmp(A, B, sizeof(*A));
}

unsigned int uint32_hash(const void *p) {
	const uint32_t *a = p;
	return *a;
}
int uint32_eq(const void *a, const void *b) {
	const uint32_t *A = a, *B = b;
	return (*A == *B) ? TRUE : FALSE;
}

int timeval_cmp_zero(const void *a, const void *b) {
	const struct timeval *A = a, *B = b;

	/* zero timevals go last */
	if (A->tv_sec == 0 && B->tv_sec != 0)
		return 1;
	if (B->tv_sec == 0 && A->tv_sec == 0)
		return -1;
	if (A->tv_sec == 0 && B->tv_sec == 0)
		return 0;
	/* earlier timevals go first */
	return timeval_cmp(A, B);
}

int timeval_cmp_ptr(const void *a, const void *b) {
	const struct timeval *A = a, *B = b;
	int ret;
	ret = timeval_cmp_zero(A, B);
	if (ret)
		return ret;
	/* equal timeval, so use pointer as tie breaker */
	if (A < B)
		return -1;
	if (A > B)
		return 1;
	return 0;
}

void free_gbuf(char **p) {
	g_free(*p);
}

void free_gvbuf(char ***p) {
	g_strfreev(*p);
}

int num_cpu_cores(int minval) {
#ifdef _SC_NPROCESSORS_ONLN
	int ret = sysconf(_SC_NPROCESSORS_ONLN);
	if (ret >= 1 && ret >= minval)
		return ret;
#endif
	return minval;
}
