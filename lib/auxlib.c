#include "auxlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include "log.h"
#include "loglib.h"


static int version;
struct rtpengine_common_config *rtpe_common_config_ptr;


void daemonize(void) {
	if (rtpe_common_config_ptr->foreground)
		return;
	if (fork())
		_exit(0);
	write_log = (write_log_t *) syslog;
	stdin = freopen("/dev/null", "r", stdin);
	stdout = freopen("/dev/null", "w", stdout);
	stderr = freopen("/dev/null", "w", stderr);
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


static unsigned int options_length(const GOptionEntry *arr) {
	unsigned int len = 0;
	for (const GOptionEntry *p = arr; p->long_name; p++)
		len++;
	return len;
}


#define CONF_OPTION_GLUE(get_func, data_type, ...) 							\
	{												\
		data_type *varptr = e->arg_data;							\
		data_type var = g_key_file_get_ ## get_func(kf, rtpe_common_config_ptr->config_section, e->long_name,		\
			##__VA_ARGS__, &er);								\
		if (er && g_error_matches(er, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {	\
			g_error_free(er);								\
			er = NULL;									\
			break;										\
		}											\
		if (er)											\
			goto err;									\
		*varptr = var;										\
		break;											\
	}

void config_load(int *argc, char ***argv, GOptionEntry *app_entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *cconfig)
{
	GOptionContext *c;
	GError *er = NULL;
	const char *use_config;
	int fatal = 0;
	int saved_argc = *argc;
	char **saved_argv = g_strdupv(*argv);

	rtpe_common_config_ptr = cconfig;

	// defaults
#ifndef __DEBUG
	rtpe_common_config_ptr->log_level = LOG_INFO;
#else
	rtpe_common_config_ptr->log_level = LOG_DEBUG;
#endif

	GOptionEntry shared_options[] = {
		{ "version",		'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",		NULL		},
		{ "config-file",	0,   0, G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->config_file,	"Load config from this file",		"FILE"		},
		{ "config-section",	0,   0, G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->config_section,"Config file section to use",		"STRING"	},
		{ "log-facility",	0,   0,	G_OPTION_ARG_STRING,	&rtpe_common_config_ptr->log_facility,	"Syslog facility to use for logging",	"daemon|local0|...|local7"},
		{ "log-level",		'L', 0, G_OPTION_ARG_INT,	(void *)&rtpe_common_config_ptr->log_level,"Mask log priorities above this level","INT"		},
		{ "log-stderr",		'E', 0, G_OPTION_ARG_NONE,	&rtpe_common_config_ptr->log_stderr,	"Log on stderr instead of syslog",	NULL		},
		{ "pidfile",		'p', 0, G_OPTION_ARG_FILENAME,	&rtpe_common_config_ptr->pidfile,	"Write PID to file",			"FILE"		},
		{ "foreground",		'f', 0, G_OPTION_ARG_NONE,	&rtpe_common_config_ptr->foreground,	"Don't fork to background",		NULL		},
		{ NULL, }
	};


	// prepend shared CLI options
	unsigned int shared_len = options_length(shared_options);
	unsigned int app_len = options_length(app_entries);
	GOptionEntry *entries = malloc(sizeof(*entries) * (shared_len + app_len + 1));
	memcpy(entries, shared_options, sizeof(*entries) * shared_len);
	memcpy(&entries[shared_len], app_entries, sizeof(*entries) * (app_len + 1));

	if (!rtpe_common_config_ptr->config_section)
		rtpe_common_config_ptr->config_section = default_section;

	c = g_option_context_new(description);
	g_option_context_add_main_entries(c, entries, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		goto err;

	// is there a config file to load?
	use_config = default_config;
	if (rtpe_common_config_ptr->config_file) {
		use_config = rtpe_common_config_ptr->config_file;
		fatal = 1;
	}

	GKeyFile *kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, use_config, G_KEY_FILE_NONE, &er)) {
		if (!fatal && (g_error_matches(er, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)
					|| g_error_matches(er, G_FILE_ERROR, G_FILE_ERROR_NOENT)))
			goto out;
		goto err;
	}

	// iterate the options list and see if the config file defines any
	for (GOptionEntry *e = entries; e->long_name; e++) {
		switch (e->arg) {
			case G_OPTION_ARG_NONE:
				CONF_OPTION_GLUE(boolean, int);

			case G_OPTION_ARG_INT:
				CONF_OPTION_GLUE(integer, int);

			case G_OPTION_ARG_INT64:
				CONF_OPTION_GLUE(uint64, uint64_t);

			case G_OPTION_ARG_DOUBLE:
				CONF_OPTION_GLUE(double, double);

			case G_OPTION_ARG_STRING:
			case G_OPTION_ARG_FILENAME:
				CONF_OPTION_GLUE(string, char *);

			case G_OPTION_ARG_STRING_ARRAY:
				CONF_OPTION_GLUE(string_list, char **, NULL);

			default:
				abort();
		}
	}

	// process CLI arguments again so they override options from the config file
	g_option_context_parse(c, &saved_argc, &saved_argv, &er);

out:
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

	if ((rtpe_common_config_ptr->log_level < LOG_EMERG) || (rtpe_common_config_ptr->log_level > LOG_DEBUG))
	        die("Invalid log level (--log_level)");

	if (rtpe_common_config_ptr->log_stderr) {
		write_log = log_to_stderr;
		max_log_line_length = 0;
	}


	return;

err:
	die("Bad command line: %s", er->message);
}
