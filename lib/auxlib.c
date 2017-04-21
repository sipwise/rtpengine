#include "auxlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "log.h"


static const char *config_file;
static const char *config_section;
static const char *pid_file;
static const char *log_facility;
static int foreground;
static int version;


void daemonize(void) {
	if (foreground)
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

	if (!pid_file)
		return;

	fp = fopen(pid_file, "w");
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


static const GOptionEntry shared_options[] = {
	{ "version",		'v', 0, G_OPTION_ARG_NONE,	&version,	"Print build time and exit",		NULL		},
	{ "config-file",	0,   0, G_OPTION_ARG_STRING,	&config_file,	"Load config from this file",		"FILE"		},
	{ "config-section",	0,   0, G_OPTION_ARG_STRING,	&config_section,"Config file section to use",		"STRING"	},
	{ "log-facility",	0,   0,	G_OPTION_ARG_STRING,	&log_facility,	"Syslog facility to use for logging",	"daemon|local0|...|local7"},
	{ "log-level",		'L', 0, G_OPTION_ARG_INT,	(void *)&log_level,"Mask log priorities above this level","INT"		},
	{ "log-stderr",		'E', 0, G_OPTION_ARG_NONE,	&ilog_stderr,	"Log on stderr instead of syslog",	NULL		},
	{ "pidfile",		'p', 0, G_OPTION_ARG_FILENAME,	&pid_file,	"Write PID to file",			"FILE"		},
	{ "foreground",		'f', 0, G_OPTION_ARG_NONE,	&foreground,	"Don't fork to background",		NULL		},
	{ NULL, }
};

#define CONF_OPTION_GLUE(get_func, data_type, ...) 							\
	{												\
		data_type *varptr = e->arg_data;							\
		data_type var = g_key_file_get_ ## get_func(kf, config_section, e->long_name,		\
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
		const char *default_config, const char *default_section)
{
	GOptionContext *c;
	GError *er = NULL;
	const char *use_config;
	int fatal = 0;
	int saved_argc = *argc;
	char **saved_argv = g_strdupv(*argv);

	// prepend shared CLI options
	unsigned int shared_len = options_length(shared_options);
	unsigned int app_len = options_length(app_entries);
	GOptionEntry *entries = malloc(sizeof(*entries) * (shared_len + app_len + 1));
	memcpy(entries, shared_options, sizeof(*entries) * shared_len);
	memcpy(&entries[shared_len], app_entries, sizeof(*entries) * (app_len + 1));

	if (!config_section)
		config_section = default_section;

	c = g_option_context_new(description);
	g_option_context_add_main_entries(c, entries, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		goto err;

	// is there a config file to load?
	use_config = default_config;
	if (config_file) {
		use_config = config_file;
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


	if (log_facility) {
		if (!parse_log_facility(log_facility, &ilog_facility)) {
			print_available_log_facilities();
			die ("Invalid log facility '%s' (--log-facility)", log_facility);
		}
	}

	if (ilog_stderr) {
		write_log = log_to_stderr;
		max_log_line_length = 0;
	}


	return;

err:
	die("Bad command line: %s", er->message);
}
