#include "auxlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>
#include <stdlib.h>
#include "loglib.h"

void daemonize(void) {
	if (fork())
		_exit(0);
	write_log = (write_log_t *) syslog;
	stdin = freopen("/dev/null", "r", stdin);
	stdout = freopen("/dev/null", "w", stdout);
	stderr = freopen("/dev/null", "w", stderr);
	setpgrp();
}

void wpidfile(const char *pidfile) {
	FILE *fp;

	if (!pidfile)
		return;

	fp = fopen(pidfile, "w");
	if (fp) {
		fprintf(fp, "%u\n", getpid());
		fclose(fp);
	}
}

#define CONF_OPTION_GLUE(get_func, data_type, ...) 							\
	{												\
		data_type *varptr = e->arg_data;							\
		data_type var = g_key_file_get_ ## get_func(kf, *section_ptr, e->long_name,		\
			##__VA_ARGS__, &er);								\
		if (er && g_error_matches(er, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {	\
			er = NULL;									\
			break;										\
		}											\
		if (er)											\
			return er->message;								\
		*varptr = var;										\
		break;											\
	}

const char *config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char **filename_ptr, const char *default_config, char **section_ptr)
{
	GOptionContext *c;
	GError *er = NULL;
	const char *config_file;
	int fatal = 0;
	int *saved_argc = argc;
	char ***saved_argv = argv;

	c = g_option_context_new(description);
	g_option_context_add_main_entries(c, entries, NULL);
	if (!g_option_context_parse(c, argc, argv, &er))
		return er->message;

	// is there a config file to load?
	config_file = default_config;
	if (filename_ptr && *filename_ptr) {
		config_file = *filename_ptr;
		fatal = 1;
	}

	GKeyFile *kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, config_file, G_KEY_FILE_NONE, &er)) {
		if (!fatal && (g_error_matches(er, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)
					|| g_error_matches(er, G_FILE_ERROR, G_FILE_ERROR_NOENT)))
			return NULL;
		return er->message;
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

	return NULL;
}
