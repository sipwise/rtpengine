#ifndef _AUXLIB_H_
#define _AUXLIB_H_

#include <glib.h>

void daemonize(void);
void wpidfile(const char *pidfile);
const char *config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char **filename_ptr, const char *default_config, char **section_ptr);


#endif
