#ifndef _AUXLIB_H_
#define _AUXLIB_H_

#include <glib.h>

void daemonize(void);
void wpidfile(void);
void config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		const char *default_config, const char *default_section);


#endif
