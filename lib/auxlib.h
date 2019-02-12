#ifndef _AUXLIB_H_
#define _AUXLIB_H_

#include <glib.h>
#include <assert.h>
#include "compat.h"
#include <openssl/rand.h>


#define THREAD_BUF_SIZE		64
#define NUM_THREAD_BUFS		8


struct rtpengine_common_config {
	char *config_file;
	char *config_section;
	char *log_facility;
	volatile int log_level;
	int log_stderr;
	char *pidfile;
	int foreground;
};

extern struct rtpengine_common_config *rtpe_common_config_ptr;

/*** PROTOTYPES ***/

void daemonize(void);
void wpidfile(void);
void service_notify(const char *message);
void config_load(int *argc, char ***argv, GOptionEntry *entries, const char *description,
		char *default_config, char *default_section,
		struct rtpengine_common_config *);

char *get_thread_buf(void);

unsigned int in6_addr_hash(const void *p);
int in6_addr_eq(const void *a, const void *b);
unsigned int uint32_hash(const void *p);
int uint32_eq(const void *a, const void *b);


/*** HELPER MACROS ***/

#define ZERO(x)			memset(&(x), 0, sizeof(x))

#define UINT64F			"%" G_GUINT64_FORMAT

#define AUTO_CLEANUP(decl, func)		decl __attribute__ ((__cleanup__(func)))
#define AUTO_CLEANUP_INIT(decl, func, val)	AUTO_CLEANUP(decl, func) = val
#define AUTO_CLEANUP_NULL(decl, func)		AUTO_CLEANUP_INIT(decl, func, 0)
#define AUTO_CLEANUP_BUF(var)			AUTO_CLEANUP_NULL(char *var, free_buf)


/*** STRING HELPERS ***/

INLINE void random_string(unsigned char *buf, int len) {
	int ret = RAND_bytes(buf, len);
	assert(ret == 1);
}

#endif
