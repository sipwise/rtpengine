#ifndef _RECAUX_H_
#define _RECAUX_H_

extern __thread int __sscanf_hack_var;

#define sscanf_match(str, format, ...) __sscanf_match(str, format "%n", ##__VA_ARGS__, &__sscanf_hack_var)
int __sscanf_match(const char *str, const char *fmt, ...) __attribute__ ((__format__ (__scanf__, 2, 3)));


#include <time.h>
#include <sys/time.h>
#include "compat.h"

INLINE double now_double(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1000000.0;
}


#endif
