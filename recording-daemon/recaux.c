#include "recaux.h"
#include <stdio.h>
#include <stdarg.h>


__thread int __sscanf_hack_var;


int __sscanf_match(const char *s, const char *fmt, ...) {
	va_list ap;

	__sscanf_hack_var = 0; // to make sure that sscanf consumes the entire string

	va_start(ap, fmt);
	int ret = vsscanf(s, fmt, ap);
	va_end(ap);

	if (__sscanf_hack_var == 0)
		return 0;
	return ret;
}
