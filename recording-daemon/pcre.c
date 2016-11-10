#include "pcre.h"
#include <pcre.h>
#include "log.h"


void pcre_build(pcre_t *out, const char *pattern) {
	const char *errptr;
	int erroff;

	out->re = pcre_compile(pattern, PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	if (!out->re)
		die("Failed to compile PCRE '%s': %s (at %i)", pattern, errptr, erroff);
	out->extra = pcre_study(out->re, 0, &errptr);
}
