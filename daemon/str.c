#include "str.h"
#include <assert.h>
#include <stdarg.h>

/* adapted from g_str_hash() from glib */
guint str_hash(gconstpointer ss) {
	const str *s = ss;
	guint ret = 5381;
	str it = *s;

	while (it.len > 0) {
		ret = (ret << 5) + ret + *it.s;
		it.s++;
		it.len--;
	}

	return ret;
}

gboolean str_equal(gconstpointer a, gconstpointer b) {
	return str_cmp_str((str *) a, (str *) b) == 0;
}

str *__str_sprintf(const char *fmt, ...) {
	str *ret;
	va_list ap;
	va_start(ap, fmt);
	ret = __str_vsprintf(fmt, ap);
	va_end(ap);
	return ret;
}

void str_slice_free(void *p) {
	g_slice_free1(sizeof(str), p);
}
