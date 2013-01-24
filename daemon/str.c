#include <assert.h>
#include "str.h"

guint str_hash(gconstpointer ss) {
	const str *s = ss;
	guint ret = 0;
	str it = *s;

	while (it.len >= sizeof(guint)) {
		guint *x = (void *) it.s;
		ret ^= *x;
		it.s += sizeof(guint);
		it.len -= sizeof(guint);
	}
	while (it.len >= sizeof(gushort)) {
		gushort *x = (void *) it.s;
		ret ^= *x;
		it.s += sizeof(gushort);
		it.len -= sizeof(gushort);
	}
	while (it.len > 0) {
		ret ^= *it.s;
		it.s++;
		it.len--;
	}

	return ret;
}

gboolean str_equal(gconstpointer a, gconstpointer b) {
	return str_cmp_str((str *) a, (str *) b) == 0;
}
