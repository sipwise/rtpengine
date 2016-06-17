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


/**
 * Generates a random string sandwiched between affixes.
 * Will create the char string for you. Don't forget to clean up!
 */
char *rand_affixed_str(char *prefix, int num_bytes, char *suffix) {
	int rand_len = num_bytes*2 + 1;
	char rand_affix[rand_len];
	int prefix_len = strlen(prefix);
	int suffix_len = strlen(suffix);
	char *full_path = calloc(rand_len + prefix_len + suffix_len, sizeof(char));

	rand_hex_str(rand_affix, num_bytes);
	snprintf(full_path, rand_len+prefix_len, "%s%s", prefix, rand_affix);
	snprintf(full_path + rand_len+prefix_len-1, suffix_len+1, "%s", suffix);
	return full_path;
}

/**
 * Generates a random hexadecimal string representing n random bytes.
 * rand_str length must be 2*num_bytes + 1.
 */
char *rand_hex_str(char *rand_str, int num_bytes) {
	char rand_tmp[3];
	u_int8_t rand_byte;
	int i, n;
	// We might convert an int to a hex string shorter than 2 digits.
	// This causes those strings to have leading '0' characters.
	for (i=0; i<num_bytes*2 + 1; i++) {
		rand_str[i] = '0';
	}

	for (i=0; i<num_bytes; i++) {
		// Determine the length of the hex byte string.
		// If less than two, offset by 2-len to pad with prefix zeroes.
		rand_byte = (u_int8_t)rand();
		snprintf(rand_tmp, 3, "%x", rand_byte);
		n = strlen(rand_tmp);
		snprintf(rand_str + i*2 + (2-n), 3, "%s", rand_tmp);
		rand_str[i*2 + 2] = '0';
	}
	rand_str[num_bytes*2] = '\0';
	return rand_str;
}
