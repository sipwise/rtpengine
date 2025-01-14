#include "str.h"
#include "auxlib.h"
#include <assert.h>
#include <stdarg.h>

/* adapted from g_str_hash() from glib */
guint str_hash(const str *ss) {
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

gboolean str_equal(const str *a, const str *b) {
	return str_cmp_str((str *) a, (str *) b) == 0;
}

guint str_case_hash(const str *ss) {
	const str *s = ss;
	guint ret = 5381;
	str it = *s;

	while (it.len > 0) {
		ret = (ret << 5) + ret + (*it.s & 0xdf);
		it.s++;
		it.len--;
	}

	return ret;
}

gboolean str_case_equal(const str *a, const str *b) {
	return str_casecmp_str((str *) a, (str *) b) == 0;
}

str str_sprintf(const char *fmt, ...) {
	str ret;
	va_list ap;
	va_start(ap, fmt);
	ret = str_vsprintf(fmt, ap);
	va_end(ap);
	return ret;
}


/**
 * Generates a random hexadecimal string representing n random bytes.
 * rand_str length must be 2*num_bytes + 1.
 */
char *rand_hex_str(char *rand_str, int num_bytes) {
	unsigned char rand_tmp[num_bytes];
	random_string(rand_tmp, num_bytes);
	for (int i = 0; i < num_bytes; i++) {
		sprintf(&rand_str[i * 2], "%02x", rand_tmp[i]);
	}
	return rand_str;
}


static const char *hex_chars = "0123456789abcdef";
str str_uri_encode_len(char *out, const char *in, size_t len) {
	const char *end = in + len;
	char *ori_out = out;

	while (in < end) {
		if (*in < ' ' || *in > '~' || *in == '%' || *in == '\\' || *in == '\'' || *in == '"') {
			*(out++) = '%';
			*(out++) = hex_chars[(*((unsigned char *) in)) >> 4];
			*(out++) = hex_chars[(*((unsigned char *) in)) & 0xf];
			in++;
			continue;
		}

		*(out++) = *(in++);
	}

	*out = 0;
	return STR_LEN(ori_out, out - ori_out);
}

str *str_uri_decode_len(const char *in, size_t in_len) {
	const char *end = in + in_len;
	str *ret = str_alloc(in_len);
	char *outp = ret->s;

	while (in < end) {
		if (*in != '%') {
			*(outp++) = (*in++);
			continue;
		}

		if (end - in < 3 || !g_ascii_isxdigit(in[1]) || !g_ascii_isxdigit(in[2])) {
			free(ret);
			return NULL;
		}

		unsigned char c = g_ascii_xdigit_value(in[1]) << 4 | g_ascii_xdigit_value(in[2]);
		*(outp++) = c;
		in += 3;
	}

	*outp = 0;
	ret->len = outp - ret->s;
	return ret;
}
