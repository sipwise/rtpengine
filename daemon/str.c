#include "str.h"
#include "aux.h"
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
int str_uri_encode_len(char *out, const char *in, int len) {
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
	return out - ori_out;
}

int str_uri_decode_len(char **out, const char *in, int in_len) {
	const char *end = in + in_len;
	*out = malloc(in_len + 1);
	char *outp = *out;

	while (in < end) {
		if (*in != '%') {
			*(outp++) = (*in++);
			continue;
		}

		if (end - in < 3 || !g_ascii_isxdigit(in[1]) || !g_ascii_isxdigit(in[2])) {
			free(*out);
			*out = NULL;
			return -1;
		}

		unsigned char c = g_ascii_xdigit_value(in[1]) << 4 | g_ascii_xdigit_value(in[2]);
		*(outp++) = c;
		in += 3;
	}

	*outp = 0;
	return outp - *out;
}
