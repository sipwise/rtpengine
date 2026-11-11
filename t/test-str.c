#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "str.h"

static int failed;

#define check(cond) do { \
		if (!(cond)) { \
			fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__, #cond); \
			failed = 1; \
		} \
	} while (0)

// str_to_d() on the first `len` bytes of `s` only
static double to_d(const char *s, size_t len, double def) {
	str st = STR_LEN(s, len);
	return str_to_d(&st, def);
}

// Exercise the public helpers, including slices without a terminating NUL.
#define integer_common(fn) do { \
	check(fn(&STR_CONST("0"), 77) == 0); \
	check(fn(&STR_CONST("42"), 77) == 42); \
	check(fn(&STR_CONST(" +42"), 77) == 42); \
	check(fn(&STR_LEN("42x", 2), 77) == 42); \
	check(fn(&STR_CONST(""), 77) == 77); \
	check(fn(&STR_CONST(" "), 77) == 77); \
	check(fn(&STR_CONST("+"), 77) == 77); \
	check(fn(&STR_CONST("x"), 77) == 77); \
	check(fn(&STR_CONST("42x"), 77) == 77); \
	check(fn(&STR_CONST("42 "), 77) == 77); \
	check(fn(&STR_CONST("42\0x"), 77) == 77); \
} while (0)

#define signed_limits(fn, min, max) do { \
	char buf[64]; \
	snprintf(buf, sizeof(buf), "%lld", (long long) (min)); \
	check(fn(STR_PTR(buf), 77) == (min)); \
	snprintf(buf, sizeof(buf), "%lld", (long long) (max)); \
	check(fn(STR_PTR(buf), 77) == (max)); \
	snprintf(buf, sizeof(buf), "%llu", (unsigned long long) (max) + 1); \
	check(fn(STR_PTR(buf), 77) == 77); \
	snprintf(buf, sizeof(buf), "-%llu", (unsigned long long) (-((min) + 1)) + 2); \
	check(fn(STR_PTR(buf), 77) == 77); \
	check(fn(&STR_CONST("-42"), 77) == -42); \
} while (0)

#define unsigned_limits(fn, max) do { \
	char buf[64]; \
	snprintf(buf, sizeof(buf), "%llu", (unsigned long long) (max)); \
	check(fn(STR_PTR(buf), 77) == (max)); \
	/* Appending a zero exceeds the destination range without C overflow. */ \
	snprintf(buf, sizeof(buf), "%llu0", (unsigned long long) (max)); \
	check(fn(STR_PTR(buf), 77) == 77); \
	check(fn(&STR_CONST("-1"), 77) == 77); \
	check(fn(&STR_CONST(" -1"), 77) == 77); \
	check(fn(&STR_CONST("-0"), 77) == 77); \
} while (0)

static void integer_tests(void) {
	integer_common(str_to_i);
	integer_common(str_to_u);
	integer_common(str_to_l);
	integer_common(str_to_ul);
	integer_common(str_to_ll);
	integer_common(str_to_ull);
	signed_limits(str_to_i, INT_MIN, INT_MAX);
	signed_limits(str_to_l, LONG_MIN, LONG_MAX);
	signed_limits(str_to_ll, LLONG_MIN, LLONG_MAX);
	unsigned_limits(str_to_u, UINT_MAX);
	unsigned_limits(str_to_ul, ULONG_MAX);
	unsigned_limits(str_to_ull, ULLONG_MAX);

	// These previously narrowed to small valid positive integers.
	check(str_to_i(&STR_CONST("4295003297"), 77) == 77);
	check(str_to_i(&STR_CONST("-4294931295"), 77) == 77);
	check(str_to_u(&STR_CONST("4294967296"), 77) == 77);
	check(str_to_u(&STR_CONST("4295003297"), 77) == 77);
	// Unsigned values above LLONG_MAX must remain valid.
	check(str_to_ull(&STR_CONST("9223372036854775808"), 77) == 9223372036854775808ULL);
}

int main(void) {
	integer_tests();
	check(to_d("1.5", 3, -1) == 1.5);
	check(to_d("-2.25", 5, -1) == -2.25);
	check(to_d("0", 1, -1) == 0);
	check(to_d(" 3", 2, -1) == 3);
	check(to_d("1e3", 3, -1) == 1000);

	// the bytes after the str are not read
	check(to_d("1.57", 3, -1) == 1.5);
	check(to_d("99.5" "7:command", 4, -1) == 99.5);

	// not a number, or not only a number: the default
	check(to_d("abc", 3, -1) == -1);
	check(to_d("1.5x", 4, -1) == -1);
	check(to_d("1.5 ", 4, -1) == -1);
	check(to_d("", 0, -1) == -1);
	check(isnan(to_d("abc", 3, NAN)));

	// out of range: the default, with errno set
	errno = 0;
	check(to_d("1e999", 5, -1) == -1);
	check(errno == ERANGE);
	check(to_d("-1e999", 6, -1) == -1);
	check(to_d("1e-999", 6, -1) == -1);

	// longer than any double needs: the default
	char lng[100];
	memset(lng, '0', sizeof(lng));
	lng[sizeof(lng) - 1] = '1';
	check(to_d(lng, sizeof(lng), -1) == -1);
	check(to_d(lng + sizeof(lng) - 63, 63, -1) == 1);

	if (failed)
		return 1;
	printf("all tests passed\n");
	return 0;
}
