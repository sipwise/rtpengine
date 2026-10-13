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

int main(void) {
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
