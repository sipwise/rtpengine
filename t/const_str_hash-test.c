#include <stdlib.h>
#include <stdio.h>
#include "str.h"

static int test_hash(char *p) {
	str s;
	str_init(&s, p);
	switch (__lookup(&s)) {
		case STR_LOOKUP("one"):
			return 1;
		case STR_LOOKUP("two"):
			return 2;
		case STR_LOOKUP("dashed-string"):
			return 3;
		default:
			return 0;
	}
	// STR_LOOKUP("one") // catch duplicate
}

static void test(char *p, int exp) {
	int h = test_hash(p);
	if (h != exp) {
		printf("%s:%i test failed: %u != %u (string '%s')\n", __FILE__, __LINE__, h, exp, p);
		abort();
	}
}

int main() {
	test("one", 1);
	test("two", 2);
	test("dashed-string", 3);
	test("doesn't exist", 0);
	return 0;
}
