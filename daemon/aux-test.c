#include <stdio.h>
#include "aux.h"


int test[32] = {
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0xff,

	0x10ff, 0x20ff, 0x30ff, 0x40ff, 0x50ff, 0x60ff, 0x70ff, 0x80ff,
	0x90ff, 0xa0ff, 0xb0ff, 0xc0ff, 0xd0ff, 0xe0ff, 0xf0ff, 0xffff,
};

void exsrx(int x, int exp, unsigned int s, int ex) {
	int ret = mybsearch(test, s, sizeof(int), &x, 0, sizeof(x), ex);
	if (ret != exp)
		fprintf(stderr, "TEST FAILED! params=%u %i; result=%i, expected=%i\n", s, ex, ret, exp);
}

void exsr1(int x, int exp) {
	exsrx(x, exp, 16, 1);
}

void exsr2(int x, int exp) {
	exsrx(x, exp, 15, 1);
}

void exsr3(int x, int exp) {
	exsrx(x, exp, 2, 1);
}

void exsr4(int x, int exp) {
	exsrx(x, exp, 1, 1);
}

void exsr5(int x, int exp) {
	exsrx(x, exp, 32, 1);
}

void exsr6(int x, int exp) {
	exsrx(x, exp, 31, 1);
}

void exsr7(int x, int exp) {
	exsrx(x, exp, 16, 0);
}

void exsr8(int x, int exp) {
	exsrx(x, exp, 15, 0);
}

void exsr9(int x, int exp) {
	exsrx(x, exp, 2, 0);
}

void exsr10(int x, int exp) {
	exsrx(x, exp, 1, 0);
}

void exsr11(int x, int exp) {
	exsrx(x, exp, 32, 0);
}

void exsr12(int x, int exp) {
	exsrx(x, exp, 31, 0);
}

int main() {
	exsr1(0x10, 0);
	exsr1(0x20, 1);
	exsr1(0x30, 2);
	exsr1(0x40, 3);
	exsr1(0x50, 4);
	exsr1(0x60, 5);
	exsr1(0x70, 6);
	exsr1(0x80, 7);
	exsr1(0x90, 8);
	exsr1(0xa0, 9);
	exsr1(0xb0, 10);
	exsr1(0xc0, 11);
	exsr1(0xd0, 12);
	exsr1(0xe0, 13);
	exsr1(0xf0, 14);
	exsr1(0xff, 15);
	exsr1(0xffff, -1);
	exsr1(0xfe, -1);

	exsr2(0x10, 0);
	exsr2(0x20, 1);
	exsr2(0x30, 2);
	exsr2(0x40, 3);
	exsr2(0x50, 4);
	exsr2(0x60, 5);
	exsr2(0x70, 6);
	exsr2(0x80, 7);
	exsr2(0x90, 8);
	exsr2(0xa0, 9);
	exsr2(0xb0, 10);
	exsr2(0xc0, 11);
	exsr2(0xd0, 12);
	exsr2(0xe0, 13);
	exsr2(0xf0, 14);
	exsr2(0xff, -1);

	exsr3(0x10, 0);
	exsr3(0x20, 1);
	exsr3(0x30, -1);

	exsr4(0x10, 0);
	exsr4(0x20, -1);

	exsr5(0x10, 0);
	exsr5(0x20, 1);
	exsr5(0x30, 2);
	exsr5(0x40, 3);
	exsr5(0x50, 4);
	exsr5(0x60, 5);
	exsr5(0x70, 6);
	exsr5(0x80, 7);
	exsr5(0x90, 8);
	exsr5(0xa0, 9);
	exsr5(0xb0, 10);
	exsr5(0xc0, 11);
	exsr5(0xd0, 12);
	exsr5(0xe0, 13);
	exsr5(0xf0, 14);
	exsr5(0xff, 15);
	exsr5(0x10ff, 16);
	exsr5(0x20ff, 17);
	exsr5(0x30ff, 18);
	exsr5(0x40ff, 19);
	exsr5(0x50ff, 20);
	exsr5(0x60ff, 21);
	exsr5(0x70ff, 22);
	exsr5(0x80ff, 23);
	exsr5(0x90ff, 24);
	exsr5(0xa0ff, 25);
	exsr5(0xb0ff, 26);
	exsr5(0xc0ff, 27);
	exsr5(0xd0ff, 28);
	exsr5(0xe0ff, 29);
	exsr5(0xf0ff, 30);
	exsr5(0xffff, 31);
	exsr5(0xfff3, -1);
	exsr5(0xffffff, -1);

	exsr6(0x10, 0);
	exsr6(0x20, 1);
	exsr6(0x30, 2);
	exsr6(0x40, 3);
	exsr6(0x50, 4);
	exsr6(0x60, 5);
	exsr6(0x70, 6);
	exsr6(0x80, 7);
	exsr6(0x90, 8);
	exsr6(0xa0, 9);
	exsr6(0xb0, 10);
	exsr6(0xc0, 11);
	exsr6(0xd0, 12);
	exsr6(0xe0, 13);
	exsr6(0xf0, 14);
	exsr6(0xff, 15);
	exsr6(0x10ff, 16);
	exsr6(0x20ff, 17);
	exsr6(0x30ff, 18);
	exsr6(0x40ff, 19);
	exsr6(0x50ff, 20);
	exsr6(0x60ff, 21);
	exsr6(0x70ff, 22);
	exsr6(0x80ff, 23);
	exsr6(0x90ff, 24);
	exsr6(0xa0ff, 25);
	exsr6(0xb0ff, 26);
	exsr6(0xc0ff, 27);
	exsr6(0xd0ff, 28);
	exsr6(0xe0ff, 29);
	exsr6(0xf0ff, 30);
	exsr6(0xffff, -1);





	exsr7(0x10, 0);
	exsr7(0x20, 1);
	exsr7(0x30, 2);
	exsr7(0x40, 3);
	exsr7(0x50, 4);
	exsr7(0x60, 5);
	exsr7(0x70, 6);
	exsr7(0x80, 7);
	exsr7(0x90, 8);
	exsr7(0xa0, 9);
	exsr7(0xb0, 10);
	exsr7(0xc0, 11);
	exsr7(0xd0, 12);
	exsr7(0xe0, 13);
	exsr7(0xf0, 14);
	exsr7(0xff, 15);
	exsr7(0xffff, -17);
	exsr7(0xfe, -16);
	exsr7(0x00, -1);
	exsr8(0x05, -1);
	exsr8(0x15, -2);

	exsr8(0x10, 0);
	exsr8(0x20, 1);
	exsr8(0x30, 2);
	exsr8(0x40, 3);
	exsr8(0x50, 4);
	exsr8(0x60, 5);
	exsr8(0x70, 6);
	exsr8(0x80, 7);
	exsr8(0x90, 8);
	exsr8(0xa0, 9);
	exsr8(0xb0, 10);
	exsr8(0xc0, 11);
	exsr8(0xd0, 12);
	exsr8(0xe0, 13);
	exsr8(0xf0, 14);
	exsr8(0xff, -16);
	exsr8(0xffff, -16);
	exsr8(0xef, -15);
	exsr8(0x00, -1);
	exsr8(0x05, -1);
	exsr8(0x15, -2);

	exsr9(0x10, 0);
	exsr9(0x20, 1);
	exsr9(0x30, -3);

	exsr10(0x10, 0);
	exsr10(0x20, -2);

	exsr11(0x10, 0);
	exsr11(0x20, 1);
	exsr11(0x30, 2);
	exsr11(0x40, 3);
	exsr11(0x50, 4);
	exsr11(0x60, 5);
	exsr11(0x70, 6);
	exsr11(0x80, 7);
	exsr11(0x90, 8);
	exsr11(0xa0, 9);
	exsr11(0xb0, 10);
	exsr11(0xc0, 11);
	exsr11(0xd0, 12);
	exsr11(0xe0, 13);
	exsr11(0xf0, 14);
	exsr11(0xff, 15);
	exsr11(0x10ff, 16);
	exsr11(0x20ff, 17);
	exsr11(0x30ff, 18);
	exsr11(0x40ff, 19);
	exsr11(0x50ff, 20);
	exsr11(0x60ff, 21);
	exsr11(0x70ff, 22);
	exsr11(0x80ff, 23);
	exsr11(0x90ff, 24);
	exsr11(0xa0ff, 25);
	exsr11(0xb0ff, 26);
	exsr11(0xc0ff, 27);
	exsr11(0xd0ff, 28);
	exsr11(0xe0ff, 29);
	exsr11(0xf0ff, 30);
	exsr11(0xffff, 31);
	exsr11(0xfff3, -16);
	exsr11(0xffffff, -33);

	exsr12(0x10, 0);
	exsr12(0x20, 1);
	exsr12(0x30, 2);
	exsr12(0x40, 3);
	exsr12(0x50, 4);
	exsr12(0x60, 5);
	exsr12(0x70, 6);
	exsr12(0x80, 7);
	exsr12(0x90, 8);
	exsr12(0xa0, 9);
	exsr12(0xb0, 10);
	exsr12(0xc0, 11);
	exsr12(0xd0, 12);
	exsr12(0xe0, 13);
	exsr12(0xf0, 14);
	exsr12(0xff, 15);
	exsr12(0x10ff, 16);
	exsr12(0x20ff, 17);
	exsr12(0x30ff, 18);
	exsr12(0x40ff, 19);
	exsr12(0x50ff, 20);
	exsr12(0x60ff, 21);
	exsr12(0x70ff, 22);
	exsr12(0x80ff, 23);
	exsr12(0x90ff, 24);
	exsr12(0xa0ff, 25);
	exsr12(0xb0ff, 26);
	exsr12(0xc0ff, 27);
	exsr12(0xd0ff, 28);
	exsr12(0xe0ff, 29);
	exsr12(0xf0ff, 30);
	exsr12(0xffff, -32);

	printf("all done\n");

	return 0;
}
