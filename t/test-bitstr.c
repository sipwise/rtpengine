#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "bitstr.h"
#include "str.h"

#define do_test_ret(retval, args...) do { \
	int r = do_test(args); \
	if (r != retval) \
		err("didn't run all tests!\n"); \
	} while (0)
#define test1(input, shift_len, output, result) \
	do_test_ret(1, input, sizeof(input)-1, __FILE__, __LINE__, shift_len, output, sizeof(output)-1, \
			result, 0)
#define test2(input, shift_len1, output1, result1, shift_len2, output2, result2) \
	do_test_ret(2, input, sizeof(input)-1, __FILE__, __LINE__, \
			shift_len1, output1, sizeof(output1)-1, result1, \
			shift_len2, output2, sizeof(output2)-1, result2, \
			0)
#define test3(input, \
		shift_len1, output1, result1, \
		shift_len2, output2, result2, \
		shift_len3, output3, result3) \
	do_test_ret(3, input, sizeof(input)-1, __FILE__, __LINE__, \
			shift_len1, output1, sizeof(output1)-1, result1, \
			shift_len2, output2, sizeof(output2)-1, result2, \
			shift_len3, output3, sizeof(output3)-1, result3, \
			0)

#define err(fmt...) do { \
		fprintf(stderr, fmt); \
		exit(1); \
	} while (0)

int do_test(const char *input, unsigned int input_len,
		const char *file, unsigned int line,
		...)
{
	char in_buf[input_len];
	memcpy(in_buf, input, input_len);
	str inp = STR_LEN(in_buf, input_len);
	bitstr inp_bs;
	bitstr_init(&inp_bs, &inp);

	va_list ap;
	va_start(ap, line);
	int argc = 0;

	while (1) {
		unsigned int shift_len = va_arg(ap, unsigned int);
		if (!shift_len)
			break;
		const char *output = va_arg(ap, const char *);
		unsigned int output_len = va_arg(ap, unsigned int);
		int result = va_arg(ap, int);

		char out_buf[output_len+1];
		str outp = STR_CONST_BUF(out_buf);

		int ret;
		if (output)
			ret = bitstr_shift_ret(&inp_bs, shift_len, &outp);
		else
			ret = bitstr_shift(&inp_bs, shift_len);

		if (ret != result)
			err("ERROR return %i instead of %i (%s:%i arg %i)\n",
					ret, result, file, line, argc);
		if (ret == 0 && output) {
			if (outp.len != output_len)
				err("ERROR output len %zu instead of %u (%s:%i arg %i)\n",
						outp.len, output_len, file, line, argc);
			if (memcmp(outp.s, output, output_len))
				err("ERROR output string mismatch (%s:%i arg %i)\n",
						file, line, argc);
		}
//		if (inp.len != remainder_len)
//			err("ERROR remainder len %i instead of %i (%s:%i arg %i)\n",
//					inp.len, remainder_len, file, line, argc);

		printf("test ok: %s:%i arg %i\n", file, line, argc);
		argc++;
	}

	return argc;
}

int main(void) {
	test1("\x81", 8, "\x81", 0);
	test2("\x81", 8, "\x81", 0, 1, "", -1);
	test2("\x81", 8, "\x81", 0, 1, NULL, -1);

	test1("\x81", 7, "\x80", 0);
	test2("\x81", 7, "\x80", 0, 1, "\x80", 0);
	test3("\x81", 7, "\x80", 0, 1, "\x80", 0, 1, "", -1);
	test3("\x81", 7, "\x80", 0, 1, NULL, 0, 1, "", -1);
	test3("\x81", 7, "\x80", 0, 1, "\x80", 0, 1, NULL, -1);
	test3("\x81", 7, "\x80", 0, 1, NULL, 0, 1, NULL, -1);
	test2("\x81", 7, "\x80", 0, 2, "", -1);
	test2("\x81", 7, "\x80", 0, 2, NULL, -1);

	test1("\x82", 7, "\x82", 0);
	test2("\x82", 7, "\x82", 0, 1, "\x00", 0);
	test2("\x82", 7, NULL, 0, 1, "\x00", 0);
	test3("\x82", 7, "\x82", 0, 1, "\x00", 0, 1, "", -1);
	test3("\x82", 7, "\x82", 0, 1, NULL, 0, 1, "", -1);
	test3("\x82", 7, "\x82", 0, 1, "\x00", 0, 1, NULL, -1);
	test3("\x82", 7, "\x82", 0, 1, NULL, 0, 1, NULL, -1);
	test2("\x82", 7, "\x82", 0, 2, "", -1);
	test2("\x82", 7, "\x82", 0, 2, NULL, -1);

	test1("\x83", 7, "\x82", 0);
	test2("\x83", 7, "\x82", 0, 1, "\x80", 0);
	test2("\x83", 7, NULL, 0, 1, "\x80", 0);
	test3("\x83", 7, "\x82", 0, 1, "\x80", 0, 1, "", -1);
	test3("\x83", 7, "\x82", 0, 1, NULL, 0, 1, "", -1);
	test2("\x83", 7, "\x82", 0, 2, "", -1);

	test1("\x81", 1, "\x80", 0);
	test2("\x81", 1, "\x80", 0, 7, "\x02", 0);
	test3("\x81", 1, "\x80", 0, 7, "\x02", 0, 1, "", -1);
	test3("\x81", 1, NULL, 0, 7, "\x02", 0, 1, "", -1);
	test3("\x81", 1, "\x80", 0, 7, NULL, 0, 1, "", -1);
	test3("\x81", 1, NULL, 0, 7, NULL, 0, 1, "", -1);

	test1("\xff", 1, "\x80", 0);
	test2("\xff", 1, "\x80", 0, 5, "\xf8", 0);
	test3("\xff", 1, "\x80", 0, 5, "\xf8", 0, 2, "\xc0", 0);
	test3("\xff", 1, NULL, 0, 5, "\xf8", 0, 2, "\xc0", 0);
	test3("\xff", 1, "\x80", 0, 5, NULL, 0, 2, "\xc0", 0);
	test3("\xff", 1, NULL, 0, 5, NULL, 0, 2, "\xc0", 0);
	test3("\xff", 1, "\x80", 0, 5, "\xf8", 0, 3, "", -1);
	test2("\xff", 1, "\x80", 0, 7, "\xfe", 0);
	test3("\xff", 1, "\x80", 0, 7, "\xfe", 0, 1, "", -1);
	test3("\xff", 1, NULL, 0, 7, "\xfe", 0, 1, "", -1);
	test3("\xff", 1, "\x80", 0, 7, NULL, 0, 1, "", -1);
	test3("\xff", 1, NULL, 0, 7, NULL, 0, 1, "", -1);

	test1("J76x", 8, "J", 0);

	test2("J76x", 8, "J", 0, 8, "7", 0);
	test3("J76x", 8, "J", 0, 8, "7", 0, 7, "6", 0);
	test3("J76x", 8, "J", 0, 8, "7", 0, 14, "6x", 0);
	test3("J76x", 8, "J", 0, 8, "7", 0, 16, "6x", 0);
	test3("J76x", 8, "J", 0, 8, "7", 0, 17, "", -1);

	test2("J76x", 8, "J", 0, 12, "70", 0);
	test3("J76x", 8, "J", 0, 12, "70", 0, 3, "`", 0);
	test3("J76x", 8, "J", 0, 12, "70", 0, 6, "d", 0);
	test3("J76x", 8, "J", 0, 12, "70", 0, 8, "g", 0);
	test3("J76x", 8, "J", 0, 12, "70", 0, 12, "g\x80", 0);
	test3("J76x", 8, NULL, 0, 12, "70", 0, 12, "g\x80", 0);
	test3("J76x", 8, "J", 0, 12, NULL, 0, 12, "g\x80", 0);
	test3("J76x", 8, NULL, 0, 12, NULL, 0, 12, "g\x80", 0);
	test3("J76x", 8, "J", 0, 12, "70", 0, 13, "", -1);

	test2("J76x", 8, "J", 0, 14, "74", 0);
	test3("J76x", 8, "J", 0, 14, "74", 0, 5, "\x98", 0);
	test3("J76x", 8, NULL, 0, 14, "74", 0, 5, "\x98", 0);
	test3("J76x", 8, "J", 0, 14, NULL, 0, 5, "\x98", 0);
	test3("J76x", 8, NULL, 0, 14, NULL, 0, 5, "\x98", 0);
	test3("J76x", 8, "J", 0, 14, "74", 0, 8, "\x9e", 0);
	test3("J76x", 8, NULL, 0, 14, "74", 0, 8, "\x9e", 0);
	test3("J76x", 8, "J", 0, 14, NULL, 0, 8, "\x9e", 0);
	test3("J76x", 8, NULL, 0, 14, NULL, 0, 8, "\x9e", 0);

	test1("J76x", 12, "J0", 0);
	test2("J76x", 12, "J0", 0, 3, "`", 0);
	test3("J76x", 12, "J0", 0, 3, "`", 0, 3, "\x80", 0);
	test3("J76x", 12, "J0", 0, 3, "`", 0, 6, "\x98", 0);

	test2("J76x", 12, "J0", 0, 4, "p", 0);
	test2("J76x", 12, "J0", 0, 4, "p", 0);
	test3("J76x", 12, "J0", 0, 4, "p", 0, 3, "\x20", 0);
	test3("J76x", 12, "J0", 0, 4, "p", 0, 6, "\x34", 0);

	test2("J76x", 12, "J0", 0, 6, "p", 0);
	test2("J76x", 12, "J0", 0, 6, "p", 0);
	test3("J76x", 12, "J0", 0, 6, "p", 0, 3, "\xc0", 0);
	test3("J76x", 12, "J0", 0, 6, "p", 0, 6, "\xd8", 0);

	test2("J76x", 12, "J0", 0, 8, "s", 0);
	test2("J76x", 12, "J0", 0, 8, "s", 0);
	test3("J76x", 12, "J0", 0, 8, "s", 0, 3, "\x60", 0);
	test3("J76x", 12, "J0", 0, 8, "s", 0, 6, "\x64", 0);

	test2("J76x", 12, "J0", 0, 11, "s`", 0);
	test2("J76x", 12, "J0", 0, 11, "s`", 0);
	test3("J76x", 12, "J0", 0, 11, "s`", 0, 3, "\x20", 0);
	test3("J76x", 12, "J0", 0, 11, "s`", 0, 6, "\x3c", 0);

	test2("J76x", 12, "J0", 0, 18, "sg\x80", 0);
	test2("J76x", 12, "J0", 0, 18, "sg\x80", 0);
	test3("J76x", 12, "J0", 0, 18, "sg\x80", 0, 2, "\x00", 0);
	test3("J76x", 12, "J0", 0, 18, NULL, 0, 2, "\x00", 0);
	test3("J76x", 12, NULL, 0, 18, "sg\x80", 0, 2, "\x00", 0);
	test3("J76x", 12, NULL, 0, 18, NULL, 0, 2, "\x00", 0);
	test3("J76x", 12, "J0", 0, 18, "sg\x80", 0, 3, NULL, -1);

	// non octet aligned AMR
	test3("\xf0\xde\xc0\x81\xc0\x08\xa9\xbc\x06\x33\x53\x14\x69\xdd\x3d\x2e\xa9\x8f\x81\xee\x2e\x09\x08\x80\xca\x05\x1e\x91\x00\x10\x00\x00\xca\x05\x20\x91\x00\x10\x00\x00\xca\x05\x22\x91\x00\x10\x00\x00\xca\x05\x24\x91\x00\x10\x00\x00\xca\x05\x26\x91\x00\x10", 4, "\xf0", 0, 6, "\x0c", 0, 177, "\x7b\x02\x07\x00\x22\xa6\xf0\x18\xcd\x4c\x51\xa7\x74\xf4\xba\xa6\x3e\x07\xb8\xb8\x24\x22\x00", 0);
}
