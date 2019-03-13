#ifndef _BITSTR_H_
#define _BITSTR_H_

#include "str.h"
#include <assert.h>

struct bitstr_s {
	str s;
	unsigned int bit_offset; // leading consumed bits
};
typedef struct bitstr_s bitstr;

INLINE void bitstr_init(bitstr *b, const str *s) {
	b->s = *s;
	b->bit_offset = 0;
}

INLINE int bitstr_shift_ret(bitstr *b, unsigned int bits, str *ret) {
	if (!bits)
		return 0;
	// check if we have enough
	if (bits > b->s.len * 8 - b->bit_offset)
		return -1;

	unsigned int to_copy = (bits + b->bit_offset + 7) / 8;

	if (ret) {
		assert(ret->len >= to_copy);
		ret->len = to_copy;
		memcpy(ret->s, b->s.s, to_copy);
		unsigned char *ret_s = (unsigned char *) ret->s; // avoid bitshifts on signed chars

		// we have to bit-shift the entire string if there was a leading offset
		if (b->bit_offset) {
			unsigned int left = bits;
			unsigned int c = 0;
			while (b->bit_offset + left > 8) {
				// enough to fill one output byte from two consecutive input bytes
				ret_s[c] <<= b->bit_offset;
				ret_s[c] |= ret_s[c + 1] >> (8 - b->bit_offset);
				if (left <= 8) {
					// final trailing bits overlapping bytes: truncate
					ret_s[c] &= 0xff << (8 - left);
					left = 0;
					ret->len--;
				}
				else
					left -= 8;
				c++;
			}
			if (left) {
				// last byte has the remainder
				ret_s[c] <<= b->bit_offset;
				ret_s[c] &= 0xff << (8 - left);
			}
		}
		else {
			// truncate last byte if needed
			unsigned int bits_left = bits % 8;
			if (bits_left)
				ret_s[to_copy - 1] &= 0xff << (8 - bits_left);
		}
	}

	b->bit_offset += bits;
	unsigned int int_bytes = b->bit_offset / 8;
	int shift_ret = str_shift(&b->s, int_bytes);
	assert(shift_ret == 0);
	(void) shift_ret;
	b->bit_offset -= int_bytes * 8;

	return 0;
}

INLINE int bitstr_shift(bitstr *b, unsigned int bits) {
	return bitstr_shift_ret(b, bits, NULL);
}


#endif
