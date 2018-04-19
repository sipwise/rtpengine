#include "codeclib.h"
#include "str.h"
#include <assert.h>

int frame_cb(decoder_t *dec, AVFrame *frame, void *u1, void *u2) {
	char **expect = u1;
	int *expect_len = u2;
	assert(expect);
	assert(expect_len);
	assert(*expect);
	assert(*expect_len);
	assert(*expect_len == frame->linesize[0]);
	assert(memcmp(frame->data[0], *expect, *expect_len) == 0);
	*expect = NULL;
	*expect_len = 0;
	return 0;
}

void do_test_amr_wb(const char *file, int line,
		char *fmtp_s, char *data_s, int data_len, char *expect_s, int expect_len)
{
	printf("running test %s:%i\n", file, line);
	const str codec_name = STR_CONST_INIT("AMR-WB");
	const codec_def_t *def = codec_find(&codec_name, MT_AUDIO);
	assert(def);
	const format_t fmt = { .clockrate = 16000, .channels = 1, .format = AV_SAMPLE_FMT_S16};
	str fmtp_str, *fmtp = NULL;
	if (fmtp_s) {
		str_init(&fmtp_str, fmtp_s);
		fmtp = &fmtp_str;
	}
	decoder_t *d = decoder_new_fmtp(def, 16000, 1, &fmt, fmtp);
	assert(d);
	const str data = { data_s, data_len };
	int ret = decoder_input_data(d, &data, 1, frame_cb, &expect_s, &expect_len);
	assert(!ret);
	assert(expect_s == NULL);
	decoder_close(d);
	printf("test ok: %s:%i\n", file, line);
}

#define do_test_wb(in, out, fmt) \
	do_test_amr_wb(__FILE__, __LINE__, fmt, in, sizeof(in)-1, out, sizeof(out)-1)

int main() {
	codeclib_init(0);

	do_test_wb(
			"\xf0\x44\xf1\x46\x18\x1d\xd1\x57\x23\x13\x42\xf0\x00\x0c\x50\x33\xdd\xff\x0b\x99\x89\x2c\x68\x52\xf8\xf8\xd9\x59\x16\xd7\x45\xe7\x01\xec\x1f\xfe\x5b\xc6\xf9\x01\xa4\xb5\xe0\x6c\x91\x41\xfe\x52\x2c\xce\x44\xbb\x5a\xdf\x76\x29\xf8\xdb\xca\x18\xd6\x50",
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\xff\x02\x00\xff\xff\xff\xff\x02\x00\xfd\xff\x03\x00\x00\x00\xfd\xff\x04\x00\xfc\xff\x02\x00\x01\x00\xfd\xff\x03\x00\xfe\xff\x01\x00\x01\x00\xff\xff\x01\x00\xff\xff\x01\x00\xff\xff\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\xfe\xff\x02\x00\xff\xff\xff\xff\x03\x00\xfd\xff\x03\x00\xff\xff\xff\xff\x03\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x02\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x02\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x04\x00\xfe\xff\xfd\xff\x00\x00\x02\x00\xfe\xff\xf8\xff\x01\x00\x04\x00\xff\xff\xff\xff\xfc\xff\x06\x00\x00\x00\xf8\xff\x11\x00\x09\x00\x06\x00\x3f\x00\x37\x00\xf9\xff\x11\x00\x4e\x00\x34\x00\xf4\xff\x17\x00\x5d\x00\x31\x00\xe0\xff\x0b\x00\x71\x00\x42\x00\xd3\xff\x09\x00\x74\x00\x3c\x00\xc8\xff\x03\x00\x78\x00\x35\x00\xbc\xff\xff\xff\x7a\x00\x2e\x00\xb0\xff\x00\x00\x77\x00\x26\x00\xaa\xff\xfc\xff\x78\x00\x1c\x00\xa3\xff\xfe\xff\x72\x00\x14\x00\xa0\xff\xfc\xff\x6f\x00\x09\x00\x8e\xff\xfc\xff\x72\x00\xff\xff\x89\xff\xff\xff\x7e\x00\xfe\xff\x7b\xff\x19\x00\xa9\x00\xfa\xff\x62\xff\x14\x00\xae\x00\xf5\xff\x54\xff\x16\x00\xb6\x00\xe8\xff\x3f\xff\x0b\x00\xb9\x00\xee\xff\x34\xff\xfd\xff\xb8\x00\xe9\xff\x2d\xff\x00\x00\xb8\x00\xe4\xff\x2c\xff\xff\xff\xb9\x00\xdf\xff\x25\xff\xff\xff\xb2\x00\xda\xff\x28\xff\xfc\xff\xae\x00\xd6\xff\x2a\xff\xff\xff\xa5\x00\xd8\xff\x30\xff\xfc\xff\xa1\x00\xd5\xff\x35\xff\xf9\xff\x97\x00\xd4\xff\x37\xff\xfa\xff\x92\x00\xcd\xff\x38\xff\xfe\xff\x8e\x00\xcb\xff\x3e\xff\xfe\xff\x88\x00\xcc\xff\x40\xff\xfa\xff\x89\x00\xcf\xff\x41\xff\xfa\xff\x87\x00\xd0\xff\x44\xff\xfa\xff\x89\x00\xd6\xff\x48\xff\xf9\xff\x88\x00\xdd\xff\x4d\xff\xf2\xff\x81\x00\xde\xff\x54\xff\xf4\xff\x7b\x00\xde\xff\x5c\xff\xf6\xff\x73\x00\xe0\xff\x65\xff\xf6\xff\x6d\x00\xe0\xff\x6f\xff\xf7\xff\x63\x00\xe0\xff\x78\xff\xf7\xff\x5d\x00\xde\xff\x76\xff\xf9\xff\x60\x00\xdf\xff\x7f\xff\xfb\xff\x5c\x00\xe8\xff\x85\xff\xfb\xff\x60\x00\xea\xff\x87\xff\xfe\xff\x63\x00\xee\xff\x8b\xff\x00\x00\x64\x00\xf3\xff\x8d\xff\xfe\xff\x66\x00\xf7\xff\x8f\xff\xfd\xff\x68\x00\xf9\xff\x8c\xff\xfd\xff\x6d\x00\xfc\xff\x8c\xff\xfd\xff\x71\x00\xff\xff\x89\xff\xfe\xff\x75\x00\x02\x00\x88\xff\xfc\xff\x78\x00\x03\x00\x87\xff\xfd\xff\x7b\x00\x03\x00\x86\xff\x00\x00\x7e\x00\x03\x00\x84\xff\xfe\xff\x81\x00\x07\x00\x82\xff\x01\x00\x84\x00\x03\x00\x82\xff\x05\x00\x88\x00\x05\x00\x81\xff\x04\x00\x88\x00\x05\x00\x80\xff\x05\x00\x8a\x00\x05\x00",
			"octet-align=1");

	do_test_wb(
			"\xf4\x7c\x51\x86\x07\x74\x55\xc8\xc4\xd0\xbc\x00\x03\x14\x0c\xf7\x7f\xc2\xe6\x62\x4b\x1a\x14\xbe\x3e\x36\x56\x45\xb5\xd1\x79\xc0\x7b\x07\xff\x96\xf1\xbe\x40\x69\x2d\x78\x1b\x24\x50\x7f\x94\x8b\x33\x91\x2e\xd6\xb7\xdd\x8a\x7e\x36\xf2\x86\x35\x94",
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\xff\x02\x00\xff\xff\xff\xff\x02\x00\xfd\xff\x03\x00\x00\x00\xfd\xff\x04\x00\xfc\xff\x02\x00\x01\x00\xfd\xff\x03\x00\xfe\xff\x01\x00\x01\x00\xff\xff\x01\x00\xff\xff\x01\x00\xff\xff\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\xfe\xff\x02\x00\xff\xff\xff\xff\x03\x00\xfd\xff\x03\x00\xff\xff\xff\xff\x03\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x02\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x02\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x04\x00\xfe\xff\xfd\xff\x00\x00\x02\x00\xfe\xff\xf8\xff\x01\x00\x04\x00\xff\xff\xff\xff\xfc\xff\x06\x00\x00\x00\xf8\xff\x11\x00\x09\x00\x06\x00\x3f\x00\x37\x00\xf9\xff\x11\x00\x4e\x00\x34\x00\xf4\xff\x17\x00\x5d\x00\x31\x00\xe0\xff\x0b\x00\x71\x00\x42\x00\xd3\xff\x09\x00\x74\x00\x3c\x00\xc8\xff\x03\x00\x78\x00\x35\x00\xbc\xff\xff\xff\x7a\x00\x2e\x00\xb0\xff\x00\x00\x77\x00\x26\x00\xaa\xff\xfc\xff\x78\x00\x1c\x00\xa3\xff\xfe\xff\x72\x00\x14\x00\xa0\xff\xfc\xff\x6f\x00\x09\x00\x8e\xff\xfc\xff\x72\x00\xff\xff\x89\xff\xff\xff\x7e\x00\xfe\xff\x7b\xff\x19\x00\xa9\x00\xfa\xff\x62\xff\x14\x00\xae\x00\xf5\xff\x54\xff\x16\x00\xb6\x00\xe8\xff\x3f\xff\x0b\x00\xb9\x00\xee\xff\x34\xff\xfd\xff\xb8\x00\xe9\xff\x2d\xff\x00\x00\xb8\x00\xe4\xff\x2c\xff\xff\xff\xb9\x00\xdf\xff\x25\xff\xff\xff\xb2\x00\xda\xff\x28\xff\xfc\xff\xae\x00\xd6\xff\x2a\xff\xff\xff\xa5\x00\xd8\xff\x30\xff\xfc\xff\xa1\x00\xd5\xff\x35\xff\xf9\xff\x97\x00\xd4\xff\x37\xff\xfa\xff\x92\x00\xcd\xff\x38\xff\xfe\xff\x8e\x00\xcb\xff\x3e\xff\xfe\xff\x88\x00\xcc\xff\x40\xff\xfa\xff\x89\x00\xcf\xff\x41\xff\xfa\xff\x87\x00\xd0\xff\x44\xff\xfa\xff\x89\x00\xd6\xff\x48\xff\xf9\xff\x88\x00\xdd\xff\x4d\xff\xf2\xff\x81\x00\xde\xff\x54\xff\xf4\xff\x7b\x00\xde\xff\x5c\xff\xf6\xff\x73\x00\xe0\xff\x65\xff\xf6\xff\x6d\x00\xe0\xff\x6f\xff\xf7\xff\x63\x00\xe0\xff\x78\xff\xf7\xff\x5d\x00\xde\xff\x76\xff\xf9\xff\x60\x00\xdf\xff\x7f\xff\xfb\xff\x5c\x00\xe8\xff\x85\xff\xfb\xff\x60\x00\xea\xff\x87\xff\xfe\xff\x63\x00\xee\xff\x8b\xff\x00\x00\x64\x00\xf3\xff\x8d\xff\xfe\xff\x66\x00\xf7\xff\x8f\xff\xfd\xff\x68\x00\xf9\xff\x8c\xff\xfd\xff\x6d\x00\xfc\xff\x8c\xff\xfd\xff\x71\x00\xff\xff\x89\xff\xfe\xff\x75\x00\x02\x00\x88\xff\xfc\xff\x78\x00\x03\x00\x87\xff\xfd\xff\x7b\x00\x03\x00\x86\xff\x00\x00\x7e\x00\x03\x00\x84\xff\xfe\xff\x81\x00\x07\x00\x82\xff\x01\x00\x84\x00\x03\x00\x82\xff\x05\x00\x88\x00\x05\x00\x81\xff\x04\x00\x88\x00\x05\x00\x80\xff\x05\x00\x8a\x00\x05\x00",
			NULL);

	do_test_wb(
			"\xf4\x7c\x51\x86\x07\x74\x55\xc8\xc4\xd0\xbc\x00\x03\x14\x0c\xf7\x7f\xc2\xe6\x62\x4b\x1a\x14\xbe\x3e\x36\x56\x45\xb5\xd1\x79\xc0\x7b\x07\xff\x96\xf1\xbe\x40\x69\x2d\x78\x1b\x24\x50\x7f\x94\x8b\x33\x91\x2e\xd6\xb7\xdd\x8a\x7e\x36\xf2\x86\x35\x94",
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\xff\x02\x00\xff\xff\xff\xff\x02\x00\xfd\xff\x03\x00\x00\x00\xfd\xff\x04\x00\xfc\xff\x02\x00\x01\x00\xfd\xff\x03\x00\xfe\xff\x01\x00\x01\x00\xff\xff\x01\x00\xff\xff\x01\x00\xff\xff\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\xfe\xff\x02\x00\xff\xff\xff\xff\x03\x00\xfd\xff\x03\x00\xff\xff\xff\xff\x03\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x02\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x02\x00\xfe\xff\x01\x00\x00\x00\xff\xff\x04\x00\xfe\xff\xfd\xff\x00\x00\x02\x00\xfe\xff\xf8\xff\x01\x00\x04\x00\xff\xff\xff\xff\xfc\xff\x06\x00\x00\x00\xf8\xff\x11\x00\x09\x00\x06\x00\x3f\x00\x37\x00\xf9\xff\x11\x00\x4e\x00\x34\x00\xf4\xff\x17\x00\x5d\x00\x31\x00\xe0\xff\x0b\x00\x71\x00\x42\x00\xd3\xff\x09\x00\x74\x00\x3c\x00\xc8\xff\x03\x00\x78\x00\x35\x00\xbc\xff\xff\xff\x7a\x00\x2e\x00\xb0\xff\x00\x00\x77\x00\x26\x00\xaa\xff\xfc\xff\x78\x00\x1c\x00\xa3\xff\xfe\xff\x72\x00\x14\x00\xa0\xff\xfc\xff\x6f\x00\x09\x00\x8e\xff\xfc\xff\x72\x00\xff\xff\x89\xff\xff\xff\x7e\x00\xfe\xff\x7b\xff\x19\x00\xa9\x00\xfa\xff\x62\xff\x14\x00\xae\x00\xf5\xff\x54\xff\x16\x00\xb6\x00\xe8\xff\x3f\xff\x0b\x00\xb9\x00\xee\xff\x34\xff\xfd\xff\xb8\x00\xe9\xff\x2d\xff\x00\x00\xb8\x00\xe4\xff\x2c\xff\xff\xff\xb9\x00\xdf\xff\x25\xff\xff\xff\xb2\x00\xda\xff\x28\xff\xfc\xff\xae\x00\xd6\xff\x2a\xff\xff\xff\xa5\x00\xd8\xff\x30\xff\xfc\xff\xa1\x00\xd5\xff\x35\xff\xf9\xff\x97\x00\xd4\xff\x37\xff\xfa\xff\x92\x00\xcd\xff\x38\xff\xfe\xff\x8e\x00\xcb\xff\x3e\xff\xfe\xff\x88\x00\xcc\xff\x40\xff\xfa\xff\x89\x00\xcf\xff\x41\xff\xfa\xff\x87\x00\xd0\xff\x44\xff\xfa\xff\x89\x00\xd6\xff\x48\xff\xf9\xff\x88\x00\xdd\xff\x4d\xff\xf2\xff\x81\x00\xde\xff\x54\xff\xf4\xff\x7b\x00\xde\xff\x5c\xff\xf6\xff\x73\x00\xe0\xff\x65\xff\xf6\xff\x6d\x00\xe0\xff\x6f\xff\xf7\xff\x63\x00\xe0\xff\x78\xff\xf7\xff\x5d\x00\xde\xff\x76\xff\xf9\xff\x60\x00\xdf\xff\x7f\xff\xfb\xff\x5c\x00\xe8\xff\x85\xff\xfb\xff\x60\x00\xea\xff\x87\xff\xfe\xff\x63\x00\xee\xff\x8b\xff\x00\x00\x64\x00\xf3\xff\x8d\xff\xfe\xff\x66\x00\xf7\xff\x8f\xff\xfd\xff\x68\x00\xf9\xff\x8c\xff\xfd\xff\x6d\x00\xfc\xff\x8c\xff\xfd\xff\x71\x00\xff\xff\x89\xff\xfe\xff\x75\x00\x02\x00\x88\xff\xfc\xff\x78\x00\x03\x00\x87\xff\xfd\xff\x7b\x00\x03\x00\x86\xff\x00\x00\x7e\x00\x03\x00\x84\xff\xfe\xff\x81\x00\x07\x00\x82\xff\x01\x00\x84\x00\x03\x00\x82\xff\x05\x00\x88\x00\x05\x00\x81\xff\x04\x00\x88\x00\x05\x00\x80\xff\x05\x00\x8a\x00\x05\x00",
			"");

	return 0;
}
