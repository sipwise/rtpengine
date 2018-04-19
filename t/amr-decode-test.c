#include "codeclib.h"
#include "str.h"
#include <assert.h>

int frame_cb(decoder_t *dec, AVFrame *frame, void *u1, void *u2) {
	printf("received frame\n");
	printf("length: %i\n", frame->linesize[0]);
	printf("content: ");
	for (int i = 0; i < frame->linesize[0]; i++)
		printf("%02x", (unsigned int) frame->data[0][i]);
	printf("\n");
	return 0;
}

int main() {
	codeclib_init(0);

	const str codec_name = STR_CONST_INIT("AMR-WB");
	const codec_def_t *def = codec_find(&codec_name, MT_AUDIO);
	assert(def);
	const format_t fmt = { .clockrate = 16000, .channels = 1, .format = AV_SAMPLE_FMT_S16};
	decoder_t *d = decoder_new_fmtp(def, 16000, 1, &fmt, NULL);
	assert(d);
	//const str data = STR_CONST_INIT("\xf0\xde\xc0\x81\xc0\x08\xa9\xbc\x06\x33\x53\x14\x69\xdd\x3d\x2e\xa9\x8f\x81\xee\x2e\x09\x08\x80\xca\x05\x1e\x91\x00\x10\x00\x00\xca\x05\x20\x91\x00\x10\x00\x00\xca\x05\x22\x91\x00\x10\x00\x00\xca\x05\x24\x91\x00\x10\x00\x00\xca\x05\x26\x91\x00\x10");
	const str data = STR_CONST_INIT("\x44\xf1\x46\x18\x1d\xd1\x57\x23\x13\x42\xf0\x00\x0c\x50\x33\xdd\xff\x0b\x99\x89\x2c\x68\x52\xf8\xf8\xd9\x59\x16\xd7\x45\xe7\x01\xec\x1f\xfe\x5b\xc6\xf9\x01\xa4\xb5\xe0\x6c\x91\x41\xfe\x52\x2c\xce\x44\xbb\x5a\xdf\x76\x29\xf8\xdb\xca\x18\xd6\x50");
	int ret = decoder_input_data(d, &data, 1, frame_cb, NULL, NULL);
	assert(!ret);

	return 0;
}
