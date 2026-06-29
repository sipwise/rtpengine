#include "codecmod.h"


static const codec_def_t l16 = {
	.rtpname = "L16",
	.avcodec_id = AV_CODEC_ID_PCM_S16BE,
	.default_clockrate = 44100,
	.default_channels = 1,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.bits_per_sample = 16,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
};
static const codec_def_t x_l16 = {
	.rtpname = "X-L16",
	.avcodec_id = AV_CODEC_ID_PCM_S16LE,
	.default_clockrate = 44100,
	.default_channels = 1,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.bits_per_sample = 16,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
};



__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&l16);
	codeclib_register_codec(&x_l16);
}
