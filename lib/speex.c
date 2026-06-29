#include "codecmod.h"


static const codec_def_t speex = {
	.rtpname = "speex",
	.avcodec_id = AV_CODEC_ID_SPEEX,
	.default_clockrate = 16000,
	.default_channels = 1,
	.default_bitrate = 11000,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&speex);
}
