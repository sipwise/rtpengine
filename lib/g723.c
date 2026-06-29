#include "codecmod.h"

static const codec_def_t g723 = {
	.rtpname = "G723",
	.avcodec_id = AV_CODEC_ID_G723_1,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 30,
	.minimum_ptime = 30,
	.default_bitrate = 6300,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};

__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&g723);
}
