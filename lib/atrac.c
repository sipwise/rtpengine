#include "codecmod.h"


static const codec_def_t atrac3 = {
	.rtpname = "ATRAC3",
	.avcodec_id = AV_CODEC_ID_ATRAC3,
	.default_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
};

static const codec_def_t atrac_x = {
	.rtpname = "ATRAC-X",
	.avcodec_id = AV_CODEC_ID_ATRAC3P,
	.default_ptime = 20,
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
	codeclib_register_codec(&atrac3);
	codeclib_register_codec(&atrac_x);
}
