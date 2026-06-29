#include "codecmod.h"


static const codec_def_t ac3 = {
	.rtpname = "ac3",
	.avcodec_id = AV_CODEC_ID_AC3,
	.default_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
};

static const codec_def_t eac3 = {
	.rtpname = "eac3",
	.avcodec_id = AV_CODEC_ID_EAC3,
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
	codeclib_register_codec(&ac3);
	codeclib_register_codec(&eac3);
}
