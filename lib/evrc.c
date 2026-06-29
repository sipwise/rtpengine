#include "codecmod.h"


#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)

static const codec_def_t evrc = {
	.rtpname = "EVRC",
	.avcodec_id = AV_CODEC_ID_EVRC,
	.default_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
};
static const codec_def_t evrc0 = {
	.rtpname = "EVRC0",
	.avcodec_id = AV_CODEC_ID_EVRC,
	.default_clockrate = 8000,
	.default_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
};
static const codec_def_t evrc1 = {
	.rtpname = "EVRC1",
	.avcodec_id = AV_CODEC_ID_EVRC,
	.default_clockrate = 8000,
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
	codeclib_register_codec(&evrc);
	codeclib_register_codec(&evrc0);
	codeclib_register_codec(&evrc1);
}

#endif
