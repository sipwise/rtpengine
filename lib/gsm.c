#include "codecmod.h"


static const codec_def_t gsm = {
	.rtpname = "GSM",
	.avcodec_id = AV_CODEC_ID_GSM,
	.default_clockrate = 8000,
	.default_channels = 1,
	//.default_bitrate = 13200,
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
	codeclib_register_codec(&gsm);
}
