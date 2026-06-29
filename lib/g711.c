#include "codecmod.h"


static const codec_def_t pcma = {
	.rtpname = "PCMA",
	.avcodec_id = AV_CODEC_ID_PCM_ALAW,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.packetizer = packetizer_samplestream,
	.format_cmp = format_cmp_ignore,
	.bits_per_sample = 8,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.silence_pattern = STR_CONST("\xd5"),
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};

static const codec_def_t pcmu = {
	.rtpname = "PCMU",
	.avcodec_id = AV_CODEC_ID_PCM_MULAW,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.packetizer = packetizer_samplestream,
	.bits_per_sample = 8,
	.format_cmp = format_cmp_ignore,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.silence_pattern = STR_CONST("\xff"),
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,

};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&pcma);
	codeclib_register_codec(&pcmu);
}
