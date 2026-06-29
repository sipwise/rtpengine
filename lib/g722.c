#include "codecmod.h"

static const codec_def_t g722 = {
	.rtpname = "G722",
	.avcodec_id = AV_CODEC_ID_ADPCM_G722,
	.default_clockrate_fact = {2,1},
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.format_cmp = format_cmp_ignore,
	.packetizer = packetizer_samplestream,
	.bits_per_sample = 4,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.silence_pattern = STR_CONST("\xfa"),
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&g722);
}
