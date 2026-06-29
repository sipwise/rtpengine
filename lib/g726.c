#include "codecmod.h"


static const char *g726_encoder_init(encoder_t *enc, const str *extra_opts) {
	const char *err = avc_encoder_init(enc, extra_opts);
	if (err)
		return err;

	enc->samples_per_packet = enc->ptime * 8;

	return NULL;
}

static const codec_type_t codec_type_g726 = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = avc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = g726_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};


static const codec_def_t g726_16 = {
		.rtpname = "G726-16",
		.avcodec_id = AV_CODEC_ID_ADPCM_G726,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.default_bitrate = 16000,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 2,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_g726,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
};
static const codec_def_t g726_24 = {
		.rtpname = "G726-24",
		.avcodec_id = AV_CODEC_ID_ADPCM_G726,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.default_bitrate = 24000,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 3,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_g726,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
};
static const codec_def_t g726_32 = {
		.rtpname = "G726-32",
		.avcodec_id = AV_CODEC_ID_ADPCM_G726,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.default_bitrate = 32000,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 4,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_g726,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
};
static const codec_def_t g726_40 = {
		.rtpname = "G726-40",
		.avcodec_id = AV_CODEC_ID_ADPCM_G726,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.default_bitrate = 40000,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 5,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_g726,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&g726_16);
	codeclib_register_codec(&g726_24);
	codeclib_register_codec(&g726_32);
	codeclib_register_codec(&g726_40);
}
