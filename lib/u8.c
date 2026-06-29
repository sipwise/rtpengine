#include "codecmod.h"


static const codec_def_t u8 = {
	.rtpname = "PCM-U8",
	.avcodec_id = AV_CODEC_ID_PCM_U8,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
};

__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&u8);
}
