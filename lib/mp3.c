#include "codecmod.h"


static const codec_def_t mp3 = {
	.rtpname = "MP3",
	.avcodec_id = AV_CODEC_ID_MP3,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
};

__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&mp3);
}
