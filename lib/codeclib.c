#include "codeclib.h"
#include <libavcodec/avcodec.h>
#include <glib.h>
#include "str.h"




#define CODEC_DEF_MULT_NAME(ref, id, mult, name) { \
	.rtpname = #ref, \
	.avcodec_id = AV_CODEC_ID_ ## id, \
	.clockrate_mult = mult, \
	.avcodec_name = #name, \
}
#define CODEC_DEF_MULT(ref, id, mult) CODEC_DEF_MULT_NAME(ref, id, mult, NULL)
#define CODEC_DEF_NAME(ref, id, name) CODEC_DEF_MULT_NAME(ref, id, 1, name)
#define CODEC_DEF(ref, id) CODEC_DEF_MULT(ref, id, 1)

static const struct codec_def_s codecs[] = {
	CODEC_DEF(PCMA, PCM_ALAW),
	CODEC_DEF(PCMU, PCM_MULAW),
	CODEC_DEF(G723, G723_1),
	CODEC_DEF_MULT(G722, ADPCM_G722, 2),
	CODEC_DEF(QCELP, QCELP),
	CODEC_DEF(G729, G729),
	CODEC_DEF(speex, SPEEX),
	CODEC_DEF(GSM, GSM),
	CODEC_DEF(iLBC, ILBC),
	CODEC_DEF_NAME(opus, OPUS, libopus),
	CODEC_DEF_NAME(vorbis, VORBIS, libvorbis),
	CODEC_DEF(ac3, AC3),
	CODEC_DEF(eac3, EAC3),
	CODEC_DEF(ATRAC3, ATRAC3),
	CODEC_DEF(ATRAC-X, ATRAC3P),
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	CODEC_DEF(EVRC, EVRC),
	CODEC_DEF(EVRC0, EVRC),
	CODEC_DEF(EVRC1, EVRC),
#endif
	CODEC_DEF(AMR, AMR_NB),
	CODEC_DEF(AMR-WB, AMR_WB),
};



// XXX use hashtable for quicker lookup
const codec_def_t *codec_find(const str *name) {
	for (int i = 0; i < G_N_ELEMENTS(codecs); i++) {
		if (!str_cmp(name, codecs[i].rtpname))
			return &codecs[i];
	}
	return NULL;
}
