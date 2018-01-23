#ifndef __CODECLIB_H__
#define __CODECLIB_H__


#include <libavresample/avresample.h>
#include <libavcodec/avcodec.h>
#include "str.h"



struct codec_def_s;
struct decoder_s;
struct format_s;
struct resample_s;

typedef struct codec_def_s codec_def_t;
typedef struct decoder_s decoder_t;
typedef struct format_s format_t;
typedef struct resample_s resample_t;



struct codec_def_s {
	const char *rtpname;
	int clockrate_mult;
	int avcodec_id;
	const char *avcodec_name;
};

struct format_s {
	int clockrate;
	int channels;
	int format; // enum AVSampleFormat
};

struct resample_s {
	AVAudioResampleContext *avresample;
};

struct decoder_s {
	format_t in_format,
		 out_format;

	resample_t mix_resample,
		   output_resample;

	AVCodecContext *avcctx;
	AVPacket avpkt;
	unsigned long rtp_ts;
	uint64_t pts;

	unsigned int mixer_idx;
};



void codeclib_init(void);


const codec_def_t *codec_find(const str *name);


decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, int resample);
void decoder_close(decoder_t *dec);
int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2);



INLINE int format_eq(const format_t *a, const format_t *b) {
	if (G_UNLIKELY(a->clockrate != b->clockrate))
		return 0;
	if (G_UNLIKELY(a->channels != b->channels))
		return 0;
	if (G_UNLIKELY(a->format != b->format))
		return 0;
	return 1;
}
INLINE void format_init(format_t *f) {
	f->clockrate = -1;
	f->channels = -1;
	f->format = -1;
}


#endif
