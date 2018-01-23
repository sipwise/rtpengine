#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <libavutil/samplefmt.h>
#include <glib.h>
#include <stdint.h>
#include <libavresample/avresample.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "str.h"
#include "output.h"
#include "mix.h"
#include "resample.h"
#include "codeclib.h"


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




int resample_audio;



decoder_t *decoder_new(const char *payload_str) {
	str name;
	char *slash = strchr(payload_str, '/');
	if (!slash) {
		ilog(LOG_WARN, "Invalid payload format: %s", payload_str);
		return NULL;
	}

	str_init_len(&name, (char *) payload_str, slash - payload_str);
	int clockrate = atoi(slash + 1);

	int channels = 1;
	slash = strchr(slash + 1, '/');
	if (slash) {
		channels = atoi(slash + 1);
		if (!channels)
			channels = 1;
	}

	const codec_def_t *def = codec_find(&name);
	if (!def) {
		ilog(LOG_WARN, "No decoder for payload %s", payload_str);
		return NULL;
	}
	clockrate *= def->clockrate_mult;

	return decoder_new_fmt(def, clockrate, channels, resample_audio);
}


static int decoder_got_frame(decoder_t *dec, AVFrame *frame, void *op, void *mp) {
	metafile_t *metafile = mp;
	output_t *output = op;

	dbg("got frame pts %llu samples %u contents %02x%02x%02x%02x...", (unsigned long long) frame->pts, frame->nb_samples,
			(unsigned int) frame->extended_data[0][0],
			(unsigned int) frame->extended_data[0][1],
			(unsigned int) frame->extended_data[0][2],
			(unsigned int) frame->extended_data[0][3]);

	// determine and save sample type
	if (G_UNLIKELY(dec->in_format.format == -1))
		dec->in_format.format = dec->out_format.format = frame->format;

	// handle mix output
	pthread_mutex_lock(&metafile->mix_lock);
	if (metafile->mix_out) {
		if (G_UNLIKELY(dec->mixer_idx == (unsigned int) -1))
			dec->mixer_idx = mix_get_index(metafile->mix);
		format_t actual_format;
		if (output_config(metafile->mix_out, &dec->out_format, &actual_format))
			goto no_mix_out;
		mix_config(metafile->mix, &actual_format);
		AVFrame *dec_frame = resample_frame(&dec->mix_resample, frame, &actual_format);
		if (!dec_frame) {
			pthread_mutex_unlock(&metafile->mix_lock);
			goto err;
		}
		if (mix_add(metafile->mix, dec_frame, dec->mixer_idx, metafile->mix_out))
			ilog(LOG_ERR, "Failed to add decoded packet to mixed output");
	}
no_mix_out:
	pthread_mutex_unlock(&metafile->mix_lock);

	if (output) {
		// XXX might be a second resampling to same format
		format_t actual_format;
		if (output_config(output, &dec->out_format, &actual_format))
			goto err;
		AVFrame *dec_frame = resample_frame(&dec->output_resample, frame, &actual_format);
		if (!dec_frame)
			goto err;
		if (output_add(output, dec_frame))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
		av_frame_free(&dec_frame);
	}

	av_frame_free(&frame);
	return 0;

err:
	av_frame_free(&frame);
	return -1;
}


int decoder_input(decoder_t *dec, const str *data, unsigned long ts, output_t *output, metafile_t *metafile) {
	return decoder_input_data(dec, data, ts, decoder_got_frame, output, metafile);
}
