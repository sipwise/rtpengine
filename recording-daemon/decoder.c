#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <libavutil/samplefmt.h>
#include <glib.h>
#include <stdint.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "str.h"
#include "output.h"
#include "mix.h"
#include "resample.h"
#include "codeclib.h"


int resample_audio;



decoder_t *decoder_new(const char *payload_str, output_t *outp) {
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

	const codec_def_t *def = codec_find(&name, MT_AUDIO);
	if (!def) {
		ilog(LOG_WARN, "No decoder for payload %s", payload_str);
		return NULL;
	}
	if (def->avcodec_id == -1) // not a real audio codec
		return NULL;

	clockrate *= def->clockrate_mult;

	// we can now config our output, which determines the sample format we convert to
	format_t out_format = {
		.clockrate = clockrate,
		.channels = channels,
		.format = -1,
	};

	if (resample_audio)
		out_format.clockrate = resample_audio;
	// mono/stereo mixing goes here: out_format.channels = ...
	if (outp) {
		// if this output has been configured already, re-use the same format
		if (outp->encoder && outp->encoder->requested_format.format != -1)
			out_format = outp->encoder->requested_format;
		output_config(outp, &out_format, &out_format);
		// save the returned sample format so we don't output_config() twice
		outp->encoder->requested_format.format = out_format.format;
	}

	return decoder_new_fmt(def, clockrate, channels, &out_format);
}


static int decoder_got_frame(decoder_t *dec, AVFrame *frame, void *op, void *mp) {
	metafile_t *metafile = mp;
	output_t *output = op;

	dbg("got frame pts %llu samples %u contents %02x%02x%02x%02x...", (unsigned long long) frame->pts, frame->nb_samples,
			(unsigned int) frame->extended_data[0][0],
			(unsigned int) frame->extended_data[0][1],
			(unsigned int) frame->extended_data[0][2],
			(unsigned int) frame->extended_data[0][3]);

	// handle mix output
	pthread_mutex_lock(&metafile->mix_lock);
	if (metafile->mix_out) {
		if (G_UNLIKELY(dec->mixer_idx == (unsigned int) -1))
			dec->mixer_idx = mix_get_index(metafile->mix);
		format_t actual_format;
		if (output_config(metafile->mix_out, &dec->out_format, &actual_format))
			goto no_mix_out;
		mix_config(metafile->mix, &actual_format);
		// XXX might be a second resampling to same format
		AVFrame *dec_frame = resample_frame(&dec->mix_resampler, frame, &actual_format);
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
		if (output_config(output, &dec->out_format, NULL))
			goto err;
		if (output_add(output, frame))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
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
