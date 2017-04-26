#include "resample.h"
#include <glib.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <inttypes.h>
#include <libavresample/avresample.h>
#include <libavutil/opt.h>
#include <libavutil/frame.h>
#include "log.h"
#include "types.h"




AVFrame *resample_frame(resample_t *resample, AVFrame *frame, const format_t *to_format) {
	const char *err;
	int errcode = 0;

	uint64_t to_channel_layout = av_get_default_channel_layout(to_format->channels);
	if (frame->format != to_format->format)
		goto resample;
	if (frame->sample_rate != to_format->clockrate)
		goto resample;
	if (frame->channel_layout != to_channel_layout)
		goto resample;

	return av_frame_clone(frame);

resample:

	if (G_UNLIKELY(!resample->avresample)) {
		resample->avresample = avresample_alloc_context();
		err = "failed to alloc resample context";
		if (!resample->avresample)
			goto err;

#if LIBAVUTIL_VERSION_INT >= AV_VERSION_INT(54, 31, 0)
		if (!frame->channel_layout)
			frame->channel_layout = av_get_default_channel_layout(
				av_frame_get_channels(frame));
#endif

		err = "failed to set resample option";
		if ((errcode = av_opt_set_int(resample->avresample, "in_channel_layout",
				frame->channel_layout, 0)))
			goto err;
		if ((errcode = av_opt_set_int(resample->avresample, "in_sample_fmt",
				frame->format, 0)))
			goto err;
		if ((errcode = av_opt_set_int(resample->avresample, "in_sample_rate",
				frame->sample_rate, 0)))
			goto err;
		if ((errcode = av_opt_set_int(resample->avresample, "out_channel_layout",
				to_channel_layout, 0)))
			goto err;
		if ((errcode = av_opt_set_int(resample->avresample, "out_sample_fmt",
				to_format->format, 0)))
			goto err;
		if ((errcode = av_opt_set_int(resample->avresample, "out_sample_rate",
				to_format->clockrate, 0)))
			goto err;
		// av_opt_set_int(dec->avresample, "internal_sample_fmt", AV_SAMPLE_FMT_FLTP, 0); // ?

		err = "failed to init resample context";
		if ((errcode = avresample_open(resample->avresample)) < 0)
			goto err;
	}

	// get a large enough buffer for resampled audio - this should be enough so we don't
	// have to loop
	int dst_samples = avresample_available(resample->avresample) +
		av_rescale_rnd(avresample_get_delay(resample->avresample) + frame->nb_samples,
				to_format->clockrate, frame->sample_rate, AV_ROUND_UP);

	AVFrame *swr_frame = av_frame_alloc();

	err = "failed to alloc resampling frame";
	if (!swr_frame)
		goto err;
	av_frame_copy_props(swr_frame, frame);
	swr_frame->format = to_format->format;
	swr_frame->channel_layout = to_channel_layout;
	swr_frame->nb_samples = dst_samples;
	swr_frame->sample_rate = to_format->clockrate;
	err = "failed to get resample buffers";
	if ((errcode = av_frame_get_buffer(swr_frame, 0)) < 0)
		goto err;

	swr_frame->nb_samples = dst_samples;
	int ret_samples = avresample_convert(resample->avresample, swr_frame->extended_data,
				swr_frame->linesize[0], dst_samples,
				frame->extended_data,
				frame->linesize[0], frame->nb_samples);
	err = "failed to resample audio";
	if ((errcode = ret_samples) < 0)
		goto err;

	swr_frame->nb_samples = ret_samples;
	swr_frame->pts = av_rescale(frame->pts, to_format->clockrate, frame->sample_rate);
	return swr_frame;

err:
	ilog(LOG_ERR, "Error resampling: %s (code %i)", err, errcode);
	resample_shutdown(resample);
	return NULL;
}


void resample_shutdown(resample_t *resample) {
	avresample_free(&resample->avresample);
}
