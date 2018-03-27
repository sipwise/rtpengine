#include "resample.h"
#include <glib.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <inttypes.h>
#include <libswresample/swresample.h>
#include <libavutil/opt.h>
#include <libavutil/frame.h>
#include "log.h"
#include "codeclib.h"
#include "fix_frame_channel_layout.h"




AVFrame *resample_frame(resample_t *resample, AVFrame *frame, const format_t *to_format) {
	const char *err;
	int errcode = 0;

	uint64_t to_channel_layout = av_get_default_channel_layout(to_format->channels);
	fix_frame_channel_layout(frame);

	if (frame->format != to_format->format)
		goto resample;
	if (frame->sample_rate != to_format->clockrate)
		goto resample;
	if (frame->channel_layout != to_channel_layout)
		goto resample;

	return av_frame_clone(frame);

resample:

	if (G_UNLIKELY(!resample->swresample)) {
		resample->swresample = swr_alloc_set_opts(NULL,
				to_channel_layout,
				to_format->format,
				to_format->clockrate,
				frame->channel_layout,
				frame->format,
				frame->sample_rate,
				0, NULL);
		err = "failed to alloc resample context";
		if (!resample->swresample)
			goto err;

		err = "failed to init resample context";
		if ((errcode = swr_init(resample->swresample)) < 0)
			goto err;
	}

	// get a large enough buffer for resampled audio - this should be enough so we don't
	// have to loop
	int dst_samples = av_rescale_rnd(swr_get_delay(resample->swresample, to_format->clockrate)
			+ frame->nb_samples,
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

	int ret_samples = swr_convert(resample->swresample, swr_frame->extended_data,
				dst_samples,
				(const uint8_t **) frame->extended_data,
				frame->nb_samples);
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
	swr_free(&resample->swresample);
}
