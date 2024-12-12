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

	CH_LAYOUT_T to_channel_layout;
	DEF_CH_LAYOUT(&to_channel_layout, to_format->channels);
	fix_frame_channel_layout(frame);

	if (frame->format != to_format->format)
		goto resample;
	if (frame->sample_rate != to_format->clockrate)
		goto resample;
	if (!CH_LAYOUT_EQ(frame->CH_LAYOUT, to_channel_layout))
		goto resample;

	return frame;

resample:

	if (G_UNLIKELY(!resample->swresample)) {
		SWR_ALLOC_SET_OPTS(&resample->swresample,
				to_channel_layout,
				to_format->format,
				to_format->clockrate,
				frame->CH_LAYOUT,
				frame->format,
				frame->sample_rate,
				0, NULL);

		err = "failed to alloc resample context";
		if (!resample->swresample)
			goto err;

		if (resample->no_filter)
			av_opt_set_int(resample->swresample, "filter_size", 0, AV_OPT_SEARCH_CHILDREN);

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
	swr_frame->CH_LAYOUT = to_channel_layout;
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
	swr_frame->linesize[0] = av_get_bytes_per_sample(swr_frame->format) * ret_samples;
	return swr_frame;

err:
	if (errcode)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error resampling: %s (%s)", err, av_error(errcode));
	else
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error resampling: %s", err);
	resample_shutdown(resample);
	return NULL;
}


void resample_shutdown(resample_t *resample) {
	swr_free(&resample->swresample);
}
