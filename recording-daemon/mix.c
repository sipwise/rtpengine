#include "mix.h"
#include <glib.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/channel_layout.h>
#include <inttypes.h>
#include <libavresample/avresample.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "output.h"


struct mix_s {
	// format params
	int clockrate;
	int channels;

	AVFilterGraph *graph;
	AVFilterContext *src_ctxs[2];
	AVFilterContext *amix_ctx;
	AVFilterContext *sink_ctx;
	unsigned int next_idx;
	AVFrame *sink_frame;

	AVAudioResampleContext *avresample;
	AVFrame *swr_frame;
	int swr_buffers;
};


static void mix_shutdown(mix_t *mix) {
	if (mix->amix_ctx)
		avfilter_free(mix->amix_ctx);
	mix->amix_ctx = NULL;

	if (mix->sink_ctx)
		avfilter_free(mix->sink_ctx);
	mix->sink_ctx = NULL;

	for (int i = 0; i < G_N_ELEMENTS(mix->src_ctxs); i++) {
		if (mix->src_ctxs[i])
			avfilter_free(mix->src_ctxs[i]);
		mix->src_ctxs[i] = NULL;
	}

	avresample_free(&mix->avresample);
	avfilter_graph_free(&mix->graph);
}


void mix_destroy(mix_t *mix) {
	mix_shutdown(mix);
	av_frame_free(&mix->sink_frame);
	av_frame_free(&mix->swr_frame);
	g_slice_free1(sizeof(*mix), mix);
}


unsigned int mix_get_index(mix_t *mix) {
	return mix->next_idx++;
}


int mix_config(mix_t *mix, unsigned int clockrate, unsigned int channels) {
	const char *err;
	char args[512];

	// anything to do?
	if (G_UNLIKELY(mix->clockrate != clockrate))
		goto format_mismatch;
	if (G_UNLIKELY(mix->channels != channels))
		goto format_mismatch;

	// all good
	return 0;

format_mismatch:
	mix_shutdown(mix);

	// copy params
	mix->clockrate = clockrate;
	mix->channels = channels;

	// filter graph
	err = "failed to alloc filter graph";
	mix->graph = avfilter_graph_alloc();
	if (!mix->graph)
		goto err;

	// amix
	err = "no amix filter available";
	AVFilter *flt = avfilter_get_by_name("amix");
	if (!flt)
		goto err;

	snprintf(args, sizeof(args), "inputs=%lu", (unsigned long) G_N_ELEMENTS(mix->src_ctxs));
	err = "failed to create amix filter context";
	if (avfilter_graph_create_filter(&mix->amix_ctx, flt, NULL, args, NULL, mix->graph))
		goto err;

	// inputs
	err = "no abuffer filter available";
	flt = avfilter_get_by_name("abuffer");
	if (!flt)
		goto err;

	for (int i = 0; i < G_N_ELEMENTS(mix->src_ctxs); i++) {
		dbg("init input ctx %i", i);

		snprintf(args, sizeof(args), "time_base=%d/%d:sample_rate=%d:sample_fmt=%s:"
				"channel_layout=0x%" PRIx64,
				1, mix->clockrate, mix->clockrate,
				av_get_sample_fmt_name(AV_SAMPLE_FMT_S16),
				av_get_default_channel_layout(mix->channels));

		err = "failed to create abuffer filter context";
		if (avfilter_graph_create_filter(&mix->src_ctxs[i], flt, NULL, args, NULL, mix->graph))
			goto err;

		err = "failed to link abuffer to amix";
		if (avfilter_link(mix->src_ctxs[i], 0, mix->amix_ctx, i))
			goto err;
	}

	// sink
	err = "no abuffersink filter available";
	flt = avfilter_get_by_name("abuffersink");
	if (!flt)
		goto err;

	err = "failed to create abuffersink filter context";
	if (avfilter_graph_create_filter(&mix->sink_ctx, flt, NULL, NULL, NULL, mix->graph))
		goto err;

	err = "failed to link amix to abuffersink";
	if (avfilter_link(mix->amix_ctx, 0, mix->sink_ctx, 0))
		goto err;

	// finish up
	err = "failed to configure filter chain";
	if (avfilter_graph_config(mix->graph, NULL))
		goto err;

	return 0;

err:
	mix_shutdown(mix);
	ilog(LOG_ERR, "Failed to initialize mixer: %s", err);
	return -1;
}


mix_t *mix_new() {
	mix_t *mix = g_slice_alloc0(sizeof(*mix));
	mix->clockrate = -1;
	mix->channels = -1;
	mix->sink_frame = av_frame_alloc();

	return mix;
}


static AVFrame *mix_resample_frame(mix_t *mix, AVFrame *frame) {
	const char *err;

	if (frame->format == AV_SAMPLE_FMT_S16)
		return frame;

	if (!mix->avresample) {
		mix->avresample = avresample_alloc_context();
		err = "failed to alloc resample context";
		if (!mix->avresample)
			goto err;

		av_opt_set_int(mix->avresample, "in_channel_layout",
				av_get_default_channel_layout(mix->channels), 0);
		av_opt_set_int(mix->avresample, "in_sample_fmt",
				frame->format, 0);
		av_opt_set_int(mix->avresample, "in_sample_rate",
				mix->clockrate, 0);
		av_opt_set_int(mix->avresample, "out_channel_layout",
				av_get_default_channel_layout(mix->channels), 0);
		av_opt_set_int(mix->avresample, "out_sample_fmt",
				AV_SAMPLE_FMT_S16, 0);
		av_opt_set_int(mix->avresample, "out_sample_rate",
				mix->clockrate, 0);
		// av_opt_set_int(dec->avresample, "internal_sample_fmt", AV_SAMPLE_FMT_FLTP, 0); // ?

		err = "failed to init resample context";
		if (avresample_open(mix->avresample) < 0)
			goto err;
	}

	// get a large enough buffer for resampled audio - this should be enough so we don't
	// have to loop
	int dst_samples = avresample_available(mix->avresample) +
		av_rescale_rnd(avresample_get_delay(mix->avresample) + frame->nb_samples,
				mix->clockrate, mix->clockrate, AV_ROUND_UP);
	if (!mix->swr_frame || mix->swr_buffers < dst_samples) {
		av_frame_free(&mix->swr_frame);
		mix->swr_frame = av_frame_alloc();
		err = "failed to alloc resampling frame";
		if (!mix->swr_frame)
			goto err;
		av_frame_copy_props(mix->swr_frame, frame);
		mix->swr_frame->format = frame->format;
		mix->swr_frame->channel_layout = frame->channel_layout;
		mix->swr_frame->nb_samples = dst_samples;
		mix->swr_frame->sample_rate = mix->clockrate;
		err = "failed to get resample buffers";
		if (av_frame_get_buffer(mix->swr_frame, 0) < 0)
			goto err;
		mix->swr_buffers = dst_samples;
	}

	mix->swr_frame->nb_samples = dst_samples;
	int ret_samples = avresample_convert(mix->avresample, mix->swr_frame->extended_data,
				mix->swr_frame->linesize[0], dst_samples,
				frame->extended_data,
				frame->linesize[0], frame->nb_samples);
	err = "failed to resample audio";
	if (ret_samples < 0)
		goto err;

	mix->swr_frame->nb_samples = ret_samples;
	mix->swr_frame->pts = av_rescale(frame->pts, mix->clockrate, mix->clockrate);
	return mix->swr_frame;

err:
	ilog(LOG_ERR, "Error resampling: %s", err);
	return NULL;
}


// frees the frame passed to it
int mix_add(mix_t *mix, AVFrame *frame, unsigned int idx, output_t *output) {
	const char *err;

	err = "index out of range";
	if (idx >= G_N_ELEMENTS(mix->src_ctxs))
		goto err;

	err = "mixer not initialized";
	if (!mix->src_ctxs[idx])
		goto err;

	err = "failed to add frame to mixer";
	if (av_buffersrc_add_frame(mix->src_ctxs[idx], frame))
		goto err;

	av_frame_free(&frame);

	while (1) {
		int ret = av_buffersink_get_frame(mix->sink_ctx, mix->sink_frame);
		err = "failed to get frame from mixer";
		if (ret < 0) {
			if (ret == AVERROR(EAGAIN))
				break;
			else
				goto err;
		}
		frame = mix_resample_frame(mix, mix->sink_frame);

		ret = output_add(output, mix->sink_frame);

		av_frame_unref(mix->sink_frame);

		if (ret)
			return -1;
	}

	return 0;

err:
	ilog(LOG_ERR, "Failed to add frame to mixer: %s", err);
	av_frame_free(&frame);
	return -1;
}
