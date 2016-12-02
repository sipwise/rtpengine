#include "mix.h"
#include <glib.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/opt.h>
#include <libavutil/channel_layout.h>
#include "types.h"
#include "log.h"
#include "output.h"


struct mix_s {
	// format params
	int clockrate;
	int channels;

	AVFilterGraph *graph;
	AVFilterContext *src_ctxs[16];
	AVFilterContext *amix_ctx;
	AVFilterContext *sink_ctx;
	unsigned int next_idx;
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

	avfilter_graph_free(&mix->graph);
}


void mix_destroy(mix_t *mix) {
	mix_shutdown(mix);
	g_slice_free1(sizeof(*mix), mix);
}


unsigned int mix_get_index(mix_t *mix) {
	return mix->next_idx++;
}


int mix_config(mix_t *mix, unsigned int clockrate, unsigned int channels) {
	const char *err;

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

	err = "failed to alloc amix filter context";
	mix->amix_ctx = avfilter_graph_alloc_filter(mix->graph, flt, NULL);
	if (!mix->amix_ctx)
		goto err;

	av_opt_set_int(mix->amix_ctx, "inputs", G_N_ELEMENTS(mix->src_ctxs), 0);

	err = "failed to init amix filter context";
	if (avfilter_init_str(mix->amix_ctx, NULL))
		goto err;

	// inputs
	err = "no abuffer filter available";
	flt = avfilter_get_by_name("buffer");
	if (!flt)
		goto err;

	for (int i = 0; i < G_N_ELEMENTS(mix->src_ctxs); i++) {
		err = "failed to alloc abuffer filter context";
		mix->src_ctxs[i] = avfilter_graph_alloc_filter(mix->graph, flt, NULL);
		if (!mix->src_ctxs[i])
			goto err;

		int ret;
		ret = av_opt_set_int(mix->src_ctxs[i], "channel_layout",
				av_get_default_channel_layout(mix->channels), AV_OPT_SEARCH_CHILDREN);
		dbg("ret1 %i", ret);
		ret = av_opt_set_int(mix->src_ctxs[i], "sample_fmt",
				AV_SAMPLE_FMT_S16, AV_OPT_SEARCH_CHILDREN);
		dbg("ret2 %i", ret);
		ret = av_opt_set_int(mix->src_ctxs[i], "sample_rate",
				mix->clockrate, AV_OPT_SEARCH_CHILDREN);
		dbg("ret3 %i", ret);
		ret = av_opt_set_q(mix->src_ctxs[i], "time_base",
				(AVRational){1,mix->clockrate}, AV_OPT_SEARCH_CHILDREN);
		dbg("ret4 %i", ret);

		err = "failed to init abuffer filter context";
		if (avfilter_init_str(mix->src_ctxs[i], NULL))
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

	err = "failed to alloc abuffersink filter context";
	mix->sink_ctx = avfilter_graph_alloc_filter(mix->graph, flt, NULL);
	if (!mix->sink_ctx)
		goto err;

	err = "failed to init abuffersink filter context";
	if (avfilter_init_str(mix->sink_ctx, NULL))
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

	return mix;
}


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

	while (1) {
		int ret = av_buffersink_get_frame(mix->sink_ctx, frame);
		err = "failed to get frame from mixer";
		if (ret < 0) {
			if (ret == AVERROR(EAGAIN))
				break;
			else
				goto err;
		}
		if (output_add(output, frame))
			return -1;
	}

	return 0;

err:
	ilog(LOG_ERR, "Failed to add frame to mixer: %s", err);
	return -1;
}
