#include "mix.h"
#include <glib.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <inttypes.h>
#include <libavutil/opt.h>
#include <sys/time.h>
#include "types.h"
#include "log.h"
#include "output.h"
#include "resample.h"
#include "main.h"
#include "fix_frame_channel_layout.h"



struct mix_s {
	format_t in_format,
		 out_format;

	// TODO: use mix_buffer
	AVFilterGraph *graph;
	AVFilterContext *src_ctxs[MIX_MAX_INPUTS];
	uint64_t pts_offs[MIX_MAX_INPUTS]; // initialized at first input seen
	uint64_t in_pts[MIX_MAX_INPUTS]; // running counter of next expected adjusted pts
	struct timeval last_use[MIX_MAX_INPUTS]; // to recycle old mix inputs
	void *input_ref[MIX_MAX_INPUTS]; // to avoid collisions in case of idx re-use
	CH_LAYOUT_T channel_layout[MIX_MAX_INPUTS];
	AVFilterContext *amix_ctx;
	AVFilterContext *sink_ctx;
	unsigned int next_idx[MIX_MAX_INPUTS]; //slots can never exceed MIN_MAX_INPUTS by definition
	unsigned int channel_slots;
	AVFrame *sink_frame;

	resample_t resample;

	uint64_t out_pts; // starting at zero

	AVFrame *silence_frame;
};


static void mix_shutdown(mix_t *mix) {
	if (mix->amix_ctx)
		avfilter_free(mix->amix_ctx);
	mix->amix_ctx = NULL;

	if (mix->sink_ctx)
		avfilter_free(mix->sink_ctx);
	mix->sink_ctx = NULL;

	for (unsigned int i = 0; i < mix_num_inputs; i++) {
		if (mix->src_ctxs[i])
			avfilter_free(mix->src_ctxs[i]);
		mix->src_ctxs[i] = NULL;
	}

	resample_shutdown(&mix->resample);
	avfilter_graph_free(&mix->graph);

	format_init(&mix->in_format);
	format_init(&mix->out_format);
}


void mix_destroy(mix_t *mix) {
	if (!mix)
		return;
	mix_shutdown(mix);
	av_frame_free(&mix->sink_frame);
	av_frame_free(&mix->silence_frame);
	g_slice_free1(sizeof(*mix), mix);
}

void mix_set_channel_slots(mix_t *mix, unsigned int channel_slots) {
	if(!mix)
		return;

	if(channel_slots > mix_num_inputs) {
		ilog(LOG_ERR, "channel_slots specified %u is higher than the maximum available %u", channel_slots, mix_num_inputs);
	}
	//ensures that mix->channel_slots will always be within the range of 1 to mix_max_inputs
	mix->channel_slots = channel_slots < 1 ? 1 : (channel_slots > mix_num_inputs ? mix_num_inputs : channel_slots);
	ilog(LOG_DEBUG, "setting slots %i", mix->channel_slots);
}


static void mix_input_reset(mix_t *mix, unsigned int idx) {
	mix->pts_offs[idx] = (uint64_t) -1LL;
	ZERO(mix->last_use[idx]);
	mix->input_ref[idx] = NULL;
	mix->in_pts[idx] = 0;
}


unsigned int mix_get_index(mix_t *mix, void *ptr, unsigned int media_sdp_id, unsigned int stream_channel_slot) {
	unsigned int next;

	if (mix_output_per_media) {
		next = media_sdp_id;
		if (next >= mix_num_inputs) {
			ilog(LOG_WARNING, "Error with mix_output_per_media sdp_label next %i is bigger than mix_num_inputs %i", next, mix_num_inputs );
		}
	} else {
		ilog(LOG_DEBUG, "getting mix input index for slot %u. channel slots for this mix are %u", stream_channel_slot, mix->channel_slots);
		next = mix->next_idx[stream_channel_slot];
		mix->next_idx[stream_channel_slot] += mix->channel_slots;
		ilog(LOG_DEBUG, "mix input index chosen is #%u", next);
	}

	if (next < mix_num_inputs) {
		// must be unused
		mix->input_ref[next] = ptr;
		return next;
	}

	ilog(LOG_DEBUG, "mix input index #%u too high, cycling to find one to re-use", next);

	// too many inputs - find one to re-use
	struct timeval earliest = {0,};
	next = 0;
	for (unsigned int i = 0; i < mix_num_inputs; i++) {
		if ((earliest.tv_sec == 0 || timeval_cmp(&earliest, &mix->last_use[i]) > 0) &&
				i % mix->channel_slots == stream_channel_slot) {
			next = i;
			earliest = mix->last_use[i];
		}
	}

	ilog(LOG_DEBUG, "requested slot is %u, Re-using mix input index #%u", stream_channel_slot, next);
	mix_input_reset(mix, next);
	mix->input_ref[next] = ptr;
	mix->next_idx[stream_channel_slot] = next;
	return next;
}


int mix_config(mix_t *mix, const format_t *format) {
	const char *err;
	char args[512];

	if (format_eq(format, &mix->in_format))
		return 0;

	mix_shutdown(mix);

	mix->in_format = *format;

	// filter graph
	err = "failed to alloc filter graph";
	mix->graph = avfilter_graph_alloc();
	if (!mix->graph)
		goto err;
	mix->graph->nb_threads = 1;
	mix->graph->thread_type = 0;

	// amix
	err = "no amix/amerge filter available";
	const AVFilter *flt = NULL;
	if (mix_method == MM_DIRECT)
		flt = avfilter_get_by_name("amix");
	else if (mix_method == MM_CHANNELS)
		flt = avfilter_get_by_name("amerge");
	if (!flt)
		goto err;

	snprintf(args, sizeof(args), "inputs=%lu", (unsigned long) mix_num_inputs);
	err = "failed to create amix/amerge filter context";
	if (avfilter_graph_create_filter(&mix->amix_ctx, flt, NULL, args, NULL, mix->graph))
		goto err;

	// inputs
	err = "no abuffer filter available";
	flt = avfilter_get_by_name("abuffer");
	if (!flt)
		goto err;

	CH_LAYOUT_T channel_layout, ext_layout;
	DEF_CH_LAYOUT(&channel_layout, mix->in_format.channels);
	DEF_CH_LAYOUT(&ext_layout, mix->in_format.channels * mix_num_inputs);

	for (unsigned int i = 0; i < mix_num_inputs; i++) {
		dbg("init input ctx %i", i);

		CH_LAYOUT_T ch_layout = channel_layout;

		if (mix_method == MM_CHANNELS) {
			uint64_t mask = 0;
			for (int ch = 0; ch < mix->in_format.channels; ch++) {
				mask |= CH_LAYOUT_EXTRACT_MASK(ext_layout,
						i * mix->in_format.channels + ch);
			}
			CH_LAYOUT_FROM_MASK(&ch_layout, mask);
		}

		char chlayoutbuf[64];
		CH_LAYOUT_PRINT(ch_layout, chlayoutbuf);
		snprintf(args, sizeof(args), "time_base=%d/%d:sample_rate=%d:sample_fmt=%s:"
				"channel_layout=%s",
				1, mix->in_format.clockrate, mix->in_format.clockrate,
				av_get_sample_fmt_name(mix->in_format.format),
				chlayoutbuf);
		mix->channel_layout[i] = ch_layout;

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

	mix->out_format = mix->in_format;
	if (mix_method == MM_CHANNELS)
		mix->out_format.channels *= mix_num_inputs;

	return 0;

err:
	mix_shutdown(mix);
	ilog(LOG_ERR, "Failed to initialize mixer: %s", err);
	return -1;
}


mix_t *mix_new(void) {
	mix_t *mix = g_slice_alloc0(sizeof(*mix));
	format_init(&mix->in_format);
	format_init(&mix->out_format);
	mix->sink_frame = av_frame_alloc();

	for (unsigned int i = 0; i < mix_num_inputs; i++)
		mix->pts_offs[i] = (uint64_t) -1LL;

	for (unsigned int i = 0; i < mix_num_inputs; i++) {
		// initialise with the first mixer channel to use for each slot. This is set to mix_num_inputs+1
		// so that we can detect first use and also if the maximum use has been reached.
		//mix->next_idx[i] = mix_num_inputs+1;
		mix->next_idx[i] = i;
	}

	return mix;
}


static void mix_silence_fill_idx_upto(mix_t *mix, unsigned int idx, uint64_t upto) {
	unsigned int silence_samples = mix->in_format.clockrate / 100;

	while (mix->in_pts[idx] < upto) {
		if (G_UNLIKELY(upto - mix->in_pts[idx] > mix->in_format.clockrate * 30)) {
			ilog(LOG_WARN, "More than 30 seconds of silence needed to fill mix buffer, resetting");
			mix->in_pts[idx] = upto;
			break;
		}

		if (G_UNLIKELY(!mix->silence_frame)) {
			mix->silence_frame = av_frame_alloc();
			mix->silence_frame->format = mix->in_format.format;
			DEF_CH_LAYOUT(&mix->silence_frame->CH_LAYOUT,
				mix->in_format.channels);
			mix->silence_frame->nb_samples = silence_samples;
			mix->silence_frame->sample_rate = mix->in_format.clockrate;
			if (av_frame_get_buffer(mix->silence_frame, 0) < 0) {
				ilog(LOG_ERR, "Failed to get silence frame buffers");
				return;
			}
			int planes = av_sample_fmt_is_planar(mix->silence_frame->format) ? mix->in_format.channels : 1;
			for (int i = 0; i < planes; i++)
				memset(mix->silence_frame->extended_data[i], 0, mix->silence_frame->linesize[0]);
		}

		dbg("pushing silence frame into stream %i (%lli < %llu)", idx,
				(long long unsigned) mix->in_pts[idx],
				(long long unsigned) upto);

		mix->silence_frame->pts = mix->in_pts[idx];
		mix->silence_frame->nb_samples = MIN(silence_samples, upto - mix->in_pts[idx]);
		mix->in_pts[idx] += mix->silence_frame->nb_samples;

		mix->silence_frame->CH_LAYOUT = mix->channel_layout[idx];
		if (av_buffersrc_write_frame(mix->src_ctxs[idx], mix->silence_frame))
			ilog(LOG_WARN, "Failed to write silence frame to buffer");
	}
}


static void mix_silence_fill(mix_t *mix) {
	if (mix->out_pts < mix->in_format.clockrate)
		return;

	for (unsigned int i = 0; i < mix_num_inputs; i++) {
		// check the pts of each input and give them max 0.5 second of delay.
		// if they fall behind too much, fill input with silence. otherwise
		// output stalls and won't produce media
		mix_silence_fill_idx_upto(mix, i, mix->out_pts - mix->in_format.clockrate / 2);
	}
}


int mix_add(mix_t *mix, AVFrame *frame, unsigned int idx, void *ptr, output_t *output) {
	const char *err;

	err = "index out of range";
	if (idx >= mix_num_inputs)
		goto err;

	err = "mixer not initialized";
	if (!mix->src_ctxs[idx])
		goto err;

	err = "received samples for old re-used input channel";
	if (ptr != mix->input_ref[idx])
		goto err;

	gettimeofday(&mix->last_use[idx], NULL);

	dbg("stream %i pts_off %llu in pts %llu in frame pts %llu samples %u mix out pts %llu", 
			idx,
			(unsigned long long) mix->pts_offs[idx],
			(unsigned long long) mix->in_pts[idx],
			(unsigned long long) frame->pts,
			frame->nb_samples,
			(unsigned long long) mix->out_pts);

	// adjust for media started late
	if (G_UNLIKELY(mix->pts_offs[idx] == (uint64_t) -1LL))
		mix->pts_offs[idx] = mix->out_pts - frame->pts;
	frame->pts += mix->pts_offs[idx];

	// fill missing time
	mix_silence_fill_idx_upto(mix, idx, frame->pts);

	// check for pts gap. this is the opposite of silence fill-in. if the frame
	// pts is behind the expected input pts, there was a gap and we reset our
	// pts adjustment
	if (G_UNLIKELY(frame->pts < mix->in_pts[idx]))
		mix->pts_offs[idx] += mix->in_pts[idx] - frame->pts;

	uint64_t next_pts = frame->pts + frame->nb_samples;

	frame->CH_LAYOUT = mix->channel_layout[idx];
	err = "failed to add frame to mixer";
	if (av_buffersrc_add_frame(mix->src_ctxs[idx], frame))
		goto err;

	// update running counters
	if (next_pts > mix->out_pts)
		mix->out_pts = next_pts;
	if (next_pts > mix->in_pts[idx])
		mix->in_pts[idx] = next_pts;

	av_frame_free(&frame);

	mix_silence_fill(mix);

	while (1) {
		int ret = av_buffersink_get_frame(mix->sink_ctx, mix->sink_frame);
		err = "failed to get frame from mixer";
		if (ret < 0) {
			if (ret == AVERROR(EAGAIN))
				break;
			else
				goto err;
		}
		frame = resample_frame(&mix->resample, mix->sink_frame, &mix->out_format);

		ret = output_add(output, frame);

		av_frame_unref(mix->sink_frame);
		if (frame != mix->sink_frame)
			av_frame_free(&frame);

		if (ret)
			return -1;
	}

	return 0;

err:
	ilog(LOG_ERR, "Failed to add frame to mixer: %s", err);
	av_frame_free(&frame);
	return -1;
}
