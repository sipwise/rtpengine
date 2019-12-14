#include "mix.h"
#include <glib.h>
#include <time.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <inttypes.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "output.h"
#include "resample.h"
#include "timer.h"


#define MAX_NUM_INPUTS 4

extern const char *mix_filter;

struct mix_s {
	format_t input_format;
	format_t out_format;

	AVFilterGraph *graph;
	AVFilterContext *src_ctxs[MAX_NUM_INPUTS];
	uint64_t pts_offs[MAX_NUM_INPUTS]; // initialized at first input seen
	uint64_t in_pts[MAX_NUM_INPUTS]; // running counter of next expected adjusted pts
	AVFilterContext *filter_ctx;
	AVFilterContext *sink_ctx;
	unsigned int next_idx;
	AVFrame *sink_frame;

	resample_t resample;

	uint64_t out_pts; // starting at zero

	uint64_t silence_pts;

	AVFrame *silence_frame;

	int timer_fd;
    handler_t timer_handler;
	time_t start_time;
};

static int NUM_INPUTS  = MAX_NUM_INPUTS;

static int mix_timer_init(mix_t *mix);
static int mix_timer_destroy(mix_t *mix);

static void mix_shutdown(mix_t *mix) {
	if (mix->filter_ctx)
		avfilter_free(mix->filter_ctx);
	mix->filter_ctx = NULL;

	if (mix->sink_ctx)
		avfilter_free(mix->sink_ctx);
	mix->sink_ctx = NULL;

	for (int i = 0; i < MAX_NUM_INPUTS; i++) {
		if (mix->src_ctxs[i])
			avfilter_free(mix->src_ctxs[i]);
		mix->src_ctxs[i] = NULL;
	}

	resample_shutdown(&mix->resample);
	avfilter_graph_free(&mix->graph);

	format_init(&mix->input_format);
	format_init(&mix->out_format);
}

uint64_t mix_get_silence_pts(mix_t *mix){
	return mix->silence_pts;
}

void mix_destroy(mix_t *mix) {
	if (!mix)
		return;
	mix_timer_destroy(mix);
	mix_shutdown(mix);
	av_frame_free(&mix->sink_frame);
	av_frame_free(&mix->silence_frame);
	g_slice_free1(sizeof(*mix), mix);
}

int mix_get_out_channels(int input_channels){
	if (strcmp(mix_filter, "amerge") == 0) 
		return NUM_INPUTS * input_channels;		
	return input_channels;		
}

unsigned int mix_get_index(mix_t *mix) {
	return mix->next_idx++;
}


int mix_config(mix_t *mix, const format_t *input_format, const format_t *out_format) {
	const char *err;
	char args[512];

	if (format_eq(input_format, &mix->input_format))
		return 0;

	mix_shutdown(mix);

	mix->input_format = *input_format;
	mix->out_format = *out_format;

	// filter graph
	err = "failed to alloc filter graph";
	mix->graph = avfilter_graph_alloc();
	if (!mix->graph)
		goto err;

	// filter 
	err = "no filter available";
	const AVFilter *flt = avfilter_get_by_name(mix_filter);
	if (!flt)
		goto err;

	snprintf(args, sizeof(args), "inputs=%lu", (unsigned long) NUM_INPUTS);
	err = "failed to create filter context";
	if (avfilter_graph_create_filter(&mix->filter_ctx, flt, NULL, args, NULL, mix->graph))
		goto err;

	// inputs
	err = "no abuffer filter available";
	flt = avfilter_get_by_name("abuffer");
	if (!flt)
		goto err;

	for (int i = 0; i < NUM_INPUTS; i++) {
		dbg("init input ctx %i", i);

		snprintf(args, sizeof(args), "time_base=%d/%d:sample_rate=%d:sample_fmt=%s:"
				"channel_layout=0x%" PRIx64,
				1, mix->input_format.clockrate, mix->input_format.clockrate,
				av_get_sample_fmt_name(mix->input_format.format),
				av_get_default_channel_layout(mix->input_format.channels));

		err = "failed to create abuffer filter context";
		if (avfilter_graph_create_filter(&mix->src_ctxs[i], flt, NULL, args, NULL, mix->graph))
			goto err;

		err = "failed to link abuffer to filter";
		if (avfilter_link(mix->src_ctxs[i], 0, mix->filter_ctx, i))
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

	err = "failed to link filter to abuffersink";
	if (avfilter_link(mix->filter_ctx, 0, mix->sink_ctx, 0))
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
	if (strcmp(mix_filter, "amerge") == 0)
		NUM_INPUTS = 2;				// we just merge two mono streams to one stereo stream.
	mix_t *mix = g_slice_alloc0(sizeof(*mix));
	format_init(&mix->input_format);
	format_init(&mix->out_format);
	mix->sink_frame = av_frame_alloc();

	for (int i = 0; i < MAX_NUM_INPUTS; i++) {
		mix->pts_offs[i] = (uint64_t) -1LL;
		mix->src_ctxs[i] = NULL;
	}

	mix->timer_fd = -1;
	mix_timer_init(mix);
	
	mix->silence_pts = 0;
	mix->start_time = time(NULL);
	return mix;
}

static int mix_get_frame_and_output(mix_t *mix, output_t *output) {
	int ret = av_buffersink_get_frame(mix->sink_ctx, mix->sink_frame);
	if (ret >= 0) {
		AVFrame *frame = resample_frame(&mix->resample, mix->sink_frame, &mix->out_format);

		ret = output_add(output, frame);

		av_frame_unref(mix->sink_frame);

		av_frame_free(&frame);
	}
	return ret;
}

#define MIX_TIMER_INTERVAL 1

static void log_repeated_error(int err_count, const char* err, int ret){
	char errmsg[256];
	errmsg[0] = 0;
	av_strerror(ret, errmsg, sizeof(errmsg));
	if (err != NULL && err_count > 0) {
		if (err_count == 1)
			ilog(LOG_ERR, "Failure in max_add: %s(ret=%d, err=%s)", err, ret, errmsg);
		else 
			ilog(LOG_ERR, "Failure in max_add: %s (ret=%d, err=%s, happened %d times in last %d seconds)", 
						err, ret, errmsg, err_count, MIX_TIMER_INTERVAL);
	}
}

// if (err == NULL), just flush the errors
// if this is a new error, flush the old errors and then output the new error
// if this is a repeated error, just increase the count
// this method assumes that err is a literal string so it does not allocate any space for err
static void throttle_error_output(const char* err, int ret){
	static const char *last_err = NULL;
	static int last_ret = 0;
	static int err_count = 0;

	if (err != NULL) {
		if (last_err != NULL && strcmp(last_err, err) == 0 && last_ret == ret) { // repeated error
			err_count++;
			return;
		}	
		log_repeated_error(err_count, last_err, last_ret);
		log_repeated_error(1, err, ret);		// output new error immediately
		last_err = err;
		last_ret = ret;
	}
	else {	// if err is NULL, just flush old errors
		if (err_count > 0)
			log_repeated_error(err_count, last_err, last_ret);
	}
	err_count = 0;
}


static void mix_silence_fill_idx_upto(mix_t *mix, unsigned int idx, uint64_t upto, output_t *output) {
	unsigned int silence_samples = 20 * mix->input_format.clockrate / 1000;

	while (mix->in_pts[idx] < upto) {
/*		if (G_UNLIKELY(upto - mix->in_pts[idx] > mix->input_format.clockrate * 30)) {
			ilog(LOG_WARN, "More than 30 seconds of silence needed to fill mix buffer, resetting");
			mix->in_pts[idx] = upto;
			break;
		}
*/
		if (G_UNLIKELY(!mix->silence_frame)) {
			mix->silence_frame = av_frame_alloc();
			mix->silence_frame->format = mix->input_format.format;
			mix->silence_frame->channel_layout =
				av_get_default_channel_layout(mix->input_format.channels);
			mix->silence_frame->nb_samples = silence_samples;
			mix->silence_frame->sample_rate = mix->input_format.clockrate;
			if (av_frame_get_buffer(mix->silence_frame, 0) < 0) {
				ilog(LOG_ERR, "Failed to get silence frame buffers");
				return;
			}
			int planes = av_sample_fmt_is_planar(mix->silence_frame->format) ? mix->input_format.channels : 1;
			for (int i = 0; i < planes; i++)
				memset(mix->silence_frame->extended_data[i], 0, mix->silence_frame->linesize[0]);
		}

		dbg("pushing silence frame into stream %i (%lli < %llu)", idx,
				(long long unsigned) mix->in_pts[idx],
				(long long unsigned) upto);

		mix->silence_frame->pts = mix->in_pts[idx];
		mix->silence_frame->nb_samples = MIN(silence_samples, upto - mix->in_pts[idx]);
		mix->silence_frame->pkt_size = mix->silence_frame->nb_samples;
		mix->in_pts[idx] += mix->silence_frame->nb_samples;

		mix->silence_pts += mix->silence_frame->nb_samples;
		int ret = av_buffersrc_write_frame(mix->src_ctxs[idx], mix->silence_frame);
		if (ret) {
			ilog(LOG_ERR, "Failed to write silence frame to buffer(ret=%d)", ret);
		}
		ret = mix_get_frame_and_output(mix, output);
		if (ret < 0 && ret != AVERROR(EAGAIN)) {
			throttle_error_output("failed to get frame from mixer", ret);
		}
	}
}


static void mix_silence_fill(mix_t *mix, output_t *output) {
	if (mix->out_pts < mix->input_format.clockrate)
		return;

	for (int i = 0; i < NUM_INPUTS; i++) {
		// check the pts of each input and give them max 1 second of delay.
		// if they fall behind too much, fill input with silence. otherwise
		// output stalls and won't produce media
		mix_silence_fill_idx_upto(mix, i, mix->out_pts - mix->input_format.clockrate, output);
	}
}

int mix_add(mix_t *mix, AVFrame *frame, unsigned int idx, output_t *output) {
	const char *err;
	int ret = 0;

	err = "index out of range";
	if (idx >= NUM_INPUTS)
		goto err;

	err = "mixer not initialized";
	if (!mix->src_ctxs[idx])
		goto err;

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
	mix_silence_fill_idx_upto(mix, idx, frame->pts, output);

	uint64_t next_pts = frame->pts + frame->nb_samples;

	err = "failed to add frame to mixer";
	ret = av_buffersrc_add_frame(mix->src_ctxs[idx], frame);
	if (ret)
		goto err;

	// update running counters
	if (next_pts > mix->out_pts)
		mix->out_pts = next_pts;
	if (next_pts > mix->in_pts[idx])
		mix->in_pts[idx] = next_pts;

	av_frame_free(&frame);

	mix_silence_fill(mix, output);

	err = "failed to get frame from mixer";
	while (1) {
		ret = mix_get_frame_and_output(mix, output);
		if (ret < 0) {
			if (ret == AVERROR(EAGAIN))
				break;
			else
				goto err;
		}
	}
	return 0;

err:
	throttle_error_output(err, ret);
	av_frame_free(&frame);
	return -1;
}

static void mix_timer_handler(handler_t *handler) {
    uint64_t exp = 0;
    mix_t *mix = handler->ptr;
    if (mix == NULL)
        return;
    read(mix->timer_fd, &exp, sizeof(uint64_t));
	throttle_error_output(NULL, 0);	
}

int mix_timer_init(mix_t *mix) {
    if (mix->timer_fd != -1){
        ilog(LOG_WARN, "setup error check timer error");
        return 0;
    }

    mix->timer_handler.ptr = mix;
    mix->timer_handler.func = mix_timer_handler;
    mix->timer_fd = timerfd_init(&mix->timer_handler, MIX_TIMER_INTERVAL*1000);
    return mix->timer_fd > 0 ? 0 : -1;
}

int mix_timer_destroy(mix_t *mix)
{
	throttle_error_output(NULL, 0);
    if (mix->timer_fd != -1) {
    	timerfd_destroy(mix->timer_fd);
    	mix->timer_fd = -1;
	}
    return 0;
}