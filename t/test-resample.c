#include <libavutil/frame.h>
#include <libavutil/opt.h>
#include <assert.h>
#include "resample.h"
#include "codeclib.h"
#include "fix_frame_channel_layout.h"
#include "main.h"

struct rtpengine_config rtpe_config;
struct rtpengine_config initial_rtpe_config;

void test_1(int in_samples, int in_format, int in_rate, int in_channels, bool no_filter,
		int out_format, int out_rate, int out_channels,
		int out_exp_samples)
{
	printf("testing %i %i %i %i %i %i %i %i\n", in_samples, in_format, in_rate, in_channels,
			out_format, out_rate, out_channels,
			out_exp_samples);

	AVFrame *in_f = av_frame_alloc();
	in_f->nb_samples = in_samples;
	in_f->format = in_format;
	in_f->sample_rate = in_rate;
	DEF_CH_LAYOUT(&in_f->CH_LAYOUT, in_channels);
	int ret = av_frame_get_buffer(in_f, 0);
	assert(ret == 0);
	memset(in_f->extended_data[0], 0, in_f->nb_samples * av_get_bytes_per_sample(in_f->format));

	resample_t resampler;
	ZERO(resampler);
	resampler.no_filter = no_filter;

	format_t out_fmt = {
		.channels = out_channels,
		.clockrate = out_rate,
		.format = out_format,
	};
	AVFrame *out_f = resample_frame(&resampler, in_f, &out_fmt);
	assert(out_f != NULL);

	printf("received samples %i\n", out_f->nb_samples);
	assert(out_f->nb_samples == out_exp_samples);

	av_frame_free(&in_f);
	av_frame_free(&out_f);
	resample_shutdown(&resampler);
}

int main(void) {
	rtpe_common_config_ptr = &rtpe_config.common;
	codeclib_init(0);

	test_1(320, AV_SAMPLE_FMT_S16, 16000, 1, false, AV_SAMPLE_FMT_S16, 8000, 1, 144);
	test_1(160, AV_SAMPLE_FMT_S16, 8000, 1, false, AV_SAMPLE_FMT_S16, 16000, 1, 288);

	test_1(320, AV_SAMPLE_FMT_S16, 16000, 1, true, AV_SAMPLE_FMT_S16, 8000, 1, 160);
	test_1(160, AV_SAMPLE_FMT_S16, 8000, 1, true, AV_SAMPLE_FMT_S16, 16000, 1, 320);

	return 0;
}

int get_local_log_level(unsigned int u) {
	return 7;
}
