#include <libavutil/frame.h>
#include <libavutil/opt.h>
#include <assert.h>
#include "resample.h"
#include "codeclib.h"

void test_1(int in_samples, int in_format, int in_rate, int in_channels,
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
	in_f->channel_layout = av_get_default_channel_layout(in_channels);
	int ret = av_frame_get_buffer(in_f, 0);
	assert(ret == 0);
	memset(in_f->extended_data[0], 0, in_f->nb_samples * av_get_bytes_per_sample(in_f->format));

	resample_t resampler;
	ZERO(resampler);
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
	codeclib_init(0);

	test_1(320, AV_SAMPLE_FMT_S16, 16000, 1, AV_SAMPLE_FMT_S16, 8000, 1, 144);
	test_1(160, AV_SAMPLE_FMT_S16, 8000, 1, AV_SAMPLE_FMT_S16, 16000, 1, 288);

	return 0;
}

int get_local_log_level(unsigned int u) {
	return 7;
}
