#include "output.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include "log.h"


struct output_s {
	char *filename;

	// format params
	int clockrate;
	int channels;

	AVCodecContext *avcctx;
	AVFormatContext *fmtctx;
	AVStream *avst;
	AVPacket avpkt;
	AVAudioFifo *fifo;
	int64_t fifo_pts; // pts of first data in fifo
	int64_t mux_dts; // last dts passed to muxer
	AVFrame *frame;
};



static int output_codec_id;
static const char *output_file_format;



static void output_shutdown(output_t *output);



static int output_flush(output_t *output) {
	while (av_audio_fifo_size(output->fifo) >= output->frame->nb_samples) {

		if (av_audio_fifo_read(output->fifo, (void **) output->frame->data,
					output->frame->nb_samples) <= 0)
			abort();

		dbg("%p output fifo pts %lu", output, (unsigned long) output->fifo_pts);
		output->frame->pts = output->fifo_pts;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
		int ret = avcodec_send_frame(output->avcctx, output->frame);
		dbg("%p send frame ret %i", output, ret);
		if (ret)
			return -1;

		ret = avcodec_receive_packet(output->avcctx, &output->avpkt);
		dbg("%p receive packet ret %i", output, ret);
		if (ret)
			return -1;
#else
		int got_packet = 0;
		int ret = avcodec_encode_audio2(output->avcctx, &output->avpkt, output->frame, &got_packet);
		dbg("%p encode frame ret %i, got packet %i", output, ret, got_packet);
		if (!got_packet)
			return 0;
#endif

		dbg("%p output avpkt size is %i", output, (int) output->avpkt.size);
		dbg("%p output pkt pts/dts is %li/%li", output, (long) output->avpkt.pts,
				(long) output->avpkt.dts);
		dbg("%p output dts %li", output, (long) output->mux_dts);

		// the encoder may return frames with the same dts multiple consecutive times.
		// the muxer may not like this, so ensure monotonically increasing dts.
		if (output->mux_dts > output->avpkt.dts)
			output->avpkt.dts = output->mux_dts;
		if (output->avpkt.pts < output->avpkt.dts)
			output->avpkt.pts = output->avpkt.dts;

		av_write_frame(output->fmtctx, &output->avpkt);

		output->fifo_pts += output->frame->nb_samples;
		output->mux_dts = output->avpkt.dts + 1; // min next expected dts
	}

	return 0;
}


int output_add(output_t *output, AVFrame *frame) {
	if (!output)
		return -1;

	dbg("%p output fifo size %u fifo_pts %lu", output, (unsigned int) av_audio_fifo_size(output->fifo),
			(unsigned long) output->fifo_pts);
	// fix up output pts
	if (av_audio_fifo_size(output->fifo) == 0)
		output->fifo_pts = frame->pts;

	if (av_audio_fifo_write(output->fifo, (void **) frame->extended_data, frame->nb_samples) < 0)
		return -1;

	return output_flush(output);
}


output_t *output_new(const char *filename) {
	output_t *ret = g_slice_alloc0(sizeof(*ret));
	if (asprintf(&ret->filename, "%s.%s", filename, output_file_format) <= 0)
		abort();
	ret->clockrate = -1;
	ret->channels = -1;
	ret->frame = av_frame_alloc();
	return ret;
}


int output_config(output_t *output, unsigned int clockrate, unsigned int channels) {
	// anything to do?
	if (G_UNLIKELY(output->clockrate != clockrate))
		goto format_mismatch;
	if (G_UNLIKELY(output->channels != channels))
		goto format_mismatch;

	// all good
	return 0;

format_mismatch:
	// XXX support reset/config change

	// copy params
	output->clockrate = clockrate;
	output->channels = channels;

	// XXX error reporting
	output->fmtctx = avformat_alloc_context();
	if (!output->fmtctx)
		goto err;
	output->fmtctx->oformat = av_guess_format(output_file_format, NULL, NULL);
	if (!output->fmtctx->oformat)
		goto err;

	AVCodec *codec = avcodec_find_encoder(output_codec_id);
	// XXX error handling
	output->avst = avformat_new_stream(output->fmtctx, codec);
	if (!output->avst)
		goto err;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	output->avcctx = avcodec_alloc_context3(codec);
	if (!output->avcctx)
		goto err;
#else
	output->avcctx = output->avst->codec;
#endif

	output->avcctx->channels = output->channels;
	output->avcctx->channel_layout = av_get_default_channel_layout(output->channels);
	output->avcctx->sample_rate = output->clockrate;
	output->avcctx->sample_fmt = AV_SAMPLE_FMT_S16;
	output->avcctx->time_base = (AVRational){output->clockrate,1};
	output->avst->time_base = output->avcctx->time_base;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	avcodec_parameters_from_context(output->avst->codecpar, output->avcctx);
#endif

	int i = avcodec_open2(output->avcctx, codec, NULL);
	if (i)
		goto err;
	i = avio_open(&output->fmtctx->pb, output->filename, AVIO_FLAG_WRITE);
	if (i < 0)
		goto err;
	i = avformat_write_header(output->fmtctx, NULL);
	if (i)
		goto err;

	av_init_packet(&output->avpkt);

	// output frame and fifo
	output->frame->nb_samples = output->avcctx->frame_size ? : 256;
	output->frame->format = output->avcctx->sample_fmt;
	output->frame->sample_rate = output->avcctx->sample_rate;
	output->frame->channel_layout = output->avcctx->channel_layout;
	if (!output->frame->channel_layout)
		output->frame->channel_layout = av_get_default_channel_layout(output->avcctx->channels);
	if (av_frame_get_buffer(output->frame, 0) < 0)
		abort();

	output->fifo = av_audio_fifo_alloc(output->avcctx->sample_fmt, output->avcctx->channels,
			output->frame->nb_samples);

	return 0;

err:
	output_shutdown(output);
	return -1;
}


static void output_shutdown(output_t *output) {
	if (!output)
		return;
	av_write_trailer(output->fmtctx);
	avcodec_close(output->avcctx);
	avio_closep(&output->fmtctx->pb);
	avformat_free_context(output->fmtctx);
	av_audio_fifo_free(output->fifo);
	av_frame_free(&output->frame);

	output->avcctx = NULL;
	output->fmtctx = NULL;
	output->avst = NULL;
	output->fifo = NULL;
}


void output_close(output_t *output) {
	if (!output)
		return;
	output_shutdown(output);
	free(output->filename);
	g_slice_free1(sizeof(*output), output);
}


void output_init(const char *format) {
	if (!strcmp(format, "wav")) {
		output_codec_id = AV_CODEC_ID_PCM_S16LE;
		output_file_format = "wav";
	}
	else if (!strcmp(format, "mp3")) {
		output_codec_id = AV_CODEC_ID_MP3;
		output_file_format = "mp3";
	}
	else
		die("Unknown output format '%s'", format);
}
