#include "output.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <glib.h>
#include "log.h"


struct output_s {
	char filename[PATH_MAX];

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

int mp3_bitrate;



static void output_shutdown(output_t *output);



static int output_flush(output_t *output) {
	while (av_audio_fifo_size(output->fifo) >= output->frame->nb_samples) {

		if (av_audio_fifo_read(output->fifo, (void **) output->frame->data,
					output->frame->nb_samples) <= 0)
			abort();

		dbg("%p output fifo pts %lu", output, (unsigned long) output->fifo_pts);
		output->frame->pts = output->fifo_pts;

		int keep_going;
		int have_frame = 1;
		do {
			keep_going = 0;
			int got_packet = 0;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
			if (have_frame) {
				int ret = avcodec_send_frame(output->avcctx, output->frame);
				dbg("%p send frame ret %i", output, ret);
				if (ret == 0) {
					// consumed
					have_frame = 0;
					keep_going = 1;
				}
				else {
					if (ret == AVERROR(EAGAIN))
						; // check output and maybe try again
					else
						return -1;
				}
			}

			int ret = avcodec_receive_packet(output->avcctx, &output->avpkt);
			dbg("%p receive packet ret %i", output, ret);
			if (ret == 0) {
				// got some data
				keep_going = 1;
				got_packet = 1;
			}
			else {
				if (ret == AVERROR(EAGAIN))
					; // try again if there's still more input
				else
					return -1;
			}
#else
			if (!have_frame)
				break;

			int ret = avcodec_encode_audio2(output->avcctx, &output->avpkt, output->frame, &got_packet);
			dbg("%p encode frame ret %i, got packet %i", output, ret, got_packet);
			if (ret == 0)
				have_frame = 0; // consumed
			else
				return -1; // error
			if (got_packet)
				keep_going = 1;
#endif

			if (!got_packet)
				continue;

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
		} while (keep_going);
	}

	return 0;
}


int output_add(output_t *output, AVFrame *frame) {
	if (!output)
		return -1;
	if (!output->frame) // not ready - not configured
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
	g_strlcpy(ret->filename, filename, sizeof(ret->filename));
	ret->clockrate = -1;
	ret->channels = -1;
	return ret;
}


int output_config(output_t *output, unsigned int clockrate, unsigned int channels) {
	const char *err;

	// anything to do?
	if (G_UNLIKELY(output->clockrate != clockrate))
		goto format_mismatch;
	if (G_UNLIKELY(output->channels != channels))
		goto format_mismatch;

	// all good
	return 0;

format_mismatch:
	output_shutdown(output);

	// copy params
	output->clockrate = clockrate;
	output->channels = channels;

	err = "failed to alloc format context";
	output->fmtctx = avformat_alloc_context();
	if (!output->fmtctx)
		goto err;
	output->fmtctx->oformat = av_guess_format(output_file_format, NULL, NULL);
	err = "failed to determine output format";
	if (!output->fmtctx->oformat)
		goto err;

	err = "output codec not found";
	AVCodec *codec = avcodec_find_encoder(output_codec_id);
	if (!codec)
		goto err;
	err = "failed to alloc output stream";
	output->avst = avformat_new_stream(output->fmtctx, codec);
	if (!output->avst)
		goto err;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	err = "failed to alloc codec context";
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
	output->avcctx->time_base = (AVRational){1,output->clockrate};
	output->avcctx->bit_rate = mp3_bitrate;
	output->avst->time_base = output->avcctx->time_base;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	avcodec_parameters_from_context(output->avst->codecpar, output->avcctx);
#endif

	char full_fn[PATH_MAX];
	char suff[16] = "";
	for (int i = 1; i < 20; i++) {
		snprintf(full_fn, sizeof(full_fn), "%s%s.%s", output->filename, suff, output_file_format);
		if (!g_file_test(full_fn, G_FILE_TEST_EXISTS))
			goto got_fn;
		snprintf(suff, sizeof(suff), "-%i", i);
	}

	err = "failed to find unused output file number";
	goto err;

got_fn:
	err = "failed to open output context";
	int i = avcodec_open2(output->avcctx, codec, NULL);
	if (i)
		goto err;
	err = "failed to open avio";
	i = avio_open(&output->fmtctx->pb, full_fn, AVIO_FLAG_WRITE);
	if (i < 0)
		goto err;
	err = "failed to write header";
	i = avformat_write_header(output->fmtctx, NULL);
	if (i)
		goto err;

	av_init_packet(&output->avpkt);

	// output frame and fifo
	output->frame = av_frame_alloc();
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
	ilog(LOG_ERR, "Error configuring media output: %s", err);
	return -1;
}


static void output_shutdown(output_t *output) {
	if (!output)
		return;
	if (!output->fmtctx)
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

	output->fifo_pts = 0;
	output->mux_dts = 0;
}


void output_close(output_t *output) {
	if (!output)
		return;
	output_shutdown(output);
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
