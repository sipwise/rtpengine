#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <glib.h>
#include <stdint.h>
#include "types.h"
#include "log.h"


struct decoder_s {
	AVCodecContext *avcctx;
	AVPacket avpkt;
	AVFrame *frame;
	unsigned long rtp_ts;
	uint64_t pts;
};


struct output_s {
	AVCodecContext *avcctx;
	AVFormatContext *fmtctx;
	AVStream *avst;
	AVPacket avpkt;
};


decoder_t *decoder_new(unsigned int payload_type, const char *payload_str) {
	decoder_t *ret = g_slice_alloc0(sizeof(*ret));

	// XXX error reporting
	AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_PCM_ALAW);
	ret->avcctx = avcodec_alloc_context3(codec);
	if (!ret->avcctx)
		goto err;
	ret->avcctx->channels = 1;
	ret->avcctx->sample_rate = 8000;
	int i = avcodec_open2(ret->avcctx, codec, NULL);
	if (i)
		goto err;

	av_init_packet(&ret->avpkt);
	ret->frame = av_frame_alloc();
	if (!ret->frame)
		goto err;

	ret->pts = (uint64_t) -1LL;
	ret->rtp_ts = (unsigned long) -1L;

	return ret;

err:
	decoder_close(ret);
	return NULL;
}


static int output_add(output_t *output, AVFrame *frame) {
	if (!output)
		return -1;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	int ret = avcodec_send_frame(output->avcctx, frame);
	dbg("send frame ret %i", ret);
	if (ret)
		return -1;

	ret = avcodec_receive_packet(output->avcctx, &output->avpkt);
	dbg("receive packet ret %i", ret);
	if (ret)
		return -1;
#else
	int got_packet = 0;
	int ret = avcodec_encode_audio2(output->avcctx, &output->avpkt, frame, &got_packet);
	dbg("encode frame ret %i, got packet %i", ret, got_packet);
	if (!got_packet)
		return 0;
#endif

	av_write_frame(output->fmtctx, &output->avpkt);

	return 0;
}


int decoder_input(decoder_t *dec, const str *data, unsigned long ts, output_t *output) {
	if (G_UNLIKELY(!dec))
		return -1;

	if (G_UNLIKELY(dec->rtp_ts == (unsigned long) -1L)) {
		// initialize pts
		dec->pts = 0;
	}
	else {
		// shift pts according to rtp ts shift
		dec->pts += (ts - dec->rtp_ts) * output->avst->time_base.num * 8000 / output->avst->time_base.den;
		// XXX handle lost packets here if timestamps don't line up?
	}
	dec->rtp_ts = ts;

	dec->avpkt.data = (unsigned char *) data->s;
	dec->avpkt.size = data->len;
	dec->avpkt.pts = dec->pts;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	int ret = avcodec_send_packet(dec->avcctx, &dec->avpkt);
	dbg("send packet ret %i", ret);
	if (ret)
		return -1;

	ret = avcodec_receive_frame(dec->avcctx, dec->frame);
	dbg("receive frame ret %i", ret);
	if (ret)
		return -1;
#else
	int got_frame = 0;
	int ret = avcodec_decode_audio4(dec->avcctx, dec->frame, &got_frame, &dec->avpkt);
	dbg("decode frame ret %i, got frame %i", ret, got_frame);
	if (!got_frame)
		return 0;
#endif

	dec->frame->pts = dec->frame->pkt_pts;

	output_add(output, dec->frame);

	return 0;
}


output_t *output_new(const char *filename) {
	output_t *ret = g_slice_alloc0(sizeof(*ret));

	// XXX error reporting
	ret->fmtctx = avformat_alloc_context();
	if (!ret->fmtctx)
		goto err;
	ret->fmtctx->oformat = av_guess_format("wav", NULL, NULL); // XXX better way?
	if (!ret->fmtctx->oformat)
		goto err;

	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_PCM_S16LE);
	// XXX error handling
	ret->avst = avformat_new_stream(ret->fmtctx, codec);
	if (!ret->avst)
		goto err;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	ret->avcctx = avcodec_alloc_context3(codec);
	if (!ret->avcctx)
		goto err;
#else
	ret->avcctx = ret->avst->codec;
#endif

	ret->avcctx->channels = 1;
	ret->avcctx->sample_rate = 8000;
	ret->avcctx->sample_fmt = AV_SAMPLE_FMT_S16;
	ret->avcctx->time_base = (AVRational){8000,1};
	ret->avst->time_base = ret->avcctx->time_base;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	avcodec_parameters_from_context(ret->avst->codecpar, ret->avcctx);
#endif

	int i = avcodec_open2(ret->avcctx, codec, NULL);
	if (i)
		goto err;
	i = avio_open(&ret->fmtctx->pb, filename, AVIO_FLAG_WRITE);
	if (i < 0)
		goto err;
	i = avformat_write_header(ret->fmtctx, NULL);
	if (i)
		goto err;

	av_init_packet(&ret->avpkt);

	return ret;

err:
	output_close(ret);
	return NULL;
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	avcodec_free_context(&dec->avcctx);
	av_frame_free(&dec->frame);
	g_slice_free1(sizeof(*dec), dec);
}


void output_close(output_t *output) {
	if (!output)
		return;
	av_write_trailer(output->fmtctx);
	avcodec_close(output->avcctx);
	avio_closep(&output->fmtctx->pb);
	avformat_free_context(output->fmtctx);
	g_slice_free1(sizeof(*output), output);
}
