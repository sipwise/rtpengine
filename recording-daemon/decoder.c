#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <glib.h>
#include "types.h"
#include "log.h"


struct decoder_s {
	AVCodecContext *avcctx;
	AVPacket avpkt;
	AVFrame *frame;
};


struct output_s {
	AVCodecContext *avcctx;
	AVFormatContext *fmtctx;
	AVStream *avst;
	AVPacket avpkt;
};


decoder_t *decoder_new(unsigned int payload_type, const char *payload_str) {
	decoder_t *ret = g_slice_alloc0(sizeof(*ret));

	AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_PCM_ALAW);
	ret->avcctx = avcodec_alloc_context3(codec);
	ret->avcctx->channels = 1;
	ret->avcctx->sample_rate = 8000;
	int i = avcodec_open2(ret->avcctx, codec, NULL);
	// XXX error handling

	av_init_packet(&ret->avpkt);
	ret->frame = av_frame_alloc();

	return ret;
}


static int output_add(output_t *output, AVFrame *frame) {
	int got_packet = 0;
	int ret = avcodec_encode_audio2(output->avcctx, &output->avpkt, frame, &got_packet);

	dbg("encode frame ret %i, got packet %i", ret, got_packet);

	if (got_packet)
		av_write_frame(output->fmtctx, &output->avpkt);

	return 0;
}


int decoder_input(decoder_t *dec, const str *data, output_t *output) {
	dec->avpkt.data = (unsigned char *) data->s;
	dec->avpkt.size = data->len;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	int ret = avcodec_send_packet(dec->avcctx, &dec->avpkt);
	dbg("send packet ret %i", ret);

	ret = avcodec_receive_frame(dec->avcctx, dec->frame);
	dbg("receive frame ret %i", ret);
#else
	int got_frame = 0;
	int ret = avcodec_decode_audio4(dec->avcctx, dec->frame, &got_frame, &dec->avpkt);
	dbg("decode frame ret %i, got frame %i", ret, got_frame);
#endif

	output_add(output, dec->frame);

	return 0;
}


output_t *output_new(const char *filename) {
	output_t *ret = g_slice_alloc0(sizeof(*ret));

	ret->fmtctx = avformat_alloc_context();
	ret->fmtctx->oformat = av_guess_format("wav", NULL, NULL);

	AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_PCM_S16LE);
	// XXX error handling
	ret->avst = avformat_new_stream(ret->fmtctx, codec);
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	ret->avcctx = avcodec_alloc_context3(codec);
#else
	ret->avcctx = ret->avst->codec;
#endif

	ret->avcctx->channels = 1;
	ret->avcctx->sample_rate = 8000;
	ret->avcctx->sample_fmt = AV_SAMPLE_FMT_S16;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	avcodec_parameters_from_context(ret->avst->codecpar, ret->avcctx);
#endif

	int i = avcodec_open2(ret->avcctx, codec, NULL);
	avio_open(&ret->fmtctx->pb, filename, AVIO_FLAG_WRITE);
	avformat_write_header(ret->fmtctx, NULL);

	av_init_packet(&ret->avpkt);

	return ret;
}


void decoder_close(decoder_t *dec) {
	avcodec_free_context(&dec->avcctx);
	av_frame_free(&dec->frame);
	g_slice_free1(sizeof(*dec), dec);
}


void output_close(output_t *output) {
	av_write_trailer(output->fmtctx);
	avcodec_close(output->avcctx);
	avio_closep(&output->fmtctx->pb);
	avformat_free_context(output->fmtctx);
	g_slice_free1(sizeof(*output), output);
}
