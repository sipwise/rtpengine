#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <libavutil/samplefmt.h>
#include <glib.h>
#include <stdint.h>
#include <libavresample/avresample.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "str.h"
#include "output.h"
#include "mix.h"
#include "resample.h"


struct decoder_s {
	format_t in_format,
		 out_format;

	resample_t mix_resample,
		   output_resample;

	AVCodecContext *avcctx;
	AVPacket avpkt;
	unsigned long rtp_ts;
	uint64_t pts;

	unsigned int mixer_idx;
};


struct decoder_def_s {
	const char *rtpname;
	int clockrate_mult;
	int avcodec_id;
	const char *avcodec_name;
};


#define DECODER_DEF_MULT_NAME(ref, id, mult, name) { \
	.rtpname = #ref, \
	.avcodec_id = AV_CODEC_ID_ ## id, \
	.clockrate_mult = mult, \
	.avcodec_name = #name, \
}
#define DECODER_DEF_MULT(ref, id, mult) DECODER_DEF_MULT_NAME(ref, id, mult, NULL)
#define DECODER_DEF_NAME(ref, id, name) DECODER_DEF_MULT_NAME(ref, id, 1, name)
#define DECODER_DEF(ref, id) DECODER_DEF_MULT(ref, id, 1)

static const struct decoder_def_s decoders[] = {
	DECODER_DEF(PCMA, PCM_ALAW),
	DECODER_DEF(PCMU, PCM_MULAW),
	DECODER_DEF(G723, G723_1),
	DECODER_DEF_MULT(G722, ADPCM_G722, 2),
	DECODER_DEF(QCELP, QCELP),
	DECODER_DEF(G729, G729),
	DECODER_DEF(speex, SPEEX),
	DECODER_DEF(GSM, GSM),
	DECODER_DEF(iLBC, ILBC),
	DECODER_DEF_NAME(opus, OPUS, libopus),
	DECODER_DEF_NAME(vorbis, VORBIS, libvorbis),
	DECODER_DEF(ac3, AC3),
	DECODER_DEF(eac3, EAC3),
	DECODER_DEF(ATRAC3, ATRAC3),
	DECODER_DEF(ATRAC-X, ATRAC3P),
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	DECODER_DEF(EVRC, EVRC),
	DECODER_DEF(EVRC0, EVRC),
	DECODER_DEF(EVRC1, EVRC),
#endif
	DECODER_DEF(AMR, AMR_NB),
	DECODER_DEF(AMR-WB, AMR_WB),
};
typedef struct decoder_def_s decoder_def_t;




int resample_audio;




static const decoder_def_t *decoder_find(const str *name) {
	for (int i = 0; i < G_N_ELEMENTS(decoders); i++) {
		if (!str_cmp(name, decoders[i].rtpname))
			return &decoders[i];
	}
	return NULL;
}


decoder_t *decoder_new(const char *payload_str) {
	const char *err = NULL;

	str name;
	char *slash = strchr(payload_str, '/');
	if (!slash) {
		ilog(LOG_WARN, "Invalid payload format: %s", payload_str);
		return NULL;
	}

	str_init_len(&name, (char *) payload_str, slash - payload_str);
	int clockrate = atoi(slash + 1);

	int channels = 1;
	slash = strchr(slash + 1, '/');
	if (slash) {
		channels = atoi(slash + 1);
		if (!channels)
			channels = 1;
	}

	const decoder_def_t *def = decoder_find(&name);
	if (!def) {
		ilog(LOG_WARN, "No decoder for payload %s", payload_str);
		return NULL;
	}
	clockrate *= def->clockrate_mult;

	decoder_t *ret = g_slice_alloc0(sizeof(*ret));

	format_init(&ret->in_format);
	ret->in_format.channels = channels;
	ret->in_format.clockrate = clockrate;
	// output defaults to same as input
	ret->out_format = ret->in_format;
	if (resample_audio)
		ret->out_format.clockrate = resample_audio;
	// sample format to be determined later when decoded frames arrive

	AVCodec *codec = NULL;
	if (def->avcodec_name)
		codec = avcodec_find_decoder_by_name(def->avcodec_name);
	if (!codec)
		codec = avcodec_find_decoder(def->avcodec_id);
	if (!codec) {
		ilog(LOG_WARN, "Codec '%s' not supported", def->rtpname);
		goto err;
	}

	ret->avcctx = avcodec_alloc_context3(codec);
	err = "failed to alloc codec context";
	if (!ret->avcctx)
		goto err;
	ret->avcctx->channels = channels;
	ret->avcctx->sample_rate = clockrate;
	err = "failed to open codec context";
	int i = avcodec_open2(ret->avcctx, codec, NULL);
	if (i)
		goto err;

	for (const enum AVSampleFormat *sfmt = codec->sample_fmts; sfmt && *sfmt != -1; sfmt++)
		dbg("supported sample format for input codec %s: %s", codec->name, av_get_sample_fmt_name(*sfmt));

	av_init_packet(&ret->avpkt);

	ret->pts = (uint64_t) -1LL;
	ret->rtp_ts = (unsigned long) -1L;
	ret->mixer_idx = (unsigned int) -1;

	return ret;

err:
	decoder_close(ret);
	if (err)
		ilog(LOG_ERR, "Error creating media decoder: %s", err);
	return NULL;
}


static int decoder_got_frame(decoder_t *dec, output_t *output, metafile_t *metafile, AVFrame *frame) {
	// determine and save sample type
	if (G_UNLIKELY(dec->in_format.format == -1))
		dec->in_format.format = dec->out_format.format = frame->format;

	// handle mix output
	pthread_mutex_lock(&metafile->mix_lock);
	if (metafile->mix_out) {
		if (G_UNLIKELY(dec->mixer_idx == (unsigned int) -1))
			dec->mixer_idx = mix_get_index(metafile->mix);
		format_t actual_format;
		if (output_config(metafile->mix_out, &dec->out_format, &actual_format))
			goto no_mix_out;
		mix_config(metafile->mix, &actual_format);
		AVFrame *dec_frame = resample_frame(&dec->mix_resample, frame, &actual_format);
		if (!dec_frame) {
			pthread_mutex_unlock(&metafile->mix_lock);
			goto err;
		}
		if (mix_add(metafile->mix, dec_frame, dec->mixer_idx, metafile->mix_out))
			ilog(LOG_ERR, "Failed to add decoded packet to mixed output");
	}
no_mix_out:
	pthread_mutex_unlock(&metafile->mix_lock);

	if (output) {
		// XXX might be a second resampling to same format
		format_t actual_format;
		if (output_config(output, &dec->out_format, &actual_format))
			goto err;
		AVFrame *dec_frame = resample_frame(&dec->output_resample, frame, &actual_format);
		if (!dec_frame)
			goto err;
		if (output_add(output, dec_frame))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
		av_frame_free(&dec_frame);
	}

	av_frame_free(&frame);
	return 0;

err:
	av_frame_free(&frame);
	return -1;
}


int decoder_input(decoder_t *dec, const str *data, unsigned long ts, output_t *output, metafile_t *metafile) {
	const char *err;

	if (G_UNLIKELY(!dec))
		return -1;

	dbg("%p dec pts %llu rtp_ts %llu incoming ts %lu", dec, (unsigned long long) dec->pts,
			(unsigned long long) dec->rtp_ts, (unsigned long) ts);

	if (G_UNLIKELY(dec->rtp_ts == (unsigned long) -1L)) {
		// initialize pts
		dec->pts = 0;
	}
	else {
		// shift pts according to rtp ts shift
		dec->pts += (ts - dec->rtp_ts);
		// XXX handle lost packets here if timestamps don't line up?
	}
	dec->rtp_ts = ts;

	dec->avpkt.data = (unsigned char *) data->s;
	dec->avpkt.size = data->len;
	dec->avpkt.pts = dec->pts;

	AVFrame *frame = NULL;

	// loop until all input is consumed and all available output has been processed
	int keep_going;
	do {
		keep_going = 0;
		int got_frame = 0;
		err = "failed to alloc av frame";
		frame = av_frame_alloc();
		if (!frame)
			goto err;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 36, 0)
		if (dec->avpkt.size) {
			int ret = avcodec_send_packet(dec->avcctx, &dec->avpkt);
			dbg("send packet ret %i", ret);
			err = "failed to send packet to avcodec";
			if (ret == 0) {
				// consumed the packet
				dec->avpkt.size = 0;
				keep_going = 1;
			}
			else {
				if (ret == AVERROR(EAGAIN))
					; // try again after reading output
				else
					goto err;
			}
		}

		int ret = avcodec_receive_frame(dec->avcctx, frame);
		dbg("receive frame ret %i", ret);
		err = "failed to receive frame from avcodec";
		if (ret == 0) {
			// got a frame
			keep_going = 1;
			got_frame = 1;
		}
		else {
			if (ret == AVERROR(EAGAIN))
				; // maybe needs more input now
			else
				goto err;
		}
#else
		// only do this if we have any input left
		if (dec->avpkt.size == 0)
			break;

		int ret = avcodec_decode_audio4(dec->avcctx, frame, &got_frame, &dec->avpkt);
		dbg("decode frame ret %i, got frame %i", ret, got_frame);
		err = "failed to decode audio packet";
		if (ret < 0)
			goto err;
		if (ret > 0) {
			// consumed some input
			err = "invalid return value";
			if (ret > dec->avpkt.size)
				goto err;
			dec->avpkt.size -= ret;
			dec->avpkt.data += ret;
			keep_going = 1;
		}
		if (got_frame)
			keep_going = 1;
#endif

		if (got_frame) {
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 36, 0)
			frame->pts = frame->pkt_pts;
#endif
			if (G_UNLIKELY(frame->pts == AV_NOPTS_VALUE))
				frame->pts = dec->avpkt.pts;
			if (decoder_got_frame(dec, output, metafile, frame))
				return -1;
			frame = NULL;
		}
	} while (keep_going);

	av_frame_free(&frame);
	return 0;

err:
	ilog(LOG_ERR, "Error decoding media packet: %s", err);
	av_frame_free(&frame);
	return -1;
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(56, 1, 0)
	avcodec_free_context(&dec->avcctx);
#else
	avcodec_close(dec->avcctx);
	av_free(dec->avcctx);
#endif
	resample_shutdown(&dec->mix_resample);
	resample_shutdown(&dec->output_resample);
	g_slice_free1(sizeof(*dec), dec);
}
