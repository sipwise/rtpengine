#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include <glib.h>
#include <stdint.h>
#include <libavresample/avresample.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "str.h"
#include "output.h"
#include "mix.h"


struct decoder_s {
	// format params
	int channels;
	int in_clockrate;
	int out_clockrate;

	AVAudioResampleContext *avresample;
	AVFrame *swr_frame;
	int swr_buffers;

	AVCodecContext *avcctx;
	AVPacket avpkt;
	AVFrame *frame;
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

	ret->channels = channels;
	ret->in_clockrate = clockrate;
	ret->out_clockrate = resample_audio ? : clockrate;

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

	av_init_packet(&ret->avpkt);
	ret->frame = av_frame_alloc();
	err = "failed to alloc av frame";
	if (!ret->frame)
		goto err;

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


static AVFrame *decoder_resample_frame(decoder_t *dec) {
	const char *err;

	if (dec->in_clockrate == dec->out_clockrate)
		return dec->frame;

	if (!dec->avresample) {
		dec->avresample = avresample_alloc_context();
		err = "failed to alloc resample context";
		if (!dec->avresample)
			goto err;

		av_opt_set_int(dec->avresample, "in_channel_layout",
				av_get_default_channel_layout(dec->channels), 0);
		av_opt_set_int(dec->avresample, "in_sample_fmt",
				AV_SAMPLE_FMT_S16, 0);
		av_opt_set_int(dec->avresample, "in_sample_rate",
				dec->in_clockrate, 0);
		av_opt_set_int(dec->avresample, "out_channel_layout",
				av_get_default_channel_layout(dec->channels), 0);
		av_opt_set_int(dec->avresample, "out_sample_fmt",
				AV_SAMPLE_FMT_S16, 0);
		av_opt_set_int(dec->avresample, "out_sample_rate",
				dec->out_clockrate, 0);
		// av_opt_set_int(dec->avresample, "internal_sample_fmt", AV_SAMPLE_FMT_FLTP, 0); // ?

		err = "failed to init resample context";
		if (avresample_open(dec->avresample) < 0)
			goto err;
	}

	// get a large enough buffer for resampled audio - this should be enough so we don't
	// have to loop
	int dst_samples = avresample_available(dec->avresample) +
		av_rescale_rnd(avresample_get_delay(dec->avresample) + dec->frame->nb_samples,
				dec->out_clockrate, dec->in_clockrate, AV_ROUND_UP);
	if (!dec->swr_frame || dec->swr_buffers < dst_samples) {
		av_frame_free(&dec->swr_frame);
		dec->swr_frame = av_frame_alloc();
		err = "failed to alloc resampling frame";
		if (!dec->swr_frame)
			goto err;
		av_frame_copy_props(dec->swr_frame, dec->frame);
		dec->swr_frame->format = dec->frame->format;
		dec->swr_frame->channel_layout = dec->frame->channel_layout;
		dec->swr_frame->nb_samples = dst_samples;
		dec->swr_frame->sample_rate = dec->out_clockrate;
		err = "failed to get resample buffers";
		if (av_frame_get_buffer(dec->swr_frame, 0) < 0)
			goto err;
		dec->swr_buffers = dst_samples;
	}

	dec->swr_frame->nb_samples = dst_samples;
	int ret_samples = avresample_convert(dec->avresample, dec->swr_frame->extended_data,
				dec->swr_frame->linesize[0], dst_samples,
				dec->frame->extended_data,
				dec->frame->linesize[0], dec->frame->nb_samples);
	err = "failed to resample audio";
	if (ret_samples < 0)
		goto err;

	dec->swr_frame->nb_samples = ret_samples;
	dec->swr_frame->pts = av_rescale(dec->frame->pts, dec->out_clockrate, dec->in_clockrate);
	return dec->swr_frame;

err:
	ilog(LOG_ERR, "Error resampling: %s", err);
	return NULL;
}


static int decoder_got_frame(decoder_t *dec, output_t *output, metafile_t *metafile) {
	// do we need to resample?
	AVFrame *dec_frame = decoder_resample_frame(dec);

	// handle mix output
	pthread_mutex_lock(&metafile->mix_lock);
	if (metafile->mix_out) {
		if (G_UNLIKELY(dec->mixer_idx == (unsigned int) -1))
			dec->mixer_idx = mix_get_index(metafile->mix);
		output_config(metafile->mix_out, dec->out_clockrate, dec->channels);
		mix_config(metafile->mix, dec->out_clockrate, dec->channels);
		AVFrame *clone = av_frame_clone(dec_frame);
		clone->pts = dec_frame->pts;
		if (mix_add(metafile->mix, clone, dec->mixer_idx, metafile->mix_out))
			ilog(LOG_ERR, "Failed to add decoded packet to mixed output");
	}
	pthread_mutex_unlock(&metafile->mix_lock);

	if (output) {
		output_config(output, dec->out_clockrate, dec->channels);
		if (output_add(output, dec_frame))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
	}

	return 0;
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

	// loop until all input is consumed and all available output has been processed
	int keep_going;
	do {
		keep_going = 0;
		int got_frame = 0;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
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

		int ret = avcodec_receive_frame(dec->avcctx, dec->frame);
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

		int ret = avcodec_decode_audio4(dec->avcctx, dec->frame, &got_frame, &dec->avpkt);
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
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 0, 0)
			dec->frame->pts = dec->frame->pkt_pts;
#endif
			if (G_UNLIKELY(dec->frame->pts == AV_NOPTS_VALUE))
				dec->frame->pts = dec->avpkt.pts;
			if (decoder_got_frame(dec, output, metafile))
				return -1;
		}
	} while (keep_going);

	return 0;

err:
	ilog(LOG_ERR, "Error decoding media packet: %s", err);
	return -1;
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs
	avcodec_free_context(&dec->avcctx);
	av_frame_free(&dec->frame);
	av_frame_free(&dec->swr_frame);
	avresample_free(&dec->avresample);
	g_slice_free1(sizeof(*dec), dec);
}
