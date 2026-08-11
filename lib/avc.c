#include "codecmod.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <libavutil/opt.h>
#include "loglib.h"
#include "fix_frame_channel_layout.compat"


TYPED_GHASHTABLE(codecs_by_id_alloc, void, struct codec_def_s, g_direct_hash, g_direct_equal, NULL, g_free)


static rwlock_t generic_ffmpeg_codecs_lock = RWLOCK_STATIC_INIT;
static codecs_by_id_alloc generic_ffmpeg_codecs;


const codec_type_t codec_type_avcodec = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = avc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};


const char *avc_decoder_init(decoder_t *dec, const str *extra_opts) {
	const AVCodec *codec = dec->def->decoder;
	if (!codec)
		return "codec not supported";

	dec->avc.avpkt = av_packet_alloc();

	dec->avc.avcctx = avcodec_alloc_context3(codec);
	if (!dec->avc.avcctx)
		return "failed to alloc codec context";
	SET_CHANNELS(dec->avc.avcctx, dec->in_format.channels);
	DEF_CH_LAYOUT(&dec->avc.avcctx->CH_LAYOUT, dec->in_format.channels);
	dec->avc.avcctx->sample_rate = dec->in_format.clockrate;

	if (dec->def->set_dec_options)
		dec->def->set_dec_options(dec, extra_opts);

	int i = avcodec_open2(dec->avc.avcctx, codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open codec context";
	}

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(61, 19, 0)
	avcodec_get_supported_config(dec->avc.avcctx, codec, AV_CODEC_CONFIG_SAMPLE_FORMAT, 0, (const void **) &dec->avc.sample_fmts, NULL);
#else
	dec->avc.sample_fmts = codec->sample_fmts;
#endif

	for (const enum AVSampleFormat *sfmt = dec->avc.sample_fmts; sfmt && *sfmt != -1; sfmt++)
		ilogs(internals, LOG_DEBUG, "supported sample format for input codec %s: %s",
				codec->name, av_get_sample_fmt_name(*sfmt));

	return NULL;
}


void avc_decoder_close(decoder_t *dec) {
	avcodec_free_context(&dec->avc.avcctx);
	av_packet_free(&dec->avc.avpkt);
}


int avc_decoder_input(decoder_t *dec, const str *data, frame_q *out) {
	if (!dec->avc.avpkt)
		return -1; // decoder shut down

	const char *err;
	int av_ret = 0;

	dec->avc.avpkt->data = (unsigned char *) data->s;
	dec->avc.avpkt->size = data->len;
	dec->avc.avpkt->pts = dec->pts;

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

		if (dec->avc.avpkt->size) {
			av_ret = avcodec_send_packet(dec->avc.avcctx, dec->avc.avpkt);
			ilogs(internals, LOG_DEBUG, "send packet ret %i", av_ret);
			err = "failed to send packet to avcodec";
			if (av_ret == 0) {
				// consumed the packet
				dec->avc.avpkt->size = 0;
				keep_going = 1;
			}
			else {
				if (av_ret == AVERROR(EAGAIN))
					; // try again after reading output
				else
					goto err;
			}
		}

		av_ret = avcodec_receive_frame(dec->avc.avcctx, frame);
		ilogs(internals, LOG_DEBUG, "receive frame ret %i", av_ret);
		err = "failed to receive frame from avcodec";
		if (av_ret == 0) {
			// got a frame
			keep_going = 1;
			got_frame = 1;
		}
		else {
			if (av_ret == AVERROR(EAGAIN))
				; // maybe needs more input now
			else
				goto err;
		}

		if (got_frame) {
			ilogs(internals, LOG_DEBUG, "raw frame from decoder pts %llu samples %u",
					(unsigned long long) frame->pts, frame->nb_samples);

			if (G_UNLIKELY(frame->pts == AV_NOPTS_VALUE))
				frame->pts = dec->avc.avpkt->pts;
			dec->avc.avpkt->pts += frame->nb_samples;

			t_queue_push_tail(out, frame);
			frame = NULL;
		}
	} while (keep_going);

	av_frame_free(&frame);
	return 0;

err:
	ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error decoding media packet: %s", err);
	if (av_ret)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(av_ret));
	av_frame_free(&frame);
	return -1;
}


void avc_def_init(struct codec_def_s *def) {
	// look up AVCodec structs
	if (def->avcodec_name_enc)
		def->encoder = avcodec_find_encoder_by_name(def->avcodec_name_enc);
	if (def->avcodec_name_dec)
		def->decoder = avcodec_find_decoder_by_name(def->avcodec_name_dec);
	if (def->avcodec_id >= 0) {
		if (!def->encoder)
			def->encoder = avcodec_find_encoder(def->avcodec_id);
		if (!def->decoder)
			def->decoder = avcodec_find_decoder(def->avcodec_id);
	}
	// check if we have support if we are supposed to
	if (def->avcodec_name_enc || def->avcodec_id >= 0) {
		if (def->encoder)
			def->support_encoding = 1;
	}
	if (def->avcodec_name_dec || def->avcodec_id >= 0) {
		if (def->decoder)
			def->support_decoding = 1;
	}
}



const char *avc_encoder_init(encoder_t *enc, const str *extra_opts) {
	enc->avc.codec = enc->def->encoder;
	if (!enc->avc.codec)
		return "output codec not found";

	enc->avc.avcctx = avcodec_alloc_context3(enc->avc.codec);
	if (!enc->avc.avcctx)
		return "failed to alloc codec context";

	enc->actual_format = enc->requested_format;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(61, 19, 0)
	avcodec_get_supported_config(enc->avc.avcctx, enc->avc.codec, AV_CODEC_CONFIG_SAMPLE_FORMAT, 0, (const void **) &enc->avc.sample_fmts, NULL);
#else
	enc->avc.sample_fmts = enc->avc.codec->sample_fmts;
#endif

	enc->actual_format.format = -1;
	for (const enum AVSampleFormat *sfmt = enc->avc.sample_fmts; sfmt && *sfmt != -1; sfmt++) {
		ilogs(internals, LOG_DEBUG, "supported sample format for output codec %s: %s",
				enc->avc.codec->name, av_get_sample_fmt_name(*sfmt));
		if (*sfmt == enc->requested_format.format)
			enc->actual_format.format = *sfmt;
	}
	if (enc->actual_format.format == -1 && enc->avc.sample_fmts)
		enc->actual_format.format = enc->avc.sample_fmts[0];
	ilogs(internals, LOG_DEBUG, "using output sample format %s for codec %s",
			av_get_sample_fmt_name(enc->actual_format.format), enc->avc.codec->name);

	SET_CHANNELS(enc->avc.avcctx, enc->actual_format.channels);
	DEF_CH_LAYOUT(&enc->avc.avcctx->CH_LAYOUT, enc->actual_format.channels);
	enc->avc.avcctx->sample_rate = enc->actual_format.clockrate;
	enc->avc.avcctx->sample_fmt = enc->actual_format.format;
	enc->avc.avcctx->time_base = (AVRational){1,enc->actual_format.clockrate};
	enc->avc.avcctx->bit_rate = enc->bitrate;

	if (enc->def->set_enc_options)
		enc->def->set_enc_options(enc, extra_opts);

	int i = avcodec_open2(enc->avc.avcctx, enc->avc.codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open output context";
	}

	if (enc->avc.avcctx->frame_size)
		enc->samples_per_frame = enc->avc.avcctx->frame_size;
	else
		enc->samples_per_frame = enc->actual_format.clockrate * enc->ptime / 1000;

	enc->samples_per_packet = enc->samples_per_frame;

	return NULL;
}


void avc_encoder_close(encoder_t *enc) {
	if (enc->avc.avcctx) {
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(61, 0, 0)
		avcodec_close(enc->avc.avcctx);
#endif
		avcodec_free_context(&enc->avc.avcctx);
	}
	enc->avc.avcctx = NULL;
	enc->avc.codec = NULL;
}


int avc_encoder_input(encoder_t *enc, AVFrame **frame) {
	int keep_going = 0;
	int got_packet = 0;
	int av_ret = 0;

	if (!enc->avc.avcctx)
		return -1;

	if (*frame) {
		av_ret = avcodec_send_frame(enc->avc.avcctx, *frame);
		ilogs(internals, LOG_DEBUG, "send frame ret %i", av_ret);
		if (av_ret == 0) {
			// consumed
			*frame = NULL;
			keep_going = 1;
		}
		else {
			if (av_ret == AVERROR(EAGAIN))
				; // check output and maybe try again
			else
				goto err;
		}
	}

	av_ret = avcodec_receive_packet(enc->avc.avcctx, enc->avpkt);
	ilogs(internals, LOG_DEBUG, "receive packet ret %i", av_ret);
	if (av_ret == 0) {
		// got some data
		keep_going = 1;
		got_packet = 1;
	}
	else {
		if (av_ret == AVERROR(EAGAIN))
			; // try again if there's still more input
		else
			goto err;
	}

	if (!got_packet)
		return keep_going;

	ilogs(internals, LOG_DEBUG, "output avpkt size is %i", (int) enc->avpkt->size);
	ilogs(internals, LOG_DEBUG, "output pkt pts/dts is %li/%li", (long) enc->avpkt->pts,
			(long) enc->avpkt->dts);

	// the encoder may return frames with the same dts multiple consecutive times.
	// the muxer may not like this, so ensure monotonically increasing dts.
	if (enc->mux_dts > enc->avpkt->dts)
		enc->avpkt->dts = enc->mux_dts;
	if (enc->avpkt->pts < enc->avpkt->dts)
		enc->avpkt->pts = enc->avpkt->dts;

	return keep_going;

err:
	if (av_ret)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(av_ret));
	return -1;
}


int codeclib_set_av_opt_int(encoder_t *enc, const char *opt, int64_t val) {
	ilog(LOG_DEBUG, "Setting ffmpeg '%s' option for '%s' to %" PRId64,
			opt, enc->def->rtpname, val);

	int ret = av_opt_set_int(enc->avc.avcctx, opt, val, AV_OPT_SEARCH_CHILDREN);
	if (!ret)
		return 0;

	ilog(LOG_WARN, "Failed to set ffmpeg '%s' option for codec '%s' to %" PRId64 ": %s",
			opt, enc->def->rtpname, val, av_error(ret));
	return -1;
}


codec_def_t *codec_def_make_generic_av(enum AVCodecID id) {
	{
		RWLOCK_R(&generic_ffmpeg_codecs_lock);

		struct codec_def_s *ret = t_hash_table_lookup(generic_ffmpeg_codecs, GINT_TO_POINTER(id));
		if (ret)
			return ret;
	}

	{
		RWLOCK_W(&generic_ffmpeg_codecs_lock);

		struct codec_def_s *ret = t_hash_table_lookup(generic_ffmpeg_codecs, GINT_TO_POINTER(id));
		if (ret)
			return ret;

		const AVCodec *codec = avcodec_find_decoder(id);
		if (!codec)
			return NULL;

		ret = g_new(__typeof(*ret), 1);
		*ret = (__typeof(*ret)) {
			.rtpname = "generic ffmpeg codec",
			.rtpname_str = STR_CONST("generic ffmpeg codec"),
			.avcodec_id = id,
			.default_clockrate_fact = {1,1},
			.media_type = MT_AUDIO,
			.codec_type = &codec_type_avcodec,
			.decoder = codec,
			.support_decoding = 1,
			.support_encoding = 1, // just pretend
		};

		t_hash_table_insert(generic_ffmpeg_codecs, GINT_TO_POINTER(id), ret);

		return ret;
	}
}


static void avlog_ilog(void *ptr, int loglevel, const char *fmt, va_list ap) {
	char *msg;
	if (vasprintf(&msg, fmt, ap) <= 0)
		ilogs(ffmpeg, LOG_ERR | LOG_FLAG_LIMIT, "av_log message dropped");
	else {
#ifdef AV_LOG_PANIC
		// translate AV_LOG_ constants to LOG_ levels
		if (loglevel >= AV_LOG_VERBOSE)
			loglevel = LOG_DEBUG;
		else if (loglevel >= AV_LOG_INFO)
			loglevel = LOG_NOTICE;
		else if (loglevel >= AV_LOG_WARNING)
			loglevel = LOG_WARNING;
		else if (loglevel >= AV_LOG_ERROR)
			loglevel = LOG_ERROR;
		else if (loglevel >= AV_LOG_FATAL)
			loglevel = LOG_CRIT;
		else
			loglevel = LOG_ALERT;
#else
		// defuse avlog log levels to be either DEBUG or ERR
		if (loglevel <= LOG_ERR)
			loglevel = LOG_ERR;
		else
			loglevel = LOG_DEBUG;
#endif
		ilogs(ffmpeg, loglevel | LOG_FLAG_LIMIT, "av_log: %s", msg);
		free(msg);
	}
}


void avc_init(void) {
	avformat_network_init();
	av_log_set_callback(avlog_ilog);

	generic_ffmpeg_codecs = codecs_by_id_alloc_new();
}


void avc_cleanup(void) {
	t_hash_table_destroy(generic_ffmpeg_codecs);
	avformat_network_deinit();
}
