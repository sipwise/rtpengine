#include "codeclib.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <libavutil/opt.h>
#include <glib.h>
#include <arpa/inet.h>
#ifdef HAVE_BCG729
#include <bcg729/encoder.h>
#include <bcg729/decoder.h>
#endif
#include "str.h"
#include "log.h"
#include "loglib.h"
#include "resample.h"
#include "rtplib.h"
#include "bitstr.h"
#include "dtmflib.h"



#define PACKET_SEQ_DUPE_THRES 100
#define PACKET_TS_RESET_THRES 5000 // milliseconds



#ifndef dbg
#ifdef __DEBUG
#define dbg(x...) ilog(LOG_DEBUG, x)
#else
#define dbg(x...) ((void)0)
#endif
#endif




static packetizer_f packetizer_passthrough; // pass frames as they arrive in AVPackets
static packetizer_f packetizer_samplestream; // flat stream of samples
static packetizer_f packetizer_amr;

static format_init_f opus_init;
static set_enc_options_f opus_set_enc_options;

static set_enc_options_f ilbc_set_enc_options;
static set_dec_options_f ilbc_set_dec_options;

static set_enc_options_f amr_set_enc_options;
static set_dec_options_f amr_set_dec_options;

static void avc_def_init(codec_def_t *);
static const char *avc_decoder_init(decoder_t *, const str *);
static int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void avc_decoder_close(decoder_t *);
static const char *avc_encoder_init(encoder_t *enc, const str *);
static int avc_encoder_input(encoder_t *enc, AVFrame **frame);
static void avc_encoder_close(encoder_t *enc);

static int amr_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static int ilbc_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static const char *dtmf_decoder_init(decoder_t *, const str *);
static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out);




static const codec_type_t codec_type_avcodec = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = avc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_ilbc = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = ilbc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_amr = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = amr_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_dtmf = {
	.decoder_init = dtmf_decoder_init,
	.decoder_input = dtmf_decoder_input,
};

#ifdef HAVE_BCG729
static packetizer_f packetizer_g729; // aggregate some frames into packets

static void bcg729_def_init(codec_def_t *);
static const char *bcg729_decoder_init(decoder_t *, const str *);
static int bcg729_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void bcg729_decoder_close(decoder_t *);
static const char *bcg729_encoder_init(encoder_t *enc, const str *);
static int bcg729_encoder_input(encoder_t *enc, AVFrame **frame);
static void bcg729_encoder_close(encoder_t *enc);

static const codec_type_t codec_type_bcg729 = {
	.def_init = bcg729_def_init,
	.decoder_init = bcg729_decoder_init,
	.decoder_input = bcg729_decoder_input,
	.decoder_close = bcg729_decoder_close,
	.encoder_init = bcg729_encoder_init,
	.encoder_input = bcg729_encoder_input,
	.encoder_close = bcg729_encoder_close,
};
#endif



static codec_def_t __codec_defs[] = {
	{
		.rtpname = "PCMA",
		.avcodec_id = AV_CODEC_ID_PCM_ALAW,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "PCMU",
		.avcodec_id = AV_CODEC_ID_PCM_MULAW,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "G723",
		.avcodec_id = AV_CODEC_ID_G723_1,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 30,
		.default_bitrate = 6300,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "G722",
		.avcodec_id = AV_CODEC_ID_ADPCM_G722,
		.clockrate_mult = 2,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "QCELP",
		.avcodec_id = AV_CODEC_ID_QCELP,
		.clockrate_mult = 1,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
#ifndef HAVE_BCG729
	{
		.rtpname = "G729",
		.avcodec_id = AV_CODEC_ID_G729,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "G729a",
		.avcodec_id = AV_CODEC_ID_G729,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
#else
	{
		.rtpname = "G729",
		.avcodec_id = -1,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_g729,
		.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_bcg729,
	},
	{
		.rtpname = "G729a",
		.avcodec_id = -1,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_g729,
		.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_bcg729,
	},
#endif
	{
		.rtpname = "speex",
		.avcodec_id = AV_CODEC_ID_SPEEX,
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 11000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "GSM",
		.avcodec_id = AV_CODEC_ID_GSM,
		.default_clockrate = 8000,
		.default_channels = 1,
		//.default_bitrate = 13200,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "iLBC",
		.avcodec_id = AV_CODEC_ID_ILBC,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 30,
		.default_fmtp = "mode=30",
		//.default_bitrate = 15200,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_ilbc,
		.set_enc_options = ilbc_set_enc_options,
		.set_dec_options = ilbc_set_dec_options,
	},
	{
		.rtpname = "opus",
		.avcodec_id = AV_CODEC_ID_OPUS,
		.avcodec_name = "libopus",
		.default_clockrate = 48000,
		.default_channels = 2,
		.default_bitrate = 32000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.init = opus_init,
		.set_enc_options = opus_set_enc_options,
	},
	{
		.rtpname = "vorbis",
		.avcodec_id = AV_CODEC_ID_VORBIS,
		.avcodec_name = "libvorbis",
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "ac3",
		.avcodec_id = AV_CODEC_ID_AC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "eac3",
		.avcodec_id = AV_CODEC_ID_EAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "ATRAC3",
		.avcodec_id = AV_CODEC_ID_ATRAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "ATRAC-X",
		.avcodec_id = AV_CODEC_ID_ATRAC3P,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	{
		.rtpname = "EVRC",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.avcodec_name = NULL,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "EVRC0",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.avcodec_name = NULL,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "EVRC1",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.avcodec_name = NULL,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
#endif
	{
		.rtpname = "AMR",
		.avcodec_id = AV_CODEC_ID_AMR_NB,
		.avcodec_name = NULL,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_bitrate = 6700,
		.default_ptime = 20,
		.default_fmtp = "octet-align=1",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 12200 / 8000 = 1.525 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
	},
	{
		.rtpname = "AMR-WB",
		.avcodec_id = AV_CODEC_ID_AMR_WB,
		.avcodec_name = NULL,
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 14250,
		.default_ptime = 20,
		.default_fmtp = "octet-align=1",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 23850 / 16000 = 1.490625 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
	},
	{
		.rtpname = "telephone-event",
		.avcodec_id = -1,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.supplemental = 1,
		.dtmf = 1,
		.default_clockrate = 1, // special handling
		.default_channels = 1,
		.default_fmtp = "0-15",
		.codec_type = &codec_type_dtmf,
		.support_encoding = 1,
		.support_decoding = 1,
	},
	// for file reading and writing
	{
		.rtpname = "PCM-S16LE",
		.avcodec_id = AV_CODEC_ID_PCM_S16LE,
		.avcodec_name = NULL,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "PCM-U8",
		.avcodec_id = AV_CODEC_ID_PCM_U8,
		.avcodec_name = NULL,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "MP3",
		.avcodec_id = AV_CODEC_ID_MP3,
		.avcodec_name = NULL,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
};



static GHashTable *codecs_ht;
static GHashTable *codecs_ht_by_av;



const codec_def_t *codec_find(const str *name, enum media_type type) {
	codec_def_t *ret = g_hash_table_lookup(codecs_ht, name);
	if (!ret)
		return NULL;
	if (type && type != ret->media_type)
		return NULL;
	return ret;
}

const codec_def_t *codec_find_by_av(enum AVCodecID id) {
	return g_hash_table_lookup(codecs_ht_by_av, GINT_TO_POINTER(id));
}

enum media_type codec_get_type(const str *type) {
	if (!type || !type->len)
		return MT_UNKNOWN;
	if (!str_cmp(type, "audio"))
		return MT_AUDIO;
	if (!str_cmp(type, "video"))
		return MT_VIDEO;
	if (!str_cmp(type, "image"))
		return MT_IMAGE;
	return MT_OTHER;
}




static const char *avc_decoder_init(decoder_t *dec, const str *fmtp) {
	AVCodec *codec = dec->def->decoder;
	if (!codec)
		return "codec not supported";

	dec->u.avc.avcctx = avcodec_alloc_context3(codec);
	if (!dec->u.avc.avcctx)
		return "failed to alloc codec context";
	dec->u.avc.avcctx->channels = dec->in_format.channels;
	dec->u.avc.avcctx->sample_rate = dec->in_format.clockrate;

	if (dec->def->set_dec_options)
		dec->def->set_dec_options(dec, fmtp);

	int i = avcodec_open2(dec->u.avc.avcctx, codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open codec context";
	}

	for (const enum AVSampleFormat *sfmt = codec->sample_fmts; sfmt && *sfmt != -1; sfmt++)
		dbg("supported sample format for input codec %s: %s",
				codec->name, av_get_sample_fmt_name(*sfmt));

	return NULL;
}



decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, int ptime, const format_t *resample_fmt) {
	return decoder_new_fmtp(def, clockrate, channels, ptime, resample_fmt, NULL);
}

decoder_t *decoder_new_fmtp(const codec_def_t *def, int clockrate, int channels, int ptime, const format_t *resample_fmt,
		const str *fmtp)
{
	const char *err;
	decoder_t *ret = NULL;

	err = "codec not supported";
	if (!def->codec_type)
		goto err;

	clockrate *= def->clockrate_mult;

	ret = g_slice_alloc0(sizeof(*ret));

	ret->def = def;
	format_init(&ret->in_format);
	ret->in_format.channels = channels;
	ret->in_format.clockrate = clockrate;
	// output defaults to same as input
	ret->out_format = ret->in_format;
	if (resample_fmt)
		ret->out_format = *resample_fmt;
	if (ptime > 0)
		ret->ptime = ptime;
	else
		ret->ptime = def->default_ptime;

	err = def->codec_type->decoder_init(ret, fmtp);
	if (err)
		goto err;

	av_init_packet(&ret->u.avc.avpkt);

	ret->pts = (uint64_t) -1LL;
	ret->rtp_ts = (unsigned long) -1L;

	return ret;

err:
	if (ret)
		decoder_close(ret);
	if (err)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error creating media decoder for codec %s: %s", def->rtpname, err);
	return NULL;
}


static void avc_decoder_close(decoder_t *dec) {
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(56, 1, 0)
	avcodec_free_context(&dec->u.avc.avcctx);
#else
	avcodec_close(dec->u.avc.avcctx);
	av_free(dec->u.avc.avcctx);
#endif
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs

	if (dec->def && dec->def->codec_type && dec->def->codec_type->decoder_close)
		dec->def->codec_type->decoder_close(dec);

	resample_shutdown(&dec->resampler);
	g_slice_free1(sizeof(*dec), dec);
}


static int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	const char *err;
	int av_ret = 0;

	dec->u.avc.avpkt.data = (unsigned char *) data->s;
	dec->u.avc.avpkt.size = data->len;
	dec->u.avc.avpkt.pts = dec->pts;

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
		if (dec->u.avc.avpkt.size) {
			av_ret = avcodec_send_packet(dec->u.avc.avcctx, &dec->u.avc.avpkt);
			dbg("send packet ret %i", av_ret);
			err = "failed to send packet to avcodec";
			if (av_ret == 0) {
				// consumed the packet
				dec->u.avc.avpkt.size = 0;
				keep_going = 1;
			}
			else {
				if (av_ret == AVERROR(EAGAIN))
					; // try again after reading output
				else
					goto err;
			}
		}

		av_ret = avcodec_receive_frame(dec->u.avc.avcctx, frame);
		dbg("receive frame ret %i", av_ret);
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
#else
		// only do this if we have any input left
		if (dec->u.avc.avpkt.size == 0)
			break;

		av_ret = avcodec_decode_audio4(dec->u.avc.avcctx, frame, &got_frame, &dec->u.avc.avpkt);
		dbg("decode frame ret %i, got frame %i", av_ret, got_frame);
		err = "failed to decode audio packet";
		if (av_ret < 0)
			goto err;
		if (av_ret > 0) {
			// consumed some input
			err = "invalid return value";
			if (av_ret > dec->u.avc.avpkt.size)
				goto err;
			dec->u.avc.avpkt.size -= av_ret;
			dec->u.avc.avpkt.data += av_ret;
			keep_going = 1;
		}
		if (got_frame)
			keep_going = 1;
#endif

		if (got_frame) {
			dbg("raw frame from decoder pts %llu samples %u",
					(unsigned long long) frame->pts, frame->nb_samples);

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 36, 0)
			frame->pts = frame->pkt_pts;
#endif
			if (G_UNLIKELY(frame->pts == AV_NOPTS_VALUE))
				frame->pts = dec->u.avc.avpkt.pts;
			dec->u.avc.avpkt.pts += frame->nb_samples;

			g_queue_push_tail(out, frame);
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

int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	GQueue frames = G_QUEUE_INIT;

	if (G_UNLIKELY(!dec))
		return -1;
	if (!data || !data->s || !data->len)
		return 0;

	ts *= dec->def->clockrate_mult;

	dbg("%p dec pts %llu rtp_ts %llu incoming ts %lu", dec, (unsigned long long) dec->pts,
			(unsigned long long) dec->rtp_ts, (unsigned long) ts);

	if (G_UNLIKELY(dec->rtp_ts == (unsigned long) -1L)) {
		// initialize pts
		dec->pts = 0;
	}
	else {
		// shift pts according to rtp ts shift
		u_int64_t shift_ts = ts - dec->rtp_ts;
		if ((shift_ts * 1000) / dec->in_format.clockrate > PACKET_TS_RESET_THRES) {
			ilog(LOG_DEBUG, "Timestamp discontinuity detected, resetting timestamp from "
					"%lu to %lu",
					dec->rtp_ts, ts);
			// XXX handle lost packets here if timestamps don't line up?
		}
		else
			dec->pts += shift_ts;
	}
	dec->rtp_ts = ts;

	dec->def->codec_type->decoder_input(dec, data, &frames);

	AVFrame *frame;
	int ret = 0;
	while ((frame = g_queue_pop_head(&frames))) {
		AVFrame *rsmp_frame = resample_frame(&dec->resampler, frame, &dec->out_format);
		if (!rsmp_frame) {
			ilog(LOG_ERR | LOG_FLAG_LIMIT, "Resampling failed");
			ret = -1;
		}
		else {
			if (callback(dec, rsmp_frame, u1, u2))
				ret = -1;
		}
		av_frame_free(&frame);
	}

	return ret;
}


static void avlog_ilog(void *ptr, int loglevel, const char *fmt, va_list ap) {
	char *msg;
	if (vasprintf(&msg, fmt, ap) <= 0)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "av_log message dropped");
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
		ilog(loglevel | LOG_FLAG_LIMIT, "av_log: %s", msg);
		free(msg);
	}
}


static void avc_def_init(codec_def_t *def) {
	// look up AVCodec structs
	if (def->avcodec_name) {
		def->encoder = avcodec_find_encoder_by_name(def->avcodec_name);
		def->decoder = avcodec_find_decoder_by_name(def->avcodec_name);
	}
	if (def->avcodec_id >= 0) {
		if (!def->encoder)
			def->encoder = avcodec_find_encoder(def->avcodec_id);
		if (!def->decoder)
			def->decoder = avcodec_find_decoder(def->avcodec_id);
	}
	// check if we have support if we are supposed to
	if (def->avcodec_name || def->avcodec_id >= 0) {
		if (def->encoder)
			def->support_encoding = 1;
		if (def->decoder)
			def->support_decoding = 1;
	}
}

void codeclib_init(int print) {
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
	av_register_all();
	avcodec_register_all();
	avfilter_register_all();
#endif
	avformat_network_init();
	av_log_set_callback(avlog_ilog);

	codecs_ht = g_hash_table_new(str_case_hash, str_case_equal);
	codecs_ht_by_av = g_hash_table_new(g_direct_hash, g_direct_equal);

	for (int i = 0; i < G_N_ELEMENTS(__codec_defs); i++) {
		// add to hash table
		codec_def_t *def = &__codec_defs[i];
		str_init(&def->rtpname_str, (char *) def->rtpname);
		assert(g_hash_table_lookup(codecs_ht, &def->rtpname_str) == NULL);
		g_hash_table_insert(codecs_ht, &def->rtpname_str, def);

		if (def->avcodec_id >= 0) {
			if (g_hash_table_lookup(codecs_ht_by_av, GINT_TO_POINTER(def->avcodec_id)) == NULL)
				g_hash_table_insert(codecs_ht_by_av, GINT_TO_POINTER(def->avcodec_id), def);
		}

		// init undefined member vars
		if (!def->clockrate_mult)
			def->clockrate_mult = 1;
		if (!def->default_ptime)
			def->default_ptime = -1;
		if (!def->default_clockrate)
			def->default_clockrate = -1;
		if (!def->default_channels)
			def->default_channels = -1;

		// init RFC-related info
		const struct rtp_payload_type *pt = rtp_get_rfc_codec(&def->rtpname_str);
		if (pt)
			def->rfc_payload_type = pt->payload_type;
		else
			def->rfc_payload_type = -1;

		if (def->codec_type && def->codec_type->def_init)
			def->codec_type->def_init(def);

		if (print) {
			if (def->support_encoding && def->support_decoding) {
				if (def->default_channels > 0 && def->default_clockrate >= 0)
					printf("%20s: fully supported\n", def->rtpname);
				else
					printf("%20s: codec supported but lacks RTP definition\n", def->rtpname);
			}
			else if (def->support_decoding)
				printf("%20s: supported for decoding only\n", def->rtpname);
			else if (def->support_encoding)
				printf("%20s: supported for encoding only\n", def->rtpname);
			else
				printf("%20s: not supported\n", def->rtpname);
		}
		else {
			if (!def->support_encoding && !def->support_decoding)
				ilog(LOG_DEBUG, "Codec %s is not supported by codec library",
						def->rtpname);
			else if (!def->support_encoding) {
				ilog(LOG_DEBUG, "Codec %s is only supported for decoding "
						"by codec library", def->rtpname);
			}
			else if (!def->support_decoding)
				ilog(LOG_DEBUG, "Codec %s is only supported for encoding "
						"by codec library", def->rtpname);
		}
	}
}






static int ptr_cmp(const void *a, const void *b, void *dummy) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

void __packet_sequencer_init(packet_sequencer_t *ps, GDestroyNotify ffunc) {
	ps->packets = g_tree_new_full(ptr_cmp, NULL, NULL, ffunc);
	ps->seq = -1;
}
void packet_sequencer_destroy(packet_sequencer_t *ps) {
	if (ps->packets)
		g_tree_destroy(ps->packets);
	ps->packets = NULL;
}
struct tree_searcher {
	int find_seq,
	    found_seq;
};
static int packet_tree_search(const void *testseq_p, const void *ts_p) {
	struct tree_searcher *ts = (void *) ts_p;
	int testseq = GPOINTER_TO_INT(testseq_p);
	// called as a binary search test function. we're looking for the lowest
	// seq number that is higher than find_seq. if our test number is too low,
	// we proceed with higher numbers. if it's too high, we proceed to the lower
	// numbers, but remember the lowest we've seen along that path.
	if (G_UNLIKELY(testseq == ts->find_seq)) {
		// we've struck gold
		ts->found_seq = testseq;
		return 0;
	}
	if (testseq < ts->find_seq)
		return 1;
	// testseq > ts->find_seq
	if (ts->found_seq == -1 || testseq < ts->found_seq)
		ts->found_seq = testseq;
	return -1;
}
// caller must take care of locking
static void *__packet_sequencer_next_packet(packet_sequencer_t *ps, int num_wait) {
	// see if we have a packet with the correct seq nr in the queue
	seq_packet_t *packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ps->seq));
	if (G_LIKELY(packet != NULL)) {
		dbg("returning in-sequence packet (seq %i)", ps->seq);
		goto out;
	}

	// why not? do we have anything? (we should)
	int nnodes = g_tree_nnodes(ps->packets);
	if (G_UNLIKELY(nnodes == 0)) {
		dbg("packet queue empty");
		return NULL;
	}
	if (G_LIKELY(nnodes < num_wait)) {
		dbg("only %i packets in queue - waiting for more", nnodes);
		return NULL; // need to wait for more
	}

	// packet was probably lost. search for the next highest seq
	struct tree_searcher ts = { .find_seq = ps->seq + 1, .found_seq = -1 };
	packet = g_tree_search(ps->packets, packet_tree_search, &ts);
	if (packet) {
		// bullseye
		dbg("lost packet - returning packet with next seq %i", packet->seq);
		goto out;
	}
	if (G_UNLIKELY(ts.found_seq == -1)) {
		// didn't find anything. seq must have wrapped around. retry
		// starting from zero
		ts.find_seq = 0;
		packet = g_tree_search(ps->packets, packet_tree_search, &ts);
		if (packet) {
			dbg("lost packet - returning packet with next seq %i (after wrap)", packet->seq);
			goto out;
		}
		if (G_UNLIKELY(ts.found_seq == -1))
			abort();
	}

	// pull out the packet we found
	packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ts.found_seq));
	if (G_UNLIKELY(packet == NULL))
		abort();

	dbg("lost multiple packets - returning packet with next highest seq %i", packet->seq);

out:
	;
	u_int16_t l = packet->seq - ps->seq;
	ps->lost_count += l;

	g_tree_steal(ps->packets, GINT_TO_POINTER(packet->seq));
	ps->seq = (packet->seq + 1) & 0xffff;

	if (packet->seq < ps->ext_seq)
		ps->roc++;
	ps->ext_seq = ps->roc << 16 | packet->seq;

	return packet;
}
void *packet_sequencer_next_packet(packet_sequencer_t *ps) {
	return __packet_sequencer_next_packet(ps, 10); // arbitrary value
}
void *packet_sequencer_force_next_packet(packet_sequencer_t *ps) {
	return __packet_sequencer_next_packet(ps, 0);
}

int packet_sequencer_insert(packet_sequencer_t *ps, seq_packet_t *p) {
	int ret = 0;

	// check seq for dupes
	if (G_UNLIKELY(ps->seq == -1)) {
		// first packet we see
		ps->seq = p->seq;
		goto seq_ok;
	}

	int diff = p->seq - ps->seq;
	// early packet: p->seq = 200, ps->seq = 150, diff = 50
	if (G_LIKELY(diff >= 0 && diff < PACKET_SEQ_DUPE_THRES))
		goto seq_ok;
	// early packet with wrap-around: p->seq = 20, ps->seq = 65530, diff = -65510
	if (diff < (-0xffff + PACKET_SEQ_DUPE_THRES))
		goto seq_ok;
	// recent duplicate: p->seq = 1000, ps->seq = 1080, diff = -80
	if (diff < 0 && diff > -PACKET_SEQ_DUPE_THRES)
		return -1;
	// recent duplicate after wrap-around: p->seq = 65530, ps->seq = 30, diff = 65500
	if (diff > (0xffff - PACKET_SEQ_DUPE_THRES))
		return -1;

	// everything else we consider a seq reset
	ilog(LOG_DEBUG, "Seq reset detected: expected seq %i, received seq %i", ps->seq, p->seq);
	ps->seq = p->seq;
	ret = 1;
	// seq ok - fall through
	g_tree_clear(ps->packets);
seq_ok:
	if (g_tree_lookup(ps->packets, GINT_TO_POINTER(p->seq)))
		return -1;
	g_tree_insert(ps->packets, GINT_TO_POINTER(p->seq), p);

	return ret;
}




encoder_t *encoder_new(void) {
	encoder_t *ret = g_slice_alloc0(sizeof(*ret));
	format_init(&ret->requested_format);
	format_init(&ret->actual_format);
	return ret;
}

static const char *avc_encoder_init(encoder_t *enc, const str *fmtp) {
	enc->u.avc.codec = enc->def->encoder;
	if (!enc->u.avc.codec)
		return "output codec not found";

	enc->u.avc.avcctx = avcodec_alloc_context3(enc->u.avc.codec);
	if (!enc->u.avc.avcctx)
		return "failed to alloc codec context";

	enc->actual_format = enc->requested_format;

	enc->actual_format.format = -1;
	for (const enum AVSampleFormat *sfmt = enc->u.avc.codec->sample_fmts; sfmt && *sfmt != -1; sfmt++) {
		dbg("supported sample format for output codec %s: %s",
				enc->u.avc.codec->name, av_get_sample_fmt_name(*sfmt));
		if (*sfmt == enc->requested_format.format)
			enc->actual_format.format = *sfmt;
	}
	if (enc->actual_format.format == -1 && enc->u.avc.codec->sample_fmts)
		enc->actual_format.format = enc->u.avc.codec->sample_fmts[0];
	dbg("using output sample format %s for codec %s",
			av_get_sample_fmt_name(enc->actual_format.format), enc->u.avc.codec->name);

	enc->u.avc.avcctx->channels = enc->actual_format.channels;
	enc->u.avc.avcctx->channel_layout = av_get_default_channel_layout(enc->actual_format.channels);
	enc->u.avc.avcctx->sample_rate = enc->actual_format.clockrate;
	enc->u.avc.avcctx->sample_fmt = enc->actual_format.format;
	enc->u.avc.avcctx->time_base = (AVRational){1,enc->actual_format.clockrate};
	enc->u.avc.avcctx->bit_rate = enc->bitrate;

	enc->samples_per_frame = enc->actual_format.clockrate * enc->ptime / 1000;
	if (enc->u.avc.avcctx->frame_size)
		enc->samples_per_frame = enc->u.avc.avcctx->frame_size;
	enc->samples_per_packet = enc->samples_per_frame;

	if (enc->def->set_enc_options)
		enc->def->set_enc_options(enc, fmtp);

	int i = avcodec_open2(enc->u.avc.avcctx, enc->u.avc.codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open output context";
	}

	return NULL;
}

int encoder_config(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format)
{
	return encoder_config_fmtp(enc, def, bitrate, ptime, requested_format, actual_format, NULL);
}

int encoder_config_fmtp(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format, const str *fmtp)
{
	const char *err;

	err = "codec not supported";
	if (!def->codec_type)
		goto err;

	// anything to do?
	if (G_LIKELY(format_eq(requested_format, &enc->requested_format)))
		goto done;

	encoder_close(enc);

	enc->requested_format = *requested_format;
	enc->def = def;
	enc->ptime = ptime / def->clockrate_mult;
	enc->bitrate = bitrate;

	err = def->codec_type->encoder_init ? def->codec_type->encoder_init(enc, fmtp) : 0;
	if (err)
		goto err;

	av_init_packet(&enc->avpkt);

// output frame and fifo
	enc->frame = av_frame_alloc();

	if (enc->actual_format.format != -1 && enc->actual_format.clockrate > 0) {
		enc->frame->nb_samples = enc->samples_per_frame ? : 256;
		enc->frame->format = enc->actual_format.format;
		enc->frame->sample_rate = enc->actual_format.clockrate;
		enc->frame->channel_layout = av_get_default_channel_layout(enc->actual_format.channels);
		//if (!enc->frame->channel_layout)
			//enc->frame->channel_layout = av_get_default_channel_layout(enc->u.avc.avcctx->channels);
		if (av_frame_get_buffer(enc->frame, 0) < 0)
			abort();

		enc->fifo = av_audio_fifo_alloc(enc->frame->format, enc->actual_format.channels,
				enc->frame->nb_samples);

		ilog(LOG_DEBUG, "Initialized encoder with frame size %u samples", enc->frame->nb_samples);
	}
	else
		ilog(LOG_DEBUG, "Initialized encoder without frame buffer");


done:
	if (actual_format)
		*actual_format = enc->actual_format;
	return 0;

err:
	encoder_close(enc);
	ilog(LOG_ERR, "Error configuring media output for codec %s: %s", def->rtpname, err);
	return -1;
}

static void avc_encoder_close(encoder_t *enc) {
	if (enc->u.avc.avcctx) {
		avcodec_close(enc->u.avc.avcctx);
		avcodec_free_context(&enc->u.avc.avcctx);
	}
	enc->u.avc.avcctx = NULL;
	enc->u.avc.codec = NULL;
}

void encoder_close(encoder_t *enc) {
	if (!enc)
		return;
	if (enc->def && enc->def->codec_type && enc->def->codec_type->encoder_close)
		enc->def->codec_type->encoder_close(enc);
	format_init(&enc->requested_format);
	format_init(&enc->actual_format);
	av_audio_fifo_free(enc->fifo);
	av_frame_free(&enc->frame);
	enc->mux_dts = 0;
	enc->fifo = NULL;
	enc->fifo_pts = 0;
}
void encoder_free(encoder_t *enc) {
	encoder_close(enc);
	g_slice_free1(sizeof(*enc), enc);
}

static int avc_encoder_input(encoder_t *enc, AVFrame **frame) {
	int keep_going = 0;
	int got_packet = 0;
	int av_ret = 0;

	if (!enc->u.avc.avcctx)
		return -1;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 36, 0)
	if (*frame) {
		av_ret = avcodec_send_frame(enc->u.avc.avcctx, *frame);
		dbg("send frame ret %i", av_ret);
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

	av_ret = avcodec_receive_packet(enc->u.avc.avcctx, &enc->avpkt);
	dbg("receive packet ret %i", av_ret);
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
#else
	if (!*frame)
		return 0;

	av_ret = avcodec_encode_audio2(enc->u.avc.avcctx, &enc->avpkt, *frame, &got_packet);
	dbg("encode frame ret %i, got packet %i", av_ret, got_packet);
	if (av_ret == 0)
		*frame = NULL; // consumed
	else
		goto err;
	if (got_packet)
		keep_going = 1;
#endif

	if (!got_packet)
		return keep_going;

//	dbg("{%s} output avpkt size is %i", output->file_name, (int) enc->avpkt.size);
//	dbg("{%s} output pkt pts/dts is %li/%li", output->file_name, (long) enc->avpkt.pts,
//			(long) enc->avpkt.dts);
//	dbg("{%s} output dts %li", output->file_name, (long) output->mux_dts);

	// the encoder may return frames with the same dts multiple consecutive times.
	// the muxer may not like this, so ensure monotonically increasing dts.
	if (enc->mux_dts > enc->avpkt.dts)
		enc->avpkt.dts = enc->mux_dts;
	if (enc->avpkt.pts < enc->avpkt.dts)
		enc->avpkt.pts = enc->avpkt.dts;

	return keep_going;

err:
	if (av_ret)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(av_ret));
	return -1;
}

int encoder_input_data(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	enc->avpkt.size = 0;

	while (1) {
		if (!enc->def->codec_type->encoder_input)
			break;

		int ret = enc->def->codec_type->encoder_input(enc, &frame);
		if (ret < 0)
			return -1;

		if (enc->avpkt.size) {
			//av_write_frame(output->fmtctx, &output->avpkt);
			callback(enc, u1, u2);

			//output->fifo_pts += output->frame->nb_samples;
			enc->mux_dts = enc->avpkt.dts + 1; // min next expected dts

			av_packet_unref(&enc->avpkt);
			enc->avpkt.size = 0;
		}

		if (ret == 0)
			break;
	}

	return 0;
}

static int encoder_fifo_flush(encoder_t *enc,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	while (av_audio_fifo_size(enc->fifo) >= enc->frame->nb_samples) {

		if (av_audio_fifo_read(enc->fifo, (void **) enc->frame->data,
					enc->frame->nb_samples) <= 0)
			abort();

		dbg("output fifo pts %lu",(unsigned long) enc->fifo_pts);
		enc->frame->pts = enc->fifo_pts;

		encoder_input_data(enc, enc->frame, callback, u1, u2);

		enc->fifo_pts += enc->frame->nb_samples;
	}

	return 0;
}

int encoder_input_fifo(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	if (av_audio_fifo_write(enc->fifo, (void **) frame->extended_data, frame->nb_samples) < 0)
		return -1;

	return encoder_fifo_flush(enc, callback, u1, u2);
}


static int packetizer_passthrough(AVPacket *pkt, GString *buf, str *output, encoder_t *enc) {
	if (!pkt)
		return -1;
	assert(output->len >= pkt->size);
	output->len = pkt->size;
	memcpy(output->s, pkt->data, pkt->size);
	return 0;
}

// returns: -1 = not enough data, nothing returned; 0 = returned a packet;
// 1 = returned a packet and there's more
static int packetizer_samplestream(AVPacket *pkt, GString *buf, str *input_output, encoder_t *enc) {
	// avoid moving buffers around if possible:
	// most common case: new input packet has just enough (or more) data as what we need
	if (G_LIKELY(pkt && buf->len == 0 && pkt->size >= input_output->len)) {
		memcpy(input_output->s, pkt->data, input_output->len);
		if (pkt->size > input_output->len) // any leftovers?
			g_string_append_len(buf, (char *) pkt->data + input_output->len,
					pkt->size - input_output->len);
		return buf->len >= input_output->len ? 1 : 0;
	}
	// we have to move data around. append input packet to buffer if we have one
	if (pkt)
		g_string_append_len(buf, (char *) pkt->data, pkt->size);
	// do we have enough?
	if (buf->len < input_output->len)
		return -1;
	// copy requested data into provided output buffer and remove from interim buffer
	memcpy(input_output->s, buf->str, input_output->len);
	g_string_erase(buf, 0, input_output->len);
	return buf->len >= input_output->len ? 1 : 0;
}





static void opus_init(struct rtp_payload_type *pt) {
	if (pt->clock_rate != 48000) {
		ilog(LOG_WARN, "Opus is only supported with a clock rate of 48 kHz");
		pt->clock_rate = 48000;
	}

	switch (pt->ptime) {
		case 5:
		case 10:
		case 20:
		case 40:
		case 60:
			break;
		default:
			;
			int np;
			if (pt->ptime < 10)
				np = 5;
			else if (pt->ptime < 20)
				np = 10;
			else if (pt->ptime < 40)
				np = 20;
			else if (pt->ptime < 60)
				np = 40;
			else
				np = 60;
			ilog(LOG_INFO, "Opus doesn't support a ptime of %i ms; using %i ms instead",
					pt->ptime, np);
			pt->ptime = np;
			break;
	}

	if (pt->bitrate) {
		if (pt->bitrate < 6000) {
			ilog(LOG_DEBUG, "Opus bitrate %i bps too small, assuming %i kbit/s",
					pt->bitrate, pt->bitrate);
			pt->bitrate *= 1000;
		}
		return;
	}
	if (pt->channels == 1)
		pt->bitrate = 24000;
	else if (pt->channels == 2)
		pt->bitrate = 32000;
	else
		pt->bitrate = 64000;
	ilog(LOG_DEBUG, "Using default bitrate of %i bps for %i-channel Opus", pt->bitrate, pt->channels);
}

static void opus_set_enc_options(encoder_t *enc, const str *fmtp) {
	int ret;
	if (enc->ptime)
		if ((ret = av_opt_set_int(enc->u.avc.avcctx, "frame_duration", enc->ptime,
						AV_OPT_SEARCH_CHILDREN)))
			ilog(LOG_WARN, "Failed to set Opus frame_duration option to %i: %s",
					enc->ptime, av_error(ret));
	// XXX additional opus options
}

static int ilbc_mode(int ptime, const str *fmtp, const char *direction) {
	int mode = 0;

	if (fmtp) {
		if (!str_cmp(fmtp, "mode=20")) {
			mode = 20;
			ilog(LOG_DEBUG, "Setting iLBC %s mode to 20 ms based on fmtp", direction);
		}
		else if (!str_cmp(fmtp, "mode=30")) {
			mode = 30;
			ilog(LOG_DEBUG, "Setting iLBC %s mode to 30 ms based on fmtp", direction);
		}
	}

	if (!mode) {
		switch (ptime) {
			case 20:
			case 40:
			case 60:
			case 80:
			case 100:
			case 120:
				mode = 20;
				ilog(LOG_DEBUG, "Setting iLBC %s mode to 20 ms based on ptime %i",
						direction, ptime);
				break;
			case 30:
			case 90:
				mode = 30;
				ilog(LOG_DEBUG, "Setting iLBC %s mode to 30 ms based on ptime %i",
						direction, ptime);
				break;
		}
	}

	if (!mode) {
		mode = 20;
		ilog(LOG_WARNING, "No iLBC %s mode specified, setting to 20 ms", direction);
	}

	return mode;
}

static void ilbc_set_enc_options(encoder_t *enc, const str *fmtp) {
	int ret;
	int mode = ilbc_mode(enc->ptime, fmtp, "encoder");

	if ((ret = av_opt_set_int(enc->u.avc.avcctx, "mode", mode,
					AV_OPT_SEARCH_CHILDREN)))
		ilog(LOG_WARN, "Failed to set iLBC mode option to %i: %s",
				mode, av_error(ret));
}

static void ilbc_set_dec_options(decoder_t *dec, const str *fmtp) {
	int mode = ilbc_mode(dec->ptime, fmtp, "decoder");
	if (mode == 20)
		dec->u.avc.avcctx->block_align = 38;
	else if (mode == 30)
		dec->u.avc.avcctx->block_align = 50;
	else
		ilog(LOG_WARN, "Unsupported iLBC mode %i", mode);
}

static int ilbc_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	int mode = 0, block_align = 0;
	static const str mode_20 = STR_CONST_INIT("mode=20");
	static const str mode_30 = STR_CONST_INIT("mode=30");
	const str *fmtp;

	if (data->len % 50 == 0) {
		mode = 30;
		block_align = 50;
		fmtp = &mode_30;
	}
	else if (data->len % 38 == 0) {
		mode = 20;
		block_align = 38;
		fmtp = &mode_20;
	}
	else
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "iLBC received %i bytes packet, does not match "
				"one of the block sizes", (int) data->len);

	if (block_align && dec->u.avc.avcctx->block_align != block_align) {
		ilog(LOG_INFO | LOG_FLAG_LIMIT, "iLBC decoder set to %i bytes blocks, but received packet "
				"of %i bytes, therefore resetting decoder and switching to %i bytes "
				"block mode (%i ms mode)",
				(int) dec->u.avc.avcctx->block_align, (int) data->len, block_align, mode);
		avc_decoder_close(dec);
		avc_decoder_init(dec, fmtp);
	}

	return avc_decoder_input(dec, data, out);
}





#define AMR_FT_TYPES 14
const static unsigned int amr_bits_per_frame[AMR_FT_TYPES] = {
	95, // 4.75 kbit/s // 0
	103, // 5.15 kbit/s // 1
	118, // 5.90 kbit/s // 2
	134, // 6.70 kbit/s // 3
	148, // 7.40 kbit/s // 4
	159, // 7.95 kbit/s // 5
	204, // 10.2 kbit/s // 6
	244, // 12.2 kbit/s // 7
	40, // comfort noise // 8
	40, // comfort noise // 9
	40, // comfort noise // 10
	40, // comfort noise // 11
	0, // invalid // 12
	0, // invalid // 13
};
const static unsigned int amr_wb_bits_per_frame[AMR_FT_TYPES] = {
	132, // 6.60 kbit/s // 0
	177, // 8.85 kbit/s // 1
	253, // 12.65 kbit/s // 2
	285, // 14.25 kbit/s // 3
	317, // 15.85 kbit/s // 4
	365, // 18.25 kbit/s // 5
	397, // 19.85 kbit/s // 6
	461, // 23.05 kbit/s // 7
	477, // 23.85 kbit/s // 8
	40, // comfort noise // 9
	0, // invalid // 10
	0, // invalid // 11
	0, // invalid // 12
	0, // invalid // 13
};
static void amr_set_encdec_options(codec_options_t *opts, const str *fmtp, const codec_def_t *def) {
	if (!strcmp(def->rtpname, "AMR"))
		opts->amr.bits_per_frame = amr_bits_per_frame;
	else
		opts->amr.bits_per_frame = amr_wb_bits_per_frame;

	if (!fmtp || !fmtp->s)
		return;

	// semicolon-separated key=value
	str s = *fmtp;
	str token, key;
	while (str_token_sep(&token, &s, ';') == 0) {
		if (str_token(&key, &token, '='))
			continue;
		if (!str_cmp(&key, "octet-align")) {
			if (token.len == 1 && token.s[0] == '1')
				opts->amr.octet_aligned = 1;
		}
		else if (!str_cmp(&key, "crc")) {
			if (token.len == 1 && token.s[0] == '1') {
				opts->amr.octet_aligned = 1;
				opts->amr.crc = 1;
			}
		}
		else if (!str_cmp(&key, "robust-sorting")) {
			if (token.len == 1 && token.s[0] == '1') {
				opts->amr.octet_aligned = 1;
				opts->amr.robust_sorting = 1;
			}
		}
		else if (!str_cmp(&key, "interleaving")) {
			opts->amr.octet_aligned = 1;
			opts->amr.interleaving = str_to_i(&token, 0);
		}
		// XXX other options
	}
}
static void amr_set_enc_options(encoder_t *enc, const str *fmtp) {
	amr_set_encdec_options(&enc->codec_options, fmtp, enc->def);
}
static void amr_set_dec_options(decoder_t *dec, const str *fmtp) {
	amr_set_encdec_options(&dec->codec_options, fmtp, dec->def);
}

static int amr_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	const char *err = NULL;

	if (!data || !data->s)
		goto err;

	bitstr d;
	bitstr_init(&d, data);

	GQueue toc = G_QUEUE_INIT;
	unsigned int ill = 0, ilp = 0;

	unsigned char cmr_chr[2];
	str cmr = STR_CONST_INIT_BUF(cmr_chr);
	err = "no CMR";
	if (bitstr_shift_ret(&d, 4, &cmr))
		goto err;
	// XXX handle CMR?

	if (dec->codec_options.amr.octet_aligned) {
		if (bitstr_shift(&d, 4))
			goto err;

		if (dec->codec_options.amr.interleaving) {
			unsigned char ill_ilp_chr[2];
			str ill_ilp = STR_CONST_INIT_BUF(ill_ilp_chr);
			err = "no ILL/ILP";
			if (bitstr_shift_ret(&d, 8, &ill_ilp))
				goto err;
			ill = ill_ilp_chr[0] >> 4;
			ilp = ill_ilp_chr[0] & 0xf;
		}
	}

	err = "ILP > ILL";
	if (ilp > ill)
		goto err;
	err = "interleaving unimplemented";
	if (ill)
		goto err;

	// TOC
	int num_crcs = 0;
	while (1) {
		unsigned char toc_byte[2];
		str toc_entry = STR_CONST_INIT_BUF(toc_byte);
		err = "missing TOC entry";
		if (bitstr_shift_ret(&d, 6, &toc_entry))
			goto err;

		if (dec->codec_options.amr.octet_aligned)
			if (bitstr_shift(&d, 2))
				goto err;

		unsigned char ft = (toc_byte[0] >> 3) & 0xf;
		if (ft != 14 && ft != 15) {
			num_crcs++;
			err = "invalid frame type";
			if (ft >= AMR_FT_TYPES)
				goto err;
			if (dec->codec_options.amr.bits_per_frame[ft] == 0)
				goto err;
		}

		g_queue_push_tail(&toc, GUINT_TO_POINTER(toc_byte[0]));

		// no F bit = last TOC entry
		if (!(toc_byte[0] & 0x80))
			break;
	}

	if (dec->codec_options.amr.crc) {
		// CRCs is one byte per frame
		err = "missing CRC entry";
		if (bitstr_shift(&d, num_crcs * 8))
			goto err;
		// XXX use/check CRCs
	}

	while (toc.length) {
		unsigned char toc_byte = GPOINTER_TO_UINT(g_queue_pop_head(&toc));
		unsigned char ft = (toc_byte >> 3) & 0xf;
		if (ft >= AMR_FT_TYPES) // invalid
			continue;

		unsigned int bits = dec->codec_options.amr.bits_per_frame[ft];

		// AMR encoder expects an octet aligned TOC byte plus the payload
		unsigned char frame_buf[(bits + 7) / 8 + 1 + 1];
		str frame = STR_CONST_INIT_BUF(frame_buf);
		str_shift(&frame, 1);
		err = "short frame";
		if (bitstr_shift_ret(&d, bits, &frame))
			goto err;

		// add TOC byte
		str_shift(&frame, -1);
		frame.s[0] = toc_byte & 0x7c; // strip F bit, keep FT and Q, zero padding (01111100)

		if (dec->codec_options.amr.octet_aligned && (bits % 8) != 0) {
			unsigned int padding_bits = 8 - (bits % 8);
			if (bitstr_shift(&d, padding_bits))
				goto err;
		}

		err = "failed to decode AMR data";
		if (avc_decoder_input(dec, &frame, out))
			goto err;
	}

	return 0;

err:
	if (err)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error unpacking AMR packet: %s", err);

	return -1;
}
static int packetizer_amr(AVPacket *pkt, GString *buf, str *output, encoder_t *enc) {
	assert(pkt->size >= 1);

	// CMR + TOC byte (already included) + optional ILL/ILP + optional CRC + payload
	assert(output->len >= pkt->size + 3);

	unsigned char toc = pkt->data[0];
	unsigned char ft = (toc >> 3) & 0xf;
	assert(ft <= 13);
	unsigned int bits = enc->codec_options.amr.bits_per_frame[ft];
	assert(bits != 0);

	unsigned char *s = (unsigned char *) output->s; // for safe bit shifting

	s[0] = '\xf0'; // no CMR req (4 bits)

	if (enc->codec_options.amr.octet_aligned) {
		unsigned int offset = 1; // CMR byte
		if (enc->codec_options.amr.interleaving)
			s[offset++] = 0; // no interleaving
		if (enc->codec_options.amr.crc)
			s[offset++] = 0; // not implemented
		memcpy(s + offset, pkt->data, pkt->size);
		output->len = pkt->size + offset;
		return 0;
	}

	// bit shift TOC byte in (6 bits)
	s[0] |= pkt->data[0] >> 4;
	s[1] = (pkt->data[0] & 0x0c) << 4;

	// bit shift payload in (shifted by 4+6 = 10 bits = 1 byte + 2 bits
	for (int i = 1; i < pkt->size; i++) {
		s[i] |= pkt->data[i] >> 2;
		s[i+1] = pkt->data[i] << 6;
	}

	// is the last byte just padding?
	bits += 4 + 6; // CMR and TOC
	unsigned int bytes = (bits + 7) / 8;
	output->len = bytes;

	return 0;
}




#ifdef HAVE_BCG729
static void bcg729_def_init(codec_def_t *def) {
	// test init
	bcg729EncoderChannelContextStruct *e = initBcg729EncoderChannel(0);
	bcg729DecoderChannelContextStruct *d = initBcg729DecoderChannel();
	if (e) {
		def->support_encoding = 1;
		closeBcg729EncoderChannel(e);
	}
	if (d) {
		def->support_decoding = 1;
		closeBcg729DecoderChannel(d);
	}
}

static const char *bcg729_decoder_init(decoder_t *dec, const str *fmtp) {
	dec->u.bcg729 = initBcg729DecoderChannel();
	if (!dec->u.bcg729)
		return "failed to initialize bcg729";
	return NULL;
}

static int bcg729_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	str input = *data;
	u_int64_t pts = dec->pts;

	while (input.len >= 2) {
		int frame_len = input.len >= 10 ? 10 : 2;
		str inp_frame = input;
		inp_frame.len = frame_len;
		str_shift(&input, frame_len);

		AVFrame *frame = av_frame_alloc();
		frame->nb_samples = 80;
		frame->format = AV_SAMPLE_FMT_S16;
		frame->sample_rate = dec->in_format.clockrate; // 8000
		frame->channel_layout = av_get_default_channel_layout(dec->in_format.channels); // 1 channel
		frame->pts = pts;
		if (av_frame_get_buffer(frame, 0) < 0)
			abort();

		pts += frame->nb_samples;

		// XXX handle lost packets and comfort noise
		bcg729Decoder(dec->u.bcg729, (void *) inp_frame.s, inp_frame.len, 0, 0, 0,
				(void *) frame->extended_data[0]);

		g_queue_push_tail(out, frame);
	}

	return 0;
}

static void bcg729_decoder_close(decoder_t *dec) {
	if (dec->u.bcg729)
		closeBcg729DecoderChannel(dec->u.bcg729);
	dec->u.bcg729 = NULL;
}

static const char *bcg729_encoder_init(encoder_t *enc, const str *fmtp) {
	enc->u.bcg729 = initBcg729EncoderChannel(0); // no VAD
	if (!enc->u.bcg729)
		return "failed to initialize bcg729";

	enc->actual_format.format = AV_SAMPLE_FMT_S16;
	enc->actual_format.channels = 1;
	enc->actual_format.clockrate = 8000;
	enc->samples_per_frame = 80;
	enc->samples_per_packet = enc->actual_format.clockrate * enc->ptime / 1000;

	return NULL;
}

static int bcg729_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	if ((*frame)->nb_samples != 80) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "bcg729: input %u samples instead of 80", (*frame)->nb_samples);
		return -1;
	}

	av_new_packet(&enc->avpkt, 10);
	unsigned char len = 0;

	bcg729Encoder(enc->u.bcg729, (void *) (*frame)->extended_data[0], enc->avpkt.data, &len);
	if (!len) {
		av_packet_unref(&enc->avpkt);
		return 0;
	}

	enc->avpkt.size = len;
	enc->avpkt.pts = (*frame)->pts;

	return 0;
}

static void bcg729_encoder_close(encoder_t *enc) {
	if (enc->u.bcg729)
		closeBcg729EncoderChannel(enc->u.bcg729);
	enc->u.bcg729 = NULL;
}

static int packetizer_g729(AVPacket *pkt, GString *buf, str *input_output, encoder_t *enc) {
	// how many frames do we want?
	int want_frames = input_output->len / 10;

	// easiest case: we only want one frame. return what we got
	if (want_frames == 1 && pkt)
		return packetizer_passthrough(pkt, buf, input_output, enc);

	// any other case, we go through our buffer
	str output = *input_output; // remaining output buffer
	if (pkt)
		g_string_append_len(buf, (char *) pkt->data, pkt->size);

	// how many frames do we have?
	int have_audio_frames = buf->len / 10;
	int have_noise_frames = (buf->len % 10) / 2;
	// we have enough?
	// special case: 4 noise frames (8 bytes) must be returned now, as otherwise
	// (5 noise frames) they might become indistinguishable from an audio frame
	if (have_audio_frames + have_noise_frames < want_frames
			&& have_noise_frames != 4)
		return -1;

	// return non-silence/noise frames while we can
	while (buf->len >= 10 && want_frames && output.len >= 10) {
		memcpy(output.s, buf->str, 10);
		g_string_erase(buf, 0, 10);
		want_frames--;
		str_shift(&output, 10);
	}

	// append silence/noise frames if we can
	while (buf->len >= 2 && want_frames && output.len >= 2) {
		memcpy(output.s, buf->str, 2);
		g_string_erase(buf, 0, 2);
		want_frames--;
		str_shift(&output, 2);
	}

	if (output.len == input_output->len)
		return -1; // got nothing
	input_output->len = output.s - input_output->s;
	return buf->len >= 2 ? 1 : 0;
}
#endif


static const char *dtmf_decoder_init(decoder_t *dec, const str *fmtp) {
	dec->u.dtmf.event = -1;
	return NULL;
}

static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	struct telephone_event_payload *dtmf;
	if (data->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %u)", data->len);
		return -1;
	}
	dtmf = (void *) data->s;

	// init if we need to
	if (dtmf->event != dec->u.dtmf.event || dec->rtp_ts != dec->u.dtmf.start_ts) {
		ZERO(dec->u.dtmf);
		dec->u.dtmf.event = dtmf->event;
		dec->u.dtmf.start_ts = dec->rtp_ts;
		ilog(LOG_DEBUG, "New DTMF event starting: %u at TS %lu", dtmf->event, dec->rtp_ts);
	}

	unsigned long duration = ntohs(dtmf->duration);
	unsigned long frame_ts = dec->rtp_ts - dec->u.dtmf.start_ts + dec->u.dtmf.duration;
	long num_samples = duration - dec->u.dtmf.duration;

	ilog(LOG_DEBUG, "Generate DTMF samples for event %u, start TS %lu, TS now %lu, frame TS %lu, "
			"duration %lu, "
			"old duration %lu, num samples %li",
			dtmf->event, dec->u.dtmf.start_ts, dec->rtp_ts, frame_ts,
			duration, dec->u.dtmf.duration, num_samples);

	if (num_samples <= 0)
		return 0;
	if (num_samples > dec->in_format.clockrate) {
		ilog(LOG_ERR, "Cannot generate %li DTMF samples (clock rate %u)", num_samples,
				dec->in_format.clockrate);
		return -1;
	}

	// synthesise PCM
	// first get our frame and figure out how many samples we need, and the start offset
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = num_samples;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = dec->in_format.clockrate;
	frame->channel_layout = AV_CH_LAYOUT_MONO;
	frame->pts = frame_ts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	// fill samples
	dtmf_samples(frame->extended_data[0], frame_ts, frame->nb_samples, dtmf->event,
			dtmf->volume, dec->in_format.clockrate);

	g_queue_push_tail(out, frame);

	dec->u.dtmf.duration = duration;

	return 0;
}
