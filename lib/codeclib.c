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



#define cdbg(x...) ilogs(internals, LOG_DEBUG, x)




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
static const char *avc_decoder_init(decoder_t *, const str *, const str *);
static int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void avc_decoder_close(decoder_t *);
static const char *avc_encoder_init(encoder_t *enc, const str *, const str *);
static int avc_encoder_input(encoder_t *enc, AVFrame **frame);
static void avc_encoder_close(encoder_t *enc);

static int amr_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void amr_encoder_got_packet(encoder_t *enc);
static int ilbc_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static const char *dtmf_decoder_init(decoder_t *, const str *, const str *);
static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static const char *cn_decoder_init(decoder_t *, const str *, const str *);
static int cn_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static int format_cmp_ignore(const struct rtp_payload_type *, const struct rtp_payload_type *);

static int generic_silence_dtx(decoder_t *, GQueue *, int);
static int amr_dtx(decoder_t *, GQueue *, int);

static int generic_cn_dtx_init(decoder_t *);
static void generic_cn_dtx_cleanup(decoder_t *);
static int generic_cn_dtx(decoder_t *, GQueue *, int);




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
	.encoder_got_packet = amr_encoder_got_packet,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_dtmf = {
	.decoder_init = dtmf_decoder_init,
	.decoder_input = dtmf_decoder_input,
};
static const codec_type_t codec_type_cn = {
	.def_init = avc_def_init,
	.decoder_init = cn_decoder_init,
	.decoder_input = cn_decoder_input,
	.decoder_close = avc_decoder_close,
};

static const dtx_method_t dtx_method_silence = {
	.method_id = DTX_SILENCE,
	.do_dtx = generic_silence_dtx,
};
static const dtx_method_t dtx_method_cn = {
	.method_id = DTX_CN,
	.do_dtx = generic_cn_dtx,
	.init = generic_cn_dtx_init,
	.cleanup = generic_cn_dtx_cleanup,
};
static const dtx_method_t dtx_method_amr = {
	.method_id = DTX_NATIVE,
	.do_dtx = amr_dtx,
};

#ifdef HAVE_BCG729
static packetizer_f packetizer_g729; // aggregate some frames into packets

static void bcg729_def_init(codec_def_t *);
static const char *bcg729_decoder_init(decoder_t *, const str *, const str *);
static int bcg729_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void bcg729_decoder_close(decoder_t *);
static const char *bcg729_encoder_init(encoder_t *enc, const str *, const str *);
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
		.silence_pattern = STR_CONST_INIT("\xd5"),
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.silence_pattern = STR_CONST_INIT("\xff"),
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.silence_pattern = STR_CONST_INIT("\xfa"),
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "QCELP",
		.avcodec_id = AV_CODEC_ID_QCELP,
		.clockrate_mult = 1,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
#else
	{
		.rtpname = "G729",
		.avcodec_id = -1,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.default_fmtp = "annexb=no",
		.packetizer = packetizer_g729,
		.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_bcg729,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
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
		.avcodec_name_enc = "libopus",
		.avcodec_name_dec = "libopus",
		.default_clockrate = 48000,
		.default_channels = 2,
		.default_bitrate = 32000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.init = opus_init,
		.format_cmp = format_cmp_ignore,
		.set_enc_options = opus_set_enc_options,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "vorbis",
		.avcodec_id = AV_CODEC_ID_VORBIS,
		.avcodec_name_enc = "libvorbis",
		.avcodec_name_dec = "libvorbis",
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "ac3",
		.avcodec_id = AV_CODEC_ID_AC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "eac3",
		.avcodec_id = AV_CODEC_ID_EAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "ATRAC3",
		.avcodec_id = AV_CODEC_ID_ATRAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "ATRAC-X",
		.avcodec_id = AV_CODEC_ID_ATRAC3P,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	{
		.rtpname = "EVRC",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "EVRC0",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "EVRC1",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
#endif
	{
		.rtpname = "AMR",
		.avcodec_id = AV_CODEC_ID_AMR_NB,
		.avcodec_name_enc = "libopencore_amrnb",
		.avcodec_name_dec = "libopencore_amrnb",
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_bitrate = 6700,
		.default_ptime = 20,
		.default_fmtp = "octet-align=1;mode-change-capability=2",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 12200 / 8000 = 1.525 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
		.amr = 1,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_amr,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "AMR-WB",
		.avcodec_id = AV_CODEC_ID_AMR_WB,
		.avcodec_name_enc = "libvo_amrwbenc",
		.avcodec_name_dec = "libopencore_amrwb",
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 14250,
		.default_ptime = 20,
		.default_fmtp = "octet-align=1;mode-change-capability=2",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 23850 / 16000 = 1.490625 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
		.amr = 1,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_amr,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "telephone-event",
		.avcodec_id = -1,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.supplemental = 1,
		.dtmf = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_fmtp = "0-15",
		.format_cmp = format_cmp_ignore,
		.codec_type = &codec_type_dtmf,
		.support_encoding = 1,
		.support_decoding = 1,
	},
	{
		.rtpname = "CN",
		.avcodec_id = AV_CODEC_ID_COMFORT_NOISE,
		.avcodec_name_enc = "comfortnoise",
		.avcodec_name_dec = "comfortnoise",
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.supplemental = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.format_cmp = format_cmp_ignore,
		.codec_type = &codec_type_cn,
	},
	// for file reading and writing
	{
		.rtpname = "PCM-S16LE",
		.avcodec_id = AV_CODEC_ID_PCM_S16LE,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "PCM-U8",
		.avcodec_id = AV_CODEC_ID_PCM_U8,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "MP3",
		.avcodec_id = AV_CODEC_ID_MP3,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
};

static GQueue __supplemental_codecs = G_QUEUE_INIT;
const GQueue * const codec_supplemental_codecs = &__supplemental_codecs;
static codec_def_t *codec_def_cn;



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




static const char *avc_decoder_init(decoder_t *dec, const str *fmtp, const str *extra_opts) {
	AVCodec *codec = dec->def->decoder;
	if (!codec)
		return "codec not supported";

	dec->u.avc.avpkt = av_packet_alloc();

	dec->u.avc.avcctx = avcodec_alloc_context3(codec);
	if (!dec->u.avc.avcctx)
		return "failed to alloc codec context";
	dec->u.avc.avcctx->channels = dec->in_format.channels;
	dec->u.avc.avcctx->sample_rate = dec->in_format.clockrate;

	if (dec->def->set_dec_options)
		dec->def->set_dec_options(dec, fmtp, extra_opts);

	int i = avcodec_open2(dec->u.avc.avcctx, codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open codec context";
	}

	for (const enum AVSampleFormat *sfmt = codec->sample_fmts; sfmt && *sfmt != -1; sfmt++)
		cdbg("supported sample format for input codec %s: %s",
				codec->name, av_get_sample_fmt_name(*sfmt));

	return NULL;
}



decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt)
{
	return decoder_new_fmtp(def, clockrate, channels, ptime, resample_fmt, NULL, NULL);
}

decoder_t *decoder_new_fmtp(const codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt,
		const str *fmtp,
		const str *extra_opts)
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
	ret->dest_format = ret->in_format;
	ret->dec_out_format = ret->in_format;
	if (resample_fmt)
		ret->dest_format = *resample_fmt;
	if (ptime > 0)
		ret->ptime = ptime;
	else
		ret->ptime = def->default_ptime;

	// init with first supported DTX method
	enum dtx_method dm = -1;
	for (int i = 0; i < NUM_DTX_METHODS; i++) {
		if (def->dtx_methods[i]) {
			dm = i;
			break;
		}
	}

	err = def->codec_type->decoder_init(ret, fmtp, extra_opts);
	if (err)
		goto err;

	ret->pts = (uint64_t) -1LL;
	ret->rtp_ts = (unsigned long) -1L;

	decoder_switch_dtx(ret, dm);

	return ret;

err:
	if (ret)
		decoder_close(ret);
	if (err)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error creating media decoder for codec %s: %s", def->rtpname, err);
	return NULL;
}


int decoder_switch_dtx(decoder_t *dec, enum dtx_method dm) {
	if (dec->dtx.cleanup)
		dec->dtx.cleanup(dec);
	ZERO(dec->dtx);
	unsigned int i = dm;
	if (i >= NUM_DTX_METHODS)
		return -1;
	const dtx_method_t *dmp = dec->def->dtx_methods[i];
	if (!dmp)
		return -1;
	dec->dtx = *dmp;
	if (dmp->init) {
		if (dmp->init(dec)) {
			ilog(LOG_ERR, "Failed to initialise DTX (%u)", i);
			decoder_switch_dtx(dec, -1);
			return -1;
		}
	}
	return 0;
}

int decoder_set_cn_dtx(decoder_t *dec, const str *cn_pl) {
	if (decoder_switch_dtx(dec, DTX_CN))
		return -1;
	dec->dtx.u.cn.cn_payload = cn_pl;
	return 0;
}


gboolean decoder_has_dtx(decoder_t *dec) {
	return dec->dtx.do_dtx == NULL ? FALSE : TRUE;
}


static void avc_decoder_close(decoder_t *dec) {
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(56, 1, 0)
	avcodec_free_context(&dec->u.avc.avcctx);
#else
	avcodec_close(dec->u.avc.avcctx);
	av_free(dec->u.avc.avcctx);
#endif
	av_packet_free(&dec->u.avc.avpkt);
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs

	if (dec->def && dec->def->codec_type && dec->def->codec_type->decoder_close)
		dec->def->codec_type->decoder_close(dec);

	decoder_switch_dtx(dec, -1);

	resample_shutdown(&dec->resampler);
	g_slice_free1(sizeof(*dec), dec);
}


static int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	const char *err;
	int av_ret = 0;

	dec->u.avc.avpkt->data = (unsigned char *) data->s;
	dec->u.avc.avpkt->size = data->len;
	dec->u.avc.avpkt->pts = dec->pts;

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
		if (dec->u.avc.avpkt->size) {
			av_ret = avcodec_send_packet(dec->u.avc.avcctx, dec->u.avc.avpkt);
			cdbg("send packet ret %i", av_ret);
			err = "failed to send packet to avcodec";
			if (av_ret == 0) {
				// consumed the packet
				dec->u.avc.avpkt->size = 0;
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
		cdbg("receive frame ret %i", av_ret);
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
		if (dec->u.avc.avpkt->size == 0)
			break;

		av_ret = avcodec_decode_audio4(dec->u.avc.avcctx, frame, &got_frame, dec->u.avc.avpkt);
		cdbg("decode frame ret %i, got frame %i", av_ret, got_frame);
		err = "failed to decode audio packet";
		if (av_ret < 0)
			goto err;
		if (av_ret > 0) {
			// consumed some input
			err = "invalid return value";
			if (av_ret > dec->u.avc.avpkt->size)
				goto err;
			dec->u.avc.avpkt->size -= av_ret;
			dec->u.avc.avpkt->data += av_ret;
			keep_going = 1;
		}
		if (got_frame)
			keep_going = 1;
#endif

		if (got_frame) {
			cdbg("raw frame from decoder pts %llu samples %u",
					(unsigned long long) frame->pts, frame->nb_samples);

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 36, 0)
			frame->pts = frame->pkt_pts;
#endif
			if (G_UNLIKELY(frame->pts == AV_NOPTS_VALUE))
				frame->pts = dec->u.avc.avpkt->pts;
			dec->u.avc.avpkt->pts += frame->nb_samples;

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

static int __decoder_input_data(decoder_t *dec, const str *data, unsigned long ts, int *ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	GQueue frames = G_QUEUE_INIT;

	if (G_UNLIKELY(!dec))
		return -1;

	if (!data && (!dec->dtx.do_dtx || !ptime))
		return 0;

	ts *= dec->def->clockrate_mult;

	cdbg("%p dec pts %llu rtp_ts %llu incoming ts %lu", dec, (unsigned long long) dec->pts,
			(unsigned long long) dec->rtp_ts, (unsigned long) ts);

	if (G_UNLIKELY(dec->rtp_ts == (unsigned long) -1L)) {
		// initialize pts
		dec->pts = 0;
	}
	else {
		// shift pts according to rtp ts shift
		uint64_t shift_ts = ts - dec->rtp_ts;
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

	if (data)
		dec->def->codec_type->decoder_input(dec, data, &frames);
	else
		dec->dtx.do_dtx(dec, &frames, *ptime);

	AVFrame *frame;
	int ret = 0;
	unsigned long samples = 0;
	while ((frame = g_queue_pop_head(&frames))) {
		samples += frame->nb_samples;
		dec->dec_out_format.format = frame->format;
		AVFrame *rsmp_frame = resample_frame(&dec->resampler, frame, &dec->dest_format);
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

	if (ptime)
		*ptime = samples * 1000L / dec->in_format.clockrate;

	return ret;
}
int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	if (!data || !data->s || !data->len)
		return 0;
	return __decoder_input_data(dec, data, ts, NULL, callback, u1, u2);
}
int decoder_input_data_ptime(decoder_t *dec, const str *data, unsigned long ts, int *ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	if (!data || !data->s || !data->len)
		return 0;
	return __decoder_input_data(dec, data, ts, ptime, callback, u1, u2);
}
int decoder_dtx(decoder_t *dec, unsigned long ts, int ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	return __decoder_input_data(dec, NULL, ts, &ptime, callback, u1, u2);
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


static void avc_def_init(codec_def_t *def) {
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

void codeclib_free(void) {
	g_hash_table_destroy(codecs_ht);
	g_hash_table_destroy(codecs_ht_by_av);
	avformat_network_deinit();
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

		if (!strcmp(def->rtpname, "CN"))
			codec_def_cn = def;

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

		if (def->supplemental)
			g_queue_push_tail(&__supplemental_codecs, def);
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
		cdbg("returning in-sequence packet (seq %i)", ps->seq);
		goto out;
	}

	// why not? do we have anything? (we should)
	int nnodes = g_tree_nnodes(ps->packets);
	if (G_UNLIKELY(nnodes == 0)) {
		cdbg("packet queue empty");
		return NULL;
	}
	if (G_LIKELY(nnodes < num_wait)) {
		cdbg("only %i packets in queue - waiting for more", nnodes);
		return NULL; // need to wait for more
	}

	// packet was probably lost. search for the next highest seq
	struct tree_searcher ts = { .find_seq = ps->seq + 1, .found_seq = -1 };
	packet = g_tree_search(ps->packets, packet_tree_search, &ts);
	if (packet) {
		// bullseye
		cdbg("lost packet - returning packet with next seq %i", packet->seq);
		goto out;
	}
	if (G_UNLIKELY(ts.found_seq == -1)) {
		// didn't find anything. seq must have wrapped around. retry
		// starting from zero
		ts.find_seq = 0;
		packet = g_tree_search(ps->packets, packet_tree_search, &ts);
		if (packet) {
			cdbg("lost packet - returning packet with next seq %i (after wrap)", packet->seq);
			goto out;
		}
		if (G_UNLIKELY(ts.found_seq == -1))
			abort();
	}

	// pull out the packet we found
	packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ts.found_seq));
	if (G_UNLIKELY(packet == NULL))
		abort();

	cdbg("lost multiple packets - returning packet with next highest seq %i", packet->seq);

out:
	;
	uint16_t l = packet->seq - ps->seq;
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

int packet_sequencer_next_ok(packet_sequencer_t *ps) {
	if (g_tree_lookup(ps->packets, GINT_TO_POINTER(ps->seq)))
		return 1;
	return 0;
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
	ret->avpkt = av_packet_alloc();
	return ret;
}

static const char *avc_encoder_init(encoder_t *enc, const str *fmtp, const str *extra_opts) {
	enc->u.avc.codec = enc->def->encoder;
	if (!enc->u.avc.codec)
		return "output codec not found";

	enc->u.avc.avcctx = avcodec_alloc_context3(enc->u.avc.codec);
	if (!enc->u.avc.avcctx)
		return "failed to alloc codec context";

	enc->actual_format = enc->requested_format;

	enc->actual_format.format = -1;
	for (const enum AVSampleFormat *sfmt = enc->u.avc.codec->sample_fmts; sfmt && *sfmt != -1; sfmt++) {
		cdbg("supported sample format for output codec %s: %s",
				enc->u.avc.codec->name, av_get_sample_fmt_name(*sfmt));
		if (*sfmt == enc->requested_format.format)
			enc->actual_format.format = *sfmt;
	}
	if (enc->actual_format.format == -1 && enc->u.avc.codec->sample_fmts)
		enc->actual_format.format = enc->u.avc.codec->sample_fmts[0];
	cdbg("using output sample format %s for codec %s",
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
		enc->def->set_enc_options(enc, fmtp, extra_opts);

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
	return encoder_config_fmtp(enc, def, bitrate, ptime, requested_format, actual_format, NULL, NULL);
}

int encoder_config_fmtp(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format, const str *fmtp,
		const str *extra_opts)
{
	const char *err;

	err = "codec not supported";
	if (!def->codec_type)
		goto err;

	// anything to do?
	if (G_LIKELY(format_eq(requested_format, &enc->requested_format)))
		goto done;

	encoder_close(enc);

	if (ptime <= 0)
		ptime = 20;

	enc->requested_format = *requested_format;
	enc->def = def;
	enc->ptime = ptime / def->clockrate_mult;
	enc->bitrate = bitrate;

	err = def->codec_type->encoder_init ? def->codec_type->encoder_init(enc, fmtp, extra_opts) : 0;
	if (err)
		goto err;

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
	av_packet_free(&enc->avpkt);
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
		cdbg("send frame ret %i", av_ret);
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

	av_ret = avcodec_receive_packet(enc->u.avc.avcctx, enc->avpkt);
	cdbg("receive packet ret %i", av_ret);
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

	av_ret = avcodec_encode_audio2(enc->u.avc.avcctx, enc->avpkt, *frame, &got_packet);
	cdbg("encode frame ret %i, got packet %i", av_ret, got_packet);
	if (av_ret == 0)
		*frame = NULL; // consumed
	else
		goto err;
	if (got_packet)
		keep_going = 1;
#endif

	if (!got_packet)
		return keep_going;

	cdbg("output avpkt size is %i", (int) enc->avpkt->size);
	cdbg("output pkt pts/dts is %li/%li", (long) enc->avpkt->pts,
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

int encoder_input_data(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	enc->avpkt->size = 0;

	while (1) {
		if (!enc->def || !enc->def->codec_type)
			break;
		if (!enc->def->codec_type->encoder_input)
			break;

		int ret = enc->def->codec_type->encoder_input(enc, &frame);
		if (ret < 0)
			return -1;

		if (enc->avpkt->size) {
			// don't rely on the encoder producing steady timestamps,
			// instead keep track of them ourselves based on the returned
			// frame duration
			enc->avpkt->pts = enc->next_pts;

			if (enc->def->codec_type->encoder_got_packet)
				enc->def->codec_type->encoder_got_packet(enc);

			callback(enc, u1, u2);

			enc->next_pts += enc->avpkt->duration;
			enc->mux_dts = enc->avpkt->dts + 1; // min next expected dts

			av_packet_unref(enc->avpkt);
			enc->avpkt->size = 0;
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

		cdbg("output fifo pts %lu",(unsigned long) enc->fifo_pts);
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
		// any leftovers?
		if (pkt->size > input_output->len) {
			g_string_append_len(buf, (char *) pkt->data + input_output->len,
					pkt->size - input_output->len);
			enc->packet_pts = pkt->pts + input_output->len
				* (enc->def->bits_per_sample * enc->def->clockrate_mult / 8);
		}
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
	// adjust output pts
	enc->avpkt->pts = enc->packet_pts;
	enc->packet_pts += input_output->len * (enc->def->bits_per_sample * enc->def->clockrate_mult / 8);
	return buf->len >= input_output->len ? 1 : 0;
}


static int codeclib_set_av_opt_int(encoder_t *enc, const char *opt, int64_t val) {
	ilog(LOG_DEBUG, "Setting ffmpeg '%s' option for '%s' to %" PRId64,
			opt, enc->def->rtpname, val);

	int ret = av_opt_set_int(enc->u.avc.avcctx, opt, val, AV_OPT_SEARCH_CHILDREN);
	if (!ret)
		return 0;

	ilog(LOG_WARN, "Failed to set ffmpeg '%s' option for codec '%s' to %" PRId64 ": %s",
			opt, enc->def->rtpname, val, av_error(ret));
	return -1;
}
static int codeclib_set_av_opt_intstr(encoder_t *enc, const char *opt, str *val) {
	int i = val ? str_to_i(val, -1) : -1;
	if (i == -1) {
		ilog(LOG_WARN, "Failed to parse '" STR_FORMAT "' as integer value for ffmpeg option '%s'",
				STR_FMT0(val), opt);
		return -1;
	}
	return codeclib_set_av_opt_int(enc, opt, i);
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

static void opus_set_enc_options(encoder_t *enc, const str *fmtp, const str *codec_opts) {
	if (enc->ptime > 0)
		codeclib_set_av_opt_int(enc, "frame_duration", enc->ptime);
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

static void ilbc_set_enc_options(encoder_t *enc, const str *fmtp, const str *codec_opts) {
	int mode = ilbc_mode(enc->ptime, fmtp, "encoder");
	codeclib_set_av_opt_int(enc, "mode", mode);
}

static void ilbc_set_dec_options(decoder_t *dec, const str *fmtp, const str *codec_opts) {
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
		avc_decoder_init(dec, fmtp, NULL);
	}

	return avc_decoder_input(dec, data, out);
}


static void codeclib_key_value_parse(const str *instr, int need_value,
		void (*cb)(str *key, str *value, void *data), void *data)
{
	if (!instr || !instr->s)
		return;

	// semicolon-separated key=value
	str s = *instr;
	str key, value;
	while (str_token_sep(&value, &s, ';') == 0) {
		if (str_token(&key, &value, '=')) {
			if (need_value)
				continue;
			value = STR_NULL;
		}

		// truncate whitespace
		while (key.len && key.s[0] == ' ')
			str_shift(&key, 1);
		while (key.len && key.s[key.len - 1] == ' ')
			key.len--;
		while (value.len && value.s[0] == ' ')
			str_shift(&value, 1);
		while (value.len && value.s[value.len - 1] == ' ')
			value.len--;

		if (key.len == 0)
			continue;

		cb(&key, &value, data);
	}

}





static const unsigned int amr_bitrates[AMR_FT_TYPES] = {
	4750, // 0
	5150, // 1
	5900, // 2
	6700, // 3
	7400, // 4
	7950, // 5
	10200, // 6
	12200, // 7
	0, // comfort noise // 8
	0, // comfort noise // 9
	0, // comfort noise // 10
	0, // comfort noise // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_bits_per_frame[AMR_FT_TYPES] = {
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
static const unsigned int amr_wb_bitrates[AMR_FT_TYPES] = {
	6600, // 0
	8850, // 1
	12650, // 2
	14250, // 3
	15850, // 4
	18250, // 5
	19850, // 6
	23050, // 7
	23850, // 8
	0, // comfort noise // 9
	0, // invalid // 10
	0, // invalid // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_wb_bits_per_frame[AMR_FT_TYPES] = {
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
static void amr_set_encdec_options_cb(str *key, str *token, void *data) {
	codec_options_t *opts = data;

	if (!str_cmp(key, "octet-align")) {
		if (token->len == 1 && token->s[0] == '1')
			opts->amr.octet_aligned = 1;
	}
	else if (!str_cmp(key, "crc")) {
		if (token->len == 1 && token->s[0] == '1') {
			opts->amr.octet_aligned = 1;
			opts->amr.crc = 1;
		}
	}
	else if (!str_cmp(key, "robust-sorting")) {
		if (token->len == 1 && token->s[0] == '1') {
			opts->amr.octet_aligned = 1;
			opts->amr.robust_sorting = 1;
		}
	}
	else if (!str_cmp(key, "interleaving")) {
		opts->amr.octet_aligned = 1;
		opts->amr.interleaving = str_to_i(token, 0);
	}
	else if (!str_cmp(key, "mode-set")) {
		str mode;
		while (str_token_sep(&mode, token, ',') == 0) {
			int m = str_to_i(&mode, -1);
			if (m < 0 || m >= AMR_FT_TYPES)
				continue;
			opts->amr.mode_set |= (1 << m);
		}
	}
	else if (!str_cmp(key, "mode-change-period"))
		opts->amr.mode_change_period = str_to_i(token, 0);
	else if (!str_cmp(key, "mode-change-neighbor")) {
		if (token->len == 1 && token->s[0] == '1')
			opts->amr.mode_change_neighbor = 1;
	}
}
static void amr_set_encdec_options(codec_options_t *opts, const str *fmtp, const codec_def_t *def) {
	if (!strcmp(def->rtpname, "AMR")) {
		opts->amr.bits_per_frame = amr_bits_per_frame;
		opts->amr.bitrates = amr_bitrates;
	}
	else {
		opts->amr.bits_per_frame = amr_wb_bits_per_frame;
		opts->amr.bitrates = amr_wb_bitrates;
	}

	codeclib_key_value_parse(fmtp, 1, amr_set_encdec_options_cb, opts);
}
static void amr_set_dec_codec_options(str *key, str *value, void *data) {
	decoder_t *dec = data;

	if (!str_cmp(key, "CMR-interval"))
		dec->codec_options.amr.cmr_interval = str_to_i(value, 0);
	else if (!str_cmp(key, "mode-change-interval"))
		dec->codec_options.amr.mode_change_interval = str_to_i(value, 0);

}
static void amr_set_enc_codec_options(str *key, str *value, void *data) {
	encoder_t *enc = data;

	if (!str_cmp(key, "CMR-interval"))
		; // not an encoder option
	else if (!str_cmp(key, "mode-change-interval"))
		; // not an encoder option
	else {
		// our string might not be null terminated
		char *s = g_strdup_printf(STR_FORMAT, STR_FMT(key));
		codeclib_set_av_opt_intstr(enc, s, value);
		g_free(s);
	}
}
static void amr_set_enc_options(encoder_t *enc, const str *fmtp, const str *codec_opts) {
	amr_set_encdec_options(&enc->codec_options, fmtp, enc->def);

	codeclib_key_value_parse(codec_opts, 1, amr_set_enc_codec_options, enc);

	// if a mode-set was given, pick the highest supported bitrate
	if (enc->codec_options.amr.mode_set) {
		int max_bitrate = enc->u.avc.avcctx->bit_rate;
		int use_bitrate = 0;
		for (int i = 0; i < AMR_FT_TYPES; i++) {
			if (!(enc->codec_options.amr.mode_set & (1 << i)))
				continue;
			unsigned int br = enc->codec_options.amr.bitrates[i];
			// we depend on the list being in ascending order, with
			// invalid modes at the end
			if (!br) // end of list
				break;
			if (br > max_bitrate && use_bitrate) // done
				break;
			use_bitrate = br;
		}
		if (!use_bitrate)
			ilog(LOG_WARN, "Unable to determine a valid bitrate from %s mode-set, using default",
					enc->def->rtpname);
		else {
			ilog(LOG_DEBUG, "Using %i as initial %s bitrate based on mode-set",
					use_bitrate, enc->def->rtpname);
			enc->u.avc.avcctx->bit_rate = use_bitrate;
		}
	}
}
static void amr_set_dec_options(decoder_t *dec, const str *fmtp, const str *codec_opts) {
	amr_set_encdec_options(&dec->codec_options, fmtp, dec->def);
	codeclib_key_value_parse(codec_opts, 1, amr_set_dec_codec_options, dec);
}

static void amr_bitrate_tracker(decoder_t *dec, unsigned int ft) {
	if (dec->codec_options.amr.cmr_interval <= 0)
		return;

	if (dec->u.avc.u.amr.tracker_end.tv_sec
			&& timeval_cmp(&dec->u.avc.u.amr.tracker_end, &rtpe_now) >= 0) {
		// analyse the data we gathered
		int next_highest = -1;
		int lowest_used = -1;
		for (int i = 0; i < AMR_FT_TYPES; i++) {
			unsigned int br = dec->codec_options.amr.bitrates[i];
			if (!br)
				break; // end of list

			// ignore restricted modes
			if (dec->codec_options.amr.mode_set) {
				if (!(dec->codec_options.amr.mode_set & (1 << i)))
					continue;
			}

			// would this be a "next step up" mode?
			if (next_highest == -1)
				next_highest = i;

			// did we see any frames?
			if (!dec->u.avc.u.amr.bitrate_tracker[i])
				continue;

			next_highest = -1;
			lowest_used = i;
		}

		if (lowest_used != -1 && next_highest != -1) {
			// we can request a switch up
			ilog(LOG_DEBUG, "Sending %s CMR to request upping bitrate to %u",
					dec->def->rtpname, dec->codec_options.amr.bitrates[next_highest]);
			decoder_event(dec, CE_AMR_SEND_CMR, GINT_TO_POINTER(next_highest));
		}

		// and reset tracker
		ZERO(dec->u.avc.u.amr.tracker_end);
	}

	if (!dec->u.avc.u.amr.tracker_end.tv_sec) {
		// init
		ZERO(dec->u.avc.u.amr.bitrate_tracker);
		dec->u.avc.u.amr.tracker_end = rtpe_now;
		timeval_add_usec(&dec->u.avc.u.amr.tracker_end, dec->codec_options.amr.cmr_interval * 1000);
	}

	dec->u.avc.u.amr.bitrate_tracker[ft]++;
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

	unsigned int cmr_int = cmr_chr[0] >> 4;
	if (cmr_int != 15) {
		decoder_event(dec, CE_AMR_CMR_RECV, GUINT_TO_POINTER(cmr_int));
		dec->u.avc.u.amr.last_cmr = rtpe_now;
	}
	else if (dec->codec_options.amr.mode_change_interval) {
		// no CMR, check if we're due to do our own mode change
		if (!dec->u.avc.u.amr.last_cmr.tv_sec) // start tracking now
			dec->u.avc.u.amr.last_cmr = rtpe_now;
		else if (timeval_diff(&rtpe_now, &dec->u.avc.u.amr.last_cmr)
				>= (long long) dec->codec_options.amr.mode_change_interval * 1000) {
			// switch up if we can
			decoder_event(dec, CE_AMR_CMR_RECV, GUINT_TO_POINTER(0xffff));
			dec->u.avc.u.amr.last_cmr = rtpe_now;
		}
	}

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

		// AMR decoder expects an octet aligned TOC byte plus the payload
		unsigned char frame_buf[(bits + 7) / 8 + 1 + 1];
		str frame = STR_CONST_INIT_BUF(frame_buf);
		str_shift(&frame, 1);
		err = "short frame";
		if (bitstr_shift_ret(&d, bits, &frame))
			goto err;

		// add TOC byte
		str_unshift(&frame, 1);
		frame.s[0] = toc_byte & 0x7c; // strip F bit, keep FT and Q, zero padding (01111100)

		if (dec->codec_options.amr.octet_aligned && (bits % 8) != 0) {
			unsigned int padding_bits = 8 - (bits % 8);
			if (bitstr_shift(&d, padding_bits))
				goto err;
		}

		err = "failed to decode AMR data";
		if (bits == 40) {
			// SID
			if (dec->dtx.method_id == DTX_NATIVE) {
				if (avc_decoder_input(dec, &frame, out))
					goto err;
			}
			else {
				// use the DTX generator to replace SID
				if (dec->dtx.do_dtx(dec, out, 20))
					goto err;
			}
		}
		else {
			if (avc_decoder_input(dec, &frame, out))
				goto err;
		}

		amr_bitrate_tracker(dec, ft);
	}

	return 0;

err:
	if (err)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error unpacking AMR packet: %s", err);

	return -1;
}
static unsigned int amr_encoder_find_next_mode(encoder_t *enc) {
	int mode = -1;
	for (int i = 0; i < AMR_FT_TYPES; i++) {
		int br = enc->codec_options.amr.bitrates[i];
		if (!br) // end of list
			break;
		if (br == enc->u.avc.avcctx->bit_rate) {
			mode = i;
			break;
		}
	}
	if (mode == -1)
		return -1;
	int next_mode = mode + 1;
	// if modes are restricted, find the next one up
	if (enc->codec_options.amr.mode_set) {
		// is there anything?
		if ((1 << next_mode) > enc->codec_options.amr.mode_set)
			return -1;
		int next_up = -1;
		for (; next_mode < AMR_FT_TYPES; next_mode++) {
			if (!(enc->codec_options.amr.mode_set & (1 << next_mode)))
				continue;
			next_up = next_mode;
			break;
		}
		if (next_up == -1)
			return -1;
		next_mode = next_up;
	}
	// valid mode?
	if (next_mode >= AMR_FT_TYPES || enc->codec_options.amr.bitrates[next_mode] == 0)
		return -1;
	return next_mode;
}
static void amr_encoder_mode_change(encoder_t *enc) {
	if (!memcmp(&enc->codec_options.amr.cmr.cmr_in_ts,
				&enc->u.avc.u.amr.cmr_in_ts, sizeof(struct timeval)))
		return;
	// mode change requested: check if this is allowed right now
	if (enc->codec_options.amr.mode_change_period == 2 && (enc->u.avc.u.amr.pkt_seq & 1) != 0)
		return;
	unsigned int cmr = enc->codec_options.amr.cmr.cmr_in;
	if (cmr == 0xffff)
		cmr = amr_encoder_find_next_mode(enc);
	if (cmr >= AMR_FT_TYPES)
		return;
	// ignore CMR for invalid modes
	if (enc->codec_options.amr.mode_set && !(enc->codec_options.amr.mode_set & (1 << cmr)))
		return;
	int req_br = enc->codec_options.amr.bitrates[cmr];
	if (!req_br)
		return;
	int cmr_done = 1;
	if (enc->codec_options.amr.mode_change_neighbor) {
		// handle non-neighbour mode changes
		int cur_br = enc->u.avc.avcctx->bit_rate;
		// step up or down from the requested bitrate towards the current one
		int cmr_diff = (req_br > cur_br) ? -1 : 1;
		int neigh_br = req_br;
		int cmr_br = req_br;
		while (1) {
			// step up or down towards the current bitrate
			cmr += cmr_diff;
			// still in bounds?
			if (cmr >= AMR_FT_TYPES)
				break;
			cmr_br = enc->codec_options.amr.bitrates[cmr];
			if (cmr_br == cur_br)
				break;
			// allowed by mode set?
			if (enc->codec_options.amr.mode_set) {
				if (!(enc->codec_options.amr.mode_set & (1 << cmr)))
					continue; // go to next mode
			}
			// valid bitrate - continue stepping
			neigh_br = cmr_br;
		}
		// did we finish stepping or is there more to go?
		if (neigh_br != req_br)
			cmr_done = 0;
		req_br = neigh_br; // set to this
	}
	enc->u.avc.avcctx->bit_rate = req_br;
	if (cmr_done)
		enc->u.avc.u.amr.cmr_in_ts = enc->codec_options.amr.cmr.cmr_in_ts;
}
static void amr_encoder_got_packet(encoder_t *enc) {
	amr_encoder_mode_change(enc);
	enc->u.avc.u.amr.pkt_seq++;
}
static int packetizer_amr(AVPacket *pkt, GString *buf, str *output, encoder_t *enc) {
	assert(pkt->size >= 1);

	// CMR + TOC byte (already included) + optional ILL/ILP + optional CRC + payload
	assert(output->len >= pkt->size + 3);

	unsigned char toc = pkt->data[0];
	unsigned char ft = (toc >> 3) & 0xf;
	if (ft > 15) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received bogus AMR FT %u from encoder", ft);
		return -1;
	}
	if (ft >= 14) {
		// NO_DATA or SPEECH_LOST
		return -1;
	}
	assert(ft < AMR_FT_TYPES); // internal bug
	unsigned int bits = enc->codec_options.amr.bits_per_frame[ft];
	if (bits == 0) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received bogus AMR FT %u from encoder", ft);
		return -1;
	}

	unsigned char *s = (unsigned char *) output->s; // for safe bit shifting

	s[0] = '\xf0'; // no CMR req (4 bits)

	// or do we have a CMR?
	if (!enc->u.avc.u.amr.cmr_out_seq) {
		if (memcmp(&enc->u.avc.u.amr.cmr_out_ts, &enc->codec_options.amr.cmr.cmr_out_ts,
					sizeof(struct timeval))) {
			enc->u.avc.u.amr.cmr_out_seq += 3; // make this configurable?
			enc->u.avc.u.amr.cmr_out_ts = enc->codec_options.amr.cmr.cmr_out_ts;
		}
	}
	if (enc->u.avc.u.amr.cmr_out_seq) {
		enc->u.avc.u.amr.cmr_out_seq--;
		unsigned int cmr = enc->codec_options.amr.cmr.cmr_out;
		if (cmr < AMR_FT_TYPES && enc->codec_options.amr.bitrates[cmr])
			s[0] = cmr << 4;
	}

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
static int amr_dtx(decoder_t *dec, GQueue *out, int ptime) {
	// ignore ptime, must be 20
	ilog(LOG_DEBUG, "pushing empty/lost frame to AMR decoder");
	unsigned char frame_buf[1];
	frame_buf[0] = 0xf << 3; // no data
	str frame = STR_CONST_INIT_BUF(frame_buf);
	if (avc_decoder_input(dec, &frame, out))
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error while writing 'no data' frame to AMR decoder");
	return 0;
}



static int generic_silence_dtx(decoder_t *dec, GQueue *out, int ptime) {
	if (dec->dec_out_format.format == -1)
		return -1;

	if (ptime <= 0)
		ptime = 20;
	int num_samples = ptime * dec->in_format.clockrate / 1000;
	ilog(LOG_DEBUG, "pushing %i silence samples into %s decoder", num_samples, dec->def->rtpname);

	// create dummy frame, fill with silence, pretend it was returned from the decoder
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = num_samples;
	frame->format = dec->dec_out_format.format;
	frame->sample_rate = dec->dec_out_format.clockrate;
	frame->channel_layout = av_get_default_channel_layout(dec->dec_out_format.channels);
	if (av_frame_get_buffer(frame, 0) < 0) {
		av_frame_free(&frame);
		return -1;
	}

	memset(frame->extended_data[0], 0, frame->linesize[0]);

	// advance PTS
	frame->pts = dec->u.avc.avpkt->pts;
	dec->u.avc.avpkt->pts += frame->nb_samples;

	g_queue_push_tail(out, frame);

	return 0;
}


static int cn_append_frame(decoder_t *dec, AVFrame *f, void *u1, void *u2) {
	GQueue *out = u1;
	g_queue_push_tail(out, f);
	return 0;
}

static int generic_cn_dtx(decoder_t *dec, GQueue *out, int ptime) {
	dec->dtx.u.cn.cn_dec->ptime = ptime;
	return decoder_input_data(dec->dtx.u.cn.cn_dec, dec->dtx.u.cn.cn_payload,
			dec->rtp_ts, cn_append_frame, out, NULL);
}

static int generic_cn_dtx_init(decoder_t *dec) {
	dec->dtx.u.cn.cn_dec = decoder_new_fmt(codec_def_cn, 8000, 1, dec->ptime, &dec->dest_format);
	return 0;
}

static void generic_cn_dtx_cleanup(decoder_t *dec) {
	decoder_close(dec->dtx.u.cn.cn_dec);
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

static const char *bcg729_decoder_init(decoder_t *dec, const str *fmtp, const str *extra_opts) {
	dec->u.bcg729 = initBcg729DecoderChannel();
	if (!dec->u.bcg729)
		return "failed to initialize bcg729";
	return NULL;
}

static int bcg729_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	str input = *data;
	uint64_t pts = dec->pts;

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

static const char *bcg729_encoder_init(encoder_t *enc, const str *fmtp, const str *extra_opts) {
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

	av_new_packet(enc->avpkt, 10);
	unsigned char len = 0;

	bcg729Encoder(enc->u.bcg729, (void *) (*frame)->extended_data[0], enc->avpkt->data, &len);
	if (!len) {
		av_packet_unref(enc->avpkt);
		return 0;
	}

	enc->avpkt->size = len;
	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = len * 8; // Duration is used by encoder_input_data for pts calculation

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


static const char *dtmf_decoder_init(decoder_t *dec, const str *fmtp, const str *extra_opts) {
	dec->u.dtmf.event = -1;
	return NULL;
}

static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	struct telephone_event_payload *dtmf;
	if (data->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %zu)", data->len);
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



static int format_cmp_ignore(const struct rtp_payload_type *a, const struct rtp_payload_type *b) {
	return 0;
}



static const char *cn_decoder_init(decoder_t *dec, const str *fmtp, const str *opts) {
	// the ffmpeg cngdec always runs at 8000
	dec->in_format.clockrate = 8000;
	dec->in_format.channels = 1;
	dec->resampler.no_filter = true;
	return avc_decoder_init(dec, fmtp, opts);
}
static int cn_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	// generate one set of ptime worth of samples
	int ptime = dec->ptime;
	if (ptime <= 0)
		ptime = 20; // ?
	int samples = dec->in_format.clockrate * ptime / 1000;
	dec->u.avc.avcctx->frame_size = samples;
	int ret = avc_decoder_input(dec, data, out);
	if (ret)
		return ret;
	if (!out->length)
		return -1;
	return 0;
}
