#include "codecmod.h"
#include "loglib.h"


static bool ilbc_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	if (!fmtp || !fmtp->len)
		return false;
	switch (__csh_lookup(fmtp)) {
		case CSH_LOOKUP("mode=20"):
			f->parsed.ilbc.mode = 20;
			break;
		case CSH_LOOKUP("mode=30"):
			f->parsed.ilbc.mode = 30;
			break;
		default:
			return false;
	}
	return true;
}

static int ilbc_mode(int ptime, const union codec_format_options *fmtp, const char *direction) {
	int mode = 0;
	if (fmtp)
		mode = fmtp->ilbc.mode;

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

static void ilbc_set_enc_options(encoder_t *enc, const str *codec_opts) {
	int mode = ilbc_mode(enc->ptime, &enc->format_options, "encoder");
	codeclib_set_av_opt_int(enc, "mode", mode);
}

static void ilbc_set_dec_options(decoder_t *dec, const str *codec_opts) {
	int mode = ilbc_mode(dec->ptime, &dec->format_options, "decoder");
	if (mode == 20)
		dec->avc.avcctx->block_align = 38;
	else if (mode == 30)
		dec->avc.avcctx->block_align = 50;
	else
		ilog(LOG_WARN, "Unsupported iLBC mode %i", mode);
}

static int ilbc_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	int mode = 0, block_align = 0;
	static const union codec_format_options mode_20 = { .ilbc = { 20 } };
	static const union codec_format_options mode_30 = { .ilbc = { 30 } };
	const union codec_format_options *fmtp;

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

	if (block_align && dec->avc.avcctx->block_align != block_align) {
		ilog(LOG_INFO | LOG_FLAG_LIMIT, "iLBC decoder set to %i bytes blocks, but received packet "
				"of %i bytes, therefore resetting decoder and switching to %i bytes "
				"block mode (%i ms mode)",
				(int) dec->avc.avcctx->block_align, (int) data->len, block_align, mode);
		avc_decoder_close(dec);
		dec->format_options = *fmtp;
		avc_decoder_init(dec, NULL);
	}

	return avc_decoder_input(dec, data, out);
}


static const codec_type_t codec_type_ilbc = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = ilbc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};


static const codec_def_t ilbc = {
	.rtpname = "iLBC",
	.avcodec_id = AV_CODEC_ID_ILBC,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 30,
	.default_fmtp = "mode=30",
	.format_parse = ilbc_format_parse,
	//.default_bitrate = 15200,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_ilbc,
	.set_enc_options = ilbc_set_enc_options,
	.set_dec_options = ilbc_set_dec_options,
};

__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&ilbc);
}
