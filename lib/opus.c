#include "codecmod.h"
#include <opus.h>
#include "loglib.h"
#include "fix_frame_channel_layout.compat"



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

static const char *libopus_decoder_init(decoder_t *dec, const str *extra_opts) {
	if (dec->in_format.channels != 1 && dec->in_format.channels != 2)
		return "invalid number of channels";
	switch (dec->in_format.clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			break;
		default:
			return "invalid clock rate";
	}

	int err = 0;
	dec->opus = opus_decoder_create(dec->in_format.clockrate, dec->in_format.channels, &err);
	if (!dec->opus) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error from libopus: %s", opus_strerror(err));
		return "failed to alloc codec context";
	}

	return NULL;
}
static void libopus_decoder_close(decoder_t *dec) {
	opus_decoder_destroy(dec->opus);
}
static int libopus_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	// get frame with buffer large enough for the max
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = 960;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = dec->in_format.clockrate;
	DEF_CH_LAYOUT(&frame->CH_LAYOUT, dec->in_format.channels);
	frame->pts = dec->pts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	int ret = opus_decode(dec->opus, (unsigned char *) data->s, data->len,
			(int16_t *) frame->extended_data[0], frame->nb_samples, 0);
	if (ret < 0) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error decoding Opus packet: %s", opus_strerror(ret));
		av_frame_free(&frame);
		return -1;
	}

	frame->nb_samples = ret;
	g_queue_push_tail(out, frame);
	return 0;
}

struct libopus_encoder_options {
	int complexity;
	int vbr;
	int vbr_constraint;
	int pl;
	int application;
};
static void libopus_set_enc_opts(str *key, str *val, void *p) {
	struct libopus_encoder_options *opts = p;

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("complexity"):
		case CSH_LOOKUP("compression_level"):
			opts->complexity = str_to_i(val, -1);
			break;
		case CSH_LOOKUP("application"):
			switch (__csh_lookup(val)) {
				case CSH_LOOKUP("VOIP"):
				case CSH_LOOKUP("VoIP"):
				case CSH_LOOKUP("voip"):
					opts->application = OPUS_APPLICATION_VOIP;
					break;
				case CSH_LOOKUP("audio"):
					opts->application = OPUS_APPLICATION_AUDIO;
					break;
				case CSH_LOOKUP("low-delay"):
				case CSH_LOOKUP("low delay"):
				case CSH_LOOKUP("lowdelay"):
					opts->application = OPUS_APPLICATION_RESTRICTED_LOWDELAY;
					break;
				default:
					ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unknown Opus application: '"
							STR_FORMAT "'", STR_FMT(val));
			};
			break;
		case CSH_LOOKUP("vbr"):
		case CSH_LOOKUP("VBR"):
			// aligned with ffmpeg vbr=0/1/2 option
			opts->vbr = str_to_i(val, -1);
			if (opts->vbr == 2) {
				opts->vbr = 1;
				opts->vbr_constraint = 1;
			}
			break;
		case CSH_LOOKUP("packet_loss"):
		case CSH_LOOKUP("packet loss"):
			opts->pl = str_to_i(val, -1);
			break;
		default:
			ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unknown Opus encoder option encountered: '"
					STR_FORMAT "'", STR_FMT(key));
	}
}
static const char *libopus_encoder_init(encoder_t *enc, const str *extra_opts) {
	if (enc->requested_format.channels != 1 && enc->requested_format.channels != 2)
		return "invalid number of channels";

	if (enc->requested_format.format == -1)
		enc->requested_format.format = AV_SAMPLE_FMT_S16;
	else if (enc->requested_format.format != AV_SAMPLE_FMT_S16)
		return "invalid sample format";

	switch (enc->requested_format.clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			break;
		default:
			return "invalid clock rate";
	}

	struct libopus_encoder_options opts = { .vbr = 1, .complexity = 10, .application = OPUS_APPLICATION_VOIP };
	codeclib_key_value_parse(extra_opts, true, libopus_set_enc_opts, &opts);

	int err;
	enc->opus = opus_encoder_create(enc->requested_format.clockrate, enc->requested_format.channels,
			opts.application, &err);
	if (!enc->opus) {
		ilog(LOG_ERR, "Error from libopus: %s", opus_strerror(err));
		return "failed to alloc codec context";
	}

	enc->actual_format = enc->requested_format;

	enc->samples_per_frame = enc->actual_format.clockrate * enc->ptime / 1000;
	enc->samples_per_packet = enc->samples_per_frame;

	err = opus_encoder_ctl(enc->opus, OPUS_SET_BITRATE(enc->bitrate));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus bitrate to %i: %s", enc->bitrate,
				opus_strerror(err));

	err = opus_encoder_ctl(enc->opus, OPUS_SET_COMPLEXITY(opts.complexity));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus complexity to %i': %s",
				opts.complexity, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_VBR(opts.vbr));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus VBR to %i': %s",
				opts.vbr, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_VBR_CONSTRAINT(opts.vbr_constraint));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus VBR constraint to %i': %s",
				opts.vbr_constraint, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_PACKET_LOSS_PERC(opts.pl));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus PL%% to %i': %s",
				opts.pl, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_INBAND_FEC(enc->format_options.opus.fec_send >= 0));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus FEC to %i': %s",
				enc->format_options.opus.fec_send >= 0, opus_strerror(err));

	return NULL;
}
static void libopus_encoder_close(encoder_t *enc) {
	opus_encoder_destroy(enc->opus);
}
#define MAX_OPUS_FRAME_SIZE 1275 /* 20 ms at 510 kbps */
#define MAX_OPUS_FRAMES_PER_PACKET 6 /* 120 ms = 6 * 20 ms */
#define MAX_OPUS_HEADER_SIZE 7
static int libopus_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	// max length of Opus packet:
	av_new_packet(enc->avpkt, MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE);

	int ret = opus_encode(enc->opus, (int16_t *) (*frame)->extended_data[0], (*frame)->nb_samples,
			enc->avpkt->data, enc->avpkt->size);
	if (ret < 0) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error encoding Opus packet: %s", opus_strerror(ret));
		av_packet_unref(enc->avpkt);
		return -1;
	}

	enc->avpkt->size = ret;
	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = (*frame)->nb_samples;

	return 0;
}






// opus RTP always runs at 48 kHz
static void opus_select_encoder_format(encoder_t *enc, format_t *req_format, const format_t *f,
		const struct rtp_codec_format *fmtp)
{
	if (req_format->clockrate != 48000)
		return; // bail - encoder will fail to initialise

	// check against natively supported rates first
	switch (f->clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			enc->clockrate_fact = (struct fraction) {1, 48000 / f->clockrate};
			break;
		default:
			// resample to next best rate
			if (f->clockrate > 24000)
				enc->clockrate_fact = (struct fraction) {1,1};
			else if (f->clockrate > 16000)
				enc->clockrate_fact = (struct fraction) {1,2};
			else if (f->clockrate > 12000)
				enc->clockrate_fact = (struct fraction) {1,3};
			else if (f->clockrate > 8000)
				enc->clockrate_fact = (struct fraction) {1,4};
			else
				enc->clockrate_fact = (struct fraction) {1,6};
			break;
	}

	// honour remote stereo=0/1 flag if given,
	// otherwise go with the input format
	if (fmtp && fmtp->parsed.opus.stereo_send == -1)
		req_format->channels = 1;
	else if (fmtp && fmtp->parsed.opus.stereo_send == 1)
		req_format->channels = 2;
	else if (req_format->channels == 2 && f->channels == 1)
		req_format->channels = 1;
}
static void opus_select_decoder_format(decoder_t *dec, const struct rtp_codec_format *fmtp) {
	if (dec->in_format.clockrate != 48000)
		return;

	// check against natively supported rates first
	switch (dec->dest_format.clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			dec->clockrate_fact = (struct fraction) {1, 48000 / dec->dest_format.clockrate};
			break;
		default:
			// resample to next best rate
			if (dec->dest_format.clockrate > 24000)
				dec->clockrate_fact = (struct fraction) {1,1};
			else if (dec->dest_format.clockrate > 16000)
				dec->clockrate_fact = (struct fraction) {1,2};
			else if (dec->dest_format.clockrate > 12000)
				dec->clockrate_fact = (struct fraction) {1,3};
			else if (dec->dest_format.clockrate > 8000)
				dec->clockrate_fact = (struct fraction) {1,4};
			else
				dec->clockrate_fact = (struct fraction) {1,6};
			break;
	}

	// switch to mono decoding if possible
	if (dec->in_format.channels == 2 && dec->dest_format.channels == 1)
		dec->in_format.channels = 1;
}
static void opus_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;
	__auto_type o = &opts->opus;

	switch (__csh_lookup(key)) {
#define YNFLAG(flag, varname) \
		case flag: \
			if (token->len == 1 && token->s[0] == '1') \
				o->varname = 1; \
			else if (token->len == 1 && token->s[0] == '0') \
				o->varname = -1; \
			break;
		YNFLAG(CSH_LOOKUP("stereo"), stereo_recv)
		YNFLAG(CSH_LOOKUP("sprop-stereo"), stereo_send)
		YNFLAG(CSH_LOOKUP("useinbandfec"), fec_recv)
		YNFLAG(CSH_LOOKUP("cbr"), cbr)
		YNFLAG(CSH_LOOKUP("usedtx"), usedtx)
#undef YNFLAG
		case CSH_LOOKUP("maxplaybackrate"):
			opts->opus.maxplaybackrate = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("sprop-maxcapturerate"):
			opts->opus.sprop_maxcapturerate = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("maxaveragebitrate"):
			opts->opus.maxaveragebitrate = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("minptime"):
			opts->opus.minptime = str_to_i(token, 0);
			break;
	}
}
static bool opus_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	codeclib_key_value_parse(fmtp, true, opus_parse_format_cb, &f->parsed);
	return true;
}
static GString *opus_format_print(const struct rtp_payload_type *p) {
	if (!p->format.fmtp_parsed)
		return NULL;

	GString *s = g_string_new("");
	__auto_type f = &p->format.parsed.opus;

	if (f->stereo_recv)
		g_string_append_printf(s, "stereo=%i; ", f->stereo_recv == -1 ? 0 : 1);
	if (f->stereo_send)
		g_string_append_printf(s, "sprop-stereo=%i; ", f->stereo_send == -1 ? 0 : 1);
	if (f->fec_recv)
		g_string_append_printf(s, "useinbandfec=%i; ", f->fec_recv == -1 ? 0 : 1);
	if (f->usedtx)
		g_string_append_printf(s, "usedtx=%i; ", f->usedtx == -1 ? 0 : 1);
	if (f->cbr)
		g_string_append_printf(s, "cbr=%i; ", f->cbr == -1 ? 0 : 1);
	if (f->maxplaybackrate)
		g_string_append_printf(s, "maxplaybackrate=%i; ", f->maxplaybackrate);
	if (f->maxaveragebitrate)
		g_string_append_printf(s, "maxaveragebitrate=%i; ", f->maxaveragebitrate);
	if (f->sprop_maxcapturerate)
		g_string_append_printf(s, "sprop-maxcapturerate=%i; ", f->sprop_maxcapturerate);
	if (f->minptime)
		g_string_append_printf(s, "minptime=%i; ", f->minptime);

	if (s->len != 0)
		g_string_truncate(s, s->len - 2);

	return s;
}
static void opus_format_answer(struct rtp_payload_type *p, const struct rtp_payload_type *src) {
	if (!p->format.fmtp_parsed)
		return;

	__auto_type f = &p->format.parsed.opus;

	// swap send/recv

	int t = f->stereo_send;
	f->stereo_send = f->stereo_recv;
	f->stereo_recv = t;

	t = f->fec_send;
	f->fec_send = f->fec_recv;
	f->fec_recv = t;

	// if stereo recv is unset, base it on input format
	if (f->stereo_recv == 0)
		f->stereo_recv = src->channels == 1 ? -1 : 1;

	// we can always use FEC, unless we've been told that we should lie
	if (f->fec_recv == 0)
		f->fec_recv = 1;

	// set everything unsupported to 0
	f->usedtx = 0;
	f->cbr = 0;
	f->maxplaybackrate = 0;
	f->sprop_maxcapturerate = 0;
	f->maxaveragebitrate = 0;
	f->minptime = 0;
}




static const codec_type_t codec_type_libopus = {
	.decoder_init = libopus_decoder_init,
	.decoder_input = libopus_decoder_input,
	.decoder_close = libopus_decoder_close,
	.encoder_init = libopus_encoder_init,
	.encoder_input = libopus_encoder_input,
	.encoder_close = libopus_encoder_close,
};


static const codec_def_t opus = {
	.rtpname = "opus",
	.avcodec_id = -1,
	.default_clockrate = 48000,
	.default_channels = 2,
	.default_bitrate = 32000,
	.default_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_libopus,
	.init = opus_init,
	.default_fmtp = "useinbandfec=1",
	.format_parse = opus_format_parse,
	.format_print = opus_format_print,
	.format_cmp = format_cmp_ignore,
	.format_answer = opus_format_answer,
	.select_encoder_format = opus_select_encoder_format,
	.select_decoder_format = opus_select_decoder_format,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.support_encoding = 1,
	.support_decoding = 1,
};

__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&opus);
}
