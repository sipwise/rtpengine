#include "codecmod.h"
#include "loglib.h"

// Codec 2 (https://www.rowetel.com/?page_id=452) through libcodec2.
//
// There is no RFC payload format for Codec 2. This follows what Asterisk does: encoding
// name "codec2" with an 8 kHz clock, and the payload of each RTP packet is one or more
// complete Codec 2 frames back to back, each padded to whole bytes as produced by
// libcodec2. The bit rate (Codec 2 "mode") is selected through the optional format
// parameter "mode=" (3200, 2400, 1600, 1400, 1300, 1200 or 700C). Without it, mode 2400
// is assumed, which is the only mode Asterisk supports.

#define CODEC2_DEFAULT_MODE 2400


// modes are identified by their bit rate (700 for 700C); returns -1 if there is no such mode
static int codec2_mode_from_int(int br) {
	switch (br) {
		case 3200:
		case 2400:
		case 1600:
		case 1400:
		case 1300:
		case 1200:
		case 700:
			return br;
	}
	return -1;
}

// returns the mode for a "mode=" value, or -1 if unknown
static int codec2_mode_from_str(const str *s) {
	if (!str_cmp(s, "700C") || !str_cmp(s, "700c"))
		return 700;
	return codec2_mode_from_int(str_to_i(s, -1));
}

static const char *codec2_mode_name(int mode) {
	switch (mode) {
		case 3200:
			return "3200";
		case 2400:
			return "2400";
		case 1600:
			return "1600";
		case 1400:
			return "1400";
		case 1300:
			return "1300";
		case 1200:
			return "1200";
		case 700:
			return "700C";
	}
	return NULL;
}

static const char *codec2_mode_fmtp(int mode) {
	switch (mode) {
		case 3200:
			return "mode=3200";
		case 2400:
			return "mode=2400";
		case 1600:
			return "mode=1600";
		case 1400:
			return "mode=1400";
		case 1300:
			return "mode=1300";
		case 1200:
			return "mode=1200";
		case 700:
			return "mode=700C";
	}
	return NULL;
}

static void codec2_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;

	if (str_cmp(key, "mode"))
		return;

	int mode = codec2_mode_from_str(token);
	if (mode < 0) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unsupported Codec 2 mode '" STR_FORMAT "'",
				STR_FMT(token));
		opts->codec2.mode = -1;
		return;
	}
	opts->codec2.mode = mode;
}

static bool codec2_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	codeclib_key_value_parse(fmtp, codec2_parse_format_cb, &f->parsed);
	return true;
}

// absent "mode=" means the default mode
static int codec2_effective_mode(const struct rtp_payload_type *p) {
	if (!p->format.fmtp_parsed)
		return CODEC2_DEFAULT_MODE;
	return p->format.parsed.codec2.mode ?: CODEC2_DEFAULT_MODE;
}

static int codec2_format_cmp(const struct rtp_payload_type *A, const struct rtp_payload_type *B) {
	// different modes are different bit streams
	int a = codec2_effective_mode(A);
	int b = codec2_effective_mode(B);
	if (a < 0 || b < 0) {
		// a mode we don't know (e.g. 450): can still be passed through if both
		// sides use the very same format parameters
		if (a != b || str_cmp_str(&A->format_parameters, &B->format_parameters))
			return -1;
		return 0;
	}
	if (a != b)
		return -1;
	return 0;
}

static GString *codec2_format_print(const struct rtp_payload_type *p) {
	if (!p->format.fmtp_parsed)
		return NULL;
	if (p->format.parsed.codec2.mode < 0)
		return NULL; // unknown mode: pass the original fmtp through

	GString *s = g_string_new("");
	const char *fmtp = codec2_mode_fmtp(p->format.parsed.codec2.mode);
	if (fmtp)
		g_string_append(s, fmtp);

	return s;
}


static void codec2_init(struct rtp_payload_type *pt) {
	if (pt->clock_rate != 8000) {
		ilog(LOG_WARN, "Codec 2 is only supported with a clock rate of 8000 Hz");
		pt->clock_rate = 8000;
	}

	// a bit rate given in the codec string (e.g. "codec2/8000/1/3200") selects the mode,
	// so that it's also signalled in the SDP
	if (pt->format.fmtp_parsed && !pt->format.parsed.codec2.mode && pt->bitrate
			&& pt->bitrate != CODEC2_DEFAULT_MODE)
	{
		int mode = codec2_mode_from_int(pt->bitrate);
		if (mode > 0) {
			pt->format.parsed.codec2.mode = mode;
			// also keep the plain fmtp string in line. A static string is fine here
			// because the caller copies it right after this
			if (!pt->format_parameters.len)
				pt->format_parameters = STR(codec2_mode_fmtp(mode));
		}
		else
			ilog(LOG_WARN, "Codec 2 has no mode for a bit rate of %i bit/s", pt->bitrate);
	}

	int mode = codec2_effective_mode(pt);
	if (mode > 0)
		pt->bitrate = mode;

	// modes 1600 and below use 40 ms frames
	if (mode > 0 && mode <= 1600 && pt->ptime > 0 && pt->ptime % 40) {
		int np = (pt->ptime + 39) / 40 * 40;
		ilog(LOG_DEBUG, "Codec 2 mode %s uses 40 ms frames, using ptime %i ms instead of %i ms",
				codec2_mode_name(mode), np, pt->ptime);
		pt->ptime = np;
	}
}


#ifdef HAVE_CODEC2

#include <codec2.h>
#include "fix_frame_channel_layout.compat"


static int codec2_lib_mode(int mode) {
	switch (mode) {
		case 3200:
			return CODEC2_MODE_3200;
		case 2400:
			return CODEC2_MODE_2400;
		case 1600:
			return CODEC2_MODE_1600;
		case 1400:
			return CODEC2_MODE_1400;
		case 1300:
			return CODEC2_MODE_1300;
		case 1200:
			return CODEC2_MODE_1200;
		case 700:
			return CODEC2_MODE_700C;
	}
	return -1;
}

// the mode comes from fmtp only, so that both sides agree on it
static int codec2_select_mode(const union codec_format_options *fmtp) {
	if (fmtp && fmtp->codec2.mode)
		return fmtp->codec2.mode;
	return CODEC2_DEFAULT_MODE;
}


static void codec2_def_init(struct codec_def_s *def) {
	struct CODEC2 *c2 = codec2_create(CODEC2_MODE_2400);
	if (!c2)
		return;
	codec2_destroy(c2);
	def->support_encoding = 1;
	def->support_decoding = 1;
}


static const char *codec2_decoder_init(decoder_t *dec, const str *extra_opts) {
	if (dec->in_format.clockrate != 8000)
		return "Codec 2 requires a clock rate of 8000 Hz";
	if (dec->in_format.channels != 1)
		return "Codec 2 supports mono only";

	int mode = codec2_select_mode(&dec->format_options);
	int lib_mode = codec2_lib_mode(mode);
	if (lib_mode < 0)
		return "unsupported Codec 2 mode";

	dec->codec2 = codec2_create(lib_mode);
	if (!dec->codec2)
		return "failed to create Codec 2 decoder";

	ilog(LOG_DEBUG, "Created Codec 2 decoder in mode %s (%i samples and %i bytes per frame)",
			codec2_mode_name(mode), codec2_samples_per_frame(dec->codec2),
			codec2_bytes_per_frame(dec->codec2));

	return NULL;
}

static int codec2_decoder_input(decoder_t *dec, const str *data, frame_q *out, bool mark) {
	struct CODEC2 *c2 = dec->codec2;
	const int bytes_per_frame = codec2_bytes_per_frame(c2);
	const int samples_per_frame = codec2_samples_per_frame(c2);

	size_t num_frames = data->len / bytes_per_frame;
	if (num_frames == 0 || data->len % bytes_per_frame) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Codec 2 payload of %zu bytes is not a multiple of the "
				"frame size (%i bytes)", data->len, bytes_per_frame);
		if (num_frames == 0)
			return -1;
	}

	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = num_frames * samples_per_frame;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = dec->in_format.clockrate;
	DEF_CH_LAYOUT(&frame->CH_LAYOUT, 1);
	frame->pts = dec->pts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	const unsigned char *in = (const unsigned char *) data->s;
	short *pcm = (short *) frame->extended_data[0];
	for (size_t i = 0; i < num_frames; i++) {
		codec2_decode(c2, pcm, in);
		in += bytes_per_frame;
		pcm += samples_per_frame;
	}

	t_queue_push_tail(out, frame);
	return 0;
}

static void codec2_decoder_close(decoder_t *dec) {
	if (dec->codec2)
		codec2_destroy(dec->codec2);
	dec->codec2 = NULL;
}


static const char *codec2_encoder_init(encoder_t *enc, const str *extra_opts) {
	if (enc->requested_format.channels != 1)
		ilog(LOG_WARN, "Codec 2 supports mono only, ignoring %i requested channels",
				enc->requested_format.channels);

	int mode = codec2_select_mode(&enc->format_options);
	int lib_mode = codec2_lib_mode(mode);
	if (lib_mode < 0)
		return "unsupported Codec 2 mode";

	enc->codec2 = codec2_create(lib_mode);
	if (!enc->codec2)
		return "failed to create Codec 2 encoder";

	if (enc->requested_format.clockrate != 8000)
		ilog(LOG_WARN, "Codec 2 requires a clock rate of 8000 Hz, ignoring requested %i Hz",
				enc->requested_format.clockrate);

	enc->actual_format = enc->requested_format;
	enc->actual_format.format = AV_SAMPLE_FMT_S16;
	enc->actual_format.channels = 1;
	enc->actual_format.clockrate = 8000;
	enc->actual_format.time_base = 8000;

	// put as many whole frames into each packet as fit the ptime, but at least one
	// (the 1600 and lower modes use 40 ms frames)
	int samples_per_frame = codec2_samples_per_frame(enc->codec2);
	int frame_ms = samples_per_frame * 1000 / enc->actual_format.clockrate;
	int frames = enc->ptime / frame_ms;
	if (frames < 1)
		frames = 1;
	if (frames * frame_ms != enc->ptime)
		ilog(LOG_INFO, "Codec 2 mode %s uses %i ms frames, sending %i ms per packet instead of "
				"ptime %i ms", codec2_mode_name(mode), frame_ms, frames * frame_ms, enc->ptime);

	enc->samples_per_frame = frames * samples_per_frame;
	enc->samples_per_packet = enc->samples_per_frame;
	enc->bitrate = mode;

	ilog(LOG_DEBUG, "Created Codec 2 encoder in mode %s (%i frames of %i bytes per packet)",
			codec2_mode_name(mode), frames, codec2_bytes_per_frame(enc->codec2));

	return NULL;
}

static int codec2_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	struct CODEC2 *c2 = enc->codec2;
	const int samples_per_frame = codec2_samples_per_frame(c2);
	const int bytes_per_frame = codec2_bytes_per_frame(c2);

	if ((*frame)->nb_samples != enc->samples_per_frame) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Codec 2: input %i samples instead of %i",
				(*frame)->nb_samples, enc->samples_per_frame);
		return -1;
	}

	int num_frames = (*frame)->nb_samples / samples_per_frame;
	av_new_packet(enc->avpkt, num_frames * bytes_per_frame);

	short *pcm = (short *) (*frame)->extended_data[0];
	unsigned char *out = enc->avpkt->data;
	for (int i = 0; i < num_frames; i++) {
		codec2_encode(c2, out, pcm);
		pcm += samples_per_frame;
		out += bytes_per_frame;
	}

	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = (*frame)->nb_samples;

	return 0;
}

static void codec2_encoder_close(encoder_t *enc) {
	if (enc->codec2)
		codec2_destroy(enc->codec2);
	enc->codec2 = NULL;
}


static const codec_type_t codec_type_codec2 = {
	.def_init = codec2_def_init,
	.decoder_init = codec2_decoder_init,
	.decoder_input = codec2_decoder_input,
	.decoder_close = codec2_decoder_close,
	.encoder_init = codec2_encoder_init,
	.encoder_input = codec2_encoder_input,
	.encoder_close = codec2_encoder_close,
};

#endif


static const codec_def_t codec2 = {
	.rtpname = "codec2",
	.avcodec_id = -1,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_bitrate = CODEC2_DEFAULT_MODE,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.init = codec2_init,
	.format_parse = codec2_format_parse,
	.format_cmp = codec2_format_cmp,
	.format_print = codec2_format_print,
	.packetizer = &packetizer_passthrough,
	.bits_per_sample = 1, // at most 3200 bit/s at 8000 samples/s
	.media_type = MT_AUDIO,
#ifdef HAVE_CODEC2
	.codec_type = &codec_type_codec2,
#endif
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&codec2);
}
