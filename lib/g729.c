#include "codecmod.h"

#ifndef HAVE_BCG729

static const codec_def_t g729 = {
	.rtpname = "G729",
	.avcodec_id = AV_CODEC_ID_G729,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};

static const codec_def_t g729a = {
	.rtpname = "G729a",
	.avcodec_id = AV_CODEC_ID_G729,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_avcodec,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};

#else

#include <bcg729/encoder.h>
#include <bcg729/decoder.h>
#include "fix_frame_channel_layout.compat"
#include "loglib.h"


static packetizer_f packetizer_g729; // aggregate some frames into packets

static void bcg729_def_init(struct codec_def_s *);
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

static const codec_def_t g729 = {
	.rtpname = "G729",
	.avcodec_id = -1,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.default_fmtp = "annexb=yes",
	.format_cmp = format_cmp_ignore,
	.packetizer = packetizer_g729,
	.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_bcg729,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};

static const codec_def_t g729a = {
	.rtpname = "G729a",
	.avcodec_id = -1,
	.default_clockrate = 8000,
	.default_channels = 1,
	.default_ptime = 20,
	.minimum_ptime = 20,
	.default_fmtp = "annexb=no",
	.format_cmp = format_cmp_ignore,
	.packetizer = packetizer_g729,
	.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_bcg729,
	.dtx_methods = {
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
	.fixed_sizes = 1,
};



static void bcg729_def_init(struct codec_def_s *def) {
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

static const char *bcg729_decoder_init(decoder_t *dec, const str *extra_opts) {
	dec->bcg729 = initBcg729DecoderChannel();
	if (!dec->bcg729)
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
		DEF_CH_LAYOUT(&frame->CH_LAYOUT, dec->in_format.channels);
		frame->pts = pts;
		if (av_frame_get_buffer(frame, 0) < 0)
			abort();

		pts += frame->nb_samples;

		// XXX handle lost packets and comfort noise
		bcg729Decoder(dec->bcg729, (void *) inp_frame.s, inp_frame.len, 0, 0, 0,
				(void *) frame->extended_data[0]);

		g_queue_push_tail(out, frame);
	}

	return 0;
}

static void bcg729_decoder_close(decoder_t *dec) {
	if (dec->bcg729)
		closeBcg729DecoderChannel(dec->bcg729);
	dec->bcg729 = NULL;
}

static const char *bcg729_encoder_init(encoder_t *enc, const str *extra_opts) {
	enc->bcg729 = initBcg729EncoderChannel(0); // no VAD
	if (!enc->bcg729)
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

	bcg729Encoder(enc->bcg729, (void *) (*frame)->extended_data[0], enc->avpkt->data, &len);
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
	if (enc->bcg729)
		closeBcg729EncoderChannel(enc->bcg729);
	enc->bcg729 = NULL;
}

static int packetizer_g729(AVPacket *pkt, GString *buf, str *input_output, size_t num_bytes, encoder_t *enc,
		int64_t *__restrict pts, int64_t *__restrict duration)
{
	// how many frames do we want?
	int want_frames = input_output->len / 10;

	// easiest case: we only want one frame. return what we got
	if (want_frames == 1 && pkt)
		return packetizer_passthrough(pkt, buf, input_output, num_bytes, enc, pts, duration);

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

	int64_t dur = 0;

	// return non-silence/noise frames while we can
	while (buf->len >= 10 && want_frames && output.len >= 10) {
		memcpy(output.s, buf->str, 10);
		g_string_erase(buf, 0, 10);
		want_frames--;
		str_shift(&output, 10);
		dur += 80;
	}

	// append silence/noise frames if we can
	while (buf->len >= 2 && want_frames && output.len >= 2) {
		memcpy(output.s, buf->str, 2);
		g_string_erase(buf, 0, 2);
		want_frames--;
		str_shift(&output, 2);
		dur += 80;
	}

	*pts = enc->packet_pts;
	*duration = dur;
	enc->packet_pts += dur;

	if (output.len == input_output->len)
		return -1; // got nothing
	input_output->len = output.s - input_output->s;
	return buf->len >= 2 ? 1 : 0;
}


#endif


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&g729);
	codeclib_register_codec(&g729a);
}
