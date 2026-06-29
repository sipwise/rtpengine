#include "codecmod.h"
#include <arpa/inet.h>
#include "loglib.h"
#include "fix_frame_channel_layout.compat"
#include "dtmflib.h"


static const char *dtmf_decoder_init(decoder_t *dec, const str *extra_opts) {
	dec->dtmf.event = -1;
	return NULL;
}


static AVFrame *dtmf_frame_int16_t_mono(unsigned long frame_ts, unsigned long num_samples, unsigned int event,
		unsigned int volume,
		unsigned int sample_rate)
{
	// synthesise PCM
	// first get our frame and figure out how many samples we need, and the start offset
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = num_samples;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = sample_rate;
	frame->CH_LAYOUT = (CH_LAYOUT_T) MONO_LAYOUT;
	frame->pts = frame_ts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	// fill samples
	dtmf_samples_int16_t_mono(frame->extended_data[0], frame_ts, frame->nb_samples, event,
			volume, sample_rate);

	return frame;

}

static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	struct telephone_event_payload *dtmf;
	if (data->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %zu)", data->len);
		return -1;
	}
	dtmf = (void *) data->s;

	// init if we need to
	if (dtmf->event != dec->dtmf.event || dec->rtp_ts != dec->dtmf.start_ts) {
		ZERO(dec->dtmf);
		dec->dtmf.event = dtmf->event;
		dec->dtmf.start_ts = dec->rtp_ts;
		ilog(LOG_DEBUG, "New DTMF event starting: %u at TS %lu", dtmf->event, dec->rtp_ts);
	}

	unsigned long duration = ntohs(dtmf->duration);
	unsigned long frame_ts = dec->rtp_ts - dec->dtmf.start_ts + dec->dtmf.duration;
	long num_samples = duration - dec->dtmf.duration;

	ilog(LOG_DEBUG, "Generate DTMF samples for event %u, start TS %lu, TS now %lu, frame TS %lu, "
			"duration %lu, "
			"old duration %lu, num samples %li",
			dtmf->event, dec->dtmf.start_ts, dec->rtp_ts, frame_ts,
			duration, dec->dtmf.duration, num_samples);

	if (num_samples <= 0)
		return 0;
	if (num_samples > dec->in_format.clockrate) {
		ilog(LOG_ERR, "Cannot generate %li DTMF samples (clock rate %u)", num_samples,
				dec->in_format.clockrate);
		return -1;
	}

	AVFrame *frame = dtmf_frame_int16_t_mono(frame_ts, num_samples, dtmf->event, dtmf->volume,
			dec->in_format.clockrate);
	frame->pts += dec->dtmf.start_ts;
	g_queue_push_tail(out, frame);

	dec->dtmf.duration = duration;

	return 0;
}



static const char *cn_decoder_init(decoder_t *dec, const str *opts) {
	// the ffmpeg cngdec always runs at 8000
	dec->in_format.clockrate = 8000;
	dec->in_format.channels = 1;
	dec->resampler.no_filter = true;
	return avc_decoder_init(dec, opts);
}
static int cn_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	// generate one set of ptime worth of samples
	int ptime = dec->ptime;
	if (ptime <= 0)
		ptime = 20; // ?
	int samples = dec->in_format.clockrate * ptime / 1000;
	int max_size = dec->avc.avcctx->frame_size;

	AVFrame *aframe = NULL;

	do {
		if (samples < max_size)
			dec->avc.avcctx->frame_size = samples;
		int ret = avc_decoder_input(dec, data, out);
		dec->avc.avcctx->frame_size = max_size;

		if (ret)
			return ret;
		if (!out->length)
			return -1;

		AVFrame *oframe = out->head->data;

		// one-shot handling if fewer samples than the CNG's frame size are requested
		if (!aframe && out->length == 1) {
			if (oframe->nb_samples >= samples) {
				oframe->nb_samples = samples;
				return 0;
			}
		}

		// consume frames and merge into single output frame

		if (!aframe) {
			aframe = av_frame_alloc();
			aframe->nb_samples = samples;
			assert(oframe->format == AV_SAMPLE_FMT_S16);
			aframe->format = oframe->format;
			assert(oframe->sample_rate == 8000);
			aframe->sample_rate = oframe->sample_rate;
			aframe->CH_LAYOUT = oframe->CH_LAYOUT; // should be mono
			aframe->pts = oframe->pts;
			aframe->pkt_dts = oframe->pkt_dts;
			if (av_frame_get_buffer(aframe, 0) < 0)
				abort();

			aframe->nb_samples = 0; // to track progress
		}

		while (out->length) {
			oframe = g_queue_pop_head(out);

			if (oframe->nb_samples <= 0) // error
				return -1; // XXX leaves frames in `out`

			// use as much as we have and as much as we need
			int rsamples = MIN(oframe->nb_samples, samples);

			memcpy(aframe->extended_data[0] + aframe->nb_samples * 2,
					oframe->extended_data[0], rsamples * 2);

			aframe->nb_samples += rsamples;
			samples -= rsamples; // drop to zero when finished

			av_frame_free(&oframe);
		};
	} while (samples > 0);

	g_queue_push_tail(out, aframe);

	return 0;
}


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

static const codec_def_t dtmf = {
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
};

static const codec_def_t cn = {
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
};

static const codec_def_t red = {
	.rtpname = "red",
	.avcodec_id = -1,
	.packetizer = packetizer_passthrough,
	.media_type = MT_AUDIO,
	.supplemental = 1,
	.default_clockrate = 8000,
	.default_channels = 1,
	.format_cmp = format_cmp_ignore,
	.support_encoding = 1,
	.support_decoding = 1,
};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&dtmf);
	codeclib_register_codec(&cn);
	codeclib_register_codec(&red);
}
