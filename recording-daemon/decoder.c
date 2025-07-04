#include "decoder.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <libavutil/samplefmt.h>
#include <glib.h>
#include <stdint.h>
#include <libavutil/opt.h>
#include "types.h"
#include "log.h"
#include "str.h"
#include "output.h"
#include "mix.h"
#include "resample.h"
#include "codeclib.h"
#include "streambuf.h"
#include "main.h"
#include "packet.h"
#include "tag.h"
#include "tls_send.h"


// does not initialise the contained `sink`
decode_t *decoder_new(const char *payload_str, const char *format, int ptime) {
	char *slash = strchr(payload_str, '/');
	if (!slash) {
		ilog(LOG_WARN, "Invalid payload format: %s", payload_str);
		return NULL;
	}

	str name = STR_LEN(payload_str, slash - payload_str);
	int clockrate = atoi(slash + 1);
	if (clockrate <= 0) {
		ilog(LOG_ERR, "Invalid clock rate %i (parsed from '%.20s'/'%.20s')",
				clockrate, slash + 1, payload_str);
		return NULL;
	}

	int channels = 1;
	slash = strchr(slash + 1, '/');
	if (slash) {
		channels = atoi(slash + 1);
		if (!channels)
			channels = 1;
	}

	codec_def_t *def = codec_find(&name, MT_AUDIO);
	if (!def) {
		ilog(LOG_WARN, "No decoder for payload %s", payload_str);
		return NULL;
	}
	if (def->supplemental || !def->support_decoding || def->media_type != MT_AUDIO) {
		// not a real audio codec
		ilog(LOG_DEBUG, "Not decoding codec %s", payload_str);
		return NULL;
	}

	// decoder_new_fmt already handles the clockrate_mult scaling
	int rtp_clockrate = clockrate;
	clockrate = fraction_mult(clockrate, &def->default_clockrate_fact);

	format_t out_format = {
		.clockrate = clockrate,
		.channels = channels,
		.format = AV_SAMPLE_FMT_S16,
	};

	str fmtp = STR(format);

	decoder_t *dec = decoder_new_fmtp(def, rtp_clockrate, channels, ptime, &out_format, NULL, &fmtp, NULL);
	if (!dec)
		return NULL;
	decode_t *deco = g_new0(decode_t, 1);
	deco->dec = dec;
	return deco;
}


static int decoder_got_frame(decoder_t *dec, AVFrame *frame, void *sp, void *dp) {
	ssrc_t *ssrc = sp;
	metafile_t *metafile = ssrc->metafile;
	output_t *output = ssrc->output;
	stream_t *stream = ssrc->stream;
	decode_t *deco = dp;

	dbg("got frame pts %llu samples %u contents %02x%02x%02x%02x...", (unsigned long long) frame->pts, frame->nb_samples,
			(unsigned int) frame->extended_data[0][0],
			(unsigned int) frame->extended_data[0][1],
			(unsigned int) frame->extended_data[0][2],
			(unsigned int) frame->extended_data[0][3]);

	if (metafile->recording_on) {
		sink_add(&deco->mix_sink, frame);

		if (output) {
			dbg("SSRC %lx of stream #%lu has single output", ssrc->ssrc, stream->id);
			if (!sink_add(&output->sink, frame))
				ilog(LOG_ERR, "Failed to add decoded packet to individual output");
		}
	}

	if (metafile->forwarding_on)
		sink_add(&deco->tls_mix_sink, frame);

	if (ssrc->tls_fwd) {
		dbg("SSRC %lx of stream #%lu has TLS forwarding stream", ssrc->ssrc, stream->id);
		if (!sink_add(&ssrc->tls_fwd->sink, frame))
			ilog(LOG_ERR, "Failed to add decoded packet to TLS/TCP forward output");

	}

	av_frame_free(&frame);
	return 0;
}


int decoder_input(decode_t *deco, const str *data, unsigned long ts, ssrc_t *ssrc) {
	return decoder_input_data(deco->dec, data, ts, decoder_got_frame, ssrc, deco);
}

void decoder_free(decode_t *deco) {
	if (!deco)
		return;
	decoder_close(deco->dec);
	sink_close(&deco->mix_sink);
	sink_close(&deco->tls_mix_sink);
	g_free(deco);
}
