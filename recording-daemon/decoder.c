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


int resample_audio;



// does not initialise the contained `sink`
decode_t *decoder_new(const char *payload_str, const char *format, int ptime, const format_t *dec_format) {
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

	// we can now config our output, which determines the sample format we convert to
	format_t out_format = {
		.clockrate = clockrate,
		.channels = channels,
		.format = -1,
	};

	if (resample_audio)
		out_format.clockrate = resample_audio;
	// mono/stereo mixing goes here: out_format.channels = ...
	// if the output has been configured already, re-use the same format
	if (dec_format->format != -1)
		out_format = *dec_format;
	else
		out_format.format = AV_SAMPLE_FMT_S16; // needed for TLS-only scenarios

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

	if (!metafile->recording_on)
		goto no_recording;

	sink_add(&deco->mix_sink, frame, &dec->dest_format);

	if (output) {
		dbg("SSRC %lx of stream #%lu has single output", ssrc->ssrc, stream->id);
		if (!sink_add(&output->sink, frame, &dec->dest_format))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
	}

no_recording:
	if (ssrc->tls_fwd) {
		// XXX might be a second resampling to same format
		dbg("SSRC %lx of stream #%lu has TLS forwarding stream", ssrc->ssrc, stream->id);

		tls_fwd_state(&ssrc->tls_fwd);
		// if we're in the middle of a disconnect then ssrc_tls_state may have destroyed the streambuf
		// so we need to skip the below to ensure we only send metadata for the new connection
		// once we've got a new streambuf
		if (!ssrc->tls_fwd)
			goto err;

		AVFrame *dec_frame = resample_frame(&ssrc->tls_fwd->resampler, frame, &ssrc->tls_fwd->format);

		if (!ssrc->tls_fwd->sent_intro) {
			tag_t *tag = NULL;

			if (ssrc->stream)
				tag = tag_get(metafile, ssrc->stream->tag);

			if (tag && tag->metadata) {
				dbg("Writing tag metadata header to TLS");
				streambuf_write(ssrc->tls_fwd->stream, tag->metadata, strlen(tag->metadata) + 1);
			}
			else if (metafile->metadata) {
				dbg("Writing call metadata header to TLS");
				streambuf_write(ssrc->tls_fwd->stream, metafile->metadata, strlen(metafile->metadata) + 1);
			}
			else {
				ilog(LOG_WARN, "No metadata present for forwarding connection");
				streambuf_write(ssrc->tls_fwd->stream, "\0", 1);
			}
			ssrc->tls_fwd->sent_intro = 1;
		}

		tls_fwd_silence_frames_upto(ssrc->tls_fwd, dec_frame, dec_frame->pts);
		uint64_t next_pts = dec_frame->pts + dec_frame->nb_samples;
		if (next_pts > ssrc->tls_fwd->in_pts)
			ssrc->tls_fwd->in_pts = next_pts;

		int linesize = av_get_bytes_per_sample(dec_frame->format) * dec_frame->nb_samples;
		dbg("Writing %u bytes PCM to TLS", linesize);
		streambuf_write(ssrc->tls_fwd->stream, (char *) dec_frame->extended_data[0], linesize);
		if (dec_frame != frame)
			av_frame_free(&dec_frame);

	}

	av_frame_free(&frame);
	return 0;

err:
	av_frame_free(&frame);
	return -1;
}


int decoder_input(decode_t *deco, const str *data, unsigned long ts, ssrc_t *ssrc) {
	return decoder_input_data(deco->dec, data, ts, decoder_got_frame, ssrc, deco);
}

void decoder_free(decode_t *deco) {
	if (!deco)
		return;
	decoder_close(deco->dec);
	sink_close(&deco->mix_sink);
	g_free(deco);
}
