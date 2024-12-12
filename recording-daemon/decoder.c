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


int resample_audio;



decode_t *decoder_new(const char *payload_str, const char *format, int ptime, output_t *outp) {
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
	if (outp) {
		// if this output has been configured already, re-use the same format
		if (outp->requested_format.format != -1)
			out_format = outp->requested_format;
		output_config(outp, &out_format, &out_format);
	}
	else
		out_format.format = AV_SAMPLE_FMT_S16; // needed for TLS-only scenarios

	str fmtp = STR(format);

	decoder_t *dec = decoder_new_fmtp(def, rtp_clockrate, channels, ptime, &out_format, NULL, &fmtp, NULL);
	if (!dec)
		return NULL;
	decode_t *deco = g_slice_alloc0(sizeof(decode_t));
	deco->dec = dec;
	deco->mixer_idx = (unsigned int) -1;
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

	// handle mix output
	pthread_mutex_lock(&metafile->mix_lock);
	if (metafile->mix_out) {
		dbg("adding packet from stream #%lu to mix output", stream->id);
		if (G_UNLIKELY(deco->mixer_idx == (unsigned int) -1))
			deco->mixer_idx = mix_get_index(metafile->mix, ssrc, stream->media_sdp_id, stream->channel_slot);
		format_t actual_format;
		if (output_config(metafile->mix_out, &dec->dest_format, &actual_format))
			goto no_mix_out;
		mix_config(metafile->mix, &actual_format);
		// XXX might be a second resampling to same format
		AVFrame *copy_frame = av_frame_clone(frame);
		AVFrame *dec_frame = resample_frame(&deco->mix_resampler, copy_frame, &actual_format);
		if (!dec_frame) {
			pthread_mutex_unlock(&metafile->mix_lock);
			goto err;
		}
		if (mix_add(metafile->mix, dec_frame, deco->mixer_idx, ssrc, metafile->mix_out))
			ilog(LOG_ERR, "Failed to add decoded packet to mixed output");
		if (dec_frame != copy_frame)
			av_frame_free(&copy_frame);
	}
no_mix_out:
	pthread_mutex_unlock(&metafile->mix_lock);

	if (output) {
		dbg("SSRC %lx of stream #%lu has single output", ssrc->ssrc, stream->id);
		if (output_config(output, &dec->dest_format, NULL))
			goto err;
		if (output_add(output, frame))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
	}

no_recording:
	if (ssrc->tls_fwd_stream) {
		// XXX might be a second resampling to same format
		dbg("SSRC %lx of stream #%lu has TLS forwarding stream", ssrc->ssrc, stream->id);

		ssrc_tls_state(ssrc);
		// if we're in the middle of a disconnect then ssrc_tls_state may have destroyed the streambuf
		// so we need to skip the below to ensure we only send metadata for the new connection
		// once we've got a new streambuf
		if (!ssrc->tls_fwd_stream)
			goto err;

		AVFrame *dec_frame = resample_frame(&ssrc->tls_fwd_resampler, frame, &ssrc->tls_fwd_format);

		if (!ssrc->sent_intro) {
			tag_t *tag = NULL;

			if (ssrc->stream)
				tag = tag_get(metafile, ssrc->stream->tag);

			if (tag && tag->metadata) {
				dbg("Writing tag metadata header to TLS");
				streambuf_write(ssrc->tls_fwd_stream, tag->metadata, strlen(tag->metadata) + 1);
			}
			else if (metafile->metadata) {
				dbg("Writing call metadata header to TLS");
				streambuf_write(ssrc->tls_fwd_stream, metafile->metadata, strlen(metafile->metadata) + 1);
			}
			else {
				ilog(LOG_WARN, "No metadata present for forwarding connection");
				streambuf_write(ssrc->tls_fwd_stream, "\0", 1);
			}
			ssrc->sent_intro = 1;
		}

		ssrc_tls_fwd_silence_frames_upto(ssrc, dec_frame, dec_frame->pts);
		uint64_t next_pts = dec_frame->pts + dec_frame->nb_samples;
		if (next_pts > ssrc->tls_in_pts)
			ssrc->tls_in_pts = next_pts;

		int linesize = av_get_bytes_per_sample(dec_frame->format) * dec_frame->nb_samples;
		dbg("Writing %u bytes PCM to TLS", linesize);
		streambuf_write(ssrc->tls_fwd_stream, (char *) dec_frame->extended_data[0], linesize);
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
	resample_shutdown(&deco->mix_resampler);
	g_slice_free1(sizeof(*deco), deco);
}
