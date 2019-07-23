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
#include "maskbeep.h"


int resample_audio;



decode_t *decoder_new(const char *payload_str, output_t *outp) {
	str name;
	char *slash = strchr(payload_str, '/');
	if (!slash) {
		ilog(LOG_WARN, "Invalid payload format: %s", payload_str);
		return NULL;
	}

	str_init_len(&name, (char *) payload_str, slash - payload_str);
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

	const codec_def_t *def = codec_find(&name, MT_AUDIO);
	if (!def) {
		ilog(LOG_WARN, "No decoder for payload %s", payload_str);
		return NULL;
	}
	if (def->avcodec_id == -1) // not a real audio codec
		return NULL;

	// decoder_new_fmt already handles the clockrate_mult scaling
	int rtp_clockrate = clockrate;
	clockrate *= def->clockrate_mult;

	format_t out_format = {
		.clockrate = clockrate,
		.channels = channels,
		.format = -1,
	};

	if (resample_audio)
		out_format.clockrate = resample_audio;
	dbg("====> rtp_clockrate = %d, resample_clockrate = %d", rtp_clockrate, resample_audio);

	// mono/stereo mixing goes here: out_format.channels = ...
	out_format.channels = 2;
	out_format.format = AV_SAMPLE_FMT_S16;
	if (outp) {
		// if this output has been configured already, re-use the same format
		if (outp->encoder && outp->encoder->requested_format.format != -1)
			out_format = outp->encoder->requested_format;
		out_format.channels = mix_get_out_channels(channels);
		output_config(outp, &out_format, &out_format);
		// save the returned sample format so we don't output_config() twice
		outp->encoder->requested_format.format = out_format.format;
	}

	format_t resample_format = out_format;
	resample_format.channels = channels;
	decoder_t *dec = decoder_new_fmt(def, rtp_clockrate, channels, &resample_format);
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
			deco->mixer_idx = mix_get_index(metafile->mix);
		format_t actual_format = dec->out_format;
	//	if (output_config(metafile->mix_out, &dec->out_format, &actual_format))
	//		goto no_mix_out;
		mix_config(metafile->mix, &actual_format, &metafile->mix_out->encoder->actual_format);
		// XXX might be a second resampling to same format
		AVFrame *dec_frame = resample_frame(&deco->mix_resampler, frame, &actual_format);
		if (!dec_frame) {
			pthread_mutex_unlock(&metafile->mix_lock);
			goto err;
		}
		if (mix_add(metafile->mix, dec_frame, deco->mixer_idx, metafile->mix_out))
			ilog(LOG_ERR, "Failed to add decoded packet to mixed output");
	}
//no_mix_out:
	pthread_mutex_unlock(&metafile->mix_lock);

	if (output) {
		dbg("SSRC %lx of stream #%lu has single output", ssrc->ssrc, stream->id);
		if (output_config(output, &dec->out_format, NULL))
			goto err;
		if (output_add(output, frame))
			ilog(LOG_ERR, "Failed to add decoded packet to individual output");
	}

no_recording:
	if (ssrc->tls_fwd_stream) {
		// XXX might be a second resampling to same format
		dbg("SSRC %lx of stream #%lu has TLS forwarding stream", ssrc->ssrc, stream->id);
		AVFrame *dec_frame = resample_frame(&ssrc->tls_fwd_resampler, frame, &ssrc->tls_fwd_format);

		ssrc_tls_state(ssrc);

		if (!ssrc->sent_intro) {
			if (metafile->metadata) {
				dbg("Writing metadata header to TLS");
				streambuf_write(ssrc->tls_fwd_stream, metafile->metadata, strlen(metafile->metadata) + 1);
			}
			else {
				ilog(LOG_WARN, "No metadata present for forwarding connection");
				streambuf_write(ssrc->tls_fwd_stream, "\0", 1);
			}
			ssrc->sent_intro = 1;
		}

		dbg("Writing %u bytes PCM to TLS", dec_frame->linesize[0]);
		streambuf_write(ssrc->tls_fwd_stream, (char *) dec_frame->extended_data[0],
				dec_frame->linesize[0]);
		av_frame_free(&dec_frame);

	}

	av_frame_free(&frame);
	return 0;

err:
	av_frame_free(&frame);
	return -1;
}

// only insert mask_beep when the time of a pause is greater than PAUSE_RECORDING_THRESHOLD
#define PAUSE_RECORDING_THRESHOLD 1000	

const unsigned char* fill_mask_data(unsigned char* mask_data, int len, const unsigned char * pMask){
	if (pMaskBeepEnd - pMask >= len)
	{
		memcpy(mask_data, pMask, len);
		pMask += len;
		if (pMask == pMaskBeepEnd)
			pMask = maskbeep;
	}
	else{
		int firstPartLen = pMaskBeepEnd - pMask;
		memcpy(mask_data, pMask, firstPartLen);
		int secondPartLen = len - firstPartLen;
		pMask = maskbeep;
		memcpy(mask_data + firstPartLen, pMask, secondPartLen);
		pMask += secondPartLen;
	}
	return pMask;
}

int decoder_input(decode_t *deco, const str *data, unsigned long ts, ssrc_t *ssrc) {
	decoder_t *dec = deco->dec;
	if (G_UNLIKELY(dec->rtp_ts != (unsigned long) -1L)) {
		// shift pts according to rtp ts shift
		u_int64_t multipliedTs = ts * dec->def->clockrate_mult;
		u_int64_t last_ts = dec->rtp_ts;
		int shift_ts = multipliedTs - last_ts;
		dbg("====> check pause/resume shift_ts = %d last_ts = %llu multipliedTs = %llu", shift_ts, last_ts, multipliedTs);
		if ((shift_ts * 1000) / dec->in_format.clockrate > PAUSE_RECORDING_THRESHOLD){
			// insert mask_beep, it is PCMU data from mask_beep.h
			// This is not a right place to do it, is the input encoder is probably not PCMU
			// We should move the insertion after decoding and before mixing and insert a RAW data instead of PCMU
			//
			// The following code is hard coded for PCMU 
			int nb_samples = 160;
			shift_ts -= data->len;
			u_int64_t next_ts = last_ts;

			unsigned char mask_data[nb_samples];
			str pMaskData;
			pMaskData.s = (char*)mask_data;

			const unsigned char* pMask = maskbeep;
			dbg("====> total len = %d", shift_ts);
			while (shift_ts > 0){
				int len = MIN(nb_samples, shift_ts);
				pMaskData.len = len;
				dbg("====> insert maskbeep[%d:%d]", pMask-maskbeep, len);
				pMask = fill_mask_data(mask_data, len, pMask);
				next_ts += len;
				decoder_input_data(dec, &pMaskData, next_ts, decoder_got_frame, ssrc, deco);
				shift_ts -= len;
				usleep(1000);
			}
		}

	}
	return decoder_input_data(dec, data, ts, decoder_got_frame, ssrc, deco);
}

void decoder_free(decode_t *deco) {
	if (!deco)
		return;
	decoder_close(deco->dec);
	resample_shutdown(&deco->mix_resampler);
	g_slice_free1(sizeof(*deco), deco);
}
