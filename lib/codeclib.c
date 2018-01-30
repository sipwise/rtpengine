#include "codeclib.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <glib.h>
#include "str.h"
#include "log.h"
#include "loglib.h"
#include "resample.h"



#define PACKET_SEQ_DUPE_THRES 100
#define PACKET_TS_RESET_THRES 5000 // milliseconds



#ifndef dbg
#ifdef __DEBUG
#define dbg(x...) ilog(LOG_DEBUG, x)
#else
#define dbg(x...) ((void)0)
#endif
#endif




#define CODEC_DEF_FULL(ref, codec_id, mult, name, clockrate, channels, bitrate) { \
	.rtpname = #ref, \
	.avcodec_id = codec_id, \
	.clockrate_mult = mult, \
	.avcodec_name = #name, \
	.default_clockrate = clockrate, \
	.default_channels = channels, \
	.default_bitrate = bitrate, \
}
#define CODEC_DEF_AVC(ref, id, mult, name, clockrate, channels, bitrate) \
	CODEC_DEF_FULL(ref, AV_CODEC_ID_ ## id, mult, name, clockrate, channels, bitrate)
#define CODEC_DEF_MULT_NAME(ref, id, mult, name) CODEC_DEF_AVC(ref, id, mult, name, -1, -1, 0)
#define CODEC_DEF_MULT_NAME_ENC(ref, id, mult, name, clockrate, channels, bitrate) \
	CODEC_DEF_AVC(ref, id, mult, name, clockrate, channels, bitrate)
#define CODEC_DEF_MULT(ref, id, mult) CODEC_DEF_MULT_NAME(ref, id, mult, NULL)
#define CODEC_DEF_MULT_ENC(ref, id, mult, clockrate, channels) \
	CODEC_DEF_MULT_NAME_ENC(ref, id, mult, NULL, clockrate, channels, 0)
#define CODEC_DEF_NAME(ref, id, name) CODEC_DEF_MULT_NAME(ref, id, 1, name)
#define CODEC_DEF_NAME_ENC(ref, id, name, clockrate, channels, bitrate) \
	CODEC_DEF_MULT_NAME_ENC(ref, id, 1, name, clockrate, channels, bitrate)
#define CODEC_DEF(ref, id) CODEC_DEF_MULT(ref, id, 1)
#define CODEC_DEF_ENC(ref, id, clockrate, channels) CODEC_DEF_MULT_ENC(ref, id, 1, clockrate, channels)
#define CODEC_DEF_STUB(ref) CODEC_DEF_FULL(ref, -1, 1, ref, -1, -1, 0)

static const struct codec_def_s codecs[] = {
	CODEC_DEF(PCMA, PCM_ALAW),
	CODEC_DEF(PCMU, PCM_MULAW),
	CODEC_DEF(G723, G723_1),
	CODEC_DEF_MULT(G722, ADPCM_G722, 2),
	CODEC_DEF(QCELP, QCELP),
	CODEC_DEF(G729, G729),
	CODEC_DEF_ENC(speex, SPEEX, 16000, 1),
	CODEC_DEF(GSM, GSM),
	CODEC_DEF(iLBC, ILBC),
	CODEC_DEF_NAME_ENC(opus, OPUS, libopus, 48000, 2, 24000),
	CODEC_DEF_NAME(vorbis, VORBIS, libvorbis),
	CODEC_DEF(ac3, AC3),
	CODEC_DEF(eac3, EAC3),
	CODEC_DEF(ATRAC3, ATRAC3),
	CODEC_DEF(ATRAC-X, ATRAC3P),
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	CODEC_DEF(EVRC, EVRC),
	CODEC_DEF(EVRC0, EVRC),
	CODEC_DEF(EVRC1, EVRC),
#endif
	CODEC_DEF_ENC(AMR, AMR_NB, 8000, 1),
	CODEC_DEF_ENC(AMR-WB, AMR_WB, 16000, 1),
	CODEC_DEF_STUB(telephone-event),
};



// XXX use hashtable for quicker lookup
const codec_def_t *codec_find(const str *name) {
	for (int i = 0; i < G_N_ELEMENTS(codecs); i++) {
		if (!str_cmp(name, codecs[i].rtpname))
			return &codecs[i];
	}
	return NULL;
}



decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, const format_t *resample_fmt) {
	const char *err = NULL;

	if (def->avcodec_id == -1)
		return NULL;

	clockrate *= def->clockrate_mult;

	decoder_t *ret = g_slice_alloc0(sizeof(*ret));

	format_init(&ret->in_format);
	ret->in_format.channels = channels;
	ret->in_format.clockrate = clockrate;
	// output defaults to same as input
	ret->out_format = ret->in_format;
	if (resample_fmt)
		ret->out_format = *resample_fmt;
	// sample format to be determined later when decoded frames arrive

	AVCodec *codec = NULL;
	if (def->avcodec_name)
		codec = avcodec_find_decoder_by_name(def->avcodec_name);
	if (!codec)
		codec = avcodec_find_decoder(def->avcodec_id);
	if (!codec) {
		ilog(LOG_WARN, "Codec '%s' not supported", def->rtpname);
		goto err;
	}

	ret->avcctx = avcodec_alloc_context3(codec);
	err = "failed to alloc codec context";
	if (!ret->avcctx)
		goto err;
	ret->avcctx->channels = channels;
	ret->avcctx->sample_rate = clockrate;
	err = "failed to open codec context";
	int i = avcodec_open2(ret->avcctx, codec, NULL);
	if (i)
		goto err;

	for (const enum AVSampleFormat *sfmt = codec->sample_fmts; sfmt && *sfmt != -1; sfmt++)
		dbg("supported sample format for input codec %s: %s",
				codec->name, av_get_sample_fmt_name(*sfmt));

	av_init_packet(&ret->avpkt);

	ret->pts = (uint64_t) -1LL;
	ret->rtp_ts = (unsigned long) -1L;
	ret->mixer_idx = (unsigned int) -1;

	return ret;

err:
	decoder_close(ret);
	if (err)
		ilog(LOG_ERR, "Error creating media decoder: %s", err);
	return NULL;
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(56, 1, 0)
	avcodec_free_context(&dec->avcctx);
#else
	avcodec_close(dec->avcctx);
	av_free(dec->avcctx);
#endif
	resample_shutdown(&dec->resampler);
	resample_shutdown(&dec->mix_resampler);
	g_slice_free1(sizeof(*dec), dec);
}

int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	const char *err;

	if (G_UNLIKELY(!dec))
		return -1;

	dbg("%p dec pts %llu rtp_ts %llu incoming ts %lu", dec, (unsigned long long) dec->pts,
			(unsigned long long) dec->rtp_ts, (unsigned long) ts);

	if (G_UNLIKELY(dec->rtp_ts == (unsigned long) -1L)) {
		// initialize pts
		dec->pts = 0;
	}
	else {
		// shift pts according to rtp ts shift
		u_int64_t shift_ts = ts - dec->rtp_ts;
		if ((shift_ts * dec->avcctx->time_base.num * 1000) / dec->avcctx->time_base.den
				> PACKET_TS_RESET_THRES)
		{
			ilog(LOG_DEBUG, "Timestamp disconinuity detected, resetting timestamp from "
					"%lu to %lu",
					dec->rtp_ts, ts);
			// XXX handle lost packets here if timestamps don't line up?
			dec->pts += dec->avcctx->time_base.den;
		}
		else
			dec->pts += shift_ts;
	}
	dec->rtp_ts = ts;

	dec->avpkt.data = (unsigned char *) data->s;
	dec->avpkt.size = data->len;
	dec->avpkt.pts = dec->pts;

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
		if (dec->avpkt.size) {
			int ret = avcodec_send_packet(dec->avcctx, &dec->avpkt);
			dbg("send packet ret %i", ret);
			err = "failed to send packet to avcodec";
			if (ret == 0) {
				// consumed the packet
				dec->avpkt.size = 0;
				keep_going = 1;
			}
			else {
				if (ret == AVERROR(EAGAIN))
					; // try again after reading output
				else
					goto err;
			}
		}

		int ret = avcodec_receive_frame(dec->avcctx, frame);
		dbg("receive frame ret %i", ret);
		err = "failed to receive frame from avcodec";
		if (ret == 0) {
			// got a frame
			keep_going = 1;
			got_frame = 1;
		}
		else {
			if (ret == AVERROR(EAGAIN))
				; // maybe needs more input now
			else
				goto err;
		}
#else
		// only do this if we have any input left
		if (dec->avpkt.size == 0)
			break;

		int ret = avcodec_decode_audio4(dec->avcctx, frame, &got_frame, &dec->avpkt);
		dbg("decode frame ret %i, got frame %i", ret, got_frame);
		err = "failed to decode audio packet";
		if (ret < 0)
			goto err;
		if (ret > 0) {
			// consumed some input
			err = "invalid return value";
			if (ret > dec->avpkt.size)
				goto err;
			dec->avpkt.size -= ret;
			dec->avpkt.data += ret;
			keep_going = 1;
		}
		if (got_frame)
			keep_going = 1;
#endif

		if (got_frame) {
			dbg("raw frame from decoder pts %llu samples %u", (unsigned long long) frame->pts, frame->nb_samples);

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 36, 0)
			frame->pts = frame->pkt_pts;
#endif
			if (G_UNLIKELY(frame->pts == AV_NOPTS_VALUE))
				frame->pts = dec->avpkt.pts;
			dec->avpkt.pts += frame->nb_samples;

			err = "resampling failed";
			AVFrame *rsmp_frame = resample_frame(&dec->resampler, frame, &dec->out_format);
			if (!rsmp_frame)
				goto err;

			if (callback(dec, rsmp_frame, u1, u2))
				return -1;
			av_frame_free(&frame);
		}
	} while (keep_going);

	av_frame_free(&frame);
	return 0;

err:
	ilog(LOG_ERR, "Error decoding media packet: %s", err);
	av_frame_free(&frame);
	return -1;
}


static void avlog_ilog(void *ptr, int loglevel, const char *fmt, va_list ap) {
	char *msg;
	if (vasprintf(&msg, fmt, ap) <= 0)
		ilog(LOG_ERR, "av_log message dropped");
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
		ilog(loglevel, "av_log: %s", msg);
		free(msg);
	}
}
void codeclib_init() {
	av_register_all();
	avcodec_register_all();
	avfilter_register_all();
	avformat_network_init();
	av_log_set_callback(avlog_ilog);
}






static int ptr_cmp(const void *a, const void *b, void *dummy) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

void packet_sequencer_init(packet_sequencer_t *ps, GDestroyNotify ffunc) {
	ps->packets = g_tree_new_full(ptr_cmp, NULL, NULL, ffunc);
	ps->seq = -1;
}
void packet_sequencer_destroy(packet_sequencer_t *ps) {
	g_tree_destroy(ps->packets);
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
void *packet_sequencer_next_packet(packet_sequencer_t *ps) {
	// see if we have a packet with the correct seq nr in the queue
	seq_packet_t *packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ps->seq));
	if (G_LIKELY(packet != NULL)) {
		dbg("returning in-sequence packet (seq %i)", ps->seq);
		goto out;
	}

	// why not? do we have anything? (we should)
	int nnodes = g_tree_nnodes(ps->packets);
	if (G_UNLIKELY(nnodes == 0)) {
		dbg("packet queue empty");
		return NULL;
	}
	if (G_LIKELY(nnodes < 10)) { // XXX arbitrary value
		dbg("only %i packets in queue - waiting for more", nnodes);
		return NULL; // need to wait for more
	}

	// packet was probably lost. search for the next highest seq
	struct tree_searcher ts = { .find_seq = ps->seq + 1, .found_seq = -1 };
	packet = g_tree_search(ps->packets, packet_tree_search, &ts);
	if (packet) {
		// bullseye
		dbg("lost packet - returning packet with next seq %i", packet->seq);
		goto out;
	}
	if (G_UNLIKELY(ts.found_seq == -1)) {
		// didn't find anything. seq must have wrapped around. retry
		// starting from zero
		ts.find_seq = 0;
		packet = g_tree_search(ps->packets, packet_tree_search, &ts);
		if (packet) {
			dbg("lost packet - returning packet with next seq %i (after wrap)", packet->seq);
			goto out;
		}
		if (G_UNLIKELY(ts.found_seq == -1))
			abort();
	}

	// pull out the packet we found
	packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ts.found_seq));
	if (G_UNLIKELY(packet == NULL))
		abort();

	dbg("lost multiple packets - returning packet with next highest seq %i", packet->seq);

out:
	g_tree_steal(ps->packets, GINT_TO_POINTER(packet->seq));
	ps->seq = (packet->seq + 1) & 0xffff;
	return packet;
}

int packet_sequencer_insert(packet_sequencer_t *ps, seq_packet_t *p) {
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
	// seq ok - fall thru
seq_ok:
	if (g_tree_lookup(ps->packets, GINT_TO_POINTER(p->seq)))
		return -1;
	g_tree_insert(ps->packets, GINT_TO_POINTER(p->seq), p);

	return 0;
}




encoder_t *encoder_new() {
	encoder_t *ret = g_slice_alloc0(sizeof(*ret));
	format_init(&ret->requested_format);
	format_init(&ret->actual_format);
	return ret;
}

int encoder_config(encoder_t *enc, int codec_id, int bitrate, const format_t *requested_format,
		format_t *actual_format)
{
	const char *err;

	// anything to do?
	if (G_LIKELY(format_eq(requested_format, &enc->requested_format)))
		goto done;

	encoder_close(enc);

	enc->requested_format = *requested_format;

	err = "output codec not found";
	enc->codec = avcodec_find_encoder(codec_id);
	if (!enc->codec)
		goto err;

	err = "failed to alloc codec context";
	enc->avcctx = avcodec_alloc_context3(enc->codec);
	if (!enc->avcctx)
		goto err;

	enc->actual_format = enc->requested_format;

	enc->actual_format.format = -1;
	for (const enum AVSampleFormat *sfmt = enc->codec->sample_fmts; sfmt && *sfmt != -1; sfmt++) {
		dbg("supported sample format for output codec %s: %s", enc->codec->name, av_get_sample_fmt_name(*sfmt));
		if (*sfmt == requested_format->format)
			enc->actual_format.format = *sfmt;
	}
	if (enc->actual_format.format == -1 && enc->codec->sample_fmts)
		enc->actual_format.format = enc->codec->sample_fmts[0];
	dbg("using output sample format %s for codec %s", av_get_sample_fmt_name(enc->actual_format.format), enc->codec->name);

	enc->avcctx->channels = enc->actual_format.channels;
	enc->avcctx->channel_layout = av_get_default_channel_layout(enc->actual_format.channels);
	enc->avcctx->sample_rate = enc->actual_format.clockrate;
	enc->avcctx->sample_fmt = enc->actual_format.format;
	enc->avcctx->time_base = (AVRational){1,enc->actual_format.clockrate};
	enc->avcctx->bit_rate = bitrate;

	err = "failed to open output context";
	int i = avcodec_open2(enc->avcctx, enc->codec, NULL);
	if (i)
		goto err;

	av_init_packet(&enc->avpkt);

done:
	*actual_format = enc->actual_format;
	return 0;

err:
	encoder_close(enc);
	ilog(LOG_ERR, "Error configuring media output: %s", err);
	return -1;
}

void encoder_close(encoder_t *enc) {
	if (!enc)
		return;
	if (enc->avcctx) {
		avcodec_close(enc->avcctx);
		avcodec_free_context(&enc->avcctx);
	}
	enc->avcctx = NULL;
	format_init(&enc->requested_format);
	format_init(&enc->actual_format);
	enc->mux_dts = 0;
}
void encoder_free(encoder_t *enc) {
	encoder_close(enc);
	g_slice_free1(sizeof(*enc), enc);
}

int encoder_input_data(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	int keep_going;
	int have_frame = 1;
	do {
		keep_going = 0;
		int got_packet = 0;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 36, 0)
		if (have_frame) {
			int ret = avcodec_send_frame(enc->avcctx, frame);
			dbg("send frame ret %i", ret);
			if (ret == 0) {
				// consumed
				have_frame = 0;
				keep_going = 1;
			}
			else {
				if (ret == AVERROR(EAGAIN))
					; // check output and maybe try again
				else
					return -1;
			}
		}

		int ret = avcodec_receive_packet(enc->avcctx, &enc->avpkt);
		dbg("receive packet ret %i", ret);
		if (ret == 0) {
			// got some data
			keep_going = 1;
			got_packet = 1;
		}
		else {
			if (ret == AVERROR(EAGAIN))
				; // try again if there's still more input
			else
				return -1;
		}
#else
		if (!have_frame)
			break;

		int ret = avcodec_encode_audio2(enc->avcctx, &enc->avpkt, frame, &got_packet);
		dbg("encode frame ret %i, got packet %i", ret, got_packet);
		if (ret == 0)
			have_frame = 0; // consumed
		else
			return -1; // error
		if (got_packet)
			keep_going = 1;
#endif

		if (!got_packet)
			continue;

//		dbg("{%s} output avpkt size is %i", output->file_name, (int) enc->avpkt.size);
//		dbg("{%s} output pkt pts/dts is %li/%li", output->file_name, (long) enc->avpkt.pts,
//				(long) enc->avpkt.dts);
//		dbg("{%s} output dts %li", output->file_name, (long) output->mux_dts);

		// the encoder may return frames with the same dts multiple consecutive times.
		// the muxer may not like this, so ensure monotonically increasing dts.
		if (enc->mux_dts > enc->avpkt.dts)
			enc->avpkt.dts = enc->mux_dts;
		if (enc->avpkt.pts < enc->avpkt.dts)
			enc->avpkt.pts = enc->avpkt.dts;

		//av_write_frame(output->fmtctx, &output->avpkt);
		callback(enc, u1, u2);

		//output->fifo_pts += output->frame->nb_samples;
		enc->mux_dts = enc->avpkt.dts + 1; // min next expected dts

		av_packet_unref(&enc->avpkt);
	} while (keep_going);

	return 0;
}
