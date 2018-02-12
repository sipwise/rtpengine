#include "codeclib.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <libavutil/opt.h>
#include <glib.h>
#include "str.h"
#include "log.h"
#include "loglib.h"
#include "resample.h"
#include "rtplib.h"



#define PACKET_SEQ_DUPE_THRES 100
#define PACKET_TS_RESET_THRES 5000 // milliseconds



#ifndef dbg
#ifdef __DEBUG
#define dbg(x...) ilog(LOG_DEBUG, x)
#else
#define dbg(x...) ((void)0)
#endif
#endif




static packetizer_f packetizer_passthrough; // pass frames as they arrive in AVPackets
static packetizer_f packetizer_samplestream; // flat stream of samples

static format_init_f opus_init;
static set_options_f opus_set_options;



static codec_def_t __codec_defs[] = {
	{
		.rtpname = "PCMA",
		.avcodec_id = AV_CODEC_ID_PCM_ALAW,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "PCMU",
		.avcodec_id = AV_CODEC_ID_PCM_MULAW,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "G723",
		.avcodec_id = AV_CODEC_ID_G723_1,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 30,
		.default_bitrate = 6300,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "G722",
		.avcodec_id = AV_CODEC_ID_ADPCM_G722,
		.clockrate_mult = 2,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "QCELP",
		.avcodec_id = AV_CODEC_ID_QCELP,
		.clockrate_mult = 1,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "G729",
		.avcodec_id = AV_CODEC_ID_G729,
		.clockrate_mult = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "speex",
		.avcodec_id = AV_CODEC_ID_SPEEX,
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 11000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "GSM",
		.avcodec_id = AV_CODEC_ID_GSM,
		.default_clockrate = 8000,
		.default_channels = 1,
		//.default_bitrate = 13200,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "iLBC",
		.avcodec_id = AV_CODEC_ID_ILBC,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		//.default_bitrate = 15200,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "opus",
		.avcodec_id = AV_CODEC_ID_OPUS,
		.avcodec_name = "libopus",
		.default_clockrate = 48000,
		.default_channels = 2,
		.default_bitrate = 32000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
		.init = opus_init,
		.set_options = opus_set_options,
	},
	{
		.rtpname = "vorbis",
		.avcodec_id = AV_CODEC_ID_VORBIS,
		.avcodec_name = "libvorbis",
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "ac3",
		.avcodec_id = AV_CODEC_ID_AC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "eac3",
		.avcodec_id = AV_CODEC_ID_EAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "ATRAC3",
		.avcodec_id = AV_CODEC_ID_ATRAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "ATRAC-X",
		.avcodec_id = AV_CODEC_ID_ATRAC3P,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	{
		.rtpname = "EVRC",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.avcodec_name = NULL,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "EVRC0",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.avcodec_name = NULL,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "EVRC1",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.avcodec_name = NULL,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
#endif
	{
		.rtpname = "AMR",
		.avcodec_id = AV_CODEC_ID_AMR_NB,
		.avcodec_name = NULL,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_bitrate = 6600,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "AMR-WB",
		.avcodec_id = AV_CODEC_ID_AMR_NB,
		.avcodec_name = NULL,
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 14250,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	// pseudo-codecs
	{
		.rtpname = "telephone-event",
		.avcodec_id = -1,
		.avcodec_name = NULL,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	// for file writing
	{
		.rtpname = "PCM-S16LE",
		.avcodec_id = AV_CODEC_ID_PCM_S16LE,
		.avcodec_name = NULL,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
	{
		.rtpname = "MP3",
		.avcodec_id = AV_CODEC_ID_MP3,
		.avcodec_name = NULL,
		.packetizer = packetizer_passthrough,
		.type = MT_AUDIO,
	},
};



static GHashTable *codecs_ht;



const codec_def_t *codec_find(const str *name, enum media_type type) {
	codec_def_t *ret = g_hash_table_lookup(codecs_ht, name);
	if (!ret)
		return NULL;
	if (type && type != ret->type)
		return NULL;
	return ret;
}

enum media_type codec_get_type(const str *type) {
	if (!type || !type->len)
		return MT_UNKNOWN;
	if (!str_cmp(type, "audio"))
		return MT_AUDIO;
	if (!str_cmp(type, "video"))
		return MT_VIDEO;
	if (!str_cmp(type, "image"))
		return MT_IMAGE;
	return MT_OTHER;
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

	AVCodec *codec = def->decoder;
//	AVCodec *codec = NULL;
//	if (def->decoder)
//		codec = def->decoder;
//	if (!codec && def->avcodec_name)
//		codec = avcodec_find_decoder_by_name(def->avcodec_name);
//	if (!codec && def->avcodec_id >= 0)
//		codec = avcodec_find_decoder(def->avcodec_id);
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
	if (!data || !data->s || !data->len)
		return 0;

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
void codeclib_init(int print) {
	av_register_all();
	avcodec_register_all();
	avfilter_register_all();
	avformat_network_init();
	av_log_set_callback(avlog_ilog);

	codecs_ht = g_hash_table_new(str_hash, str_equal);

	for (int i = 0; i < G_N_ELEMENTS(__codec_defs); i++) {
		// add to hash table
		codec_def_t *def = &__codec_defs[i];
		str_init(&def->rtpname_str, (char *) def->rtpname);
		assert(g_hash_table_lookup(codecs_ht, &def->rtpname_str) == NULL);
		g_hash_table_insert(codecs_ht, &def->rtpname_str, def);

		// init undefined member vars
		if (!def->clockrate_mult)
			def->clockrate_mult = 1;
		if (!def->default_ptime)
			def->default_ptime = -1;
		if (!def->default_clockrate)
			def->default_clockrate = -1;
		if (!def->default_channels)
			def->default_channels = -1;

		// init RFC-related info
		const struct rtp_payload_type *pt = rtp_get_rfc_codec(&def->rtpname_str);
		if (pt)
			def->rfc_payload_type = pt->payload_type;
		else
			def->rfc_payload_type = -1;

		// look up AVCodec structs
		if (def->avcodec_name) {
			def->encoder = avcodec_find_encoder_by_name(def->avcodec_name);
			def->decoder = avcodec_find_decoder_by_name(def->avcodec_name);
		}
		if (def->avcodec_id >= 0) {
			if (!def->encoder)
				def->encoder = avcodec_find_encoder(def->avcodec_id);
			if (!def->decoder)
				def->decoder = avcodec_find_decoder(def->avcodec_id);
		}
		// check if we have support if we are supposed to
		if (def->avcodec_name || def->avcodec_id >= 0) {
			if (print) {
				if (def->encoder && def->decoder)
					printf("%20s: fully supported\n", def->rtpname);
				else if (def->decoder)
					printf("%20s: supported for decoding only\n", def->rtpname);
				else if (def->encoder)
					printf("%20s: supported for encoding only\n", def->rtpname);
				else
					printf("%20s: not supported\n", def->rtpname);
			}
			else {
				if (!def->encoder && !def->decoder)
					ilog(LOG_DEBUG, "Codec %s is not supported by codec library",
							def->rtpname);
				else if (!def->encoder) {
					ilog(LOG_DEBUG, "Codec %s is only supported for decoding "
							"by codec library", def->rtpname);
				}
				else if (!def->decoder)
					ilog(LOG_DEBUG, "Codec %s is only supported for encoding "
							"by codec library", def->rtpname);
			}
		}
	}
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
	;
	u_int16_t l = packet->seq - ps->seq;
	ps->lost_count += l;

	g_tree_steal(ps->packets, GINT_TO_POINTER(packet->seq));
	ps->seq = (packet->seq + 1) & 0xffff;

	if (packet->seq < ps->ext_seq)
		ps->roc++;
	ps->ext_seq = ps->roc << 16 | packet->seq;

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

int encoder_config(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format)
{
	const char *err;

	// anything to do?
	if (G_LIKELY(format_eq(requested_format, &enc->requested_format)))
		goto done;

	encoder_close(enc);

	enc->requested_format = *requested_format;

	err = "output codec not found";
	enc->def = def;
	enc->codec = def->encoder;
//	if (codec_name)
//		enc->codec = avcodec_find_encoder_by_name(codec_name);
//	if (!enc->codec)
//		enc->codec = avcodec_find_encoder(codec_id);
	if (!enc->codec)
		goto err;

	ptime /= def->clockrate_mult;
	enc->ptime = ptime;

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
	enc->samples_per_frame = enc->actual_format.clockrate * ptime / 1000;

	if (def->set_options)
		def->set_options(enc);

	err = "failed to open output context";
	int i = avcodec_open2(enc->avcctx, enc->codec, NULL);
	if (i)
		goto err;

	av_init_packet(&enc->avpkt);


// output frame and fifo
	enc->frame = av_frame_alloc();
	enc->frame->nb_samples = enc->avcctx->frame_size ? : (enc->samples_per_frame ? : 256);
	enc->frame->format = enc->avcctx->sample_fmt;
	enc->frame->sample_rate = enc->avcctx->sample_rate;
	enc->frame->channel_layout = enc->avcctx->channel_layout;
	if (!enc->frame->channel_layout)
		enc->frame->channel_layout = av_get_default_channel_layout(enc->avcctx->channels);
	if (av_frame_get_buffer(enc->frame, 0) < 0)
		abort();

	enc->fifo = av_audio_fifo_alloc(enc->avcctx->sample_fmt, enc->avcctx->channels,
			enc->frame->nb_samples);

	ilog(LOG_DEBUG, "Initialized encoder with frame size %u samples", enc->frame->nb_samples);


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
	enc->codec = NULL;
	format_init(&enc->requested_format);
	format_init(&enc->actual_format);
	av_audio_fifo_free(enc->fifo);
	av_frame_free(&enc->frame);
	enc->mux_dts = 0;
	enc->fifo = NULL;
	enc->fifo_pts = 0;
}
void encoder_free(encoder_t *enc) {
	encoder_close(enc);
	g_slice_free1(sizeof(*enc), enc);
}

int encoder_input_data(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	if (G_UNLIKELY(!enc->avcctx))
		return -1;
	if (G_UNLIKELY(!enc->codec))
		return -1;

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

static int encoder_fifo_flush(encoder_t *enc,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	while (av_audio_fifo_size(enc->fifo) >= enc->frame->nb_samples) {

		if (av_audio_fifo_read(enc->fifo, (void **) enc->frame->data,
					enc->frame->nb_samples) <= 0)
			abort();

		dbg("output fifo pts %lu",(unsigned long) enc->fifo_pts);
		enc->frame->pts = enc->fifo_pts;

		encoder_input_data(enc, enc->frame, callback, u1, u2);

		enc->fifo_pts += enc->frame->nb_samples;
	}

	return 0;
}

int encoder_input_fifo(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	// fix up output pts
	if (av_audio_fifo_size(enc->fifo) == 0)
		enc->fifo_pts = frame->pts;

	if (av_audio_fifo_write(enc->fifo, (void **) frame->extended_data, frame->nb_samples) < 0)
		return -1;

	return encoder_fifo_flush(enc, callback, u1, u2);
}


int packetizer_passthrough(AVPacket *pkt, GString *buf, str *output) {
	if (!pkt)
		return -1;
	assert(output->len >= pkt->size);
	output->len = pkt->size;
	memcpy(output->s, pkt->data, pkt->size);
	return 0;
}

// returns: -1 = not enough data, nothing returned; 0 = returned a packet;
// 1 = returned a packet and there's more
int packetizer_samplestream(AVPacket *pkt, GString *buf, str *input_output) {
	// avoid moving buffers around if possible:
	// most common case: new input packet has just enough (or more) data as what we need
	if (G_LIKELY(pkt && buf->len == 0 && pkt->size >= input_output->len)) {
		memcpy(input_output->s, pkt->data, input_output->len);
		if (pkt->size > input_output->len) // any leftovers?
			g_string_append_len(buf, (char *) pkt->data + input_output->len,
					pkt->size - input_output->len);
		return buf->len >= input_output->len ? 1 : 0;
	}
	// we have to move data around. append input packet to buffer if we have one
	if (pkt)
		g_string_append_len(buf, (char *) pkt->data, pkt->size);
	// do we have enough?
	if (buf->len < input_output->len)
		return -1;
	// copy requested data into provided output buffer and remove from interim buffer
	memcpy(input_output->s, buf->str, input_output->len);
	g_string_erase(buf, 0, input_output->len);
	return buf->len >= input_output->len ? 1 : 0;
}


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

static void opus_set_options(encoder_t *enc) {
	int ret;
	if ((ret = av_opt_set_int(enc->avcctx, "frame_duration", enc->ptime, 0)))
		ilog(LOG_WARN, "Failed to set Opus frame_duration option (error code %i)", ret);
	// XXX additional opus options
}
