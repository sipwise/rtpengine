#include "codeclib.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <glib.h>
#include "str.h"
#include "log.h"
#include "loglib.h"
#include "resample.h"




#ifndef dbg
#ifdef __DEBUG
#define dbg(x...) ilog(LOG_DEBUG, x)
#else
#define dbg(x...) ((void)0)
#endif
#endif



struct decoder_s {
	format_t in_format,
		 out_format;

	resample_t mix_resample,
		   output_resample;

	AVCodecContext *avcctx;
	AVPacket avpkt;
	unsigned long rtp_ts;
	uint64_t pts;

	unsigned int mixer_idx;
};




#define CODEC_DEF_MULT_NAME(ref, id, mult, name) { \
	.rtpname = #ref, \
	.avcodec_id = AV_CODEC_ID_ ## id, \
	.clockrate_mult = mult, \
	.avcodec_name = #name, \
}
#define CODEC_DEF_MULT(ref, id, mult) CODEC_DEF_MULT_NAME(ref, id, mult, NULL)
#define CODEC_DEF_NAME(ref, id, name) CODEC_DEF_MULT_NAME(ref, id, 1, name)
#define CODEC_DEF(ref, id) CODEC_DEF_MULT(ref, id, 1)

static const struct codec_def_s codecs[] = {
	CODEC_DEF(PCMA, PCM_ALAW),
	CODEC_DEF(PCMU, PCM_MULAW),
	CODEC_DEF(G723, G723_1),
	CODEC_DEF_MULT(G722, ADPCM_G722, 2),
	CODEC_DEF(QCELP, QCELP),
	CODEC_DEF(G729, G729),
	CODEC_DEF(speex, SPEEX),
	CODEC_DEF(GSM, GSM),
	CODEC_DEF(iLBC, ILBC),
	CODEC_DEF_NAME(opus, OPUS, libopus),
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
	CODEC_DEF(AMR, AMR_NB),
	CODEC_DEF(AMR-WB, AMR_WB),
};



// XXX use hashtable for quicker lookup
const codec_def_t *codec_find(const str *name) {
	for (int i = 0; i < G_N_ELEMENTS(codecs); i++) {
		if (!str_cmp(name, codecs[i].rtpname))
			return &codecs[i];
	}
	return NULL;
}



decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, int resample) {
	const char *err = NULL;

	clockrate *= def->clockrate_mult;

	decoder_t *ret = g_slice_alloc0(sizeof(*ret));

	format_init(&ret->in_format);
	ret->in_format.channels = channels;
	ret->in_format.clockrate = clockrate;
	// output defaults to same as input
	ret->out_format = ret->in_format;
	if (resample)
		ret->out_format.clockrate = resample;
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
	resample_shutdown(&dec->mix_resample);
	resample_shutdown(&dec->output_resample);
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
		dec->pts += (ts - dec->rtp_ts);
		// XXX handle lost packets here if timestamps don't line up?
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

			if (callback(dec, frame, u1, u2))
				return -1;
			frame = NULL;
		}
	} while (keep_going);

	av_frame_free(&frame);
	return 0;

err:
	ilog(LOG_ERR, "Error decoding media packet: %s", err);
	av_frame_free(&frame);
	return -1;
}


void codeclib_init() {
	av_register_all();
	avcodec_register_all();
	avfilter_register_all();
	avformat_network_init();
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
	if (diff >= 0x8000)
		return -1;
	if (diff < 0 && diff > -0x8000)
		return -1;

	// seq ok - fall thru
seq_ok:
	if (g_tree_lookup(ps->packets, GINT_TO_POINTER(p->seq)))
		return -1;
	g_tree_insert(ps->packets, GINT_TO_POINTER(p->seq), p);

	return 0;
}
