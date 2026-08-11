#include "codeclib.h"
#include <glib.h>
#include <dlfcn.h>
#include "str.h"
#include "loglib.h"
#include "resample.h"
#include "rtplib.h"
#include "dtmflib.h"
#include "fix_frame_channel_layout.compat"
#include "codecmod.h"
#include "cchain.h"



#define PACKET_TS_RESET_THRES 5000 // milliseconds



#define cdbg(x...) ilogs(internals, LOG_DEBUG, x)



static int generic_silence_dtx(decoder_t *, frame_q *, int);

static int generic_cn_dtx_init(decoder_t *);
static void generic_cn_dtx_cleanup(decoder_t *);
static int generic_cn_dtx(decoder_t *, frame_q *, int);



const dtx_method_t dtx_method_silence = {
	.method_id = DTX_SILENCE,
	.do_dtx = generic_silence_dtx,
};
const dtx_method_t dtx_method_cn = {
	.method_id = DTX_CN,
	.do_dtx = generic_cn_dtx,
	.init = generic_cn_dtx_init,
	.cleanup = generic_cn_dtx_cleanup,
};

static struct codec_def_s *__codec_defs;
static unsigned int __num_codec_defs;

static GQueue __supplemental_codecs = G_QUEUE_INIT;
const GQueue * const codec_supplemental_codecs = &__supplemental_codecs;
static codec_def_t *codec_def_cn;
static codec_def_t *codec_def_pcm16;

void (*codeclib_thread_init)(void);
void (*codeclib_thread_cleanup)(void);
void (*codeclib_thread_loop)(void);


TYPED_GHASHTABLE(codecs_by_name, str, struct codec_def_s, str_case_hash, str_case_equal, NULL, NULL)

static codecs_by_name codecs_by_name_ht;



codec_def_t *codec_find(const str *name, enum media_type type) {
	codec_def_t *ret = t_hash_table_lookup(codecs_by_name_ht, name);
	if (!ret)
		return NULL;
	if (type && type != ret->media_type)
		return NULL;
	return ret;
}

codec_def_t *codec_get_pcm16(void) {
	return codec_def_pcm16;
}


decoder_t *decoder_new_fmt(codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt)
{
	return decoder_new_fmtp(def, clockrate, channels, ptime, resample_fmt, NULL, NULL, NULL);
}

bool codec_parse_fmtp(codec_def_t *def, struct rtp_codec_format *fmtp, const str *fmtp_string,
		union codec_format_options *copy)
{
	struct rtp_codec_format fmtp_store;

	if (copy)
		ZERO(*copy);

	if (!def)
		return false;
	if (!def->format_parse)
		return true;
	if (!fmtp) {
		ZERO(fmtp_store);
		fmtp = &fmtp_store;
	}
	if (fmtp->fmtp_parsed) {
		if (copy)
			*copy = fmtp->parsed;
		return true;
	}
	// Call format_parse even without fmtp_string so that codecs can populate defaults and set
	// fmtp_parsed = true (e.g. AMR with RFC 4867 defaults).
	bool ret = def->format_parse(fmtp, fmtp_string);
	if (ret) {
		fmtp->fmtp_parsed = true;
		if (copy)
			*copy = fmtp->parsed;
	}
	return ret;
}

decoder_t *decoder_new_fmtp(codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt,
		struct rtp_codec_format *fmtp, const str *fmtp_string,
		const str *extra_opts)
{
	const char *err;
	decoder_t *ret = NULL;

	err = "codec not supported";
	if (!def->codec_type)
		goto err;

	ret = g_new0(__typeof(*ret), 1);

	ret->def = def;
	ret->clockrate_fact = def->default_clockrate_fact;
	format_init(&ret->in_format);
	ret->in_format.channels = channels;
	ret->in_format.clockrate = clockrate;

	// output defaults to same as input
	ret->dest_format = ret->in_format;
	if (resample_fmt)
		ret->dest_format = *resample_fmt;

	err = "failed to parse \"fmtp\"";
	if (!codec_parse_fmtp(def, fmtp, fmtp_string, &ret->format_options))
		goto err;

	if (def->select_decoder_format)
		def->select_decoder_format(ret, fmtp);

	ret->in_format.clockrate = fraction_mult(ret->in_format.clockrate, &ret->clockrate_fact);
	ret->dec_out_format = ret->in_format;

	if (ptime > 0)
		ret->ptime = ptime;
	else
		ret->ptime = def->default_ptime;

	// init with first supported DTX method
	enum dtx_method dm = -1;
	for (int i = 0; i < NUM_DTX_METHODS; i++) {
		if (def->dtx_methods[i]) {
			dm = i;
			break;
		}
	}

	err = def->codec_type->decoder_init(ret, extra_opts);
	if (err)
		goto err;

	ret->pts = (uint64_t) -1LL;
	ret->rtp_ts = (unsigned long) -1L;

	decoder_switch_dtx(ret, dm);

	return ret;

err:
	if (ret)
		decoder_close(ret);
	if (err)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error creating media decoder for codec %s: %s", def->rtpname, err);
	return NULL;
}


int decoder_switch_dtx(decoder_t *dec, enum dtx_method dm) {
	if (dec->dtx.cleanup)
		dec->dtx.cleanup(dec);
	ZERO(dec->dtx);
	unsigned int i = dm;
	if (i >= NUM_DTX_METHODS)
		return -1;
	const dtx_method_t *dmp = dec->def->dtx_methods[i];
	if (!dmp)
		return -1;
	dec->dtx = *dmp;
	if (dmp->init) {
		if (dmp->init(dec)) {
			ilog(LOG_ERR, "Failed to initialise DTX (%u)", i);
			decoder_switch_dtx(dec, -1);
			return -1;
		}
	}
	return 0;
}

int decoder_set_cn_dtx(decoder_t *dec, const str *cn_pl) {
	if (decoder_switch_dtx(dec, DTX_CN))
		return -1;
	dec->dtx.cn.cn_payload = cn_pl;
	return 0;
}


gboolean decoder_has_dtx(decoder_t *dec) {
	return dec->dtx.do_dtx == NULL ? FALSE : TRUE;
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs

	if (dec->def && dec->def->codec_type && dec->def->codec_type->decoder_close)
		dec->def->codec_type->decoder_close(dec);

	decoder_switch_dtx(dec, -1);

	resample_shutdown(&dec->resampler);
	g_free(dec);
}


static int __decoder_input_data(decoder_t *dec, const str *data, unsigned long ts, int *ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	frame_q frames = TYPED_GQUEUE_INIT;

	if (G_UNLIKELY(!dec))
		return -1;

	if (!data && (!dec->dtx.do_dtx || !ptime))
		return 0;

	ts = fraction_mult(ts, &dec->clockrate_fact);

	cdbg("%p dec pts %llu rtp_ts %llu incoming ts %lu", dec, (unsigned long long) dec->pts,
			(unsigned long long) dec->rtp_ts, (unsigned long) ts);

	if (G_UNLIKELY(dec->rtp_ts == (unsigned long) -1L)) {
		// initialize pts
		dec->pts = 0;
	}
	else {
		// shift pts according to rtp ts shift
		uint64_t shift_ts = ts - dec->rtp_ts;
		if ((shift_ts * 1000) / dec->in_format.clockrate > PACKET_TS_RESET_THRES) {
			ilog(LOG_DEBUG, "Timestamp discontinuity detected, resetting timestamp from "
					"%lu to %lu",
					dec->rtp_ts, ts);
			// XXX handle lost packets here if timestamps don't line up?
		}
		else
			dec->pts += shift_ts;
	}
	dec->rtp_ts = ts;

	if (data)
		dec->def->codec_type->decoder_input(dec, data, &frames);
	else
		dec->dtx.do_dtx(dec, &frames, *ptime);

	AVFrame *frame;
	int ret = 0;
	unsigned long samples = 0;
	while ((frame = t_queue_pop_head(&frames))) {
		samples += frame->nb_samples;
		dec->dec_out_format.format = frame->format;
		AVFrame *rsmp_frame = resample_frame(&dec->resampler, frame, &dec->dest_format);
		if (!rsmp_frame) {
			ilog(LOG_ERR | LOG_FLAG_LIMIT, "Resampling failed");
			ret = -1;
		}
		else {
			if (callback(dec, rsmp_frame, u1, u2))
				ret = -1;
		}
		if (rsmp_frame != frame)
			av_frame_free(&frame);
	}

	if (ptime)
		*ptime = samples * 1000L / dec->in_format.clockrate;

	return ret;
}
int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	if (!data || !data->s || !data->len)
		return 0;
	return __decoder_input_data(dec, data, ts, NULL, callback, u1, u2);
}
int decoder_input_data_ptime(decoder_t *dec, const str *data, unsigned long ts, int *ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	if (!data || !data->s || !data->len)
		return 0;
	return __decoder_input_data(dec, data, ts, ptime, callback, u1, u2);
}
int decoder_dtx(decoder_t *dec, unsigned long ts, int ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	return __decoder_input_data(dec, NULL, ts, &ptime, callback, u1, u2);
}


void codeclib_free(void) {
	t_hash_table_destroy(codecs_by_name_ht);
	cc_cleanup();
}


bool rtpe_has_cpu_flag(enum rtpe_cpu_flag flag) {
	static bool done = false;
	static bool cpu_flags[__NUM_RTPE_CPU_FLAGS] = {false,};

	if (!done) {
#if defined(__x86_64__)
		int32_t ebx_7h0h, edx_1h;

		__asm (
			"mov $1, %%eax"		"\n\t"
			"cpuid"			"\n\t"
			"mov %%edx, %1"		"\n\t"
			"mov $7, %%eax"		"\n\t"
			"xor %%ecx, %%ecx"	"\n\t"
			"cpuid"			"\n\t"
			"mov %%ebx, %0"		"\n\t"
			: "=rm" (ebx_7h0h), "=rm" (edx_1h)
			:
			: "eax", "ebx", "ecx", "edx"
		    );

		cpu_flags[RTPE_CPU_FLAG_SSE2]      = !!(edx_1h   & (1L << 26));
		cpu_flags[RTPE_CPU_FLAG_AVX2]      = !!(ebx_7h0h & (1L << 5));
		cpu_flags[RTPE_CPU_FLAG_AVX512BW]  = !!(ebx_7h0h & (1L << 30));
		cpu_flags[RTPE_CPU_FLAG_AVX512F]   = !!(ebx_7h0h & (1L << 16));
#endif

		done = true;
	}

	if (flag < 0 || flag >= __NUM_RTPE_CPU_FLAGS)
		abort();

	return cpu_flags[flag];
}


void *dlsym_assert(void *handle, const char *sym, const char *fn) {
	void *ret = dlsym(handle, sym);
	if (!ret)
		die("Failed to resolve symbol '%s' from '%s': %s", sym, fn, dlerror());
	return ret;
}



void codeclib_register_codec(const codec_def_t *c) {
	struct codec_def_s *n = realloc(__codec_defs, sizeof(*__codec_defs) * (__num_codec_defs + 1));
	if (!n) {
		fprintf(stderr, "Out of memory initialising codecs\n");
		abort();
	}

	__codec_defs = n;

	memcpy(&__codec_defs[__num_codec_defs], c, sizeof(*c));

	__num_codec_defs++;
}


void codeclib_init(int print) {
	codecs_by_name_ht = codecs_by_name_new();
	avc_init();
	cc_init();

	for (unsigned int i = 0; i < __num_codec_defs; i++) {
		// add to hash table
		struct codec_def_s *def = &__codec_defs[i];
		def->rtpname_str = STR(def->rtpname);
		assert(t_hash_table_lookup(codecs_by_name_ht, &def->rtpname_str) == NULL);
		t_hash_table_insert(codecs_by_name_ht, &def->rtpname_str, def);

		// init undefined member vars
		if (!def->default_clockrate_fact.mult)
			def->default_clockrate_fact.mult = 1;
		if (!def->default_clockrate_fact.div)
			def->default_clockrate_fact.div = 1;
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
		else {
			// special case:
			if (!strcmp(def->rtpname, "G729a"))
				def->rfc_payload_type = 18;
			else
				def->rfc_payload_type = -1;
		}

		if (def->codec_type && def->codec_type->def_init)
			def->codec_type->def_init(def);

		if (!strcmp(def->rtpname, "CN"))
			codec_def_cn = def;
		if (def->avcodec_id == AV_CODEC_ID_PCM_S16LE)
			codec_def_pcm16 = def;

		if (print) {
			if (def->support_encoding && def->support_decoding) {
				if (def->default_channels > 0 && def->default_clockrate >= 0)
					printf("%20s: fully supported\n", def->rtpname);
				else
					printf("%20s: codec supported but lacks RTP definition\n", def->rtpname);
			}
			else if (def->support_decoding)
				printf("%20s: supported for decoding only\n", def->rtpname);
			else if (def->support_encoding)
				printf("%20s: supported for encoding only\n", def->rtpname);
			else
				printf("%20s: not supported\n", def->rtpname);
		}
		else {
			if (!def->support_encoding && !def->support_decoding)
				ilog(LOG_DEBUG, "Codec %s is not supported by codec library",
						def->rtpname);
			else if (!def->support_encoding) {
				ilog(LOG_DEBUG, "Codec %s is only supported for decoding "
						"by codec library", def->rtpname);
			}
			else if (!def->support_decoding)
				ilog(LOG_DEBUG, "Codec %s is only supported for encoding "
						"by codec library", def->rtpname);
		}

		if (def->supplemental)
			g_queue_push_tail(&__supplemental_codecs, def);

		if (rtpe_common_config_ptr->mos_type) {
			def->mos_type = rtpe_common_config_ptr->mos_type;
			if (def->mos_type == MOS_FB && def->default_clockrate != 48000)
				def->mos_type = MOS_NB;
		}
	}
}






void packet_sequencer_init(packet_sequencer_t *ps, void (*ffunc)(seq_packet_t *)) {
	ps->free_func = ffunc;
	ps->a_seq = -1u;
	ps->a_nxt = -1u;
}
static void sequencer_packets_clear(packet_sequencer_t *ps) {
	for (unsigned int i = 0; i < G_N_ELEMENTS(ps->packets); i++) {
		if (ps->packets[i])
			ps->free_func(ps->packets[i]);
		ps->packets[i] = NULL;
	}
	ps->n_pks = 0;
	ps->a_nxt = -1u;
}
void packet_sequencer_destroy(packet_sequencer_t *ps) {
	sequencer_packets_clear(ps);
}
// caller must take care of locking
static void *__packet_sequencer_next_packet(packet_sequencer_t *ps, unsigned int num_wait) {
	// see if we have a packet with the correct seq nr in the queue
	unsigned int ix;
	seq_packet_t *packet = ps->packets[ps->a_idx];
	if (G_LIKELY(packet != NULL)) {
		cdbg("returning in-sequence packet (seq %i)", ps->a_seq);
		ix = ps->a_idx;
		goto out;
	}

	// why not? do we have anything? (we should)
	if (G_UNLIKELY(ps->n_pks == 0)) {
		cdbg("packet queue empty");
		return NULL;
	}
	if (G_LIKELY(ps->n_pks < num_wait)) {
		cdbg("only %i packets in queue - waiting for more", ps->n_pks);
		return NULL; // need to wait for more
	}

	// packet was probably lost. search for the next highest seq
	if (ps->a_nxt != -1u) {
		ix = ps->a_nxt;
		packet = ps->packets[ix];
		cdbg("lost packet - returning packet with next seq %i", packet->seq);
		goto out;
	}

	for (unsigned int i = 0; i < G_N_ELEMENTS(ps->packets); i++) {
		ix = (ps->a_idx + i) % G_N_ELEMENTS(ps->packets);
		if (ps->packets[ix]) {
			packet = ps->packets[ix];
			cdbg("lost packet - returning packet with next seq %i", packet->seq);
			goto out;
		}
	}

	abort();

out:;
	uint16_t l = packet->seq - ps->a_seq;
	ps->lost_count += l;

	ps->packets[ix] = NULL;
	ps->n_pks--;
	ps->a_seq = (packet->seq + 1) & 0xffff;
	ps->a_idx = (ix + 1) % G_N_ELEMENTS(ps->packets);
	if (ps->a_nxt == ix)
		ps->a_nxt = -1u;

	unsigned int ext_seq = ps->roc << 16 | packet->seq;
	while (ext_seq < ps->ext_seq) {
		ps->roc++;
		ext_seq += 0x10000;
	}
	ps->ext_seq = ext_seq;

	return packet;
}
void *packet_sequencer_next_packet(packet_sequencer_t *ps) {
	return __packet_sequencer_next_packet(ps, 10); // arbitrary value
}
void *packet_sequencer_force_next_packet(packet_sequencer_t *ps) {
	return __packet_sequencer_next_packet(ps, 0);
}

bool packet_sequencer_next_ok(packet_sequencer_t *ps) {
	if (ps->packets[ps->a_idx])
		return true;
	return false;
}

int packet_sequencer_insert(packet_sequencer_t *ps, seq_packet_t *p) {
	int ret = 0;

	// check seq for dupes
	if (G_UNLIKELY(ps->a_seq == -1u)) {
		// first packet we see
		ps->a_seq = p->seq;
		goto seq_ok;
	}

	int diff = p->seq - ps->a_seq;
	// early packet: p->seq = 200, ps->a_seq = 150, diff = 50
	// or exact match: p->seq = 200, ps->a_seq = 200, diff = 0
	if (G_LIKELY(diff >= 0 && diff < G_N_ELEMENTS(ps->packets)))
		goto seq_ok;
	// early packet with wrap-around: p->seq = 20, ps->a_seq = 65530, diff = -65510
	if (diff < (-0xffff + (signed) G_N_ELEMENTS(ps->packets)))
		goto seq_ok;
	// recent duplicate: p->seq = 1000, ps->seq = 1080, diff = -80
	if (diff < 0 && diff > -(signed) G_N_ELEMENTS(ps->packets))
		return -1;
	// recent duplicate after wrap-around: p->seq = 65530, ps->seq = 30, diff = 65500
	if (diff > (0xffff - (signed) G_N_ELEMENTS(ps->packets)))
		return -1;

	// everything else we consider a seq reset
	ilog(LOG_DEBUG, "Seq reset detected: expected seq %i, received seq %i", ps->a_seq, p->seq);
	ps->a_seq = p->seq;
	ret = 1;
	sequencer_packets_clear(ps);
	// seq ok - fall through
seq_ok:;
	// slot of this packet
	unsigned int idx = (ps->a_idx + p->seq - ps->a_seq) % G_N_ELEMENTS(ps->packets);
	// packet already present?
	if (ps->packets[idx])
		return -1;

	if (ps->a_idx != idx)
		ret = 2; // indicates an out-of-order packet

	// if not set
	if (ps->a_nxt == -1u)
		ps->a_nxt = idx;
	// or if new idx is less than a_nxt
	else if ((ps->a_nxt - ps->a_idx) % G_N_ELEMENTS(ps->packets)
			> (idx - ps->a_idx) % G_N_ELEMENTS(ps->packets))
		ps->a_nxt = idx;

	ps->packets[idx] = p;
	ps->n_pks++;

	return ret;
}




encoder_t *encoder_new(void) {
	encoder_t *ret = g_new0(__typeof(*ret), 1);
	format_init(&ret->requested_format);
	format_init(&ret->actual_format);
	ret->avpkt = av_packet_alloc();
	return ret;
}


int encoder_config(encoder_t *enc, codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format)
{
	return encoder_config_fmtp(enc, def, bitrate, ptime, NULL, requested_format, actual_format,
			NULL, NULL, NULL);
}

int encoder_config_fmtp(encoder_t *enc, codec_def_t *def, int bitrate, int ptime,
		const format_t *input_format,
		const format_t *requested_format_p, format_t *actual_format,
		struct rtp_codec_format *fmtp, const str *fmtp_string,
		const str *extra_opts)
{
	const char *err;

	err = "codec not supported";
	if (!def->codec_type)
		goto err;

	err = "failed to parse \"fmtp\"";
	if (!codec_parse_fmtp(def, fmtp, fmtp_string, &enc->format_options))
		goto err;

	// select encoder format
	format_t requested_format = *requested_format_p;
	enc->clockrate_fact = def->default_clockrate_fact;
	if (def->select_encoder_format)
		def->select_encoder_format(enc, &requested_format, input_format, fmtp);

	requested_format.clockrate = fraction_mult(requested_format.clockrate, &enc->clockrate_fact);

	// anything to do?
	if (G_LIKELY(format_eq(&requested_format, &enc->requested_format))) {
		if (!input_format)
			goto done;
		if (G_LIKELY(format_eq(input_format, &enc->input_format)))
			goto done;
	}

	encoder_close(enc);

	if (ptime <= 0)
		ptime = 20;
	if (def->minimum_ptime && ptime < def->minimum_ptime)
		ptime = def->minimum_ptime;

	enc->requested_format = requested_format;
	if (input_format)
		enc->input_format = *input_format;
	else
		format_init(&enc->input_format);
	enc->def = def;
	enc->ptime = ptime;
	enc->bitrate = bitrate;

	err = def->codec_type->encoder_init ? def->codec_type->encoder_init(enc, extra_opts) : 0;
	if (err)
		goto err;

// output frame and fifo
	enc->frame = av_frame_alloc();

	if (enc->actual_format.format != -1 && enc->actual_format.clockrate > 0) {
		enc->frame->nb_samples = enc->samples_per_frame ? : 256;
		enc->frame->format = enc->actual_format.format;
		enc->frame->sample_rate = enc->actual_format.clockrate;
		DEF_CH_LAYOUT(&enc->frame->CH_LAYOUT, enc->actual_format.channels);
		if (av_frame_get_buffer(enc->frame, 0) < 0)
			abort();

		enc->fifo = av_audio_fifo_alloc(enc->frame->format, enc->actual_format.channels,
				enc->frame->nb_samples);

		ilog(LOG_DEBUG, "Initialized encoder with frame size %u samples", enc->frame->nb_samples);
	}
	else
		ilog(LOG_DEBUG, "Initialized encoder without frame buffer");


done:
	if (actual_format)
		*actual_format = enc->actual_format;
	return 0;

err:
	encoder_close(enc);
	ilog(LOG_ERR, "Error configuring media output for codec %s: %s", def->rtpname, err);
	return -1;
}


void encoder_close(encoder_t *enc) {
	if (!enc)
		return;
	if (enc->def && enc->def->codec_type && enc->def->codec_type->encoder_close)
		enc->def->codec_type->encoder_close(enc);
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
	av_packet_free(&enc->avpkt);
	resample_shutdown(&enc->resampler);
	g_free(enc);
}


int encoder_input_data(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	enc->avpkt->size = 0;

	while (1) {
		if (!enc->def || !enc->def->codec_type)
			break;
		if (!enc->def->codec_type->encoder_input)
			break;

		int ret = enc->def->codec_type->encoder_input(enc, &frame);
		if (ret < 0)
			return -1;

		if (enc->avpkt->size) {
			// don't rely on the encoder producing steady timestamps,
			// instead keep track of them ourselves based on the returned
			// frame duration
			enc->avpkt->pts = enc->next_pts;

			if (enc->def->codec_type->encoder_got_packet)
				enc->def->codec_type->encoder_got_packet(enc);

			callback(enc, u1, u2);

			enc->next_pts += enc->avpkt->duration;
			enc->mux_dts = enc->avpkt->dts + 1; // min next expected dts

			av_packet_unref(enc->avpkt);
			enc->avpkt->size = 0;
		}

		if (ret == 0)
			break;
	}

	return 0;
}

static int encoder_fifo_flush(encoder_t *enc,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	while (av_audio_fifo_size(enc->fifo) >= enc->frame->nb_samples) {

		if (av_audio_fifo_read(enc->fifo, (void **) enc->frame->data,
					enc->frame->nb_samples) <= 0)
			abort();

		cdbg("output fifo pts %lu",(unsigned long) enc->fifo_pts);
		enc->frame->pts = enc->fifo_pts;

		encoder_input_data(enc, enc->frame, callback, u1, u2);

		enc->fifo_pts += enc->frame->nb_samples;
	}

	return 0;
}

int encoder_input_fifo(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2)
{
	AVFrame *rsmp_frame = resample_frame(&enc->resampler, frame, &enc->actual_format);
	if (!rsmp_frame) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Resampling failed");
		return -1;
	}
	if (av_audio_fifo_write(enc->fifo, (void **) rsmp_frame->extended_data, rsmp_frame->nb_samples) < 0)
		return -1;
	if (rsmp_frame != frame)
		av_frame_free(&rsmp_frame);

	return encoder_fifo_flush(enc, callback, u1, u2);
}


int packetizer_passthrough(AVPacket *pkt, GString *buf, str *output, size_t num_bytes, encoder_t *enc,
		int64_t *__restrict pts, int64_t *__restrict duration)
{
	if (!pkt)
		return -1;
	if (output->len < pkt->size) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Output packet size too small (%zu < %i)",
				output->len, pkt->size);
		return -1;
	}
	output->len = pkt->size;
	memcpy(output->s, pkt->data, pkt->size);
	*pts = pkt->pts;
	*duration = pkt->duration;
	return 0;
}

// returns: -1 = not enough data, nothing returned; 0 = returned a packet;
// 1 = returned a packet and there's more
int packetizer_samplestream(AVPacket *pkt, GString *buf, str *input_output, size_t num_bytes,
		encoder_t *enc, int64_t *__restrict pts, int64_t *__restrict duration)
{
	// avoid moving buffers around if possible:
	// most common case: new input packet has just enough (or more) data as what we need
	if (G_LIKELY(pkt && buf->len == 0 && pkt->size >= num_bytes)) {
		*pts = pkt->pts;
		*duration = pkt->duration;
		memcpy(input_output->s, pkt->data, num_bytes);
		// any leftovers?
		if (pkt->size > num_bytes) {
			g_string_append_len(buf, (char *) pkt->data + num_bytes,
					pkt->size - num_bytes);
			*duration = fraction_mult(num_bytes * 8, &enc->clockrate_fact)
				/ enc->def->bits_per_sample;
			enc->packet_pts = pkt->pts + *duration;
		}
		input_output->len = num_bytes;
		return buf->len >= num_bytes ? 1 : 0;
	}
	// we have to move data around. append input packet to buffer if we have one
	if (pkt)
		g_string_append_len(buf, (char *) pkt->data, pkt->size);
	// do we have enough?
	if (buf->len < num_bytes)
		return -1;
	// copy requested data into provided output buffer and remove from interim buffer
	memcpy(input_output->s, buf->str, num_bytes);
	input_output->len = num_bytes;
	g_string_erase(buf, 0, num_bytes);
	// adjust output pts
	*pts = enc->packet_pts;
	*duration = fraction_mult(num_bytes * 8, &enc->clockrate_fact) / enc->def->bits_per_sample;
	enc->packet_pts += *duration;
	return buf->len >= num_bytes ? 1 : 0;
}


void codeclib_key_value_parse(const str *instr, bool need_value,
		void (*cb)(str *key, str *value, void *data), void *data)
{
	if (!instr || !instr->s)
		return;

	// semicolon-separated key=value
	str s = *instr;
	str key, value;
	while (str_token_sep(&value, &s, ';')) {
		if (!str_token(&key, &value, '=')) {
			if (need_value)
				continue;
			value = STR_NULL;
		}

		// truncate whitespace
		while (key.len && key.s[0] == ' ')
			str_shift(&key, 1);
		while (key.len && key.s[key.len - 1] == ' ')
			key.len--;
		while (value.len && value.s[0] == ' ')
			str_shift(&value, 1);
		while (value.len && value.s[value.len - 1] == ' ')
			value.len--;

		if (key.len == 0)
			continue;

		cb(&key, &value, data);
	}

}



static int generic_silence_dtx(decoder_t *dec, frame_q *out, int ptime) {
	if (dec->dec_out_format.format == -1)
		return -1;
	if (!dec->avc.avpkt)
		return -1;

	if (ptime <= 0)
		ptime = 20;
	int num_samples = ptime * dec->in_format.clockrate / 1000;
	ilog(LOG_DEBUG, "pushing %i silence samples into %s decoder", num_samples, dec->def->rtpname);

	// create dummy frame, fill with silence, pretend it was returned from the decoder
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = num_samples;
	frame->format = dec->dec_out_format.format;
	frame->sample_rate = dec->dec_out_format.clockrate;
	DEF_CH_LAYOUT(&frame->CH_LAYOUT, dec->dec_out_format.channels);
	if (av_frame_get_buffer(frame, 0) < 0) {
		av_frame_free(&frame);
		return -1;
	}

	memset(frame->extended_data[0], 0, frame->linesize[0]);

	// advance PTS
	frame->pts = dec->avc.avpkt->pts;
	dec->avc.avpkt->pts += frame->nb_samples;

	t_queue_push_tail(out, frame);

	return 0;
}


static int cn_append_frame(decoder_t *dec, AVFrame *f, void *u1, void *u2) {
	GQueue *out = u1;
	g_queue_push_tail(out, f);
	return 0;
}

static int generic_cn_dtx(decoder_t *dec, frame_q *out, int ptime) {
	dec->dtx.cn.cn_dec->ptime = ptime;
	return decoder_input_data(dec->dtx.cn.cn_dec, dec->dtx.cn.cn_payload,
			dec->rtp_ts, cn_append_frame, out, NULL);
}

static int generic_cn_dtx_init(decoder_t *dec) {
	// upsample CN output to same params as output of parent codec
	format_t cn_format = dec->dest_format;
	cn_format.channels = dec->in_format.channels;
	cn_format.clockrate = dec->in_format.clockrate;
	dec->dtx.cn.cn_dec = decoder_new_fmt(codec_def_cn, 8000, 1, dec->ptime, &cn_format);
	return 0;
}

static void generic_cn_dtx_cleanup(decoder_t *dec) {
	decoder_close(dec->dtx.cn.cn_dec);
}




int format_cmp_ignore(const struct rtp_payload_type *a, const struct rtp_payload_type *b) {
	return 0;
}


void frame_fill_tone_samples(enum AVSampleFormat fmt, void *samples, unsigned int offset, unsigned int num,
		unsigned int freq, unsigned int volume, unsigned int sample_rate, unsigned int channels)
{
	switch (fmt) {
		case AV_SAMPLE_FMT_S16:
			tone_samples_int16_t(samples, offset, num, freq, volume, sample_rate, channels);
			break;
		case AV_SAMPLE_FMT_S32:
			tone_samples_int32_t(samples, offset, num, freq, volume, sample_rate, channels);
			break;
		case AV_SAMPLE_FMT_DBL:
			tone_samples_double(samples, offset, num, freq, volume, sample_rate, channels);
			break;
		case AV_SAMPLE_FMT_FLT:
			tone_samples_float(samples, offset, num, freq, volume, sample_rate, channels);
			break;
		default:
			ilog(LOG_ERR | LOG_FLAG_LIMIT, "Unsupported sample format %u", fmt);
			break;
	}
}

void frame_fill_dtmf_samples(enum AVSampleFormat fmt, void *samples, unsigned int offset, unsigned int num,
		unsigned int event, unsigned int volume, unsigned int sample_rate, unsigned int channels)
{
	switch (fmt) {
		case AV_SAMPLE_FMT_S16:
			dtmf_samples_int16_t(samples, offset, num, event, volume, sample_rate, channels);
			break;
		case AV_SAMPLE_FMT_S32:
			dtmf_samples_int32_t(samples, offset, num, event, volume, sample_rate, channels);
			break;
		case AV_SAMPLE_FMT_DBL:
			dtmf_samples_double(samples, offset, num, event, volume, sample_rate, channels);
			break;
		case AV_SAMPLE_FMT_FLT:
			dtmf_samples_float(samples, offset, num, event, volume, sample_rate, channels);
			break;
		default:
			ilog(LOG_ERR | LOG_FLAG_LIMIT, "Unsupported sample format %u", fmt);
			break;
	}
}
