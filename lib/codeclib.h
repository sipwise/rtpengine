#ifndef __CODECLIB_H__
#define __CODECLIB_H__


struct codec_def_s;
typedef struct codec_def_s codec_def_t;


#ifndef WITHOUT_CODECLIB



#include <libswresample/swresample.h>
#include <libavcodec/avcodec.h>
#include <libavutil/audio_fifo.h>
#ifdef HAVE_BCG729
#include <bcg729/encoder.h>
#include <bcg729/decoder.h>
#endif
#include "str.h"



struct codec_type_s;
struct decoder_s;
struct encoder_s;
struct format_s;
struct resample_s;
struct seq_packet_s;
struct packet_sequencer_s;
struct rtp_payload_type;
union codec_options_u;

typedef struct codec_type_s codec_type_t;
typedef struct decoder_s decoder_t;
typedef struct encoder_s encoder_t;
typedef struct format_s format_t;
typedef struct resample_s resample_t;
typedef struct seq_packet_s seq_packet_t;
typedef struct packet_sequencer_s packet_sequencer_t;
typedef union codec_options_u codec_options_t;

typedef int packetizer_f(AVPacket *, GString *, str *, encoder_t *);
typedef void format_init_f(struct rtp_payload_type *);
typedef void set_enc_options_f(encoder_t *, const str *);
typedef void set_dec_options_f(decoder_t *, const str *);



enum media_type {
	MT_UNKNOWN = 0,
	MT_AUDIO,
	MT_VIDEO,
	MT_IMAGE,
	MT_OTHER,
};

struct codec_type_s {
	void (*def_init)(codec_def_t *);

	const char *(*decoder_init)(decoder_t *, const str *);
	int (*decoder_input)(decoder_t *, const str *data, GQueue *);
	void (*decoder_close)(decoder_t *);

	const char *(*encoder_init)(encoder_t *, const str *);
	int (*encoder_input)(encoder_t *, AVFrame **);
	void (*encoder_close)(encoder_t *);
};

union codec_options_u {
	struct {
		int interleaving;
		int octet_aligned:1;
		int crc:1;
		int robust_sorting:1;

		const unsigned int *bits_per_frame;
	} amr;
};

struct codec_def_s {
	const char * const rtpname;
	int clockrate_mult;
	const int avcodec_id;
	const char * const avcodec_name;
	int default_clockrate;
	int default_channels;
	const int default_bitrate;
	int default_ptime;
	const char *default_fmtp;
	packetizer_f * const packetizer;
	const int bits_per_sample;
	const enum media_type media_type;

	// codec-specific callbacks
	format_init_f *init;
	set_enc_options_f *set_enc_options;
	set_dec_options_f *set_dec_options;

	// filled in by codeclib_init()
	str rtpname_str;
	int rfc_payload_type;
	int support_encoding:1,
	    support_decoding:1;

	// flags
	int pseudocodec:1,
	    dtmf:1; // special case

	const codec_type_t *codec_type;

	// libavcodec
	AVCodec *encoder;
	AVCodec *decoder;
};

struct format_s {
	int clockrate;
	int channels;
	int format; // enum AVSampleFormat
};

struct resample_s {
	SwrContext *swresample;
};

struct decoder_s {
	const codec_def_t *def;
	codec_options_t codec_options;

	format_t in_format,
		 out_format;

	resample_t resampler,
		   mix_resampler; // XXX move this out of here - specific to recording-daemon

	union {
		struct {
			AVCodecContext *avcctx;
			AVPacket avpkt;
		} avc;
#ifdef HAVE_BCG729
		bcg729DecoderChannelContextStruct *bcg729;
#endif
	} u;

	unsigned long rtp_ts;
	uint64_t pts;

	unsigned int mixer_idx;
};

struct encoder_s {
	format_t requested_format,
		 actual_format;

	const codec_def_t *def;
	codec_options_t codec_options;

	union {
		struct {
			AVCodec *codec;
			AVCodecContext *avcctx;
		} avc;
#ifdef HAVE_BCG729
		bcg729EncoderChannelContextStruct *bcg729;
#endif
	} u;
	AVPacket avpkt;
	AVAudioFifo *fifo;
	int64_t fifo_pts; // pts of first data in fifo
	int ptime;
	int bitrate;
	int samples_per_frame; // for encoding
	int samples_per_packet; // for frame packetizer
	AVFrame *frame; // to pull samples from the fifo
	int64_t mux_dts; // last dts passed to muxer
};

struct seq_packet_s {
	int seq;
};
struct packet_sequencer_s {
	GTree *packets;
	unsigned int lost_count;
	int seq; // next expected
	unsigned int ext_seq; // last received
	int roc; // rollover counter XXX duplicate with SRTP encryption context
};



void codeclib_init(int);


const codec_def_t *codec_find(const str *name, enum media_type);
enum media_type codec_get_type(const str *type);


decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, const format_t *resample_fmt);
decoder_t *decoder_new_fmtp(const codec_def_t *def, int clockrate, int channels, const format_t *resample_fmt,
		const str *fmtp);
void decoder_close(decoder_t *dec);
int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2);


encoder_t *encoder_new();
int encoder_config(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format);
int encoder_config_fmtp(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format, const str *fmtp);
void encoder_close(encoder_t *);
void encoder_free(encoder_t *);
int encoder_input_data(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2);
int encoder_input_fifo(encoder_t *enc, AVFrame *frame,
		int (*callback)(encoder_t *, void *u1, void *u2), void *u1, void *u2);


void __packet_sequencer_init(packet_sequencer_t *ps, GDestroyNotify);
INLINE void packet_sequencer_init(packet_sequencer_t *ps, GDestroyNotify);
void packet_sequencer_destroy(packet_sequencer_t *ps);
void *packet_sequencer_next_packet(packet_sequencer_t *ps);
void *packet_sequencer_force_next_packet(packet_sequencer_t *ps);
int packet_sequencer_insert(packet_sequencer_t *ps, seq_packet_t *);



// `ps` must be zero allocated
INLINE void packet_sequencer_init(packet_sequencer_t *ps, GDestroyNotify n) {
	if (ps->packets)
		return;
	__packet_sequencer_init(ps, n);
}
INLINE int format_eq(const format_t *a, const format_t *b) {
	if (G_UNLIKELY(a->clockrate != b->clockrate))
		return 0;
	if (G_UNLIKELY(a->channels != b->channels))
		return 0;
	if (G_UNLIKELY(a->format != b->format))
		return 0;
	return 1;
}
INLINE void format_init(format_t *f) {
	f->clockrate = -1;
	f->channels = -1;
	f->format = -1;
}


#else

// stubs
enum media_type {
	MT_INVALID = -1,
};
struct codec_def_s {
};

INLINE void codeclib_init(int print) {
	if (print)
		printf("No codecs supported.\n");
}

INLINE enum media_type codec_get_type(const str *type) {
	return -1;
}
INLINE const codec_def_t *codec_find(const str *name, enum media_type type) {
	return NULL;
}


#endif
#endif
