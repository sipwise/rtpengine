#ifndef __CODECLIB_H__
#define __CODECLIB_H__


struct codec_def_s;
struct packet_sequencer_s;
typedef struct codec_def_s codec_def_t;
typedef struct packet_sequencer_s packet_sequencer_t;

enum media_type {
	MT_UNKNOWN = 0,
	MT_AUDIO,
	MT_VIDEO,
	MT_IMAGE,
	MT_MESSAGE,
	MT_OTHER,
};


#include "str.h"

INLINE enum media_type codec_get_type(const str *type) {
	if (!type || !type->len)
		return MT_UNKNOWN;
	if (!str_cmp(type, "audio"))
		return MT_AUDIO;
	if (!str_cmp(type, "video"))
		return MT_VIDEO;
	if (!str_cmp(type, "image"))
		return MT_IMAGE;
	if (!str_cmp(type, "message"))
		return MT_MESSAGE;
	return MT_OTHER;
}


#ifndef WITHOUT_CODECLIB



#include <stdbool.h>
#include <libswresample/swresample.h>
#include <libavcodec/avcodec.h>
#include <libavutil/audio_fifo.h>
#ifdef HAVE_BCG729
#include <bcg729/encoder.h>
#include <bcg729/decoder.h>
#endif

#define AMR_FT_TYPES 14



struct codec_type_s;
struct decoder_s;
struct encoder_s;
struct format_s;
struct resample_s;
struct seq_packet_s;
struct rtp_payload_type;
union codec_options_u;
struct dtx_method_s;

typedef struct codec_type_s codec_type_t;
typedef struct decoder_s decoder_t;
typedef struct encoder_s encoder_t;
typedef struct format_s format_t;
typedef struct resample_s resample_t;
typedef struct seq_packet_s seq_packet_t;
typedef union codec_options_u codec_options_t;
typedef struct dtx_method_s dtx_method_t;

typedef int packetizer_f(AVPacket *, GString *, str *, encoder_t *);
typedef void format_init_f(struct rtp_payload_type *);
typedef void set_enc_options_f(encoder_t *, const str *, const str *);
typedef void set_dec_options_f(decoder_t *, const str *, const str *);
typedef int format_cmp_f(const struct rtp_payload_type *, const struct rtp_payload_type *);



struct codec_type_s {
	void (*def_init)(codec_def_t *);

	const char *(*decoder_init)(decoder_t *, const str *, const str *);
	int (*decoder_input)(decoder_t *, const str *data, GQueue *);
	void (*decoder_close)(decoder_t *);

	const char *(*encoder_init)(encoder_t *, const str *, const str *);
	int (*encoder_input)(encoder_t *, AVFrame **);
	void (*encoder_got_packet)(encoder_t *);
	void (*encoder_close)(encoder_t *);
};

struct amr_cmr {
	struct timeval cmr_in_ts;
	unsigned int cmr_in;

	struct timeval cmr_out_ts;
	unsigned int cmr_out;
};

union codec_options_u {
	struct {
		int interleaving;
		unsigned int mode_set; // bitfield
		int mode_change_period;
		int mode_change_interval;
		unsigned int octet_aligned:1;
		unsigned int crc:1;
		unsigned int robust_sorting:1;
		unsigned int mode_change_neighbor:1;

		const unsigned int *bits_per_frame;
		const unsigned int *bitrates;

		struct amr_cmr cmr; // input from external calling code

		int cmr_interval;
	} amr;
};

enum dtx_method {
	DTX_NATIVE = 0,
	DTX_SILENCE,
	DTX_CN,

	NUM_DTX_METHODS
};

struct codec_def_s {
	const char * const rtpname;
	int clockrate_mult;
	const int avcodec_id;
	const char * const avcodec_name_enc;
	const char * const avcodec_name_dec;
	int default_clockrate;
	int default_channels;
	const int default_bitrate;
	int default_ptime;
	const char *default_fmtp;
	format_cmp_f * const format_cmp;
	packetizer_f * const packetizer;
	const int bits_per_sample;
	const enum media_type media_type;
	const str silence_pattern;

	// codec-specific callbacks
	format_init_f *init;
	set_enc_options_f *set_enc_options;
	set_dec_options_f *set_dec_options;
	const dtx_method_t * const dtx_methods[NUM_DTX_METHODS];

	// filled in by codeclib_init()
	str rtpname_str;
	int rfc_payload_type;
	unsigned int support_encoding:1,
	             support_decoding:1;

	// flags
	unsigned int supplemental:1,
	             dtmf:1, // special case
		     amr:1;

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
	bool no_filter;
};

enum codec_event {
	CE_AMR_CMR_RECV,
	CE_AMR_SEND_CMR,
};

struct dtx_method_s {
	enum dtx_method method_id;

	int (*init)(decoder_t *);
	void (*cleanup)(decoder_t *);
	int (*do_dtx)(decoder_t *, GQueue *, int);

	union {
		struct {
			decoder_t *cn_dec;
			const str *cn_payload;
		} cn;
	} u;
};

struct decoder_s {
	const codec_def_t *def;
	codec_options_t codec_options;
	dtx_method_t dtx;

	format_t in_format,
		 dec_out_format,
		 dest_format;

	resample_t resampler;

	union {
		struct {
			AVCodecContext *avcctx;
			AVPacket *avpkt;

			union {
				struct {
					uint16_t bitrate_tracker[AMR_FT_TYPES];
					struct timeval tracker_end;
					struct timeval last_cmr;
				} amr;
			} u;
		} avc;
#ifdef HAVE_BCG729
		bcg729DecoderChannelContextStruct *bcg729;
#endif
		struct {
			unsigned long start_ts;
			unsigned int event;
			unsigned long duration;
		} dtmf;
	} u;

	unsigned long rtp_ts;
	uint64_t pts;
	int ptime;

	int (*event_func)(enum codec_event event, void *ptr, void *event_data);
	void *event_data;
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

			union {
				struct {
					struct timeval cmr_in_ts;
					struct timeval cmr_out_ts;
					unsigned int cmr_out_seq;
					uint64_t pkt_seq;
				} amr;
			} u;
		} avc;
#ifdef HAVE_BCG729
		bcg729EncoderChannelContextStruct *bcg729;
#endif
	} u;
	AVPacket *avpkt;
	AVAudioFifo *fifo;
	int64_t fifo_pts; // pts of first data in fifo
	int64_t packet_pts; // first pts of data in packetizer buffer
	int64_t next_pts; // next pts expected from the encoder
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


extern const GQueue * const codec_supplemental_codecs;


void codeclib_init(int);
void codeclib_free(void);


const codec_def_t *codec_find(const str *name, enum media_type);
const codec_def_t *codec_find_by_av(enum AVCodecID);


decoder_t *decoder_new_fmt(const codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt);
decoder_t *decoder_new_fmtp(const codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt,
		const str *fmtp, const str *codec_opts);
void decoder_close(decoder_t *dec);
int decoder_input_data(decoder_t *dec, const str *data, unsigned long ts,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2);
int decoder_input_data_ptime(decoder_t *dec, const str *data, unsigned long ts, int *ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2);
gboolean decoder_has_dtx(decoder_t *);
int decoder_switch_dtx(decoder_t *dec, enum dtx_method);
int decoder_set_cn_dtx(decoder_t *dec, const str *);
int decoder_dtx(decoder_t *dec, unsigned long ts, int ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2);


encoder_t *encoder_new(void);
int encoder_config(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format);
int encoder_config_fmtp(encoder_t *enc, const codec_def_t *def, int bitrate, int ptime,
		const format_t *requested_format, format_t *actual_format, const str *fmtp, const str *codec_opts);
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
int packet_sequencer_next_ok(packet_sequencer_t *ps);
void *packet_sequencer_force_next_packet(packet_sequencer_t *ps);
int packet_sequencer_insert(packet_sequencer_t *ps, seq_packet_t *);


#include "auxlib.h"


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
INLINE char *av_error(int no) {
	char *buf = get_thread_buf();
	av_strerror(no, buf, THREAD_BUF_SIZE);
	return buf;
}
INLINE int decoder_event(decoder_t *dec, enum codec_event event, void *ptr) {
	if (!dec)
		return 0;
	if (!dec->event_func)
		return 0;
	return dec->event_func(event, ptr, dec->event_data);
}


#else

typedef int format_cmp_f(const void *, const void *);

// stubs
struct codec_def_s {
	int dtmf;
	int supplemental;
	format_cmp_f * const format_cmp;
	const str silence_pattern;
};
struct packet_sequencer_s {
};

INLINE void codeclib_init(int print) {
	if (print)
		printf("No codecs supported.\n");
}
INLINE void codeclib_free(void) {
	;
}

INLINE const codec_def_t *codec_find(const str *name, enum media_type type) {
	return NULL;
}
INLINE void packet_sequencer_destroy(packet_sequencer_t *p) {
	return;
}


#endif
#endif
