#include "codeclib.h"
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <libavutil/opt.h>
#include <glib.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#ifdef HAVE_BCG729
#include <bcg729/encoder.h>
#include <bcg729/decoder.h>
#endif
#include <opus.h>
#ifdef HAVE_CODEC_CHAIN
#include <codec-chain/types.h>
#include <codec-chain/client.h>
#endif
#include "str.h"
#include "log.h"
#include "loglib.h"
#include "resample.h"
#include "rtplib.h"
#include "bitstr.h"
#include "dtmflib.h"
#include "fix_frame_channel_layout.h"



#define PACKET_SEQ_DUPE_THRES 100
#define PACKET_TS_RESET_THRES 5000 // milliseconds



#define cdbg(x...) ilogs(internals, LOG_DEBUG, x)




static packetizer_f packetizer_samplestream; // flat stream of samples
static packetizer_f packetizer_amr;


static void codeclib_key_value_parse(const str *instr, bool need_value,
		void (*cb)(str *key, str *value, void *data), void *data);

static const char *libopus_decoder_init(decoder_t *, const str *);
static int libopus_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void libopus_decoder_close(decoder_t *);
static const char *libopus_encoder_init(encoder_t *enc, const str *);
static int libopus_encoder_input(encoder_t *enc, AVFrame **frame);
static void libopus_encoder_close(encoder_t *enc);
static format_init_f opus_init;
static select_encoder_format_f opus_select_encoder_format;
static select_decoder_format_f opus_select_decoder_format;
static format_parse_f opus_format_parse;
static format_print_f opus_format_print;
static format_answer_f opus_format_answer;

static format_parse_f ilbc_format_parse;
static set_enc_options_f ilbc_set_enc_options;
static set_dec_options_f ilbc_set_dec_options;

static format_parse_f amr_format_parse;
static set_enc_options_f amr_set_enc_options;
static set_dec_options_f amr_set_dec_options;
static format_cmp_f amr_format_cmp;

static void avc_def_init(struct codec_def_s *);
static const char *avc_decoder_init(decoder_t *, const str *);
static int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void avc_decoder_close(decoder_t *);
static const char *avc_encoder_init(encoder_t *enc, const str *);
static int avc_encoder_input(encoder_t *enc, AVFrame **frame);
static void avc_encoder_close(encoder_t *enc);

static int amr_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void amr_encoder_got_packet(encoder_t *enc);
static int ilbc_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static const char *dtmf_decoder_init(decoder_t *, const str *);
static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static const char *cn_decoder_init(decoder_t *, const str *);
static int cn_decoder_input(decoder_t *dec, const str *data, GQueue *out);

static int format_cmp_ignore(const struct rtp_payload_type *, const struct rtp_payload_type *);

static int generic_silence_dtx(decoder_t *, GQueue *, int);
static int amr_dtx(decoder_t *, GQueue *, int);
static int evs_dtx(decoder_t *, GQueue *, int);

static int generic_cn_dtx_init(decoder_t *);
static void generic_cn_dtx_cleanup(decoder_t *);
static int generic_cn_dtx(decoder_t *, GQueue *, int);


#if defined(__x86_64__)
// mvr2s_x64_avx2.S
void mvr2s_avx2(float *in, const uint16_t len, int16_t *out);

// mvr2s_x64_avx512.S
void mvr2s_avx512(float *in, const uint16_t len, int16_t *out);
#endif



static void *evs_lib_handle;
static unsigned int evs_decoder_size;
static unsigned int evs_encoder_size;
static unsigned int evs_encoder_ind_list_size;
static void (*evs_init_decoder)(void *);
static void (*evs_init_encoder)(void *);
static void (*evs_destroy_decoder)(void *);
static void (*evs_destroy_encoder)(void *);
static void (*evs_set_encoder_opts)(void *, unsigned long, void *);
static void (*evs_set_encoder_brate)(void *, unsigned long br, unsigned int bwidth,
		unsigned int mode, unsigned int amr);
static void (*evs_set_decoder_Fs)(void *, unsigned long);
static void (*evs_enc_in)(void *, const uint16_t *s, const uint16_t n);
static void (*evs_amr_enc_in)(void *, const uint16_t *s, const uint16_t n);
static void (*evs_enc_out)(void *, unsigned char *buf, uint16_t *len);
static void (*evs_dec_in)(void *, char *in, uint16_t len, uint16_t amr_mode, uint16_t core_mode,
		uint16_t q_bit, uint16_t partial_frame, uint16_t next_type);
static void (*evs_dec_out)(void *, void *, int frame_mode); // frame_mode=1: missing
static void (*evs_dec_inc_frame)(void *);
static void (*evs_amr_dec_out)(void *, void *);
static void (*evs_syn_output)(float *in, const uint16_t len, int16_t *out);
static void (*evs_reset_enc_ind)(void *);

static void evs_def_init(struct codec_def_s *);
static const char *evs_decoder_init(decoder_t *, const str *);
static int evs_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void evs_decoder_close(decoder_t *);
static const char *evs_encoder_init(encoder_t *enc, const str *);
static int evs_encoder_input(encoder_t *enc, AVFrame **frame);
static void evs_encoder_close(encoder_t *);
static format_parse_f evs_format_parse;
static format_cmp_f evs_format_cmp;
static format_print_f evs_format_print;
static format_answer_f evs_format_answer;
static select_encoder_format_f evs_select_encoder_format;




static void *cc_lib_handle;

#ifdef HAVE_CODEC_CHAIN

static __typeof__(codec_chain_client_connect) *cc_client_connect;
static __typeof__(codec_chain_set_thread_funcs) *cc_set_thread_funcs;

static __typeof__(codec_chain_client_pcma2opus_runner_new) *cc_client_pcma2opus_runner_new;
static __typeof__(codec_chain_client_pcmu2opus_runner_new) *cc_client_pcmu2opus_runner_new;
static __typeof__(codec_chain_client_opus2pcma_runner_new) *cc_client_opus2pcma_runner_new;
static __typeof__(codec_chain_client_opus2pcmu_runner_new) *cc_client_opus2pcmu_runner_new;

static __typeof__(codec_chain_client_pcma2opus_runner_free) *cc_client_pcma2opus_runner_free;
static __typeof__(codec_chain_client_pcmu2opus_runner_free) *cc_client_pcmu2opus_runner_free;
static __typeof__(codec_chain_client_opus2pcma_runner_free) *cc_client_opus2pcma_runner_free;
static __typeof__(codec_chain_client_opus2pcmu_runner_free) *cc_client_opus2pcmu_runner_free;

static __typeof__(codec_chain_client_pcma2opus_async_runner_new) *cc_client_pcma2opus_async_runner_new;
static __typeof__(codec_chain_client_pcmu2opus_async_runner_new) *cc_client_pcmu2opus_async_runner_new;
static __typeof__(codec_chain_client_opus2pcma_async_runner_new) *cc_client_opus2pcma_async_runner_new;
static __typeof__(codec_chain_client_opus2pcmu_async_runner_new) *cc_client_opus2pcmu_async_runner_new;

static __typeof__(codec_chain_client_pcma2opus_async_runner_free) *cc_client_pcma2opus_async_runner_free;
static __typeof__(codec_chain_client_pcmu2opus_async_runner_free) *cc_client_pcmu2opus_async_runner_free;
static __typeof__(codec_chain_client_opus2pcma_async_runner_free) *cc_client_opus2pcma_async_runner_free;
static __typeof__(codec_chain_client_opus2pcmu_async_runner_free) *cc_client_opus2pcmu_async_runner_free;

static __typeof__(codec_chain_pcma2opus_runner_do) *cc_pcma2opus_runner_do;
static __typeof__(codec_chain_pcmu2opus_runner_do) *cc_pcmu2opus_runner_do;
static __typeof__(codec_chain_opus2pcma_runner_do) *cc_opus2pcma_runner_do;
static __typeof__(codec_chain_opus2pcmu_runner_do) *cc_opus2pcmu_runner_do;

static __typeof__(codec_chain_pcma2opus_runner_async_do_nonblock) *cc_pcma2opus_runner_async_do_nonblock;
static __typeof__(codec_chain_pcmu2opus_runner_async_do_nonblock) *cc_pcmu2opus_runner_async_do_nonblock;
static __typeof__(codec_chain_opus2pcma_runner_async_do_nonblock) *cc_opus2pcma_runner_async_do_nonblock;
static __typeof__(codec_chain_opus2pcmu_runner_async_do_nonblock) *cc_opus2pcmu_runner_async_do_nonblock;

static __typeof__(codec_chain_client_float2opus_new_ext) *cc_client_float2opus_new_ext;
static __typeof__(codec_chain_client_opus2float_new) *cc_client_opus2float_new;

static __typeof__(codec_chain_client_float2opus_free) *cc_client_float2opus_free;
static __typeof__(codec_chain_client_opus2float_free) *cc_client_opus2float_free;

static codec_chain_client *cc_client;

static codec_chain_pcma2opus_runner *pcma2opus_runner;
static codec_chain_pcmu2opus_runner *pcmu2opus_runner;
static codec_chain_opus2pcmu_runner *opus2pcmu_runner;
static codec_chain_opus2pcma_runner *opus2pcma_runner;

static codec_chain_pcma2opus_async_runner *pcma2opus_async_runner;
static codec_chain_pcmu2opus_async_runner *pcmu2opus_async_runner;
static codec_chain_opus2pcmu_async_runner *opus2pcmu_async_runner;
static codec_chain_opus2pcma_async_runner *opus2pcma_async_runner;

typedef enum {
	CCC_OK,
	CCC_ASYNC,
	CCC_ERR,
} codec_cc_state;

struct async_job {
	str data;
	unsigned long ts;
	void *async_cb_obj;
};
TYPED_GQUEUE(async_job, struct async_job);

struct codec_cc_s {
	union {
		struct {
			codec_chain_pcmu2opus_runner *runner;
			codec_chain_float2opus *enc;
		} pcmu2opus;
		struct {
			codec_chain_pcma2opus_runner *runner;
			codec_chain_float2opus *enc;
		} pcma2opus;
		struct {
			codec_chain_opus2pcmu_runner *runner;
			codec_chain_opus2float *dec;
		} opus2pcmu;
		struct {
			codec_chain_opus2pcma_runner *runner;
			codec_chain_opus2float *dec;
		} opus2pcma;
		struct {
			codec_chain_pcmu2opus_async_runner *runner;
			codec_chain_float2opus *enc;
		} pcmu2opus_async;
		struct {
			codec_chain_pcma2opus_async_runner *runner;
			codec_chain_float2opus *enc;
		} pcma2opus_async;
		struct {
			codec_chain_opus2pcmu_async_runner *runner;
			codec_chain_opus2float *dec;
		} opus2pcmu_async;
		struct {
			codec_chain_opus2pcma_async_runner *runner;
			codec_chain_opus2float *dec;
		} opus2pcma_async;
	};
	AVPacket *avpkt;
	codec_cc_state (*run)(codec_cc_t *c, const str *data, unsigned long ts, void *);
	void (*clear)(void *);
	void *clear_arg;

	mutex_t async_lock;
	AVPacket *avpkt_async;
	size_t data_len;
	bool async_busy; // currently processing a packet
	bool async_blocked; // couldn't find context
	bool async_shutdown; // shutdown/free happened while busy
	async_job_q async_jobs;
	unsigned long ts;
	void *(*async_init)(void *, void *, void *);
	void (*async_callback)(AVPacket *, void *);
	void *async_cb_obj;
};

static codec_cc_t *codec_cc_new_sync(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *));
static codec_cc_t *codec_cc_new_async(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *));

static bool __cc_pcmu2opus_run_async(codec_cc_t *, const str *, unsigned long, void *);
static bool __cc_pcma2opus_run_async(codec_cc_t *, const str *, unsigned long, void *);
static bool __cc_opus2pcma_run_async(codec_cc_t *, const str *, unsigned long, void *);
static bool __cc_opus2pcmu_run_async(codec_cc_t *, const str *, unsigned long, void *);

codec_cc_t *(*codec_cc_new)(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *));

#endif




static const codec_type_t codec_type_avcodec = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = avc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_libopus = {
	.decoder_init = libopus_decoder_init,
	.decoder_input = libopus_decoder_input,
	.decoder_close = libopus_decoder_close,
	.encoder_init = libopus_encoder_init,
	.encoder_input = libopus_encoder_input,
	.encoder_close = libopus_encoder_close,
};
static const codec_type_t codec_type_ilbc = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = ilbc_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_amr = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = amr_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_got_packet = amr_encoder_got_packet,
	.encoder_close = avc_encoder_close,
};
static const codec_type_t codec_type_evs = {
	.def_init = evs_def_init,
	.decoder_init = evs_decoder_init,
	.decoder_input = evs_decoder_input,
	.decoder_close = evs_decoder_close,
	.encoder_init = evs_encoder_init,
	.encoder_input = evs_encoder_input,
//	.encoder_got_packet = amr_encoder_got_packet,
	.encoder_close = evs_encoder_close,
};
static const codec_type_t codec_type_dtmf = {
	.decoder_init = dtmf_decoder_init,
	.decoder_input = dtmf_decoder_input,
};
static const codec_type_t codec_type_cn = {
	.def_init = avc_def_init,
	.decoder_init = cn_decoder_init,
	.decoder_input = cn_decoder_input,
	.decoder_close = avc_decoder_close,
};

static const dtx_method_t dtx_method_silence = {
	.method_id = DTX_SILENCE,
	.do_dtx = generic_silence_dtx,
};
static const dtx_method_t dtx_method_cn = {
	.method_id = DTX_CN,
	.do_dtx = generic_cn_dtx,
	.init = generic_cn_dtx_init,
	.cleanup = generic_cn_dtx_cleanup,
};
static const dtx_method_t dtx_method_amr = {
	.method_id = DTX_NATIVE,
	.do_dtx = amr_dtx,
};
static const dtx_method_t dtx_method_evs = {
	.method_id = DTX_NATIVE,
	.do_dtx = evs_dtx,
};

#ifdef HAVE_BCG729
static packetizer_f packetizer_g729; // aggregate some frames into packets
static format_cmp_f format_cmp_g729;

static void bcg729_def_init(struct codec_def_s *);
static const char *bcg729_decoder_init(decoder_t *, const str *);
static int bcg729_decoder_input(decoder_t *dec, const str *data, GQueue *out);
static void bcg729_decoder_close(decoder_t *);
static const char *bcg729_encoder_init(encoder_t *enc, const str *);
static int bcg729_encoder_input(encoder_t *enc, AVFrame **frame);
static void bcg729_encoder_close(encoder_t *enc);

static const codec_type_t codec_type_bcg729 = {
	.def_init = bcg729_def_init,
	.decoder_init = bcg729_decoder_init,
	.decoder_input = bcg729_decoder_input,
	.decoder_close = bcg729_decoder_close,
	.encoder_init = bcg729_encoder_init,
	.encoder_input = bcg729_encoder_input,
	.encoder_close = bcg729_encoder_close,
};
#endif



static struct codec_def_s __codec_defs[] = {
	{
		.rtpname = "PCMA",
		.avcodec_id = AV_CODEC_ID_PCM_ALAW,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.silence_pattern = STR_CONST("\xd5"),
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
	{
		.rtpname = "PCMU",
		.avcodec_id = AV_CODEC_ID_PCM_MULAW,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 8,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.silence_pattern = STR_CONST("\xff"),
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
	{
		.rtpname = "G723",
		.avcodec_id = AV_CODEC_ID_G723_1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 30,
		.minimum_ptime = 30,
		.default_bitrate = 6300,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
	{
		.rtpname = "G722",
		.avcodec_id = AV_CODEC_ID_ADPCM_G722,
		.default_clockrate_fact = {2,1},
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.format_cmp = format_cmp_ignore,
		.packetizer = packetizer_samplestream,
		.bits_per_sample = 4,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.silence_pattern = STR_CONST("\xfa"),
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
	{
		.rtpname = "QCELP",
		.avcodec_id = AV_CODEC_ID_QCELP,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
#ifndef HAVE_BCG729
	{
		.rtpname = "G729",
		.avcodec_id = AV_CODEC_ID_G729,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
	{
		.rtpname = "G729a",
		.avcodec_id = AV_CODEC_ID_G729,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
#else
	{
		.rtpname = "G729",
		.avcodec_id = -1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.default_fmtp = "annexb=no",
		.format_cmp = format_cmp_g729,
		.packetizer = packetizer_g729,
		.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_bcg729,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
	{
		.rtpname = "G729a",
		.avcodec_id = -1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.format_cmp = format_cmp_g729,
		.packetizer = packetizer_g729,
		.bits_per_sample = 1, // 10 ms frame has 80 samples and encodes as (max) 10 bytes = 80 bits
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_bcg729,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.fixed_sizes = 1,
	},
#endif
	{
		.rtpname = "speex",
		.avcodec_id = AV_CODEC_ID_SPEEX,
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 11000,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "GSM",
		.avcodec_id = AV_CODEC_ID_GSM,
		.default_clockrate = 8000,
		.default_channels = 1,
		//.default_bitrate = 13200,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "iLBC",
		.avcodec_id = AV_CODEC_ID_ILBC,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 30,
		.default_fmtp = "mode=30",
		.format_parse = ilbc_format_parse,
		//.default_bitrate = 15200,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_ilbc,
		.set_enc_options = ilbc_set_enc_options,
		.set_dec_options = ilbc_set_dec_options,
	},
	{
		.rtpname = "opus",
		.avcodec_id = -1,
		.default_clockrate = 48000,
		.default_channels = 2,
		.default_bitrate = 32000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_libopus,
		.init = opus_init,
		.default_fmtp = "useinbandfec=1",
		.format_parse = opus_format_parse,
		.format_print = opus_format_print,
		.format_cmp = format_cmp_ignore,
		.format_answer = opus_format_answer,
		.select_encoder_format = opus_select_encoder_format,
		.select_decoder_format = opus_select_decoder_format,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
		.support_encoding = 1,
		.support_decoding = 1,
	},
	{
		.rtpname = "EVS",
		.avcodec_id = -1,
		.default_clockrate_fact = {3,1},
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_ptime = 20,
		.default_bitrate = 16400,
		.default_fmtp = "dtx=0;dtx-recv=0",
		.format_parse = evs_format_parse,
		.format_cmp = evs_format_cmp,
		.format_print = evs_format_print,
		.format_answer = evs_format_answer,
		.select_encoder_format = evs_select_encoder_format,
		.packetizer = packetizer_passthrough,
		.bits_per_sample = 1,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_evs,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_evs,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "vorbis",
		.avcodec_id = AV_CODEC_ID_VORBIS,
		.avcodec_name_enc = "libvorbis",
		.avcodec_name_dec = "libvorbis",
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "ac3",
		.avcodec_id = AV_CODEC_ID_AC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "eac3",
		.avcodec_id = AV_CODEC_ID_EAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "ATRAC3",
		.avcodec_id = AV_CODEC_ID_ATRAC3,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "ATRAC-X",
		.avcodec_id = AV_CODEC_ID_ATRAC3P,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 0, 0)
	{
		.rtpname = "EVRC",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "EVRC0",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "EVRC1",
		.avcodec_id = AV_CODEC_ID_EVRC,
		.default_clockrate = 8000,
		.default_ptime = 20,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
		.dtx_methods = {
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
#endif
	{
		.rtpname = "AMR",
		.avcodec_id = AV_CODEC_ID_AMR_NB,
		.avcodec_name_enc = "libopencore_amrnb",
		.avcodec_name_dec = "libopencore_amrnb",
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_bitrate = 6700,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.format_parse = amr_format_parse,
		.format_cmp = amr_format_cmp,
		.default_fmtp = "octet-align=1;mode-change-capability=2",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 12200 / 8000 = 1.525 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
		.amr = 1,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_amr,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "AMR-WB",
		.avcodec_id = AV_CODEC_ID_AMR_WB,
		.avcodec_name_enc = "libvo_amrwbenc",
		.avcodec_name_dec = "libopencore_amrwb",
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 14250,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.format_parse = amr_format_parse,
		.format_cmp = amr_format_cmp,
		.default_fmtp = "octet-align=1;mode-change-capability=2",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 23850 / 16000 = 1.490625 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
		.amr = 1,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_amr,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
	},
	{
		.rtpname = "telephone-event",
		.avcodec_id = -1,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.supplemental = 1,
		.dtmf = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_fmtp = "0-15",
		.format_cmp = format_cmp_ignore,
		.codec_type = &codec_type_dtmf,
		.support_encoding = 1,
		.support_decoding = 1,
	},
	{
		.rtpname = "CN",
		.avcodec_id = AV_CODEC_ID_COMFORT_NOISE,
		.avcodec_name_enc = "comfortnoise",
		.avcodec_name_dec = "comfortnoise",
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.supplemental = 1,
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_ptime = 20,
		.format_cmp = format_cmp_ignore,
		.codec_type = &codec_type_cn,
	},
	// for file reading and writing
	{
		.rtpname = "PCM-S16LE",
		.avcodec_id = AV_CODEC_ID_PCM_S16LE,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "PCM-U8",
		.avcodec_id = AV_CODEC_ID_PCM_U8,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
	{
		.rtpname = "MP3",
		.avcodec_id = AV_CODEC_ID_MP3,
		.packetizer = packetizer_passthrough,
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_avcodec,
	},
};

static GQueue __supplemental_codecs = G_QUEUE_INIT;
const GQueue * const codec_supplemental_codecs = &__supplemental_codecs;
static codec_def_t *codec_def_cn;

void (*codeclib_thread_init)(void);
void (*codeclib_thread_cleanup)(void);
void (*codeclib_thread_loop)(void);


static GHashTable *codecs_ht;
static GHashTable *codecs_ht_by_av;



codec_def_t *codec_find(const str *name, enum media_type type) {
	codec_def_t *ret = g_hash_table_lookup(codecs_ht, name);
	if (!ret)
		return NULL;
	if (type && type != ret->media_type)
		return NULL;
	return ret;
}

codec_def_t *codec_find_by_av(enum AVCodecID id) {
	return g_hash_table_lookup(codecs_ht_by_av, GINT_TO_POINTER(id));
}




static const char *avc_decoder_init(decoder_t *dec, const str *extra_opts) {
	const AVCodec *codec = dec->def->decoder;
	if (!codec)
		return "codec not supported";

	dec->avc.avpkt = av_packet_alloc();

	dec->avc.avcctx = avcodec_alloc_context3(codec);
	if (!dec->avc.avcctx)
		return "failed to alloc codec context";
	SET_CHANNELS(dec->avc.avcctx, dec->in_format.channels);
	DEF_CH_LAYOUT(&dec->avc.avcctx->CH_LAYOUT, dec->in_format.channels);
	dec->avc.avcctx->sample_rate = dec->in_format.clockrate;

	if (dec->def->set_dec_options)
		dec->def->set_dec_options(dec, extra_opts);

	int i = avcodec_open2(dec->avc.avcctx, codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open codec context";
	}

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(61, 19, 0)
	avcodec_get_supported_config(dec->avc.avcctx, codec, AV_CODEC_CONFIG_SAMPLE_FORMAT, 0, (const void **) &dec->avc.sample_fmts, NULL);
#else
	dec->avc.sample_fmts = codec->sample_fmts;
#endif

	for (const enum AVSampleFormat *sfmt = dec->avc.sample_fmts; sfmt && *sfmt != -1; sfmt++)
		cdbg("supported sample format for input codec %s: %s",
				codec->name, av_get_sample_fmt_name(*sfmt));

	return NULL;
}



decoder_t *decoder_new_fmt(codec_def_t *def, int clockrate, int channels, int ptime,
		const format_t *resample_fmt)
{
	return decoder_new_fmtp(def, clockrate, channels, ptime, resample_fmt, NULL, NULL, NULL);
}

int codec_parse_fmtp(codec_def_t *def, struct rtp_codec_format *fmtp, const str *fmtp_string,
		union codec_format_options *copy)
{
	struct rtp_codec_format fmtp_store;

	if (copy)
		ZERO(*copy);

	if (!def)
		return -1;
	if (!def->format_parse)
		return 0;
	if (!fmtp_string)
		return 0;
	if (!fmtp) {
		ZERO(fmtp_store);
		fmtp = &fmtp_store;
	}
	if (fmtp->fmtp_parsed) {
		if (copy)
			*copy = fmtp->parsed;
		return 0;
	}
	int ret = def->format_parse(fmtp, fmtp_string);
	if (!ret) {
		fmtp->fmtp_parsed = 1;
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

	ret = g_slice_alloc0(sizeof(*ret));

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
	if (codec_parse_fmtp(def, fmtp, fmtp_string, &ret->format_options))
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


static void avc_decoder_close(decoder_t *dec) {
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(56, 1, 0)
	avcodec_free_context(&dec->avc.avcctx);
#else
	avcodec_close(dec->avc.avcctx);
	av_free(dec->avc.avcctx);
#endif
	av_packet_free(&dec->avc.avpkt);
}


void decoder_close(decoder_t *dec) {
	if (!dec)
		return;
	/// XXX drain inputs and outputs

	if (dec->def && dec->def->codec_type && dec->def->codec_type->decoder_close)
		dec->def->codec_type->decoder_close(dec);

	decoder_switch_dtx(dec, -1);

	resample_shutdown(&dec->resampler);
	g_slice_free1(sizeof(*dec), dec);
}


static int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	if (!dec->avc.avpkt)
		return -1; // decoder shut down

	const char *err;
	int av_ret = 0;

	dec->avc.avpkt->data = (unsigned char *) data->s;
	dec->avc.avpkt->size = data->len;
	dec->avc.avpkt->pts = dec->pts;

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
		if (dec->avc.avpkt->size) {
			av_ret = avcodec_send_packet(dec->avc.avcctx, dec->avc.avpkt);
			cdbg("send packet ret %i", av_ret);
			err = "failed to send packet to avcodec";
			if (av_ret == 0) {
				// consumed the packet
				dec->avc.avpkt->size = 0;
				keep_going = 1;
			}
			else {
				if (av_ret == AVERROR(EAGAIN))
					; // try again after reading output
				else
					goto err;
			}
		}

		av_ret = avcodec_receive_frame(dec->avc.avcctx, frame);
		cdbg("receive frame ret %i", av_ret);
		err = "failed to receive frame from avcodec";
		if (av_ret == 0) {
			// got a frame
			keep_going = 1;
			got_frame = 1;
		}
		else {
			if (av_ret == AVERROR(EAGAIN))
				; // maybe needs more input now
			else
				goto err;
		}
#else
		// only do this if we have any input left
		if (dec->avc.avpkt->size == 0)
			break;

		av_ret = avcodec_decode_audio4(dec->avc.avcctx, frame, &got_frame, dec->avc.avpkt);
		cdbg("decode frame ret %i, got frame %i", av_ret, got_frame);
		err = "failed to decode audio packet";
		if (av_ret < 0)
			goto err;
		if (av_ret > 0) {
			// consumed some input
			err = "invalid return value";
			if (av_ret > dec->avc.avpkt->size)
				goto err;
			dec->avc.avpkt->size -= av_ret;
			dec->avc.avpkt->data += av_ret;
			keep_going = 1;
		}
		if (got_frame)
			keep_going = 1;
#endif

		if (got_frame) {
			cdbg("raw frame from decoder pts %llu samples %u",
					(unsigned long long) frame->pts, frame->nb_samples);

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 36, 0)
			frame->pts = frame->pkt_pts;
#endif
			if (G_UNLIKELY(frame->pts == AV_NOPTS_VALUE))
				frame->pts = dec->avc.avpkt->pts;
			dec->avc.avpkt->pts += frame->nb_samples;

			g_queue_push_tail(out, frame);
			frame = NULL;
		}
	} while (keep_going);

	av_frame_free(&frame);
	return 0;

err:
	ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error decoding media packet: %s", err);
	if (av_ret)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(av_ret));
	av_frame_free(&frame);
	return -1;
}

static int __decoder_input_data(decoder_t *dec, const str *data, unsigned long ts, int *ptime,
		int (*callback)(decoder_t *, AVFrame *, void *u1, void *u2), void *u1, void *u2)
{
	GQueue frames = G_QUEUE_INIT;

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
	while ((frame = g_queue_pop_head(&frames))) {
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


static void avlog_ilog(void *ptr, int loglevel, const char *fmt, va_list ap) {
	char *msg;
	if (vasprintf(&msg, fmt, ap) <= 0)
		ilogs(ffmpeg, LOG_ERR | LOG_FLAG_LIMIT, "av_log message dropped");
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
		ilogs(ffmpeg, loglevel | LOG_FLAG_LIMIT, "av_log: %s", msg);
		free(msg);
	}
}


static void avc_def_init(struct codec_def_s *def) {
	// look up AVCodec structs
	if (def->avcodec_name_enc)
		def->encoder = avcodec_find_encoder_by_name(def->avcodec_name_enc);
	if (def->avcodec_name_dec)
		def->decoder = avcodec_find_decoder_by_name(def->avcodec_name_dec);
	if (def->avcodec_id >= 0) {
		if (!def->encoder)
			def->encoder = avcodec_find_encoder(def->avcodec_id);
		if (!def->decoder)
			def->decoder = avcodec_find_decoder(def->avcodec_id);
	}
	// check if we have support if we are supposed to
	if (def->avcodec_name_enc || def->avcodec_id >= 0) {
		if (def->encoder)
			def->support_encoding = 1;
	}
	if (def->avcodec_name_dec || def->avcodec_id >= 0) {
		if (def->decoder)
			def->support_decoding = 1;
	}
}

static void cc_cleanup(void);

void codeclib_free(void) {
	g_hash_table_destroy(codecs_ht);
	g_hash_table_destroy(codecs_ht_by_av);
	avformat_network_deinit();
	cc_cleanup();
	if (evs_lib_handle)
		dlclose(evs_lib_handle);
	if (cc_lib_handle)
		dlclose(cc_lib_handle);
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


static void *dlsym_assert(void *handle, const char *sym, const char *fn) {
	void *ret = dlsym(handle, sym);
	if (!ret)
		die("Failed to resolve symbol '%s' from '%s': %s", sym, fn, dlerror());
	return ret;
}


#ifdef HAVE_CODEC_CHAIN
static void cc_dlsym_resolve(const char *fn) {
	cc_client_connect = dlsym_assert(cc_lib_handle, "codec_chain_client_connect", fn);
	cc_set_thread_funcs = dlsym_assert(cc_lib_handle, "codec_chain_set_thread_funcs", fn);

	cc_client_pcma2opus_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcma2opus_runner_new", fn);
	cc_client_pcmu2opus_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcmu2opus_runner_new", fn);
	cc_client_opus2pcma_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcma_runner_new", fn);
	cc_client_opus2pcmu_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcmu_runner_new", fn);

	cc_client_pcma2opus_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcma2opus_runner_free", fn);
	cc_client_pcmu2opus_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcmu2opus_runner_free", fn);
	cc_client_opus2pcma_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcma_runner_free", fn);
	cc_client_opus2pcmu_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcmu_runner_free", fn);

	cc_client_pcma2opus_async_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcma2opus_async_runner_new", fn);
	cc_client_pcmu2opus_async_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcmu2opus_async_runner_new", fn);
	cc_client_opus2pcma_async_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcma_async_runner_new", fn);
	cc_client_opus2pcmu_async_runner_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcmu_async_runner_new", fn);

	cc_client_pcma2opus_async_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcma2opus_async_runner_free", fn);
	cc_client_pcmu2opus_async_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_pcmu2opus_async_runner_free", fn);
	cc_client_opus2pcma_async_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcma_async_runner_free", fn);
	cc_client_opus2pcmu_async_runner_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2pcmu_async_runner_free", fn);

	cc_pcma2opus_runner_do = dlsym_assert(cc_lib_handle,
			"codec_chain_pcma2opus_runner_do", fn);
	cc_pcmu2opus_runner_do = dlsym_assert(cc_lib_handle,
			"codec_chain_pcmu2opus_runner_do", fn);
	cc_opus2pcma_runner_do = dlsym_assert(cc_lib_handle,
			"codec_chain_opus2pcma_runner_do", fn);
	cc_opus2pcmu_runner_do = dlsym_assert(cc_lib_handle,
			"codec_chain_opus2pcmu_runner_do", fn);

	cc_pcma2opus_runner_async_do_nonblock = dlsym_assert(cc_lib_handle,
			"codec_chain_pcma2opus_runner_async_do_nonblock", fn);
	cc_pcmu2opus_runner_async_do_nonblock = dlsym_assert(cc_lib_handle,
			"codec_chain_pcmu2opus_runner_async_do_nonblock", fn);
	cc_opus2pcma_runner_async_do_nonblock = dlsym_assert(cc_lib_handle,
			"codec_chain_opus2pcma_runner_async_do_nonblock", fn);
	cc_opus2pcmu_runner_async_do_nonblock = dlsym_assert(cc_lib_handle,
			"codec_chain_opus2pcmu_runner_async_do_nonblock", fn);

	cc_client_float2opus_new_ext = dlsym_assert(cc_lib_handle,
			"codec_chain_client_float2opus_new_ext", fn);
	cc_client_opus2float_new = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2float_new", fn);

	cc_client_float2opus_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_float2opus_free", fn);
	cc_client_opus2float_free = dlsym_assert(cc_lib_handle,
			"codec_chain_client_opus2float_free", fn);
}

static void cc_create_runners(void) {
	pcma2opus_runner = cc_client_pcma2opus_runner_new(cc_client,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!pcma2opus_runner)
		die("Failed to initialise GPU pcma2opus");

	pcmu2opus_runner = cc_client_pcmu2opus_runner_new(cc_client,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!pcmu2opus_runner)
		die("Failed to initialise GPU pcmu2opus");

	opus2pcmu_runner = cc_client_opus2pcmu_runner_new(cc_client,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!opus2pcmu_runner)
		die("Failed to initialise GPU opus2pcmu");

	opus2pcma_runner = cc_client_opus2pcma_runner_new(cc_client,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!opus2pcma_runner)
		die("Failed to initialise GPU opus2pcma");
}

static void cc_create_async_runners(void) {
	pcma2opus_async_runner = cc_client_pcma2opus_async_runner_new(cc_client,
			rtpe_common_config_ptr->codec_chain_async,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!pcma2opus_async_runner)
		die("Failed to initialise GPU pcma2opus");

	pcmu2opus_async_runner = cc_client_pcmu2opus_async_runner_new(cc_client,
			rtpe_common_config_ptr->codec_chain_async,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!pcmu2opus_async_runner)
		die("Failed to initialise GPU pcmu2opus");

	opus2pcmu_async_runner = cc_client_opus2pcmu_async_runner_new(cc_client,
			rtpe_common_config_ptr->codec_chain_async,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!opus2pcmu_async_runner)
		die("Failed to initialise GPU opus2pcmu");

	opus2pcma_async_runner = cc_client_opus2pcma_async_runner_new(cc_client,
			rtpe_common_config_ptr->codec_chain_async,
			10000,
			rtpe_common_config_ptr->codec_chain_runners,
			rtpe_common_config_ptr->codec_chain_concurrency, 160);
	if (!opus2pcma_async_runner)
		die("Failed to initialise GPU opus2pcma");
}


static codec_cc_t *codec_cc_new_dummy(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *))
{
	return NULL;
}

static void cc_init(void) {
	codec_cc_new = codec_cc_new_dummy;

	if (!rtpe_common_config_ptr->codec_chain_lib_path)
		return;

	cc_lib_handle = dlopen(rtpe_common_config_ptr->codec_chain_lib_path, RTLD_NOW | RTLD_LOCAL);
	if (!cc_lib_handle)
		die("Failed to load libcodec-chain.so '%s': %s",
				rtpe_common_config_ptr->codec_chain_lib_path,
				dlerror());

	cc_dlsym_resolve(rtpe_common_config_ptr->codec_chain_lib_path);

	cc_set_thread_funcs(codeclib_thread_init, codeclib_thread_cleanup, codeclib_thread_loop);

	cc_client = cc_client_connect(4);
	if (!cc_client)
		die("Failed to connect to cudecsd");

	if (!rtpe_common_config_ptr->codec_chain_async) {
		cc_create_runners();
		codec_cc_new = codec_cc_new_sync;
	}
	else {
		cc_create_async_runners();
		codec_cc_new = codec_cc_new_async;
	}

	ilog(LOG_DEBUG, "CUDA codecs initialised");
}

static void cc_cleanup(void) {
	if (!cc_lib_handle)
		return;

	cc_client_opus2pcma_runner_free(cc_client, &opus2pcma_runner);
	cc_client_opus2pcmu_runner_free(cc_client, &opus2pcmu_runner);
	cc_client_pcma2opus_runner_free(cc_client, &pcma2opus_runner);
	cc_client_pcmu2opus_runner_free(cc_client, &pcmu2opus_runner);

	cc_client_opus2pcma_async_runner_free(cc_client, &opus2pcma_async_runner);
	cc_client_opus2pcmu_async_runner_free(cc_client, &opus2pcmu_async_runner);
	cc_client_pcma2opus_async_runner_free(cc_client, &pcma2opus_async_runner);
	cc_client_pcmu2opus_async_runner_free(cc_client, &pcmu2opus_async_runner);
}

#else

static void cc_init(void) { }
static void cc_cleanup(void) { }

#endif

void codeclib_init(int print) {
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
	av_register_all();
	avcodec_register_all();
	avfilter_register_all();
#endif
	avformat_network_init();
	av_log_set_callback(avlog_ilog);

	codecs_ht = g_hash_table_new((GHashFunc) str_case_hash, (GEqualFunc) str_case_equal);
	codecs_ht_by_av = g_hash_table_new(g_direct_hash, g_direct_equal);

	cc_init();

	for (int i = 0; i < G_N_ELEMENTS(__codec_defs); i++) {
		// add to hash table
		struct codec_def_s *def = &__codec_defs[i];
		def->rtpname_str = STR(def->rtpname);
		assert(g_hash_table_lookup(codecs_ht, &def->rtpname_str) == NULL);
		g_hash_table_insert(codecs_ht, &def->rtpname_str, def);

		if (def->avcodec_id >= 0) {
			if (g_hash_table_lookup(codecs_ht_by_av, GINT_TO_POINTER(def->avcodec_id)) == NULL)
				g_hash_table_insert(codecs_ht_by_av, GINT_TO_POINTER(def->avcodec_id), def);
		}

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
		else
			def->rfc_payload_type = -1;

		if (def->codec_type && def->codec_type->def_init)
			def->codec_type->def_init(def);

		if (!strcmp(def->rtpname, "CN"))
			codec_def_cn = def;

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






static int ptr_cmp(const void *a, const void *b, void *dummy) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

void __packet_sequencer_init(packet_sequencer_t *ps, GDestroyNotify ffunc) {
	ps->packets = g_tree_new_full(ptr_cmp, NULL, NULL, ffunc);
	ps->seq = -1;
}
void packet_sequencer_destroy(packet_sequencer_t *ps) {
	if (ps->packets)
		g_tree_destroy(ps->packets);
	ps->packets = NULL;
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
static void *__packet_sequencer_next_packet(packet_sequencer_t *ps, int num_wait) {
	// see if we have a packet with the correct seq nr in the queue
	seq_packet_t *packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ps->seq));
	if (G_LIKELY(packet != NULL)) {
		cdbg("returning in-sequence packet (seq %i)", ps->seq);
		goto out;
	}

	// why not? do we have anything? (we should)
	int nnodes = g_tree_nnodes(ps->packets);
	if (G_UNLIKELY(nnodes == 0)) {
		cdbg("packet queue empty");
		return NULL;
	}
	if (G_LIKELY(nnodes < num_wait)) {
		cdbg("only %i packets in queue - waiting for more", nnodes);
		return NULL; // need to wait for more
	}

	// packet was probably lost. search for the next highest seq
	struct tree_searcher ts = { .find_seq = ps->seq + 1, .found_seq = -1 };
	packet = g_tree_search(ps->packets, packet_tree_search, &ts);
	if (packet) {
		// bullseye
		cdbg("lost packet - returning packet with next seq %i", packet->seq);
		goto out;
	}
	if (G_UNLIKELY(ts.found_seq == -1)) {
		// didn't find anything. seq must have wrapped around. retry
		// starting from zero
		ts.find_seq = 0;
		packet = g_tree_search(ps->packets, packet_tree_search, &ts);
		if (packet) {
			cdbg("lost packet - returning packet with next seq %i (after wrap)", packet->seq);
			goto out;
		}
		if (G_UNLIKELY(ts.found_seq == -1))
			abort();
	}

	// pull out the packet we found
	packet = g_tree_lookup(ps->packets, GINT_TO_POINTER(ts.found_seq));
	if (G_UNLIKELY(packet == NULL))
		abort();

	cdbg("lost multiple packets - returning packet with next highest seq %i", packet->seq);

out:
	;
	uint16_t l = packet->seq - ps->seq;
	ps->lost_count += l;

	g_tree_steal(ps->packets, GINT_TO_POINTER(packet->seq));
	ps->seq = (packet->seq + 1) & 0xffff;

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

int packet_sequencer_next_ok(packet_sequencer_t *ps) {
	if (g_tree_lookup(ps->packets, GINT_TO_POINTER(ps->seq)))
		return 1;
	return 0;
}

int packet_sequencer_insert(packet_sequencer_t *ps, seq_packet_t *p) {
	int ret = 0;

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
	ret = 1;
	// seq ok - fall through
	g_tree_clear(ps->packets);
seq_ok:
	if (g_tree_lookup(ps->packets, GINT_TO_POINTER(p->seq)))
		return -1;
	ret = g_tree_nnodes(ps->packets) == 0 ? ret : 2; // indicates an out-of-order packet
	g_tree_insert(ps->packets, GINT_TO_POINTER(p->seq), p);

	return ret;
}




encoder_t *encoder_new(void) {
	encoder_t *ret = g_slice_alloc0(sizeof(*ret));
	format_init(&ret->requested_format);
	format_init(&ret->actual_format);
	ret->avpkt = av_packet_alloc();
	return ret;
}

static const char *avc_encoder_init(encoder_t *enc, const str *extra_opts) {
	enc->avc.codec = enc->def->encoder;
	if (!enc->avc.codec)
		return "output codec not found";

	enc->avc.avcctx = avcodec_alloc_context3(enc->avc.codec);
	if (!enc->avc.avcctx)
		return "failed to alloc codec context";

	enc->actual_format = enc->requested_format;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(61, 19, 0)
	avcodec_get_supported_config(enc->avc.avcctx, enc->avc.codec, AV_CODEC_CONFIG_SAMPLE_FORMAT, 0, (const void **) &enc->avc.sample_fmts, NULL);
#else
	enc->avc.sample_fmts = enc->avc.codec->sample_fmts;
#endif

	enc->actual_format.format = -1;
	for (const enum AVSampleFormat *sfmt = enc->avc.sample_fmts; sfmt && *sfmt != -1; sfmt++) {
		cdbg("supported sample format for output codec %s: %s",
				enc->avc.codec->name, av_get_sample_fmt_name(*sfmt));
		if (*sfmt == enc->requested_format.format)
			enc->actual_format.format = *sfmt;
	}
	if (enc->actual_format.format == -1 && enc->avc.sample_fmts)
		enc->actual_format.format = enc->avc.sample_fmts[0];
	cdbg("using output sample format %s for codec %s",
			av_get_sample_fmt_name(enc->actual_format.format), enc->avc.codec->name);

	SET_CHANNELS(enc->avc.avcctx, enc->actual_format.channels);
	DEF_CH_LAYOUT(&enc->avc.avcctx->CH_LAYOUT, enc->actual_format.channels);
	enc->avc.avcctx->sample_rate = enc->actual_format.clockrate;
	enc->avc.avcctx->sample_fmt = enc->actual_format.format;
	enc->avc.avcctx->time_base = (AVRational){1,enc->actual_format.clockrate};
	enc->avc.avcctx->bit_rate = enc->bitrate;

	enc->samples_per_frame = enc->actual_format.clockrate * enc->ptime / 1000;
	if (enc->avc.avcctx->frame_size)
		enc->samples_per_frame = enc->avc.avcctx->frame_size;
	enc->samples_per_packet = enc->samples_per_frame;

	if (enc->def->set_enc_options)
		enc->def->set_enc_options(enc, extra_opts);

	int i = avcodec_open2(enc->avc.avcctx, enc->avc.codec, NULL);
	if (i) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(i));
		return "failed to open output context";
	}

	return NULL;
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
	if (codec_parse_fmtp(def, fmtp, fmtp_string, &enc->format_options))
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

static void avc_encoder_close(encoder_t *enc) {
	if (enc->avc.avcctx) {
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(61, 0, 0)
		avcodec_close(enc->avc.avcctx);
#endif
		avcodec_free_context(&enc->avc.avcctx);
	}
	enc->avc.avcctx = NULL;
	enc->avc.codec = NULL;
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
	g_slice_free1(sizeof(*enc), enc);
}

static int avc_encoder_input(encoder_t *enc, AVFrame **frame) {
	int keep_going = 0;
	int got_packet = 0;
	int av_ret = 0;

	if (!enc->avc.avcctx)
		return -1;

#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(57, 36, 0)
	if (*frame) {
		av_ret = avcodec_send_frame(enc->avc.avcctx, *frame);
		cdbg("send frame ret %i", av_ret);
		if (av_ret == 0) {
			// consumed
			*frame = NULL;
			keep_going = 1;
		}
		else {
			if (av_ret == AVERROR(EAGAIN))
				; // check output and maybe try again
			else
				goto err;
		}
	}

	av_ret = avcodec_receive_packet(enc->avc.avcctx, enc->avpkt);
	cdbg("receive packet ret %i", av_ret);
	if (av_ret == 0) {
		// got some data
		keep_going = 1;
		got_packet = 1;
	}
	else {
		if (av_ret == AVERROR(EAGAIN))
			; // try again if there's still more input
		else
			goto err;
	}
#else
	if (!*frame)
		return 0;

	av_ret = avcodec_encode_audio2(enc->avc.avcctx, enc->avpkt, *frame, &got_packet);
	cdbg("encode frame ret %i, got packet %i", av_ret, got_packet);
	if (av_ret == 0)
		*frame = NULL; // consumed
	else
		goto err;
	if (got_packet)
		keep_going = 1;
#endif

	if (!got_packet)
		return keep_going;

	cdbg("output avpkt size is %i", (int) enc->avpkt->size);
	cdbg("output pkt pts/dts is %li/%li", (long) enc->avpkt->pts,
			(long) enc->avpkt->dts);

	// the encoder may return frames with the same dts multiple consecutive times.
	// the muxer may not like this, so ensure monotonically increasing dts.
	if (enc->mux_dts > enc->avpkt->dts)
		enc->avpkt->dts = enc->mux_dts;
	if (enc->avpkt->pts < enc->avpkt->dts)
		enc->avpkt->pts = enc->avpkt->dts;

	return keep_going;

err:
	if (av_ret)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error returned from libav: %s", av_error(av_ret));
	return -1;
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


int packetizer_passthrough(AVPacket *pkt, GString *buf, str *output, encoder_t *enc) {
	if (!pkt)
		return -1;
	if (output->len < pkt->size) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Output packet size too small (%zu < %i)",
				output->len, pkt->size);
		return -1;
	}
	output->len = pkt->size;
	memcpy(output->s, pkt->data, pkt->size);
	return 0;
}

// returns: -1 = not enough data, nothing returned; 0 = returned a packet;
// 1 = returned a packet and there's more
static int packetizer_samplestream(AVPacket *pkt, GString *buf, str *input_output, encoder_t *enc) {
	// avoid moving buffers around if possible:
	// most common case: new input packet has just enough (or more) data as what we need
	if (G_LIKELY(pkt && buf->len == 0 && pkt->size >= input_output->len)) {
		memcpy(input_output->s, pkt->data, input_output->len);
		// any leftovers?
		if (pkt->size > input_output->len) {
			g_string_append_len(buf, (char *) pkt->data + input_output->len,
					pkt->size - input_output->len);
			enc->packet_pts = pkt->pts + input_output->len
				* (fraction_mult(enc->def->bits_per_sample, &enc->clockrate_fact) / 8);
		}
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
	// adjust output pts
	enc->avpkt->pts = enc->packet_pts;
	enc->packet_pts += input_output->len
		* fraction_mult(enc->def->bits_per_sample, &enc->clockrate_fact) / 8;
	return buf->len >= input_output->len ? 1 : 0;
}


static int codeclib_set_av_opt_int(encoder_t *enc, const char *opt, int64_t val) {
	ilog(LOG_DEBUG, "Setting ffmpeg '%s' option for '%s' to %" PRId64,
			opt, enc->def->rtpname, val);

	int ret = av_opt_set_int(enc->avc.avcctx, opt, val, AV_OPT_SEARCH_CHILDREN);
	if (!ret)
		return 0;

	ilog(LOG_WARN, "Failed to set ffmpeg '%s' option for codec '%s' to %" PRId64 ": %s",
			opt, enc->def->rtpname, val, av_error(ret));
	return -1;
}
static int codeclib_set_av_opt_intstr(encoder_t *enc, const char *opt, str *val) {
	int i = val ? str_to_i(val, -1) : -1;
	if (i == -1) {
		ilog(LOG_WARN, "Failed to parse '" STR_FORMAT "' as integer value for ffmpeg option '%s'",
				STR_FMT0(val), opt);
		return -1;
	}
	return codeclib_set_av_opt_int(enc, opt, i);
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

static const char *libopus_decoder_init(decoder_t *dec, const str *extra_opts) {
	if (dec->in_format.channels != 1 && dec->in_format.channels != 2)
		return "invalid number of channels";
	switch (dec->in_format.clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			break;
		default:
			return "invalid clock rate";
	}

	int err = 0;
	dec->opus = opus_decoder_create(dec->in_format.clockrate, dec->in_format.channels, &err);
	if (!dec->opus) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error from libopus: %s", opus_strerror(err));
		return "failed to alloc codec context";
	}

	return NULL;
}
static void libopus_decoder_close(decoder_t *dec) {
	opus_decoder_destroy(dec->opus);
}
static int libopus_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	// get frame with buffer large enough for the max
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = 960;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = dec->in_format.clockrate;
	DEF_CH_LAYOUT(&frame->CH_LAYOUT, dec->in_format.channels);
	frame->pts = dec->pts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	int ret = opus_decode(dec->opus, (unsigned char *) data->s, data->len,
			(int16_t *) frame->extended_data[0], frame->nb_samples, 0);
	if (ret < 0) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error decoding Opus packet: %s", opus_strerror(ret));
		av_frame_free(&frame);
		return -1;
	}

	frame->nb_samples = ret;
	g_queue_push_tail(out, frame);
	return 0;
}

struct libopus_encoder_options {
	int complexity;
	int vbr;
	int vbr_constraint;
	int pl;
	int application;
};
static void libopus_set_enc_opts(str *key, str *val, void *p) {
	struct libopus_encoder_options *opts = p;

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("complexity"):
		case CSH_LOOKUP("compression_level"):
			opts->complexity = str_to_i(val, -1);
			break;
		case CSH_LOOKUP("application"):
			switch (__csh_lookup(val)) {
				case CSH_LOOKUP("VOIP"):
				case CSH_LOOKUP("VoIP"):
				case CSH_LOOKUP("voip"):
					opts->application = OPUS_APPLICATION_VOIP;
					break;
				case CSH_LOOKUP("audio"):
					opts->application = OPUS_APPLICATION_AUDIO;
					break;
				case CSH_LOOKUP("low-delay"):
				case CSH_LOOKUP("low delay"):
				case CSH_LOOKUP("lowdelay"):
					opts->application = OPUS_APPLICATION_RESTRICTED_LOWDELAY;
					break;
				default:
					ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unknown Opus application: '"
							STR_FORMAT "'", STR_FMT(val));
			};
			break;
		case CSH_LOOKUP("vbr"):
		case CSH_LOOKUP("VBR"):
			// aligned with ffmpeg vbr=0/1/2 option
			opts->vbr = str_to_i(val, -1);
			if (opts->vbr == 2) {
				opts->vbr = 1;
				opts->vbr_constraint = 1;
			}
			break;
		case CSH_LOOKUP("packet_loss"):
		case CSH_LOOKUP("packet loss"):
			opts->pl = str_to_i(val, -1);
			break;
		default:
			ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unknown Opus encoder option encountered: '"
					STR_FORMAT "'", STR_FMT(key));
	}
}
static const char *libopus_encoder_init(encoder_t *enc, const str *extra_opts) {
	if (enc->requested_format.channels != 1 && enc->requested_format.channels != 2)
		return "invalid number of channels";

	if (enc->requested_format.format == -1)
		enc->requested_format.format = AV_SAMPLE_FMT_S16;
	else if (enc->requested_format.format != AV_SAMPLE_FMT_S16)
		return "invalid sample format";

	switch (enc->requested_format.clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			break;
		default:
			return "invalid clock rate";
	}

	struct libopus_encoder_options opts = { .vbr = 1, .complexity = 10, .application = OPUS_APPLICATION_VOIP };
	codeclib_key_value_parse(extra_opts, true, libopus_set_enc_opts, &opts);

	int err;
	enc->opus = opus_encoder_create(enc->requested_format.clockrate, enc->requested_format.channels,
			opts.application, &err);
	if (!enc->opus) {
		ilog(LOG_ERR, "Error from libopus: %s", opus_strerror(err));
		return "failed to alloc codec context";
	}

	enc->actual_format = enc->requested_format;

	enc->samples_per_frame = enc->actual_format.clockrate * enc->ptime / 1000;
	enc->samples_per_packet = enc->samples_per_frame;

	err = opus_encoder_ctl(enc->opus, OPUS_SET_BITRATE(enc->bitrate));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus bitrate to %i: %s", enc->bitrate,
				opus_strerror(err));

	err = opus_encoder_ctl(enc->opus, OPUS_SET_COMPLEXITY(opts.complexity));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus complexity to %i': %s",
				opts.complexity, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_VBR(opts.vbr));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus VBR to %i': %s",
				opts.vbr, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_VBR_CONSTRAINT(opts.vbr_constraint));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus VBR constraint to %i': %s",
				opts.vbr_constraint, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_PACKET_LOSS_PERC(opts.pl));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus PL%% to %i': %s",
				opts.pl, opus_strerror(err));
	err = opus_encoder_ctl(enc->opus, OPUS_SET_INBAND_FEC(enc->format_options.opus.fec_send >= 0));
	if (err != OPUS_OK)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Failed to set Opus FEC to %i': %s",
				enc->format_options.opus.fec_send >= 0, opus_strerror(err));

	return NULL;
}
static void libopus_encoder_close(encoder_t *enc) {
	opus_encoder_destroy(enc->opus);
}
#define MAX_OPUS_FRAME_SIZE 1275 /* 20 ms at 510 kbps */
#define MAX_OPUS_FRAMES_PER_PACKET 6 /* 120 ms = 6 * 20 ms */
#define MAX_OPUS_HEADER_SIZE 7
static int libopus_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	// max length of Opus packet:
	av_new_packet(enc->avpkt, MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE);

	int ret = opus_encode(enc->opus, (int16_t *) (*frame)->extended_data[0], (*frame)->nb_samples,
			enc->avpkt->data, enc->avpkt->size);
	if (ret < 0) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Error encoding Opus packet: %s", opus_strerror(ret));
		av_packet_unref(enc->avpkt);
		return -1;
	}

	enc->avpkt->size = ret;
	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = (*frame)->nb_samples;

	return 0;
}






// opus RTP always runs at 48 kHz
static void opus_select_encoder_format(encoder_t *enc, format_t *req_format, const format_t *f,
		const struct rtp_codec_format *fmtp)
{
	if (req_format->clockrate != 48000)
		return; // bail - encoder will fail to initialise

	// check against natively supported rates first
	switch (f->clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			enc->clockrate_fact = (struct fraction) {1, 48000 / f->clockrate};
			break;
		default:
			// resample to next best rate
			if (f->clockrate > 24000)
				enc->clockrate_fact = (struct fraction) {1,1};
			else if (f->clockrate > 16000)
				enc->clockrate_fact = (struct fraction) {1,2};
			else if (f->clockrate > 12000)
				enc->clockrate_fact = (struct fraction) {1,3};
			else if (f->clockrate > 8000)
				enc->clockrate_fact = (struct fraction) {1,4};
			else
				enc->clockrate_fact = (struct fraction) {1,6};
			break;
	}

	// honour remote stereo=0/1 flag if given,
	// otherwise go with the input format
	if (fmtp && fmtp->parsed.opus.stereo_send == -1)
		req_format->channels = 1;
	else if (fmtp && fmtp->parsed.opus.stereo_send == 1)
		req_format->channels = 2;
	else if (req_format->channels == 2 && f->channels == 1)
		req_format->channels = 1;
}
static void opus_select_decoder_format(decoder_t *dec, const struct rtp_codec_format *fmtp) {
	if (dec->in_format.clockrate != 48000)
		return;

	// check against natively supported rates first
	switch (dec->dest_format.clockrate) {
		case 48000:
		case 24000:
		case 16000:
		case 12000:
		case 8000:
			dec->clockrate_fact = (struct fraction) {1, 48000 / dec->dest_format.clockrate};
			break;
		default:
			// resample to next best rate
			if (dec->dest_format.clockrate > 24000)
				dec->clockrate_fact = (struct fraction) {1,1};
			else if (dec->dest_format.clockrate > 16000)
				dec->clockrate_fact = (struct fraction) {1,2};
			else if (dec->dest_format.clockrate > 12000)
				dec->clockrate_fact = (struct fraction) {1,3};
			else if (dec->dest_format.clockrate > 8000)
				dec->clockrate_fact = (struct fraction) {1,4};
			else
				dec->clockrate_fact = (struct fraction) {1,6};
			break;
	}

	// switch to mono decoding if possible
	if (dec->in_format.channels == 2 && dec->dest_format.channels == 1)
		dec->in_format.channels = 1;
}
static void opus_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;
	__auto_type o = &opts->opus;

	switch (__csh_lookup(key)) {
#define YNFLAG(flag, varname) \
		case flag: \
			if (token->len == 1 && token->s[0] == '1') \
				o->varname = 1; \
			else if (token->len == 1 && token->s[0] == '0') \
				o->varname = -1; \
			break;
		YNFLAG(CSH_LOOKUP("stereo"), stereo_recv)
		YNFLAG(CSH_LOOKUP("sprop-stereo"), stereo_send)
		YNFLAG(CSH_LOOKUP("useinbandfec"), fec_recv)
		YNFLAG(CSH_LOOKUP("cbr"), cbr)
		YNFLAG(CSH_LOOKUP("usedtx"), fec_recv)
#undef YNFLAG
		case CSH_LOOKUP("maxplaybackrate"):
			opts->opus.maxplaybackrate = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("sprop-maxcapturerate"):
			opts->opus.sprop_maxcapturerate = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("maxaveragebitrate"):
			opts->opus.maxaveragebitrate = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("minptime"):
			opts->opus.minptime = str_to_i(token, 0);
			break;
	}
}
static int opus_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	codeclib_key_value_parse(fmtp, true, opus_parse_format_cb, &f->parsed);
	return 0;
}
static GString *opus_format_print(const struct rtp_payload_type *p) {
	if (!p->format.fmtp_parsed)
		return NULL;

	GString *s = g_string_new("");
	__auto_type f = &p->format.parsed.opus;

	if (f->stereo_recv)
		g_string_append_printf(s, "stereo=%i; ", f->stereo_recv == -1 ? 0 : 1);
	if (f->stereo_send)
		g_string_append_printf(s, "sprop-stereo=%i; ", f->stereo_send == -1 ? 0 : 1);
	if (f->fec_recv)
		g_string_append_printf(s, "useinbandfec=%i; ", f->fec_recv == -1 ? 0 : 1);
	if (f->usedtx)
		g_string_append_printf(s, "usedtx=%i; ", f->usedtx == -1 ? 0 : 1);
	if (f->cbr)
		g_string_append_printf(s, "cbr=%i; ", f->cbr == -1 ? 0 : 1);
	if (f->maxplaybackrate)
		g_string_append_printf(s, "maxplaybackrate=%i; ", f->maxplaybackrate);
	if (f->maxaveragebitrate)
		g_string_append_printf(s, "maxaveragebitrate=%i; ", f->maxaveragebitrate);
	if (f->sprop_maxcapturerate)
		g_string_append_printf(s, "sprop-maxcapturerate=%i; ", f->sprop_maxcapturerate);
	if (f->minptime)
		g_string_append_printf(s, "minptime=%i; ", f->minptime);

	if (s->len != 0)
		g_string_truncate(s, s->len - 2);

	return s;
}
static void opus_format_answer(struct rtp_payload_type *p, const struct rtp_payload_type *src) {
	if (!p->format.fmtp_parsed)
		return;

	__auto_type f = &p->format.parsed.opus;

	// swap send/recv

	int t = f->stereo_send;
	f->stereo_send = f->stereo_recv;
	f->stereo_recv = t;

	t = f->fec_send;
	f->fec_send = f->fec_recv;
	f->fec_recv = t;

	// if stereo recv is unset, base it on input format
	if (f->stereo_recv == 0)
		f->stereo_recv = src->channels == 1 ? -1 : 1;

	// we can always use FEC, unless we've been told that we should lie
	if (f->fec_recv == 0)
		f->fec_recv = 1;

	// set everything unsupported to 0
	f->usedtx = 0;
	f->cbr = 0;
	f->maxplaybackrate = 0;
	f->sprop_maxcapturerate = 0;
	f->maxaveragebitrate = 0;
	f->minptime = 0;
}




static int ilbc_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	switch (__csh_lookup(fmtp)) {
		case CSH_LOOKUP("mode=20"):
			f->parsed.ilbc.mode = 20;
			break;
		case CSH_LOOKUP("mode=30"):
			f->parsed.ilbc.mode = 30;
			break;
		default:
			return -1;
	}
	f->fmtp_parsed = 1;
	return 0;
}

static int ilbc_mode(int ptime, const union codec_format_options *fmtp, const char *direction) {
	int mode = 0;
	if (fmtp)
		mode = fmtp->ilbc.mode;

	if (!mode) {
		switch (ptime) {
			case 20:
			case 40:
			case 60:
			case 80:
			case 100:
			case 120:
				mode = 20;
				ilog(LOG_DEBUG, "Setting iLBC %s mode to 20 ms based on ptime %i",
						direction, ptime);
				break;
			case 30:
			case 90:
				mode = 30;
				ilog(LOG_DEBUG, "Setting iLBC %s mode to 30 ms based on ptime %i",
						direction, ptime);
				break;
		}
	}

	if (!mode) {
		mode = 20;
		ilog(LOG_WARNING, "No iLBC %s mode specified, setting to 20 ms", direction);
	}

	return mode;
}

static void ilbc_set_enc_options(encoder_t *enc, const str *codec_opts) {
	int mode = ilbc_mode(enc->ptime, &enc->format_options, "encoder");
	codeclib_set_av_opt_int(enc, "mode", mode);
}

static void ilbc_set_dec_options(decoder_t *dec, const str *codec_opts) {
	int mode = ilbc_mode(dec->ptime, &dec->format_options, "decoder");
	if (mode == 20)
		dec->avc.avcctx->block_align = 38;
	else if (mode == 30)
		dec->avc.avcctx->block_align = 50;
	else
		ilog(LOG_WARN, "Unsupported iLBC mode %i", mode);
}

static int ilbc_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	int mode = 0, block_align = 0;
	static const union codec_format_options mode_20 = { .ilbc = { 20 } };
	static const union codec_format_options mode_30 = { .ilbc = { 30 } };
	const union codec_format_options *fmtp;

	if (data->len % 50 == 0) {
		mode = 30;
		block_align = 50;
		fmtp = &mode_30;
	}
	else if (data->len % 38 == 0) {
		mode = 20;
		block_align = 38;
		fmtp = &mode_20;
	}
	else
		ilog(LOG_WARNING | LOG_FLAG_LIMIT, "iLBC received %i bytes packet, does not match "
				"one of the block sizes", (int) data->len);

	if (block_align && dec->avc.avcctx->block_align != block_align) {
		ilog(LOG_INFO | LOG_FLAG_LIMIT, "iLBC decoder set to %i bytes blocks, but received packet "
				"of %i bytes, therefore resetting decoder and switching to %i bytes "
				"block mode (%i ms mode)",
				(int) dec->avc.avcctx->block_align, (int) data->len, block_align, mode);
		avc_decoder_close(dec);
		dec->format_options = *fmtp;
		avc_decoder_init(dec, NULL);
	}

	return avc_decoder_input(dec, data, out);
}


static void codeclib_key_value_parse(const str *instr, bool need_value,
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





static const unsigned int amr_bitrates[AMR_FT_TYPES] = {
	4750, // 0
	5150, // 1
	5900, // 2
	6700, // 3
	7400, // 4
	7950, // 5
	10200, // 6
	12200, // 7
	0, // comfort noise // 8
	0, // comfort noise // 9
	0, // comfort noise // 10
	0, // comfort noise // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_bits_per_frame[AMR_FT_TYPES] = {
	95, // 4.75 kbit/s // 0
	103, // 5.15 kbit/s // 1
	118, // 5.90 kbit/s // 2
	134, // 6.70 kbit/s // 3
	148, // 7.40 kbit/s // 4
	159, // 7.95 kbit/s // 5
	204, // 10.2 kbit/s // 6
	244, // 12.2 kbit/s // 7
	40, // comfort noise // 8
	40, // comfort noise // 9
	40, // comfort noise // 10
	40, // comfort noise // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_wb_bitrates[AMR_FT_TYPES] = {
	6600, // 0
	8850, // 1
	12650, // 2
	14250, // 3
	15850, // 4
	18250, // 5
	19850, // 6
	23050, // 7
	23850, // 8
	0, // comfort noise // 9
	0, // invalid // 10
	0, // invalid // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_wb_bits_per_frame[AMR_FT_TYPES] = {
	132, // 6.60 kbit/s // 0
	177, // 8.85 kbit/s // 1
	253, // 12.65 kbit/s // 2
	285, // 14.25 kbit/s // 3
	317, // 15.85 kbit/s // 4
	365, // 18.25 kbit/s // 5
	397, // 19.85 kbit/s // 6
	461, // 23.05 kbit/s // 7
	477, // 23.85 kbit/s // 8
	40, // comfort noise // 9
	0, // invalid // 10
	0, // invalid // 11
	0, // invalid // 12
	0, // invalid // 13
};
static void amr_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("octet-align"):
			if (token->len == 1 && token->s[0] == '1')
				opts->amr.octet_aligned = 1;
			break;
		case CSH_LOOKUP("crc"):
			if (token->len == 1 && token->s[0] == '1') {
				opts->amr.octet_aligned = 1;
				opts->amr.crc = 1;
			}
			break;
		case CSH_LOOKUP("robust-sorting"):
			if (token->len == 1 && token->s[0] == '1') {
				opts->amr.octet_aligned = 1;
				opts->amr.robust_sorting = 1;
			}
			break;
		case CSH_LOOKUP("interleaving"):
			opts->amr.octet_aligned = 1;
			opts->amr.interleaving = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("mode-set"):;
			str mode;
			while (str_token_sep(&mode, token, ',')) {
				int m = str_to_i(&mode, -1);
				if (m < 0 || m >= AMR_FT_TYPES)
					continue;
				opts->amr.mode_set |= (1 << m);
			}
			break;
		case CSH_LOOKUP("mode-change-period"):
			opts->amr.mode_change_period = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("mode-change-neighbor"):
			if (token->len == 1 && token->s[0] == '1')
				opts->amr.mode_change_neighbor = 1;
			break;
	}
}
static int amr_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	codeclib_key_value_parse(fmtp, true, amr_parse_format_cb, f);
	return 0;
}
static void amr_set_encdec_options(codec_options_t *opts, codec_def_t *def) {
	if (!strcmp(def->rtpname, "AMR")) {
		opts->amr.bits_per_frame = amr_bits_per_frame;
		opts->amr.bitrates = amr_bitrates;
	}
	else {
		opts->amr.bits_per_frame = amr_wb_bits_per_frame;
		opts->amr.bitrates = amr_wb_bitrates;
	}
}
static void amr_set_dec_codec_options(str *key, str *value, void *data) {
	decoder_t *dec = data;

	if (!str_cmp(key, "CMR-interval"))
		dec->codec_options.amr.cmr_interval = str_to_i(value, 0);
	else if (!str_cmp(key, "mode-change-interval"))
		dec->codec_options.amr.mode_change_interval = str_to_i(value, 0);

}
static void amr_set_enc_codec_options(str *key, str *value, void *data) {
	encoder_t *enc = data;

	if (!str_cmp(key, "CMR-interval"))
		; // not an encoder option
	else if (!str_cmp(key, "mode-change-interval"))
		; // not an encoder option
	else {
		// our string might not be null terminated
		char *s = g_strdup_printf(STR_FORMAT, STR_FMT(key));
		codeclib_set_av_opt_intstr(enc, s, value);
		g_free(s);
	}
}
static void amr_set_enc_options(encoder_t *enc, const str *codec_opts) {
	amr_set_encdec_options(&enc->codec_options, enc->def);

	codeclib_key_value_parse(codec_opts, true, amr_set_enc_codec_options, enc);

	// if a mode-set was given, pick the highest supported bitrate
	if (enc->format_options.amr.mode_set) {
		int max_bitrate = enc->avc.avcctx->bit_rate;
		int use_bitrate = 0;
		for (int i = 0; i < AMR_FT_TYPES; i++) {
			if (!(enc->format_options.amr.mode_set & (1 << i)))
				continue;
			unsigned int br = enc->codec_options.amr.bitrates[i];
			// we depend on the list being in ascending order, with
			// invalid modes at the end
			if (!br) // end of list
				break;
			if (br > max_bitrate && use_bitrate) // done
				break;
			use_bitrate = br;
		}
		if (!use_bitrate)
			ilog(LOG_WARN, "Unable to determine a valid bitrate from %s mode-set, using default",
					enc->def->rtpname);
		else {
			ilog(LOG_DEBUG, "Using %i as initial %s bitrate based on mode-set",
					use_bitrate, enc->def->rtpname);
			enc->avc.avcctx->bit_rate = use_bitrate;
		}
	}
}
static void amr_set_dec_options(decoder_t *dec, const str *codec_opts) {
	amr_set_encdec_options(&dec->codec_options, dec->def);
	codeclib_key_value_parse(codec_opts, true, amr_set_dec_codec_options, dec);
}
static int amr_mode_set_cmp(unsigned int a, unsigned int b) {
	if (a && b) {
		// `a` must be broader than `b`:
		// `b` must not have any bits set that `a` has set
		if (a == b)
			return 0;
		else if ((b & ~a) == 0)
			return 1;
		else
			return -1;
	}
	else if (!a && b) // `a` is broader (allow anything) than `b` (restricted)
		return 1;
	else if (a && !b)
		return -1;
	return 0;
}
static int amr_format_cmp(const struct rtp_payload_type *A, const struct rtp_payload_type *B) {
	// params must have been parsed successfully
	if (!A->format.fmtp_parsed || !B->format.fmtp_parsed)
		return -1;

	__auto_type a = &A->format.parsed.amr;
	__auto_type b = &B->format.parsed.amr;

	// reject anything that is outright incompatible (RFC 4867, 8.3.1)
	if (a->octet_aligned != b->octet_aligned)
		return -1;
	if (a->crc != b->crc)
		return -1;
	if (a->interleaving != b->interleaving)
		return -1;
	if (a->robust_sorting != b->robust_sorting)
		return -1;

	// determine whether codecs are compatible
	int compat = 0;

	if (a->mode_change_neighbor != b->mode_change_neighbor)
		compat++;
	if (a->mode_change_period != b->mode_change_period)
		compat++;

	int match = amr_mode_set_cmp(a->mode_set, b->mode_set);
	if (match == 1)
		compat++;
	else if (match == -1)
		return -1;

	return (compat == 0) ? 0 : 1;
}

static void amr_bitrate_tracker(decoder_t *dec, unsigned int ft) {
	if (dec->codec_options.amr.cmr_interval <= 0)
		return;

	if (dec->avc.amr.tracker_end.tv_sec
			&& timeval_cmp(&dec->avc.amr.tracker_end, &rtpe_now) >= 0) {
		// analyse the data we gathered
		int next_highest = -1;
		int lowest_used = -1;
		for (int i = 0; i < AMR_FT_TYPES; i++) {
			unsigned int br = dec->codec_options.amr.bitrates[i];
			if (!br)
				break; // end of list

			// ignore restricted modes
			if (dec->format_options.amr.mode_set) {
				if (!(dec->format_options.amr.mode_set & (1 << i)))
					continue;
			}

			// would this be a "next step up" mode?
			if (next_highest == -1)
				next_highest = i;

			// did we see any frames?
			if (!dec->avc.amr.bitrate_tracker[i])
				continue;

			next_highest = -1;
			lowest_used = i;
		}

		if (lowest_used != -1 && next_highest != -1) {
			// we can request a switch up
			ilog(LOG_DEBUG, "Sending %s CMR to request upping bitrate to %u",
					dec->def->rtpname, dec->codec_options.amr.bitrates[next_highest]);
			decoder_event(dec, CE_AMR_SEND_CMR, GINT_TO_POINTER(next_highest));
		}

		// and reset tracker
		ZERO(dec->avc.amr.tracker_end);
	}

	if (!dec->avc.amr.tracker_end.tv_sec) {
		// init
		ZERO(dec->avc.amr.bitrate_tracker);
		dec->avc.amr.tracker_end = rtpe_now;
		timeval_add_usec(&dec->avc.amr.tracker_end, dec->codec_options.amr.cmr_interval * 1000);
	}

	dec->avc.amr.bitrate_tracker[ft]++;
}
static int amr_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	const char *err = NULL;
	g_auto(GQueue) toc = G_QUEUE_INIT;

	if (!data || !data->s)
		goto err;

	bitstr d;
	bitstr_init(&d, data);

	unsigned int ill = 0, ilp = 0;

	unsigned char cmr_chr[2];
	str cmr = STR_CONST_BUF(cmr_chr);
	err = "no CMR";
	if (bitstr_shift_ret(&d, 4, &cmr))
		goto err;

	unsigned int cmr_int = cmr_chr[0] >> 4;
	if (cmr_int != 15) {
		decoder_event(dec, CE_AMR_CMR_RECV, GUINT_TO_POINTER(cmr_int));
		dec->avc.amr.last_cmr = rtpe_now;
	}
	else if (dec->codec_options.amr.mode_change_interval) {
		// no CMR, check if we're due to do our own mode change
		if (!dec->avc.amr.last_cmr.tv_sec) // start tracking now
			dec->avc.amr.last_cmr = rtpe_now;
		else if (timeval_diff(&rtpe_now, &dec->avc.amr.last_cmr)
				>= (long long) dec->codec_options.amr.mode_change_interval * 1000) {
			// switch up if we can
			decoder_event(dec, CE_AMR_CMR_RECV, GUINT_TO_POINTER(0xffff));
			dec->avc.amr.last_cmr = rtpe_now;
		}
	}

	if (dec->format_options.amr.octet_aligned) {
		if (bitstr_shift(&d, 4))
			goto err;

		if (dec->format_options.amr.interleaving) {
			unsigned char ill_ilp_chr[2];
			str ill_ilp = STR_CONST_BUF(ill_ilp_chr);
			err = "no ILL/ILP";
			if (bitstr_shift_ret(&d, 8, &ill_ilp))
				goto err;
			ill = ill_ilp_chr[0] >> 4;
			ilp = ill_ilp_chr[0] & 0xf;
		}
	}

	err = "ILP > ILL";
	if (ilp > ill)
		goto err;
	err = "interleaving unimplemented";
	if (ill)
		goto err;

	// TOC
	int num_crcs = 0;
	while (1) {
		unsigned char toc_byte[2];
		str toc_entry = STR_CONST_BUF(toc_byte);
		err = "missing TOC entry";
		if (bitstr_shift_ret(&d, 6, &toc_entry))
			goto err;

		if (dec->format_options.amr.octet_aligned)
			if (bitstr_shift(&d, 2))
				goto err;

		unsigned char ft = (toc_byte[0] >> 3) & 0xf;
		if (ft != 14 && ft != 15) {
			num_crcs++;
			err = "invalid frame type";
			if (ft >= AMR_FT_TYPES)
				goto err;
			if (dec->codec_options.amr.bits_per_frame[ft] == 0)
				goto err;
		}

		g_queue_push_tail(&toc, GUINT_TO_POINTER(toc_byte[0]));

		// no F bit = last TOC entry
		if (!(toc_byte[0] & 0x80))
			break;
	}

	if (dec->format_options.amr.crc) {
		// CRCs is one byte per frame
		err = "missing CRC entry";
		if (bitstr_shift(&d, num_crcs * 8))
			goto err;
		// XXX use/check CRCs
	}

	while (toc.length) {
		unsigned char toc_byte = GPOINTER_TO_UINT(g_queue_pop_head(&toc));
		unsigned char ft = (toc_byte >> 3) & 0xf;
		if (ft >= AMR_FT_TYPES) // invalid
			continue;

		unsigned int bits = dec->codec_options.amr.bits_per_frame[ft];

		// AMR decoder expects an octet aligned TOC byte plus the payload
		unsigned char frame_buf[(bits + 7) / 8 + 1 + 1];
		str frame = STR_CONST_BUF(frame_buf);
		str_shift(&frame, 1);
		err = "short frame";
		if (bitstr_shift_ret(&d, bits, &frame))
			goto err;

		// add TOC byte
		str_unshift(&frame, 1);
		frame.s[0] = toc_byte & 0x7c; // strip F bit, keep FT and Q, zero padding (01111100)

		if (dec->format_options.amr.octet_aligned && (bits % 8) != 0) {
			unsigned int padding_bits = 8 - (bits % 8);
			if (bitstr_shift(&d, padding_bits))
				goto err;
		}

		err = "failed to decode AMR data";
		if (bits == 40) {
			// SID
			if (dec->dtx.method_id == DTX_NATIVE) {
				if (avc_decoder_input(dec, &frame, out))
					goto err;
			}
			else {
				// use the DTX generator to replace SID
				if (dec->dtx.do_dtx(dec, out, 20))
					goto err;
			}
		}
		else {
			if (avc_decoder_input(dec, &frame, out))
				goto err;
		}

		amr_bitrate_tracker(dec, ft);
	}

	return 0;

err:
	if (err)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error unpacking AMR packet: %s", err);

	return -1;
}
static unsigned int amr_encoder_find_next_mode(encoder_t *enc) {
	int mode = -1;
	for (int i = 0; i < AMR_FT_TYPES; i++) {
		int br = enc->codec_options.amr.bitrates[i];
		if (!br) // end of list
			break;
		if (br == enc->avc.avcctx->bit_rate) {
			mode = i;
			break;
		}
	}
	if (mode == -1)
		return -1;
	int next_mode = mode + 1;
	// if modes are restricted, find the next one up
	if (enc->format_options.amr.mode_set) {
		// is there anything?
		if ((1 << next_mode) > enc->format_options.amr.mode_set)
			return -1;
		int next_up = -1;
		for (; next_mode < AMR_FT_TYPES; next_mode++) {
			if (!(enc->format_options.amr.mode_set & (1 << next_mode)))
				continue;
			next_up = next_mode;
			break;
		}
		if (next_up == -1)
			return -1;
		next_mode = next_up;
	}
	// valid mode?
	if (next_mode >= AMR_FT_TYPES || enc->codec_options.amr.bitrates[next_mode] == 0)
		return -1;
	return next_mode;
}
static void amr_encoder_mode_change(encoder_t *enc) {
	if (!memcmp(&enc->callback.amr.cmr_in_ts,
				&enc->avc.amr.cmr_in_ts, sizeof(struct timeval)))
		return;
	// mode change requested: check if this is allowed right now
	if (enc->format_options.amr.mode_change_period == 2 && (enc->avc.amr.pkt_seq & 1) != 0)
		return;
	unsigned int cmr = enc->callback.amr.cmr_in;
	if (cmr == 0xffff)
		cmr = amr_encoder_find_next_mode(enc);
	if (cmr >= AMR_FT_TYPES)
		return;
	// ignore CMR for invalid modes
	if (enc->format_options.amr.mode_set && !(enc->format_options.amr.mode_set & (1 << cmr)))
		return;
	int req_br = enc->codec_options.amr.bitrates[cmr];
	if (!req_br)
		return;
	int cmr_done = 1;
	if (enc->format_options.amr.mode_change_neighbor) {
		// handle non-neighbour mode changes
		int cur_br = enc->avc.avcctx->bit_rate;
		// step up or down from the requested bitrate towards the current one
		int cmr_diff = (req_br > cur_br) ? -1 : 1;
		int neigh_br = req_br;
		int cmr_br = req_br;
		while (1) {
			// step up or down towards the current bitrate
			cmr += cmr_diff;
			// still in bounds?
			if (cmr >= AMR_FT_TYPES)
				break;
			cmr_br = enc->codec_options.amr.bitrates[cmr];
			if (cmr_br == cur_br)
				break;
			// allowed by mode set?
			if (enc->format_options.amr.mode_set) {
				if (!(enc->format_options.amr.mode_set & (1 << cmr)))
					continue; // go to next mode
			}
			// valid bitrate - continue stepping
			neigh_br = cmr_br;
		}
		// did we finish stepping or is there more to go?
		if (neigh_br != req_br)
			cmr_done = 0;
		req_br = neigh_br; // set to this
	}
	enc->avc.avcctx->bit_rate = req_br;
	if (cmr_done)
		enc->avc.amr.cmr_in_ts = enc->callback.amr.cmr_in_ts;
}
static void amr_encoder_got_packet(encoder_t *enc) {
	amr_encoder_mode_change(enc);
	enc->avc.amr.pkt_seq++;
}
static int packetizer_amr(AVPacket *pkt, GString *buf, str *output, encoder_t *enc) {
	assert(pkt->size >= 1);

	// CMR + TOC byte (already included) + optional ILL/ILP + optional CRC + payload
	if (output->len < pkt->size + 3) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Output AMR packet size too small (%zu < %i + 3)",
				output->len, pkt->size);
		return -1;
	}

	unsigned char toc = pkt->data[0];
	unsigned char ft = (toc >> 3) & 0xf;
	if (ft > 15) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received bogus AMR FT %u from encoder", ft);
		return -1;
	}
	if (ft >= 14) {
		// NO_DATA or SPEECH_LOST
		return -1;
	}
	assert(ft < AMR_FT_TYPES); // internal bug
	unsigned int bits = enc->codec_options.amr.bits_per_frame[ft];
	if (bits == 0) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received bogus AMR FT %u from encoder", ft);
		return -1;
	}

	unsigned char *s = (unsigned char *) output->s; // for safe bit shifting

	s[0] = '\xf0'; // no CMR req (4 bits)

	// or do we have a CMR?
	if (!enc->avc.amr.cmr_out_seq) {
		if (memcmp(&enc->avc.amr.cmr_out_ts, &enc->callback.amr.cmr_out_ts,
					sizeof(struct timeval))) {
			enc->avc.amr.cmr_out_seq += 3; // make this configurable?
			enc->avc.amr.cmr_out_ts = enc->callback.amr.cmr_out_ts;
		}
	}
	if (enc->avc.amr.cmr_out_seq) {
		enc->avc.amr.cmr_out_seq--;
		unsigned int cmr = enc->callback.amr.cmr_out;
		if (cmr < AMR_FT_TYPES && enc->codec_options.amr.bitrates[cmr])
			s[0] = cmr << 4;
	}

	if (enc->format_options.amr.octet_aligned) {
		unsigned int offset = 1; // CMR byte
		if (enc->format_options.amr.interleaving)
			s[offset++] = 0; // no interleaving
		if (enc->format_options.amr.crc)
			s[offset++] = 0; // not implemented
		memcpy(s + offset, pkt->data, pkt->size);
		output->len = pkt->size + offset;
		return 0;
	}

	// bit shift TOC byte in (6 bits)
	s[0] |= pkt->data[0] >> 4;
	s[1] = (pkt->data[0] & 0x0c) << 4;

	// bit shift payload in (shifted by 4+6 = 10 bits = 1 byte + 2 bits
	for (int i = 1; i < pkt->size; i++) {
		s[i] |= pkt->data[i] >> 2;
		s[i+1] = pkt->data[i] << 6;
	}

	// is the last byte just padding?
	bits += 4 + 6; // CMR and TOC
	unsigned int bytes = (bits + 7) / 8;
	output->len = bytes;

	return 0;
}
static int amr_dtx(decoder_t *dec, GQueue *out, int ptime) {
	// ignore ptime, must be 20
	ilog(LOG_DEBUG, "pushing empty/lost frame to AMR decoder");
	unsigned char frame_buf[1];
	frame_buf[0] = 0xf << 3; // no data
	str frame = STR_CONST_BUF(frame_buf);
	if (avc_decoder_input(dec, &frame, out))
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error while writing 'no data' frame to AMR decoder");
	return 0;
}



static int generic_silence_dtx(decoder_t *dec, GQueue *out, int ptime) {
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

	g_queue_push_tail(out, frame);

	return 0;
}


static int cn_append_frame(decoder_t *dec, AVFrame *f, void *u1, void *u2) {
	GQueue *out = u1;
	g_queue_push_tail(out, f);
	return 0;
}

static int generic_cn_dtx(decoder_t *dec, GQueue *out, int ptime) {
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




#ifdef HAVE_BCG729
static void bcg729_def_init(struct codec_def_s *def) {
	// test init
	bcg729EncoderChannelContextStruct *e = initBcg729EncoderChannel(0);
	bcg729DecoderChannelContextStruct *d = initBcg729DecoderChannel();
	if (e) {
		def->support_encoding = 1;
		closeBcg729EncoderChannel(e);
	}
	if (d) {
		def->support_decoding = 1;
		closeBcg729DecoderChannel(d);
	}
}

static const char *bcg729_decoder_init(decoder_t *dec, const str *extra_opts) {
	dec->bcg729 = initBcg729DecoderChannel();
	if (!dec->bcg729)
		return "failed to initialize bcg729";
	return NULL;
}

static int bcg729_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	str input = *data;
	uint64_t pts = dec->pts;

	while (input.len >= 2) {
		int frame_len = input.len >= 10 ? 10 : 2;
		str inp_frame = input;
		inp_frame.len = frame_len;
		str_shift(&input, frame_len);

		AVFrame *frame = av_frame_alloc();
		frame->nb_samples = 80;
		frame->format = AV_SAMPLE_FMT_S16;
		frame->sample_rate = dec->in_format.clockrate; // 8000
		DEF_CH_LAYOUT(&frame->CH_LAYOUT, dec->in_format.channels);
		frame->pts = pts;
		if (av_frame_get_buffer(frame, 0) < 0)
			abort();

		pts += frame->nb_samples;

		// XXX handle lost packets and comfort noise
		bcg729Decoder(dec->bcg729, (void *) inp_frame.s, inp_frame.len, 0, 0, 0,
				(void *) frame->extended_data[0]);

		g_queue_push_tail(out, frame);
	}

	return 0;
}

static void bcg729_decoder_close(decoder_t *dec) {
	if (dec->bcg729)
		closeBcg729DecoderChannel(dec->bcg729);
	dec->bcg729 = NULL;
}

static const char *bcg729_encoder_init(encoder_t *enc, const str *extra_opts) {
	enc->bcg729 = initBcg729EncoderChannel(0); // no VAD
	if (!enc->bcg729)
		return "failed to initialize bcg729";

	enc->actual_format.format = AV_SAMPLE_FMT_S16;
	enc->actual_format.channels = 1;
	enc->actual_format.clockrate = 8000;
	enc->samples_per_frame = 80;
	enc->samples_per_packet = enc->actual_format.clockrate * enc->ptime / 1000;

	return NULL;
}

static int bcg729_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	if ((*frame)->nb_samples != 80) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "bcg729: input %u samples instead of 80", (*frame)->nb_samples);
		return -1;
	}

	av_new_packet(enc->avpkt, 10);
	unsigned char len = 0;

	bcg729Encoder(enc->bcg729, (void *) (*frame)->extended_data[0], enc->avpkt->data, &len);
	if (!len) {
		av_packet_unref(enc->avpkt);
		return 0;
	}

	enc->avpkt->size = len;
	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = len * 8; // Duration is used by encoder_input_data for pts calculation

	return 0;
}

static void bcg729_encoder_close(encoder_t *enc) {
	if (enc->bcg729)
		closeBcg729EncoderChannel(enc->bcg729);
	enc->bcg729 = NULL;
}

static int packetizer_g729(AVPacket *pkt, GString *buf, str *input_output, encoder_t *enc) {
	// how many frames do we want?
	int want_frames = input_output->len / 10;

	// easiest case: we only want one frame. return what we got
	if (want_frames == 1 && pkt)
		return packetizer_passthrough(pkt, buf, input_output, enc);

	// any other case, we go through our buffer
	str output = *input_output; // remaining output buffer
	if (pkt)
		g_string_append_len(buf, (char *) pkt->data, pkt->size);

	// how many frames do we have?
	int have_audio_frames = buf->len / 10;
	int have_noise_frames = (buf->len % 10) / 2;
	// we have enough?
	// special case: 4 noise frames (8 bytes) must be returned now, as otherwise
	// (5 noise frames) they might become indistinguishable from an audio frame
	if (have_audio_frames + have_noise_frames < want_frames
			&& have_noise_frames != 4)
		return -1;

	// return non-silence/noise frames while we can
	while (buf->len >= 10 && want_frames && output.len >= 10) {
		memcpy(output.s, buf->str, 10);
		g_string_erase(buf, 0, 10);
		want_frames--;
		str_shift(&output, 10);
	}

	// append silence/noise frames if we can
	while (buf->len >= 2 && want_frames && output.len >= 2) {
		memcpy(output.s, buf->str, 2);
		g_string_erase(buf, 0, 2);
		want_frames--;
		str_shift(&output, 2);
	}

	if (output.len == input_output->len)
		return -1; // got nothing
	input_output->len = output.s - input_output->s;
	return buf->len >= 2 ? 1 : 0;
}

static int format_cmp_g729(const struct rtp_payload_type *a, const struct rtp_payload_type *b) {
	// shortcut the most common case:
	if (!str_cmp_str(&a->format_parameters, &b->format_parameters))
		return 0;
	// incompatible is if one side uses annex B but the other one doesn't
	if (str_str(&a->format_parameters, "annexb=yes") != -1
			&& str_str(&b->format_parameters, "annexb=yes") == -1)
		return -1;
	if (str_str(&a->format_parameters, "annexb=yes") == -1
			&& str_str(&b->format_parameters, "annexb=yes") != -1)
		return -1;
	// everything else is compatible
	return 0;
}
#endif


static const char *dtmf_decoder_init(decoder_t *dec, const str *extra_opts) {
	dec->dtmf.event = -1;
	return NULL;
}

static AVFrame *dtmf_frame_int16_t_mono(unsigned long frame_ts, unsigned long num_samples, unsigned int event,
		unsigned int volume,
		unsigned int sample_rate)
{
	// synthesise PCM
	// first get our frame and figure out how many samples we need, and the start offset
	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = num_samples;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = sample_rate;
	frame->CH_LAYOUT = (CH_LAYOUT_T) MONO_LAYOUT;
	frame->pts = frame_ts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	// fill samples
	dtmf_samples_int16_t_mono(frame->extended_data[0], frame_ts, frame->nb_samples, event,
			volume, sample_rate);

	return frame;

}

static int dtmf_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	struct telephone_event_payload *dtmf;
	if (data->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %zu)", data->len);
		return -1;
	}
	dtmf = (void *) data->s;

	// init if we need to
	if (dtmf->event != dec->dtmf.event || dec->rtp_ts != dec->dtmf.start_ts) {
		ZERO(dec->dtmf);
		dec->dtmf.event = dtmf->event;
		dec->dtmf.start_ts = dec->rtp_ts;
		ilog(LOG_DEBUG, "New DTMF event starting: %u at TS %lu", dtmf->event, dec->rtp_ts);
	}

	unsigned long duration = ntohs(dtmf->duration);
	unsigned long frame_ts = dec->rtp_ts - dec->dtmf.start_ts + dec->dtmf.duration;
	long num_samples = duration - dec->dtmf.duration;

	ilog(LOG_DEBUG, "Generate DTMF samples for event %u, start TS %lu, TS now %lu, frame TS %lu, "
			"duration %lu, "
			"old duration %lu, num samples %li",
			dtmf->event, dec->dtmf.start_ts, dec->rtp_ts, frame_ts,
			duration, dec->dtmf.duration, num_samples);

	if (num_samples <= 0)
		return 0;
	if (num_samples > dec->in_format.clockrate) {
		ilog(LOG_ERR, "Cannot generate %li DTMF samples (clock rate %u)", num_samples,
				dec->in_format.clockrate);
		return -1;
	}

	AVFrame *frame = dtmf_frame_int16_t_mono(frame_ts, num_samples, dtmf->event, dtmf->volume,
			dec->in_format.clockrate);
	frame->pts += dec->dtmf.start_ts;
	g_queue_push_tail(out, frame);

	dec->dtmf.duration = duration;

	return 0;
}



static int format_cmp_ignore(const struct rtp_payload_type *a, const struct rtp_payload_type *b) {
	return 0;
}



static const char *cn_decoder_init(decoder_t *dec, const str *opts) {
	// the ffmpeg cngdec always runs at 8000
	dec->in_format.clockrate = 8000;
	dec->in_format.channels = 1;
	dec->resampler.no_filter = true;
	return avc_decoder_init(dec, opts);
}
static int cn_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	// generate one set of ptime worth of samples
	int ptime = dec->ptime;
	if (ptime <= 0)
		ptime = 20; // ?
	int samples = dec->in_format.clockrate * ptime / 1000;
	dec->avc.avcctx->frame_size = samples;
	int ret = avc_decoder_input(dec, data, out);
	if (ret)
		return ret;
	if (!out->length)
		return -1;
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




// lamely parse out decimal numbers without using floating point
static unsigned int str_to_i_k(str *s) {
	str intg;
	str frac = *s;
	if (str_token(&intg, &frac, '.')) {
		unsigned int ret = str_to_i(s, 0) * 1000;
		if (frac.len > 1) // at most one decimal digit
			frac.len = 1;
		return ret + str_to_i(&frac, 0) * 100;
	}
	return str_to_i(s, 0) * 1000;
}

static const char *evs_bw_strings[__EVS_BW_MAX] = { "nb", "wb", "swb", "fb" };

static void evs_parse_bw(enum evs_bw *minp, enum evs_bw *maxp, const str *token) {
	switch (__csh_lookup(token)) {
		case CSH_LOOKUP("nb"):
			*maxp = EVS_BW_NB;
			break;
		case CSH_LOOKUP("wb"):
			*maxp = EVS_BW_WB;
			break;
		case CSH_LOOKUP("swb"):
			*maxp = EVS_BW_SWB;
			break;
		case CSH_LOOKUP("fb"):
			*maxp = EVS_BW_FB;
			break;
		case CSH_LOOKUP("nb-wb"):
			*minp = EVS_BW_NB;
			*maxp = EVS_BW_WB;
			break;
		case CSH_LOOKUP("nb-swb"):
			*minp = EVS_BW_NB;
			*maxp = EVS_BW_SWB;
			break;
		case CSH_LOOKUP("nb-fb"):
			*minp = EVS_BW_NB;
			*maxp = EVS_BW_FB;
			break;
		// the ones below are not mentioned in the spec - lower bound ignored
		case CSH_LOOKUP("wb-swb"):
			*minp = EVS_BW_WB;
			*maxp = EVS_BW_SWB;
			break;
		case CSH_LOOKUP("wb-fb"):
			*minp = EVS_BW_WB;
			*maxp = EVS_BW_FB;
			break;
		case CSH_LOOKUP("swb-fb"):
			*minp = EVS_BW_SWB;
			*maxp = EVS_BW_FB;
			break;
		default:
			ilog(LOG_WARN, "EVS: bandwidth selection '" STR_FORMAT "' not understood",
					STR_FMT(token));
	}
}
static void evs_parse_br(unsigned int *minp, unsigned int *maxp, str *token) {
	str min;
	str max = *token;
	if (str_token(&min, &max, '-')) {
		*minp = str_to_i_k(&min);
		*maxp = str_to_i_k(&max);
	}
	else
		*minp = *maxp = str_to_i_k(token);
	if (*minp > *maxp) {
		ilog(LOG_WARN, "EVS: min bitrate %u is larger than max bitrate %u",
				*minp, *maxp);
		*maxp = *minp;
	}
}
// lamely print fractional number
static void evs_print_frac_num(GString *s, unsigned int num) {
	unsigned int frac = (num / 100 % 10);
	unsigned int intg = num / 1000;
	if (frac)
		g_string_append_printf(s, "%u.%u", intg, frac);
	else
		g_string_append_printf(s, "%u", intg);
}
static void evs_format_print_br(GString *s, const char *k, unsigned int min, unsigned int max) {
	if (!max)
		return;

	g_string_append(s, k);
	g_string_append_c(s, '=');

	if (min != max) {
		evs_print_frac_num(s, min);
		g_string_append_c(s, '-');
	}
	evs_print_frac_num(s, max);
	g_string_append(s, "; ");
}
static void evs_format_print_bw(GString *s, const char *k, enum evs_bw min, enum evs_bw max) {
	if (max == EVS_BW_UNSPEC)
		return;

	g_string_append(s, k);
	g_string_append_c(s, '=');

	if (min != EVS_BW_UNSPEC) {
		g_string_append(s, evs_bw_strings[min]);
		g_string_append_c(s, '-');
	}
	g_string_append(s, evs_bw_strings[max]);
	g_string_append(s, "; ");
}
static GString *evs_format_print(const struct rtp_payload_type *p) {
	if (!p->format.fmtp_parsed)
		return false;

	GString *s = g_string_new("");
	__auto_type f = &p->format.parsed.evs;

	if (f->hf_only)
		g_string_append(s, "hf-only=1; ");
	if (f->no_dtx)
		g_string_append(s, "dtx=0; ");
	if (f->no_dtx_recv)
		g_string_append(s, "dtx-recv=0; ");
	if (f->cmr)
		g_string_append_printf(s, "cmr=%i; ", f->cmr);

	if (f->amr_io) {
		// AMR
		g_string_append(s, "evs-mode-switch=1; ");

		if (f->mode_set) {
			g_string_append(s, "mode-set=");
			for (unsigned int i = 0; i < 8; i++) {
				if ((f->mode_set & (1 << i)))
					g_string_append_printf(s, "%u,", i);
			}
			g_string_truncate(s, s->len - 1); // remove trailing ","
			g_string_append(s, "; ");
		}

		if (f->mode_change_neighbor)
			g_string_append(s, "mode-change-neighbor=1; ");
		if (f->mode_change_period)
			g_string_append_printf(s, "mode-change-period=%i; ", f->mode_change_period);
	}
	else {
		// EVS
		evs_format_print_br(s, "br", f->min_br, f->max_br);
		evs_format_print_br(s, "br-send", f->min_br_send, f->max_br_send);
		evs_format_print_br(s, "br-recv", f->min_br_recv, f->max_br_recv);

		evs_format_print_bw(s, "bw", f->min_bw, f->max_bw);
		evs_format_print_bw(s, "bw-send", f->min_bw_send, f->max_bw_send);
		evs_format_print_bw(s, "bw-recv", f->min_bw_recv, f->max_bw_recv);
	}

	if (s->len != 0)
		g_string_truncate(s, s->len - 2); // remove trailing "; " if anything was printed

	return s;
}
static void evs_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;
	__auto_type o = &opts->evs;

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("hf-only"):
			if (token->len == 1 && token->s[0] == '1')
				o->hf_only = 1;
			break;
		case CSH_LOOKUP("evs-mode-switch"):
			if (token->len == 1 && token->s[0] == '1')
				o->amr_io = 1;
			break;
		case CSH_LOOKUP("dtx"):
			if (token->len == 1 && token->s[0] == '0')
				o->no_dtx = 1;
			break;
		case CSH_LOOKUP("dtx-recv"):
			if (token->len == 1 && token->s[0] == '0')
				o->no_dtx_recv = 1;
			break;
		case CSH_LOOKUP("cmr"):
			if (token->len == 1 && token->s[0] == '1')
				o->cmr = 1;
			else if (token->len == 2 && token->s[0] == '-' && token->s[1] == '1')
				o->cmr = -1;
			break;
		case CSH_LOOKUP("br"):
			evs_parse_br(&o->min_br, &o->max_br, token);
			break;
		case CSH_LOOKUP("br-send"):
			evs_parse_br(&o->min_br_send, &o->max_br_send, token);
			break;
		case CSH_LOOKUP("br-recv"):
			evs_parse_br(&o->min_br_recv, &o->max_br_recv, token);
			break;
		case CSH_LOOKUP("bw"):
			evs_parse_bw(&o->min_bw, &o->max_bw, token);
			break;
		case CSH_LOOKUP("bw-send"):
			evs_parse_bw(&o->min_bw_send, &o->max_bw_send, token);
			break;
		case CSH_LOOKUP("bw-recv"):
			evs_parse_bw(&o->min_bw_recv, &o->max_bw_recv, token);
			break;
		case CSH_LOOKUP("mode-set"):;
			str mode;
			while (str_token_sep(&mode, token, ',')) {
				int m = str_to_i(&mode, -1);
				if (m < 0 || m > 8)
					continue;
				o->mode_set |= (1 << m);
			}
			break;
		case CSH_LOOKUP("mode-change-period"):
			o->mode_change_period = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("mode-change-neighbor"):
			if (token->len == 1 && token->s[0] == '1')
				o->mode_change_neighbor = 1;
			break;
	}
}
static int evs_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	// initialise
	f->parsed.evs.max_bw = EVS_BW_UNSPEC;
	f->parsed.evs.min_bw = EVS_BW_UNSPEC;
	f->parsed.evs.max_bw_send = EVS_BW_UNSPEC;
	f->parsed.evs.min_bw_send = EVS_BW_UNSPEC;
	f->parsed.evs.max_bw_recv = EVS_BW_UNSPEC;
	f->parsed.evs.min_bw_recv = EVS_BW_UNSPEC;

	codeclib_key_value_parse(fmtp, true, evs_parse_format_cb, &f->parsed);
	return 0;
}
static void evs_format_answer(struct rtp_payload_type *p, const struct rtp_payload_type *src) {
	if (!p->format.fmtp_parsed)
		return;

	__auto_type f = &p->format.parsed.evs;

	// swap send/recv

	__auto_type t1 = f->max_br_recv;
	f->max_br_recv = f->max_br_send;
	f->max_br_send = t1;

	t1 = f->min_br_recv;
	f->min_br_recv = f->min_br_send;
	f->min_br_send = t1;

	__auto_type t2 = f->max_bw_recv;
	f->max_bw_recv = f->max_bw_send;
	f->max_bw_send = t2;

	t2 = f->min_bw_recv;
	f->min_bw_recv = f->min_bw_send;
	f->min_bw_send = t2;
}
static int evs_format_cmp(const struct rtp_payload_type *A, const struct rtp_payload_type *B) {
	// params must have been parsed successfully
	if (!A->format.fmtp_parsed || !B->format.fmtp_parsed)
		return -1;

	__auto_type a = &A->format.parsed.evs;
	__auto_type b = &B->format.parsed.evs;

	// reject what is incompatible
	if (a->amr_io != b->amr_io)
		return -1;
	if (a->hf_only != b->hf_only)
		return -1;

	// determine whether we are compatible
	int compat = 0;

#define FEATURE_CMP(field, compat_op, undefined_val) \
	if (a->field != undefined_val && b->field != undefined_val) { \
		if (a->field == b->field) \
			; \
		else if (a->field compat_op b->field) \
			compat++; \
		else \
			return -1; \
	} \
	else if (a->field == undefined_val && b->field != undefined_val) /* `a` is broader than `b` */ \
		compat++; \
	else if (a->field != undefined_val && b->field == undefined_val) \
		return -1;

	if (!a->amr_io) {
		// EVS
		FEATURE_CMP(max_br, >, 0)
		FEATURE_CMP(min_br, <, 0)
		FEATURE_CMP(max_br_recv, >, 0)
		FEATURE_CMP(min_br_recv, <, 0)
		FEATURE_CMP(max_br_send, >, 0)
		FEATURE_CMP(min_br_send, <, 0)

		FEATURE_CMP(max_bw, >, EVS_BW_UNSPEC)
		FEATURE_CMP(min_bw, <, EVS_BW_UNSPEC)
		FEATURE_CMP(max_bw_recv, >, EVS_BW_UNSPEC)
		FEATURE_CMP(min_bw_recv, <, EVS_BW_UNSPEC)
		FEATURE_CMP(max_bw_send, >, EVS_BW_UNSPEC)
		FEATURE_CMP(min_bw_send, <, EVS_BW_UNSPEC)
	}
	else {
		// AMR
		int match = amr_mode_set_cmp(a->mode_set, b->mode_set);
		if (match == 1)
			compat++;
		else if (match == -1)
			return -1;
	}

#undef FEATURE_CMP

	return (compat == 0) ? 0 : 1;
}
// EVS RTP always runs at 16 kHz
static void evs_select_encoder_format(encoder_t *enc, format_t *req_format, const format_t *f,
		const struct rtp_codec_format *fmtp)
{
	if (req_format->clockrate != 16000)
		return; // bail - encoder will fail to initialise

	// check against natively supported rates first
	switch (f->clockrate) {
		case 48000:
		case 32000:
		case 16000:
			enc->clockrate_fact = (struct fraction) {48000 / f->clockrate, 1};
			break;
		case 8000:
			enc->clockrate_fact = (struct fraction) {1, 16000 / f->clockrate};
			break;
		default:
			// resample to next best rate
			if (f->clockrate > 32000)
				enc->clockrate_fact = (struct fraction) {3,1};
			else if (f->clockrate > 16000)
				enc->clockrate_fact = (struct fraction) {2,1};
			else if (f->clockrate > 8000)
				enc->clockrate_fact = (struct fraction) {1,1};
			else
				enc->clockrate_fact = (struct fraction) {1,2};
			break;
	}
}



static const char *evs_decoder_init(decoder_t *dec, const str *extra_opts) {
	dec->evs = g_slice_alloc0(evs_decoder_size);
	if (dec->in_format.clockrate != 48000)
		ilog(LOG_WARN, "EVS: invalid decoder clock rate (%i) requested",
				fraction_div(dec->in_format.clockrate, &dec->clockrate_fact));
	if (dec->in_format.channels != 1)
		ilog(LOG_WARN, "EVS: %i-channel EVS is not supported",
				dec->in_format.channels);
	dec->in_format.clockrate = 48000;
	evs_set_decoder_Fs(dec->evs, dec->in_format.clockrate);
	evs_init_decoder(dec->evs);
	return NULL;
}
static void evs_decoder_close(decoder_t *dec) {
	evs_destroy_decoder(dec->evs);
	g_slice_free1(evs_decoder_size, dec->evs);
}



// upper 16 bits: 0 = EVS, 1 = AMR
// lower 8 bits: mode num
// 0x000000AA = mode num
// 0x00AAAA00 = actual number of bits
// 0xAA000000 = 0=EVS, 1=AMR
// -1 == invalid
static int32_t evs_mode_from_bytes(int bytes) {
	switch (bytes) {
		// EVS
		case 7: // 2.8
			return 0 | (56 << 8);
		case 18: // 7.2
			return 1 | (144 << 8);
		case 20: // 8.0
			return 2 | (160 << 8);
		case 24: // 9.6
			return 3 | (192 << 8);
		case 33: // 13.2
			return 4 | (264 << 8);
		case 41: // 16.4
			return 5 | (328 << 8);
		case 61: // 24.4
			return 6 | (488 << 8);
		case 80: // 32.0
			return 7 | (640 << 8);
		case 120: // 48.8
			return 8 | (960 << 8);
		case 160: // 64.0
			return 9 | (1280 << 8);
		case 240: // 96.0
			return 10 | (1920 << 8);
		case 320: // 128.0
			return 11 | (2560 << 8);
		case 6: // sid
			return 12 | (48 << 8);
		// AMR
		case 17: // (16.5) 6.60 kbit/s // 0
			return 0 | 0x01000000 | (132 << 8);
		case 23: // (22.125) 8.85 kbit/s // 1
			return 1 | 0x01000000 | (177 << 8);
		case 32: // (31.625) 12.65 kbit/s // 2
			return 2 | 0x01000000 | (253 << 8);
		case 36: // (35.625) 14.25 kbit/s // 3
			return 3 | 0x01000000 | (285 << 8);
		case 40: // (39.625) 15.85 kbit/s // 4
			return 4 | 0x01000000 | (317 << 8);
		case 46: // (45.625) 18.25 kbit/s // 5
			return 5 | 0x01000000 | (365 << 8);
		case 50: // (49.625) 19.85 kbit/s // 6
			return 6 | 0x01000000 | (397 << 8);
		case 58: // (57.625) 23.05 kbit/s // 7
			return 7 | 0x01000000 | (461 << 8);
		case 60: // (59.625) 23.85 kbit/s // 8
			return 8 | 0x01000000 | (477 << 8);
		case 5: // sid
			return 9 | 0x01000000 | (40 << 8);
	}
	return -1;
}
static int32_t evs_mode_from_bitrate(int bitrate) {
	int bytes_per_frame = ((bitrate / 50) + 7) / 8;
	if (bytes_per_frame >= 7)
		return evs_mode_from_bytes(bytes_per_frame);
	return -1;
}

static int evs_bitrate_mode(int bitrate) {
	switch (bitrate) {
		// EVS
		case 2800:
		case 5900:
		case 7200:
		case 8000:
		case 13200:
		case 32000:
		case 64000:
		// AMR
		case 6600:
		case 8850:
		case 12650:
		case 14250:
		case 15850:
		case 18250:
		case 19850:
		case 23050:
		case 23850:
			return 1;
		// EVS
		case 9600:
		case 16400:
		case 24400:
		case 48000:
		case 96000:
		case 128000:
			return 2;
	}
	return 0;
}

static const int evs_mode_bits[2][16] = {
	// EVS
	{
		56, // 0
		144, // 1
		160, // 2
		192, // 3
		264, // 4
		328, // 5
		488, // 6
		640, // 7
		960, // 8
		1280, // 9
		1920, // 10
		2560, // 11
		48, // 12
		0, // 13 invalid
		0, // 14 invalid
		0, // 15 invalid
	},
	// AMR
	{
		132, // 6.60 kbit/s // 0
		177, // 8.85 kbit/s // 1
		253, // 12.65 kbit/s // 2
		285, // 14.25 kbit/s // 3
		317, // 15.85 kbit/s // 4
		365, // 18.25 kbit/s // 5
		397, // 19.85 kbit/s // 6
		461, // 23.05 kbit/s // 7
		477, // 23.85 kbit/s // 8
		40, // comfort noise // 9
		0, // invalid // 10
		0, // invalid // 11
		0, // invalid // 12
		0, // invalid // 13
		0, // invalid // 14
		0, // invalid // 15
	},
};
static const int evs_mode_bitrates[2][16] = {
	// EVS
	{
		5900, // 0 (VBR)
		7200, // 1
		8000, // 2
		9600, // 3
		13200, // 4
		16400, // 5
		24400, // 6
		32000, // 7
		48800, // 8
		64000, // 9
		96000, // 10
		128000, // 11
		0, // 12 SID
		0, // 13 invalid
		0, // 14 invalid
		0, // 15 invalid
	},
	// AMR
	{
		6600, // 0
		8850, // 1
		12650, // 2
		14250, // 3
		15850, // 4
		18250, // 5
		19850, // 6
		23050, // 7
		23850, // 8
		0, // comfort noise // 9
		0, // invalid // 10
		0, // invalid // 11
		0, // invalid // 12
		0, // invalid // 13
		0, // invalid // 14
		0, // invalid // 15
	},
};
static const uint8_t evs_min_max_modes_by_bw[__EVS_BW_MAX][2] = {
	{ 0,  6 }, // NB
	{ 0, 11 }, // WB
	{ 3, 11 }, // SWB
	{ 5, 11 }, // FB
};
static uint8_t evs_clamp_mode_by_bw(const uint8_t mode, const enum evs_bw bw) {
	if (mode < evs_min_max_modes_by_bw[bw][0])
		return evs_min_max_modes_by_bw[bw][0];
	else if (mode > evs_min_max_modes_by_bw[bw][1])
		return evs_min_max_modes_by_bw[bw][1];
	return mode;
}

static int evs_match_bitrate(int orig_br, unsigned int amr) {
	// is it already a valid bitrate?
	int32_t mode = evs_mode_from_bitrate(orig_br);
	if (mode >= 0) {
		int bits = (mode >> 8) & 0xffff;
		if (mode > 0 && (mode >> 24) == amr && bits * 50 == orig_br)
			return orig_br;
	}

	// find closest match
	int max_mode = amr ? 8 : 11;
	int test_mode = max_mode / 2;
	int mode_off = (max_mode + 1) / 2;
	bool last = false;
	while (1) {
		int new_br = evs_mode_bitrates[amr][test_mode];
		int new_off = (mode_off + 1) / 2;
		if (new_br > orig_br) {
			if (test_mode == 0 || last)
				return new_br;
			test_mode -= new_off;
		}
		else { // new_br < orig_br
			if (test_mode == max_mode)
				return new_br;
			test_mode += new_off;
		}
		if (mode_off == 1)
			last = true;
		mode_off = new_off;
	}
}



static const char *evs_encoder_init(encoder_t *enc, const str *extra_opts) {
	enc->evs.ctx = g_slice_alloc0(evs_encoder_size);
	enc->evs.ind_list = g_slice_alloc(evs_encoder_ind_list_size);
	if (enc->requested_format.channels != 1)
		ilog(LOG_WARN, "EVS: %i-channel EVS is not supported",
				enc->requested_format.channels);
	enc->actual_format = enc->requested_format;
	enc->actual_format.format = AV_SAMPLE_FMT_S16;
	enc->samples_per_frame = enc->actual_format.clockrate * 20 / 1000;

	__auto_type o = &enc->format_options.evs;

	// determine max BW
	if (o->max_bw_send != EVS_BW_UNSPEC)
		enc->codec_options.evs.max_bw = o->max_bw_send;
	else if (o->max_bw != EVS_BW_UNSPEC)
		enc->codec_options.evs.max_bw = o->max_bw;
	else
		enc->codec_options.evs.max_bw = EVS_BW_WB;
	assert(enc->codec_options.evs.max_bw >= 0 && enc->codec_options.evs.max_bw < __EVS_BW_MAX);

	switch (enc->requested_format.clockrate) {
		case 48000:
		case 32000:
			if (enc->codec_options.evs.max_bw > EVS_BW_SWB)
				enc->codec_options.evs.max_bw = EVS_BW_SWB;
			break;
		case 16000:
			if (enc->codec_options.evs.max_bw > EVS_BW_WB)
				enc->codec_options.evs.max_bw = EVS_BW_WB;
			break;
		case 8000:
			enc->codec_options.evs.max_bw = EVS_BW_NB;
			break;
		default:
			ilog(LOG_WARN, "EVS: invalid encoder clock rate (%i) requested",
					fraction_div(enc->requested_format.clockrate, &enc->clockrate_fact));
	}
	evs_set_encoder_opts(enc->evs.ctx, enc->actual_format.clockrate, enc->evs.ind_list);

	// limit bitrate to given range
	if (!o->amr_io) {
		// EVS
		if (o->max_br && enc->bitrate > o->max_br)
			enc->bitrate = o->max_br;
		if (o->min_br && enc->bitrate < o->max_br)
			enc->bitrate = o->min_br;

		// verify bitrate
		int bitrate = evs_match_bitrate(enc->bitrate, 0);
		if (bitrate != enc->bitrate) {
			ilog(LOG_INFO, "EVS: Using bitrate %i instead of %i", bitrate, enc->bitrate);
			enc->bitrate = bitrate;
		}

		// limit max bitrate to one supported by the selected BW
		int32_t mode = evs_mode_from_bitrate(enc->bitrate);
		if (mode == -1)
			ilog(LOG_WARN, "EVS: ended up with unknown bitrate %i", enc->bitrate);
		else {
			mode &= 0xff;
			mode = evs_clamp_mode_by_bw(mode, enc->codec_options.evs.max_bw);
			bitrate = evs_mode_bitrates[0][mode];
			ilog(LOG_INFO, "EVS: using bitrate %i instead of %i as restricted by BW %i",
					bitrate, enc->bitrate, enc->codec_options.evs.max_bw);
			enc->bitrate = bitrate;
		}
	}
	else {
		// AMR
		int32_t mode = evs_mode_from_bitrate(enc->bitrate);
		if (mode != -1) {
			if (mode >> 24 != 1)
				mode = -1; // EVS bitrate
			else if (o->mode_set) {
				if ((o->mode_set & (1 << (mode & 0xff))) == 0)
					mode = -1; // not part of the mode-set
			}
		}
		if (mode == -1) {
			// find closest match bitrate
			int bitrate = evs_match_bitrate(enc->bitrate, 1);
			mode = evs_mode_from_bitrate(bitrate);
			if (mode == -1 || (mode >> 24 != 1))
				ilog(LOG_WARN, "EVS: ended up with unknown bitrate %i", bitrate);
			else {
				mode &= 0xff;
				// restrict by mode-set if there is one
				if (o->mode_set) {
					if ((o->mode_set & (1 << (mode & 0xff))) == 0) {
						// pick next higher mode if possible, otherwise go lower:
						// clear lower unwanted modes from mode-set
						unsigned int mode_set = o->mode_set & (0xfe << mode);
						if (mode_set) {
							// got a higher mode: which one?
							mode = __builtin_ffs(mode_set) - 1;
						}
						else {
							// no higher mode, get next lower one
							mode = sizeof(int) * 8 - __builtin_clz(o->mode_set) - 1;
						}
					}
				}
				bitrate = evs_mode_bitrates[1][mode];
				ilog(LOG_INFO, "EVS: using bitrate %i instead of %i as restricted by mode-set",
						bitrate, enc->bitrate);
				enc->bitrate = bitrate;
			}
		}
	}

	evs_set_encoder_brate(enc->evs.ctx, enc->bitrate, enc->codec_options.evs.max_bw,
			evs_bitrate_mode(enc->bitrate), o->amr_io);
	evs_init_encoder(enc->evs.ctx);

	return NULL;
}
static void evs_encoder_close(encoder_t *enc) {
	evs_destroy_encoder(enc->evs.ctx);
	g_slice_free1(evs_encoder_size, enc->evs.ctx);
	g_slice_free1(evs_encoder_ind_list_size, enc->evs.ind_list);
}




static void evs_handle_cmr(encoder_t *enc) {
	if ((enc->callback.evs.cmr_in & 0x80) == 0)
		return;
	if (!memcmp(&enc->callback.evs.cmr_in_ts,
				&enc->evs.cmr_in_ts, sizeof(struct timeval)))
		return;

	enc->evs.cmr_in_ts = enc->callback.evs.cmr_in_ts; // XXX should use a queue or something instead

	__auto_type f = &enc->format_options.evs;
	__auto_type o = &enc->codec_options.evs;
	unsigned char type = (enc->callback.evs.cmr_in >> 4) & 0x7;
	unsigned char req = enc->callback.evs.cmr_in & 0xf;
	int bitrate;

	if (type == 1) {
		// AMR
		if (!f->amr_io)
			goto err;
		if (req > 8)
			goto err;
		bitrate = evs_mode_bitrates[1][req];
	}
	else if (type <= 4) {
		// EVS modes
		if (f->amr_io)
			goto err;
		if (req > 11)
			goto err;
		int bw = type;
		if (bw >= 2)
			bw--; // 0..3
		// ignore min BW
		// instead of ignoring invalid request, clamp them to what is allowed by BW
		if (o->max_bw != EVS_BW_UNSPEC && o->max_bw < bw)
			bw = o->max_bw;
		req = evs_clamp_mode_by_bw(req, bw);
		bitrate = evs_mode_bitrates[0][req];
	}
	else
		goto err;

	enc->bitrate = bitrate;
	evs_set_encoder_brate(enc->evs.ctx, bitrate, o->max_bw,
			evs_bitrate_mode(bitrate), f->amr_io);

	return;

err:
	if (f->amr_io)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "EVS: received invalid CMR (type %u, "
				"request %u) in AMR mode", type, req);
	else
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "EVS: received invalid CMR (type %u, "
				"request %u) with BW <= %i", type, req, o->max_bw);
}

static int evs_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	if ((*frame)->nb_samples != enc->actual_format.clockrate * 20 / 1000) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "EVS: input %u samples instead of %i", (*frame)->nb_samples,
				enc->actual_format.clockrate * 20 / 1000);
		return -1;
	}

	evs_handle_cmr(enc);

	if (!enc->format_options.evs.amr_io)
		evs_enc_in(enc->evs.ctx, (void *) (*frame)->extended_data[0], (*frame)->nb_samples);
	else
		evs_amr_enc_in(enc->evs.ctx, (void *) (*frame)->extended_data[0], (*frame)->nb_samples);

	// max output: 320 bytes, plus some overhead
	av_new_packet(enc->avpkt, 340);

	unsigned char *out = enc->avpkt->data;
	unsigned char *cmr = NULL;

	if (!enc->format_options.evs.amr_io) {
		// EVS
		if (enc->format_options.evs.cmr == 1) {
			cmr = out;
			*cmr = 0xff; // no CMR
			out++;
		}
	}
	else {
		// AMR IO
		if (!enc->format_options.evs.hf_only) {
			// compact
			cmr = out;
			*cmr = 0xe0; // no CMR
			out++; // to be shuffled below
		}
		else {
			// header-full
			if (enc->format_options.evs.cmr == 1) {
				cmr = out;
				*cmr = 0xff; // no CMR
				out++;
			}
		}
	}

	// TOC byte
	unsigned char *toc = NULL;
	if (enc->format_options.evs.hf_only) {
		// header-full always has TOC
		toc = out;
		out++;
	}
	else {
		// compact
		if (cmr && !enc->format_options.evs.amr_io) {
			// EVS with CMR is also header-full with TOC
			toc = out;
			out++;
		}
	}

	uint16_t bits = 0;
	evs_enc_out(enc->evs.ctx, out, &bits);
	uint16_t bytes = (bits + 7) / 8;
	int32_t mode = evs_mode_from_bytes(bytes);
	if (mode < 0) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "EVS: invalid encoding received from codec "
				"(%i bits per frame)", bits);
		av_packet_unref(enc->avpkt);
		return -1;
	}
	evs_reset_enc_ind(enc->evs.ctx);

	if (toc) {
		*toc = (mode & 0xff);
		if (enc->format_options.evs.amr_io)
			*toc |= 0x30;
	}

	if (enc->format_options.evs.amr_io && !enc->format_options.evs.hf_only) {
		// how many output bytes (frame minus CMR bits) total?
		bytes = (bits - 5 + 7) / 8;
		// bit-shuffle payload
		unsigned char first = out[0];
		*cmr |= (first >> 2) & 0x1f;
		// XXX accelerate with larger word sizes
		for (int i = 0; i < bytes; i++) {
			out[i] <<= 6;
			out[i] |= out[i+1] >> 2;
		}
		// restore first bit, clear out tail end padding bits
		unsigned int first_bit_shift = (bits + 2) % 8;
		out[bytes-1] &= (0xff << (8 - first_bit_shift)); // clear leftovers
		out[bytes-1] |= ((first & 0x80) >> first_bit_shift); // last/first bit
	}

	bytes += (out - enc->avpkt->data);
	assert(bytes <= enc->avpkt->size);

	if (toc && !enc->format_options.evs.amr_io && !enc->format_options.evs.hf_only) {
		// hf-only=0 but HF packet, check for size collisions and zero-pad if needed
		while (evs_mode_from_bytes(bytes) != -1) {
			enc->avpkt->data[bytes] = '\0';
			bytes++;
		}
	}

	enc->avpkt->size = bytes;
	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = (*frame)->nb_samples;

	return 0;
}


// 3GPP TS 26.445 A.2.1.2.1 -> A.2.2.1.1
static const char evs_amr_io_compact_cmr[8] = {
	0x90 | 0, // 6.6
	0x90 | 1, // 8.85
	0x90 | 2, // 12.65
	0x90 | 4, // 15.85
	0x90 | 5, // 18.25
	0x90 | 7, // 23.05
	0x90 | 8, // 23.85
	0xff      // no req
};


#if defined(__x86_64__) && !defined(ASAN_BUILD) && HAS_ATTR(ifunc) && defined(__GLIBC__)
static void mvr2s_dynlib_wrapper(float *in, const uint16_t len, int16_t *out) {
	evs_syn_output(in, len, out);
}
static void (*resolve_float2int16_array(void))(float *, const uint16_t, int16_t *) {
#if defined(__x86_64__)
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX512BW) && rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX512F))
		return mvr2s_avx512;
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX2))
		return mvr2s_avx2;
#endif
	return mvr2s_dynlib_wrapper;
}
static void float2int16_array(float *in, const uint16_t len, int16_t *out)
	__attribute__ ((ifunc ("resolve_float2int16_array")));
#else
#define float2int16_array evs_syn_output
#endif



static int evs_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	str input = *data;
	uint64_t pts = dec->pts;
	const char *err = NULL;

	if (input.len == 0)
		return 0;

	unsigned int n_samples = dec->in_format.clockrate * 20 / 1000;

	str frame_data = STR_NULL;
	const unsigned char *toc = NULL, *toc_end = NULL;
	unsigned char cmr = 0xff;
	// check for single frame in compact format
	int32_t mode = evs_mode_from_bytes(input.len);
	int is_amr, bits, q_bit;
	if ((mode & 0xff0000ff) == 0) {
		// special case, clause A.2.1.3
		if ((input.s[0] & 0x80)) {
			// AMR in HF format with CMR
			mode = -1;
		}
	}
	if (mode != -1) {
		// single compact frame: consume all
		frame_data = input;
		input.len = 0;

		// extract mode information
		bits = (mode >> 8) & 0xffff;
		is_amr = mode >> 24;
		q_bit = 1;
		mode = mode & 0xff;

		if (is_amr) {
			// save and clear CMR
			unsigned char *shifter = (unsigned char *) frame_data.s; // use unsigned
			cmr = shifter[0] & 0xe0;
			shifter[0] &= 0x1f;

			// convert CMR to full byte format
			cmr >>= 5; // now guaranteed to be 0..7
			cmr = evs_amr_io_compact_cmr[cmr];

			// bit shift payload
			// XXX use larger word sizes
			for (size_t i = 0; i < frame_data.len; i++) {
				shifter[i] <<= 2;
				shifter[i] |= shifter[i+1] >> 6;
			}
			// restore first bit
			size_t first_bit_octet = bits / 8;
			size_t first_bit_bit = bits % 8;
			shifter[0] |= (shifter[first_bit_octet] << first_bit_bit) & 0x80;
		}
	}
	else {
		// header-full
		toc = (unsigned char *) input.s;
		str_shift(&input, 1);
		// is this TOC or CMR?
		if ((*toc & 0x80)) {
			cmr = *toc;
			toc = (unsigned char *) input.s;
			err = "short packet (no TOC after CMR)";
			if (str_shift(&input, 1))
				goto err;
			err = "invalid TOC byte";
			if ((*toc & 0x80))
				goto err;
		}
		// skip over all TOC entries
		unsigned char toc_ent = *toc;
		while ((toc_ent & 0x40)) {
			toc_ent = *((unsigned char *) input.s);
			err = "short packet (no repeating TOC)";
			if (str_shift(&input, 1))
				goto err;
		}
		// `toc` is now the first TOC entry and `input` points to the first speech frame
		toc_end = (void *) input.s;
	}

	while (1) {
		// process frame if we have one; we don't have one if
		// this is the first iteration and this is not a compact frame
		if (mode != -1) {
			AVFrame *frame = av_frame_alloc();
			frame->nb_samples = n_samples;
			frame->format = AV_SAMPLE_FMT_S16;
			frame->sample_rate = dec->in_format.clockrate; // 48000
			DEF_CH_LAYOUT(&frame->CH_LAYOUT, dec->in_format.channels);
			frame->pts = pts;
			if (av_frame_get_buffer(frame, 0) < 0)
				abort();

			evs_dec_in(dec->evs, frame_data.s, bits, is_amr, mode, q_bit, 0, 0);

			// check for floating point implementation
			if (evs_syn_output) {
				// temp float buffer
				float tmp[n_samples * 3];
				if (!is_amr)
					evs_dec_out(dec->evs, tmp, 0);
				else
					evs_amr_dec_out(dec->evs, tmp);
				float2int16_array(tmp, n_samples, (void *) frame->extended_data[0]);
			}
			else {
				if (!is_amr)
					evs_dec_out(dec->evs, frame->extended_data[0], 0);
				else
					evs_amr_dec_out(dec->evs, frame->extended_data[0]);
			}

			evs_dec_inc_frame(dec->evs);

			pts += n_samples;
			g_queue_push_tail(out, frame);
		}

		// anything left? we break here in compact mode
		if (!input.len)
			break;

		// if we're here, we're in HF mode: look at the next TOC and extract speech frame
		if (toc >= toc_end) // leftover data/padding at the end
			break;
		mode = *toc & 0xf;
		is_amr = (*toc >> 5) & 0x1;
		if (is_amr)
			q_bit = (*toc >> 4) & 0x1;
		else
			q_bit = 1;
		bits = evs_mode_bits[is_amr][mode]; // guaranteed to be 0..1 and 0..15

		// consume and shift
		toc++;
		int bytes = (bits + 7) / 8;
		frame_data = STR_LEN(input.s, bytes);
		err = "speech frame truncated";
		if (str_shift(&input, bytes))
			goto err;
	}

	if (cmr != 0xff)
		decoder_event(dec, CE_EVS_CMR_RECV, GUINT_TO_POINTER(cmr));

	return 0;

err:
	if (err)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error unpacking EVS packet: %s", err);
	return -1;
}


static void evs_load_so(const char *path) {
	if (!path)
		return;

	evs_lib_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!evs_lib_handle)
		die("Failed to open EVS codec .so '%s': %s", path, dlerror());

	static unsigned int (*get_evs_decoder_size)(void);
	static unsigned int (*get_evs_encoder_size)(void);
	static unsigned int (*get_evs_encoder_ind_list_size)(void);

	// flp codec?
	evs_init_decoder = dlsym(evs_lib_handle, "init_decoder");
	if (!evs_init_decoder) {
		// fx codec?
		evs_init_decoder = dlsym_assert(evs_lib_handle, "init_decoder_fx", path);
		evs_init_encoder = dlsym_assert(evs_lib_handle, "init_encoder_fx", path);
		evs_destroy_encoder = dlsym_assert(evs_lib_handle, "destroy_encoder_fx", path);
		evs_enc_in = dlsym_assert(evs_lib_handle, "evs_enc_fx", path);
		evs_amr_enc_in = dlsym_assert(evs_lib_handle, "amr_wb_enc_fx", path);
		evs_reset_enc_ind = dlsym_assert(evs_lib_handle, "reset_indices_enc_fx", path);
		evs_dec_in = dlsym_assert(evs_lib_handle, "read_indices_from_djb_fx", path);
		evs_dec_out = dlsym_assert(evs_lib_handle, "evs_dec_fx", path);
		evs_amr_dec_out = dlsym_assert(evs_lib_handle, "amr_wb_dec_fx", path);
	}
	else {
		// flp codec
		evs_init_encoder = dlsym_assert(evs_lib_handle, "init_encoder", path);
		evs_destroy_encoder = dlsym_assert(evs_lib_handle, "destroy_encoder", path);
		evs_enc_in = dlsym_assert(evs_lib_handle, "evs_enc", path);
		evs_amr_enc_in = dlsym_assert(evs_lib_handle, "amr_wb_enc", path);
		evs_reset_enc_ind = dlsym_assert(evs_lib_handle, "reset_indices_enc", path);
		evs_dec_in = dlsym_assert(evs_lib_handle, "read_indices_from_djb", path);
		evs_dec_out = dlsym_assert(evs_lib_handle, "evs_dec", path);
		evs_syn_output = dlsym_assert(evs_lib_handle, "syn_output", path);
		evs_amr_dec_out = dlsym_assert(evs_lib_handle, "amr_wb_dec", path);
	}

	// common
	get_evs_decoder_size = dlsym_assert(evs_lib_handle, "decoder_size", path);
	get_evs_encoder_size = dlsym_assert(evs_lib_handle, "encoder_size", path);
	get_evs_encoder_ind_list_size = dlsym_assert(evs_lib_handle, "encoder_ind_list_size", path);
	evs_destroy_decoder = dlsym_assert(evs_lib_handle, "destroy_decoder", path);
	evs_enc_out = dlsym_assert(evs_lib_handle, "indices_to_serial", path);
	evs_set_encoder_opts = dlsym_assert(evs_lib_handle, "encoder_set_opts", path);
	evs_set_encoder_brate = dlsym_assert(evs_lib_handle, "encoder_set_brate", path);
	evs_set_decoder_Fs = dlsym_assert(evs_lib_handle, "decoder_set_Fs", path);
	evs_dec_inc_frame = dlsym_assert(evs_lib_handle, "decoder_inc_ini_frame", path);

	// all ok

	evs_decoder_size = get_evs_decoder_size();
	evs_encoder_size = get_evs_encoder_size();
	evs_encoder_ind_list_size = get_evs_encoder_ind_list_size();

	return;
}

static void evs_def_init(struct codec_def_s *def) {
	evs_load_so(rtpe_common_config_ptr->evs_lib_path);

	if (evs_lib_handle) {
		def->support_decoding = 1;
		def->support_encoding = 1;
	}
}

static int evs_dtx(decoder_t *dec, GQueue *out, int ptime) {
	return 0;
}






#ifdef HAVE_CODEC_CHAIN
codec_cc_state cc_pcmu2opus_run(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt;
	ssize_t ret = cc_pcmu2opus_runner_do(c->pcmu2opus.runner, c->pcmu2opus.enc,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size);
	if (ret <= 0)
		return CCC_ERR;
	// XXX handle input frame sizes != 160

	pkt->size = ret;
	pkt->duration = data->len * 6L;
	pkt->pts = ts * 6L;

	return CCC_OK;
}

codec_cc_state cc_pcma2opus_run(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt;
	ssize_t ret = cc_pcma2opus_runner_do(c->pcma2opus.runner, c->pcma2opus.enc,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size);
	if (ret <= 0)
		return CCC_ERR;
	// XXX handle input frame sizes != 160

	pkt->size = ret;
	pkt->duration = data->len * 6L;
	pkt->pts = ts * 6L;

	return CCC_OK;
}

codec_cc_state cc_opus2pcmu_run(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt;
	ssize_t ret = cc_opus2pcmu_runner_do(c->opus2pcmu.runner, c->opus2pcmu.dec,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size);
	if (ret <= 0)
		return CCC_ERR;

	pkt->size = ret;
	pkt->duration = ret;
	pkt->pts = ts / 6L;

	return CCC_OK;
}

codec_cc_state cc_opus2pcma_run(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt;
	ssize_t ret = cc_opus2pcma_runner_do(c->opus2pcma.runner, c->opus2pcma.dec,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size);
	if (ret <= 0)
		return CCC_ERR;

	pkt->size = ret;
	pkt->duration = ret;
	pkt->pts = ts / 6L;

	return CCC_OK;
}

static void __cc_async_job_free(struct async_job *j) {
	g_free(j->data.s);
	g_free(j);
}

static void __codec_cc_free(codec_cc_t *c) {
	c->clear(c->clear_arg);
	while (c->async_jobs.length) {
		__auto_type j = t_queue_pop_head(&c->async_jobs);
		c->async_callback(NULL, j->async_cb_obj);
		__cc_async_job_free(j);
	}
	av_packet_free(&c->avpkt);
	av_packet_free(&c->avpkt_async);
	g_slice_free1(sizeof(*c), c);
}


// lock must be held
// append job to queue
static void __cc_async_do_add_queue(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	struct async_job *j = g_new0(__typeof__(*j), 1);
	j->data = str_dup_str(data);
	j->async_cb_obj = async_cb_obj;
	j->ts = ts;
	t_queue_push_tail(&c->async_jobs, j);
}
// check busy flag and append to queue if set
// if not busy, sets busy flag
// also check blocked flag if busy: if set, try running first job
static bool __cc_async_check_busy_blocked_queue(codec_cc_t *c, const str *data, unsigned long ts,
		void *async_cb_obj, __typeof__(__cc_pcmu2opus_run_async) run_async)
{
	struct async_job *j = NULL;

	{
		LOCK(&c->async_lock);

		if (!c->async_busy) {
			// we can try running
			c->async_busy = true;
			return false;
		}

		// codec is busy (either currently running or was blocked)
		// append to queue
		__cc_async_do_add_queue(c, data, ts, async_cb_obj);

		// if we were blocked (not currently running), try running now
		if (c->async_blocked)
			j = t_queue_pop_head(&c->async_jobs);
	}

	if (j) {
		if (!run_async(c, &j->data, j->ts, j->async_cb_obj)) {
			// still blocked. return to queue
			LOCK(&c->async_lock);
			t_queue_push_head(&c->async_jobs, j);
		}
		else {
			// unblocked, running now
			__cc_async_job_free(j);
			LOCK(&c->async_lock);
			c->async_blocked = false;
		}
	}

	return true;
}
// runner failed, needed to block (no available context)
// set blocked flag and append to queue
// queue is guaranteed to be empty
static void __cc_async_blocked_queue(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	LOCK(&c->async_lock);
	__cc_async_do_add_queue(c, data, ts, async_cb_obj);
	c->async_blocked = true;
	// busy == true
}

static codec_cc_state cc_X_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj,
		__typeof__(__cc_pcmu2opus_run_async) run_async)
{
	if (__cc_async_check_busy_blocked_queue(c, data, ts, async_cb_obj, run_async))
		return CCC_ASYNC;
	if (!run_async(c, data, ts, async_cb_obj))
		__cc_async_blocked_queue(c, data, ts, async_cb_obj);
	return CCC_ASYNC;
}

static void cc_X_pkt_callback(codec_cc_t *c, int size, __typeof__(__cc_pcmu2opus_run_async) run_async) {
	AVPacket *pkt = c->avpkt_async;
	void *async_cb_obj = c->async_cb_obj;
	c->async_cb_obj = NULL;

	c->async_callback(pkt, async_cb_obj);

	pkt->size = 0;

	struct async_job *j = NULL;
	bool shutdown = false;
	{
		LOCK(&c->async_lock);
		j = t_queue_pop_head(&c->async_jobs);
		if (!j) {
			if (c->async_shutdown)
				shutdown = true;
			else
				c->async_busy = false;
		}
	}

	if (shutdown) {
		__codec_cc_free(c);
		return;
	}

	if (j) {
		if (!run_async(c, &j->data, j->ts, j->async_cb_obj)) {
			LOCK(&c->async_lock);
			t_queue_push_head(&c->async_jobs, j);
			c->async_blocked = true;
		}
		else {
			g_free(j->data.s);
			g_free(j);
			LOCK(&c->async_lock);
			c->async_blocked = false;
		}
	}
}

static void cc_pcmX2opus_run_callback(void *p, int size, __typeof__(__cc_pcmu2opus_run_async) run_async) {
	codec_cc_t *c = p;

	assert(size > 0); // XXX handle errors XXX handle input frame sizes != 160

	AVPacket *pkt = c->avpkt_async;

	pkt->size = size;
	pkt->duration = c->data_len * 6L;
	pkt->pts = c->ts * 6L;

	cc_X_pkt_callback(c, size, run_async);
}

static void cc_pcmu2opus_run_callback(void *p, int size) {
	cc_pcmX2opus_run_callback(p, size, __cc_pcmu2opus_run_async);
}
static bool __cc_pcmu2opus_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt_async;
	pkt->size = MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE;

	c->data_len = data->len;
	c->ts = ts;
	c->async_cb_obj = async_cb_obj;

	return cc_pcmu2opus_runner_async_do_nonblock(c->pcmu2opus_async.runner, c->pcmu2opus.enc,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size, cc_pcmu2opus_run_callback, c);
}
codec_cc_state cc_pcmu2opus_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	return cc_X_run_async(c, data, ts, async_cb_obj, __cc_pcmu2opus_run_async);
}

static void cc_pcma2opus_run_callback(void *p, int size) {
	cc_pcmX2opus_run_callback(p, size, __cc_pcma2opus_run_async);
}
static bool __cc_pcma2opus_run_async(codec_cc_t *c, const str *data, unsigned long ts,
		void *async_cb_obj)
{
	AVPacket *pkt = c->avpkt_async;
	pkt->size = MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE;

	c->data_len = data->len;
	c->ts = ts;
	c->async_cb_obj = async_cb_obj;

	return cc_pcma2opus_runner_async_do_nonblock(c->pcma2opus_async.runner, c->pcma2opus.enc,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size, cc_pcma2opus_run_callback, c);
}
codec_cc_state cc_pcma2opus_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	return cc_X_run_async(c, data, ts, async_cb_obj, __cc_pcma2opus_run_async);
}

static void cc_opus2pcmX_run_callback(void *p, int size, __typeof__(__cc_opus2pcma_run_async) run_async) {
	codec_cc_t *c = p;

	assert(size > 0); // XXX handle errors

	AVPacket *pkt = c->avpkt_async;

	pkt->size = size;
	pkt->duration = size;
	pkt->pts = c->ts / 6L;

	cc_X_pkt_callback(c, size, run_async);
}

static void cc_opus2pcmu_run_callback(void *p, int size) {
	cc_opus2pcmX_run_callback(p, size, __cc_opus2pcmu_run_async);
}
static bool __cc_opus2pcmu_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt_async;
	pkt->size = 960;

	c->data_len = data->len;
	c->ts = ts;
	c->async_cb_obj = async_cb_obj;

	return cc_opus2pcmu_runner_async_do_nonblock(c->opus2pcmu_async.runner, c->opus2pcmu.dec,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size, cc_opus2pcmu_run_callback, c);
}
codec_cc_state cc_opus2pcmu_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	return cc_X_run_async(c, data, ts, async_cb_obj, __cc_opus2pcmu_run_async);
}

static void cc_opus2pcma_run_callback(void *p, int size) {
	return cc_opus2pcmX_run_callback(p, size, __cc_opus2pcma_run_async);
}
static bool __cc_opus2pcma_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	AVPacket *pkt = c->avpkt_async;
	pkt->size = 960;

	c->data_len = data->len;
	c->ts = ts;
	c->async_cb_obj = async_cb_obj;

	return cc_opus2pcma_runner_async_do_nonblock(c->opus2pcma_async.runner, c->opus2pcma.dec,
			(unsigned char *) data->s, data->len,
			pkt->data, pkt->size, cc_opus2pcma_run_callback, c);
}
codec_cc_state cc_opus2pcma_run_async(codec_cc_t *c, const str *data, unsigned long ts, void *async_cb_obj) {
	return cc_X_run_async(c, data, ts, async_cb_obj, __cc_opus2pcma_run_async);
}



static void cc_float2opus_clear(void *a) {
	codec_chain_float2opus *enc = a;
	cc_client_float2opus_free(cc_client, enc);
}
static void cc_opus2float_clear(void *a) {
	codec_chain_opus2float *dec = a;
	cc_client_opus2float_free(cc_client, dec);
}

static codec_cc_t *codec_cc_new_sync(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *))
{
	if (!strcmp(dst->rtpname, "opus") && !strcmp(src->rtpname, "PCMA")) {
		if (src_format->clockrate != 8000)
			return NULL;
		if (src_format->channels != 1)
			return NULL;
		if (dst_format->channels != 2)
			return NULL;
		if (dst_format->clockrate != 48000)
			return NULL;

		if (!pcma2opus_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->pcma2opus.enc = cc_client_float2opus_new_ext(cc_client,
				(codec_chain_opus_arguments) {
					.bitrate = bitrate,
					.complexity = rtpe_common_config_ptr->codec_chain_opus_complexity,
					.application = rtpe_common_config_ptr->codec_chain_opus_application,
				});
		ret->clear = cc_float2opus_clear;
		ret->clear_arg = ret->pcma2opus.enc;
		ret->pcma2opus.runner = pcma2opus_runner;
		ret->avpkt = av_packet_alloc();
		ret->run = cc_pcma2opus_run;

		return ret;
	}
	else if (!strcmp(dst->rtpname, "opus") && !strcmp(src->rtpname, "PCMU")) {
		if (src_format->clockrate != 8000)
			return NULL;
		if (src_format->channels != 1)
			return NULL;
		if (dst_format->channels != 2)
			return NULL;
		if (dst_format->clockrate != 48000)
			return NULL;

		if (!pcmu2opus_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->pcmu2opus.enc = cc_client_float2opus_new_ext(cc_client,
				(codec_chain_opus_arguments) {
					.bitrate = bitrate,
					.complexity = rtpe_common_config_ptr->codec_chain_opus_complexity,
					.application = rtpe_common_config_ptr->codec_chain_opus_application,
				});
		ret->clear = cc_float2opus_clear;
		ret->clear_arg = ret->pcmu2opus.enc;
		ret->pcmu2opus.runner = pcmu2opus_runner;
		ret->avpkt = av_packet_alloc();
		ret->run = cc_pcmu2opus_run;

		return ret;
	}
	else if (!strcmp(dst->rtpname, "PCMU") && !strcmp(src->rtpname, "opus")) {
		if (dst_format->clockrate != 8000)
			return NULL;
		if (dst_format->channels != 1)
			return NULL;
		if (src_format->channels != 2)
			return NULL;
		if (src_format->clockrate != 48000)
			return NULL;

		if (!opus2pcmu_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->opus2pcmu.dec = cc_client_opus2float_new(cc_client);
		ret->clear = cc_opus2float_clear;
		ret->clear_arg = ret->opus2pcmu.dec;
		ret->opus2pcmu.runner = opus2pcmu_runner;
		ret->avpkt = av_packet_alloc();
		ret->run = cc_opus2pcmu_run;

		return ret;
	}
	else if (!strcmp(dst->rtpname, "PCMA") && !strcmp(src->rtpname, "opus")) {
		if (dst_format->clockrate != 8000)
			return NULL;
		if (dst_format->channels != 1)
			return NULL;
		if (src_format->channels != 2)
			return NULL;
		if (src_format->clockrate != 48000)
			return NULL;

		if (!opus2pcma_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->opus2pcma.dec = cc_client_opus2float_new(cc_client);
		ret->clear = cc_opus2float_clear;
		ret->clear_arg = ret->opus2pcma.dec;
		ret->opus2pcma.runner = opus2pcma_runner;
		ret->avpkt = av_packet_alloc();
		ret->run = cc_opus2pcma_run;

		return ret;
	}

	return NULL;
}

static codec_cc_t *codec_cc_new_async(codec_def_t *src, format_t *src_format, codec_def_t *dst,
		format_t *dst_format, int bitrate, int ptime,
		void *(*async_init)(void *, void *, void *),
		void (*async_callback)(AVPacket *, void *))
{
	// XXX check ptime, adjust avpkt sizes
	if (!strcmp(dst->rtpname, "opus") && !strcmp(src->rtpname, "PCMA")) {
		if (src_format->clockrate != 8000)
			return NULL;
		if (src_format->channels != 1)
			return NULL;
		if (dst_format->channels != 2)
			return NULL;
		if (dst_format->clockrate != 48000)
			return NULL;

		if (!pcma2opus_async_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->pcma2opus.enc = cc_client_float2opus_new_ext(cc_client,
				(codec_chain_opus_arguments) {
					.bitrate = bitrate,
					.complexity = rtpe_common_config_ptr->codec_chain_opus_complexity,
					.application = rtpe_common_config_ptr->codec_chain_opus_application,
				});
		ret->clear = cc_float2opus_clear;
		ret->clear_arg = ret->pcma2opus.enc;
		ret->pcma2opus_async.runner = pcma2opus_async_runner;
		ret->run = cc_pcma2opus_run_async;
		ret->avpkt_async = av_packet_alloc();
		av_new_packet(ret->avpkt_async,
				MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE);
		mutex_init(&ret->async_lock);
		t_queue_init(&ret->async_jobs);
		ret->async_init = async_init;
		ret->async_callback = async_callback;

		return ret;
	}
	else if (!strcmp(dst->rtpname, "opus") && !strcmp(src->rtpname, "PCMU")) {
		if (src_format->clockrate != 8000)
			return NULL;
		if (src_format->channels != 1)
			return NULL;
		if (dst_format->channels != 2)
			return NULL;
		if (dst_format->clockrate != 48000)
			return NULL;

		if (!pcmu2opus_async_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->pcmu2opus.enc = cc_client_float2opus_new_ext(cc_client,
				(codec_chain_opus_arguments) {
					.bitrate = bitrate,
					.complexity = rtpe_common_config_ptr->codec_chain_opus_complexity,
					.application = rtpe_common_config_ptr->codec_chain_opus_application,
				});
		ret->clear = cc_float2opus_clear;
		ret->clear_arg = ret->pcmu2opus.enc;
		ret->pcmu2opus_async.runner = pcmu2opus_async_runner;
		ret->run = cc_pcmu2opus_run_async;
		ret->avpkt_async = av_packet_alloc();
		av_new_packet(ret->avpkt_async,
				MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE);
		mutex_init(&ret->async_lock);
		t_queue_init(&ret->async_jobs);
		ret->async_init = async_init;
		ret->async_callback = async_callback;

		return ret;
	}
	else if (!strcmp(dst->rtpname, "PCMU") && !strcmp(src->rtpname, "opus")) {
		if (dst_format->clockrate != 8000)
			return NULL;
		if (dst_format->channels != 1)
			return NULL;
		if (src_format->channels != 2)
			return NULL;
		if (src_format->clockrate != 48000)
			return NULL;

		if (!opus2pcmu_async_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->opus2pcmu.dec = cc_client_opus2float_new(cc_client);
		ret->clear = cc_opus2float_clear;
		ret->clear_arg = ret->opus2pcmu.dec;
		ret->opus2pcmu_async.runner = opus2pcmu_async_runner;
		ret->run = cc_opus2pcmu_run_async;
		ret->avpkt_async = av_packet_alloc();
		av_new_packet(ret->avpkt_async, 960);
		mutex_init(&ret->async_lock);
		t_queue_init(&ret->async_jobs);
		ret->async_init = async_init;
		ret->async_callback = async_callback;

		return ret;
	}
	else if (!strcmp(dst->rtpname, "PCMA") && !strcmp(src->rtpname, "opus")) {
		if (dst_format->clockrate != 8000)
			return NULL;
		if (dst_format->channels != 1)
			return NULL;
		if (src_format->channels != 2)
			return NULL;
		if (src_format->clockrate != 48000)
			return NULL;

		if (!opus2pcma_async_runner)
			return NULL;

		codec_cc_t *ret = g_slice_alloc0(sizeof(*ret));
		ret->opus2pcma.dec = cc_client_opus2float_new(cc_client);
		ret->clear = cc_opus2float_clear;
		ret->clear_arg = ret->opus2pcma.dec;
		ret->opus2pcma_async.runner = opus2pcma_async_runner;
		ret->run = cc_opus2pcma_run_async;
		ret->avpkt_async = av_packet_alloc();
		av_new_packet(ret->avpkt_async, 960);
		mutex_init(&ret->async_lock);
		t_queue_init(&ret->async_jobs);
		ret->async_init = async_init;
		ret->async_callback = async_callback;

		return ret;
	}

	return NULL;
}

void codec_cc_stop(codec_cc_t *c) {
	if (!c)
		return;

	// steal and fire all callbacks to release any references

	async_job_q q;

	{
		LOCK(&c->async_lock);
		q = c->async_jobs;
		t_queue_init(&c->async_jobs);
	}

	while (q.length) {
		__auto_type j = t_queue_pop_head(&q);
		c->async_callback(NULL, j->async_cb_obj);
		__cc_async_job_free(j);
	}
}

void codec_cc_free(codec_cc_t **ccp) {
	codec_cc_t *c = *ccp;
	if (!c)
		return;
	*ccp = NULL;

	{
		LOCK(&c->async_lock);
		if (c->async_busy && !c->async_blocked) {
			c->async_shutdown = true;
			return; // wait for callback
		}
	}
	__codec_cc_free(c);
}


#endif

AVPacket *codec_cc_input_data(codec_cc_t *c, const str *data, unsigned long ts, void *x, void *y, void *z) {
#ifdef HAVE_CODEC_CHAIN
	if (c->avpkt)
		av_new_packet(c->avpkt, MAX_OPUS_FRAME_SIZE * MAX_OPUS_FRAMES_PER_PACKET + MAX_OPUS_HEADER_SIZE);
	void *async_cb_obj = NULL;
	if (c->async_init)
		async_cb_obj = c->async_init(x, y, z);

	codec_cc_state ret = c->run(c, data, ts, async_cb_obj);

	if (ret == CCC_ERR) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received error from codec-chain job");
		return c->avpkt; // return empty packet in case of error
	}
	if (ret == CCC_OK)
		return c->avpkt;

	// CCC_ASYNC
	return NULL;

#else
	return NULL;
#endif
}
