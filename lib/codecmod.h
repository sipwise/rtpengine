#ifndef _CODECMOD_H_
#define _CODECMOD_H_


#include "codeclib.h"


extern const codec_type_t codec_type_avcodec;

extern const dtx_method_t dtx_method_silence;
extern const dtx_method_t dtx_method_cn;

packetizer_f packetizer_samplestream; // flat stream of samples

int format_cmp_ignore(const struct rtp_payload_type *, const struct rtp_payload_type *);


void avc_def_init(struct codec_def_s *);
const char *avc_decoder_init(decoder_t *, const str *);
int avc_decoder_input(decoder_t *dec, const str *data, GQueue *out);
void avc_decoder_close(decoder_t *);
const char *avc_encoder_init(encoder_t *enc, const str *);
int avc_encoder_input(encoder_t *enc, AVFrame **frame);
void avc_encoder_close(encoder_t *enc);

int codeclib_set_av_opt_int(encoder_t *enc, const char *opt, int64_t val);
void codeclib_key_value_parse(const str *instr, bool need_value,
		void (*cb)(str *key, str *value, void *data), void *data);

void *dlsym_assert(void *handle, const char *sym, const char *fn);


void codeclib_register_codec(const codec_def_t *);


#endif
