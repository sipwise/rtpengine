#ifndef _DECODER_H_
#define _DECODER_H_

#include "types.h"
#include "str.h"


extern int resample_audio;


decode_t *decoder_new(const char *payload_str, output_t *);
int decoder_input(decode_t *, const str *, unsigned long ts, ssrc_t *);

void decoder_free(decode_t *);

typedef void (* decoder_visitor_t)(decode_t *, ssrc_t*, void*);

void decoder_append_data(decode_t * deco, ssrc_t* ssrc, void* data);

#endif
