#ifndef _DECODER_H_
#define _DECODER_H_

#include "types.h"
#include "str.h"


decode_t *decoder_new(const char *payload_str, const char *format, int ptime);
int decoder_input(decode_t *, const str *, unsigned long ts, ssrc_t *);
void decoder_free(decode_t *);


#endif
