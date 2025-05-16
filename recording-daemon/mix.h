#ifndef _MIX_H_
#define _MIX_H_

#include "types.h"
#include <libavutil/frame.h>
#include <stdint.h>

#define MIX_MAX_INPUTS 8

mix_t *mix_new(void);
void mix_destroy(mix_t *mix);
int mix_config(mix_t *, const format_t *format);
int mix_add(mix_t *mix, AVFrame *frame, unsigned int idx, uint32_t ssrc, output_t *output);
unsigned int mix_get_index(mix_t *, uint32_t ssrc, unsigned int, unsigned int);
#endif

