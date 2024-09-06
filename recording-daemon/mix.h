#ifndef _MIX_H_
#define _MIX_H_

#include "types.h"
#include <libavutil/frame.h>

#define MIX_MAX_INPUTS 4

mix_t *mix_new(void);
void mix_destroy(mix_t *mix);
void mix_set_channel_slots(mix_t *mix, unsigned int);
int mix_config(mix_t *, const format_t *format);
int mix_add(mix_t *mix, AVFrame *frame, unsigned int idx, void *, output_t *output);
unsigned int mix_get_index(mix_t *, void *, unsigned int, unsigned int);
#endif

