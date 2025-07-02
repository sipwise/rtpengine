#ifndef _MIX_H_
#define _MIX_H_

#include "types.h"
#include <libavutil/frame.h>

#define MIX_MAX_INPUTS 4

mix_t *mix_new(pthread_mutex_t *, sink_t *, unsigned int);
void mix_destroy(mix_t *mix);
void mix_close(mix_t *mix);
void mix_set_channel_slots(mix_t *mix, unsigned int);
bool mix_config(sink_t *, const format_t *requested_format, format_t *actual_format);
bool mix_add(sink_t *, AVFrame *frame);
unsigned int mix_get_index(mix_t *, void *, unsigned int, unsigned int);
void mix_sink_init(sink_t *, ssrc_t *, mix_t **, int resample);

#endif
