#ifndef _MIX_H_
#define _MIX_H_

#include "types.h"
#include <libavutil/frame.h>


mix_t *mix_new(void);
void mix_destroy(mix_t *mix);

int mix_config(mix_t *, unsigned int clockrate, unsigned int channels);
int mix_add(mix_t *mix, AVFrame *frame, unsigned int idx, output_t *output);
unsigned int mix_get_index(mix_t *);


#endif

