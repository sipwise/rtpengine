#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include "types.h"
#include <libavutil/frame.h>


void output_init(const char *format);

output_t *output_new(const char *filename);
void output_close(output_t *);

int output_config(output_t *output, unsigned int clockrate, unsigned int channels);
int output_add(output_t *output, AVFrame *frame);


#endif
