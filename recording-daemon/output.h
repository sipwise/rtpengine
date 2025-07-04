#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include "types.h"
#include <libavutil/frame.h>


extern int mp3_bitrate;


void output_init(const char *format);

output_t *output_new_ext(metafile_t *, const char *type, const char *kind, const char *label);
void output_close(metafile_t *, output_t *, tag_t *, bool discard);

int output_config(output_t *output, const format_t *requested_format, format_t *actual_format);


void sink_init(sink_t *);
void sink_close(sink_t *sink);

bool sink_add(sink_t *, AVFrame *frame);


#endif
