#ifndef _OUTPUT_H_
#define _OUTPUT_H_

#include "types.h"
#include <libavutil/frame.h>


extern int mp3_bitrate;


void output_init(const char *format);

output_t *output_new(const char *path, const char *call, const char *type, const char *kind, const char *label);
output_t *output_new_from_full_path(const char *path, char *name, const char *kind);
void output_close(metafile_t *, output_t *, tag_t *);

int output_config(output_t *output, const format_t *requested_format, format_t *actual_format);
int output_add(output_t *output, AVFrame *frame);


#endif
