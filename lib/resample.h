#ifndef _RESAMPLE_H_
#define _RESAMPLE_H_


#include "codeclib.h"
#include <libavutil/frame.h>


AVFrame *resample_frame(resample_t *resample, AVFrame *frame, const format_t *to_format);
void resample_shutdown(resample_t *resample);


#endif
