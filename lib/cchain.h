#ifndef _CCHAIN_H_
#define _CCHAIN_H_

#include "codeclib.h"

void cc_init(void);
void cc_cleanup(void);

AVPacket *codec_cc_input_data(codec_cc_t *c, const str *data, unsigned long ts, void *x, void *y, void *z);

#endif
