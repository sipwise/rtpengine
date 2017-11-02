#ifndef _FORWARD_H_
#define _FORWARD_H_

#include "types.h"

void start_forwarding_capture(metafile_t *mf, char *meta_info);
int forward_packet(metafile_t *mf, unsigned char *buf, unsigned len);

#endif
