#ifndef _STREAM_H_
#define _STREAM_H_

#include "types.h"

void stream_open(metafile_t *mf, unsigned long id, char *name);
void stream_details(metafile_t *mf, unsigned long id, unsigned int tag, unsigned int media_sdp_id, unsigned int channel_slot);
void stream_forwarding_on(metafile_t *mf, unsigned long id, unsigned int on);
void stream_sdp_label(metafile_t *mf, unsigned long id, unsigned long *label);
void stream_close(stream_t *stream);
void stream_free(stream_t *stream);

#endif
