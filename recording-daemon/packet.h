#ifndef _PACKET_H_
#define _PACKET_H_

#include "types.h"
#include <libavutil/frame.h>

void ssrc_close(ssrc_t *s);
void ssrc_free(void *p);

void packet_process(stream_t *, unsigned char *, unsigned len);

void ssrc_tls_state(ssrc_t *ssrc);
void ssrc_tls_fwd_silence_frames_upto(ssrc_t *ssrc, AVFrame *frame, int64_t upto);

#endif
