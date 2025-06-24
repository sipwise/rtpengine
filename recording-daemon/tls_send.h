#ifndef _TLS_SEND_H_
#define _TLS_SEND_H_

#include "types.h"

void tls_fwd_init(stream_t *stream, metafile_t *mf, ssrc_t *ssrc);
void ssrc_tls_shutdown(ssrc_t *ssrc);

void ssrc_tls_state(ssrc_t *ssrc);
void ssrc_tls_fwd_silence_frames_upto(ssrc_t *ssrc, AVFrame *frame, int64_t upto);

#endif
