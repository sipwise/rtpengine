#ifndef _TLS_SEND_H_
#define _TLS_SEND_H_

#include "types.h"

void tls_fwd_init(stream_t *stream, metafile_t *mf, ssrc_t *ssrc);
void tls_fwd_shutdown(tls_fwd_t **);

void tls_fwd_state(tls_fwd_t **);
void tls_fwd_silence_frames_upto(tls_fwd_t *, AVFrame *frame, int64_t upto);

#endif
