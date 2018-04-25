#include <libavutil/frame.h>
#include <libavutil/channel_layout.h>
#include "compat.h"

INLINE void fix_frame_channel_layout(AVFrame *frame) {
	if (frame->channel_layout)
		return;
#if LIBAVUTIL_VERSION_MAJOR >= 56
	frame->channel_layout = av_get_default_channel_layout(frame->channels);
#else
	frame->channel_layout = av_get_default_channel_layout(av_frame_get_channels(frame));
#endif
}
