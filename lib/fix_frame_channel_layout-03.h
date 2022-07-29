#include <libavutil/frame.h>
#include <libavutil/channel_layout.h>
#include "compat.h"

#define CH_LAYOUT channel_layout
#define CH_LAYOUT_T uint64_t
#define DEF_CH_LAYOUT(d,n) *(d) = av_get_default_channel_layout(n)
#define CH_LAYOUT_EQ(a,b) ((a) == (b))
#define SWR_ALLOC_SET_OPTS(a,b,c,d,e,f,g,h,i) *(a) = swr_alloc_set_opts(NULL,b,c,d,e,f,g,h,i)
#define SET_CHANNELS(a,b) (a)->channels = (b)
#define MONO_LAYOUT AV_CH_LAYOUT_MONO
#define GET_CHANNELS(x) (x)->channels
#define CH_LAYOUT_EXTRACT_MASK(a,b) av_channel_layout_extract_channel(a,b)
#define CH_LAYOUT_MASK(a) (a)
#define CH_LAYOUT_FROM_MASK(a,b) *(a) = (b)
#define CH_LAYOUT_PRINT(a,b) snprintf(b, sizeof(b), "0x%" PRIx64, a)

INLINE void fix_frame_channel_layout(AVFrame *frame) {
	if (frame->channel_layout) {
		if (!frame->channels)
			frame->channels = av_frame_get_channels(frame);
		return;
	}
	frame->channel_layout = av_get_default_channel_layout(frame->channels);
}
