#include <libavutil/frame.h>
#include <libavutil/channel_layout.h>
#include "compat.h"

#if LIBAVUTIL_VERSION_INT >= AV_VERSION_INT(57, 28, 100)
// both `channel_layout` and `channels` are deprecated in favour of `ch_layout`
#define CH_LAYOUT ch_layout
#define CH_LAYOUT_T AVChannelLayout
#define DEF_CH_LAYOUT(d,n) av_channel_layout_default(d,n)
#define CH_LAYOUT_EQ(a,b) (av_channel_layout_compare(&(a),&(b)) == 0)
#define SWR_ALLOC_SET_OPTS(a,b,c,d,e,f,g,h,i) swr_alloc_set_opts2(a,&(b),c,d,&(e),f,g,h,i)
#define SET_CHANNELS(a,b) ((void)0)
#define MONO_LAYOUT AV_CHANNEL_LAYOUT_MONO
#define GET_CHANNELS(x) (x)->ch_layout.nb_channels
#define CH_LAYOUT_EXTRACT_MASK(a,b) (1ULL << av_channel_layout_channel_from_index(&(a),b))
#define CH_LAYOUT_MASK(a) (a)->u.mask
#define CH_LAYOUT_FROM_MASK(a,b) av_channel_layout_from_mask(a,b)
#define CH_LAYOUT_PRINT(a,b) av_channel_layout_describe(&(a),b,sizeof(b))
#else
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
#endif

INLINE void fix_frame_channel_layout(AVFrame *frame) {
#if LIBAVUTIL_VERSION_INT >= AV_VERSION_INT(57, 28, 100)
	return;
#else
	if (frame->channel_layout) {
#if LIBAVUTIL_VERSION_MAJOR < 56
		if (!frame->channels)
			frame->channels = av_frame_get_channels(frame);
#endif
		return;
	}
#if LIBAVUTIL_VERSION_MAJOR < 56
	frame->channel_layout = av_get_default_channel_layout(av_frame_get_channels(frame));
#else
	frame->channel_layout = av_get_default_channel_layout(frame->channels);
#endif
#endif
}
