#ifdef WITH_TRANSCODING

#include "mix_buffer.h"
#include <libavutil/samplefmt.h>
#include <stdlib.h>
#include <assert.h>
#include <glib.h>
#include "ssrc.h"


typedef void mix_in_fn_t(void *restrict dst, const void *restrict src, unsigned int num);


struct mix_buffer_impl {
	unsigned int sample_size;
	mix_in_fn_t *mix_in;
};

typedef struct {
	struct ssrc_entry h; // must be first
	unsigned int write_pos;
	unsigned int loops;
} mix_buffer_ssrc_source;



#if defined(__x86_64__)
// mix_in_x64_sse2.S
mix_in_fn_t s16_mix_in_sse2;

// mix_in_x64_avx2.S
mix_in_fn_t s16_mix_in_avx2;

// mix_in_x64_avx512.S
mix_in_fn_t s16_mix_in_avx512;
#endif



static void s16_mix_in_c(void *restrict dst, const void *restrict src, unsigned int samples) {
	int16_t *d = dst;
	const int16_t *s = src;

	for (unsigned int i = 0; i < samples; i++) {
		int16_t orig = d[i];
		d[i] += s[i];
		// saturate/clamp
		if (d[i] < orig && s[i] > 0)
			d[i] = 32767;
		else if (d[i] > orig && s[i] < 0)
			d[i] = -32768;
	}
}


#if defined(__x86_64__) && !defined(ASAN_BUILD) && HAS_ATTR(ifunc) && defined(__GLIBC__)
static mix_in_fn_t *resolve_s16_mix_in(void) {
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX512BW))
		return s16_mix_in_avx512;
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX2))
		return s16_mix_in_avx2;
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_SSE2))
		return s16_mix_in_sse2;
	return s16_mix_in_c;
}
static mix_in_fn_t s16_mix_in __attribute__ ((ifunc ("resolve_s16_mix_in")));
#else
#define s16_mix_in s16_mix_in_c
#endif


const struct mix_buffer_impl impl_s16_c = {
	.sample_size = sizeof(int16_t),
	.mix_in = s16_mix_in,
};


// must be locked already
static void fill_up_to(struct mix_buffer *mb, unsigned int up_to) {
	if (mb->fill >= up_to)
		return;
	unsigned int needed = up_to - mb->fill;
	assert(up_to <= mb->size);

	// tail end
	unsigned int tail_room = mb->size - mb->head_write_pos;
	tail_room = MIN(tail_room, needed);
	memset(mb->buf.c + mb->head_write_pos * mb->sample_size_channels, 0, tail_room * mb->sample_size_channels);

	needed -= tail_room;
	mb->head_write_pos += tail_room;
	mb->fill += tail_room;

	if (needed) {
		// ran against the end of the buffer. fill up from beginning
		memset(mb->buf.c, 0, needed * mb->sample_size_channels);
		mb->head_write_pos = needed;
		mb->fill += needed;
		mb->loops++;
	}
}


void *mix_buffer_read_fast(struct mix_buffer *mb, unsigned int samples, unsigned int *size) {
	LOCK(&mb->lock);

	if (samples > mb->size || !mb->active) {
		*size = 0; // error or inactive
		return NULL;
	}

	fill_up_to(mb, samples);

	*size = samples * mb->sample_size_channels;

	// shortcut extraction possible?
	int end_read_pos = mb->read_pos + samples;
	if (end_read_pos > mb->size)
		return NULL; // nope, must use temporary buffer

	void *ret = mb->buf.c + mb->read_pos * mb->sample_size_channels;
	mb->read_pos = end_read_pos == mb->size ? 0 : end_read_pos;
	mb->fill -= samples;
	return ret;
}


// must be called after mix_buffer_read_fast returned NULL, with a buffer the size of *size bytes
void mix_buffer_read_slow(struct mix_buffer *mb, void *outbuf, unsigned int samples) {
	LOCK(&mb->lock);

	unsigned int tail_part = mb->size - mb->read_pos;
	memcpy(outbuf, mb->buf.c + mb->read_pos * mb->sample_size_channels, tail_part * mb->sample_size_channels);
	mb->fill -= samples;
	samples -= tail_part;
	memcpy(outbuf + tail_part * mb->sample_size_channels, mb->buf.c, samples * mb->sample_size_channels);

	mb->read_pos = samples;
}


static void mix_ssrc_put(mix_buffer_ssrc_source *s) {
	obj_put(&s->h);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(mix_buffer_ssrc_source, mix_ssrc_put)


// write at the write-head, direct copy without mixing
// must be locked already
static bool mix_buffer_write_fast(struct mix_buffer *mb, mix_buffer_ssrc_source *src,
		const void *buf, unsigned int samples)
{
	// check for buffer overflow
	if (mb->fill + samples > mb->size)
		return false;

	// will there be a buffer wrap-around?
	if (mb->head_write_pos + samples >= mb->size) {
		// copy in to end of buffer
		unsigned int tail_part = mb->size - mb->head_write_pos;
		memcpy(mb->buf.c + mb->head_write_pos * mb->sample_size_channels, buf,
				tail_part * mb->sample_size_channels);
		mb->fill += tail_part;
		samples -= tail_part;
		buf = ((const char *) buf) + tail_part * mb->sample_size_channels;
		mb->head_write_pos = 0;
		// src->write_pos is updated below
		mb->loops++;
		src->loops = mb->loops;
	}

	// copy in remainder, if any
	memcpy(mb->buf.c + mb->head_write_pos * mb->sample_size_channels, buf,
			samples * mb->sample_size_channels);
	mb->head_write_pos += samples;
	src->write_pos = mb->head_write_pos;
	mb->fill += samples;

	return true;
}


// write before the write-head with mixing-in
// must be locked already
static bool mix_buffer_write_slow(struct mix_buffer *mb, mix_buffer_ssrc_source *src,
		const void *buf, unsigned int samples)
{
	// mix-in up to the current write-head, or end of buffer in case of wrap-around

	if (mb->head_write_pos < src->write_pos) {
		// wrap-arund: mix-in to end of buffer
		unsigned int tail_part = mb->size - src->write_pos;
		if (tail_part > samples)
			tail_part = samples;
		mb->impl->mix_in(mb->buf.c + src->write_pos * mb->sample_size_channels, buf,
				tail_part * mb->channels);
		samples -= tail_part;
		buf = ((const char *) buf) + tail_part * mb->sample_size_channels;
		src->write_pos += tail_part;
		if (src->write_pos == mb->size) {
			src->write_pos = 0;
			src->loops++;
		}

		if (samples == 0)
			return true;
	}

	// mix-in to current write-head
	unsigned int mix_part = mb->head_write_pos - src->write_pos;
	if (mix_part > samples)
		mix_part = samples;
	mb->impl->mix_in(mb->buf.c + src->write_pos * mb->sample_size_channels, buf, mix_part * mb->channels);
	samples -= mix_part;
	src->write_pos += mix_part;
	buf = ((const char *) buf) + mix_part * mb->sample_size_channels;

	// anything that's left, just copy-in
	return mix_buffer_write_fast(mb, src, buf, samples);
}


static void mix_buffer_src_add_delay(struct mix_buffer *mb, mix_buffer_ssrc_source *src,
		unsigned int samples)
{
	if (!samples)
		return;
	// shift new write pos into the future
	src->write_pos += samples;
	if (src->write_pos >= mb->size) {
		src->write_pos -= mb->size;
		src->loops++;
	}
	// fill up buffer if needed
	if (src->loops == mb->loops && src->write_pos > mb->head_write_pos)
		fill_up_to(mb, mb->fill + src->write_pos - mb->head_write_pos);
	else if (src->loops == mb->loops + 1 && src->write_pos < mb->head_write_pos)
		fill_up_to(mb, mb->fill + src->write_pos + mb->size - mb->head_write_pos);
}


static void mix_buffer_src_init_pos(struct mix_buffer *mb, mix_buffer_ssrc_source *src) {
	src->write_pos = mb->read_pos;
	src->loops = mb->loops;
	if (mb->head_write_pos < src->write_pos)
		src->loops--;
	mix_buffer_src_add_delay(mb, src, mb->delay);
}


static void mix_buff_src_shift_delay(struct mix_buffer *mb, mix_buffer_ssrc_source *src,
		const struct timeval *last, const struct timeval *now)
{
	if (!last || !now)
		return;
	long long diff_us = timeval_diff(now, last);
	if (diff_us <= 0)
		return;
	unsigned int samples = mb->clockrate * diff_us / 1000000;
	mix_buffer_src_add_delay(mb, src, samples);
}


// takes the difference between two time stamps into account, scaled to the given clock rate,
// to add an additional write-delay for a newly created source
bool mix_buffer_write_delay(struct mix_buffer *mb, uint32_t ssrc, const void *buf, unsigned int samples,
		const struct timeval *last, const struct timeval *now)
{
	LOCK(&mb->lock);

	bool created;
	g_autoptr(mix_buffer_ssrc_source) src = get_ssrc_full(ssrc, mb->ssrc_hash, &created);
	if (!src)
		return false;
	if (created)
		mix_buff_src_shift_delay(mb, src, last, now);

	mb->active = true;

	// loop twice at the most to re-run logic after a reset
	while (true) {
		// shortcut if we're at the write head
		if (src->write_pos == mb->head_write_pos && src->loops == mb->loops)
			return mix_buffer_write_fast(mb, src, buf, samples);

		// not at the write head... did we fall behind what has been read already?
		if (mb->head_write_pos >= mb->read_pos) {
			// |--------------|###################|------------|
			//                R                   W
			//                    ^- slow mix-in
			if (src->write_pos >= mb->read_pos && src->write_pos < mb->head_write_pos
					&& src->loops == mb->loops)
				return mix_buffer_write_slow(mb, src, buf, samples);
		}
		else {
			// |#########|-----------------------------|#######|
			//           W                             R
			//     ^---     slow mix-in             ------^
			if ((src->write_pos < mb->head_write_pos && src->loops == mb->loops)
					|| (src->write_pos >= mb->read_pos && src->loops + 1 == mb->loops))
				return mix_buffer_write_slow(mb, src, buf, samples);
		}

		// we fell behind. reset write position to current read pos and try again
		mix_buffer_src_init_pos(mb, src);
	}
}


static struct ssrc_entry *mix_buffer_ssrc_new(void *p) {
	struct mix_buffer *mb = p;
	mix_buffer_ssrc_source *src = obj_alloc0(mix_buffer_ssrc_source, NULL);
	mix_buffer_src_init_pos(mb, src);
	return &src->h;
}


// struct must be zeroed already
bool mix_buffer_init_active(struct mix_buffer *mb, enum AVSampleFormat fmt, unsigned int clockrate,
		unsigned int channels, unsigned int size_ms, unsigned int delay_ms, bool active)
{
	switch (fmt) {
		case AV_SAMPLE_FMT_S16:
			mb->impl = &impl_s16_c;
			break;
		default:
			return false;
	}

	unsigned int size = clockrate * size_ms / 1000; // in samples
	unsigned int delay = clockrate * delay_ms / 1000; // in samples

	mutex_init(&mb->lock);
	mb->sample_size_channels = channels * mb->impl->sample_size;
	mb->buf.v = g_malloc(mb->sample_size_channels * size);
	mb->size = size;
	mb->clockrate = clockrate;
	mb->channels = channels;
	mb->delay = delay;
	mb->active = active;

	mb->ssrc_hash = create_ssrc_hash_full_fast(mix_buffer_ssrc_new, mb);

	return true;
}


void mix_buffer_destroy(struct mix_buffer *mb) {
	g_free(mb->buf.v);
	free_ssrc_hash(&mb->ssrc_hash);
	mutex_destroy(&mb->lock);
}

#endif
