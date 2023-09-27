#ifndef _MIX_BUFFER_H_
#define _MIX_BUFFER_H_

#include <stdint.h>
#include <stdbool.h>
#include "helpers.h"


enum AVSampleFormat;
struct mix_buffer_impl;
struct ssrc_hash;


/*
 * A simple circular audio buffer that allows mixing multiple sources of
 * audio. Sources are tracked by SSRC and all sources are expected to
 * provide audio in the same format (same clock rate, channels, sample
 * format).

 * Only one consumer per buffer is supported, which is expected to retrieve
 * buffered audio at regular intervals (ptime) and so continuously empty
 * the buffer.

 * The first audio source to write into the buffer at the leading edge of
 * the circular buffer has its audio simply copied into the buffer, with
 * the leading edge advanced, while other later sources writing into the
 * buffer mixed into the existing buffered audio at their respective write
 * positions.
 */
struct mix_buffer {
	mutex_t lock;

	union {
		// generic pointers
		void *v;
		char *c;

		// implementation-specific pointers
		int16_t *s16;
	} buf;

	unsigned int channels;
	unsigned int clockrate;

	// all sizes and positions in samples
	unsigned int size; // total size
	unsigned int read_pos; // current read (output) position
	unsigned int head_write_pos; // furthest ahead write (input) position
	unsigned int fill; // difference between read and write position
	unsigned int delay; // initial write delay for new inputs/sources

	unsigned int loops; // how many times the write pos has circled around
	bool active; // to optionally suppress early media

	// implementation details
	const struct mix_buffer_impl *impl;
	unsigned int sample_size_channels; // = sample_size * channels
	struct ssrc_hash *ssrc_hash;
};


bool mix_buffer_init_active(struct mix_buffer *, enum AVSampleFormat, unsigned int clockrate,
		unsigned int channels, unsigned int size_ms, unsigned int delay_ms, bool active);
#define mix_buffer_init(mb, fmt, clockrate, channels, size_ms, delay_ms) \
	mix_buffer_init_active(mb, fmt, clockrate, channels, size_ms, delay_ms, true)
INLINE void mix_buffer_activate(struct mix_buffer *mb) {
	LOCK(&mb->lock);
	mb->active = true;
}
void mix_buffer_destroy(struct mix_buffer *);

void *mix_buffer_read_fast(struct mix_buffer *, unsigned int samples, unsigned int *size);
void mix_buffer_read_slow(struct mix_buffer *, void *outbuf, unsigned int samples);
bool mix_buffer_write_delay(struct mix_buffer *, uint32_t ssrc, const void *buf, unsigned int samples,
		const struct timeval *, const struct timeval *);

INLINE bool mix_buffer_write(struct mix_buffer *mb, uint32_t ssrc, const void *buf, unsigned int samples) {
	return mix_buffer_write_delay(mb, ssrc, buf, samples, NULL, NULL);
}


#endif
