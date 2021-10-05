#include "dtmflib.h"
#include <math.h>
#include "compat.h"
#include "log.h"

struct dtmf_freq {
	unsigned int prim,
		     sec;
};

static const struct dtmf_freq dtmf_freqs[] = {
	{ 941, 1336 }, /* 0 */
	{ 697, 1209 }, /* 1 */
	{ 697, 1336 }, /* 2 */
	{ 697, 1477 }, /* 3 */
	{ 770, 1209 }, /* 4 */
	{ 770, 1336 }, /* 5 */
	{ 770, 1477 }, /* 6 */
	{ 852, 1209 }, /* 7 */
	{ 852, 1336 }, /* 8 */
	{ 852, 1477 }, /* 9 */
	{ 941, 1209 }, /* 10 = * */
	{ 941, 1477 }, /* 11 = # */
	{ 697, 1633 }, /* 12 = A */
	{ 770, 1633 }, /* 13 = B */
	{ 852, 1633 }, /* 14 = C */
	{ 941, 1633 }, /* 15 = D */
};


INLINE double freq2iter(unsigned int hz, unsigned int sample_rate) {
	double ret = hz;
	ret *= 2 * M_PI;
	ret /= sample_rate;
	return ret;
}

// only packed audio supported

#define freq_samples_x(type, mult) \
INLINE void freq_samples_ ## type(type *samples, unsigned long offset, unsigned long num, unsigned int prim_freq, \
		unsigned int sec_freq, unsigned int volume, unsigned int sample_rate, unsigned int channels) \
{ \
	if (!channels) \
		channels = 1; \
	/* XXX initialise/save these when the DTMF event starts */ \
	double vol = pow(1.122018, volume) * 2.0; \
 \
	double prim_iter = freq2iter(prim_freq, sample_rate); \
	double sec_iter = sec_freq ? freq2iter(sec_freq, sample_rate) : 0; \
 \
	num += offset; /* end here */ \
	while (offset < num) { \
		double prim = sin(prim_iter * offset) / vol; \
		type sample; \
		if (!sec_freq) \
			sample = prim * mult; \
		else { \
			double sec = sin(sec_iter * offset) / vol; \
			sample = prim * mult + sec * mult; \
		} \
		for (unsigned int ch = 0; ch < channels; ch++) \
			*samples++ = sample; \
		offset++; \
	} \
}

freq_samples_x(int16_t, 32767.0)
freq_samples_x(int32_t, 2147483647.0)
freq_samples_x(double, 1.0)
freq_samples_x(float, 1.0)

void dtmf_samples_int16_t_mono(void *buf, unsigned long offset, unsigned long num, unsigned int event,
		unsigned int volume, unsigned int sample_rate)
{
	int16_t *samples = buf;
	const struct dtmf_freq *df;

	if (event == 0xff) {
		// pause - silence samples
		memset(samples, 0, num * 2);
		return;
	}

	if (event >= G_N_ELEMENTS(dtmf_freqs)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unsupported DTMF event %u", event);
		memset(buf, 0, num * 2);
		return;
	}
	df = &dtmf_freqs[event];

	freq_samples_int16_t(samples, offset, num, df->prim, df->sec, volume, sample_rate, 1);
}
