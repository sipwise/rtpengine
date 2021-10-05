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

// pow(1.122018, x)
static const double vol_table[] = {
	1.0,
	1.122018,
	1.2589243923239999,
	1.4125358288265897,
	1.5848906255883524,
	1.778275809941392,
	1.9952574677188206,
	2.238714793414936,
	2.5118782950778393,
	2.818372660886647,
	3.1622648562227136,
	3.5481180894492965,
	3.9810523624877208,
	4.466812409653747,
	5.011843926254878,
	5.623379098448646,
	6.309532569283152,
	7.079409114321943,
	7.9432244556332785,
	8.91244081726074,
	9.99991902090126,
	11.22008913999359,
	12.589141976677327,
	14.12524390238754,
	15.848777912869062,
	17.78261409624152,
	19.952413103036715,
	22.38696664504305,
	25.118579541137912,
	28.183498379588475,
	31.6223924848691,
	35.480893571087854,
	39.810201242844855,
	44.667762378094295,
	50.1180334079446,
	56.23333560831519,
	63.094814752570585,
	70.79351785904974,
	79.43160132117526,
	89.12368645118244,
	99.9983804245828,
	112.19998280722955,
	125.89040030940208,
	141.25129517435468,
	158.4864957089391,
	177.82470094235242,
	199.52251530193638,
	223.86785357404804,
	251.18376133144622,
	281.8327015215866,
	316.22136409584755,
	354.8060625000947,
	398.0987886342312,
	446.6740066258028,
	501.17627556627,
	562.3288023583151,
	630.943038164472,
	707.9294457952245,
	794.3095809122663,
	891.2296473560191,
	999.9757064671057,
	1121.9907422188091,
	1258.8938086028636,
	1412.501513340968,
	1584.852122995806,
	1778.2326093395081,
	1995.2089958658962,
	2238.660407123461,
	2511.8172726798516,
	2818.3041926577016,
	3162.188033637409,
	3548.031893125778,
	3980.955648661199,
	4466.703894999541,
	5011.722170859594,
	5623.242486703541,
	6309.379288446133,
	7079.237130463753,
	7943.031486648679,
	8912.224302586577,
	9999.676087539585,
	11219.81656438899,
	12588.836141942606,
	14124.900750310158,
	15848.392890061503,
	17782.182093721025,
	19951.928388432676,
	22386.422786532454,
	25117.969322099572,
	28182.813702843516,
	31621.624265237075,
	35480.03161483277,
	39809.23411241143,
	44666.67724033965,
	50116.815863851414,
	56231.96950192683,
	63093.28195661294,
	70791.79803439493,
	79429.67164695573,
	89121.52132197398,
	99995.95111063859,
	112197.2570732565,
	125887.34198682109,
	141247.86368136902,
	158482.6455120423,
	177820.38095213068,
	199517.66819514774,
	223862.4150329833,
	251177.65919047783,
	281825.85480958153,
	316213.68196173705,
	354797.44300734426,
	398089.11740821437,
	446663.1553361299,
	501164.10022393375,
	562315.1414050576,
	630927.7103290199,
	707912.2476879463,
	794290.2843263341,
	891207.9962392647,
	999951.4135243873,
	1121963.485099806,
	1258863.225624714,
	1412467.1986889902,
	1584813.6213386236,
	1778189.4097871196,
	1995160.5251905243,
	2238606.0221532215,
};

// only packed audio supported

#define freq_samples_x(type, mult) \
INLINE void freq_samples_ ## type(type *samples, unsigned long offset, unsigned long num, unsigned int prim_freq, \
		unsigned int sec_freq, unsigned int volume, unsigned int sample_rate, unsigned int channels) \
{ \
	if (!channels) \
		channels = 1; \
\
	double vol; \
	if (volume < G_N_ELEMENTS(vol_table)) \
		vol = vol_table[volume]; \
	else \
		vol = pow(1.122018, volume); \
\
	if (sec_freq) /* halve volume of we have two tones */ \
		vol *= 2.0; \
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
