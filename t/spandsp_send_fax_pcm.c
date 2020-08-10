#undef NDEBUG
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <spandsp/telephony.h>
#include <spandsp/logging.h>
#include <spandsp/t38_core.h>
#include <spandsp/t30.h>
#include <spandsp/t30_api.h>
#include <spandsp/fax.h>
#include "compat.h"
#include "spandsp_logging.h"



#define SAMPLES_PER_CHUNK 160
#define MICROSECONDS_PER_CHUNK 20000
#ifndef TRUE
# define TRUE true
#endif


// from ITU G.191
void alaw_compress (size_t lseg, int16_t *linbuf, uint8_t *logbuf) {
  short ix, iexp;
  long n;

  for (n = 0; n < lseg; n++) {
    ix = linbuf[n] < 0          /* 0 <= ix < 2048 */
      ? (~linbuf[n]) >> 4       /* 1's complement for negative values */
      : (linbuf[n]) >> 4;

    /* Do more, if exponent > 0 */
    if (ix > 15) {              /* exponent=0 for ix <= 15 */
      iexp = 1;                 /* first step: */
      while (ix > 16 + 15) {    /* find mantissa and exponent */
        ix >>= 1;
        iexp++;
      }
      ix -= 16;                 /* second step: remove leading '1' */

      ix += iexp << 4;          /* now compute encoded value */
    }
    if (linbuf[n] >= 0)
      ix |= (0x0080);           /* add sign bit */

    logbuf[n] = ix ^ (0x0055);  /* toggle even bits */
  }
}
void alaw_expand (size_t lseg, uint8_t *logbuf, int16_t *linbuf) {
  short ix, mant, iexp;
  long n;

  for (n = 0; n < lseg; n++) {
    ix = logbuf[n] ^ (0x0055);  /* re-toggle toggled bits */

    ix &= (0x007F);             /* remove sign bit */
    iexp = ix >> 4;             /* extract exponent */
    mant = ix & (0x000F);       /* now get mantissa */
    if (iexp > 0)
      mant = mant + 16;         /* add leading '1', if exponent > 0 */

    mant = (mant << 4) + (0x0008);      /* now mantissa left justified and */
    /* 1/2 quantization step added */
    if (iexp > 1)               /* now left shift according exponent */
      mant = mant << (iexp - 1);

    linbuf[n] = logbuf[n] > 127 /* invert, if negative sample */
      ? mant : -mant;
  }
}



int done = 0;

static void phase_e_handler(PHASE_E_HANDLER_ARGS) {
	fprintf(stderr, "send: phase E result %i\n", result);
	assert(result == T30_ERR_OK);
	done = 1;
}


int main(int argc, char **argv) {
	assert(argc == 2);
	const char *input_file_name = argv[1];

	fax_state_t *fax = fax_init(NULL, TRUE);
	assert(fax != NULL);

	int use_transmit_on_idle = 1;
	int use_tep = 0;
	int supported_modems = T30_SUPPORT_V27TER | T30_SUPPORT_V29 | T30_SUPPORT_V17;
	int use_ecm = 0;

	// taken from t38_gateway_tests.c
	t30_state_t *t30 = fax_get_t30_state(fax);
	fax_set_transmit_on_idle(fax, use_transmit_on_idle);
	fax_set_tep_mode(fax, use_tep);
	t30_set_supported_modems(t30, supported_modems);
	t30_set_tx_ident(t30, "11111111");
	t30_set_tx_nsf(t30, (const uint8_t *) "\x50\x00\x00\x00Spandsp\x00", 12);
	t30_set_tx_file(t30, input_file_name, -1, -1);
	t30_set_phase_e_handler(t30, phase_e_handler, NULL);
	t30_set_ecm_capability(t30, use_ecm);
//	if (use_ecm)
//		t30_set_supported_compressions(t30, T30_SUPPORT_T4_1D_COMPRESSION | T30_SUPPORT_T4_2D_COMPRESSION | T30_SUPPORT_T6_COMPRESSION);
	t30_set_minimum_scan_line_time(t30, 40);

	struct timeval now, next;

	setbuf(stdout, NULL);
	gettimeofday(&now, NULL);

	while (!done) {
		next = now;
		next.tv_usec += MICROSECONDS_PER_CHUNK;
		while (next.tv_usec >= 1000000) {
			next.tv_usec -= 1000000;
			next.tv_sec++;
		}

		int16_t samples[SAMPLES_PER_CHUNK];

		int ret = fax_tx(fax, samples, SAMPLES_PER_CHUNK);
		assert(ret == SAMPLES_PER_CHUNK);

		uint8_t alaw[SAMPLES_PER_CHUNK];
		alaw_compress(SAMPLES_PER_CHUNK, samples, alaw);

		ret = fwrite(alaw, SAMPLES_PER_CHUNK, 1, stdout);
		if (ret < 1)
			break;

		ret = fread(alaw, SAMPLES_PER_CHUNK, 1, stdin);
		if (ret == 0)
			break;
		assert(ret == 1);

		alaw_expand(SAMPLES_PER_CHUNK, alaw, samples);

		ret = fax_rx(fax, samples, SAMPLES_PER_CHUNK);
		assert(ret == 0);

		while (1) {
			gettimeofday(&now, NULL);
			long long diff = ((long long) next.tv_sec - now.tv_sec) * 1000000
				+ ((long long) next.tv_usec - now.tv_usec);
			if (diff <= 0)
				break;
			usleep(diff);
		}
	}

//	assert(done == 1);

	return 0;
}
