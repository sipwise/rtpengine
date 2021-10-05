#ifndef _DTMFLIB_H_
#define _DTMFLIB_H_

#include <glib.h>
#include <inttypes.h>


struct telephone_event_payload {
	uint8_t event;
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	unsigned volume:6;
	unsigned r:1;
	unsigned end:1;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
	unsigned end:1;
	unsigned r:1;
	unsigned volume:6;
#else
#error "byte order unknown"
#endif
	uint16_t duration;
} __attribute__ ((packed));


void dtmf_samples_int16_t_mono(void *buf, unsigned long offset, unsigned long num, unsigned int event,
		unsigned int volume, unsigned int sample_rate);


#endif
