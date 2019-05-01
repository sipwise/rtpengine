#ifndef _DTMF_H_
#define _DTMF_H_

#include <inttypes.h>
#include <glib.h>
#include <sys/types.h>
#include "str.h"


struct media_packet;

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


int dtmf_event(struct media_packet *, str *, int);

void dtmf_samples(void *buf, unsigned long offset, unsigned long num, unsigned int event, unsigned int volume,
		unsigned int sample_rate);


#endif
