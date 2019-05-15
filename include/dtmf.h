#ifndef _DTMF_H_
#define _DTMF_H_

#include <inttypes.h>
#include "str.h"


struct media_packet;

struct dtmf_event {
	int code;
	int volume;
	uint64_t ts;
};

int dtmf_event(struct media_packet *, str *, int);
void dtmf_event_free(void *);


#endif
