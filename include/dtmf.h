#ifndef _DTMF_H_
#define _DTMF_H_

#include <inttypes.h>
#include <glib.h>
#include <errno.h>
#include "str.h"


struct media_packet;

struct dtmf_event {
	int code;
	int volume;
	uint64_t ts;
};

void dtmf_init(void);
int dtmf_event(struct media_packet *, str *, int);
int dtmf_event_payload(str *, uint64_t *, uint64_t, struct dtmf_event *, GQueue *);
void dtmf_event_free(void *);
int dtmf_do_logging(void);


#endif
