#ifndef _DTMF_H_
#define _DTMF_H_

#include <inttypes.h>
#include <glib.h>
#include <errno.h>
#include <stdbool.h>
#include "str.h"
#include "socket.h"


struct media_packet;
struct call_media;


struct dtmf_event {
	int code;
	int volume;
	uint64_t ts;
};

void dtmf_init(void);
int dtmf_event_packet(struct media_packet *, str *, int); // 0 = ok, 1 = end event, -1 = error
int dtmf_event_payload(str *, uint64_t *, uint64_t, struct dtmf_event *, GQueue *);
void dtmf_event_free(void *);
int dtmf_code_from_char(char);
const char *dtmf_inject(struct call_media *media, int code, int volume, int duration, int pause,
		struct call_media *sink);
bool dtmf_do_logging(void);

#endif
