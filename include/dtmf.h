#ifndef _DTMF_H_
#define _DTMF_H_

#include <inttypes.h>
#include <glib.h>
#include <errno.h>
#include <stdbool.h>
#include "str.h"
#include "socket.h"
#include "call.h"


struct media_packet;
struct call_media;
struct call;
struct call_monologue;


struct dtmf_event {
	int code; // char for start, zero for end
	int volume;
	uint64_t ts;
	int rand_code; // state for random replace mode
	unsigned int index; // running counter of events
	enum block_dtmf_mode block_dtmf; // block mode at the time of the event
};

void dtmf_init(void);
int dtmf_event_packet(struct media_packet *, str *, int, uint64_t ts); // 0 = ok, 1 = end event, -1 = error
int dtmf_event_payload(str *, uint64_t *, uint64_t, struct dtmf_event *, GQueue *);
void dtmf_event_free(void *);
int dtmf_code_from_char(char);
char dtmf_code_to_char(int code);
const char *dtmf_inject(struct call_media *media, int code, int volume, int duration, int pause,
		struct call_media *sink);
bool dtmf_do_logging(void);
void dtmf_dsp_event(const struct dtmf_event *new_event, struct dtmf_event *cur_event,
		struct call_media *media, int clockrate, uint64_t ts);
enum block_dtmf_mode dtmf_get_block_mode(struct call *call, struct call_monologue *ml);
bool is_pcm_dtmf_block_mode(enum block_dtmf_mode mode);
bool is_dtmf_replace_mode(enum block_dtmf_mode mode);
struct dtmf_event *is_in_dtmf_event(GQueue *, uint32_t ts, int clockrate, unsigned int head, unsigned int trail);

#endif
