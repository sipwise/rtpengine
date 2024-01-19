#ifndef _DTMF_H_
#define _DTMF_H_

#include <inttypes.h>
#include <glib.h>
#include <errno.h>
#include <stdbool.h>

#include "str.h"
#include "socket.h"


struct call_media;
struct call_monologue;


enum dtmf_trigger_type {
	DTMF_TRIGGER_BLOCK = 0,
	DTMF_TRIGGER_UNBLOCK,
	DTMF_TRIGGER_START_REC,
	DTMF_TRIGGER_STOP_REC,
	DTMF_TRIGGER_START_STOP_REC,
	DTMF_TRIGGER_PAUSE_REC,
	DTMF_TRIGGER_PAUSE_RESUME_REC,
	DTMF_TRIGGER_START_PAUSE_RESUME_REC,

	__NUM_DTMF_TRIGGERS,
};

extern const char *dtmf_trigger_types[__NUM_DTMF_TRIGGERS];

struct dtmf_trigger_state {
	enum dtmf_trigger_type type; // points to matching action
	str trigger; // string to look for
	unsigned int matched; // how many digits matched so far
	bool inactive; // ignore even if set
};

struct dtmf_trigger_action {
	void (*matched)(struct call_media *, struct call_monologue *); // run when the trigger is found
	bool repeatable; // reset after a match or not
	void (*digit)(struct call_media *, struct call_monologue *); // run when any digit is found
};


#include "call.h"

struct media_packet;
struct call_media;
struct call_monologue;

struct dtmf_event {
	int code; // char for start, zero for end
	int volume;
	uint64_t ts;
	int rand_code; // state for random replace mode
	unsigned int index; // running counter of events
	enum block_dtmf_mode block_dtmf; // block mode at the time of the event
};

bool dtmf_init(void);
int dtmf_event_packet(struct media_packet *, str *, int, uint64_t ts); // 0 = ok, 1 = end event, -1 = error
int dtmf_event_payload(str *, uint64_t *, uint64_t, struct dtmf_event *, dtmf_event_q *);
void dtmf_event_free(struct dtmf_event *);
int dtmf_code_from_char(char);
char dtmf_code_to_char(int code);
const char *dtmf_inject(struct call_media *media, int code, int volume, int duration, int pause,
		struct call_media *sink);
bool dtmf_do_logging(const call_t *, bool injected);
void dtmf_dsp_event(const struct dtmf_event *new_event, struct dtmf_event *cur_event,
		struct call_media *media, int clockrate, uint64_t ts, bool injected);
enum block_dtmf_mode dtmf_get_block_mode(call_t *call, struct call_monologue *ml);
bool is_pcm_dtmf_block_mode(enum block_dtmf_mode mode);
bool is_dtmf_replace_mode(enum block_dtmf_mode mode);
struct dtmf_event *is_in_dtmf_event(dtmf_event_q *, uint32_t ts, int clockrate, unsigned int head,
		unsigned int trail);
void dtmf_trigger_set(struct call_monologue *ml, enum dtmf_trigger_type,
		const str *s, bool inactive);

extern struct dtmf_trigger_action dtmf_trigger_actions[__NUM_DTMF_TRIGGERS];

#endif
