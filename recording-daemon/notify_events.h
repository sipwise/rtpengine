#ifndef _NOTIFY_EVENTS_H_
#define _NOTIFY_EVENTS_H_

#include <stdbool.h>
#include <stdint.h>

/**
 * Recording lifecycle notification events (shared with unit tests).
 * Full notify transport API lives in notify.h.
 */
enum notify_event {
	NOTIFY_EVT_FILE_OPENED = 0,
	NOTIFY_EVT_STARTED,
	NOTIFY_EVT_FINISHED,
	NOTIFY_EVT_DISCARDED,
	NOTIFY_EVT_FAILED,
	NOTIFY_EVT_CALL_STARTED,
	NOTIFY_EVT_CALL_FINISHED,
	NOTIFY_EVT_CALL_DISCARDED,
	NOTIFY_EVT_COUNT,
};

#define NOTIFY_MASK_OPENED		(1u << NOTIFY_EVT_FILE_OPENED)
#define NOTIFY_MASK_STARTED		(1u << NOTIFY_EVT_STARTED)
#define NOTIFY_MASK_FINISHED		(1u << NOTIFY_EVT_FINISHED)
#define NOTIFY_MASK_DISCARDED		(1u << NOTIFY_EVT_DISCARDED)
#define NOTIFY_MASK_FAILED		(1u << NOTIFY_EVT_FAILED)
#define NOTIFY_MASK_CALL_STARTED	(1u << NOTIFY_EVT_CALL_STARTED)
#define NOTIFY_MASK_CALL_FINISHED	(1u << NOTIFY_EVT_CALL_FINISHED)
#define NOTIFY_MASK_CALL_DISCARDED	(1u << NOTIFY_EVT_CALL_DISCARDED)
#define NOTIFY_MASK_STREAM_ALL		(NOTIFY_MASK_OPENED | NOTIFY_MASK_STARTED | \
					 NOTIFY_MASK_FINISHED | NOTIFY_MASK_DISCARDED | \
					 NOTIFY_MASK_FAILED)
#define NOTIFY_MASK_CALL_ALL		(NOTIFY_MASK_CALL_STARTED | NOTIFY_MASK_CALL_FINISHED | \
					 NOTIFY_MASK_CALL_DISCARDED)
#define NOTIFY_MASK_ALL			(NOTIFY_MASK_STREAM_ALL | NOTIFY_MASK_CALL_ALL)
#define NOTIFY_MASK_DEFAULT		NOTIFY_MASK_FINISHED

bool notify_events_parse(const char *csv, unsigned int *mask_out, char **err_token);
const char *notify_event_name(enum notify_event event);
const char *notify_event_status(enum notify_event event);
bool notify_event_enabled(enum notify_event event);

/* Terminal = finished/discarded/failed and call terminal counterparts. */
bool notify_event_is_terminal(enum notify_event event);

/* notify-command-format tokens (pure parse; no transport deps). */
enum notify_command_format {
	NOTIFY_CMD_LEGACY = 0,
	NOTIFY_CMD_EXTENDED,
	NOTIFY_CMD_JSON_ENV,
};
bool notify_command_format_parse(const char *s, enum notify_command_format *out);

/* Defined by main.c in daemon; unit tests provide their own. */
extern unsigned int notify_events_mask;

#endif
