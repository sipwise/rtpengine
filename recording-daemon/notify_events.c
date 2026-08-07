#include "notify_events.h"
#include <string.h>
#include <glib.h>

/*
 * Pure event helpers (no curl / thread pool).
 * Linked into the recording daemon and into unit tests.
 */

static const char *const event_names[NOTIFY_EVT_COUNT] = {
	[NOTIFY_EVT_FILE_OPENED]	= "recording_file_opened",
	[NOTIFY_EVT_STARTED]		= "recording_started",
	[NOTIFY_EVT_FINISHED]		= "recording_finished",
	[NOTIFY_EVT_DISCARDED]		= "recording_discarded",
	[NOTIFY_EVT_FAILED]		= "recording_failed",
	[NOTIFY_EVT_CALL_STARTED]	= "call_recording_started",
	[NOTIFY_EVT_CALL_FINISHED]	= "call_recording_finished",
	[NOTIFY_EVT_CALL_DISCARDED]	= "call_recording_discarded",
};

static const char *const event_statuses[NOTIFY_EVT_COUNT] = {
	[NOTIFY_EVT_FILE_OPENED]	= "opened",
	[NOTIFY_EVT_STARTED]		= "started",
	[NOTIFY_EVT_FINISHED]		= "finished",
	[NOTIFY_EVT_DISCARDED]		= "discarded",
	[NOTIFY_EVT_FAILED]		= "failed",
	[NOTIFY_EVT_CALL_STARTED]	= "call-started",
	[NOTIFY_EVT_CALL_FINISHED]	= "call-finished",
	[NOTIFY_EVT_CALL_DISCARDED]	= "call-discarded",
};

const char *notify_event_name(enum notify_event event) {
	if (event < 0 || event >= NOTIFY_EVT_COUNT)
		return "unknown";
	return event_names[event];
}

const char *notify_event_status(enum notify_event event) {
	if (event < 0 || event >= NOTIFY_EVT_COUNT)
		return "unknown";
	return event_statuses[event];
}

bool notify_event_enabled(enum notify_event event) {
	if (event < 0 || event >= NOTIFY_EVT_COUNT)
		return false;
	return (notify_events_mask & (1u << event)) != 0;
}

bool notify_events_parse(const char *csv, unsigned int *mask_out, char **err_token) {
	unsigned int mask = 0;

	if (err_token)
		*err_token = NULL;

	if (!csv || !csv[0]) {
		*mask_out = NOTIFY_MASK_DEFAULT;
		return true;
	}

	g_autofree char *dup = g_strdup(csv);
	char *save = NULL;
	for (char *tok = strtok_r(dup, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save)) {
		if (!strcmp(tok, "opened"))
			mask |= NOTIFY_MASK_OPENED;
		else if (!strcmp(tok, "started"))
			mask |= NOTIFY_MASK_STARTED;
		else if (!strcmp(tok, "finished"))
			mask |= NOTIFY_MASK_FINISHED;
		else if (!strcmp(tok, "discarded"))
			mask |= NOTIFY_MASK_DISCARDED;
		else if (!strcmp(tok, "failed"))
			mask |= NOTIFY_MASK_FAILED;
		else if (!strcmp(tok, "call-started"))
			mask |= NOTIFY_MASK_CALL_STARTED;
		else if (!strcmp(tok, "call-finished"))
			mask |= NOTIFY_MASK_CALL_FINISHED;
		else if (!strcmp(tok, "call-discarded"))
			mask |= NOTIFY_MASK_CALL_DISCARDED;
		else if (!strcmp(tok, "all"))
			mask |= NOTIFY_MASK_ALL;
		else {
			if (err_token)
				*err_token = g_strdup(tok);
			return false;
		}
	}

	if (mask == 0)
		mask = NOTIFY_MASK_DEFAULT;

	*mask_out = mask;
	return true;
}

bool notify_event_is_terminal(enum notify_event event) {
	return event == NOTIFY_EVT_FINISHED
		|| event == NOTIFY_EVT_DISCARDED
		|| event == NOTIFY_EVT_FAILED
		|| event == NOTIFY_EVT_CALL_FINISHED
		|| event == NOTIFY_EVT_CALL_DISCARDED;
}

bool notify_command_format_parse(const char *s, enum notify_command_format *out) {
	if (!out)
		return false;
	if (!s || !s[0] || !strcmp(s, "legacy")) {
		*out = NOTIFY_CMD_LEGACY;
		return true;
	}
	if (!strcmp(s, "extended")) {
		*out = NOTIFY_CMD_EXTENDED;
		return true;
	}
	if (!strcmp(s, "json-env")) {
		*out = NOTIFY_CMD_JSON_ENV;
		return true;
	}
	return false;
}
