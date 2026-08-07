#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

/* Unit tests for recording-daemon lifecycle notify event helpers. */
#include "../recording-daemon/notify_events.h"
#include "../recording-daemon/notify_events.c"

/* Provide the global used by notify_event_enabled(). */
unsigned int notify_events_mask = NOTIFY_MASK_DEFAULT;

#define err(fmt...) do { \
		fprintf(stderr, fmt); \
		exit(1); \
	} while (0)

static void expect_parse_ok(const char *csv, unsigned int expect) {
	unsigned int mask = 0;
	char *bad = NULL;
	if (!notify_events_parse(csv, &mask, &bad))
		err("parse failed for '%s' (bad token '%s')\n", csv ? csv : "(null)",
				bad ? bad : "?");
	if (mask != expect)
		err("parse '%s': mask 0x%x != expected 0x%x\n", csv ? csv : "(null)", mask, expect);
	g_free(bad);
}

static void expect_parse_fail(const char *csv, const char *expect_tok) {
	unsigned int mask = 0;
	char *bad = NULL;
	if (notify_events_parse(csv, &mask, &bad))
		err("parse should fail for '%s'\n", csv);
	if (expect_tok && (!bad || strcmp(bad, expect_tok) != 0))
		err("parse '%s': expected bad token '%s', got '%s'\n",
				csv, expect_tok, bad ? bad : "(null)");
	g_free(bad);
}

int main(void) {
	/* Default / empty => finished only */
	expect_parse_ok(NULL, NOTIFY_MASK_DEFAULT);
	expect_parse_ok("", NOTIFY_MASK_DEFAULT);
	expect_parse_ok("   ", NOTIFY_MASK_DEFAULT);
	expect_parse_ok("finished", NOTIFY_MASK_FINISHED);

	/* Single tokens */
	expect_parse_ok("opened", NOTIFY_MASK_OPENED);
	expect_parse_ok("started", NOTIFY_MASK_STARTED);
	expect_parse_ok("discarded", NOTIFY_MASK_DISCARDED);
	expect_parse_ok("failed", NOTIFY_MASK_FAILED);

	/* CSV combinations */
	expect_parse_ok("opened,started,finished",
			NOTIFY_MASK_OPENED | NOTIFY_MASK_STARTED | NOTIFY_MASK_FINISHED);
	expect_parse_ok("opened, started, finished, discarded, failed",
			NOTIFY_MASK_STREAM_ALL);
	expect_parse_ok("all", NOTIFY_MASK_ALL);

	/* Call-level tokens */
	expect_parse_ok("call-started,call-finished",
			NOTIFY_MASK_CALL_STARTED | NOTIFY_MASK_CALL_FINISHED);

	/* Unknown token */
	expect_parse_fail("opened,bogus,finished", "bogus");
	expect_parse_fail("nope", "nope");

	/* Name / status mapping */
	if (strcmp(notify_event_name(NOTIFY_EVT_FILE_OPENED), "recording_file_opened"))
		err("bad name for FILE_OPENED\n");
	if (strcmp(notify_event_name(NOTIFY_EVT_STARTED), "recording_started"))
		err("bad name for STARTED\n");
	if (strcmp(notify_event_name(NOTIFY_EVT_FINISHED), "recording_finished"))
		err("bad name for FINISHED\n");
	if (strcmp(notify_event_name(NOTIFY_EVT_DISCARDED), "recording_discarded"))
		err("bad name for DISCARDED\n");
	if (strcmp(notify_event_name(NOTIFY_EVT_FAILED), "recording_failed"))
		err("bad name for FAILED\n");
	if (strcmp(notify_event_status(NOTIFY_EVT_FILE_OPENED), "opened"))
		err("bad status for FILE_OPENED\n");
	if (strcmp(notify_event_status(NOTIFY_EVT_FINISHED), "finished"))
		err("bad status for FINISHED\n");
	if (strcmp(notify_event_name((enum notify_event) 99), "unknown"))
		err("bad name for invalid event\n");

	/* Enabled mask checks */
	notify_events_mask = NOTIFY_MASK_FINISHED;
	if (!notify_event_enabled(NOTIFY_EVT_FINISHED))
		err("finished should be enabled\n");
	if (notify_event_enabled(NOTIFY_EVT_FILE_OPENED))
		err("opened should be disabled under default mask\n");
	if (notify_event_enabled(NOTIFY_EVT_STARTED))
		err("started should be disabled under default mask\n");

	notify_events_mask = NOTIFY_MASK_OPENED | NOTIFY_MASK_STARTED | NOTIFY_MASK_FINISHED;
	if (!notify_event_enabled(NOTIFY_EVT_FILE_OPENED)
			|| !notify_event_enabled(NOTIFY_EVT_STARTED)
			|| !notify_event_enabled(NOTIFY_EVT_FINISHED))
		err("expected opened/started/finished enabled\n");
	if (notify_event_enabled(NOTIFY_EVT_DISCARDED))
		err("discarded should not be enabled\n");

	/* Call-level name/status mapping (Phase 2) */
	if (strcmp(notify_event_name(NOTIFY_EVT_CALL_STARTED), "call_recording_started"))
		err("bad name for CALL_STARTED\n");
	if (strcmp(notify_event_name(NOTIFY_EVT_CALL_FINISHED), "call_recording_finished"))
		err("bad name for CALL_FINISHED\n");
	if (strcmp(notify_event_name(NOTIFY_EVT_CALL_DISCARDED), "call_recording_discarded"))
		err("bad name for CALL_DISCARDED\n");
	if (strcmp(notify_event_status(NOTIFY_EVT_CALL_STARTED), "call-started"))
		err("bad status for CALL_STARTED\n");
	if (strcmp(notify_event_status(NOTIFY_EVT_CALL_FINISHED), "call-finished"))
		err("bad status for CALL_FINISHED\n");
	if (strcmp(notify_event_status(NOTIFY_EVT_CALL_DISCARDED), "call-discarded"))
		err("bad status for CALL_DISCARDED\n");

	/* Call-level enabled under all */
	notify_events_mask = NOTIFY_MASK_ALL;
	if (!notify_event_enabled(NOTIFY_EVT_CALL_STARTED)
			|| !notify_event_enabled(NOTIFY_EVT_CALL_FINISHED)
			|| !notify_event_enabled(NOTIFY_EVT_CALL_DISCARDED))
		err("call events should be enabled under all\n");

	/* call-discarded alone */
	expect_parse_ok("call-discarded", NOTIFY_MASK_CALL_DISCARDED);

	/* Terminal classification (Phase 3) */
	if (!notify_event_is_terminal(NOTIFY_EVT_FINISHED)
			|| !notify_event_is_terminal(NOTIFY_EVT_DISCARDED)
			|| !notify_event_is_terminal(NOTIFY_EVT_FAILED)
			|| !notify_event_is_terminal(NOTIFY_EVT_CALL_FINISHED)
			|| !notify_event_is_terminal(NOTIFY_EVT_CALL_DISCARDED))
		err("terminal events misclassified\n");
	if (notify_event_is_terminal(NOTIFY_EVT_FILE_OPENED)
			|| notify_event_is_terminal(NOTIFY_EVT_STARTED)
			|| notify_event_is_terminal(NOTIFY_EVT_CALL_STARTED))
		err("non-terminal events misclassified\n");

	/* Command format parse (Phase 2) */
	{
		enum notify_command_format fmt;
		if (!notify_command_format_parse(NULL, &fmt) || fmt != NOTIFY_CMD_LEGACY)
			err("null format should be legacy\n");
		if (!notify_command_format_parse("legacy", &fmt) || fmt != NOTIFY_CMD_LEGACY)
			err("legacy parse failed\n");
		if (!notify_command_format_parse("extended", &fmt) || fmt != NOTIFY_CMD_EXTENDED)
			err("extended parse failed\n");
		if (!notify_command_format_parse("json-env", &fmt) || fmt != NOTIFY_CMD_JSON_ENV)
			err("json-env parse failed\n");
		if (notify_command_format_parse("bogus", &fmt))
			err("bogus format should fail\n");
	}

	printf("ok\n");
	return 0;
}
