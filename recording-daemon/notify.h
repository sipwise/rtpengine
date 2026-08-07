#ifndef _NOTIFY_H_
#define _NOTIFY_H_

#include <glib.h>
#include "types.h"
#include "notify_events.h"

void notify_setup(void);
void notify_cleanup(void);

void notify_push_setup(const notif_action_t *action, output_t *o, metafile_t *mf, tag_t *tag);
void notify_push_output(output_t *, metafile_t *, tag_t *);

void notify_push_output_event(enum notify_event event, output_t *o, metafile_t *mf,
	tag_t *tag, const char *error_code, const char *error_message);
void notify_push_call_event(enum notify_event event, metafile_t *mf);
void notify_push_call(metafile_t *mf);

#endif
