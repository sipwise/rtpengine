#ifndef _NOTIFY_H_
#define _NOTIFY_H_

#include <glib.h>
#include "types.h"

void notify_setup(void);
void notify_cleanup(void);

void notify_push_output(output_t *, metafile_t *, tag_t *);
void notify_push_call(metafile_t *);

#endif
