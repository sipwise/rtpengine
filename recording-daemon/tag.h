#ifndef _TAG_H_
#define _TAG_H_

#include "types.h"

void tag_name(metafile_t *mf, unsigned long t, const char *);
void tag_label(metafile_t *mf, unsigned long t, const char *);
void tag_free(tag_t *);

#endif
