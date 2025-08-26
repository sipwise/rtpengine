#ifndef _GCS_H_
#define _GCS_H_

#include "types.h"

void gcs_store(output_t *, metafile_t *);

bool gcs_init(void);
void gcs_shutdown(void);

#endif
