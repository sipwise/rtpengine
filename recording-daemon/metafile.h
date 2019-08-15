#ifndef _METAFILE_H_
#define _METAFILE_H_

#include "types.h"

void metafile_setup(void);
void metafile_cleanup(void);

void metafile_change(char *name);
void metafile_delete(char *name);

int get_connection_uid(const metafile_t * mf, char * connectionUid, int len);

#endif
