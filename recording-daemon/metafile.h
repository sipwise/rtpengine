#ifndef _METAFILE_H_
#define _METAFILE_H_

#include "types.h"
#include "decoder.h"

void metafile_setup(void);
void metafile_cleanup(void);

void metafile_change(char *name);
void metafile_delete(char *name);

int get_connection_uid(const metafile_t * mf, char * connectionUid, int len);
metafile_t *metafile_get_by_call_id(const char* call_id);

void metafile_traverse_decoders(metafile_t *mf, decoder_visitor_t visitor_fun, void* param);

#endif
