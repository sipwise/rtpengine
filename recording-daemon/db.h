#ifndef _DB_H_
#define _DB_H_

#include "types.h"


void db_do_call(metafile_t *);
void db_close_call(metafile_t *);
void db_do_stream(metafile_t *mf, output_t *op, const char *type, unsigned int id);
void db_close_stream(output_t *op);
void db_config_stream(output_t *op);


#endif
