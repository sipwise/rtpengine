#ifndef CDR_H_
#define CDR_H_

#include "helpers.h"
#include "types.h"

enum tag_type;
enum ng_opmode;

const char *get_tag_type_text(enum tag_type t);
const char *get_opmode_text(enum ng_opmode);
void cdr_update_entry(call_t * c);

#endif /* CDR_H_ */
