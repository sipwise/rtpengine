/*
 * cdr.h
 *
 *  Created on: Mar 14, 2017
 *      Author: fmetz
 */

#ifndef CDR_H_
#define CDR_H_

#include "aux.h"

struct call;
enum tag_type;
enum call_opmode;

const char *get_tag_type_text(enum tag_type t);
const char *get_opmode_text(enum call_opmode);
void cdr_update_entry(struct call* c);

#endif /* CDR_H_ */
