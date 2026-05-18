#ifndef _LL_D_H_
#define _LL_D_H_

#include "ll_common.h"

#define ll(system, descr) log_level_index_ ## system,
enum {
__log_level_first_component = __log_level_last_common - 1,
#include "loglevels_p.inc"
__log_level_last
};
#undef ll

#endif
