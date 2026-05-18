#ifndef _LL_COMMON_H_
#define _LL_COMMON_H_

#define ll(system, descr) log_level_index_ ## system,
enum {
#include "loglevels_common.inc"
__log_level_last_common
};
#undef ll

#endif
