#ifndef __COMPAT_H__
#define __COMPAT_H__

#if __DEBUG
# define INLINE static inline
#else
# define INLINE static inline __attribute__((always_inline))
#endif


#ifndef BENCODE_MALLOC
#define BENCODE_MALLOC malloc
#define BENCODE_FREE free
#endif

#include "str.h"

#endif
