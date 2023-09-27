#ifndef __COMPAT_H__
#define __COMPAT_H__

#if __DEBUG
# define INLINE static inline
#else
# define INLINE static inline __attribute__((always_inline))
#endif

#if defined __has_attribute
# define HAS_ATTR(x) __has_attribute(x)
#else
# define HAS_ATTR(x) 0
#endif

#if HAS_ATTR(access)
# define ACCESS(...) __attribute__((access(__VA_ARGS__)))
#else
# define ACCESS(...)
#endif


#ifndef BENCODE_MALLOC
#define BENCODE_MALLOC malloc
#define BENCODE_FREE free
#endif

#include "str.h"

#endif
