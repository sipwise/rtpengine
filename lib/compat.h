#ifndef __COMPAT_H__
#define __COMPAT_H__

#if __DEBUG
# define INLINE static inline
#else
# define INLINE static inline __attribute__((always_inline))
#endif

#define ACCESS(...)
#if defined __has_attribute
# if __has_attribute(access)
#  undef ACCESS
#  define ACCESS(...) __attribute__((access(__VA_ARGS__)))
# endif
#endif


#ifndef BENCODE_MALLOC
#define BENCODE_MALLOC malloc
#define BENCODE_FREE free
#endif

#include "str.h"

#endif
