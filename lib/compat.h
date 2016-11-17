#ifndef __COMPAT_H__
#define __COMPAT_H__

#if __DEBUG
# define INLINE static inline
#else
# define INLINE static inline __attribute__((always_inline))
#endif

#endif
