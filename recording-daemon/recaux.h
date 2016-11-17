#ifndef _RECAUX_H_
#define _RECAUX_H_

extern int __thread __sscanf_hack_var;

#define sscanf_match(str, format, ...) __sscanf_match(str, format "%n", ##__VA_ARGS__, &__sscanf_hack_var)
int __sscanf_match(const char *str, const char *fmt, ...) __attribute__ ((__format__ (__scanf__, 2, 3)));

#endif
