#ifndef __LOG_H__
#define __LOG_H__

#include "loglib.h"
#define __ilog(prio, fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#endif
