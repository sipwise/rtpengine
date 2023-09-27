#ifndef __LOG_H__
#define __LOG_H__

#include "loglib.h"

void __ilog(int prio, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

GQueue *get_log_lines(uint num, uint end);

void log_clear(void);

#endif
