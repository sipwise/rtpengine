#ifndef _LOG_H_
#define _LOG_H_

#include "loglib.h"
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define dbg(fmt, ...) ilog(LOG_DEBUG, "[%s:%i] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define __C_DBG(x...) ilog(LOG_DEBUG, x)

void __ilog(int prio, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

extern __thread const char *log_info_call, *log_info_stream;
extern __thread unsigned long log_info_ssrc;

#endif
