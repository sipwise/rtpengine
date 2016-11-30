#ifndef _LOG_H_
#define _LOG_H_

#include "loglib.h"
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define __ilog(...) __ilog_np(__VA_ARGS__)
#define dbg(fmt, ...) ilog(LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif
