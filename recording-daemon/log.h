#ifndef _LOG_H_
#define _LOG_H_

#include "loglib.h"
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define die(fmt, ...) do { ilog(LOG_CRIT, "Fatal error: " fmt, ##__VA_ARGS__); exit(-1); } while (0)
#define die_errno(msg) die("%s: %s", msg, strerror(errno))
#define ilog(...) __ilog_np(__VA_ARGS__)
#define dbg(fmt, ...) ilog(LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif
