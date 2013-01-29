#ifndef __LOG_H__
#define __LOG_H__


#include <syslog.h>


#define mylog(x,y...) syslog(x,y)
#define LOG_ERROR LOG_ERR
#define LOG_WARN LOG_WARNING



#endif
