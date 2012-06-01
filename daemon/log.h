#ifndef __LOG_H__
#define __LOG_H__


#include <syslog.h>


#define mylog(x,y...) syslog(x,y)



#endif
