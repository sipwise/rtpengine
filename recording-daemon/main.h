#ifndef _MAIN_H_
#define _MAIN_H_


#include "auxlib.h"


extern int ktable;
extern int num_threads;
extern const char *output_storage;
extern const char *spool_dir;
extern const char *output_dir;
extern int output_mixed;
extern int output_single;
extern int output_enabled;
extern const char *c_mysql_host,
      *c_mysql_user,
      *c_mysql_pass,
      *c_mysql_db;
extern int c_mysql_port;
extern const char *forward_to;

extern volatile int shutdown_flag;


extern struct rtpengine_common_config rtpe_common_config;


#endif
