#ifndef _MAIN_H_
#define _MAIN_H_


extern int ktable;
extern int num_threads;
extern const char *spool_dir;
extern const char *output_dir;
extern int output_mixed;
extern int output_single;
extern const char *c_mysql_host,
      *c_mysql_user,
      *c_mysql_pass,
      *c_mysql_db;
extern int c_mysql_port;

extern volatile int shutdown_flag;


#endif
