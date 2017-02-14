#ifndef _MAIN_H_
#define _MAIN_H_


extern int ktable;
extern int num_threads;
extern const char *spool_dir;
extern const char *output_dir;
extern int output_mixed;
extern int output_single;
extern const char *mysql_host,
      *mysql_user,
      *mysql_pass,
      *mysql_db;

extern volatile int shutdown_flag;


#endif
