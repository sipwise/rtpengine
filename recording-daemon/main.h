#ifndef _MAIN_H_
#define _MAIN_H_


#include "auxlib.h"
#include "socket.h"
#include <sys/types.h>


enum output_storage_enum {
	OUTPUT_STORAGE_FILE = 0x1,
	OUTPUT_STORAGE_DB = 0x2,
	OUTPUT_STORAGE_BOTH = 0x3,
};
enum mix_method {
	MM_DIRECT = 0,
	MM_CHANNELS,
};

extern int ktable;
extern int num_threads;
extern enum output_storage_enum output_storage;
extern char *spool_dir;
extern char *output_dir;
extern int output_mixed;
extern enum mix_method mix_method;
extern int mix_num_inputs;
extern int output_single;
extern int output_enabled;
extern mode_t output_chmod;
extern mode_t output_chmod_dir;
extern uid_t output_chown;
extern gid_t output_chgrp;
extern char *output_pattern;
extern int decoding_enabled;
extern char *c_mysql_host,
      *c_mysql_user,
      *c_mysql_pass,
      *c_mysql_db;
extern int c_mysql_port;
extern char *forward_to;
extern endpoint_t tls_send_to_ep;
extern int tls_resample;
extern char *notify_uri;
extern int notify_post;
extern int notify_nverify;
extern int notify_threads;
extern int notify_retries;
extern int notify_record;

extern volatile int shutdown_flag;


extern struct rtpengine_common_config rtpe_common_config;


#endif
