#ifndef __CODECLIB_H__
#define __CODECLIB_H__


#include "str.h"



struct codec_def_s {
	const char *rtpname;
	int clockrate_mult;
	int avcodec_id;
	const char *avcodec_name;
};
typedef struct codec_def_s codec_def_t;


const codec_def_t *codec_find(const str *name);


#endif
