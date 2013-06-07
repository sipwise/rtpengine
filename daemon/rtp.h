#ifndef _RTP_H_
#define _RTP_H_



#include "str.h"



struct crypto_context;

int rtp_avp2savp(str *, struct crypto_context *);
int rtp_savp2avp(str *, struct crypto_context *);




#endif
