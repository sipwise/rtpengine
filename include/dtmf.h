#ifndef _DTMF_H_
#define _DTMF_H_

#include "str.h"


struct media_packet;

int dtmf_event(struct media_packet *, str *, int);


#endif
