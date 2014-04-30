#ifndef _CALL_INTERFACES_H_
#define _CALL_INTERFACES_H_



#include "str.h"
#include "bencode.h"



struct call;
struct call_stats;



void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output,
		struct call_stats *totals);


#endif
