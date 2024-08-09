#ifndef _CONTROL_NG_FLAGS_PARSER_H_
#define _CONTROL_NG_FLAGS_PARSER_H_

#include <string.h>

#include "bencode.h"
#include "obj.h"
#include "str.h"
#include "call.h"
#include "call_interfaces.h"

/**
 * Parse flags in raw format and return bencode.
 * Syntax:
 * rtpp_flags: flag1=<value>, flag2-<value> ...
 */
void parse_rtpp_flags(const str * rtpp_flags, sdp_ng_flags *);

#endif
