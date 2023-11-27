#ifndef __TYPES__H__
#define __TYPES__H__

#include <glib.h>

typedef struct sdp_ng_flags sdp_ng_flags;
typedef struct stats_metric stats_metric;
typedef struct ng_buffer ng_buffer;

#include "containers.h"

struct sdp_session;
TYPED_GQUEUE(sdp_sessions, struct sdp_session)

struct stream_params;
TYPED_GQUEUE(sdp_streams, struct stream_params)

#endif
