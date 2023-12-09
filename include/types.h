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

struct ice_candidate;
TYPED_GQUEUE(candidate, struct ice_candidate)

struct ice_candidate_pair;
TYPED_GQUEUE(candidate_pair, struct ice_candidate_pair)

struct codec_handler;
TYPED_GHASHTABLE_PROTO(codec_handlers_ht, struct codec_handler, struct codec_handler)
TYPED_GQUEUE(codec_handlers, struct codec_handler)

struct codec_packet;
TYPED_GQUEUE(codec_packet, struct codec_packet)

#endif
