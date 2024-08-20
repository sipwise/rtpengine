#ifndef __TYPES__H__
#define __TYPES__H__

#include <glib.h>
#include <json-glib/json-glib.h>
#include "socket.h"

typedef struct sdp_ng_flags sdp_ng_flags;
typedef struct stats_metric stats_metric;
typedef struct ng_buffer ng_buffer;
typedef struct call call_t;
typedef struct stream_fd stream_fd;
typedef struct rtp_payload_type rtp_payload_type;
typedef struct sdp_origin sdp_origin;

struct network_address {
	str network_type;
	str address_type;
	str address;
	sockaddr_t parsed;
};

struct sdp_origin {
	str username;
	str session_id;
	str version_str;
	struct network_address address;
	unsigned long long version_num;
	size_t version_output_pos;
	unsigned int parsed:1;
};
typedef struct sdp_origin sdp_origin;

union sdp_attr_print_arg {
	struct call_media *cm;
	struct call_monologue *ml;
} __attribute__ ((__transparent_union__));
typedef void sdp_attr_print_f(GString *, union sdp_attr_print_arg, const sdp_ng_flags *flags);

typedef struct ng_parser ng_parser_t;
typedef struct ng_parser_ctx ng_parser_ctx_t;
typedef struct ng_command_ctx ng_command_ctx_t;

typedef struct bencode_item bencode_item_t;

typedef struct {
	str cur;
	str remainder;
} rtpp_pos;

typedef union {
	bencode_item_t *benc;
	JsonNode *json;
	rtpp_pos *rtpp;
	void *gen;
} parser_arg  __attribute__ ((__transparent_union__));

#include "containers.h"

struct sdp_session;
TYPED_GQUEUE(sdp_sessions, struct sdp_session)

struct stream_params;
TYPED_GQUEUE(sdp_streams, struct stream_params)

struct ice_candidate;
TYPED_GQUEUE(candidate, struct ice_candidate)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(candidate_q, candidate_q_clear)

struct ice_candidate_pair;
TYPED_GQUEUE(candidate_pair, struct ice_candidate_pair)

struct codec_handler;
TYPED_GHASHTABLE_PROTO(codec_handlers_ht, struct codec_handler, struct codec_handler)
TYPED_GQUEUE(codec_handlers, struct codec_handler)

struct codec_packet;
TYPED_GQUEUE(codec_packet, struct codec_packet)

struct packet_stream;
TYPED_GQUEUE(packet_stream, struct packet_stream)

struct sink_handler;
TYPED_GQUEUE(sink_handler, struct sink_handler)

struct dtmf_event;
TYPED_GQUEUE(dtmf_event, struct dtmf_event)

struct codec_stats;
TYPED_GHASHTABLE_PROTO(codec_stats_ht, char, struct codec_stats)

TYPED_GQUEUE(call, call_t)

struct sdp_attr;
TYPED_GQUEUE(sdp_attr, struct sdp_attr)

struct intf_config;
TYPED_GQUEUE(intf_config, struct intf_config)

#endif
