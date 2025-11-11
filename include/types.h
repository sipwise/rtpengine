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

struct call_monologue;
struct call_media;

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

typedef void sdp_monologue_attr_print_f(GString *, struct call_monologue *, const sdp_ng_flags *flags);
typedef void sdp_media_attr_print_f(GString *, struct call_media *, struct call_media *, const sdp_ng_flags *flags);

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
#include "iqueue.h"

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
TYPED_GHASHTABLE_PROTO(codec_handlers_ht, struct codec_handler_index, struct codec_handler)
TYPED_GQUEUE(codec_handlers, struct codec_handler)

struct transcode_config;
struct codec_pipeline_index;
TYPED_GHASHTABLE_PROTO(transcode_config_ht, struct codec_pipeline_index, struct transcode_config)
TYPED_GQUEUE(transcode_config, struct transcode_config)

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

struct ng_codec;
TYPED_GQUEUE(ng_codecs, struct ng_codec)

struct ng_media;
TYPED_GQUEUE(ng_medias, struct ng_media)


#endif
