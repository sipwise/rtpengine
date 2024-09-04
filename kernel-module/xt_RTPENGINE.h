#ifndef XT_RTPPROXY_H
#define XT_RTPPROXY_H


#include "common_stats.h"


#define RTPE_NUM_PAYLOAD_TYPES 32
#define RTPE_MAX_FORWARD_DESTINATIONS 32
#define RTPE_NUM_SSRC_TRACKING 4



struct global_stats_counter;

struct xt_rtpengine_info {
	unsigned int			id;
};

struct re_address {
	int				family;
	union {
		unsigned char		ipv6[16];
		uint32_t		ipv4;

		unsigned char		u8[16];
		uint16_t		u16[8];
		uint32_t		u32[4];
	}				u;
	uint16_t			port;
};

enum rtpengine_cipher {
	REC_INVALID	= 0,
	REC_NULL,
	REC_AES_CM_128,
	REC_AES_F8,
	REC_AES_CM_192,
	REC_AES_CM_256,
	REC_AEAD_AES_GCM_128,
	REC_AEAD_AES_GCM_256,

	__REC_LAST
};

enum rtpengine_hmac {
	REH_INVALID	= 0,
	REH_NULL,
	REH_HMAC_SHA1,

	__REH_LAST
};


struct rtpengine_srtp {
	enum rtpengine_cipher		cipher;
	enum rtpengine_hmac		hmac;
	unsigned char			master_key[32];
	unsigned int			master_key_len;
	unsigned char			master_salt[14];
	unsigned int			master_salt_len;
	unsigned int			session_key_len;
	unsigned int			session_salt_len;
	unsigned char			mki[256]; /* XXX uses too much memory? */
	unsigned int			rtp_auth_tag_len; /* in bytes */
	unsigned int			rtcp_auth_tag_len; /* in bytes */
	unsigned int			mki_len;
};


enum rtpengine_src_mismatch {
	MSM_IGNORE	= 0,	/* process packet as normal */
	MSM_DROP,		/* drop packet */
	MSM_PROPAGATE,		/* propagate to userspace daemon */
};

struct rtpengine_pt_output {
	unsigned int min_payload_len;
	char replace_pattern[16];
	unsigned char replace_pattern_len;
};

struct rtpengine_target_info {
	struct re_address		local;
	struct re_address		expected_src; /* for incoming packets */
	enum rtpengine_src_mismatch	src_mismatch;
	unsigned int			num_destinations; // total
	unsigned int			num_rtcp_destinations;
	unsigned int			intercept_stream_idx;

	struct rtpengine_srtp		decrypt;
	uint32_t			ssrc[RTPE_NUM_SSRC_TRACKING]; // Expose the SSRC to userspace when we resync.
	struct ssrc_stats		*ssrc_stats[RTPE_NUM_SSRC_TRACKING];

	struct rtp_stats		*pt_stats[RTPE_NUM_PAYLOAD_TYPES]; // must be sorted by PT
	unsigned int			num_payload_types;

	struct interface_stats_block	*iface_stats; // for ingress stats
	struct stream_stats		*stats; // for ingress stats

	unsigned int			rtcp_mux:1,
					dtls:1,
					stun:1,
					rtp:1,
					ssrc_req:1,
					rtp_only:1,
					track_ssrc:1,
					rtcp:1,
					rtcp_fw:1,
					rtcp_fb_fw:1,
					do_intercept:1,
					pt_filter:1,
					non_forwarding:1, // empty src/dst addr
					blackhole:1,
					rtp_stats:1; // requires SSRC and clock_rates to be set
};

struct rtpengine_output_info {
	struct re_address		src_addr; /* for outgoing packets */
	struct re_address		dst_addr;

	struct rtpengine_srtp		encrypt;
	uint32_t			ssrc_out[RTPE_NUM_SSRC_TRACKING]; // Rewrite SSRC
	uint32_t			seq_offset[RTPE_NUM_SSRC_TRACKING]; // Rewrite output seq
	struct rtpengine_pt_output	pt_output[RTPE_NUM_PAYLOAD_TYPES]; // same indexes as pt_input

	struct interface_stats_block	*iface_stats; // for egress stats
	struct stream_stats		*stats; // for egress stats
	struct ssrc_stats		*ssrc_stats[RTPE_NUM_SSRC_TRACKING];

	unsigned char			tos;
	unsigned int			ssrc_subst:1;
};

struct rtpengine_destination_info {
	struct re_address		local;
	unsigned int			num;
	struct rtpengine_output_info	output;
};

struct rtpengine_call_info {
	unsigned int			call_idx;
	char				call_id[256];
};

struct rtpengine_stream_idx_info {
	unsigned int			call_idx;
	unsigned int			stream_idx;
};

struct rtpengine_stream_info {
	struct rtpengine_stream_idx_info idx;
	unsigned int			max_packets;
	char				stream_name[256];
};

struct rtpengine_packet_info {
	unsigned int			call_idx;
	unsigned int			stream_idx;
	unsigned char			data[];
};

enum rtpengine_command {
	REMG_INIT = 1,
	REMG_ADD_TARGET,
	REMG_ADD_DESTINATION,
	REMG_ADD_CALL,
	REMG_DEL_CALL,
	REMG_ADD_STREAM,
	REMG_DEL_STREAM,
	REMG_PACKET,
	REMG_DEL_TARGET,
	REMG_INIT_PLAY_STREAMS,
	REMG_GET_PACKET_STREAM,
	REMG_PLAY_STREAM_PACKET,
	REMG_PLAY_STREAM,
	REMG_STOP_STREAM,
	REMG_FREE_PACKET_STREAM,

	__REMG_LAST
};

struct rtpengine_init_info {
	int				last_cmd;
	size_t				msg_size[__REMG_LAST];
	struct global_stats_counter	*rtpe_stats;
};

struct rtpengine_command_init {
	enum rtpengine_command		cmd;
	struct rtpengine_init_info	init;
};

struct rtpengine_play_stream_info {
	struct re_address		src_addr;
	struct re_address		dst_addr;
	unsigned char			pt;
	uint32_t			ssrc;
	uint32_t			ts; // start TS
	uint16_t			seq; // start seq
	struct rtpengine_srtp		encrypt;
	unsigned int			packet_stream_idx;
	struct interface_stats_block	*iface_stats; // for egress stats
	struct stream_stats		*stats; // for egress stats
	struct ssrc_stats		*ssrc_stats;
	int				repeat;
	int				remove_at_end;
};

struct rtpengine_play_stream_packet_info {
	unsigned int			packet_stream_idx;
	unsigned long			delay_ms; // first packet = 0
	uint32_t			delay_ts; // first packet = 0
	uint32_t			duration_ts;
	unsigned char			data[];
};

struct rtpengine_command_add_target {
	enum rtpengine_command		cmd;
	struct rtpengine_target_info	target;
};

struct rtpengine_command_del_target {
	enum rtpengine_command		cmd;
	struct re_address		local;
};

struct rtpengine_command_destination {
	enum rtpengine_command		cmd;
	struct rtpengine_destination_info destination;
};

struct rtpengine_command_add_call {
	enum rtpengine_command		cmd;
	struct rtpengine_call_info	call;
};

struct rtpengine_command_del_call {
	enum rtpengine_command		cmd;
	unsigned int			call_idx;
};

struct rtpengine_command_add_stream {
	enum rtpengine_command		cmd;
	struct rtpengine_stream_info	stream;
};

struct rtpengine_command_del_stream {
	enum rtpengine_command		cmd;
	struct rtpengine_stream_idx_info stream;
};

struct rtpengine_command_packet {
	enum rtpengine_command		cmd;
	struct rtpengine_packet_info	packet;
};

struct rtpengine_command_init_play_streams {
	enum rtpengine_command		cmd;
	unsigned int			num_packet_streams;
	unsigned int			num_play_streams;
};

struct rtpengine_command_get_packet_stream {
	enum rtpengine_command		cmd;
	unsigned int			packet_stream_idx;	// output
};

struct rtpengine_command_play_stream_packet {
	enum rtpengine_command		cmd;
	struct rtpengine_play_stream_packet_info play_stream_packet;
};

struct rtpengine_command_play_stream {
	enum rtpengine_command		cmd;
	struct rtpengine_play_stream_info info;		// input
	unsigned int			play_idx;	// output
};

struct rtpengine_command_stop_stream {
	enum rtpengine_command		cmd;
	unsigned int			play_idx;
};

struct rtpengine_command_free_packet_stream {
	enum rtpengine_command		cmd;
	unsigned int			packet_stream_idx;
};


#endif
