#ifndef XT_RTPPROXY_H
#define XT_RTPPROXY_H



#define RTPE_NUM_PAYLOAD_TYPES 32
#define RTPE_MAX_FORWARD_DESTINATIONS 32
#define RTPE_NUM_SSRC_TRACKING 4



struct xt_rtpengine_info {
	unsigned int			id;
};

struct rtpengine_stats {
	uint64_t			packets;
	uint64_t			bytes;
	uint64_t			errors;
	uint64_t			delay_min;
	uint64_t			delay_avg;
	uint64_t			delay_max;
	uint8_t            		tos;
};
struct rtpengine_rtp_stats {
	uint64_t			packets;
	uint64_t			bytes;
};
struct rtpengine_ssrc_stats {
	struct rtpengine_rtp_stats	basic_stats;
	uint32_t			timestamp;
	uint32_t			ext_seq;
	uint32_t			lost_bits; // sliding bitfield, [0] = ext_seq
	uint32_t			total_lost;
	uint32_t			transit;
	uint32_t			jitter;
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
	uint64_t			last_rtp_index[RTPE_NUM_SSRC_TRACKING];
	uint64_t			last_rtcp_index[RTPE_NUM_SSRC_TRACKING];
	unsigned int			rtp_auth_tag_len; /* in bytes */
	unsigned int			rtcp_auth_tag_len; /* in bytes */
	unsigned int			mki_len;
};


enum rtpengine_src_mismatch {
	MSM_IGNORE	= 0,	/* process packet as normal */
	MSM_DROP,		/* drop packet */
	MSM_PROPAGATE,		/* propagate to userspace daemon */
};

struct rtpengine_pt_input {
	unsigned char pt_num;
	uint32_t clock_rate;
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

	struct rtpengine_pt_input	pt_input[RTPE_NUM_PAYLOAD_TYPES]; /* must be sorted */
	unsigned int			num_payload_types;

	unsigned int			rtcp_mux:1,
					dtls:1,
					stun:1,
					rtp:1,
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

struct rtpengine_stats_info {
	uint32_t			ssrc[RTPE_NUM_SSRC_TRACKING];
	struct rtpengine_ssrc_stats	ssrc_stats[RTPE_NUM_SSRC_TRACKING];
	uint64_t			last_rtcp_index[RTPE_MAX_FORWARD_DESTINATIONS][RTPE_NUM_SSRC_TRACKING];
};

enum rtpengine_command {
	REMG_NOOP = 1,
	REMG_ADD_TARGET,
	REMG_DEL_TARGET,
	REMG_ADD_DESTINATION,
	REMG_ADD_CALL,
	REMG_DEL_CALL,
	REMG_ADD_STREAM,
	REMG_DEL_STREAM,
	REMG_PACKET,
	REMG_GET_STATS,
	REMG_GET_RESET_STATS,
	REMG_DEL_TARGET_STATS,
	REMG_SEND_RTCP,

	__REMG_LAST
};

struct rtpengine_noop_info {
	int				last_cmd;
	size_t				msg_size[__REMG_LAST];
};

struct rtpengine_send_packet_info {
	struct re_address		local;
	unsigned int			destination_idx;
	struct re_address		src_addr;
	struct re_address		dst_addr;
	unsigned char			data[];
};

struct rtpengine_command_noop {
	enum rtpengine_command		cmd;
	struct rtpengine_noop_info	noop;
};

struct rtpengine_command_add_target {
	enum rtpengine_command		cmd;
	struct rtpengine_target_info	target;
};

struct rtpengine_command_del_target {
	enum rtpengine_command		cmd;
	struct re_address		local;
};

struct rtpengine_command_del_target_stats {
	enum rtpengine_command		cmd;
	struct re_address		local;		// input
	struct rtpengine_stats_info	stats;		// output
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

struct rtpengine_command_stats {
	enum rtpengine_command		cmd;
	struct re_address		local;		// input
	struct rtpengine_stats_info	stats;		// output
};

struct rtpengine_command_send_packet {
	enum rtpengine_command		cmd;
	struct rtpengine_send_packet_info send_packet;
};

struct rtpengine_list_entry {
	struct rtpengine_target_info	target;
	struct rtpengine_stats		stats_in;
	struct rtpengine_rtp_stats	rtp_stats[RTPE_NUM_PAYLOAD_TYPES]; // same index as pt_input
	struct rtpengine_output_info	outputs[RTPE_MAX_FORWARD_DESTINATIONS];
	struct rtpengine_stats		stats_out[RTPE_MAX_FORWARD_DESTINATIONS];
};


#endif
