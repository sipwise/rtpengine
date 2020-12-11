#ifndef XT_RTPPROXY_H
#define XT_RTPPROXY_H



#define NUM_PAYLOAD_TYPES 16



struct xt_rtpengine_info {
	unsigned int			id;
};

struct rtpengine_stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
	u_int64_t			delay_min;
	u_int64_t			delay_avg;
	u_int64_t			delay_max;
	u_int8_t            in_tos;
};
struct rtpengine_rtp_stats {
	u_int64_t			packets;
	u_int64_t			bytes;
};
struct rtpengine_ssrc_stats {
	struct rtpengine_rtp_stats	basic_stats;
	u_int32_t			timestamp;
	u_int32_t			ext_seq;
	u_int32_t			lost_bits; // sliding bitfield, [0] = ext_seq
	u_int32_t			total_lost;
	u_int32_t			transit;
	u_int32_t			jitter;
};

struct re_address {
	int				family;
	union {
		unsigned char		ipv6[16];
		u_int32_t		ipv4;

		unsigned char		u8[16];
		u_int16_t		u16[8];
		u_int32_t		u32[4];
	}				u;
	u_int16_t			port;
};

enum rtpengine_cipher {
	REC_INVALID	= 0,
	REC_NULL,
	REC_AES_CM_128,
	REC_AES_F8,
	REC_AES_CM_192,
	REC_AES_CM_256,

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
	unsigned int			session_key_len;
	unsigned char			mki[256]; /* XXX uses too much memory? */
	u_int64_t			last_index;
	unsigned int			auth_tag_len; /* in bytes */
	unsigned int			mki_len;
};


enum rtpengine_src_mismatch {
	MSM_IGNORE	= 0,	/* process packet as normal */
	MSM_DROP,		/* drop packet */
	MSM_PROPAGATE,		/* propagate to userspace daemon */
};

struct rtpengine_target_info {
	struct re_address		local;
	struct re_address		expected_src; /* for incoming packets */
	enum rtpengine_src_mismatch	src_mismatch;

	struct re_address		src_addr; /* for outgoing packets */
	struct re_address		dst_addr;

	struct re_address		mirror_addr;
	unsigned int			intercept_stream_idx;

	struct rtpengine_srtp		decrypt;
	struct rtpengine_srtp		encrypt;
        u_int32_t                       ssrc; // Expose the SSRC to userspace when we resync.
        u_int32_t                       ssrc_out; // Rewrite SSRC

	unsigned char			payload_types[NUM_PAYLOAD_TYPES]; /* must be sorted */
	u_int32_t			clock_rates[NUM_PAYLOAD_TYPES];
	unsigned int			num_payload_types;

	unsigned char			tos;
	int				rtcp_mux:1,
					dtls:1,
					stun:1,
					rtp:1,
					rtp_only:1,
					do_intercept:1,
					transcoding:1, // SSRC subst and RTP PT filtering
					non_forwarding:1, // empty src/dst addr
					rtp_stats:1; // requires SSRC and clock_rates to be set
};

struct rtpengine_call_info {
	unsigned int			call_idx;
	char				call_id[256];
};

struct rtpengine_stream_info {
	unsigned int			call_idx;
	unsigned int			stream_idx;
	unsigned int			max_packets;
	char				stream_name[256];
};

struct rtpengine_packet_info {
	unsigned int			call_idx;
	unsigned int			stream_idx;
};

struct rtpengine_stats_info {
	struct re_address		local;		// input
	u_int32_t			ssrc;		// output
	struct rtpengine_ssrc_stats	ssrc_stats;	// output
};

struct rtpengine_message {
	enum {
		REMG_NOOP = 1,

		/* target_info: */
		REMG_ADD,
		REMG_DEL,
		REMG_UPDATE,

		/* call_info: */
		REMG_ADD_CALL,
		REMG_DEL_CALL,

		/* stream_info: */
		REMG_ADD_STREAM,
		REMG_DEL_STREAM,

		/* packet_info: */
		REMG_PACKET,

		/* stats_info: */
		REMG_GET_STATS,
		REMG_GET_RESET_STATS,

		__REMG_LAST
	}				cmd;

	union {
		struct rtpengine_target_info	target;
		struct rtpengine_call_info	call;
		struct rtpengine_stream_info	stream;
		struct rtpengine_packet_info	packet;
		struct rtpengine_stats_info	stats;
	} u;

	unsigned char			data[];
};

struct rtpengine_list_entry {
	struct rtpengine_target_info	target;
	struct rtpengine_stats		stats;
	struct rtpengine_rtp_stats	rtp_stats[NUM_PAYLOAD_TYPES];
};


#endif
