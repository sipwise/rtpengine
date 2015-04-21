#ifndef XT_RTPPROXY_H
#define XT_RTPPROXY_H



#define NUM_PAYLOAD_TYPES 16



struct xt_rtpengine_info {
	u_int32_t			id;
};

struct rtpengine_stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
	struct timespec     delay_min;
	struct timespec     delay_avg;
	struct timespec     delay_max;
	u_int8_t            in_tos;
};
struct rtpengine_rtp_stats {
	u_int64_t			packets;
	u_int64_t			bytes;
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
	REC_AES_CM,
	REC_AES_F8,

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
	unsigned char			master_key[16];
	unsigned char			master_salt[14];
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
	u_int16_t			target_port;
	struct re_address		expected_src; /* for incoming packets */
	enum rtpengine_src_mismatch	src_mismatch;

	struct re_address		src_addr; /* for outgoing packets */
	struct re_address		dst_addr;

	struct re_address		mirror_addr;

	struct rtpengine_srtp		decrypt;
	struct rtpengine_srtp		encrypt;

	unsigned char			payload_types[NUM_PAYLOAD_TYPES]; /* must be sorted */
	unsigned int			num_payload_types;

	unsigned char			tos;
	int				rtcp_mux:1,
					dtls:1,
					stun:1,
					rtp:1,
					rtp_only:1;
};

struct rtpengine_message {
	enum {
		MMG_NOOP = 1,
		MMG_ADD,
		MMG_DEL,
		MMG_UPDATE
	}				cmd;

	struct rtpengine_target_info	target;
};

struct rtpengine_list_entry {
	struct rtpengine_target_info	target;
	struct rtpengine_stats		stats;
	struct rtpengine_rtp_stats	rtp_stats[NUM_PAYLOAD_TYPES];
};


#endif
