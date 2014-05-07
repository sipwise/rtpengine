#ifndef XT_RTPPROXY_H
#define XT_RTPPROXY_H

struct xt_mediaproxy_info {
	u_int32_t			id;
};

struct mediaproxy_stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
};

struct mp_address {
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

enum mediaproxy_cipher {
	MPC_INVALID	= 0,
	MPC_NULL,
	MPC_AES_CM,
	MPC_AES_F8,

	__MPC_LAST
};

enum mediaproxy_hmac {
	MPH_INVALID	= 0,
	MPH_NULL,
	MPH_HMAC_SHA1,

	__MPH_LAST
};


struct mediaproxy_srtp {
	enum mediaproxy_cipher		cipher;
	enum mediaproxy_hmac		hmac;
	unsigned char			master_key[16];
	unsigned char			master_salt[14];
	unsigned char			mki[256]; /* XXX uses too much memory? */
	u_int64_t			last_index;
	unsigned int			auth_tag_len; /* in bytes */
	unsigned int			mki_len;
};


enum mediaproxy_src_mismatch {
	MSM_IGNORE	= 0,	/* process packet as normal */
	MSM_DROP,		/* drop packet */
	MSM_PROPAGATE,		/* propagate to userspace daemon */
};

struct mediaproxy_target_info {
	u_int16_t			target_port;
	struct mp_address		expected_src; /* for incoming packets */
	enum mediaproxy_src_mismatch	src_mismatch;

	struct mp_address		src_addr; /* for outgoing packets */
	struct mp_address		dst_addr;

	struct mp_address		mirror_addr;

	struct mediaproxy_srtp		decrypt;
	struct mediaproxy_srtp		encrypt;

	unsigned char			tos;
	int				rtcp_mux:1,
					dtls:1,
					stun:1,
					rtp_only:1;
};

struct mediaproxy_message {
	enum {
		MMG_NOOP = 1,
		MMG_ADD,
		MMG_DEL,
		MMG_UPDATE,
	}				cmd;

	struct mediaproxy_target_info	target;
};

struct mediaproxy_list_entry {
	struct mediaproxy_target_info	target;
	struct mediaproxy_stats		stats;
};


#endif
