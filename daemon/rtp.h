#ifndef _RTP_H_
#define _RTP_H_



#include "str.h"
#include <glib.h>



struct crypto_context;

struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	u_int16_t seq_num;
	u_int32_t timestamp;
	u_int32_t ssrc;
	u_int32_t csrc[];
} __attribute__ ((packed));

struct rtp_payload_type {
	unsigned int payload_type;
	str encoding;
	unsigned int clock_rate;
	str encoding_parameters;
};





int rtp_payload(struct rtp_header **out, str *p, const str *s);
const struct rtp_payload_type *rtp_payload_type(unsigned int, GHashTable *);

int rtp_avp2savp(str *, struct crypto_context *);
int rtp_savp2avp(str *, struct crypto_context *);

void rtp_append_mki(str *s, struct crypto_context *c);
int srtp_payloads(str *to_auth, str *to_decrypt, str *auth_tag, str *mki,
		int auth_len, int mki_len,
		const str *packet, const str *payload);




#endif
