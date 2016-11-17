#ifndef _RTP_H_
#define _RTP_H_



#include "str.h"
#include <glib.h>



struct crypto_context;
struct rtp_header;

struct rtp_payload_type {
	unsigned int payload_type;
	str encoding_with_params;
	str encoding;
	unsigned int clock_rate;
	str encoding_parameters;
};





const struct rtp_payload_type *rtp_payload_type(unsigned int, GHashTable *);

int rtp_avp2savp(str *, struct crypto_context *);
int rtp_savp2avp(str *, struct crypto_context *);

void rtp_append_mki(str *s, struct crypto_context *c);
int srtp_payloads(str *to_auth, str *to_decrypt, str *auth_tag, str *mki,
		int auth_len, int mki_len,
		const str *packet, const str *payload);




#endif
