#ifndef _RTP_H_
#define _RTP_H_



#include "str.h"
#include <glib.h>



struct crypto_context;
struct rtp_header;
struct ssrc_hash;
enum ssrc_dir;
struct ssrc_ctx;
struct codec_store;





const struct rtp_payload_type *rtp_payload_type(unsigned int, struct codec_store *);

int rtp_avp2savp(str *, struct crypto_context *, struct ssrc_ctx *);
int rtp_savp2avp(str *, struct crypto_context *, struct ssrc_ctx *);

void rtp_append_mki(str *s, struct crypto_context *c);
int srtp_payloads(str *to_auth, str *to_decrypt, str *auth_tag, str *mki,
		int auth_len, int mki_len,
		const str *packet, const str *payload);




#endif
