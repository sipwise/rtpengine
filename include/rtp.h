#ifndef _RTP_H_
#define _RTP_H_

#include <glib.h>

#include "str.h"
#include "types.h"

struct crypto_context;
struct rtp_header;
struct ssrc_hash;
enum ssrc_dir;
struct ssrc_ctx;
struct codec_store;

typedef GString crypto_debug_string;

const rtp_payload_type *get_rtp_payload_type(unsigned int, struct codec_store *);

int rtp_avp2savp(str *, struct crypto_context *, struct ssrc_ctx *);
int rtp_savp2avp(str *, struct crypto_context *, struct ssrc_ctx *);

int rtp_update_index(str *, struct packet_stream *, struct ssrc_ctx *);

void rtp_append_mki(str *s, struct crypto_context *c, crypto_debug_string *);
int srtp_payloads(str *to_auth, str *to_decrypt, str *auth_tag, str *mki,
		int auth_len, int mki_len,
		const str *packet, const str *payload);

#endif
