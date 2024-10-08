#include "rtp.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <glib.h>

#include "compat.h"
#include "str.h"
#include "crypto.h"
#include "log.h"
#include "rtplib.h"
#include "ssrc.h"
#include "call.h"

INLINE int check_session_keys(struct crypto_context *c) {
	str s;
	const char *err;

	if (G_LIKELY(c->have_session_key))
		return 0;
	err = "SRTP output wanted, but no crypto suite was negotiated";
	if (!c->params.crypto_suite)
		goto error;

	err = "Failed to generate SRTP session keys";
	s = STR_LEN_ASSERT(c->session_key, c->params.crypto_suite->session_key_len);
	if (crypto_gen_session_key(c, &s, 0x00, 6))
		goto error;
	s = STR_LEN_ASSERT(c->session_auth_key, c->params.crypto_suite->srtp_auth_key_len);
	if (crypto_gen_session_key(c, &s, 0x01, 6))
		goto error;
	s = STR_LEN_ASSERT(c->session_salt, c->params.crypto_suite->session_salt_len);
	if (crypto_gen_session_key(c, &s, 0x02, 6))
		goto error;

	c->have_session_key = 1;
	crypto_init_session_key(c);

	return 0;

error:
	ilogs(srtp, LOG_ERROR | LOG_FLAG_LIMIT, "%s", err);
	return -1;
}

static unsigned int packet_index(struct ssrc_ctx *ssrc_ctx, struct rtp_header *rtp) {
	uint16_t seq;

	seq = ntohs(rtp->seq_num);

	crypto_debug_init((seq & 0x1ff) == (ssrc_ctx->parent->h.ssrc & 0x1ff));
	crypto_debug_printf("SSRC %" PRIx32 ", seq %" PRIu16, ssrc_ctx->parent->h.ssrc, seq);

	/* rfc 3711 section 3.3.1 */
	unsigned int srtp_index = atomic_get_na(&ssrc_ctx->stats->ext_seq);
	if (G_UNLIKELY(!srtp_index))
		atomic_set_na(&ssrc_ctx->stats->ext_seq, srtp_index = seq);

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	uint16_t s_l = (srtp_index & 0x00000000ffffULL);
	uint32_t roc = (srtp_index & 0xffffffff0000ULL) >> 16;
	uint32_t v = 0;

	crypto_debug_printf(", prev seq %u, s_l %" PRIu16 ", ROC %" PRIu32,
			srtp_index, s_l, roc);

	if (s_l < 0x8000) {
		if (((seq - s_l) > 0x8000) && roc > 0)
			v = (roc - 1) % 0x10000;
		else
			v = roc;
	} else {
		if ((s_l - 0x8000) > seq)
			v = (roc + 1) % 0x10000;
		else
			v = roc;
	}

	srtp_index = (uint64_t)(((v << 16) | seq) & 0xffffffffffffULL);
	atomic_set_na(&ssrc_ctx->stats->ext_seq, srtp_index);

	crypto_debug_printf(", v %" PRIu32 ", ext seq %u", v, srtp_index);

	return srtp_index;
}

void rtp_append_mki(str *s, struct crypto_context *c) {
	char *p;

	if (!c->params.mki_len)
		return;

	/* RTP_BUFFER_TAIL_ROOM guarantees enough room */
	p = s->s + s->len;
	memcpy(p, c->params.mki, c->params.mki_len);
	s->len += c->params.mki_len;

	crypto_debug_printf(", MKI: ");
	crypto_debug_dump_raw(p, c->params.mki_len);
}

/* rfc 3711, section 3.3 */
int rtp_avp2savp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtp_header *rtp;
	str payload, to_auth;
	unsigned int index;

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
	if (rtp_payload(&rtp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	index = packet_index(ssrc_ctx, rtp);

	crypto_debug_printf(", plain pl: ");
	crypto_debug_dump(&payload);

	/* rfc 3711 section 3.1 */
	int prev_len = payload.len;
	if (!c->params.session_params.unencrypted_srtp && crypto_encrypt_rtp(c, rtp, &payload, index))
		return -1;
	s->len += payload.len - prev_len;

	crypto_debug_printf(", enc pl: ");
	crypto_debug_dump(&payload);

	to_auth = *s;

	rtp_append_mki(s, c);

	if (!c->params.session_params.unauthenticated_srtp && c->params.crypto_suite->srtp_auth_tag) {
		c->params.crypto_suite->hash_rtp(c, s->s + s->len, &to_auth, index);
		crypto_debug_printf(", auth: ");
		crypto_debug_dump_raw(s->s + s->len, c->params.crypto_suite->srtp_auth_tag);
		s->len += c->params.crypto_suite->srtp_auth_tag;
	}

	crypto_debug_finish();

	return 0;
}

/* rfc 3711, section 3.3 */
int rtp_savp2avp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtp_header *rtp;
	unsigned int index;
	str payload, to_auth, to_decrypt, auth_tag;
	char hmac[20];

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
	if (rtp_payload(&rtp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	index = packet_index(ssrc_ctx, rtp);
	if (srtp_payloads(&to_auth, &to_decrypt, &auth_tag, NULL,
			c->params.session_params.unauthenticated_srtp ? 0 : c->params.crypto_suite->srtp_auth_tag,
			c->params.mki_len,
			s, &payload))
		return -1;

	crypto_debug_printf(", enc pl: ");
	crypto_debug_dump(&to_decrypt);

	if (!auth_tag.len)
		goto decrypt;

	/* authenticate */
	assert(sizeof(hmac) >= auth_tag.len);
	c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);

	crypto_debug_printf(", rcv hmac: ");
	crypto_debug_dump(&auth_tag);
	crypto_debug_printf(", calc hmac: ");
	crypto_debug_dump_raw(hmac, auth_tag.len);

	if (!str_memcmp(&auth_tag, hmac))
		goto decrypt;
	/* possible ROC mismatch, attempt to guess */
	/* first, let's see if we missed a rollover */
	index += 0x10000;
	c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);

	crypto_debug_printf(", calc hmac 2: ");
	crypto_debug_dump_raw(hmac, auth_tag.len);

	if (!str_memcmp(&auth_tag, hmac))
		goto decrypt_idx;
	/* or maybe we did a rollover too many */
	if (index >= 0x20000) {
		index -= 0x20000;
		c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);

		crypto_debug_printf(", calc hmac 3: ");
		crypto_debug_dump_raw(hmac, auth_tag.len);

		if (!str_memcmp(&auth_tag, hmac))
			goto decrypt_idx;
	}
	/* last guess: reset ROC to zero */
	index &= 0xffff;
	c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);

	crypto_debug_printf(", calc hmac 4: ");
	crypto_debug_dump_raw(hmac, auth_tag.len);

	if (!str_memcmp(&auth_tag, hmac))
		goto decrypt_idx;
	goto error;

decrypt_idx:
	ilog(LOG_DEBUG, "Detected unexpected SRTP ROC reset (from %u to %u)",
			atomic_get_na(&ssrc_ctx->stats->ext_seq), index);
	atomic_set_na(&ssrc_ctx->stats->ext_seq, index);
decrypt:;
	int prev_len = to_decrypt.len;
	if (c->params.session_params.unencrypted_srtp)
	{ } // nothing to do
	else {
		int ret;
		int guess = 0;
		while (true) {
			// make backup in case of failed decryption clobbers the buffer
			// XXX only needed for AEAD ciphers
			char backup[to_decrypt.len];
			memcpy(backup, to_decrypt.s, to_decrypt.len);

			ret = crypto_decrypt_rtp(c, rtp, &to_decrypt, index);
			if (ret != 1)
				break;
			// AEAD failed: try ROC guessing as above. restore backup buffer first
			memcpy(to_decrypt.s, backup, to_decrypt.len);
			if (guess == 0)
				index += 0x10000;
			else if (guess == 1)
				index -= 0x20000;
			else if (guess == 2)
				index &= 0xffff;
			else
				break;
			guess++;
		};
		if (ret) {
			ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Discarded SRTP packet: decryption failed");
			return -1;
		}
		if (guess != 0) {
			ilog(LOG_DEBUG, "Detected unexpected SRTP ROC reset (from %u to %u)",
					atomic_get_na(&ssrc_ctx->stats->ext_seq), index);
			atomic_set_na(&ssrc_ctx->stats->ext_seq, index);
		}
	}

	crypto_debug_printf(", dec pl: ");
	crypto_debug_dump(&to_decrypt);

	*s = to_auth;
	s->len -= prev_len - to_decrypt.len;

	crypto_debug_finish();

	return 0;

error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Discarded invalid SRTP packet: authentication failed");
	return -1;
}

/* rfc 3711 section 3.1 and 3.4 */
int srtp_payloads(str *to_auth, str *to_decrypt, str *auth_tag, str *mki,
		int auth_len, int mki_len,
		const str *packet, const str *payload)
{
	*to_auth = *packet;
	*to_decrypt = *payload;
	/* packet and payload should be identical except for the respective header */
	assert(to_auth->s + to_auth->len == to_decrypt->s + to_decrypt->len);
	assert(to_decrypt->s >= to_auth->s);

	*auth_tag = STR_NULL;
	if (auth_len) {
		if (to_decrypt->len < auth_len)
			goto error;

		*auth_tag = STR_LEN(to_decrypt->s + to_decrypt->len - auth_len, auth_len);
		to_decrypt->len -= auth_len;
		to_auth->len -= auth_len;
	}

	if (mki)
		*mki = STR_NULL;
	if (mki_len) {
		if (to_decrypt->len < mki_len)
			goto error;

		if (mki)
			*mki = STR_LEN(to_decrypt->s - mki_len, mki_len);
		to_decrypt->len -= mki_len;
		to_auth->len -= mki_len;
	}

	return 0;

error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Invalid SRTP/SRTCP packet received (short packet)");
	return -1;
}

const rtp_payload_type *get_rtp_payload_type(unsigned int type, struct codec_store *cs) {
	const rtp_payload_type *rtp_pt;

	if (!cs)
		return rtp_get_rfc_payload_type(type);

	rtp_pt = t_hash_table_lookup(cs->codecs, GINT_TO_POINTER(type));
	if (rtp_pt)
		return rtp_pt;

	return rtp_get_rfc_payload_type(type);
}
