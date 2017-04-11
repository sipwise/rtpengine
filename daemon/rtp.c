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




INLINE int check_session_keys(struct crypto_context *c) {
	str s;
	const char *err;

	if (G_LIKELY(c->have_session_key))
		return 0;
	err = "SRTP output wanted, but no crypto suite was negotiated";
	if (!c->params.crypto_suite)
		goto error;

	err = "Failed to generate SRTP session keys";
	str_init_len_assert(&s, c->session_key, c->params.crypto_suite->session_key_len);
	if (crypto_gen_session_key(c, &s, 0x00, 6))
		goto error;
	str_init_len_assert(&s, c->session_auth_key, c->params.crypto_suite->srtp_auth_key_len);
	if (crypto_gen_session_key(c, &s, 0x01, 6))
		goto error;
	str_init_len_assert(&s, c->session_salt, c->params.crypto_suite->session_salt_len);
	if (crypto_gen_session_key(c, &s, 0x02, 6))
		goto error;

	c->have_session_key = 1;
	crypto_init_session_key(c);

	return 0;

error:
	ilog(LOG_ERROR | LOG_FLAG_LIMIT, "%s", err);
	return -1;
}

static u_int64_t packet_index(struct ssrc_ctx *ssrc_ctx, struct rtp_header *rtp) {
	u_int16_t seq;

	seq = ntohs(rtp->seq_num);
	/* rfc 3711 section 3.3.1 */
	if (G_UNLIKELY(!ssrc_ctx->srtp_index))
		ssrc_ctx->srtp_index = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	u_int16_t s_l = (ssrc_ctx->srtp_index & 0x00000000ffffULL);
	u_int32_t roc = (ssrc_ctx->srtp_index & 0xffffffff0000ULL) >> 16;
	u_int32_t v = 0;

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

	ssrc_ctx->srtp_index = (u_int64_t)(((v << 16) | seq) & 0xffffffffffffULL);
	return ssrc_ctx->srtp_index;
}

void rtp_append_mki(str *s, struct crypto_context *c) {
	char *p;

	if (!c->params.mki_len)
		return;

	/* RTP_BUFFER_TAIL_ROOM guarantees enough room */
	p = s->s + s->len;
	memcpy(p, c->params.mki, c->params.mki_len);
	s->len += c->params.mki_len;
}

/* rfc 3711, section 3.3 */
int rtp_avp2savp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtp_header *rtp;
	str payload, to_auth;
	u_int64_t index;
	int ret = 0;

	if (G_UNLIKELY(!ssrc_ctx))
		return -1;
	if (rtp_payload(&rtp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	index = packet_index(ssrc_ctx, rtp);

	/* rfc 3711 section 3.1 */
	if (!c->params.session_params.unencrypted_srtp && crypto_encrypt_rtp(c, rtp, &payload, index))
		return -1;

	to_auth = *s;

	rtp_append_mki(s, c);

	if (!c->params.session_params.unauthenticated_srtp && c->params.crypto_suite->srtp_auth_tag) {
		c->params.crypto_suite->hash_rtp(c, s->s + s->len, &to_auth, index);
		s->len += c->params.crypto_suite->srtp_auth_tag;
	}

	return ret;
}

/* rfc 3711, section 3.3 */
int rtp_savp2avp(str *s, struct crypto_context *c, struct ssrc_ctx *ssrc_ctx) {
	struct rtp_header *rtp;
	u_int64_t index;
	str payload, to_auth, to_decrypt, auth_tag;
	char hmac[20];
	int ret = 0;

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

	if (!auth_tag.len)
		goto decrypt;

	/* authenticate */
	assert(sizeof(hmac) >= auth_tag.len);
	c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);
	if (!str_memcmp(&auth_tag, hmac))
		goto decrypt;
	/* possible ROC mismatch, attempt to guess */
	/* first, let's see if we missed a rollover */
	index += 0x10000;
	c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);
	if (!str_memcmp(&auth_tag, hmac))
		goto decrypt_idx;
	/* or maybe we did a rollover too many */
	if (index >= 0x20000) {
		index -= 0x20000;
		c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);
		if (!str_memcmp(&auth_tag, hmac))
			goto decrypt_idx;
	}
	/* last guess: reset ROC to zero */
	index &= 0xffff;
	c->params.crypto_suite->hash_rtp(c, hmac, &to_auth, index);
	if (!str_memcmp(&auth_tag, hmac))
		goto decrypt_idx;
	goto error;

decrypt_idx:
	ssrc_ctx->srtp_index = index;
decrypt:
	if (!c->params.session_params.unencrypted_srtp && crypto_decrypt_rtp(c, rtp, &to_decrypt, index))
		return -1;

	*s = to_auth;

	return ret;

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

		str_init_len(auth_tag, to_decrypt->s + to_decrypt->len - auth_len, auth_len);
		to_decrypt->len -= auth_len;
		to_auth->len -= auth_len;
	}

	if (mki)
		*mki = STR_NULL;
	if (mki_len) {
		if (to_decrypt->len < mki_len)
			goto error;

		if (mki)
			str_init_len(mki, to_decrypt->s - mki_len, mki_len);
		to_decrypt->len -= mki_len;
		to_auth->len -= mki_len;
	}

	return 0;

error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Invalid SRTP/SRTCP packet received (short packet)");
	return -1;
}

const struct rtp_payload_type *rtp_payload_type(unsigned int type, GHashTable *lookup) {
	const struct rtp_payload_type *rtp_pt;

	if (!lookup)
		return rtp_get_rfc_payload_type(type);

	rtp_pt = g_hash_table_lookup(lookup, &type);
	if (rtp_pt)
		return rtp_pt;

	return rtp_get_rfc_payload_type(type);
}
