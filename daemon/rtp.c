#include "rtp.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <glib.h>

#include "compat.h"
#include "str.h"
#include "crypto.h"
#include "log.h"




struct rtp_extension {
	u_int16_t undefined;
	u_int16_t length;
} __attribute__ ((packed));




#define RFC_TYPE(type, name, c_rate)					\
	[type] = {							\
		.payload_type		= type,				\
		.encoding		= STR_CONST_INIT(#name),	\
		.clock_rate		= c_rate,			\
	}

static const struct rtp_payload_type __rfc_types[] =
{
	RFC_TYPE(0, PCMU, 8000),
	RFC_TYPE(3, GSM, 8000),
	RFC_TYPE(4, G723, 8000),
	RFC_TYPE(5, DVI4, 8000),
	RFC_TYPE(6, DVI4, 16000),
	RFC_TYPE(7, LPC, 8000),
	RFC_TYPE(8, PCMA, 8000),
	RFC_TYPE(9, G722, 8000),
	RFC_TYPE(10, L16, 44100),
	RFC_TYPE(11, L16, 44100),
	RFC_TYPE(12, QCELP, 8000),
	RFC_TYPE(13, CN, 8000),
	RFC_TYPE(14, MPA, 90000),
	RFC_TYPE(15, G728, 8000),
	RFC_TYPE(16, DVI4, 11025),
	RFC_TYPE(17, DVI4, 22050),
	RFC_TYPE(18, G729, 8000),
	RFC_TYPE(25, CelB, 90000),
	RFC_TYPE(26, JPEG, 90000),
	RFC_TYPE(28, nv, 90000),
	RFC_TYPE(31, H261, 90000),
	RFC_TYPE(32, MPV, 90000),
	RFC_TYPE(33, MP2T, 90000),
	RFC_TYPE(34, H263, 90000),
};




INLINE int check_session_keys(struct crypto_context *c) {
	str s;
	const char *err;

	if (c->have_session_key)
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

int rtp_payload(struct rtp_header **out, str *p, const str *s) {
	struct rtp_header *rtp;
	struct rtp_extension *ext;
	const char *err;

	err = "short packet (header)";
	if (s->len < sizeof(*rtp))
		goto error;

	rtp = (void *) s->s;
	err = "invalid header version";
	if ((rtp->v_p_x_cc & 0xc0) != 0x80) /* version 2 */
		goto error;

	if (!p)
		goto done;

	*p = *s;
	/* fixed header */
	str_shift(p, sizeof(*rtp));
	/* csrc list */
	err = "short packet (CSRC list)";
	if (str_shift(p, (rtp->v_p_x_cc & 0xf) * 4))
		goto error;

	if ((rtp->v_p_x_cc & 0x10)) {
		/* extension */
		err = "short packet (extension header)";
		if (p->len < sizeof(*ext))
			goto error;
		ext = (void *) p->s;
		err = "short packet (header extensions)";
		if (str_shift(p, 4 + ntohs(ext->length) * 4))
			goto error;
	}

done:
	*out = rtp;

	return 0;

error:
	ilog(LOG_WARNING | LOG_FLAG_LIMIT, "Error parsing RTP header: %s", err);
	return -1;
}

static u_int64_t packet_index(struct crypto_context *c, struct rtp_header *rtp) {
	u_int16_t seq;

	seq = ntohs(rtp->seq_num);
	/* rfc 3711 section 3.3.1 */
	if (G_UNLIKELY(!c->last_index))
		c->last_index = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	u_int16_t s_l = (c->last_index & 0x00000000ffffULL);
	u_int32_t roc = (c->last_index & 0xffffffff0000ULL) >> 16;
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

	c->last_index = (u_int64_t)(((v << 16) | seq) & 0xffffffffffffULL);
	return c->last_index;
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
int rtp_avp2savp(str *s, struct crypto_context *c) {
	struct rtp_header *rtp;
	str payload, to_auth;
	u_int64_t index;
	struct rtp_ssrc_entry *cur_ssrc;
	int update_kernel = 0;

	if (rtp_payload(&rtp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	/* check last known SSRC */
	if (G_LIKELY(rtp->ssrc == c->ssrc))
		goto ssrc_ok;
	if (!c->ssrc) {
		c->ssrc = rtp->ssrc;
		update_kernel = 1;
		goto ssrc_ok;
	}

	/* SSRC mismatch. stash away last know info */
	ilog(LOG_DEBUG, "SSRC changed, updating SRTP crypto contexts");
	if (G_UNLIKELY(!c->ssrc_hash))
		c->ssrc_hash = create_ssrc_table();

	// Find the entry for the last SSRC.
	cur_ssrc = find_ssrc(c->ssrc, c->ssrc_hash);
	// If it doesn't exist, create a new entry.
	if (G_UNLIKELY(!cur_ssrc)) {
		cur_ssrc = create_ssrc_entry(c->ssrc, c->last_index);
		add_ssrc_entry(cur_ssrc, c->ssrc_hash);
	}
	else
		cur_ssrc->index = c->last_index;

	// New SSRC, set the crypto context.
	c->ssrc = rtp->ssrc;
	cur_ssrc = find_ssrc(rtp->ssrc, c->ssrc_hash);
	if (G_UNLIKELY(!cur_ssrc))
		c->last_index = 0;
	else
		c->last_index = cur_ssrc->index;

	update_kernel = 1;

ssrc_ok:
	index = packet_index(c, rtp);

	/* rfc 3711 section 3.1 */
	if (!c->params.session_params.unencrypted_srtp && crypto_encrypt_rtp(c, rtp, &payload, index))
		return -1;

	to_auth = *s;

	rtp_append_mki(s, c);

	if (!c->params.session_params.unauthenticated_srtp && c->params.crypto_suite->srtp_auth_tag) {
		c->params.crypto_suite->hash_rtp(c, s->s + s->len, &to_auth, index);
		s->len += c->params.crypto_suite->srtp_auth_tag;
	}

	return update_kernel ? 1 : 0;
}

/* rfc 3711, section 3.3 */
int rtp_savp2avp(str *s, struct crypto_context *c) {
	struct rtp_header *rtp;
	u_int64_t index;
	str payload, to_auth, to_decrypt, auth_tag;
	char hmac[20];

	if (rtp_payload(&rtp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	index = packet_index(c, rtp);
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
	c->last_index = index;
decrypt:
	if (!c->params.session_params.unencrypted_srtp && crypto_decrypt_rtp(c, rtp, &to_decrypt, index))
		return -1;

	*s = to_auth;

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
		goto rfc_types;

	rtp_pt = g_hash_table_lookup(lookup, &type);
	if (rtp_pt)
		return rtp_pt;

rfc_types:
	if (type >= G_N_ELEMENTS(__rfc_types))
		return NULL;
	rtp_pt = &__rfc_types[type];
	if (!rtp_pt->encoding.s)
		return NULL;
	return rtp_pt;

}
