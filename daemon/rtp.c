#include "rtp.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <glib.h>

#include "str.h"
#include "crypto.h"
#include "log.h"




static inline int check_session_keys(struct crypto_context *c) {
	str s;

	if (c->have_session_key)
		return 0;
	if (!c->crypto_suite)
		goto error;

	str_init_len(&s, c->session_key, c->crypto_suite->session_key_len / 8);
	if (crypto_gen_session_key(c, &s, 0x00, 6))
		goto error;
	str_init_len(&s, c->session_auth_key, c->crypto_suite->srtp_auth_key_len / 8);
	if (crypto_gen_session_key(c, &s, 0x01, 6))
		goto error;
	str_init_len(&s, c->session_salt, c->crypto_suite->session_salt_len / 8);
	if (crypto_gen_session_key(c, &s, 0x02, 6))
		goto error;

	c->have_session_key = 1;
	return 0;

error:
	mylog(LOG_WARNING, "Error generating SRTP session keys");
	return -1;
}

static int rtp_payload(struct rtp_header **out, str *p, const str *s) {
	struct rtp_header *rtp;
	struct rtp_extension *ext;

	if (s->len < sizeof(*rtp))
		goto error;

	rtp = (void *) s->s;
	if ((rtp->v_p_x_cc & 0xc0) != 0x80) /* version 2 */
		goto error;

	*p = *s;
	/* fixed header */
	str_shift(p, sizeof(*rtp));
	/* csrc list */
	if (str_shift(p, (rtp->v_p_x_cc & 0xf) * 4))
		goto error;

	if ((rtp->v_p_x_cc & 0x10)) {
		/* extension */
		if (p->len < sizeof(*ext))
			goto error;
		ext = (void *) p->s;
		if (str_shift(p, 4 + ntohs(ext->length) * 4))
			goto error;
	}

	*out = rtp;

	return 0;

error:
	mylog(LOG_WARNING, "Error parsing RTP header");
	return -1;
}

static u_int64_t packet_index(struct crypto_context *c, struct rtp_header *rtp) {
	u_int16_t seq;
	u_int64_t index;
	long long int diff;

	seq = ntohs(rtp->seq_num);
	/* rfc 3711 section 3.3.1 */
	if (G_UNLIKELY(!c->s_l))
		c->s_l = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	index = ((u_int64_t) c->roc << 16) | seq;
	diff = index - c->s_l;
	if (diff >= 0) {
		if (diff < 0x8000)
			c->s_l = index;
		else if (index >= 0x10000)
			index -= 0x10000;
	}
	else {
		if (diff >= -0x8000)
			;
		else {
			index += 0x10000;
			c->roc++;
			c->s_l = index;
		}
	}

	return index;
}

void rtp_append_mki(str *s, struct crypto_context *c) {
	u_int32_t mki_part;
	char *p;

	if (!c->mki_len)
		return;

	/* RTP_BUFFER_TAIL_ROOM guarantees enough room */
	p = s->s + s->len;
	memset(p, 0, c->mki_len);
	if (c->mki_len > 4) {
		mki_part = (c->mki & 0xffffffff00000000ULL) >> 32;
		mki_part = htonl(mki_part);
		if (c->mki_len < 8)
			memcpy(p, ((char *) &mki_part) + (8 - c->mki_len), c->mki_len - 4);
		else
			memcpy(p + (c->mki_len - 8), &mki_part, 4);
	}
	mki_part = (c->mki & 0xffffffffULL);
	mki_part = htonl(mki_part);
	if (c->mki_len < 4)
		memcpy(p, ((char *) &mki_part) + (4 - c->mki_len), c->mki_len);
	else
		memcpy(p + (c->mki_len - 4), &mki_part, 4);

	s->len += c->mki_len;
}

/* rfc 3711, section 3.3 */
int rtp_avp2savp(str *s, struct crypto_context *c) {
	struct rtp_header *rtp;
	str payload, to_auth;
	u_int64_t index;

	if (rtp_payload(&rtp, &payload, s))
		return -1;
	if (check_session_keys(c))
		return -1;

	index = packet_index(c, rtp);

	/* rfc 3711 section 3.1 */

	if (crypto_encrypt_rtp(c, rtp, &payload, index))
		return -1;

	to_auth = *s;

	rtp_append_mki(s, c);

	if (c->crypto_suite->srtp_auth_tag) {
		c->crypto_suite->hash_rtp(c, s->s + s->len, &to_auth, index);
		s->len += c->crypto_suite->srtp_auth_tag / 8;
	}

	return 0;
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
			c->crypto_suite->srtp_auth_tag, c->mki_len,
			s, &payload))
		return -1;

	if (auth_tag.len) {
		assert(sizeof(hmac) >= auth_tag.len);
		c->crypto_suite->hash_rtp(c, hmac, &to_auth, index);
		if (str_memcmp(&auth_tag, hmac))
			return -1;
	}

	if (crypto_decrypt_rtp(c, rtp, &to_decrypt, index))
		return -1;

	*s = to_auth;

	return 0;
}

/* rfc 3711 section 3.1 and 3.4 */
int srtp_payloads(str *to_auth, str *to_decrypt, str *auth_tag, str *mki,
		int auth_len, int mki_len,
		const str *packet, const str *payload)
{
	auth_len /= 8; /* given in bits */
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
	mylog(LOG_WARNING, "Invalid SRTP packet received");
	return -1;
}
