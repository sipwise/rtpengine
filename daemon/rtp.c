#include "rtp.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <glib.h>

#include "str.h"
#include "crypto.h"




static inline int check_session_key(struct crypto_context *c) {
	str s;

	if (c->have_session_key)
		return 0;
	if (!c->crypto_suite)
		return -1;

	str_init_len(&s, c->session_key, c->crypto_suite->session_key_len);
	if (crypto_gen_session_key(c, &s, 0x00))
		return -1;
	str_init_len(&s, c->session_auth_key, c->crypto_suite->srtp_auth_key_len);
	if (crypto_gen_session_key(c, &s, 0x01))
		return -1;
	str_init_len(&s, c->session_salt, c->crypto_suite->session_salt_len);
	if (crypto_gen_session_key(c, &s, 0x02))
		return -1;

	c->have_session_key = 1;
	return 0;
}

static int rtp_payload(str *p, str *s) {
	struct rtp_header *rtp;
	struct rtp_extension *ext;

	if (s->len < sizeof(*rtp))
		return -1;

	rtp = (void *) s->s;
	if ((rtp->v_p_x_cc & 0xc0) != 0x80) /* version 2 */
		return -1;

	*p = *s;
	/* fixed header */
	str_shift(p, sizeof(*rtp));
	/* csrc list */
	if (str_shift(p, (rtp->v_p_x_cc & 0xf) * 4))
		return -1;

	if ((rtp->v_p_x_cc & 0x10)) {
		/* extension */
		if (p->len < sizeof(*ext))
			return -1;
		ext = (void *) p->s;
		if (str_shift(p, 4 + ntohs(ext->length) * 4))
			return -1;
	}

	return 0;
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

/* rfc 3711, section 3.3 */
/* XXX some error handling/logging here */
int rtp_avp2savp(str *s, struct crypto_context *c) {
	struct rtp_header *rtp;
	str payload, to_auth;
	u_int64_t index;
	char *pl_end;
	u_int32_t mki_part;

	if (rtp_payload(&payload, s))
		return -1;
	if (check_session_key(c))
		return -1;

	rtp = (void *) s->s;
	index = packet_index(c, rtp);

	/* rfc 3711 section 3.1 */

	if (crypto_encrypt_rtp(c, rtp, &payload, index))
		return -1;

	pl_end = s->s + s->len;
	to_auth = *s;

	if (c->mki_len) {
		/* RTP_BUFFER_TAIL_ROOM guarantees enough room */
		memset(pl_end, 0, c->mki_len);
		if (c->mki_len > 4) {
			mki_part = (c->mki & 0xffffffff00000000ULL) >> 32;
			mki_part = htonl(mki_part);
			if (c->mki_len < 8)
				memcpy(pl_end, ((char *) &mki_part) + (8 - c->mki_len), c->mki_len - 4);
			else
				memcpy(pl_end + (c->mki_len - 8), &mki_part, 4);
		}
		mki_part = (c->mki & 0xffffffffULL);
		mki_part = htonl(mki_part);
		if (c->mki_len < 4)
			memcpy(pl_end, ((char *) &mki_part) + (4 - c->mki_len), c->mki_len);
		else
			memcpy(pl_end + (c->mki_len - 4), &mki_part, 4);

		pl_end += c->mki_len;
		to_auth.len += c->mki_len;
	}

	if (c->crypto_suite->srtp_auth_tag) {
		c->crypto_suite->hash_rtp(c, pl_end, &to_auth, index);
		pl_end += c->crypto_suite->srtp_auth_tag / 8;
	}

	s->len = pl_end - s->s;

	return 0;
}

/* rfc 3711, section 3.3 */
int rtp_savp2avp(str *s, struct crypto_context *c) {
	struct rtp_header *rtp;
	u_int64_t index;
	str payload, mki, to_auth;
	char hmac[20], *auth_tag = NULL;
	int i;

	if (rtp_payload(&payload, s))
		return -1;
	if (check_session_key(c))
		return -1;

	rtp = (void *) s->s;
	index = packet_index(c, rtp);

	/* rfc 3711 section 3.1 */

	to_auth = *s;

	if (c->crypto_suite->srtp_auth_tag) {
		i = c->crypto_suite->srtp_auth_tag / 8;

		assert(sizeof(hmac) >= i);
		if (payload.len < i)
			return -1;

		auth_tag = payload.s + payload.len - i;
		payload.len -= i;
		to_auth.len -= i;
	}

	if (c->mki_len) {
		if (payload.len < c->mki_len)
			return -1;

		str_init_len(&mki, payload.s - c->mki_len, c->mki_len);
		payload.len -= c->mki_len;
		to_auth.len -= c->mki_len;

		/* ignoring the mki for now */
	}

	if (c->crypto_suite->srtp_auth_tag) {
		c->crypto_suite->hash_rtp(c, hmac, &to_auth, index);
		if (memcmp(hmac, auth_tag, c->crypto_suite->srtp_auth_tag / 8))
			return -1;
	}

	if (crypto_decrypt_rtp(c, rtp, &payload, index))
		return -1;

	*s = to_auth;

	return 0;
}
