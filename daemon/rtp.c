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

/* XXX some error handling/logging here */
int rtp_avp2savp(str *s, struct crypto_context *c) {
	struct rtp_header *rtp;
	str payload, to_auth;
	struct rtp_extension *ext;
	u_int16_t seq;
	u_int64_t index, s_l_index;
	long long int diff;
	char *pl_end;
	u_int32_t mki_part;

	if (s->len < sizeof(*rtp))
		return -1;
	if (check_session_key(c))
		return -1;

	rtp = (void *) s->s;
	if ((rtp->v_p_x_cc & 0xc0) != 0x80) /* version 2 */
		return -1;

	payload = *s;
	/* fixed header */
	str_shift(&payload, sizeof(*rtp));
	/* csrc list */
	if (str_shift(&payload, (rtp->v_p_x_cc & 0xf) * 4))
		return -1;

	if ((rtp->v_p_x_cc & 0x10)) {
		/* extension */
		if (payload.len < sizeof(*ext))
			return -1;
		ext = (void *) payload.s;
		if (str_shift(&payload, 4 + ntohs(ext->length) * 4))
			return -1;
	}

	seq = ntohs(rtp->seq_num);
	/* rfc 3711 section 3.3.1 */
	if (G_UNLIKELY(!c->s_l))
		c->s_l = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	index = ((u_int64_t) c->roc << 16) | seq;
	s_l_index = ((u_int64_t) c->roc << 16) | c->s_l;
	diff = index - s_l_index;
	if (diff >= 0) {
		if (diff < 0x8000)
			;
		else if (index >= 0x10000)
			index -= 0x10000;
	}
	else {
		if (diff >= -0x8000)
			;
		else {
			index += 0x10000;
			c->roc++;
		}
	}

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
		c->crypto_suite->hash_rtp(c, pl_end, &to_auth);
		pl_end += c->crypto_suite->srtp_auth_tag;
	}

	s->len = pl_end - s->s;

	return 0;
}

int rtp_savp2avp(str *s, struct crypto_context *c) {
	if (check_session_key(c))
		return -1;
	return 0;
}
