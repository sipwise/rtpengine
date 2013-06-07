#include "rtp.h"

#include <sys/types.h>
#include "str.h"
#include "crypto.h"




struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	u_int16_t seq_num;
	u_int32_t timestamp;
	u_int32_t ssrc;
	u_int32_t csrc[];
} __attribute__ ((packed));





static inline int check_session_key(struct crypto_context *c) {
	str s;

	if (c->have_session_key)
		return 0;

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

	if (s->len < sizeof(*rtp))
		return -1;

	rtp = (void *) s->s;

	if (check_session_key(c))
		return -1;

	return 0;
}

int rtp_savp2avp(str *s, struct crypto_context *c) {
	if (check_session_key(c))
		return -1;
	return 0;
}
