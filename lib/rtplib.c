#include "rtplib.h"
#include <arpa/inet.h>
#include "str.h"
#include "log.h"



struct rtp_extension {
	u_int16_t undefined;
	u_int16_t length;
} __attribute__ ((packed));





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


int rtp_padding(struct rtp_header *header, str *payload) {
	if (!(header->v_p_x_cc & 0x20))
		return 0; // no padding
	if (payload->len == 0)
		return -1;
	unsigned int padding = (unsigned char) payload->s[payload->len - 1];
	if (payload->len < padding)
		return -1;
	payload->len -= padding;
	return 0;
}
