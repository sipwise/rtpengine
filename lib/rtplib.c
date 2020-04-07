#include "rtplib.h"
#include <arpa/inet.h>
#include "str.h"
#include "log.h"
#include "codeclib.h"



struct rtp_extension {
	u_int16_t undefined;
	u_int16_t length;
} __attribute__ ((packed));




#define RFC_TYPE_FULL(type, name, c_rate, chans, pt)			\
	[type] = {							\
		.payload_type		= type,				\
		.encoding		= STR_CONST_INIT(#name),	\
		.encoding_with_params	= STR_CONST_INIT(#name "/" #c_rate),	\
		.clock_rate		= c_rate,			\
		.channels		= chans,			\
		.ptime			= pt,				\
	}
#define RFC_TYPE(type, name, c_rate) RFC_TYPE_FULL(type, name, c_rate, 1, 20)

const struct rtp_payload_type rfc_rtp_payload_types[] =
{
	RFC_TYPE(0, PCMU, 8000),
	RFC_TYPE(3, GSM, 8000),
	RFC_TYPE_FULL(4, G723, 8000, 1, 30),
	RFC_TYPE(5, DVI4, 8000),
	RFC_TYPE(6, DVI4, 16000),
	RFC_TYPE(7, LPC, 8000),
	RFC_TYPE(8, PCMA, 8000),
	RFC_TYPE(9, G722, 8000),
	RFC_TYPE(10, L16, 44100),
	RFC_TYPE_FULL(11, L16, 44100, 2, 20),
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
const int num_rfc_rtp_payload_types = G_N_ELEMENTS(rfc_rtp_payload_types);






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
	ilog(LOG_DEBUG | LOG_FLAG_LIMIT, "Error parsing RTP header: %s", err);
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


const struct rtp_payload_type *rtp_get_rfc_payload_type(unsigned int type) {
	const struct rtp_payload_type *rtp_pt;

	if (type >= num_rfc_rtp_payload_types)
		return NULL;
	rtp_pt = &rfc_rtp_payload_types[type];
	if (!rtp_pt->encoding.s)
		return NULL;
	return rtp_pt;
}

// for one-time init only - better use rtp_get_rfc_payload_type(codec_def->rfc_payload_type)
const struct rtp_payload_type *rtp_get_rfc_codec(const str *codec) {
	for (int i = 0; i < num_rfc_rtp_payload_types; i++) {
		if (!rfc_rtp_payload_types[i].encoding.s)
			continue;
		if (str_cmp_str(codec, &rfc_rtp_payload_types[i].encoding))
			continue;
		return &rfc_rtp_payload_types[i];
	}
	return NULL;
}

int rtp_payload_type_cmp(const struct rtp_payload_type *a, const struct rtp_payload_type *b) {
	if (rtp_payload_type_cmp_nf(a, b))
		return 1;
	if (str_cmp_str(&a->format_parameters, &b->format_parameters))
		return 1;
	return 0;
}

int rtp_payload_type_cmp_nf(const struct rtp_payload_type *a, const struct rtp_payload_type *b) {
	if (a->payload_type != b->payload_type)
		return 1;
	if (a->clock_rate != b->clock_rate)
		return 1;
	if (a->channels != b->channels)
		return 1;
	if (str_casecmp_str(&a->encoding_with_params, &b->encoding_with_params))
		return 1;
	return 0;
}
