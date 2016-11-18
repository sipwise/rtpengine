#ifndef _RTPLIB_H_
#define _RTPLIB_H_

#include <stdint.h>
#include "str.h"


struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	uint16_t seq_num;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[];
} __attribute__ ((packed));


int rtp_payload(struct rtp_header **out, str *p, const str *s);
int rtp_padding(struct rtp_header *header, str *payload);


#endif
