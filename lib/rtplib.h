#ifndef _RTPLIB_H_
#define _RTPLIB_H_

#include <stdint.h>
#include "str.h"



struct codec_def_s;
typedef struct codec_def_s codec_def_t;


struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	uint16_t seq_num;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[];
} __attribute__ ((packed));


union codec_format_options {
	struct {
		int interleaving;
		unsigned int mode_set; // bitfield
		int mode_change_period;
		unsigned int octet_aligned:1;
		unsigned int crc:1;
		unsigned int robust_sorting:1;
		unsigned int mode_change_neighbor:1;
	} amr;

	struct {
		int mode;
	} ilbc;
};

struct rtp_codec_format {
	union codec_format_options parsed;
	unsigned int fmtp_parsed:1; // set if fmtp string was successfully parsed
};

struct rtp_payload_type {
	int payload_type;
	str encoding_with_params; // "opus/48000/2"
	str encoding_with_full_params; // "opus/48000/1"
	str encoding; // "opus"
	unsigned int clock_rate; // 48000
	str encoding_parameters; // "2"
	int channels; // 2
	str format_parameters; // value of a=fmtp
	str codec_opts; // extra codec-specific options
	GQueue rtcp_fb; // a=rtcp-fb:...

	int ptime; // default from RFC
	int bitrate;

	const codec_def_t *codec_def;
	GList *prefs_link; // link in `codec_prefs` list
	struct rtp_codec_format format; // parsed out fmtp

	unsigned int for_transcoding:1;
	unsigned int accepted:1;
};


extern const struct rtp_payload_type rfc_rtp_payload_types[];
extern const int num_rfc_rtp_payload_types;


int rtp_payload(struct rtp_header **out, str *p, const str *s);
int rtp_padding(const struct rtp_header *header, str *payload);
const struct rtp_payload_type *rtp_get_rfc_payload_type(unsigned int type);
const struct rtp_payload_type *rtp_get_rfc_codec(const str *codec);

int rtp_payload_type_cmp(const struct rtp_payload_type *, const struct rtp_payload_type *);
int rtp_payload_type_cmp_nf(const struct rtp_payload_type *, const struct rtp_payload_type *);


#endif
