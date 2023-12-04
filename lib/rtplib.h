#ifndef _RTPLIB_H_
#define _RTPLIB_H_

#include <stdint.h>
#include <stdbool.h>
#include "str.h"
#include "containers.h"



typedef const struct codec_def_s codec_def_t;


struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	uint16_t seq_num;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[];
} __attribute__ ((packed));


enum evs_bw {
	EVS_BW_NB = 0,
	EVS_BW_WB = 1,
	EVS_BW_SWB = 2,
	EVS_BW_FB = 3,

	__EVS_BW_MAX,

	EVS_BW_UNSPEC = -1,
};

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

	struct {
		// EVS options
		unsigned int min_br, max_br;
		unsigned int min_br_send, max_br_send;
		unsigned int min_br_recv, max_br_recv;
		enum evs_bw min_bw, max_bw;
		enum evs_bw min_bw_send, max_bw_send;
		enum evs_bw min_bw_recv, max_bw_recv;
		// AMR options
		unsigned int mode_set; // bitfield
		int mode_change_period;
		// bit field options
		unsigned int hf_only:1;
		unsigned int amr_io:1;
		unsigned int no_dtx:1;
		unsigned int no_dtx_recv:1;
		int cmr:2; // -1, 0, 1
		// AMR bit options
		unsigned int mode_change_neighbor:1;
	} evs;

	struct {
		// 0 = default, 1 = set, -1 = not set (0)
		int stereo_recv:2;
		int stereo_send:2;
		int fec_recv:2;
		int fec_send:2;

		// these are parsed out but ignored
		int cbr:2;
		int usedtx:2;
		int maxplaybackrate;
		int sprop_maxcapturerate;
		int maxaveragebitrate;

		int minptime; // obsolete
	} opus;
};

struct rtp_codec_format {
	union codec_format_options parsed;
	unsigned int fmtp_parsed:1; // set if fmtp string was successfully parsed
};


struct rtp_payload_type;
TYPED_GQUEUE(rtp_pt, struct rtp_payload_type)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(rtp_pt_q, rtp_pt_q_clear)

struct rtp_payload_type {
	int payload_type;
	int reverse_payload_type;
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

	codec_def_t *codec_def;
	rtp_pt_list *prefs_link; // link in `codec_prefs` list
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

// if not `exact` then also returns true if `a` is compatible with `b`
// matches all params
__attribute__((nonnull(1, 2)))
bool rtp_payload_type_eq_exact(const struct rtp_payload_type *a, const struct rtp_payload_type *b);
__attribute__((nonnull(1, 2)))
bool rtp_payload_type_eq_compat(const struct rtp_payload_type *a, const struct rtp_payload_type *b);
// matches only basic params but not payload type number
__attribute__((nonnull(1, 2)))
bool rtp_payload_type_fmt_eq_nf(const struct rtp_payload_type *a, const struct rtp_payload_type *b);
// matches only basic params and payload type number
__attribute__((nonnull(1, 2)))
bool rtp_payload_type_eq_nf(const struct rtp_payload_type *, const struct rtp_payload_type *);
// matches all params except payload type number
__attribute__((nonnull(1, 2)))
int rtp_payload_type_fmt_cmp(const struct rtp_payload_type *a, const struct rtp_payload_type *b);
__attribute__((nonnull(1, 2)))
bool rtp_payload_type_fmt_eq_exact(const struct rtp_payload_type *a, const struct rtp_payload_type *b);
__attribute__((nonnull(1, 2)))
bool rtp_payload_type_fmt_eq_compat(const struct rtp_payload_type *a, const struct rtp_payload_type *b);


#endif
