#ifndef _CALL_INTERFACES_H_
#define _CALL_INTERFACES_H_

#include <glib.h>

#include "str.h"
#include "bencode.h"
#include "socket.h"
#include "call.h"
#include "sdp.h"
#include "types.h"

struct call_stats;
struct streambuf_stream;
struct sockaddr_in6;

typedef union {
	const struct sdp_attr_helper *attr_helper;
	str_q *q;
	str_case_ht *sct;
	str_case_value_ht *svt;
	void **generic;
} helper_arg  __attribute__ ((__transparent_union__));

struct sdp_ng_flags {
	enum call_opmode opmode;
	enum message_type message_type;
	str call_id;
	str from_tag;
	str_q from_tags;
	str to_tag;
	str via_branch;
	str sdp;
	str received_from_family;
	str received_from_address;
	str media_address;
	str address_family_str;
	const struct transport_protocol *transport_protocol;
	sockaddr_t parsed_received_from;
	sockaddr_t parsed_media_address;
	str direction[2];
	str interface;
	sockfamily_t *address_family;
	int tos;
	str record_call_str;
	str recording_file;
	str recording_path;
	str recording_pattern;
	str metadata;
	str label;
	str set_label;
	str to_label;
	str address;
	sockaddr_t xmlrpc_callback;
	endpoint_t dtmf_log_dest;
	str_q codec_strip;
	str_case_ht codec_except;
	str_q codec_offer;
	str_q codec_transcode;
	str_q codec_mask;
	str_q codec_accept;
	str_q codec_consume;
	str_case_value_ht codec_set;
	int ptime,
	    rev_ptime;
	str_case_ht sdes_no;		/* individual crypto suites which are excluded */
	str_case_ht sdes_only;		/* individual crypto suites which are only accepted */
	str_q sdes_order;		/* the order, in which crypto suites are being added to the SDP */
	str_q sdes_offerer_pref;	/* preferred crypto suites to be selected for the offerer */
	str dtls_fingerprint;

	/* keep session level attributes for internal proper parsing */
	sdp_attr_q session_attributes;	// top-level (not part of an m= section) SDP session attributes
	sdp_origin session_sdp_orig;
	str session_sdp_name;

	str session_timing; /* t= line */
	int session_rr, session_rs; /* b= bandwidth per session level */

	/* commands to manipulate attr lines in SDP */
	struct sdp_manipulations * sdp_manipulations[__MT_MAX];

	enum {
		ICE_DEFAULT = 0,
		ICE_REMOVE,
		ICE_FORCE,
		ICE_FORCE_RELAY,
		ICE_OPTIONAL,
	} ice_option:3;
	enum {
		ICE_LITE_DEFAULT = 0,
		ICE_LITE_OFF,
		ICE_LITE_FWD,
		ICE_LITE_BKW,
		ICE_LITE_BOTH,
	} ice_lite_option:3;
	enum {
		MEO_DEFAULT = 0,
		MEO_BLACKHOLE,
		MEO_FWD,
		MEO_BKW,
		MEO_BOTH,
	} media_echo:3;
	enum {
		ALL_NONE = 0,
		ALL_ALL,
		ALL_OFFER_ANSWER,
		ALL_NON_OFFER_ANSWER,
		ALL_FLOWS,
	} all:3;
	enum {
		AP_DEFAULT = 0,
		AP_OFF,
		AP_TRANSCODING,
		AP_FORCE,
	} audio_player:2;
	enum endpoint_learning el_option;
	enum block_dtmf_mode block_dtmf_mode;
	int delay_buffer;
	GArray *frequencies;
	int volume;
	char digit;
	str trigger;
	enum block_dtmf_mode block_dtmf_mode_trigger;
	str trigger_end;
	enum block_dtmf_mode block_dtmf_mode_trigger_end;
	int trigger_end_digits;
	int trigger_end_ms;
	int dtmf_delay;
	int repeat_times;
	int delete_delay;
	str file;
	str blob;
	long long db_id;
	long long duration;
	long long pause;
	long long start_pos;
	str vsc_start_rec;
	str vsc_stop_rec;
	str vsc_start_stop_rec;
	str vsc_pause_rec;
	str vsc_pause_resume_rec;
	str vsc_start_pause_resume_rec;
	int t38_version;

	unsigned int asymmetric:1,
	             protocol_accept:1,
	             no_redis_update:1,
	             unidirectional:1,
	             trust_address:1,
	             port_latching:1,
	             no_port_latching:1,
	             replace_origin:1,
	             replace_origin_full:1,
	             replace_sdp_version:1,
	             force_inc_sdp_ver:1,
	             replace_username:1,
	             replace_sess_name:1,
	             replace_zero_address:1,
	             rtcp_mux_offer:1,
	             rtcp_mux_require:1,
	             rtcp_mux_demux:1,
	             rtcp_mux_accept:1,
	             rtcp_mux_reject:1,
		     ice_reject:1,
		     rtcp_mirror:1,
		     trickle_ice:1,
	             no_rtcp_attr:1,
	             full_rtcp_attr:1,
	             generate_rtcp:1,
	             generate_rtcp_off:1,
	             generate_mid:1,
		     strip_extmap:1,
	             strict_source:1,
	             media_handover:1,
	             dtls_passive:1,
	             dtls_reverse_passive:1,
	             osrtp_accept_legacy:1,
	             osrtp_accept_rfc:1,
	             osrtp_offer:1,
	             osrtp_offer_legacy:1,
	             reset:1,
		     egress:1,
		     siprec:1,
	             fragment:1,
	             record_call:1,
		     discard_recording:1,
		     exclude_recording:1,
		     skip_recording_db:1,
		     recording_vsc:1,
		     recording_announcement:1,
		     debug:1,
		     inactive:1,
	             loop_protect:1,
	             original_sendrecv:1,
	             single_codec:1,
		     reuse_codec:1,
		     static_codecs:1,
		     allow_transcoding:1,
		     allow_asymmetric_codecs:1,
		     early_media:1,
		     accept_any:1,
	             inject_dtmf:1,
		     detect_dtmf:1,
		     block_dtmf:1,
		     block_egress:1,
	             t38_decode:1,
	             t38_force:1,
	             t38_stop:1,
	             t38_no_ecm:1,
	             t38_no_v17:1,
	             t38_no_v27ter:1,
	             t38_no_v29:1,
	             t38_no_v34:1,
	             t38_no_iaf:1,
	             t38_fec:1,
	             supports_load_limit:1,
	             dtls_off:1,
	             sdes_off:1,
	             sdes_unencrypted_srtp:1,
	             sdes_unencrypted_srtcp:1,
	             sdes_unauthenticated_srtp:1,
	             sdes_encrypted_srtp:1,
	             sdes_encrypted_srtcp:1,
	             sdes_authenticated_srtp:1,
	             sdes_lifetime:1,
	             sdes_pad:1,
	             sdes_static:1,
	             sdes_nonew:1,
	             sdes_prefer:1,
		     recrypt:1,
	             drop_traffic_start:1,
	             drop_traffic_stop:1,
	             passthrough_on:1,
	             passthrough_off:1,
		     block_short:1,
	             disable_jb:1,
		     nat_wait:1,
		     pierce_nat:1,
		     directional:1,
		     fatal:1,
		     /* to_tag is used especially by delete handling */
		     to_tag_flag:1;
};


extern bool trust_address_def;
extern bool dtls_passive_def;

str *call_request_tcp(char **);
str *call_lookup_tcp(char **);
void call_delete_tcp(char **);
void calls_status_tcp(struct streambuf_stream *);

str *call_update_udp(char **, const char*, const endpoint_t *);
str *call_lookup_udp(char **);
str *call_delete_udp(char **);
str *call_query_udp(char **);

const char *call_offer_ng(ng_buffer *, bencode_item_t *, bencode_item_t *, const char*,
		const endpoint_t *);
const char *call_answer_ng(ng_buffer *, bencode_item_t *, bencode_item_t *);
const char *call_delete_ng(bencode_item_t *, bencode_item_t *);
const char *call_query_ng(bencode_item_t *, bencode_item_t *);
const char *call_list_ng(bencode_item_t *, bencode_item_t *);
const char *call_start_recording_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_recording_ng(bencode_item_t *, bencode_item_t *);
const char *call_pause_recording_ng(bencode_item_t *, bencode_item_t *);
const char *call_start_forwarding_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_forwarding_ng(bencode_item_t *, bencode_item_t *);
const char *call_block_dtmf_ng(bencode_item_t *, bencode_item_t *);
const char *call_unblock_dtmf_ng(bencode_item_t *, bencode_item_t *);
const char *call_block_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_unblock_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_silence_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_unsilence_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_play_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_play_dtmf_ng(bencode_item_t *, bencode_item_t *);
void ng_call_stats(call_t *call, const str *fromtag, const str *totag, bencode_item_t *output,
		struct call_stats *totals);
const char *call_publish_ng(ng_buffer *, bencode_item_t *, bencode_item_t *, const char *,
		const endpoint_t *);
const char *call_subscribe_request_ng(bencode_item_t *, bencode_item_t *);
const char *call_subscribe_answer_ng(ng_buffer *, bencode_item_t *, bencode_item_t *);
const char *call_unsubscribe_ng(bencode_item_t *, bencode_item_t *);

void add_media_to_sub_list(subscription_q *q, struct call_media *media, struct call_monologue *ml);

void save_last_sdp(struct call_monologue *ml, str *sdp, sdp_sessions_q *parsed, sdp_streams_q *streams);
void call_ng_flags_init(sdp_ng_flags *out, enum call_opmode opmode);
void call_ng_free_flags(sdp_ng_flags *flags);
void call_unlock_release(call_t *c);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(sdp_ng_flags, call_ng_free_flags)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(call_t, call_unlock_release)

int call_interfaces_init(void);
void call_interfaces_free(void);
void call_interfaces_timer(void);

void call_ng_flags_flags(sdp_ng_flags *out, str *s, helper_arg dummy);
void call_ng_main_flags(sdp_ng_flags *out, str *key, bencode_item_t *value,
	enum call_opmode opmode);
void call_ng_codec_flags(sdp_ng_flags *out, str *key, bencode_item_t *value,
	enum call_opmode opmode);
void call_ng_direction_flag(sdp_ng_flags *out, bencode_item_t *value);

INLINE struct sdp_manipulations *sdp_manipulations_get_by_id(const sdp_ng_flags *f, enum media_type id) {
	if (id < 0 || id >= G_N_ELEMENTS(f->sdp_manipulations))
		return NULL;
	return f->sdp_manipulations[id];
}
INLINE struct sdp_manipulations *sdp_manipulations_get_create_by_id(sdp_ng_flags *f, enum media_type id) {
	if (id < 0 || id >= G_N_ELEMENTS(f->sdp_manipulations))
		return NULL;
	if (!f->sdp_manipulations[id])
		f->sdp_manipulations[id] = g_slice_alloc0(sizeof(*f->sdp_manipulations[id]));
	return f->sdp_manipulations[id];
}
INLINE struct sdp_manipulations *sdp_manipulations_get_by_name(sdp_ng_flags *f, const str *s) {
	if (!str_cmp(s, "none") || !str_cmp(s, "global"))
		return sdp_manipulations_get_create_by_id(f, MT_UNKNOWN);
	enum media_type id = codec_get_type(s);
	if (id == MT_OTHER)
		return NULL;
	return sdp_manipulations_get_create_by_id(f, id);
}
// set all WebRTC-specific attributes
INLINE void ng_flags_webrtc(sdp_ng_flags *f) {
	f->transport_protocol = &transport_protocols[PROTO_UDP_TLS_RTP_SAVPF];
	f->ice_option = ICE_FORCE;
	f->trickle_ice = 1;
	f->rtcp_mux_offer = 1;
	f->rtcp_mux_require = 1;
	f->no_rtcp_attr = 1;
	f->sdes_off = 1;
	f->generate_mid = 1;
}



#endif
