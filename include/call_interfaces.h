#ifndef _CALL_INTERFACES_H_
#define _CALL_INTERFACES_H_



#include <glib.h>
#include "str.h"
#include "bencode.h"
#include "socket.h"
#include "call.h"



struct call;
struct call_stats;
struct streambuf_stream;
struct sockaddr_in6;
struct ng_buffer;

struct sdp_ng_flags {
	enum call_opmode opmode;
	str call_id;
	str from_tag;
	str to_tag;
	str via_branch;
	str received_from_family;
	str received_from_address;
	str media_address;
	str address_family_str;
	const struct transport_protocol *transport_protocol;
	sockaddr_t parsed_received_from;
	sockaddr_t parsed_media_address;
	str direction[2];
	sockfamily_t *address_family;
	int tos;
	str record_call_str;
	str metadata;
	str label;
	str address;
	sockaddr_t xmlrpc_callback;
	GHashTable *codec_strip;
	GHashTable *codec_except;
	GQueue codec_offer;
	GQueue codec_transcode;
	GHashTable *codec_mask;
	GHashTable *codec_accept;
	GHashTable *codec_consume;
	GHashTable *codec_set;
	int ptime,
	    rev_ptime;
	GHashTable *sdes_no;
	str dtls_fingerprint;
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
	unsigned int asymmetric:1,
	             protocol_accept:1,
	             no_redis_update:1,
	             unidirectional:1,
	             trust_address:1,
	             port_latching:1,
	             no_port_latching:1,
	             replace_origin:1,
	             replace_sess_conn:1,
	             replace_sdp_version:1,
	             replace_username:1,
	             replace_sess_name:1,
	             replace_zero_address:1,
	             rtcp_mux_offer:1,
	             rtcp_mux_require:1,
	             rtcp_mux_demux:1,
	             rtcp_mux_accept:1,
	             rtcp_mux_reject:1,
	             no_rtcp_attr:1,
	             full_rtcp_attr:1,
	             generate_rtcp:1,
	             generate_rtcp_off:1,
	             generate_mid:1,
	             strict_source:1,
	             media_handover:1,
	             dtls_passive:1,
	             dtls_reverse_passive:1,
	             osrtp_accept:1,
	             osrtp_offer:1,
	             reset:1,
	             all:1,
	             fragment:1,
	             record_call:1,
		     debug:1,
	             loop_protect:1,
	             original_sendrecv:1,
	             asymmetric_codecs:1,
	             symmetric_codecs:1,
	             reorder_codecs:1,
	             single_codec:1,
	             inject_dtmf:1,
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
	             drop_traffic_start:1,
	             drop_traffic_stop:1,
	             passthrough_on:1,
	             passthrough_off:1,
	             disable_jb:1;
};


extern int trust_address_def;
extern int dtls_passive_def;

str *call_request_tcp(char **);
str *call_lookup_tcp(char **);
void call_delete_tcp(char **);
void calls_status_tcp(struct streambuf_stream *);

str *call_update_udp(char **, const char*, const endpoint_t *);
str *call_lookup_udp(char **);
str *call_delete_udp(char **);
str *call_query_udp(char **);

const char *call_offer_ng(struct ng_buffer *, bencode_item_t *, bencode_item_t *, const char*,
		const endpoint_t *);
const char *call_answer_ng(struct ng_buffer *, bencode_item_t *, bencode_item_t *);
const char *call_delete_ng(bencode_item_t *, bencode_item_t *);
const char *call_query_ng(bencode_item_t *, bencode_item_t *);
const char *call_list_ng(bencode_item_t *, bencode_item_t *);
const char *call_start_recording_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_recording_ng(bencode_item_t *, bencode_item_t *);
const char *call_start_forwarding_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_forwarding_ng(bencode_item_t *, bencode_item_t *);
const char *call_block_dtmf_ng(bencode_item_t *, bencode_item_t *);
const char *call_unblock_dtmf_ng(bencode_item_t *, bencode_item_t *);
const char *call_block_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_unblock_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_play_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_media_ng(bencode_item_t *, bencode_item_t *);
const char *call_play_dtmf_ng(bencode_item_t *, bencode_item_t *);
void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output,
		struct call_stats *totals);

int call_interfaces_init(void);
void call_interfaces_free(void);
void call_interfaces_timer(void);


#endif
