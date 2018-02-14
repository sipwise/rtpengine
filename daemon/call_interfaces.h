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

struct sdp_ng_flags {
	enum call_opmode opmode;
	str received_from_family;
	str received_from_address;
	str media_address;
	str transport_protocol_str;
	str address_family_str;
	const struct transport_protocol *transport_protocol;
	sockaddr_t parsed_received_from;
	sockaddr_t parsed_media_address;
	str direction[2];
	sockfamily_t *address_family;
	int tos;
	str record_call_str;
	str metadata;
	GHashTable *codec_strip;
	GQueue codec_offer;
	GQueue codec_transcode;
	GHashTable *codec_mask;
	int ptime;
	int asymmetric:1,
	    no_redis_update:1,
	    unidirectional:1,
	    trust_address:1,
	    port_latching:1,
	    replace_origin:1,
	    replace_sess_conn:1,
	    ice_remove:1,
	    ice_force:1,
	    ice_force_relay:1,
	    rtcp_mux_offer:1,
	    rtcp_mux_require:1,
	    rtcp_mux_demux:1,
	    rtcp_mux_accept:1,
	    rtcp_mux_reject:1,
	    no_rtcp_attr:1,
	    strict_source:1,
	    media_handover:1,
	    dtls_passive:1,
	    reset:1,
	    record_call:1,
	    loop_protect:1,
	    dtls_off:1,
	    sdes_off:1,
	    sdes_unencrypted_srtp:1,
	    sdes_unencrypted_srtcp:1,
	    sdes_unauthenticated_srtp:1,
	    sdes_encrypted_srtp:1,
	    sdes_encrypted_srtcp:1,
	    sdes_authenticated_srtp:1;
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

const char *call_offer_ng(bencode_item_t *, bencode_item_t *, const char*,
		const endpoint_t *);
const char *call_answer_ng(bencode_item_t *, bencode_item_t *);
const char *call_delete_ng(bencode_item_t *, bencode_item_t *);
const char *call_query_ng(bencode_item_t *, bencode_item_t *);
const char *call_list_ng(bencode_item_t *, bencode_item_t *);
const char *call_start_recording_ng(bencode_item_t *, bencode_item_t *);
const char *call_stop_recording_ng(bencode_item_t *, bencode_item_t *);
void ng_call_stats(struct call *call, const str *fromtag, const str *totag, bencode_item_t *output,
		struct call_stats *totals);

int call_interfaces_init(void);


#endif
