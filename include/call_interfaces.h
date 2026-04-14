#ifndef _CALL_INTERFACES_H_
#define _CALL_INTERFACES_H_

#include <glib.h>

#include "str.h"
#include "socket.h"
#include "call.h"
#include "sdp.h"
#include "types.h"
#include "call_flags.h"


struct call_stats;
struct streambuf_stream;


extern str_case_value_ht rtpe_signalling_templates;
extern str rtpe_default_signalling_templates[OP_COUNT + 1];

str call_request_tcp(char **);
str call_lookup_tcp(char **);
void call_delete_tcp(char **);
void calls_status_tcp(struct streambuf_stream *);

str call_update_udp(char **, const char *);
str call_lookup_udp(char **);
str call_delete_udp(char **);
str call_query_udp(char **);

const char *call_offer_ng(ng_command_ctx_t *, const char *);
const char *call_answer_ng(ng_command_ctx_t *);
const char *call_delete_ng(ng_command_ctx_t *);
const char *call_query_ng(ng_command_ctx_t *);
const char *call_list_ng(ng_command_ctx_t *);
const char *call_start_recording_ng(ng_command_ctx_t *);
const char *call_stop_recording_ng(ng_command_ctx_t *);
const char *call_pause_recording_ng(ng_command_ctx_t *);
const char *call_start_forwarding_ng(ng_command_ctx_t *);
const char *call_stop_forwarding_ng(ng_command_ctx_t *);
const char *call_block_dtmf_ng(ng_command_ctx_t *);
const char *call_unblock_dtmf_ng(ng_command_ctx_t *);
const char *call_block_media_ng(ng_command_ctx_t *);
const char *call_unblock_media_ng(ng_command_ctx_t *);
const char *call_silence_media_ng(ng_command_ctx_t *);
const char *call_unsilence_media_ng(ng_command_ctx_t *);
const char *call_play_media_ng(ng_command_ctx_t *);
const char *call_stop_media_ng(ng_command_ctx_t *);
const char *call_play_dtmf_ng(ng_command_ctx_t *);
void ng_call_stats(ng_command_ctx_t *, call_t *call, const str *fromtag, const str *totag,
		struct call_stats *totals);
const char *call_publish_ng(ng_command_ctx_t *, const char *);
const char *call_subscribe_request_ng(ng_command_ctx_t *);
const char *call_subscribe_answer_ng(ng_command_ctx_t *);
const char *call_unsubscribe_ng(ng_command_ctx_t *);
const char *call_inject_start_ng(ng_command_ctx_t *);
const char *call_inject_stop_ng(ng_command_ctx_t *);
const char *call_connect_ng(ng_command_ctx_t *);
const char *call_transform_ng(ng_command_ctx_t *);
const char *call_create_ng(ng_command_ctx_t *);
const char *call_create_answer_ng(ng_command_ctx_t *);
const char *call_mesh_ng(ng_command_ctx_t *);

int call_interfaces_init(charp_ht);
void call_interfaces_free(void);
void call_interfaces_timer(void);


#endif
