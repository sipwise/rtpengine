#include "codec.h"
#include "call.h"
#include "call_interfaces.h"
#include "log.h"
#include "main.h"

int _log_facility_rtcp;
int _log_facility_cdr;
struct rtpengine_config rtpe_config;
struct poller *rtpe_poller;

static str *sdup(char *s) {
	str c = STR_CONST_INIT(s);
	str *r = g_slice_alloc(sizeof(*r));
	*r = c;
	return r;
}
int main() {
	struct call call = {{0,},};
	struct sdp_ng_flags flags = {0,};

	codeclib_init(0);

	bencode_buffer_init(&call.buffer);
	struct call_media *media_A = call_media_new(&call);
	struct call_media *media_B = call_media_new(&call);

	flags.codec_strip = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
	flags.codec_mask = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);

	g_queue_push_tail(&flags.codec_transcode, sdup("PCMA"));

	GQueue rtp_types = G_QUEUE_INIT;
	struct rtp_payload_type pt = { 0, STR_CONST_INIT("PCMU"), STR_CONST_INIT("PCMU"),
		8000, STR_CONST_INIT(""), 1, STR_NULL, 0, 0, NULL };
	g_queue_push_tail(&rtp_types, &pt);

	codec_rtp_payload_types(media_A, media_B, &rtp_types,
			flags.codec_strip, &flags.codec_offer, &flags.codec_transcode,
			flags.codec_mask);
	codec_handlers_update(media_A, media_B, &flags);

	return 0;
}
