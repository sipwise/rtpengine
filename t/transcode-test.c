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
	struct call_media media_A = {0,}, media_B = {0,};
	struct sdp_ng_flags flags = {0,};

	flags.codec_strip = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);
	flags.codec_mask = g_hash_table_new_full(str_hash, str_equal, str_slice_free, NULL);

	g_queue_push_tail(&flags.codec_transcode, sdup("PCMA"));

	codec_rtp_payload_types(&media_A, &media_B, NULL,
			flags.codec_strip, &flags.codec_offer, &flags.codec_transcode,
			flags.codec_mask);
	codec_handlers_update(&media_A, &media_B, &flags);

	return 0;
}
