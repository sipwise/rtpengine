#include "dtmf.h"
#include "media_socket.h"
#include "log.h"
#include "call.h"
#include "dtmflib.h"
#include "main.h"
#include "rtplib.h"
#include "codec.h"
#include "ssrc.h"



static socket_t dtmf_log_sock;

void dtmf_init(void) {
	if (rtpe_config.dtmf_udp_ep.port) {
		if (connect_socket(&dtmf_log_sock, SOCK_DGRAM, &rtpe_config.dtmf_udp_ep))
			ilog(LOG_ERR, "Failed to open/connect DTMF logging socket: %s", strerror(errno));
	}
}


static GString *dtmf_json_print(struct media_packet *mp,
		struct telephone_event_payload *dtmf, int clockrate)
{
	if (!dtmf->end)
		return NULL;

	GString *buf = g_string_new("");

	if (!clockrate)
		clockrate = 8000;

	g_string_append_printf(buf, "{"
			"\"callid\":\"" STR_FORMAT "\","
			"\"source_tag\":\"" STR_FORMAT "\","
			"\"tags\":[",
			STR_FMT(&mp->call->callid),
			STR_FMT(&mp->media->monologue->tag));

	GList *tag_values = g_hash_table_get_values(mp->call->tags);
	int i = 0;
	for (GList *tag_it = tag_values; tag_it; tag_it = tag_it->next) {
		struct call_monologue *ml = tag_it->data;
		if (i != 0)
			g_string_append(buf, ",");
		g_string_append_printf(buf, "\"" STR_FORMAT "\"",
				STR_FMT(&ml->tag));
		i++;
	}
	g_list_free(tag_values);

	g_string_append_printf(buf, "],"
			"\"type\":\"DTMF\",\"timestamp\":%lu,\"source_ip\":\"%s\","
			"\"event\":%u,\"duration\":%u,\"volume\":%u}",
			(unsigned long) rtpe_now.tv_sec,
			sockaddr_print_buf(&mp->fsin.address),
			(unsigned int) dtmf->event,
			(ntohs(dtmf->duration) * (1000000 / clockrate)) / 1000,
			(unsigned int) dtmf->volume);

	return buf;
}

int dtmf_event(struct media_packet *mp, str *payload, int clockrate) {
	struct telephone_event_payload *dtmf;
	if (payload->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %u)", payload->len);
		return -1;
	}
	dtmf = (void *) payload->s;

	ilog(LOG_DEBUG, "DTMF event: event %u, volume %u, end %u, duration %u",
			dtmf->event, dtmf->volume, dtmf->end, dtmf->duration);

	int ret = 0;

	GString *buf = NULL;

	if (_log_facility_dtmf || dtmf_log_sock.family)
		buf = dtmf_json_print(mp, dtmf, clockrate);

	if (buf) {
		if (_log_facility_dtmf)
			dtmflog(buf);
		if (dtmf_log_sock.family)
			send(dtmf_log_sock.fd, buf->str, buf->len, 0);
		g_string_free(buf, TRUE);

		ret = 1; // END event
	}

	return ret;
}

void dtmf_event_free(void *e) {
	g_slice_free1(sizeof(struct dtmf_event), e);
}

// returns: 0 = no DTMF. 1 = DTMF start event. 2 = DTMF in progress. 3 = DTMF end event.
int dtmf_event_payload(str *buf, uint64_t *pts, uint64_t duration, struct dtmf_event *cur_event, GQueue *events) {
	// do we have a relevant state change?
	struct dtmf_event prev_event = *cur_event;
	while (events->length) {
		struct dtmf_event *ev = g_queue_peek_head(events);
		ilog(LOG_DEBUG, "Next DTMF event starts at %lu. PTS now %li", (unsigned long) ev->ts,
				(unsigned long) *pts);
		if (ev->ts > *pts)
			break; // future event

		ilog(LOG_DEBUG, "DTMF state change at %lu: %i -> %i, duration %lu", (unsigned long) ev->ts,
				cur_event->code, ev->code, (unsigned long) duration);
		g_queue_pop_head(events);
		*cur_event = *ev;
		dtmf_event_free(ev);
		cur_event->ts = *pts; // canonicalise start TS
	}

	int ret = 2; // normal: in progress
	if (cur_event->code == 0) {
		if (prev_event.code == 0)
			return 0;
		// state change from DTMF back to audio. send DTMF end code.
		ret = 3;
		cur_event = &prev_event;
	}
	else if (prev_event.code == 0)
		ret = 1; // start event

	int dtmf_code = dtmf_code_from_char(cur_event->code);
	if (dtmf_code == -1) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Unknown DTMF event code %i", cur_event->code);
		return 0;
	}

	// replace audio RTP frame with DTMF payload
	struct telephone_event_payload *ev_pt = (void *) buf->s;
	buf->len = sizeof(*ev_pt);
	ZERO(*ev_pt);

	ev_pt->event = dtmf_code;
	if (cur_event->volume > 0)
		ev_pt->volume = 0;
	else if (cur_event->volume >= -63)
		ev_pt->volume = -1 * cur_event->volume;
	else
		ev_pt->volume = 63;
	ev_pt->end = (ret == 3) ? 1 : 0;
	ev_pt->duration = htons(*pts - cur_event->ts + duration);

	// fix up timestamp
	*pts = cur_event->ts;

	return ret;
}

int dtmf_code_from_char(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c == '*')
		return 10;
	else if (c == '#')
		return 11;
	else if (c >= 'A' && c <= 'D')
		return c - 'A' + 12;
	return -1;
}
static char dtmf_code_to_char(int code) {
	static const char codes[] = "0123456789*#ABCD";
	if (code < 0 || code > 15)
		return 0;
	return codes[code];
}

#ifdef WITH_TRANSCODING

const char *dtmf_inject(struct call_media *media, int code, int volume, int duration) {
	struct call_monologue *monologue = media->monologue;
	struct call *call = monologue->call;

	if (!media->streams.head)
		return "Media doesn't have an RTP stream";
	struct packet_stream *ps = media->streams.head->data;
	struct ssrc_ctx *ssrc_in = ps->ssrc_in;
	if (!ssrc_in)
		return "No SSRC context present for DTMF injection"; // XXX fall back to generating stream

//	if (media->dtmf_injector->dtmf_payload_type == -1) {
		// create RFC DTMF events. we do this by simulating a detected PCM DTMF event
		// XXX
//		abort();
//	}

	// create RFC DTMF events. we do this by simulating a detected PCM DTMF event
	// find payload type to use
	int pt = -1;
	for (int i = 0; i < ssrc_in->tracker.most_len; i++) {
		pt = ssrc_in->tracker.most[i];
		if (pt != 255)
			break;
	}
	if (pt < 0 || pt == 255)
		return "No RTP payload type found to be in use"; // XXX generate stream

	struct codec_handler *ch = codec_handler_get(media, pt);
	if (!ch)
		return "No matching codec handler";
	struct codec_ssrc_handler *csh = get_ssrc(ssrc_in->parent->h.ssrc, ch->ssrc_hash);
	if (!csh)
		return "No matching codec SSRC handler";

	ilog(LOG_DEBUG, "Injecting RFC DTMF event #%i for %i ms (vol %i) from '" STR_FORMAT "' (media #%u) "
			"into RTP PT %i",
			code, duration, volume, STR_FMT(&monologue->tag), media->index, pt);

	// synthesise start and stop events
	uint64_t num_samples = duration * ch->dest_pt.clock_rate / 1000;
	codec_add_dtmf_event(csh, dtmf_code_to_char(code), volume, codec_encoder_pts(csh));
	codec_add_dtmf_event(csh, 0, 0, codec_encoder_pts(csh) + num_samples);

	return NULL;

	abort();
	// synthesise event packet
	struct telephone_event_payload tep = {
		.event = code,
		.volume = volume,
		.end = 1,
	};
	struct rtp_header rtp = {
		.timestamp = 0,
		.seq_num = 0,
	};
	struct media_packet packet = {
		.tv = rtpe_now,
		.call = call,
		.media = media,
		.rtp = &rtp,
		.ssrc_in = ps->ssrc_in,
		.raw = { (void *) &tep, sizeof(tep) },
		.payload = { (void *) &tep, sizeof(tep) },
	};
	media->dtmf_injector->func(media->dtmf_injector, &packet);

	return 0;
}

#endif
