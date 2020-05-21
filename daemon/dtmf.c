#include <errno.h>
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

#ifdef WITH_TRANSCODING

static char dtmf_code_to_char(int code) {
	static const char codes[] = "0123456789*#ABCD";
	if (code < 0 || code > 15)
		return 0;
	return codes[code];
}

// takes over the csh reference
static const char *dtmf_inject_pcm(struct call_media *media, struct call_monologue *monologue,
		struct packet_stream *ps, struct ssrc_ctx *ssrc_in, struct codec_handler *ch,
		struct codec_ssrc_handler *csh,
		int code, int volume, int duration, int pause)
{
	struct call *call = monologue->call;

	struct ssrc_ctx *ssrc_out = get_ssrc_ctx(ssrc_in->ssrc_map_out, call->ssrc_hash, SSRC_DIR_OUTPUT,
			monologue);
	if (!ssrc_out)
		return "No output SSRC context present"; // XXX generate stream

	int duration_samples = duration * ch->dest_pt.clock_rate / 1000;
	int pause_samples = pause * ch->dest_pt.clock_rate / 1000;

	// we generate PCM DTMF by simulating a detected RFC event packet
	// XXX this shouldn't require faking an actual RTP packet
	struct telephone_event_payload tep = {
		.event = code,
		.volume = -1 * volume,
		.end = 1,
		.duration = htons(duration_samples),
	};
	struct rtp_header rtp = {
		.m_pt = 0xff,
		.timestamp = 0,
		.seq_num = htons(ssrc_in->parent->sequencer.seq),
		.ssrc = htonl(ssrc_in->parent->h.ssrc),
	};
	struct media_packet packet = {
		.tv = rtpe_now,
		.call = call,
		.media = media,
		.rtp = &rtp,
		.ssrc_in = ssrc_in,
		.ssrc_out = ssrc_out,
		.raw = { (void *) &tep, sizeof(tep) },
		.payload = { (void *) &tep, sizeof(tep) },
	};

	// keep track of how much PCM we've generated
	uint64_t encoder_pts = codec_encoder_pts(csh);
	uint64_t skip_pts = codec_decoder_unskip_pts(csh); // reset to zero to take up our new samples

	media->dtmf_injector->func(media->dtmf_injector, &packet);

	// insert pause
	tep.event = 0xff;
	tep.duration = htons(pause_samples);
	rtp.seq_num = htons(ssrc_in->parent->sequencer.seq);

	media->dtmf_injector->func(media->dtmf_injector, &packet);

	// skip generated samples
	uint64_t pts_offset = codec_encoder_pts(csh) - encoder_pts;
	skip_pts += av_rescale(pts_offset, ch->dest_pt.clock_rate, ch->source_pt.clock_rate);
	codec_decoder_skip_pts(csh, skip_pts);

	// ready packets for send
	// XXX handle encryption?

	media_socket_dequeue(&packet, packet_stream_sink(ps));

	obj_put_o((struct obj *) csh);
	return 0;
}

const char *dtmf_inject(struct call_media *media, int code, int volume, int duration, int pause) {
	struct call_monologue *monologue = media->monologue;

	if (!media->streams.head)
		return "Media doesn't have an RTP stream";
	struct packet_stream *ps = media->streams.head->data;
	struct ssrc_ctx *ssrc_in = ps->ssrc_in;
	if (!ssrc_in)
		return "No SSRC context present for DTMF injection"; // XXX fall back to generating stream

	// create RFC DTMF events. we do this by simulating a detected PCM DTMF event
	// find payload type to use
	struct codec_handler *ch = NULL;
	struct codec_ssrc_handler *csh = NULL;
	int pt = -1;
	for (int i = 0; i < ssrc_in->tracker.most_len; i++) {
		pt = ssrc_in->tracker.most[i];
		if (pt == 255)
			continue;
		if (pt < 0)
			break;

		ch = codec_handler_get(media, pt);
		if (!ch)
			continue;
		if (ch->output_handler && ch->output_handler->ssrc_hash) // context switch if we have multiple inputs going to one output
			ch = ch->output_handler;

		ilog(LOG_DEBUG, "DTMF injection: Using PT %i/%i -> %i (%i), SSRC %" PRIx32,
				pt,
				ch->source_pt.payload_type,
				ch->dest_pt.payload_type,
				ch->dtmf_payload_type,
				ssrc_in->parent->h.ssrc);

		if (!ch->ssrc_hash)
			continue;
		csh = get_ssrc(ssrc_in->parent->h.ssrc, ch->ssrc_hash);
		if (!csh)
			continue;
		break;
	}

	if (pt < 0 || pt == 255)
		return "No RTP payload type found to be in use"; // XXX generate stream
	if (!ch)
		return "No matching codec handler";
	if (!ch->ssrc_hash)
		return "No suitable codec handler present";
	if (!csh)
		return "No matching codec SSRC handler";

	// if we don't have a DTMF payload type, we have to generate PCM
	if (media->dtmf_injector->dtmf_payload_type == -1)
		return dtmf_inject_pcm(media, monologue, ps, ssrc_in, ch, csh, code, volume, duration, pause);

	ilog(LOG_DEBUG, "Injecting RFC DTMF event #%i for %i ms (vol %i) from '" STR_FORMAT "' (media #%u) "
			"into RTP PT %i, SSRC %" PRIx32,
			code, duration, volume, STR_FMT(&monologue->tag), media->index, pt,
			ssrc_in->parent->h.ssrc);

	// synthesise start and stop events
	uint64_t num_samples = duration * ch->dest_pt.clock_rate / 1000;
	uint64_t start_pts = codec_encoder_pts(csh);
	uint64_t last_end_pts = codec_last_dtmf_event(csh);
	if (last_end_pts) {
		// shift this new event past the end of the last event plus a pause
		start_pts = last_end_pts + pause * ch->dest_pt.clock_rate / 1000;
	}
	codec_add_dtmf_event(csh, dtmf_code_to_char(code), volume, start_pts);
	codec_add_dtmf_event(csh, 0, 0, start_pts + num_samples);

	obj_put_o((struct obj *) csh);
	return NULL;
}

#endif
