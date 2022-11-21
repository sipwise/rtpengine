#include <errno.h>
#include "dtmf.h"
#include "bencode.h"
#include "control_ng.h"
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
	ilog(LOG_DEBUG, "log dtmf over ng %d", rtpe_config.dtmf_via_ng);
	if (rtpe_config.dtmf_udp_ep.port) {
		if (connect_socket(&dtmf_log_sock, SOCK_DGRAM, &rtpe_config.dtmf_udp_ep))
			ilog(LOG_ERR, "Failed to open/connect DTMF logging socket: %s", strerror(errno));
	}
}

static unsigned int dtmf_volume_from_dsp(int vol) {
	if (vol > 0)
		return 0;
	else if (vol >= -63)
		return -1 * vol;
	else
		return 63;
}
char dtmf_code_to_char(int code) {
	static const char codes[] = "0123456789*#ABCD";
	if (code < 0 || code > 15)
		return 0;
	return codes[code];
}


static void dtmf_bencode_and_notify(struct call_media *media, unsigned int event, unsigned int volume,
		unsigned int duration, const endpoint_t *fsin, int clockrate)
{
	struct call *call = media->call;
	struct call_monologue *ml = media->monologue;

	bencode_buffer_t bencbuf;
	bencode_item_t *notify, *data, *tags;
	str encoded_data;
	int ret = bencode_buffer_init(&bencbuf);
	assert(ret == 0);

	notify = bencode_dictionary(&bencbuf);
	bencode_dictionary_add_string(notify, "notify", "onDTMF");
	data = bencode_dictionary_add_dictionary(notify, "data");
	tags = bencode_dictionary_add_list(data, "tags");

	bencode_dictionary_add_string_len(data, "callid", call->callid.s, call->callid.len);
	bencode_dictionary_add_string_len(data, "source_tag", ml->tag.s, ml->tag.len);

	GList *tag_values = g_hash_table_get_values(call->tags);
	for (GList *tag_it = tag_values; tag_it; tag_it = tag_it->next) {
		struct call_monologue *ml = tag_it->data;
		bencode_list_add_str(tags, &ml->tag);
	}
	g_list_free(tag_values);

	bencode_dictionary_add_string(data, "type", "DTMF");
	bencode_dictionary_add_string(data, "source_ip", sockaddr_print_buf(&fsin->address));
	bencode_dictionary_add_integer(data, "timestamp", rtpe_now.tv_sec);
	bencode_dictionary_add_integer(data, "event", event);
	bencode_dictionary_add_integer(data, "duration", ((long long) duration * (1000000LL / clockrate)) / 1000LL);
	bencode_dictionary_add_integer(data, "volume", volume);

	bencode_collapse_str(notify, &encoded_data);
	notify_ng_tcp_clients(&encoded_data);
	bencode_buffer_free(&bencbuf);
}

static GString *dtmf_json_print(struct call_media *media, unsigned int event, unsigned int volume,
		unsigned int duration,
		const endpoint_t *fsin, int clockrate)
{
	struct call *call = media->call;
	struct call_monologue *ml = media->monologue;

	GString *buf = g_string_new("");

	if (!clockrate)
		clockrate = 8000;

	g_string_append_printf(buf, "{"
			"\"callid\":\"" STR_FORMAT "\","
			"\"source_tag\":\"" STR_FORMAT "\","
			"\"tags\":[",
			STR_FMT(&call->callid),
			STR_FMT(&ml->tag));

	GList *tag_values = g_hash_table_get_values(call->tags);
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
			sockaddr_print_buf(&fsin->address),
			(unsigned int) event,
			(duration * (1000000 / clockrate)) / 1000,
			(unsigned int) volume);

	return buf;
}

bool dtmf_do_logging(void) {
	if (_log_facility_dtmf || dtmf_log_sock.family || rtpe_config.dtmf_via_ng)
		return true;
	return false;
}

// media->dtmf_lock must be held
static void dtmf_end_event(struct call_media *media, unsigned int event, unsigned int volume,
		unsigned int duration, const endpoint_t *fsin, int clockrate, bool rfc_event, uint64_t ts)
{
	if (!clockrate)
		clockrate = 8000;

	struct dtmf_event *ev = g_slice_alloc0(sizeof(*ev));
	*ev = (struct dtmf_event) { .code = 0, .ts = ts, .volume = 0 };
	g_queue_push_tail(&media->dtmf_recv, ev);

	ev = g_slice_alloc0(sizeof(*ev));
	*ev = (struct dtmf_event) { .code = 0, .ts = ts + media->monologue->dtmf_delay * clockrate / 1000,
		.volume = 0, .block_dtmf = media->monologue->block_dtmf };
	g_queue_push_tail(&media->dtmf_send, ev);

	if (!dtmf_do_logging())
		return;

	GString *buf = dtmf_json_print(media, event, volume, duration, fsin, clockrate);

	if (_log_facility_dtmf)
		dtmflog(buf);
	if (dtmf_log_sock.family)
		if (send(dtmf_log_sock.fd, buf->str, buf->len, 0) < 0)
			ilog(LOG_ERR, "Error sending DTMF event info to UDP socket: %s",
					strerror(errno));

	if (rtpe_config.dtmf_via_ng)
		dtmf_bencode_and_notify(media, event, volume, duration, fsin, clockrate);
	g_string_free(buf, TRUE);
}

static void dtmf_trigger_set(struct call *c, void *mlp) {
	struct call_monologue *ml = mlp;

	rwlock_lock_w(&c->master_lock);

	ilog(LOG_INFO, "Setting DTMF block mode to %i and setting new trigger to '" STR_FORMAT "'",
			ml->block_dtmf_trigger, STR_FMT(&ml->dtmf_trigger_end));

	ml->block_dtmf = ml->block_dtmf_trigger;

	// switch trigger to end trigger
	ml->block_dtmf_trigger = ml->block_dtmf_trigger_end;
	ml->dtmf_trigger = ml->dtmf_trigger_end;
	ml->dtmf_trigger_end = STR_NULL;
	ml->dtmf_trigger_digits *= -1; // negative means it's active

	codec_update_all_handlers(ml);

	rwlock_unlock_w(&c->master_lock);
}
static void dtmf_trigger_unset(struct call *c, void *mlp) {
	struct call_monologue *ml = mlp;

	ilog(LOG_INFO, "Setting DTMF block mode to %i", ml->block_dtmf_trigger_end);

	rwlock_lock_w(&c->master_lock);

	ml->block_dtmf = ml->block_dtmf_trigger_end;
	ml->dtmf_trigger = STR_NULL;

	codec_update_all_handlers(ml);

	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_check_trigger(struct call_media *media, char event, uint64_t ts, int clockrate) {
	struct call_monologue *ml = media->monologue;

	if (!clockrate)
		clockrate = 8000;

	if (!ml->dtmf_trigger.len) // do we have a trigger?
		return;
	if (ml->dtmf_trigger_match >= ml->dtmf_trigger.len) // is the trigger done already?
		return;

	// check delay from previous event
	// dtmf_lock already held
	struct dtmf_event *last_ev = g_queue_peek_tail(&media->dtmf_recv);
	if (last_ev) {
		uint32_t ts_diff = ts - last_ev->ts;
		uint64_t ts_diff_ms = (uint64_t) ts_diff * 1000 / clockrate;
		if (ts_diff_ms > rtpe_config.dtmf_digit_delay) {
			// delay too long: restart event trigger
			ml->dtmf_trigger_match = 0;
		}
	}

	if (ml->dtmf_trigger_digits < 0) {
		// end trigger is active
		ml->dtmf_trigger_digits++;
		if (ml->dtmf_trigger_digits == 0) {
			// got all digits
			codec_timer_callback(ml->call, dtmf_trigger_unset, ml, 0);
		}
	}

	// is the new event a match?
	if (ml->dtmf_trigger.s[ml->dtmf_trigger_match] == event) {
		ml->dtmf_trigger_match++;
		if (ml->dtmf_trigger_match == ml->dtmf_trigger.len) {
			// trigger is finished
			ml->dtmf_trigger_match = 0; // reset

			ilog(LOG_INFO, "DTMF trigger ('" STR_FORMAT "') matched, setting block mode to %i",
					STR_FMT(&ml->dtmf_trigger), ml->block_dtmf_trigger);

			// We only hold a read-lock on the call here and cannot switch to a write-lock
			// easily, which is needed to reset the codec handlers. Therefore we do this
			// asynchronously:
			codec_timer_callback(ml->call, dtmf_trigger_set, ml, 0);

			// set up unblock triggers
			if (ml->block_dtmf_trigger_end_ms)
				codec_timer_callback(ml->call, dtmf_trigger_unset, ml,
						ml->block_dtmf_trigger_end_ms * 1000);
		}
		return;
	}

	// can we do a partial match?
	for (size_t off = 1; off < ml->dtmf_trigger_match; off++) {
		// look for repeating prefix: trigger "ABCABD", matched 5, prefix at offset 3: [AB]C[AB]
		if (memcmp(ml->dtmf_trigger.s + off, ml->dtmf_trigger.s, ml->dtmf_trigger_match - off))
			continue;
		// is the new event a match?
		unsigned int next_match_idx = ml->dtmf_trigger.len - off;
		if (ml->dtmf_trigger.s[next_match_idx] == event) {
			// got a partial match
			ml->dtmf_trigger_match = next_match_idx;
			return;
		}
	}
	// no partial match... reset completely
	if (event == ml->dtmf_trigger.s[0])
		ml->dtmf_trigger_match = 1;
	else
		ml->dtmf_trigger_match = 0;
}

// media->dtmf_lock must be held
static void dtmf_code_event(struct call_media *media, char event, uint64_t ts, int clockrate, int volume) {
	struct dtmf_event *ev = g_queue_peek_tail(&media->dtmf_recv);
	if (ev && ev->code == event)
		return;

	// start of new event

	// check trigger before setting new dtmf_start
	dtmf_check_trigger(media, event, ts, clockrate);

	ev = g_slice_alloc0(sizeof(*ev));
	*ev = (struct dtmf_event) { .code = event, .ts = ts, .volume = volume,
		.rand_code = '0' + (ssl_random() % 10), .index = media->dtmf_count };
	g_queue_push_tail(&media->dtmf_recv, ev);

	ev = g_slice_alloc0(sizeof(*ev));
	*ev = (struct dtmf_event) { .code = event, .ts = ts + media->monologue->dtmf_delay * clockrate / 1000,
		.volume = volume,
		.block_dtmf = media->monologue->block_dtmf };
	g_queue_push_tail(&media->dtmf_send, ev);

	media->dtmf_count++;
}


struct dtmf_event *is_in_dtmf_event(GQueue *events, uint32_t this_ts, int clockrate, unsigned int head,
		unsigned int trail)
{
	if (!clockrate)
		clockrate = 8000;
	uint32_t cutoff = clockrate * 10;
	uint32_t neg = ~(clockrate * 100);

	uint32_t start_ts = this_ts + head * clockrate / 1000;
	uint32_t end_ts = this_ts - trail * clockrate / 1000;

	// go backwards through our list of DTMF events
	for (GList *l = events->tail; l; l = l->prev) {
		struct dtmf_event *ev = l->data;
		uint32_t ts = ev->ts; // truncate to 32 bits
		if (ev->code) {
			// start event: check TS against our shifted start TS.
			// start_ts must be larger than ts, but not much larger.
			uint32_t start_diff = start_ts - ts;
			// much too large? that means start_ts < ts. keep looking, we're close.
			if (start_diff >= neg)
				continue;
			// diff >= 0 and less than 10 seconds? that's a match.
			if (start_diff <= cutoff)
				return ev;
			// anything else is a bad/outdated TS. stop.
			break;
		}
		else {
			// stop event: check TS against our shifted end TS.
			uint32_t end_diff = end_ts - ts;
			if (end_diff >= neg)
				continue;
			if (end_diff == 0) // for end events, we wait until after the end
				continue;
			if (end_diff <= cutoff)
				return NULL;
			break;
		}
	}

	return NULL;
}


// media->dtmf_lock must be held
int dtmf_event_packet(struct media_packet *mp, str *payload, int clockrate, uint64_t ts) {
	struct telephone_event_payload *dtmf;
	if (payload->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %zu)", payload->len);
		return -1;
	}
	dtmf = (void *) payload->s;
	uint16_t duration = ntohs(dtmf->duration);

	ilog(LOG_DEBUG, "DTMF event packet: event %u, volume %u, end %u, duration %u",
			dtmf->event, dtmf->volume, dtmf->end, duration);

	if (!dtmf->end) {
		dtmf_code_event(mp->media, dtmf_code_to_char(dtmf->event), ts, clockrate, dtmf->volume);
		return 0;
	}

	dtmf_end_event(mp->media, dtmf->event, dtmf->volume, duration,
			&mp->fsin, clockrate, true, ts + duration - 1);

	return 1;
}

void dtmf_dsp_event(const struct dtmf_event *new_event, struct dtmf_event *cur_event_p,
		struct call_media *media, int clockrate, uint64_t ts)
{
	// update state tracker regardless of outcome
	struct dtmf_event cur_event = *cur_event_p;
	*cur_event_p = *new_event;

	if (!media)
		return;

	bool end_event;
	if (cur_event.code != 0 && new_event->code == 0)
		end_event = true;
	else if (cur_event.code == 0 && new_event->code != 0)
		end_event = false; // start of a new code
	else
		return; // don't care

	if (!media->streams.length)
		return;

	// we don't have a real fsin so just use the stream address
	struct packet_stream *ps = media->streams.head->data;

	unsigned int duration = new_event->ts - cur_event.ts;

	LOCK(&media->dtmf_lock);

	if (end_event) {
		ilog(LOG_DEBUG, "DTMF DSP end event: event %u, volume %u, duration %u",
				cur_event.code, cur_event.volume, duration);

		dtmf_end_event(media, dtmf_code_from_char(cur_event.code), dtmf_volume_from_dsp(cur_event.volume),
				duration, &ps->endpoint, clockrate, false, ts);
	}
	else {
		ilog(LOG_DEBUG, "DTMF DSP code event: event %u, volume %u, duration %u",
				new_event->code, new_event->volume, duration);
		int code = dtmf_code_from_char(new_event->code); // for validation
		if (code != -1)
			dtmf_code_event(media, (char) new_event->code, ts, clockrate,
					dtmf_volume_from_dsp(new_event->volume));
	}
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
	ev_pt->volume = dtmf_volume_from_dsp(cur_event->volume);
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

// takes over the csh reference
static const char *dtmf_inject_pcm(struct call_media *media, struct call_media *sink,
		struct call_monologue *monologue,
		struct packet_stream *ps, struct ssrc_ctx *ssrc_in, struct codec_handler *ch,
		struct codec_ssrc_handler *csh,
		int code, int volume, int duration, int pause)
{
	struct call *call = monologue->call;

	for (GList *l = ps->rtp_sinks.head; l; l = l->next) {
		struct sink_handler *sh = l->data;
		struct packet_stream *sink_ps = sh->sink;
		struct call_monologue *sink_ml = sink_ps->media->monologue;
		packet_sequencer_t *seq = g_hash_table_lookup(ssrc_in->parent->sequencers, sink_ps->media);
		if (!seq)
			continue;

		struct ssrc_ctx *ssrc_out = get_ssrc_ctx(sh->attrs.transcoding ?
					ssrc_in->ssrc_map_out : ssrc_in->parent->h.ssrc,
				sink_ml->ssrc_hash, SSRC_DIR_OUTPUT,
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
			.seq_num = htons(seq->seq),
			.ssrc = htonl(ssrc_in->parent->h.ssrc),
		};
		struct media_packet packet = {
			.tv = rtpe_now,
			.call = call,
			.media = media,
			.media_out = sink,
			.rtp = &rtp,
			.ssrc_in = ssrc_in,
			.ssrc_out = ssrc_out,
			.raw = { (void *) &tep, sizeof(tep) },
			.payload = { (void *) &tep, sizeof(tep) },
		};

		// keep track of how much PCM we've generated
		uint64_t encoder_pts = codec_encoder_pts(csh);
		uint64_t skip_pts = codec_decoder_unskip_pts(csh); // reset to zero to take up our new samples

		ch->dtmf_injector->handler_func(ch->dtmf_injector, &packet);

		// insert pause
		tep.event = 0xff;
		tep.duration = htons(pause_samples);
		rtp.seq_num = htons(seq->seq);

		ch->dtmf_injector->handler_func(ch->dtmf_injector, &packet);

		// skip generated samples
		uint64_t pts_offset = codec_encoder_pts(csh) - encoder_pts;
		skip_pts += av_rescale(pts_offset, ch->dest_pt.clock_rate, ch->source_pt.clock_rate);
		codec_decoder_skip_pts(csh, skip_pts);

		// ready packets for send
		// XXX handle encryption?

		media_socket_dequeue(&packet, sink_ps);

		obj_put_o((struct obj *) csh);
		ssrc_ctx_put(&ssrc_out);
	}

	return 0;
}

const char *dtmf_inject(struct call_media *media, int code, int volume, int duration, int pause,
		struct call_media *sink)
{
	struct call_monologue *monologue = media->monologue;

	if (!media->streams.head)
		return "Media doesn't have an RTP stream";
	struct packet_stream *ps = media->streams.head->data;
	struct ssrc_ctx *ssrc_in = ps->ssrc_in[0];
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

		ch = codec_handler_get(media, pt, sink, NULL);
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
	if (ch->dtmf_payload_type == -1 && ch->dtmf_injector)
		return dtmf_inject_pcm(media, sink, monologue, ps, ssrc_in, ch, csh, code, volume, duration,
				pause);

	ilog(LOG_DEBUG, "Injecting RFC DTMF event #%i for %i ms (vol %i) from '" STR_FORMAT "' (media #%u) "
			"into RTP PT %i, SSRC %" PRIx32,
			code, duration, volume, STR_FMT(&monologue->tag), media->index, pt,
			ssrc_in->parent->h.ssrc);

	// synthesise start and stop events
	uint64_t num_samples = (uint64_t) duration * ch->dest_pt.clock_rate / 1000;
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


enum block_dtmf_mode dtmf_get_block_mode(struct call *call, struct call_monologue *ml) {
	if (!call) {
		if (!ml)
			return BLOCK_DTMF_OFF;
		call = ml->call;
	}

	if (call && call->block_dtmf)
		return call->block_dtmf;
	if (!ml)
		return BLOCK_DTMF_OFF;
	return ml->block_dtmf;
}

bool is_pcm_dtmf_block_mode(enum block_dtmf_mode mode) {
	if (mode >= BLOCK_DTMF___PCM_REPLACE_START && mode <= BLOCK_DTMF___PCM_REPLACE_END)
		return true;
	return false;
}

bool is_dtmf_replace_mode(enum block_dtmf_mode mode) {
	if (mode >= BLOCK_DTMF___REPLACE_START && mode <= BLOCK_DTMF___REPLACE_END)
		return true;
	return false;
}
