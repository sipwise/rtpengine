#include "dtmf.h"

#include <errno.h>

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


static void dtmf_trigger_block_action(struct call_media *, struct call_monologue *);
static void dtmf_trigger_block_digit(struct call_media *, struct call_monologue *);
static void dtmf_trigger_unblock_action(struct call_media *, struct call_monologue *);
static void dtmf_trigger_start_rec(struct call_media *, struct call_monologue *);
static void dtmf_trigger_stop_rec(struct call_media *, struct call_monologue *);
static void dtmf_trigger_start_stop_rec(struct call_media *, struct call_monologue *);
static void dtmf_trigger_pause_rec(struct call_media *, struct call_monologue *);
static void dtmf_trigger_pause_resume_rec(struct call_media *, struct call_monologue *);
static void dtmf_trigger_start_pause_resume_rec(struct call_media *, struct call_monologue *);

struct dtmf_trigger_action dtmf_trigger_actions[__NUM_DTMF_TRIGGERS] = {
	[DTMF_TRIGGER_BLOCK] = {
		.matched = dtmf_trigger_block_action,
		.repeatable = false,
		.digit = dtmf_trigger_block_digit,
	},
	[DTMF_TRIGGER_UNBLOCK] = {
		.matched = dtmf_trigger_unblock_action,
		.repeatable = false,
	},
	[DTMF_TRIGGER_START_REC] = {
		.matched = dtmf_trigger_start_rec,
		.repeatable = true,
	},
	[DTMF_TRIGGER_STOP_REC] = {
		.matched = dtmf_trigger_stop_rec,
		.repeatable = true,
	},
	[DTMF_TRIGGER_START_STOP_REC] = {
		.matched = dtmf_trigger_start_stop_rec,
		.repeatable = true,
	},
	[DTMF_TRIGGER_PAUSE_REC] = {
		.matched = dtmf_trigger_pause_rec,
		.repeatable = true,
	},
	[DTMF_TRIGGER_PAUSE_RESUME_REC] = {
		.matched = dtmf_trigger_pause_resume_rec,
		.repeatable = true,
	},
	[DTMF_TRIGGER_START_PAUSE_RESUME_REC] = {
		.matched = dtmf_trigger_start_pause_resume_rec,
		.repeatable = true,
	},
};

const char *dtmf_trigger_types[__NUM_DTMF_TRIGGERS] = {
	[DTMF_TRIGGER_BLOCK] = "block DTMF",
	[DTMF_TRIGGER_UNBLOCK] = "unblock DTMF",
	[DTMF_TRIGGER_START_REC] = "start recording",
	[DTMF_TRIGGER_STOP_REC] = "stop recording",
	[DTMF_TRIGGER_START_STOP_REC] = "start/stop recording",
	[DTMF_TRIGGER_PAUSE_REC] = "pause recording",
	[DTMF_TRIGGER_PAUSE_RESUME_REC] = "pause/resume recording",
	[DTMF_TRIGGER_START_PAUSE_RESUME_REC] = "start/pause/resume recording",
};


bool dtmf_init(void) {
	ilog(LOG_DEBUG, "log dtmf over ng %d", rtpe_config.dtmf_via_ng);
	ilog(LOG_DEBUG, "no log injected dtmf %d", rtpe_config.dtmf_no_log_injects);
	if (open_v46_socket(&dtmf_log_sock, SOCK_DGRAM)) {
		ilog(LOG_ERR, "Failed to open/connect DTMF logging socket: %s", strerror(errno));
		return false;
	}
	return true;
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
	call_t *call = media->call;
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

	bencode_dictionary_add_str(data, "callid", &call->callid);
	bencode_dictionary_add_str(data, "source_tag", &ml->tag);
	if (ml->label.s) {
		bencode_dictionary_add_str(data, "source_label", &ml->label);
	}

	tags_ht_iter iter;
	t_hash_table_iter_init(&iter, call->tags);
	struct call_monologue *tml;
	while (t_hash_table_iter_next(&iter, NULL, &tml))
		bencode_list_add_str(tags, &tml->tag);

	bencode_dictionary_add_string(data, "type", "DTMF");
	bencode_dictionary_add_string(data, "source_ip", sockaddr_print_buf(&fsin->address));
	bencode_dictionary_add_integer(data, "timestamp", rtpe_now.tv_sec);
	bencode_dictionary_add_integer(data, "event", event);
	bencode_dictionary_add_integer(data, "duration", ((long long) duration * (1000000LL / clockrate)) / 1000LL);
	bencode_dictionary_add_integer(data, "volume", volume);

	encoded_data = bencode_collapse_str(notify);
	notify_ng_tcp_clients(&encoded_data);
	bencode_buffer_free(&bencbuf);
}

static GString *dtmf_json_print(struct call_media *media, unsigned int event, unsigned int volume,
		unsigned int duration,
		const endpoint_t *fsin, int clockrate)
{
	call_t *call = media->call;
	struct call_monologue *ml = media->monologue;

	GString *buf = g_string_new("");

	if (!clockrate)
		clockrate = 8000;

	g_string_append_printf(buf, "{"
			"\"callid\":\"" STR_FORMAT "\","
			"\"source_tag\":\"" STR_FORMAT "\","
			"\"source_label\":\"" STR_FORMAT "\","
			"\"tags\":[",
			STR_FMT(&call->callid),
			STR_FMT(&ml->tag),
			STR_FMT(ml->label.s ? &ml->label : &STR_EMPTY));

	tags_ht_iter iter;
	t_hash_table_iter_init(&iter, call->tags);
	int i = 0;
	struct call_monologue *tml;
	while (t_hash_table_iter_next(&iter, NULL, &tml)) {
		if (i != 0)
			g_string_append(buf, ",");
		g_string_append_printf(buf, "\"" STR_FORMAT "\"",
				STR_FMT(&tml->tag));
		i++;
	}

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

bool dtmf_do_logging(const call_t *c, bool injected) {
	if (injected && rtpe_config.dtmf_no_log_injects)
		return false;
	if (_log_facility_dtmf)
		return true;
	if (rtpe_config.dtmf_udp_ep.port)
		return true;
	if (c->dtmf_log_dest.address.family)
		return true;
	if (rtpe_config.dtmf_via_ng)
		return true;
	return false;
}

// media->dtmf_lock must be held
static void dtmf_end_event(struct call_media *media, unsigned int event, unsigned int volume,
		unsigned int duration, const endpoint_t *fsin, int clockrate, bool rfc_event, uint64_t ts, bool injected)
{
	if (!clockrate)
		clockrate = 8000;

	// don't add to recv list when it's injected, it can cause the list TS's to be out
	// of order breaking the dtmf-security and letting the generated PCM frames through
	if (!injected) {
		struct dtmf_event *ev = g_slice_alloc0(sizeof(*ev));
		*ev = (struct dtmf_event) { .code = 0, .ts = ts, .volume = 0 };
		t_queue_push_tail(&media->dtmf_recv, ev);
	}

	// only add to send list if injected, a delayed send, or not being blocked
	if (injected || !media->monologue->block_dtmf || media->monologue->dtmf_delay) {
		struct dtmf_event *ev = g_slice_alloc0(sizeof(*ev));
		*ev = (struct dtmf_event) { .code = 0, .ts = ts + media->monologue->dtmf_delay * clockrate / 1000,
			.volume = 0, .block_dtmf = media->monologue->block_dtmf };
		t_queue_push_tail(&media->dtmf_send, ev);
	}

	if (!dtmf_do_logging(media->call, injected))
		return;

	GString *buf = dtmf_json_print(media, event, volume, duration, fsin, clockrate);

	if (_log_facility_dtmf)
		dtmflog(buf);

	const endpoint_t *udp_dst = NULL;
	if (media->call->dtmf_log_dest.address.family)
		udp_dst = &media->call->dtmf_log_dest;
	else if (rtpe_config.dtmf_udp_ep.address.family)
		udp_dst = &rtpe_config.dtmf_udp_ep;

	if (udp_dst)
		if (socket_sendto(&dtmf_log_sock, buf->str, buf->len, udp_dst) < 0)
			ilog(LOG_ERR, "Error sending DTMF event info to UDP destination %s: %s",
					endpoint_print_buf(udp_dst),
					strerror(errno));

	if (rtpe_config.dtmf_via_ng)
		dtmf_bencode_and_notify(media, event, volume, duration, fsin, clockrate);
	g_string_free(buf, TRUE);
}

static struct dtmf_trigger_state *dtmf_get_trigger_state(struct call_monologue *ml, enum dtmf_trigger_type type)
{
	// Look up entry in ->dtmf_triger_state. If trigger is set already, its index
	// is stored in dtmf_trigger_index. If it isn't, grab a new entry.
	// The index must be less then num_triggers and the type of the entry pointed
	// to by the index must match the requested type. Everything else is invalid
	// and requires a new entry.
	// This keeps all set triggers at the front of the list and doesn't pollute
	// the list with unset entries, while still allowing quick lookup.
	// trigger_state[trigger_index[type]].type == type
	// trigger_index[trigger_state[idx].type] == idx

	unsigned int idx = ml->dtmf_trigger_index[type];
	if (idx >= ml->num_dtmf_triggers)
		return NULL;
	struct dtmf_trigger_state *state = &ml->dtmf_trigger_state[idx];
	if (state->type != type)
		return NULL;
	return state;
}

void dtmf_trigger_set(struct call_monologue *ml, enum dtmf_trigger_type trigger_type,
		const str *s, bool inactive)
{

	struct dtmf_trigger_state *state = dtmf_get_trigger_state(ml, trigger_type);

	if (!state) {
		// Trigger doesn't exist yet. Do we actually want to set a trigger?
		if (s->len == 0)
			return; // nothing to do

		// fill in a new entry
		assert(ml->num_dtmf_triggers < __NUM_DTMF_TRIGGERS);
		state = &ml->dtmf_trigger_state[ml->num_dtmf_triggers];
		ml->dtmf_trigger_index[trigger_type] = ml->num_dtmf_triggers;
		state->type = trigger_type;
		ml->num_dtmf_triggers++;

		// Trigger is set below
	}
	else {
		// Trigger is already set. Do we want to delete it?
		if (s->len == 0) {
			// Shift down remaining items and adjust indexes
			unsigned int idx = state - ml->dtmf_trigger_state;
			for (unsigned int i = idx; i < ml->num_dtmf_triggers - 1; i++) {
				assert(ml->dtmf_trigger_index[ml->dtmf_trigger_state[i].type] == i);
				assert(ml->dtmf_trigger_index[ml->dtmf_trigger_state[i + 1].type] == i + 1);
				ml->dtmf_trigger_state[i] = ml->dtmf_trigger_state[i + 1];
				ml->dtmf_trigger_index[ml->dtmf_trigger_state[i].type] = i;
			}
			ml->num_dtmf_triggers--;
			return;
		}

		// Replace existing trigger below
	}

	ilog(LOG_DEBUG, "Setting DTMF trigger '%s' (at idx %u) to '" STR_FORMAT "'",
			dtmf_trigger_types[trigger_type],
			(unsigned int) (state - ml->dtmf_trigger_state), STR_FMT(s));

	state->trigger = call_str_cpy(s);
	state->matched = 0;
	state->inactive = inactive;
}

static void dtmf_trigger_set_block(call_t *c, codec_timer_callback_arg_t a) {
	struct call_monologue *ml = a.ml;

	rwlock_lock_w(&c->master_lock);

	struct dtmf_trigger_state *end_trigger = dtmf_get_trigger_state(ml, DTMF_TRIGGER_UNBLOCK);

	if (end_trigger)
		ilog(LOG_INFO, "Setting DTMF block mode to %i and enabling end trigger '" STR_FORMAT "'",
				ml->block_dtmf_trigger, STR_FMT(&end_trigger->trigger));
	else
		ilog(LOG_INFO, "Setting DTMF block mode to %i",
				ml->block_dtmf_trigger);

	ml->block_dtmf = ml->block_dtmf_trigger;

	// enable end trigger
	if (end_trigger) {
		end_trigger->inactive = false;
		ml->dtmf_trigger_digits *= -1; // negative means it's active
	}

	codec_update_all_handlers(ml);

	rwlock_unlock_w(&c->master_lock);
}
static void dtmf_trigger_unset_block(call_t *c, codec_timer_callback_arg_t a) {
	struct call_monologue *ml = a.ml;

	ilog(LOG_INFO, "Setting DTMF block mode to %i", ml->block_dtmf_trigger_end);

	rwlock_lock_w(&c->master_lock);

	ml->block_dtmf = ml->block_dtmf_trigger_end;
	dtmf_trigger_set(ml, DTMF_TRIGGER_BLOCK, NULL, false);

	codec_update_all_handlers(ml);

	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_block_digit(struct call_media *media, struct call_monologue *ml) {
	if (ml->dtmf_trigger_digits >= 0)
		return;

	// end trigger is active
	ml->dtmf_trigger_digits++;
	if (ml->dtmf_trigger_digits == 0) {
		// got all digits
		codec_timer_callback(ml->call, dtmf_trigger_unset_block, ml, 0);
	}
}

// dtmf_lock must be held
static void dtmf_trigger_block_action(struct call_media *media, struct call_monologue *ml) {
	ilog(LOG_INFO, "DTMF trigger matched, setting block mode to %i",
			ml->block_dtmf_trigger);

	// We only hold a read-lock on the call here and cannot switch to a write-lock
	// easily, which is needed to reset the codec handlers. Therefore we do this
	// asynchronously:
	codec_timer_callback(ml->call, dtmf_trigger_set_block, ml, 0);

	// set up unblock triggers
	if (ml->block_dtmf_trigger_end_ms)
		codec_timer_callback(ml->call, dtmf_trigger_unset_block, ml,
				ml->block_dtmf_trigger_end_ms * 1000);
}

// dtmf_lock must be held
static void dtmf_trigger_unblock_action(struct call_media *media, struct call_monologue *ml) {
	ilog(LOG_INFO, "DTMF trigger matched, setting block mode to %i",
			ml->block_dtmf_trigger);

	// We only hold a read-lock on the call here and cannot switch to a write-lock
	// easily, which is needed to reset the codec handlers. Therefore we do this
	// asynchronously:
	codec_timer_callback(ml->call, dtmf_trigger_unset_block, ml, 0);
}

// dtmf_lock must be held
static bool dtmf_check_1_trigger(struct call_media *media, struct call_monologue *ml,
		char event, uint64_t ts, int clockrate, unsigned int i)
{
	struct dtmf_trigger_state *state = &ml->dtmf_trigger_state[i];
	struct dtmf_trigger_action *action = &dtmf_trigger_actions[state->type];

	if (state->matched >= state->trigger.len) // is the trigger done already?
		return false;

	if (action->digit)
		action->digit(media, ml);

	// is the new event a match?
	if (state->trigger.s[state->matched] == event) {
		state->matched++;
		if (state->matched == state->trigger.len) {
			// trigger is finished
			state->matched = 0; // reset

			ilog(LOG_INFO, "DTMF VSC '%s' ('" STR_FORMAT "') triggered",
					dtmf_trigger_types[state->type], STR_FMT(&state->trigger));

			action->matched(media, ml);

			if (!action->repeatable)
				dtmf_trigger_set(ml, state->type, NULL, false);

			return true;
		}
		return false;
	}

	// can we do a partial match?
	for (size_t off = 1; off < state->matched; off++) {
		// look for repeating prefix: trigger "ABCABD", matched 5, prefix at offset 3: [AB]C[AB]
		if (memcmp(state->trigger.s + off, state->trigger.s, state->matched - off))
			continue;
		// is the new event a match?
		unsigned int next_match_idx = state->trigger.len - off;
		if (state->trigger.s[next_match_idx] == event) {
			// got a partial match
			state->matched = next_match_idx;
			return false;
		}
	}
	// no partial match... reset completely
	if (event == state->trigger.s[0])
		state->matched = 1;
	else
		state->matched = 0;

	return false;
}

// dtmf_lock must be held
static void dtmf_check_trigger(struct call_media *media, char event, uint64_t ts, int clockrate) {
	if (!clockrate)
		clockrate = 8000;

	struct call_monologue *ml = media->monologue;

	if (!ml->num_dtmf_triggers)
		return; // nothing to do

	// check delay from previous event
	bool reset = false;
	struct dtmf_event *last_ev = t_queue_peek_tail(&media->dtmf_recv);
	if (last_ev) {
		uint32_t ts_diff = ts - last_ev->ts;
		uint64_t ts_diff_ms = (uint64_t) ts_diff * 1000 / clockrate;
		if (ts_diff_ms > rtpe_config.dtmf_digit_delay) {
			// delay too long: restart event trigger
			reset = true;
		}
	}

	for (unsigned int i = 0; i < ml->num_dtmf_triggers; i++) {
		if (reset)
			ml->dtmf_trigger_state[i].matched = 0;

		if (dtmf_check_1_trigger(media, ml, event, ts, clockrate, i))
			break; // triggers should be unique, so only act on one
	}
}

// media->dtmf_lock must be held
static void dtmf_code_event(struct call_media *media, char event, uint64_t ts, int clockrate, int volume, bool injected) {
	struct dtmf_event *ev = t_queue_peek_tail(&media->dtmf_recv);
	if (ev && ev->code == event)
		return;

	// start of new event

	// check trigger before setting new dtmf_start
	dtmf_check_trigger(media, event, ts, clockrate);

	// don't add to recv list when it's injected, it can cause the list TS's to be out
	// of order breaking the dtmf-security and letting the generated PCM frames through
	if (!injected) {
		ev = g_slice_alloc0(sizeof(*ev));
		*ev = (struct dtmf_event) { .code = event, .ts = ts, .volume = volume,
			.rand_code = '0' + (ssl_random() % 10), .index = media->dtmf_count };
		t_queue_push_tail(&media->dtmf_recv, ev);
	}

	// only add to send list if injected, a delayed send, or not being blocked
	if (injected || !media->monologue->block_dtmf || media->monologue->dtmf_delay) {
		ev = g_slice_alloc0(sizeof(*ev));
		*ev = (struct dtmf_event) { .code = event, .ts = ts + media->monologue->dtmf_delay * clockrate / 1000,
			.volume = volume,
			.block_dtmf = media->monologue->block_dtmf };
		t_queue_push_tail(&media->dtmf_send, ev);
	}

	media->dtmf_count++;
}


struct dtmf_event *is_in_dtmf_event(dtmf_event_q *events, uint32_t this_ts, int clockrate, unsigned int head,
		unsigned int trail)
{
	if (!clockrate)
		clockrate = 8000;
	uint32_t cutoff = clockrate * 10;
	uint32_t neg = ~(clockrate * 100);

	uint32_t start_ts = this_ts + head * clockrate / 1000;
	uint32_t end_ts = this_ts - trail * clockrate / 1000;

	// go backwards through our list of DTMF events
	for (__auto_type l = events->tail; l; l = l->prev) {
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
		dtmf_code_event(mp->media, dtmf_code_to_char(dtmf->event), ts, clockrate, dtmf->volume, false);
		return 0;
	}

	dtmf_end_event(mp->media, dtmf->event, dtmf->volume, duration,
			&mp->fsin, clockrate, true, ts + duration - 1, false);

	return 1;
}

void dtmf_dsp_event(const struct dtmf_event *new_event, struct dtmf_event *cur_event_p,
		struct call_media *media, int clockrate, uint64_t ts, bool injected)
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


	LOCK(&media->dtmf_lock);

	if (end_event) {
		unsigned int duration = new_event->ts - cur_event.ts;

		ilog(LOG_DEBUG, "DTMF DSP end event: event %i, volume %i, duration %u",
				cur_event.code, cur_event.volume, duration);

		dtmf_end_event(media, dtmf_code_from_char(cur_event.code), dtmf_volume_from_dsp(cur_event.volume),
				duration, &ps->endpoint, clockrate, false, ts, injected);
	}
	else {
		ilog(LOG_DEBUG, "DTMF DSP code event: event %i, volume %i",
				new_event->code, new_event->volume);
		int code = dtmf_code_from_char(new_event->code); // for validation
		if (code != -1)
			dtmf_code_event(media, (char) new_event->code, ts, clockrate,
					dtmf_volume_from_dsp(new_event->volume), injected);
	}
}

void dtmf_event_free(struct dtmf_event *e) {
	g_slice_free1(sizeof(*e), e);
}

// returns: 0 = no DTMF. 1 = DTMF start event. 2 = DTMF in progress. 3 = DTMF end event.
int dtmf_event_payload(str *buf, uint64_t *pts, uint64_t duration, struct dtmf_event *cur_event,
		dtmf_event_q *events)
{
	// do we have a relevant state change?
	struct dtmf_event prev_event = *cur_event;
	struct dtmf_event *ev = t_queue_peek_head(events);
	while (events->length) {
		ilog(LOG_DEBUG, "Next DTMF event starts at %" PRIu64 ". PTS now %" PRIu64, ev->ts, *pts);
		if (ev->ts > *pts)
			break; // future event

		ilog(LOG_DEBUG, "DTMF state change at %" PRIu64 ": %i -> %i, duration %" PRIu64, ev->ts,
				cur_event->code, ev->code, duration);
		t_queue_pop_head(events);
		*cur_event = *ev;
		dtmf_event_free(ev);
		ev = t_queue_peek_head(events);
		if (ev && ev->code == 0 && cur_event->ts < *pts) {
			// if the start event ts was before *pts we need
			// to adjust the end event_ts to ensure we're not shortening
			// the event
			ilog(LOG_DEBUG, "Delayed send of DTMF, adjusting end event_ts by "
					"%" PRIu64 " - %" PRIu64 " = %" PRIu64,
					*pts, cur_event->ts, *pts - cur_event->ts);
			ev->ts += *pts - cur_event->ts;
		}
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
	call_t *call = monologue->call;

	for (__auto_type l = ps->rtp_sinks.head; l; l = l->next) {
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
		uint64_t encoder_pts = codec_encoder_pts(csh, NULL);
		uint64_t skip_pts = codec_decoder_unskip_pts(csh); // reset to zero to take up our new samples

		ch->dtmf_injector->handler_func(ch->dtmf_injector, &packet);

		// insert pause
		tep.event = 0xff;
		tep.duration = htons(pause_samples);
		rtp.seq_num = htons(seq->seq);

		ch->dtmf_injector->handler_func(ch->dtmf_injector, &packet);

		// skip generated samples
		uint64_t pts_offset = codec_encoder_pts(csh, NULL) - encoder_pts;
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
	int ch_pt = -1;
	for (int i = 0; i < ssrc_in->tracker.most_len; i++) {
		pt = ssrc_in->tracker.most[i];
		if (pt == 255)
			continue;

		ch = codec_handler_get(media, pt, sink, NULL);
		if (!ch)
			continue;
		// for DTMF delay, payload type will be -1 but the real payload type will be correct
		// and as we're specifically injecting we want to make sure we end up checking the right pt
		ch_pt = ch->real_dtmf_payload_type != -1 ? ch->real_dtmf_payload_type : ch->dtmf_payload_type;
		// skip DTMF PTs
		if (pt == ch_pt)
			continue;
		if (ch->output_handler && ch->output_handler->ssrc_hash) // context switch if we have multiple inputs going to one output
			ch = ch->output_handler;

		ilog(LOG_DEBUG, "DTMF injection: Using PT %i/%i -> %i (%i), SSRC %" PRIx32,
				pt,
				ch->source_pt.payload_type,
				ch->dest_pt.payload_type,
				ch_pt,
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
	if (ch_pt == -1 && ch->dtmf_injector)
		return dtmf_inject_pcm(media, sink, monologue, ps, ssrc_in, ch, csh, code, volume, duration,
				pause);

	ilog(LOG_DEBUG, "Injecting RFC DTMF event #%i for %i ms (vol %i) from '" STR_FORMAT "' (media #%u) "
			"into RTP PT %i, SSRC %" PRIx32,
			code, duration, volume, STR_FMT(&monologue->tag), media->index, pt,
			ssrc_in->parent->h.ssrc);

	// synthesise start and stop events
	// the num_samples needs to be based on the the previous packet timestamp so we need to
	// reduce it by one packets worth or we'll generate one too many packets than requested
	uint64_t num_samples = (uint64_t) (duration - ch->dest_pt.ptime) * ch->dest_pt.clock_rate / 1000;
	uint64_t start_pts = codec_encoder_pts(csh, ssrc_in);
	// get the last event end time, and increase by the required pause
	// conversely to the above, we need to add the last packet num samples to its TS before adding
	// a pause so we dont generate one packet too few
	// if that's later than start_pts, we need to adjust it
	uint64_t last_end_pts = codec_last_dtmf_event(csh);
	if (last_end_pts) {
		last_end_pts += (pause + ch->dest_pt.ptime) * ch->dest_pt.clock_rate / 1000;
		if (last_end_pts > start_pts)
			start_pts = last_end_pts;
	}

	codec_add_dtmf_event(csh, dtmf_code_to_char(code), volume, start_pts, true);
	codec_add_dtmf_event(csh, 0, 0, start_pts + num_samples, true);

	obj_put_o((struct obj *) csh);
	return NULL;
}

#endif


enum block_dtmf_mode dtmf_get_block_mode(call_t *call, struct call_monologue *ml) {
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

static void dtmf_trigger_do_start_rec(call_t *c, codec_timer_callback_arg_t a) {
	rwlock_lock_w(&c->master_lock);
	recording_start(c);
	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_start_rec(struct call_media *media, struct call_monologue *ml) {
	codec_timer_callback(ml->call, dtmf_trigger_do_start_rec, ml, 0);
}

static void dtmf_trigger_do_stop_rec(call_t *c, codec_timer_callback_arg_t a) {
	rwlock_lock_w(&c->master_lock);
	recording_stop(c);
	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_stop_rec(struct call_media *media, struct call_monologue *ml) {
	codec_timer_callback(ml->call, dtmf_trigger_do_stop_rec, ml, 0);
}

static void dtmf_trigger_do_start_stop_rec(call_t *c, codec_timer_callback_arg_t a) {
	rwlock_lock_w(&c->master_lock);
	if (c->recording)
		recording_stop(c);
	else
		recording_start(c);
	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_start_stop_rec(struct call_media *media, struct call_monologue *ml) {
	codec_timer_callback(ml->call, dtmf_trigger_do_start_stop_rec, ml, 0);
}

static void dtmf_trigger_do_pause_rec(call_t *c, codec_timer_callback_arg_t a) {
	rwlock_lock_w(&c->master_lock);
	recording_pause(c);
	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_pause_rec(struct call_media *media, struct call_monologue *ml) {
	codec_timer_callback(ml->call, dtmf_trigger_do_pause_rec, ml, 0);
}

static void dtmf_trigger_do_pause_resume_rec(call_t *c, codec_timer_callback_arg_t a) {
	rwlock_lock_w(&c->master_lock);
	if (!c->recording) {
		rwlock_unlock_w(&c->master_lock);
		return;
	}
	if (CALL_SET(c, RECORDING_ON))
		recording_pause(c);
	else
		recording_start(c);
	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_pause_resume_rec(struct call_media *media, struct call_monologue *ml) {
	codec_timer_callback(ml->call, dtmf_trigger_do_pause_resume_rec, ml, 0);
}

static void dtmf_trigger_do_start_pause_resume_rec(call_t *c, codec_timer_callback_arg_t a) {
	rwlock_lock_w(&c->master_lock);
	if (CALL_SET(c, RECORDING_ON))
		recording_pause(c);
	else
		recording_start(c);
	rwlock_unlock_w(&c->master_lock);
}

// dtmf_lock must be held
static void dtmf_trigger_start_pause_resume_rec(struct call_media *media, struct call_monologue *ml) {
	codec_timer_callback(ml->call, dtmf_trigger_do_start_pause_resume_rec, ml, 0);
}
