#include "t38.h"

#ifdef WITH_TRANSCODING
#include <assert.h>
#include <spandsp/t30.h>
#include <spandsp/logging.h>
#include "spandsp_logging.h"
#include "codec.h"
#include "call.h"
#include "log.h"
#include "str.h"
#include "media_player.h"
#include "log_funcs.h"
#include "sdp.h"



struct udptl_packet {
	seq_packet_t p;
	str *s;
};



static void __add_udptl_len(GString *s, const void *buf, unsigned int len) {
	if (len < 0x80) {
		g_string_append_c(s, len);
		if (len)
			g_string_append_len(s, buf, len);
		return;
	}

	if (len < 0x4000) {
		uint16_t enc_len = htons(0x8000 | len);
		g_string_append_len(s, (void *) &enc_len, 2);
		g_string_append_len(s, buf, len);
		return;
	}

	// fragmented - we don't support more than 65535 bytes
	unsigned int mult = len >> 14;
	g_string_append_c(s, 0xc0 | mult);
	mult <<= 14;
	// one portion
	g_string_append_len(s, buf, mult);
	// remainder - may be zero length
	__add_udptl_len(s, buf + mult, len - mult);
}

static void __add_udptl_raw(GString *s, const char *buf, size_t len) {
	assert(len < 0x10000);

	if (len == 0) {
		// add a single zero byte, length 1
		__add_udptl_len(s, "\x00", 1);
		return;
	}

	__add_udptl_len(s, buf, len);
}

static void __add_udptl(GString *s, const str *buf) {
	__add_udptl_raw(s, buf->s, buf->len);
}


static void g_string_null_extend(GString *s, size_t len) {
	if (s->len >= len)
		return;

	size_t oldb = s->len;
	size_t newb = len - s->len;
	g_string_set_size(s, len);
	memset(s->str + oldb, 0, newb);
}

static void spandsp_logging_func(SPAN_LOG_ARGS) {
	if (level <= SPAN_LOG_PROTOCOL_ERROR)
		level = LOG_ERR;
	else if (level <= SPAN_LOG_PROTOCOL_WARNING)
		level = LOG_WARN;
	else
		level = LOG_DEBUG;
	ilogs(spandsp, level, "SpanDSP: %s", text);
}


// call is locked in R or W
static int t38_gateway_handler(t38_core_state_t *stat, void *user_data, const uint8_t *b, int len, int count) {
	struct t38_gateway *tg = user_data;

	// cap the max length of packet we can handle
	if (len < 0 || len >= 0x10000) {
		ilog(LOG_ERR, "Received %i bytes from T.38 encoder - discarding", len);
		return -1;
	}

	ilog(LOG_DEBUG, "Received %i bytes from T.38 encoder", len);

	// build udptl packet: use a conservative guess for required buffer
	GString *s = g_string_sized_new(512);

	// add seqnum
	uint16_t seq = htons(tg->seqnum);
	g_string_append_len(s, (void *) &seq, 2);

	// add primary IFP packet
	str buf = STR_LEN(b, len);
	__add_udptl(s, &buf);

	// add error correction packets
	if (tg->options.fec_span > 1) {
		// forward error correction
		g_string_append_c(s, 0x80);

		// figure out how many packets we have and which span to use
		unsigned int packets = tg->options.fec_span * tg->options.max_ec_entries;
		if (packets > tg->udptl_ec_out.length)
			packets = tg->udptl_ec_out.length;
		unsigned int span = packets / tg->options.max_ec_entries;
		if (!span)
			span = 1;
		packets = span * tg->options.max_ec_entries; // our own packets we use
		unsigned int entries = packets / span; // FEC entries in the output
		if (entries > tg->udptl_ec_out.length)
			entries = tg->udptl_ec_out.length;
		packets = entries * span;

		assert(span < 0x80);
		assert(entries < 0x80);

		g_string_append_c(s, 0x01);
		g_string_append_c(s, span);

		// create needed number of FEC packet entries
		GQueue fec = G_QUEUE_INIT;
		for (int i = 0; i < entries; i++)
			g_queue_push_tail(&fec, g_string_new(""));

		// take each input packet, going backwards in time, and XOR it into
		// the respective output FEC packet
		GList *inp = tg->udptl_ec_out.head;
		for (int i = 0; i < packets; i++) {
			assert(inp != NULL);
			str *ip = inp->data;
			// just keep shifting the list around
			GString *outp = g_queue_pop_head(&fec);

			// extend string as needed
			g_string_null_extend(outp, ip->len);

			for (size_t j = 0; j < ip->len; j++)
				outp->str[j] ^= ip->s[j];

			g_queue_push_tail(&fec, outp);
			inp = inp->next;
		}

		// output list is now complete, but in reverse. append it to output buffer
		GString *ec = g_string_sized_new(512);
		entries = 0;
		int going = 1;
		while (fec.length) {
			GString *outp = g_queue_pop_tail(&fec);
			if (going) {
				if (s->len + ec->len + outp->len > tg->options.max_datagram)
					going = 0;
				else {
					__add_udptl_raw(ec, outp->str, outp->len);
					entries++;
				}
			}
			g_string_free(outp, TRUE);
		}

		g_string_append_c(s, entries);
		g_string_append_len(s, ec->str, ec->len);
		g_string_free(ec, TRUE);
	}
	else {
		// redundancy error correction
		g_string_append_c(s, 0x00);

		GString *ec = g_string_sized_new(512);
		int entries = 0;

		for (GList *l = tg->udptl_ec_out.head; l; l = l->next) {
			str *ec_s = l->data;
			// stop when we exceed max datagram length
			if (s->len + ec->len + ec_s->len > tg->options.max_datagram)
				break;
			// add redundancy packet
			__add_udptl(ec, ec_s);
			entries++;
		}

		// number of entries - must be <0x80 as verified in settings
		g_string_append_c(s, entries);
		g_string_append_len(s, ec->str, ec->len);
		g_string_free(ec, TRUE);
	}

	// done building our packet - add primary to our error correction buffer
	tg->seqnum++;
	unsigned int q_entries = tg->options.max_ec_entries * tg->options.fec_span;
	if (q_entries) {
		while (tg->udptl_ec_out.length >= q_entries) {
			str *ec_s = g_queue_pop_tail(&tg->udptl_ec_out);
			free(ec_s);
		}
		g_queue_push_head(&tg->udptl_ec_out, str_dup(&buf));
	}

	// send our packet if we can
	struct packet_stream *ps = NULL;
	if (tg->t38_media && tg->t38_media->streams.head)
		ps = tg->t38_media->streams.head->data;
	if (ps)
		mutex_lock(&ps->out_lock);
	stream_fd *sfd = NULL;
	if (ps)
		sfd = ps->selected_sfd;
	if (sfd && sfd->socket.fd != -1 && ps->endpoint.address.family != NULL) {
		for (int i = 0; i < count; i++) {
			ilog(LOG_DEBUG, "Sending %u UDPTL bytes", (unsigned int) s->len);
			socket_sendto(&sfd->socket, s->str, s->len, &ps->endpoint);
		}
	}
	else
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unable to send T.38 UDPTL packet due to lack of "
				"socket or stream");
	if (ps)
		mutex_unlock(&ps->out_lock);

	g_string_free(s, TRUE);

	return 0;
}

void __t38_gateway_free(struct t38_gateway *tg) {
	ilog(LOG_DEBUG, "Destroying T.38 gateway");
	if (tg->gw)
		t38_gateway_free(tg->gw);
	if (tg->pcm_player) {
		media_player_stop(tg->pcm_player);
		media_player_put(&tg->pcm_player);
	}
	if (tg->udptl_fec)
		g_hash_table_destroy(tg->udptl_fec);
	g_queue_clear_full(&tg->udptl_ec_out, free);
	packet_sequencer_destroy(&tg->sequencer);
}

// call is locked in R and mp is locked
static bool t38_pcm_player(struct media_player *mp) {
	if (!mp || !mp->media)
		return true;

	struct t38_gateway *tg = mp->media->t38_gateway;
	if (!tg)
		return true;

	if (tg->pcm_media && tg->pcm_media->streams.head
			&& ((struct packet_stream *) tg->pcm_media->streams.head->data)->selected_sfd)
		log_info_stream_fd(((struct packet_stream *) tg->pcm_media->streams.head->data)->selected_sfd);

	ilog(LOG_DEBUG, "Generating T.38 PCM samples");

	mutex_lock(&tg->lock);

	int16_t smp[80];
	int num = t38_gateway_tx(tg->gw, smp, 80);
	if (num <= 0) {
		// use a fixed interval of 10 ms
		timeval_add_usec(&mp->next_run, 10000);
		timerthread_obj_schedule_abs(&mp->tt_obj, &mp->next_run);
		mutex_unlock(&tg->lock);
		return false;
	}

	ilog(LOG_DEBUG, "Generated %i T.38 PCM samples", num);

	// release gateway lock as the media player may trigger a lock on the SSRC objects
	// and this is the wrong lock order
	struct media_player *pcm_player = media_player_get(tg->pcm_player);
	unsigned long long pts = tg->pts;
	tg->pts += num;

	mutex_unlock(&tg->lock);

	// this reschedules our player as well
	media_player_add_packet(pcm_player, (char *) smp, num * 2, num * 1000000 / 8000, pts);
	media_player_put(&pcm_player);

	return false;
}


static void __udptl_packet_free(struct udptl_packet *p) {
	if (p->s)
		free(p->s);
	g_slice_free1(sizeof(*p), p);
}


static void __t38_options_normalise(struct t38_options *opts) {
	if (opts->version < 0)
		opts->version = 0;
	if (opts->fec_span < 1)
		opts->fec_span = 1;
	if (opts->min_ec_entries < 0)
		opts->min_ec_entries = 0;
	if (opts->min_ec_entries >= 0x80)
		opts->min_ec_entries = 0x7f;
	if (opts->max_ec_entries < 0)
		opts->max_ec_entries = 0;
	if (opts->max_ec_entries >= 0x80)
		opts->max_ec_entries = 0x7f;
	if (opts->max_ifp <= 0 || opts->max_ifp >= 0x4000)
		opts->max_ifp = 0x3fff;
	if (opts->max_datagram <= 0 || opts->max_datagram >= 0x4000)
		opts->max_datagram = 0x3fff;
}

static int span_log_level_map(int level) {
	if (level <= LOG_ERR)
		level = SPAN_LOG_PROTOCOL_ERROR;
	else if (level < LOG_DEBUG)
		level = SPAN_LOG_PROTOCOL_WARNING;
	else
		level = SPAN_LOG_DEBUG_3;
	return level;
}

void t38_insert_media_attributes(GString *gs, union sdp_attr_print_arg a, const sdp_ng_flags *flags) {
	struct t38_gateway *tg = a.cm->t38_gateway;
	if (!tg)
		return;

	sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxVersion", "%i", tg->options.version);
	sdp_append_attr(gs, flags, MT_IMAGE, "T38MaxBitRate", "14400");
	sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxRateManagement", "%s",
				tg->options.local_tcf ? "localTFC" : "transferredTCF");
	sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxMaxBuffer", "1800");
	sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxMaxDatagram", "512");

	if (tg->options.max_ec_entries == 0)
		sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxUdpEC", "t38UDPNoEC");
	else if (tg->options.fec_span > 1)
		sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxUdpEC", "t38UDPFEC");
	else
		sdp_append_attr(gs, flags, MT_IMAGE, "T38FaxUdpEC", "t38UDPRedundancy");
	// XXX more options possible here
}


// call is locked in W
int t38_gateway_pair(struct call_media *t38_media, struct call_media *pcm_media,
		const struct t38_options *options)
{
	const char *err = NULL;

	if (!t38_media || !pcm_media || !options)
		return -1;

	struct t38_options opts = *options;
	__t38_options_normalise(&opts);

	// do we have one yet?
	if (t38_media->t38_gateway
			&& t38_media->t38_gateway == pcm_media->t38_gateway)
	{
		// XXX check options here?
		return 0;
	}

	// release old structs, if any
	t38_gateway_put(&t38_media->t38_gateway);
	t38_gateway_put(&pcm_media->t38_gateway);

	ilog(LOG_DEBUG, "Creating new T.38 gateway");

	// create and init new
	__auto_type tg = obj_alloc0(struct t38_gateway, __t38_gateway_free);

	tg->t38_media = t38_media;
	tg->pcm_media = pcm_media;
	mutex_init(&tg->lock);
	tg->udptl_fec = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			(GDestroyNotify) __udptl_packet_free);
	tg->options = opts;

	tg->pcm_pt.payload_type = -1;
	tg->pcm_pt.encoding = STR("PCM-S16LE");
	tg->pcm_pt.encoding_with_params = tg->pcm_pt.encoding;
	tg->pcm_pt.clock_rate = 8000;
	tg->pcm_pt.channels = 1;
	tg->pcm_pt.ptime = 20;

	err = "Failed to init PCM codec";
	ensure_codec_def(&tg->pcm_pt, pcm_media);
	if (!tg->pcm_pt.codec_def)
		goto err;

	err = "Failed to create spandsp T.38 gateway";
	if (!(tg->gw = t38_gateway_init(NULL, t38_gateway_handler, tg)))
		goto err;

	media_player_new(&tg->pcm_player, pcm_media->monologue);
	// even though we call media_player_set_media() here, we need to call it again in
	// t38_gateway_start because our sink might not have any streams added here yet,
	// leaving the media_player setup incomplete
	media_player_set_media(tg->pcm_player, pcm_media);
	tg->pcm_player->run_func = t38_pcm_player;

	// set options
	t38_core_state_t *t38 = t38_gateway_get_t38_core_state(tg->gw);
	t38_gateway_set_ecm_capability(tg->gw, opts.no_ecm ? FALSE : TRUE);
	t38_gateway_set_transmit_on_idle(tg->gw, TRUE);
	t38_gateway_set_supported_modems(tg->gw,
			(opts.no_v17 ? 0 : T30_SUPPORT_V17)
			| (opts.no_v27ter ? 0 : T30_SUPPORT_V27TER)
			| (opts.no_v29 ? 0 : T30_SUPPORT_V29)
			| (opts.no_v34 ? 0 : T30_SUPPORT_V34HDX)
			| (opts.no_iaf ? 0 : T30_SUPPORT_IAF));
	t38_set_t38_version(t38, opts.version);
	t38_set_data_rate_management_method(t38,
			opts.local_tcf ? 1 : 2);
	t38_set_fill_bit_removal(t38, opts.fill_bit_removal);
	t38_set_mmr_transcoding(t38, opts.transcoding_mmr);
	t38_set_jbig_transcoding(t38, opts.transcoding_jbig);
	t38_set_max_datagram_size(t38, opts.max_ifp);

	logging_state_t *ls = t38_gateway_get_logging_state(tg->gw);
	my_span_set_log(ls, spandsp_logging_func);
	span_log_set_level(ls, span_log_level_map(get_log_level(spandsp)));

	packet_sequencer_init(&tg->sequencer, (GDestroyNotify) __udptl_packet_free);
	tg->sequencer.seq = 0;

	// done - add references to media structs
	t38_media->t38_gateway = tg;
	pcm_media->t38_gateway = obj_get(tg);

	// add SDP options for T38
	t38_media->sdp_attr_print = t38_insert_media_attributes;

	return 0;

err:
	if (err)
		ilog(LOG_ERR, "Failed to create T.38 gateway: %s", err);
	t38_gateway_put(&tg);
	return -1;
}


// call is locked in W
void t38_gateway_start(struct t38_gateway *tg, str_case_value_ht codec_set) {
	if (!tg)
		return;

	// set up our player first
	media_player_set_media(tg->pcm_player, tg->pcm_media);
	if (media_player_setup(tg->pcm_player, &tg->pcm_pt, NULL, codec_set))
		return;

	// now start our player if we can or should
	// already running?
	if (tg->pcm_player->next_run.tv_sec)
		return;

	// only start our player only if we can send both ways
	if (!tg->pcm_media->codecs.codec_prefs.length)
		return;
	if (!tg->pcm_media->streams.length)
		return;
	if (!tg->t38_media->streams.length)
		return;

	struct packet_stream *ps;
	ps = tg->pcm_media->streams.head->data;
	if (!PS_ISSET(ps, FILLED))
		return;
	ps = tg->t38_media->streams.head->data;
	if (!PS_ISSET(ps, FILLED))
		return;

	ilog(LOG_DEBUG, "Starting T.38 PCM player");

	// start off PCM player
	tg->pcm_player->next_run = rtpe_now;
	timerthread_obj_schedule_abs(&tg->pcm_player->tt_obj, &tg->pcm_player->next_run);
}


// call is locked in R
int t38_gateway_input_samples(struct t38_gateway *tg, int16_t amp[], int len) {
	if (!tg)
		return 0;
	if (len <= 0)
		return 0;

	ilog(LOG_DEBUG, "Adding %i samples to T.38 encoder", len);

	mutex_lock(&tg->lock);

	int left = t38_gateway_rx(tg->gw, amp, len);
	if (left)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "%i PCM samples were not processed by the T.38 gateway",
				left);

	mutex_unlock(&tg->lock);

	return 0;
}


static ssize_t __get_udptl_len(str *s) {
	ssize_t ret;

	if (s->len < 1)
		return -1;

	if (!(s->s[0] & 0x80)) {
		ret = s->s[0];
		str_shift(s, 1);
		return ret;
	}

	if (s->len < 2)
		return -1;

	if (!(s->s[0] & 0x40)) {
		ret = ntohs(*((uint16_t *) s->s)) & 0x3fff;
		str_shift(s, 2);
		return ret;
	}

	ilog(LOG_INFO | LOG_FLAG_LIMIT, "Decoding UDPTL fragments is not supported");
	return -1;
}

static int __get_udptl(str *piece, str *s) {
	ssize_t len = __get_udptl_len(s);
	if (len < 0)
		return -1;

	return str_shift_ret(s, len, piece);
}


static struct udptl_packet *__make_udptl_packet(const str *piece, uint16_t seq) {
	struct udptl_packet *up = g_slice_alloc0(sizeof(*up));
	up->p.seq = seq;
	up->s = str_dup(piece);
	return up;
}

static void __fec_save(struct t38_gateway *tg, const str *piece, uint16_t seq) {
	struct udptl_packet *up = __make_udptl_packet(piece, seq);
	g_hash_table_insert(tg->udptl_fec, GUINT_TO_POINTER(seq), up);
}

int t38_gateway_input_udptl(struct t38_gateway *tg, const str *buf) {
	const char *err = NULL;
	struct udptl_packet *up = NULL;

	if (!tg)
		return 0;
	if (!buf || !buf->len)
		return 0;

	if (buf->len < 4) {
		ilog(LOG_INFO | LOG_FLAG_LIMIT, "Ignoring short UDPTL packet (%zu bytes)", buf->len);
		return 0;
	}

	ilog(LOG_DEBUG, "Processing %zu UDPTL bytes", buf->len);

	str s = *buf;
	str piece;

	// get seq num
	uint16_t seq;
	if (str_shift_ret(&s, 2, &piece))
		goto err_nolock;
	seq = ntohs(*((uint16_t *) piece.s));

	err = "Invalid primary UDPTL packet";
	if (__get_udptl(&piece, &s))
		goto err;

	ilog(LOG_DEBUG, "Received primary IFP packet, len %zu, seq %i", piece.len, seq);
	str primary = piece;
	up = __make_udptl_packet(&primary, seq);

	err = "Error correction mode byte missing";
	if (str_shift_ret(&s, 1, &piece))
		goto err_nolock;
	char fec = piece.s[0];

	mutex_lock(&tg->lock);

	long diff = seq - up->p.seq;
	if (diff > 100 || diff < -100) {
		ilog(LOG_INFO | LOG_FLAG_LIMIT, "Ignoring UDPTL packet with wildly off seq (%u <> %u)",
				(unsigned int) seq, (unsigned int) up->p.seq);
		err = NULL;
		goto err;
	}

	// XXX possible short path here without going through the sequencer
	int ret = packet_sequencer_insert(&tg->sequencer, &up->p);
	if (ret < 0) {
		// main seq is dupe - everything else must be dupe too
		__udptl_packet_free(up);
		goto out;
	}

	up = NULL;

	if (!(fec & 0x80)) {
		// packet redundancy
		if (packet_sequencer_next_ok(&tg->sequencer))
			goto seq_ok;

		// process EC packets as well as something's wrong
		ssize_t num_packets = __get_udptl_len(&s);
		err = "Invalid number of EC packets";
		if (num_packets < 0 || num_packets > 100)
			goto err;
		for (int i = 0; i < num_packets; i++) {
			if (__get_udptl(&piece, &s)) {
				ilog(LOG_WARN | LOG_FLAG_LIMIT,
						"Invalid UDPTL error correction packet at index %i",
						i);
				break;
			}
			// ignore zero-length packets
			if (!piece.len)
				continue;
			ilog(LOG_DEBUG, "Received secondary IFP packet, len %zu, seq %i", piece.len,
					seq - 1 - i);
			up = __make_udptl_packet(&piece, seq - 1 - i);
			packet_sequencer_insert(&tg->sequencer, &up->p);
			up = NULL;

			// can we stop here?
			if (packet_sequencer_next_ok(&tg->sequencer))
				break;
		}
	}
	else {
		// FEC
		// start by saving the new packet
		__fec_save(tg, &primary, seq);

		if (packet_sequencer_next_ok(&tg->sequencer))
			goto seq_ok;

		// process all FEC packets
		err = "Invalid number of FEC packets";
		if (str_shift_ret(&s, 2, &piece))
			goto err;
		if (piece.s[0] != 0x01)
			goto err;
		unsigned int span = piece.s[1];
		if (span <= 0 || span >= 0x80)
			goto err;
		ssize_t entries = __get_udptl_len(&s);
		if (entries < 0 || entries > 100)
			goto err;

		// first seq we can possibly recover
		uint16_t seq_start = seq - span * entries;

		while (entries) {
			// get our entry
			if (__get_udptl(&piece, &s)) {
				ilog(LOG_WARN | LOG_FLAG_LIMIT,
						"Invalid UDPTL error correction packet at index %i",
						seq_start);
				break;
			}
			// check each of the entries covered by `span`
			for (int i = 0; i < span; i++) {
				uint16_t seq_fec = seq_start + i * span;
				// skip if we already know this packet
				if (g_hash_table_lookup(tg->udptl_fec, GUINT_TO_POINTER(seq_fec)))
					continue;

				// can we recover it? we need all other packets from the series
				GString *rec_s = g_string_new("");
				int complete = 1;

				for (int j = 0; j < span; j++) {
					uint16_t seq_rec = seq_start + i * span;
					if (seq_rec == seq_fec)
						continue;
					struct udptl_packet *recp =
						g_hash_table_lookup(tg->udptl_fec, GUINT_TO_POINTER(seq_rec));
					if (!recp) {
						ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unable to recover UDPTL FEC "
								"packet with seq %i due to missing seq %i",
								seq_fec, seq_rec);
						complete = 0;
						break;
					}

					// XOR in packet
					for (size_t k = 0; k < recp->s->len; k++)
						rec_s->str[k] ^= recp->s->s[k];
				}

				if (complete) {
					ilog(LOG_WARN | LOG_FLAG_LIMIT, "Recovered UDPTL "
							"packet with seq %i from FEC",
							seq_fec);

					str rec_str = STR_GS(rec_s);
					__fec_save(tg, &rec_str, seq_fec);
					up = __make_udptl_packet(&rec_str, seq_fec);
					packet_sequencer_insert(&tg->sequencer, &up->p);
					up = NULL;
				}

				g_string_free(rec_s, TRUE);

				// no point in continuing further: one packet was missing, which means
				// that no other packet in this span can be recovered
				break;
			}

			// proceed to next entry
			entries--;
			seq_start++;
		}
	}

seq_ok:;

	t38_core_state_t *t38 = t38_gateway_get_t38_core_state(tg->gw);

	// process any packets that we can
	while (1) {
		up = packet_sequencer_next_packet(&tg->sequencer);
		if (!up)
			break;

		ilog(LOG_DEBUG, "Processing %zu IFP bytes, seq %i", up->s->len, up->p.seq);

		t38_core_rx_ifp_packet(t38, (uint8_t *) up->s->s, up->s->len, up->p.seq);

		__udptl_packet_free(up);
	}

out:
	mutex_unlock(&tg->lock);
	return 0;

err:
	mutex_unlock(&tg->lock);
err_nolock:
	if (err)
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "Failed to process UDPTL/T.38/IFP packet: %s", err);
	if (up)
		__udptl_packet_free(up);
	return -1;
}


void t38_gateway_stop(struct t38_gateway *tg) {
	if (!tg)
		return;
	if (tg->pcm_player)
		media_player_stop(tg->pcm_player);
	if (tg->t38_media)
		tg->t38_media->sdp_attr_print = sdp_insert_media_attributes;
}


void t38_init(void) {
	my_span_mh(NULL);
}



#endif
