#include "codecmod.h"
#include "loglib.h"
#include "bitstr.h"


static int codeclib_set_av_opt_intstr(encoder_t *enc, const char *opt, str *val) {
	int i = val ? str_to_i(val, -1) : -1;
	if (i == -1) {
		ilog(LOG_WARN, "Failed to parse '" STR_FORMAT "' as integer value for ffmpeg option '%s'",
				STR_FMT0(val), opt);
		return -1;
	}
	return codeclib_set_av_opt_int(enc, opt, i);
}



static const unsigned int amr_bitrates[AMR_FT_TYPES] = {
	4750, // 0
	5150, // 1
	5900, // 2
	6700, // 3
	7400, // 4
	7950, // 5
	10200, // 6
	12200, // 7
	0, // comfort noise // 8
	0, // comfort noise // 9
	0, // comfort noise // 10
	0, // comfort noise // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_bits_per_frame[AMR_FT_TYPES] = {
	95, // 4.75 kbit/s // 0
	103, // 5.15 kbit/s // 1
	118, // 5.90 kbit/s // 2
	134, // 6.70 kbit/s // 3
	148, // 7.40 kbit/s // 4
	159, // 7.95 kbit/s // 5
	204, // 10.2 kbit/s // 6
	244, // 12.2 kbit/s // 7
	40, // comfort noise // 8
	40, // comfort noise // 9
	40, // comfort noise // 10
	40, // comfort noise // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_wb_bitrates[AMR_FT_TYPES] = {
	6600, // 0
	8850, // 1
	12650, // 2
	14250, // 3
	15850, // 4
	18250, // 5
	19850, // 6
	23050, // 7
	23850, // 8
	0, // comfort noise // 9
	0, // invalid // 10
	0, // invalid // 11
	0, // invalid // 12
	0, // invalid // 13
};
static const unsigned int amr_wb_bits_per_frame[AMR_FT_TYPES] = {
	132, // 6.60 kbit/s // 0
	177, // 8.85 kbit/s // 1
	253, // 12.65 kbit/s // 2
	285, // 14.25 kbit/s // 3
	317, // 15.85 kbit/s // 4
	365, // 18.25 kbit/s // 5
	397, // 19.85 kbit/s // 6
	461, // 23.05 kbit/s // 7
	477, // 23.85 kbit/s // 8
	40, // comfort noise // 9
	0, // invalid // 10
	0, // invalid // 11
	0, // invalid // 12
	0, // invalid // 13
};
static void amr_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("octet-align"):
			if (token->len == 1 && token->s[0] == '1')
				opts->amr.octet_aligned = 1;
			break;
		case CSH_LOOKUP("crc"):
			if (token->len == 1 && token->s[0] == '1') {
				opts->amr.octet_aligned = 1;
				opts->amr.crc = 1;
			}
			break;
		case CSH_LOOKUP("robust-sorting"):
			if (token->len == 1 && token->s[0] == '1') {
				opts->amr.octet_aligned = 1;
				opts->amr.robust_sorting = 1;
			}
			break;
		case CSH_LOOKUP("interleaving"):
			opts->amr.octet_aligned = 1;
			opts->amr.interleaving = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("mode-set"):;
			str mode;
			while (str_token_sep(&mode, token, ',')) {
				int m = str_to_i(&mode, -1);
				if (m < 0 || m >= AMR_FT_TYPES)
					continue;
				opts->amr.mode_set |= (1 << m);
			}
			break;
		case CSH_LOOKUP("mode-change-period"):
			opts->amr.mode_change_period = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("mode-change-neighbor"):
			if (token->len == 1 && token->s[0] == '1')
				opts->amr.mode_change_neighbor = 1;
			break;
	}
}
static bool amr_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	// Per RFC 4867 section 8.1, missing fmtp parameters use defaults (bandwidth-efficient mode, no
	// CRC, no robust-sorting, no interleaving). Parse whatever is present. Absent fields keep their
	// defaults.
	if (fmtp && fmtp->len)
		codeclib_key_value_parse(fmtp, true, amr_parse_format_cb, f);
	return true;
}
static void amr_set_encdec_options(codec_options_t *opts, codec_def_t *def) {
	if (!strcmp(def->rtpname, "AMR")) {
		opts->amr.bits_per_frame = amr_bits_per_frame;
		opts->amr.bitrates = amr_bitrates;
	}
	else {
		opts->amr.bits_per_frame = amr_wb_bits_per_frame;
		opts->amr.bitrates = amr_wb_bitrates;
	}
}
static void amr_set_dec_codec_options(str *key, str *value, void *data) {
	decoder_t *dec = data;

	if (!str_cmp(key, "CMR-interval"))
		dec->codec_options.amr.cmr_interval_us = str_to_i(value, 0) * 1000L;
	else if (!str_cmp(key, "mode-change-interval"))
		dec->codec_options.amr.mode_change_interval_us = str_to_i(value, 0) * 1000L;

}
static void amr_set_enc_codec_options(str *key, str *value, void *data) {
	encoder_t *enc = data;

	if (!str_cmp(key, "CMR-interval"))
		; // not an encoder option
	else if (!str_cmp(key, "mode-change-interval"))
		; // not an encoder option
	else {
		// our string might not be null terminated
		char *s = g_strdup_printf(STR_FORMAT, STR_FMT(key));
		codeclib_set_av_opt_intstr(enc, s, value);
		g_free(s);
	}
}
static void amr_set_enc_options(encoder_t *enc, const str *codec_opts) {
	amr_set_encdec_options(&enc->codec_options, enc->def);

	codeclib_key_value_parse(codec_opts, true, amr_set_enc_codec_options, enc);

	// if a mode-set was given, pick the highest supported bitrate
	if (enc->format_options.amr.mode_set) {
		int max_bitrate = enc->avc.avcctx->bit_rate;
		int use_bitrate = 0;
		for (int i = 0; i < AMR_FT_TYPES; i++) {
			if (!(enc->format_options.amr.mode_set & (1 << i)))
				continue;
			unsigned int br = enc->codec_options.amr.bitrates[i];
			// we depend on the list being in ascending order, with
			// invalid modes at the end
			if (!br) // end of list
				break;
			if (br > max_bitrate && use_bitrate) // done
				break;
			use_bitrate = br;
		}
		if (!use_bitrate)
			ilog(LOG_WARN, "Unable to determine a valid bitrate from %s mode-set, using default",
					enc->def->rtpname);
		else {
			ilog(LOG_DEBUG, "Using %i as initial %s bitrate based on mode-set",
					use_bitrate, enc->def->rtpname);
			enc->avc.avcctx->bit_rate = use_bitrate;
		}
	}
}
static void amr_set_dec_options(decoder_t *dec, const str *codec_opts) {
	amr_set_encdec_options(&dec->codec_options, dec->def);
	codeclib_key_value_parse(codec_opts, true, amr_set_dec_codec_options, dec);
}
static int amr_mode_set_cmp(unsigned int a, unsigned int b) {
	if (a && b) {
		// `a` must be broader than `b`:
		// `b` must not have any bits set that `a` has set
		if (a == b)
			return 0;
		else if ((b & ~a) == 0)
			return 1;
		else
			return -1;
	}
	else if (!a && b) // `a` is broader (allow anything) than `b` (restricted)
		return 1;
	else if (a && !b)
		return -1;
	return 0;
}
static int amr_format_cmp(const struct rtp_payload_type *A, const struct rtp_payload_type *B) {
	// params must have been parsed successfully
	if (!A->format.fmtp_parsed || !B->format.fmtp_parsed)
		return -1;

	__auto_type a = &A->format.parsed.amr;
	__auto_type b = &B->format.parsed.amr;

	// reject anything that is outright incompatible (RFC 4867, 8.3.1)
	if (a->octet_aligned != b->octet_aligned)
		return -1;
	if (a->crc != b->crc)
		return -1;
	if (a->interleaving != b->interleaving)
		return -1;
	if (a->robust_sorting != b->robust_sorting)
		return -1;

	// determine whether codecs are compatible
	int compat = 0;

	if (a->mode_change_neighbor != b->mode_change_neighbor)
		compat++;
	if (a->mode_change_period != b->mode_change_period)
		compat++;

	int match = amr_mode_set_cmp(a->mode_set, b->mode_set);
	if (match == 1)
		compat++;
	else if (match == -1)
		return -1;

	return (compat == 0) ? 0 : 1;
}

static void amr_bitrate_tracker(decoder_t *dec, unsigned int ft) {
	if (dec->codec_options.amr.cmr_interval_us <= 0)
		return;

	if (dec->avc.amr.tracker_end
			&& dec->avc.amr.tracker_end >= rtpe_now) {
		// analyse the data we gathered
		int next_highest = -1;
		int lowest_used = -1;
		for (int i = 0; i < AMR_FT_TYPES; i++) {
			unsigned int br = dec->codec_options.amr.bitrates[i];
			if (!br)
				break; // end of list

			// ignore restricted modes
			if (dec->format_options.amr.mode_set) {
				if (!(dec->format_options.amr.mode_set & (1 << i)))
					continue;
			}

			// would this be a "next step up" mode?
			if (next_highest == -1)
				next_highest = i;

			// did we see any frames?
			if (!dec->avc.amr.bitrate_tracker[i])
				continue;

			next_highest = -1;
			lowest_used = i;
		}

		if (lowest_used != -1 && next_highest != -1) {
			// we can request a switch up
			ilog(LOG_DEBUG, "Sending %s CMR to request upping bitrate to %u",
					dec->def->rtpname, dec->codec_options.amr.bitrates[next_highest]);
			decoder_event(dec, CE_AMR_SEND_CMR, GINT_TO_POINTER(next_highest));
		}

		// and reset tracker
		ZERO(dec->avc.amr.tracker_end);
	}

	if (!dec->avc.amr.tracker_end) {
		// init
		ZERO(dec->avc.amr.bitrate_tracker);
		dec->avc.amr.tracker_end = rtpe_now;
		dec->avc.amr.tracker_end += dec->codec_options.amr.cmr_interval_us;
	}

	dec->avc.amr.bitrate_tracker[ft]++;
}
static int amr_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	const char *err = NULL;
	g_auto(GQueue) toc = G_QUEUE_INIT;

	if (!data || !data->s)
		goto err;

	bitstr d;
	bitstr_init(&d, data);

	unsigned int ill = 0, ilp = 0;

	unsigned char cmr_chr[2];
	str cmr = STR_CONST_BUF(cmr_chr);
	err = "no CMR";
	if (bitstr_shift_ret(&d, 4, &cmr))
		goto err;

	unsigned int cmr_int = cmr_chr[0] >> 4;
	if (cmr_int != 15) {
		decoder_event(dec, CE_AMR_CMR_RECV, GUINT_TO_POINTER(cmr_int));
		dec->avc.amr.last_cmr = rtpe_now;
	}
	else if (dec->codec_options.amr.mode_change_interval_us) {
		// no CMR, check if we're due to do our own mode change
		if (!dec->avc.amr.last_cmr) // start tracking now
			dec->avc.amr.last_cmr = rtpe_now;
		else if (rtpe_now - dec->avc.amr.last_cmr
				>= dec->codec_options.amr.mode_change_interval_us) {
			// switch up if we can
			decoder_event(dec, CE_AMR_CMR_RECV, GUINT_TO_POINTER(0xffff));
			dec->avc.amr.last_cmr = rtpe_now;
		}
	}

	if (dec->format_options.amr.octet_aligned) {
		if (bitstr_shift(&d, 4))
			goto err;

		if (dec->format_options.amr.interleaving) {
			unsigned char ill_ilp_chr[2];
			str ill_ilp = STR_CONST_BUF(ill_ilp_chr);
			err = "no ILL/ILP";
			if (bitstr_shift_ret(&d, 8, &ill_ilp))
				goto err;
			ill = ill_ilp_chr[0] >> 4;
			ilp = ill_ilp_chr[0] & 0xf;
		}
	}

	err = "ILP > ILL";
	if (ilp > ill)
		goto err;
	err = "interleaving unimplemented";
	if (ill)
		goto err;

	// TOC
	int num_crcs = 0;
	while (1) {
		unsigned char toc_byte[2];
		str toc_entry = STR_CONST_BUF(toc_byte);
		err = "missing TOC entry";
		if (bitstr_shift_ret(&d, 6, &toc_entry))
			goto err;

		if (dec->format_options.amr.octet_aligned)
			if (bitstr_shift(&d, 2))
				goto err;

		unsigned char ft = (toc_byte[0] >> 3) & 0xf;
		if (ft != 14 && ft != 15) {
			num_crcs++;
			err = "invalid frame type";
			if (ft >= AMR_FT_TYPES)
				goto err;
			if (dec->codec_options.amr.bits_per_frame[ft] == 0)
				goto err;
		}

		g_queue_push_tail(&toc, GUINT_TO_POINTER(toc_byte[0]));

		// no F bit = last TOC entry
		if (!(toc_byte[0] & 0x80))
			break;
	}

	if (dec->format_options.amr.crc) {
		// CRCs is one byte per frame
		err = "missing CRC entry";
		if (bitstr_shift(&d, num_crcs * 8))
			goto err;
		// XXX use/check CRCs
	}

	while (toc.length) {
		unsigned char toc_byte = GPOINTER_TO_UINT(g_queue_pop_head(&toc));
		unsigned char ft = (toc_byte >> 3) & 0xf;
		if (ft >= AMR_FT_TYPES) // invalid
			continue;

		unsigned int bits = dec->codec_options.amr.bits_per_frame[ft];

		// AMR decoder expects an octet aligned TOC byte plus the payload
		unsigned char frame_buf[(bits + 7) / 8 + 1 + 1];
		str frame = STR_CONST_BUF(frame_buf);
		str_shift(&frame, 1);
		err = "short frame";
		if (bitstr_shift_ret(&d, bits, &frame))
			goto err;

		// add TOC byte
		str_unshift(&frame, 1);
		frame.s[0] = toc_byte & 0x7c; // strip F bit, keep FT and Q, zero padding (01111100)

		if (dec->format_options.amr.octet_aligned && (bits % 8) != 0) {
			unsigned int padding_bits = 8 - (bits % 8);
			if (bitstr_shift(&d, padding_bits))
				goto err;
		}

		err = "failed to decode AMR data";
		if (bits == 40) {
			// SID
			if (dec->dtx.method_id == DTX_NATIVE) {
				if (avc_decoder_input(dec, &frame, out))
					goto err;
			}
			else {
				// use the DTX generator to replace SID
				if (dec->dtx.do_dtx(dec, out, 20))
					goto err;
			}
		}
		else {
			if (avc_decoder_input(dec, &frame, out))
				goto err;
		}

		amr_bitrate_tracker(dec, ft);
	}

	return 0;

err:
	if (err)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error unpacking AMR packet: %s", err);

	return -1;
}
static unsigned int amr_encoder_find_next_mode(encoder_t *enc) {
	int mode = -1;
	for (int i = 0; i < AMR_FT_TYPES; i++) {
		int br = enc->codec_options.amr.bitrates[i];
		if (!br) // end of list
			break;
		if (br == enc->avc.avcctx->bit_rate) {
			mode = i;
			break;
		}
	}
	if (mode == -1)
		return -1;
	int next_mode = mode + 1;
	// if modes are restricted, find the next one up
	if (enc->format_options.amr.mode_set) {
		// is there anything?
		if ((1 << next_mode) > enc->format_options.amr.mode_set)
			return -1;
		int next_up = -1;
		for (; next_mode < AMR_FT_TYPES; next_mode++) {
			if (!(enc->format_options.amr.mode_set & (1 << next_mode)))
				continue;
			next_up = next_mode;
			break;
		}
		if (next_up == -1)
			return -1;
		next_mode = next_up;
	}
	// valid mode?
	if (next_mode >= AMR_FT_TYPES || enc->codec_options.amr.bitrates[next_mode] == 0)
		return -1;
	return next_mode;
}
static void amr_encoder_mode_change(encoder_t *enc) {
	if (enc->callback.amr.cmr_in_ts == enc->avc.amr.cmr_in_ts)
		return;
	// mode change requested: check if this is allowed right now
	if (enc->format_options.amr.mode_change_period == 2 && (enc->avc.amr.pkt_seq & 1) != 0)
		return;
	unsigned int cmr = enc->callback.amr.cmr_in;
	if (cmr == 0xffff)
		cmr = amr_encoder_find_next_mode(enc);
	if (cmr >= AMR_FT_TYPES)
		return;
	// ignore CMR for invalid modes
	if (enc->format_options.amr.mode_set && !(enc->format_options.amr.mode_set & (1 << cmr)))
		return;
	int req_br = enc->codec_options.amr.bitrates[cmr];
	if (!req_br)
		return;
	int cmr_done = 1;
	if (enc->format_options.amr.mode_change_neighbor) {
		// handle non-neighbour mode changes
		int cur_br = enc->avc.avcctx->bit_rate;
		// step up or down from the requested bitrate towards the current one
		int cmr_diff = (req_br > cur_br) ? -1 : 1;
		int neigh_br = req_br;
		int cmr_br = req_br;
		while (1) {
			// step up or down towards the current bitrate
			cmr += cmr_diff;
			// still in bounds?
			if (cmr >= AMR_FT_TYPES)
				break;
			cmr_br = enc->codec_options.amr.bitrates[cmr];
			if (cmr_br == cur_br)
				break;
			// allowed by mode set?
			if (enc->format_options.amr.mode_set) {
				if (!(enc->format_options.amr.mode_set & (1 << cmr)))
					continue; // go to next mode
			}
			// valid bitrate - continue stepping
			neigh_br = cmr_br;
		}
		// did we finish stepping or is there more to go?
		if (neigh_br != req_br)
			cmr_done = 0;
		req_br = neigh_br; // set to this
	}
	enc->avc.avcctx->bit_rate = req_br;
	if (cmr_done)
		enc->avc.amr.cmr_in_ts = enc->callback.amr.cmr_in_ts;
}
static void amr_encoder_got_packet(encoder_t *enc) {
	amr_encoder_mode_change(enc);
	enc->avc.amr.pkt_seq++;
}
static int packetizer_amr(AVPacket *pkt, GString *buf, str *output, size_t num_bytes, encoder_t *enc,
		int64_t *__restrict pts, int64_t *__restrict duration)
{
	assert(pkt->size >= 1);

	// CMR + TOC byte (already included) + optional ILL/ILP + optional CRC + payload
	if (output->len < pkt->size + 3) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Output AMR packet size too small (%zu < %i + 3)",
				output->len, pkt->size);
		return -1;
	}

	unsigned char toc = pkt->data[0];
	unsigned char ft = (toc >> 3) & 0xf;
	if (ft > 15) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received bogus AMR FT %u from encoder", ft);
		return -1;
	}
	if (ft >= 14) {
		// NO_DATA or SPEECH_LOST
		return -1;
	}
	assert(ft < AMR_FT_TYPES); // internal bug
	unsigned int bits = enc->codec_options.amr.bits_per_frame[ft];
	if (bits == 0) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Received bogus AMR FT %u from encoder", ft);
		return -1;
	}

	unsigned char *s = (unsigned char *) output->s; // for safe bit shifting

	*pts = pkt->pts;
	*duration = enc->actual_format.clockrate * 20LL / 1000; // 160 or 320

	s[0] = '\xf0'; // no CMR req (4 bits)

	// or do we have a CMR?
	if (!enc->avc.amr.cmr_out_seq) {
		if (enc->avc.amr.cmr_out_ts != enc->callback.amr.cmr_out_ts) {
			enc->avc.amr.cmr_out_seq += 3; // make this configurable?
			enc->avc.amr.cmr_out_ts = enc->callback.amr.cmr_out_ts;
		}
	}
	if (enc->avc.amr.cmr_out_seq) {
		enc->avc.amr.cmr_out_seq--;
		unsigned int cmr = enc->callback.amr.cmr_out;
		if (cmr < AMR_FT_TYPES && enc->codec_options.amr.bitrates[cmr])
			s[0] = cmr << 4;
	}

	if (enc->format_options.amr.octet_aligned) {
		unsigned int offset = 1; // CMR byte
		if (enc->format_options.amr.interleaving)
			s[offset++] = 0; // no interleaving
		if (enc->format_options.amr.crc)
			s[offset++] = 0; // not implemented
		memcpy(s + offset, pkt->data, pkt->size);
		output->len = pkt->size + offset;
		return 0;
	}

	// bit shift TOC byte in (6 bits)
	s[0] |= pkt->data[0] >> 4;
	s[1] = (pkt->data[0] & 0x0c) << 4;

	// bit shift payload in (shifted by 4+6 = 10 bits = 1 byte + 2 bits
	for (int i = 1; i < pkt->size; i++) {
		s[i] |= pkt->data[i] >> 2;
		s[i+1] = pkt->data[i] << 6;
	}

	// is the last byte just padding?
	bits += 4 + 6; // CMR and TOC
	unsigned int bytes = (bits + 7) / 8;
	output->len = bytes;

	return 0;
}
static int amr_dtx(decoder_t *dec, GQueue *out, int ptime) {
	// ignore ptime, must be 20
	ilog(LOG_DEBUG, "pushing empty/lost frame to AMR decoder");
	unsigned char frame_buf[1];
	frame_buf[0] = 0xf << 3; // no data
	str frame = STR_CONST_BUF(frame_buf);
	if (avc_decoder_input(dec, &frame, out))
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error while writing 'no data' frame to AMR decoder");
	return 0;
}




static const codec_type_t codec_type_amr = {
	.def_init = avc_def_init,
	.decoder_init = avc_decoder_init,
	.decoder_input = amr_decoder_input,
	.decoder_close = avc_decoder_close,
	.encoder_init = avc_encoder_init,
	.encoder_input = avc_encoder_input,
	.encoder_got_packet = amr_encoder_got_packet,
	.encoder_close = avc_encoder_close,
};

static const dtx_method_t dtx_method_amr = {
	.method_id = DTX_NATIVE,
	.do_dtx = amr_dtx,
};

static const codec_def_t amr = {
		.rtpname = "AMR",
		.avcodec_id = AV_CODEC_ID_AMR_NB,
		.avcodec_name_enc = "libopencore_amrnb",
		.avcodec_name_dec = "libopencore_amrnb",
		.default_clockrate = 8000,
		.default_channels = 1,
		.default_bitrate = 6700,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.format_parse = amr_format_parse,
		.format_cmp = amr_format_cmp,
		.default_fmtp = "octet-align=1;mode-change-capability=2",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 12200 / 8000 = 1.525 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
		.amr = 1,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_amr,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},

};
static const codec_def_t amr_wb = {
		.rtpname = "AMR-WB",
		.avcodec_id = AV_CODEC_ID_AMR_WB,
		.avcodec_name_enc = "libvo_amrwbenc",
		.avcodec_name_dec = "libopencore_amrwb",
		.default_clockrate = 16000,
		.default_channels = 1,
		.default_bitrate = 14250,
		.default_ptime = 20,
		.minimum_ptime = 20,
		.format_parse = amr_format_parse,
		.format_cmp = amr_format_cmp,
		.default_fmtp = "octet-align=1;mode-change-capability=2",
		.packetizer = packetizer_amr,
		.bits_per_sample = 2, // max is 23850 / 16000 = 1.490625 bits per sample, rounded up
		.media_type = MT_AUDIO,
		.codec_type = &codec_type_amr,
		.set_enc_options = amr_set_enc_options,
		.set_dec_options = amr_set_dec_options,
		.amr = 1,
		.dtx_methods = {
			[DTX_NATIVE] = &dtx_method_amr,
			[DTX_SILENCE] = &dtx_method_silence,
			[DTX_CN] = &dtx_method_cn,
		},
};



__attribute__((constructor))
static void init(void) {
        codeclib_register_codec(&amr);
        codeclib_register_codec(&amr_wb);
}
