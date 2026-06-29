#include "codecmod.h"
#include <dlfcn.h>
#include "loglib.h"
#include "fix_frame_channel_layout.compat"


static void *evs_lib_handle;
static unsigned int evs_decoder_size;
static unsigned int evs_encoder_size;
static unsigned int evs_encoder_ind_list_size;

static void (*evs_init_decoder)(void *);
static void (*evs_init_encoder)(void *);
static void (*evs_destroy_decoder)(void *);
static void (*evs_destroy_encoder)(void *);
static void (*evs_set_encoder_opts)(void *, unsigned long, void *);
static void (*evs_set_encoder_brate)(void *, unsigned long br, unsigned int bwidth,
		unsigned int mode, unsigned int amr);
static void (*evs_set_decoder_Fs)(void *, unsigned long);
static void (*evs_enc_in)(void *, const uint16_t *s, const uint16_t n);
static void (*evs_amr_enc_in)(void *, const uint16_t *s, const uint16_t n);
static void (*evs_enc_out)(void *, unsigned char *buf, uint16_t *len);
static void (*evs_dec_in)(void *, char *in, uint16_t len, uint16_t amr_mode, uint16_t core_mode,
		uint16_t q_bit, uint16_t partial_frame, uint16_t next_type);
static void (*evs_dec_out)(void *, void *, int frame_mode); // frame_mode=1: missing
static void (*evs_dec_inc_frame)(void *);
static void (*evs_amr_dec_out)(void *, void *);
static void (*evs_syn_output)(float *in, const uint16_t len, int16_t *out);
static void (*evs_reset_enc_ind)(void *);



static void evs_load_so(const char *path) {
	if (!path)
		return;

	evs_lib_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!evs_lib_handle)
		die("Failed to open EVS codec .so '%s': %s", path, dlerror());

	static unsigned int (*get_evs_decoder_size)(void);
	static unsigned int (*get_evs_encoder_size)(void);
	static unsigned int (*get_evs_encoder_ind_list_size)(void);

	// flp codec?
	evs_init_decoder = dlsym(evs_lib_handle, "init_decoder");
	if (!evs_init_decoder) {
		// fx codec?
		evs_init_decoder = dlsym_assert(evs_lib_handle, "init_decoder_fx", path);
		evs_init_encoder = dlsym_assert(evs_lib_handle, "init_encoder_fx", path);
		evs_destroy_encoder = dlsym_assert(evs_lib_handle, "destroy_encoder_fx", path);
		evs_enc_in = dlsym_assert(evs_lib_handle, "evs_enc_fx", path);
		evs_amr_enc_in = dlsym_assert(evs_lib_handle, "amr_wb_enc_fx", path);
		evs_reset_enc_ind = dlsym_assert(evs_lib_handle, "reset_indices_enc_fx", path);
		evs_dec_in = dlsym_assert(evs_lib_handle, "read_indices_from_djb_fx", path);
		evs_dec_out = dlsym_assert(evs_lib_handle, "evs_dec_fx", path);
		evs_amr_dec_out = dlsym_assert(evs_lib_handle, "amr_wb_dec_fx", path);
	}
	else {
		// flp codec
		evs_init_encoder = dlsym_assert(evs_lib_handle, "init_encoder", path);
		evs_destroy_encoder = dlsym_assert(evs_lib_handle, "destroy_encoder", path);
		evs_enc_in = dlsym_assert(evs_lib_handle, "evs_enc", path);
		evs_amr_enc_in = dlsym_assert(evs_lib_handle, "amr_wb_enc", path);
		evs_reset_enc_ind = dlsym_assert(evs_lib_handle, "reset_indices_enc", path);
		evs_dec_in = dlsym_assert(evs_lib_handle, "read_indices_from_djb", path);
		evs_dec_out = dlsym_assert(evs_lib_handle, "evs_dec", path);
		evs_syn_output = dlsym_assert(evs_lib_handle, "syn_output", path);
		evs_amr_dec_out = dlsym_assert(evs_lib_handle, "amr_wb_dec", path);
	}

	// common
	get_evs_decoder_size = dlsym_assert(evs_lib_handle, "decoder_size", path);
	get_evs_encoder_size = dlsym_assert(evs_lib_handle, "encoder_size", path);
	get_evs_encoder_ind_list_size = dlsym_assert(evs_lib_handle, "encoder_ind_list_size", path);
	evs_destroy_decoder = dlsym_assert(evs_lib_handle, "destroy_decoder", path);
	evs_enc_out = dlsym_assert(evs_lib_handle, "indices_to_serial", path);
	evs_set_encoder_opts = dlsym_assert(evs_lib_handle, "encoder_set_opts", path);
	evs_set_encoder_brate = dlsym_assert(evs_lib_handle, "encoder_set_brate", path);
	evs_set_decoder_Fs = dlsym_assert(evs_lib_handle, "decoder_set_Fs", path);
	evs_dec_inc_frame = dlsym_assert(evs_lib_handle, "decoder_inc_ini_frame", path);

	// all ok

	evs_decoder_size = get_evs_decoder_size();
	evs_encoder_size = get_evs_encoder_size();
	evs_encoder_ind_list_size = get_evs_encoder_ind_list_size();

	return;
}


static void evs_def_init(struct codec_def_s *def) {
	evs_load_so(rtpe_common_config_ptr->evs_lib_path);

	if (evs_lib_handle) {
		def->support_decoding = 1;
		def->support_encoding = 1;
	}
}



// 3GPP TS 26.445 A.2.1.2.1 -> A.2.2.1.1
static const char evs_amr_io_compact_cmr[8] = {
	0x90 | 0, // 6.6
	0x90 | 1, // 8.85
	0x90 | 2, // 12.65
	0x90 | 4, // 15.85
	0x90 | 5, // 18.25
	0x90 | 7, // 23.05
	0x90 | 8, // 23.85
	0xff      // no req
};


#if defined(__x86_64__)
// mvr2s_x64_avx2.S
void mvr2s_avx2(float *in, const uint16_t len, int16_t *out);

// mvr2s_x64_avx512.S
void mvr2s_avx512(float *in, const uint16_t len, int16_t *out);
#endif


#if defined(__x86_64__) && !defined(ASAN_BUILD) && HAS_ATTR(ifunc) && defined(__GLIBC__)
static void mvr2s_dynlib_wrapper(float *in, const uint16_t len, int16_t *out) {
	evs_syn_output(in, len, out);
}
static void (*resolve_float2int16_array(void))(float *, const uint16_t, int16_t *) {
#if defined(__x86_64__)
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX512BW) && rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX512F))
		return mvr2s_avx512;
	if (rtpe_has_cpu_flag(RTPE_CPU_FLAG_AVX2))
		return mvr2s_avx2;
#endif
	return mvr2s_dynlib_wrapper;
}
static void float2int16_array(float *in, const uint16_t len, int16_t *out)
	__attribute__ ((ifunc ("resolve_float2int16_array")));
#else
#define float2int16_array evs_syn_output
#endif



static void evs_push_frame(decoder_t *dec, char *frame_data, int bits, int is_amr, int mode, int q_bit,
		GQueue *out)
{
	const unsigned int n_samples = 960; // fixed 20 ms ptime
	uint64_t pts = dec->pts;

	AVFrame *frame = av_frame_alloc();
	frame->nb_samples = n_samples;
	frame->format = AV_SAMPLE_FMT_S16;
	frame->sample_rate = 48000;
	DEF_CH_LAYOUT(&frame->CH_LAYOUT, 1);
	frame->pts = pts;
	if (av_frame_get_buffer(frame, 0) < 0)
		abort();

	evs_dec_in(dec->evs, frame_data, bits, is_amr, mode, q_bit, 0, 0);

	// check for floating point implementation
	if (evs_syn_output) {
		// temp float buffer
		float tmp[n_samples * 3];
		if (!is_amr)
			evs_dec_out(dec->evs, tmp, 0);
		else
			evs_amr_dec_out(dec->evs, tmp);
		float2int16_array(tmp, n_samples, (void *) frame->extended_data[0]);
	}
	else {
		if (!is_amr)
			evs_dec_out(dec->evs, frame->extended_data[0], 0);
		else
			evs_amr_dec_out(dec->evs, frame->extended_data[0]);
	}

	evs_dec_inc_frame(dec->evs);

	pts += n_samples;
	dec->pts = pts;

	g_queue_push_tail(out, frame);
}


// upper 16 bits: 0 = EVS, 1 = AMR
// lower 8 bits: mode num
// 0x000000AA = mode num
// 0x00AAAA00 = actual number of bits
// 0xAA000000 = 0=EVS, 1=AMR
// -1 == invalid
static int32_t evs_mode_from_bytes(int bytes) {
	switch (bytes) {
		// EVS
		case 7: // 2.8
			return 0 | (56 << 8);
		case 18: // 7.2
			return 1 | (144 << 8);
		case 20: // 8.0
			return 2 | (160 << 8);
		case 24: // 9.6
			return 3 | (192 << 8);
		case 33: // 13.2
			return 4 | (264 << 8);
		case 41: // 16.4
			return 5 | (328 << 8);
		case 61: // 24.4
			return 6 | (488 << 8);
		case 80: // 32.0
			return 7 | (640 << 8);
		case 120: // 48.8
			return 8 | (960 << 8);
		case 160: // 64.0
			return 9 | (1280 << 8);
		case 240: // 96.0
			return 10 | (1920 << 8);
		case 320: // 128.0
			return 11 | (2560 << 8);
		case 6: // sid
			return 12 | (48 << 8);
		// AMR
		case 17: // (16.5) 6.60 kbit/s // 0
			return 0 | 0x01000000 | (132 << 8);
		case 23: // (22.125) 8.85 kbit/s // 1
			return 1 | 0x01000000 | (177 << 8);
		case 32: // (31.625) 12.65 kbit/s // 2
			return 2 | 0x01000000 | (253 << 8);
		case 36: // (35.625) 14.25 kbit/s // 3
			return 3 | 0x01000000 | (285 << 8);
		case 40: // (39.625) 15.85 kbit/s // 4
			return 4 | 0x01000000 | (317 << 8);
		case 46: // (45.625) 18.25 kbit/s // 5
			return 5 | 0x01000000 | (365 << 8);
		case 50: // (49.625) 19.85 kbit/s // 6
			return 6 | 0x01000000 | (397 << 8);
		case 58: // (57.625) 23.05 kbit/s // 7
			return 7 | 0x01000000 | (461 << 8);
		case 60: // (59.625) 23.85 kbit/s // 8
			return 8 | 0x01000000 | (477 << 8);
		case 5: // sid
			return 9 | 0x01000000 | (40 << 8);
	}
	return -1;
}



static const int evs_mode_bits[2][16] = {
	// EVS
	{
		56, // 0
		144, // 1
		160, // 2
		192, // 3
		264, // 4
		328, // 5
		488, // 6
		640, // 7
		960, // 8
		1280, // 9
		1920, // 10
		2560, // 11
		48, // 12
		0, // 13 invalid
		0, // 14 invalid
		0, // 15 invalid
	},
	// AMR
	{
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
		0, // invalid // 14
		0, // invalid // 15
	},
};


static int evs_decoder_input(decoder_t *dec, const str *data, GQueue *out) {
	str input = *data;
	const char *err = NULL;

	if (input.len == 0)
		return 0;

	str frame_data = STR_NULL;
	const unsigned char *toc = NULL, *toc_end = NULL;
	unsigned char cmr = 0xff;
	// check for single frame in compact format
	int32_t mode = evs_mode_from_bytes(input.len);
	int is_amr, bits, q_bit;
	if ((mode & 0xff0000ff) == 0) {
		// special case, clause A.2.1.3
		if ((input.s[0] & 0x80)) {
			// AMR in HF format with CMR
			mode = -1;
		}
	}
	if (mode != -1) {
		// single compact frame: consume all
		frame_data = input;
		input.len = 0;

		// extract mode information
		bits = (mode >> 8) & 0xffff;
		is_amr = mode >> 24;
		q_bit = 1;
		mode = mode & 0xff;

		if (is_amr) {
			// save and clear CMR
			unsigned char *shifter = (unsigned char *) frame_data.s; // use unsigned
			cmr = shifter[0] & 0xe0;
			shifter[0] &= 0x1f;

			// convert CMR to full byte format
			cmr >>= 5; // now guaranteed to be 0..7
			cmr = evs_amr_io_compact_cmr[cmr];

			// bit shift payload
			// XXX use larger word sizes
			for (size_t i = 0; i < frame_data.len; i++) {
				shifter[i] <<= 2;
				shifter[i] |= shifter[i+1] >> 6;
			}
			// restore first bit
			size_t first_bit_octet = bits / 8;
			size_t first_bit_bit = bits % 8;
			shifter[0] |= (shifter[first_bit_octet] << first_bit_bit) & 0x80;
		}
	}
	else {
		// header-full
		toc = (unsigned char *) input.s;
		str_shift(&input, 1);
		// is this TOC or CMR?
		if ((*toc & 0x80)) {
			cmr = *toc;
			toc = (unsigned char *) input.s;
			err = "short packet (no TOC after CMR)";
			if (str_shift(&input, 1))
				goto err;
			err = "invalid TOC byte";
			if ((*toc & 0x80))
				goto err;
		}
		// skip over all TOC entries
		unsigned char toc_ent = *toc;
		while ((toc_ent & 0x40)) {
			toc_ent = *((unsigned char *) input.s);
			err = "short packet (no repeating TOC)";
			if (str_shift(&input, 1))
				goto err;
		}
		// `toc` is now the first TOC entry and `input` points to the first speech frame
		toc_end = (void *) input.s;
	}

	while (1) {
		// process frame if we have one; we don't have one if
		// this is the first iteration and this is not a compact frame
		if (mode != -1)
			evs_push_frame(dec, frame_data.s, bits, is_amr, mode, q_bit, out);

		// anything left? we break here in compact mode
		if (!input.len)
			break;

		// if we're here, we're in HF mode: look at the next TOC and extract speech frame
		if (toc >= toc_end) // leftover data/padding at the end
			break;
		mode = *toc & 0xf;
		is_amr = (*toc >> 5) & 0x1;
		if (is_amr)
			q_bit = (*toc >> 4) & 0x1;
		else
			q_bit = 1;
		bits = evs_mode_bits[is_amr][mode]; // guaranteed to be 0..1 and 0..15

		// consume and shift
		toc++;
		int bytes = (bits + 7) / 8;
		frame_data = STR_LEN(input.s, bytes);
		err = "speech frame truncated";
		if (str_shift(&input, bytes))
			goto err;
	}

	if (cmr != 0xff)
		decoder_event(dec, CE_EVS_CMR_RECV, GUINT_TO_POINTER(cmr));

	return 0;

err:
	if (err)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error unpacking EVS packet: %s", err);
	return -1;
}


static int evs_dtx(decoder_t *dec, GQueue *out, int ptime) {
	ilog(LOG_DEBUG, "pushing empty/lost frame to EVS decoder");
	evs_push_frame(dec, NULL, 0, 0, 0, 0, out);
	return 0;
}



static const char *evs_bw_strings[__EVS_BW_MAX] = { "nb", "wb", "swb", "fb" };

static void evs_parse_bw(enum evs_bw *minp, enum evs_bw *maxp, const str *token) {
	switch (__csh_lookup(token)) {
		case CSH_LOOKUP("nb"):
			*maxp = EVS_BW_NB;
			break;
		case CSH_LOOKUP("wb"):
			*maxp = EVS_BW_WB;
			break;
		case CSH_LOOKUP("swb"):
			*maxp = EVS_BW_SWB;
			break;
		case CSH_LOOKUP("fb"):
			*maxp = EVS_BW_FB;
			break;
		case CSH_LOOKUP("nb-wb"):
			*minp = EVS_BW_NB;
			*maxp = EVS_BW_WB;
			break;
		case CSH_LOOKUP("nb-swb"):
			*minp = EVS_BW_NB;
			*maxp = EVS_BW_SWB;
			break;
		case CSH_LOOKUP("nb-fb"):
			*minp = EVS_BW_NB;
			*maxp = EVS_BW_FB;
			break;
		// the ones below are not mentioned in the spec - lower bound ignored
		case CSH_LOOKUP("wb-swb"):
			*minp = EVS_BW_WB;
			*maxp = EVS_BW_SWB;
			break;
		case CSH_LOOKUP("wb-fb"):
			*minp = EVS_BW_WB;
			*maxp = EVS_BW_FB;
			break;
		case CSH_LOOKUP("swb-fb"):
			*minp = EVS_BW_SWB;
			*maxp = EVS_BW_FB;
			break;
		default:
			ilog(LOG_WARN, "EVS: bandwidth selection '" STR_FORMAT "' not understood",
					STR_FMT(token));
	}
}


// lamely parse out decimal numbers without using floating point
static unsigned int str_to_i_k(str *s) {
	str intg;
	str frac = *s;
	if (str_token(&intg, &frac, '.')) {
		unsigned int ret = str_to_i(s, 0) * 1000;
		if (frac.len > 1) // at most one decimal digit
			frac.len = 1;
		return ret + str_to_i(&frac, 0) * 100;
	}
	return str_to_i(s, 0) * 1000;
}


static void evs_parse_br(unsigned int *minp, unsigned int *maxp, str *token) {
	str min;
	str max = *token;
	if (str_token(&min, &max, '-')) {
		*minp = str_to_i_k(&min);
		*maxp = str_to_i_k(&max);
	}
	else
		*minp = *maxp = str_to_i_k(token);
	if (*minp > *maxp) {
		ilog(LOG_WARN, "EVS: min bitrate %u is larger than max bitrate %u",
				*minp, *maxp);
		*maxp = *minp;
	}
}
// lamely print fractional number
static void evs_print_frac_num(GString *s, unsigned int num) {
	unsigned int frac = (num / 100 % 10);
	unsigned int intg = num / 1000;
	if (frac)
		g_string_append_printf(s, "%u.%u", intg, frac);
	else
		g_string_append_printf(s, "%u", intg);
}
static void evs_format_print_br(GString *s, const char *k, unsigned int min, unsigned int max) {
	if (!max)
		return;

	g_string_append(s, k);
	g_string_append_c(s, '=');

	if (min != max) {
		evs_print_frac_num(s, min);
		g_string_append_c(s, '-');
	}
	evs_print_frac_num(s, max);
	g_string_append(s, "; ");
}
static void evs_format_print_bw(GString *s, const char *k, enum evs_bw min, enum evs_bw max) {
	if (max == EVS_BW_UNSPEC)
		return;

	g_string_append(s, k);
	g_string_append_c(s, '=');

	if (min != EVS_BW_UNSPEC) {
		g_string_append(s, evs_bw_strings[min]);
		g_string_append_c(s, '-');
	}
	g_string_append(s, evs_bw_strings[max]);
	g_string_append(s, "; ");
}
static GString *evs_format_print(const struct rtp_payload_type *p) {
	if (!p->format.fmtp_parsed)
		return false;

	GString *s = g_string_new("");
	__auto_type f = &p->format.parsed.evs;

	if (f->hf_only)
		g_string_append(s, "hf-only=1; ");
	if (f->no_dtx)
		g_string_append(s, "dtx=0; ");
	if (f->no_dtx_recv)
		g_string_append(s, "dtx-recv=0; ");
	if (f->cmr)
		g_string_append_printf(s, "cmr=%i; ", f->cmr);

	if (f->amr_io) {
		// AMR
		g_string_append(s, "evs-mode-switch=1; ");

		if (f->mode_set) {
			g_string_append(s, "mode-set=");
			for (unsigned int i = 0; i < 8; i++) {
				if ((f->mode_set & (1 << i)))
					g_string_append_printf(s, "%u,", i);
			}
			g_string_truncate(s, s->len - 1); // remove trailing ","
			g_string_append(s, "; ");
		}

		if (f->mode_change_neighbor)
			g_string_append(s, "mode-change-neighbor=1; ");
		if (f->mode_change_period)
			g_string_append_printf(s, "mode-change-period=%i; ", f->mode_change_period);
	}
	else {
		// EVS
		evs_format_print_br(s, "br", f->min_br, f->max_br);
		evs_format_print_br(s, "br-send", f->min_br_send, f->max_br_send);
		evs_format_print_br(s, "br-recv", f->min_br_recv, f->max_br_recv);

		evs_format_print_bw(s, "bw", f->min_bw, f->max_bw);
		evs_format_print_bw(s, "bw-send", f->min_bw_send, f->max_bw_send);
		evs_format_print_bw(s, "bw-recv", f->min_bw_recv, f->max_bw_recv);
	}

	if (s->len != 0)
		g_string_truncate(s, s->len - 2); // remove trailing "; " if anything was printed

	return s;
}
static void evs_parse_format_cb(str *key, str *token, void *data) {
	union codec_format_options *opts = data;
	__auto_type o = &opts->evs;

	switch (__csh_lookup(key)) {
		case CSH_LOOKUP("hf-only"):
			if (token->len == 1 && token->s[0] == '1')
				o->hf_only = 1;
			break;
		case CSH_LOOKUP("evs-mode-switch"):
			if (token->len == 1 && token->s[0] == '1')
				o->amr_io = 1;
			break;
		case CSH_LOOKUP("dtx"):
			if (token->len == 1 && token->s[0] == '0')
				o->no_dtx = 1;
			break;
		case CSH_LOOKUP("dtx-recv"):
			if (token->len == 1 && token->s[0] == '0')
				o->no_dtx_recv = 1;
			break;
		case CSH_LOOKUP("cmr"):
			if (token->len == 1 && token->s[0] == '1')
				o->cmr = 1;
			else if (token->len == 2 && token->s[0] == '-' && token->s[1] == '1')
				o->cmr = -1;
			break;
		case CSH_LOOKUP("br"):
			evs_parse_br(&o->min_br, &o->max_br, token);
			break;
		case CSH_LOOKUP("br-send"):
			evs_parse_br(&o->min_br_send, &o->max_br_send, token);
			break;
		case CSH_LOOKUP("br-recv"):
			evs_parse_br(&o->min_br_recv, &o->max_br_recv, token);
			break;
		case CSH_LOOKUP("bw"):
			evs_parse_bw(&o->min_bw, &o->max_bw, token);
			break;
		case CSH_LOOKUP("bw-send"):
			evs_parse_bw(&o->min_bw_send, &o->max_bw_send, token);
			break;
		case CSH_LOOKUP("bw-recv"):
			evs_parse_bw(&o->min_bw_recv, &o->max_bw_recv, token);
			break;
		case CSH_LOOKUP("mode-set"):;
			str mode;
			while (str_token_sep(&mode, token, ',')) {
				int m = str_to_i(&mode, -1);
				if (m < 0 || m > 8)
					continue;
				o->mode_set |= (1 << m);
			}
			break;
		case CSH_LOOKUP("mode-change-period"):
			o->mode_change_period = str_to_i(token, 0);
			break;
		case CSH_LOOKUP("mode-change-neighbor"):
			if (token->len == 1 && token->s[0] == '1')
				o->mode_change_neighbor = 1;
			break;
	}
}
static bool evs_format_parse(struct rtp_codec_format *f, const str *fmtp) {
	// initialise
	f->parsed.evs.max_bw = EVS_BW_UNSPEC;
	f->parsed.evs.min_bw = EVS_BW_UNSPEC;
	f->parsed.evs.max_bw_send = EVS_BW_UNSPEC;
	f->parsed.evs.min_bw_send = EVS_BW_UNSPEC;
	f->parsed.evs.max_bw_recv = EVS_BW_UNSPEC;
	f->parsed.evs.min_bw_recv = EVS_BW_UNSPEC;

	codeclib_key_value_parse(fmtp, true, evs_parse_format_cb, &f->parsed);
	return true;
}
static void evs_format_answer(struct rtp_payload_type *p, const struct rtp_payload_type *src) {
	if (!p->format.fmtp_parsed)
		return;

	__auto_type f = &p->format.parsed.evs;

	// swap send/recv

	__auto_type t1 = f->max_br_recv;
	f->max_br_recv = f->max_br_send;
	f->max_br_send = t1;

	t1 = f->min_br_recv;
	f->min_br_recv = f->min_br_send;
	f->min_br_send = t1;

	__auto_type t2 = f->max_bw_recv;
	f->max_bw_recv = f->max_bw_send;
	f->max_bw_send = t2;

	t2 = f->min_bw_recv;
	f->min_bw_recv = f->min_bw_send;
	f->min_bw_send = t2;
}

// duplicated from AMR code
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

static int evs_format_cmp(const struct rtp_payload_type *A, const struct rtp_payload_type *B) {
	// params must have been parsed successfully
	if (!A->format.fmtp_parsed || !B->format.fmtp_parsed)
		return -1;

	__auto_type a = &A->format.parsed.evs;
	__auto_type b = &B->format.parsed.evs;

	// reject what is incompatible
	if (a->amr_io != b->amr_io)
		return -1;
	if (a->hf_only != b->hf_only)
		return -1;

	// determine whether we are compatible
	int compat = 0;

#define FEATURE_CMP(field, compat_op, undefined_val) \
	if (a->field != undefined_val && b->field != undefined_val) { \
		if (a->field == b->field) \
			; \
		else if (a->field compat_op b->field) \
			compat++; \
		else \
			return -1; \
	} \
	else if (a->field == undefined_val && b->field != undefined_val) /* `a` is broader than `b` */ \
		compat++; \
	else if (a->field != undefined_val && b->field == undefined_val) \
		return -1;

	if (!a->amr_io) {
		// EVS
		FEATURE_CMP(max_br, >, 0)
		FEATURE_CMP(min_br, <, 0)
		FEATURE_CMP(max_br_recv, >, 0)
		FEATURE_CMP(min_br_recv, <, 0)
		FEATURE_CMP(max_br_send, >, 0)
		FEATURE_CMP(min_br_send, <, 0)

		FEATURE_CMP(max_bw, >, EVS_BW_UNSPEC)
		FEATURE_CMP(min_bw, <, EVS_BW_UNSPEC)
		FEATURE_CMP(max_bw_recv, >, EVS_BW_UNSPEC)
		FEATURE_CMP(min_bw_recv, <, EVS_BW_UNSPEC)
		FEATURE_CMP(max_bw_send, >, EVS_BW_UNSPEC)
		FEATURE_CMP(min_bw_send, <, EVS_BW_UNSPEC)
	}
	else {
		// AMR
		int match = amr_mode_set_cmp(a->mode_set, b->mode_set);
		if (match == 1)
			compat++;
		else if (match == -1)
			return -1;
	}

#undef FEATURE_CMP

	return (compat == 0) ? 0 : 1;
}
// EVS RTP always runs at 16 kHz
static void evs_select_encoder_format(encoder_t *enc, format_t *req_format, const format_t *f,
		const struct rtp_codec_format *fmtp)
{
	if (req_format->clockrate != 16000)
		return; // bail - encoder will fail to initialise

	// check against natively supported rates first
	switch (f->clockrate) {
		case 48000:
		case 32000:
		case 16000:
			enc->clockrate_fact = (struct fraction) {48000 / f->clockrate, 1};
			break;
		case 8000:
			enc->clockrate_fact = (struct fraction) {1, 16000 / f->clockrate};
			break;
		default:
			// resample to next best rate
			if (f->clockrate > 32000)
				enc->clockrate_fact = (struct fraction) {3,1};
			else if (f->clockrate > 16000)
				enc->clockrate_fact = (struct fraction) {2,1};
			else if (f->clockrate > 8000)
				enc->clockrate_fact = (struct fraction) {1,1};
			else
				enc->clockrate_fact = (struct fraction) {1,2};
			break;
	}
}



static const char *evs_decoder_init(decoder_t *dec, const str *extra_opts) {
	dec->evs = g_malloc0(evs_decoder_size);
	if (dec->in_format.clockrate != 48000)
		ilog(LOG_WARN, "EVS: invalid decoder clock rate (%i) requested",
				fraction_div(dec->in_format.clockrate, &dec->clockrate_fact));
	if (dec->in_format.channels != 1)
		ilog(LOG_WARN, "EVS: %i-channel EVS is not supported",
				dec->in_format.channels);
	dec->in_format.clockrate = 48000;
	evs_set_decoder_Fs(dec->evs, dec->in_format.clockrate);
	evs_init_decoder(dec->evs);
	return NULL;
}
static void evs_decoder_close(decoder_t *dec) {
	evs_destroy_decoder(dec->evs);
	g_free(dec->evs);
}



static int32_t evs_mode_from_bitrate(int bitrate) {
	int bytes_per_frame = ((bitrate / 50) + 7) / 8;
	if (bytes_per_frame >= 7)
		return evs_mode_from_bytes(bytes_per_frame);
	return -1;
}

static int evs_bitrate_mode(int bitrate) {
	switch (bitrate) {
		// EVS
		case 2800:
		case 5900:
		case 7200:
		case 8000:
		case 13200:
		case 32000:
		case 64000:
		// AMR
		case 6600:
		case 8850:
		case 12650:
		case 14250:
		case 15850:
		case 18250:
		case 19850:
		case 23050:
		case 23850:
			return 1;
		// EVS
		case 9600:
		case 16400:
		case 24400:
		case 48000:
		case 96000:
		case 128000:
			return 2;
	}
	return 0;
}

static const int evs_mode_bitrates[2][16] = {
	// EVS
	{
		5900, // 0 (VBR)
		7200, // 1
		8000, // 2
		9600, // 3
		13200, // 4
		16400, // 5
		24400, // 6
		32000, // 7
		48800, // 8
		64000, // 9
		96000, // 10
		128000, // 11
		0, // 12 SID
		0, // 13 invalid
		0, // 14 invalid
		0, // 15 invalid
	},
	// AMR
	{
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
		0, // invalid // 14
		0, // invalid // 15
	},
};
static const uint8_t evs_min_max_modes_by_bw[__EVS_BW_MAX][2] = {
	{ 0,  6 }, // NB
	{ 0, 11 }, // WB
	{ 3, 11 }, // SWB
	{ 5, 11 }, // FB
};
static uint8_t evs_clamp_mode_by_bw(const uint8_t mode, const enum evs_bw bw) {
	if (mode < evs_min_max_modes_by_bw[bw][0])
		return evs_min_max_modes_by_bw[bw][0];
	else if (mode > evs_min_max_modes_by_bw[bw][1])
		return evs_min_max_modes_by_bw[bw][1];
	return mode;
}

static int evs_match_bitrate(int orig_br, unsigned int amr) {
	// is it already a valid bitrate?
	int32_t mode = evs_mode_from_bitrate(orig_br);
	if (mode >= 0) {
		int bits = (mode >> 8) & 0xffff;
		if (mode > 0 && (mode >> 24) == amr && bits * 50 == orig_br)
			return orig_br;
	}

	// find closest match
	int max_mode = amr ? 8 : 11;
	int test_mode = max_mode / 2;
	int mode_off = (max_mode + 1) / 2;
	bool last = false;
	while (1) {
		int new_br = evs_mode_bitrates[amr][test_mode];
		int new_off = (mode_off + 1) / 2;
		if (new_br > orig_br) {
			if (test_mode == 0 || last)
				return new_br;
			test_mode -= new_off;
		}
		else { // new_br < orig_br
			if (test_mode == max_mode)
				return new_br;
			test_mode += new_off;
		}
		if (mode_off == 1)
			last = true;
		mode_off = new_off;
	}
}



static const char *evs_encoder_init(encoder_t *enc, const str *extra_opts) {
	enc->evs.ctx = g_malloc0(evs_encoder_size);
	enc->evs.ind_list = g_malloc(evs_encoder_ind_list_size);
	if (enc->requested_format.channels != 1)
		ilog(LOG_WARN, "EVS: %i-channel EVS is not supported",
				enc->requested_format.channels);
	enc->actual_format = enc->requested_format;
	enc->actual_format.format = AV_SAMPLE_FMT_S16;
	enc->samples_per_frame = enc->actual_format.clockrate * 20 / 1000;

	__auto_type o = &enc->format_options.evs;

	// determine max BW
	if (o->max_bw_send != EVS_BW_UNSPEC)
		enc->codec_options.evs.max_bw = o->max_bw_send;
	else if (o->max_bw != EVS_BW_UNSPEC)
		enc->codec_options.evs.max_bw = o->max_bw;
	else
		enc->codec_options.evs.max_bw = EVS_BW_WB;
	assert(enc->codec_options.evs.max_bw >= 0 && enc->codec_options.evs.max_bw < __EVS_BW_MAX);

	switch (enc->requested_format.clockrate) {
		case 48000:
		case 32000:
			if (enc->codec_options.evs.max_bw > EVS_BW_SWB)
				enc->codec_options.evs.max_bw = EVS_BW_SWB;
			break;
		case 16000:
			if (enc->codec_options.evs.max_bw > EVS_BW_WB)
				enc->codec_options.evs.max_bw = EVS_BW_WB;
			break;
		case 8000:
			enc->codec_options.evs.max_bw = EVS_BW_NB;
			break;
		default:
			ilog(LOG_WARN, "EVS: invalid encoder clock rate (%i) requested",
					fraction_div(enc->requested_format.clockrate, &enc->clockrate_fact));
	}
	evs_set_encoder_opts(enc->evs.ctx, enc->actual_format.clockrate, enc->evs.ind_list);

	// limit bitrate to given range
	if (!o->amr_io) {
		// EVS
		if (o->max_br && enc->bitrate > o->max_br)
			enc->bitrate = o->max_br;
		if (o->min_br && enc->bitrate < o->max_br)
			enc->bitrate = o->min_br;

		// verify bitrate
		int bitrate = evs_match_bitrate(enc->bitrate, 0);
		if (bitrate != enc->bitrate) {
			ilog(LOG_INFO, "EVS: Using bitrate %i instead of %i", bitrate, enc->bitrate);
			enc->bitrate = bitrate;
		}

		// limit max bitrate to one supported by the selected BW
		int32_t mode = evs_mode_from_bitrate(enc->bitrate);
		if (mode == -1)
			ilog(LOG_WARN, "EVS: ended up with unknown bitrate %i", enc->bitrate);
		else {
			mode &= 0xff;
			mode = evs_clamp_mode_by_bw(mode, enc->codec_options.evs.max_bw);
			bitrate = evs_mode_bitrates[0][mode];
			ilog(LOG_INFO, "EVS: using bitrate %i instead of %i as restricted by BW %i",
					bitrate, enc->bitrate, enc->codec_options.evs.max_bw);
			enc->bitrate = bitrate;
		}
	}
	else {
		// AMR
		int32_t mode = evs_mode_from_bitrate(enc->bitrate);
		if (mode != -1) {
			if (mode >> 24 != 1)
				mode = -1; // EVS bitrate
			else if (o->mode_set) {
				if ((o->mode_set & (1 << (mode & 0xff))) == 0)
					mode = -1; // not part of the mode-set
			}
		}
		if (mode == -1) {
			// find closest match bitrate
			int bitrate = evs_match_bitrate(enc->bitrate, 1);
			mode = evs_mode_from_bitrate(bitrate);
			if (mode == -1 || (mode >> 24 != 1))
				ilog(LOG_WARN, "EVS: ended up with unknown bitrate %i", bitrate);
			else {
				mode &= 0xff;
				// restrict by mode-set if there is one
				if (o->mode_set) {
					if ((o->mode_set & (1 << (mode & 0xff))) == 0) {
						// pick next higher mode if possible, otherwise go lower:
						// clear lower unwanted modes from mode-set
						unsigned int mode_set = o->mode_set & (0xfe << mode);
						if (mode_set) {
							// got a higher mode: which one?
							mode = __builtin_ffs(mode_set) - 1;
						}
						else {
							// no higher mode, get next lower one
							mode = sizeof(int) * 8 - __builtin_clz(o->mode_set) - 1;
						}
					}
				}
				bitrate = evs_mode_bitrates[1][mode];
				ilog(LOG_INFO, "EVS: using bitrate %i instead of %i as restricted by mode-set",
						bitrate, enc->bitrate);
				enc->bitrate = bitrate;
			}
		}
	}

	evs_set_encoder_brate(enc->evs.ctx, enc->bitrate, enc->codec_options.evs.max_bw,
			evs_bitrate_mode(enc->bitrate), o->amr_io);
	evs_init_encoder(enc->evs.ctx);

	return NULL;
}
static void evs_encoder_close(encoder_t *enc) {
	evs_destroy_encoder(enc->evs.ctx);
	g_free(enc->evs.ctx);
	g_free(enc->evs.ind_list);
}




static void evs_handle_cmr(encoder_t *enc) {
	if ((enc->callback.evs.cmr_in & 0x80) == 0)
		return;
	if (enc->callback.evs.cmr_in_ts == enc->evs.cmr_in_ts)
		return;

	enc->evs.cmr_in_ts = enc->callback.evs.cmr_in_ts; // XXX should use a queue or something instead

	__auto_type f = &enc->format_options.evs;
	__auto_type o = &enc->codec_options.evs;
	unsigned char type = (enc->callback.evs.cmr_in >> 4) & 0x7;
	unsigned char req = enc->callback.evs.cmr_in & 0xf;
	int bitrate;

	if (type == 1) {
		// AMR
		if (!f->amr_io)
			goto err;
		if (req > 8)
			goto err;
		bitrate = evs_mode_bitrates[1][req];
	}
	else if (type <= 4) {
		// EVS modes
		if (f->amr_io)
			goto err;
		if (req > 11)
			goto err;
		int bw = type;
		if (bw >= 2)
			bw--; // 0..3
		// ignore min BW
		// instead of ignoring invalid request, clamp them to what is allowed by BW
		if (o->max_bw != EVS_BW_UNSPEC && o->max_bw < bw)
			bw = o->max_bw;
		req = evs_clamp_mode_by_bw(req, bw);
		bitrate = evs_mode_bitrates[0][req];
	}
	else
		goto err;

	enc->bitrate = bitrate;
	evs_set_encoder_brate(enc->evs.ctx, bitrate, o->max_bw,
			evs_bitrate_mode(bitrate), f->amr_io);

	return;

err:
	if (f->amr_io)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "EVS: received invalid CMR (type %u, "
				"request %u) in AMR mode", type, req);
	else
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "EVS: received invalid CMR (type %u, "
				"request %u) with BW <= %i", type, req, o->max_bw);
}

static int evs_encoder_input(encoder_t *enc, AVFrame **frame) {
	if (!*frame)
		return 0;

	if ((*frame)->nb_samples != enc->actual_format.clockrate * 20 / 1000) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "EVS: input %u samples instead of %i", (*frame)->nb_samples,
				enc->actual_format.clockrate * 20 / 1000);
		return -1;
	}

	evs_handle_cmr(enc);

	if (!enc->format_options.evs.amr_io)
		evs_enc_in(enc->evs.ctx, (void *) (*frame)->extended_data[0], (*frame)->nb_samples);
	else
		evs_amr_enc_in(enc->evs.ctx, (void *) (*frame)->extended_data[0], (*frame)->nb_samples);

	// max output: 320 bytes, plus some overhead
	av_new_packet(enc->avpkt, 340);

	unsigned char *out = enc->avpkt->data;
	unsigned char *cmr = NULL;

	if (!enc->format_options.evs.amr_io) {
		// EVS
		if (enc->format_options.evs.cmr == 1) {
			cmr = out;
			*cmr = 0xff; // no CMR
			out++;
		}
	}
	else {
		// AMR IO
		if (!enc->format_options.evs.hf_only) {
			// compact
			cmr = out;
			*cmr = 0xe0; // no CMR
			out++; // to be shuffled below
		}
		else {
			// header-full
			if (enc->format_options.evs.cmr == 1) {
				cmr = out;
				*cmr = 0xff; // no CMR
				out++;
			}
		}
	}

	// TOC byte
	unsigned char *toc = NULL;
	if (enc->format_options.evs.hf_only) {
		// header-full always has TOC
		toc = out;
		out++;
	}
	else {
		// compact
		if (cmr && !enc->format_options.evs.amr_io) {
			// EVS with CMR is also header-full with TOC
			toc = out;
			out++;
		}
	}

	uint16_t bits = 0;
	evs_enc_out(enc->evs.ctx, out, &bits);
	uint16_t bytes = (bits + 7) / 8;
	int32_t mode = evs_mode_from_bytes(bytes);
	if (mode < 0) {
		ilog(LOG_ERR | LOG_FLAG_LIMIT, "EVS: invalid encoding received from codec "
				"(%i bits per frame)", bits);
		av_packet_unref(enc->avpkt);
		return -1;
	}
	evs_reset_enc_ind(enc->evs.ctx);

	if (toc) {
		*toc = (mode & 0xff);
		if (enc->format_options.evs.amr_io)
			*toc |= 0x30;
	}

	if (enc->format_options.evs.amr_io && !enc->format_options.evs.hf_only) {
		// how many output bytes (frame minus CMR bits) total?
		bytes = (bits - 5 + 7) / 8;
		// bit-shuffle payload
		unsigned char first = out[0];
		*cmr |= (first >> 2) & 0x1f;
		// XXX accelerate with larger word sizes
		for (int i = 0; i < bytes; i++) {
			out[i] <<= 6;
			out[i] |= out[i+1] >> 2;
		}
		// restore first bit, clear out tail end padding bits
		unsigned int first_bit_shift = (bits + 2) % 8;
		out[bytes-1] &= (0xff << (8 - first_bit_shift)); // clear leftovers
		out[bytes-1] |= ((first & 0x80) >> first_bit_shift); // last/first bit
	}

	bytes += (out - enc->avpkt->data);
	assert(bytes <= enc->avpkt->size);

	if (toc && !enc->format_options.evs.amr_io && !enc->format_options.evs.hf_only) {
		// hf-only=0 but HF packet, check for size collisions and zero-pad if needed
		while (evs_mode_from_bytes(bytes) != -1) {
			enc->avpkt->data[bytes] = '\0';
			bytes++;
		}
	}

	enc->avpkt->size = bytes;
	enc->avpkt->pts = (*frame)->pts;
	enc->avpkt->duration = (*frame)->nb_samples;

	return 0;
}





static const codec_type_t codec_type_evs = {
	.def_init = evs_def_init,
	.decoder_init = evs_decoder_init,
	.decoder_input = evs_decoder_input,
	.decoder_close = evs_decoder_close,
	.encoder_init = evs_encoder_init,
	.encoder_input = evs_encoder_input,
	.encoder_close = evs_encoder_close,
};


static const dtx_method_t dtx_method_evs = {
	.method_id = DTX_NATIVE,
	.do_dtx = evs_dtx,
};


static const codec_def_t evs = {
	.rtpname = "EVS",
	.avcodec_id = -1,
	.default_clockrate_fact = {3,1},
	.default_clockrate = 16000,
	.default_channels = 1,
	.default_ptime = 20,
	.default_bitrate = 16400,
	.default_fmtp = "dtx=0;dtx-recv=0",
	.format_parse = evs_format_parse,
	.format_cmp = evs_format_cmp,
	.format_print = evs_format_print,
	.format_answer = evs_format_answer,
	.select_encoder_format = evs_select_encoder_format,
	.packetizer = packetizer_passthrough,
	.bits_per_sample = 1,
	.evs = 1,
	.media_type = MT_AUDIO,
	.codec_type = &codec_type_evs,
	.dtx_methods = {
		[DTX_NATIVE] = &dtx_method_evs,
		[DTX_SILENCE] = &dtx_method_silence,
		[DTX_CN] = &dtx_method_cn,
	},
};


__attribute__((constructor))
static void init(void) {
	codeclib_register_codec(&evs);
}

__attribute__((destructor))
static void cleanup(void) {
	if (evs_lib_handle)
		dlclose(evs_lib_handle);
}
