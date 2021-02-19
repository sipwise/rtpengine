#include "output.h"
#include <libavcodec/avcodec.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <glib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "log.h"
#include "db.h"
#include "main.h"


//static int output_codec_id;
static const codec_def_t *output_codec;
static const char *output_file_format;

int mp3_bitrate;



static int output_shutdown(output_t *output);



static int output_got_packet(encoder_t *enc, void *u1, void *u2) {
	output_t *output = u1;

	dbg("{%s%s%s} output avpkt size is %i", FMT_M(output->file_name), (int) enc->avpkt.size);
	dbg("{%s%s%s} output pkt pts/dts is %li/%li", FMT_M(output->file_name), (long) enc->avpkt.pts,
			(long) enc->avpkt.dts);
	dbg("{%s%s%s} output dts %li", FMT_M(output->file_name), (long) output->encoder->mux_dts);

	av_write_frame(output->fmtctx, &enc->avpkt);

	return 0;
}


int output_add(output_t *output, AVFrame *frame) {
	if (!output)
		return -1;
	if (!output->encoder) // not ready - not configured
		return -1;
	return encoder_input_fifo(output->encoder, frame, output_got_packet, output, NULL);
}


output_t *output_new(const char *path, const char *call, const char *type) {
	// construct output file name
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	const char *ax = call;

	GString *f = g_string_new("");
	for (const char *p = output_pattern; *p; p++) {
		if (*p != '%') {
			g_string_append_c(f, *p);
			continue;
		}
		p++;
		switch (*p) {
			case '\0':
				ilog(LOG_ERR, "Invalid output pattern (trailing %%)");
				goto done;
			case '%':
				g_string_append_c(f, '%');
				break;
			case 'c':
				g_string_append(f, call);
				break;
			case 't':
				g_string_append(f, type);
				break;
			case 'Y':
				g_string_append_printf(f, "%04i", tm.tm_year + 1900);
				break;
			case 'm':
				g_string_append_printf(f, "%02i", tm.tm_mon + 1);
				break;
			case 'd':
				g_string_append_printf(f, "%02i", tm.tm_mday);
				break;
			case 'H':
				g_string_append_printf(f, "%02i", tm.tm_hour);
				break;
			case 'M':
				g_string_append_printf(f, "%02i", tm.tm_min);
				break;
			case 'S':
				g_string_append_printf(f, "%02i", tm.tm_sec);
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':;
				char *end;
				long len = strtol(p, &end, 10);
				if (len <= 0 || len == LONG_MAX || end == p) {
					ilog(LOG_ERR, "Invalid output pattern (invalid number at '%%%s')", p);
					break;
				}
				while (*ax && len--)
					g_string_append_c(f, *ax++);
				p = end - 1; // will be advanced +1 in the next loop
				break;
			default:
				ilog(LOG_ERR, "Invalid output pattern (unknown format character '%c')", *p);
				break;
		}
	}

done:;
	output_t *ret = g_slice_alloc0(sizeof(*ret));
	ret->file_path = g_strdup(path);
	ret->file_name = f->str; // stealing the content
	ret->full_filename = g_strdup_printf("%s/%s", path, f->str);
	ret->file_format = output_file_format;
	ret->encoder = encoder_new();

	// create parent directories if needed
	char *last_sep = strrchr(ret->full_filename, G_DIR_SEPARATOR);
	if (last_sep) {
		*last_sep = '\0';
		if (g_mkdir_with_parents(ret->full_filename, output_chmod_dir))
			ilog(LOG_WARN, "Failed to create (parent) directory for '%s': %s",
					ret->full_filename, strerror(errno));
		*last_sep = G_DIR_SEPARATOR;
	}


	g_string_free(f, FALSE);

	return ret;
}


int output_config(output_t *output, const format_t *requested_format, format_t *actual_format) {
	const char *err;
	int av_ret = 0;

	// anything to do?
	if (G_LIKELY(format_eq(requested_format, &output->encoder->requested_format))) {
		if (actual_format)
			*actual_format = output->encoder->actual_format;
		goto done;
	}

	output_shutdown(output);

	err = "failed to alloc format context";
	output->fmtctx = avformat_alloc_context();
	if (!output->fmtctx)
		goto err;
	output->fmtctx->oformat = av_guess_format(output->file_format, NULL, NULL);
	err = "failed to determine output format";
	if (!output->fmtctx->oformat)
		goto err;

	if (encoder_config(output->encoder, output_codec, mp3_bitrate, 0, requested_format, actual_format))
		goto err;

	err = "failed to alloc output stream";
	output->avst = avformat_new_stream(output->fmtctx, output->encoder->u.avc.codec);
	if (!output->avst)
		goto err;
	output->avst->time_base = output->encoder->u.avc.avcctx->time_base;

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 0, 0)
	// move the avcctx to avst as we already have an initialized avcctx
	if (output->avst->codec) {
		avcodec_close(output->avst->codec);
		avcodec_free_context(&output->avst->codec);
	}
	output->avst->codec = output->encoder->u.avc.avcctx;
#endif

#if LIBAVFORMAT_VERSION_INT >= AV_VERSION_INT(57, 26, 0) // exact version? present in 57.56
	avcodec_parameters_from_context(output->avst->codecpar, output->encoder->u.avc.avcctx);
#endif

	char *full_fn = NULL;
	char suff[16] = "";
	for (int i = 1; i < 20; i++) {
		full_fn = g_strdup_printf("%s%s.%s", output->full_filename, suff, output->file_format);
		if (!g_file_test(full_fn, G_FILE_TEST_EXISTS))
			goto got_fn;
		snprintf(suff, sizeof(suff), "-%i", i);
		g_free(full_fn);
	}

	err = "failed to find unused output file number";
	goto err;

got_fn:
	output->filename = full_fn;
	err = "failed to open avio";
	av_ret = avio_open(&output->fmtctx->pb, full_fn, AVIO_FLAG_WRITE);
	if (av_ret < 0)
		goto err;
	err = "failed to write header";
	av_ret = avformat_write_header(output->fmtctx, NULL);
	if (av_ret)
		goto err;

	db_config_stream(output);
done:
	return 0;

err:
	output_shutdown(output);
	ilog(LOG_ERR, "Error configuring media output: %s", err);
	if (av_ret)
		ilog(LOG_ERR, "Error returned from libav: %s", av_error(av_ret));
	return -1;
}


static int output_shutdown(output_t *output) {
	if (!output)
		return 0;
	if (!output->fmtctx)
		return 0;

	int ret = 0;
	if (output->fmtctx->pb) {
		av_write_trailer(output->fmtctx);
		avio_closep(&output->fmtctx->pb);
		ret = 1;
		if (output_chmod)
			if (chmod(output->filename, output_chmod))
				ilog(LOG_WARN, "Failed to change file mode of '%s%s%s': %s",
						FMT_M(output->filename), strerror(errno));
		if (output_chown != -1 || output_chgrp != -1)
			if (chown(output->filename, output_chown, output_chgrp))
				ilog(LOG_WARN, "Failed to change file owner/group of '%s%s%s': %s",
						FMT_M(output->filename), strerror(errno));
	}
	avformat_free_context(output->fmtctx);

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 0, 0)
	// avoid double free - avcctx already freed
	output->encoder->u.avc.avcctx = NULL;
#endif

	encoder_close(output->encoder);

	output->fmtctx = NULL;
	output->avst = NULL;
	g_clear_pointer(&output->full_filename, g_free);
	g_clear_pointer(&output->file_path, g_free);
	g_clear_pointer(&output->file_name, g_free);
	g_clear_pointer(&output->filename, g_free);

	return ret;
}


void output_close(output_t *output) {
	if (!output)
		return;
	if (output_shutdown(output))
		db_close_stream(output);
	else
		db_delete_stream(output);
	encoder_free(output->encoder);
	g_slice_free1(sizeof(*output), output);
}


void output_init(const char *format) {
	str codec;

	if (!strcmp(format, "wav")) {
		str_init(&codec, "PCM-S16LE");
		output_file_format = "wav";
	}
	else if (!strcmp(format, "mp3")) {
		str_init(&codec, "MP3");
		output_file_format = "mp3";
	}
	else
		die("Unknown output format '%s'", format);

	output_codec = codec_find(&codec, MT_AUDIO);
	assert(output_codec != NULL);
}
