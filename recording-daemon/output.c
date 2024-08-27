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
#include "recaux.h"
#include "notify.h"


//static int output_codec_id;
static codec_def_t *output_codec;
static const char *output_file_format;

int mp3_bitrate;



static bool output_shutdown(output_t *output);



static int output_got_packet(encoder_t *enc, void *u1, void *u2) {
	output_t *output = u1;

	dbg("{%s%s%s} output avpkt size is %i", FMT_M(output->file_name), (int) enc->avpkt->size);
	dbg("{%s%s%s} output pkt pts/dts is %li/%li", FMT_M(output->file_name), (long) enc->avpkt->pts,
			(long) enc->avpkt->dts);
	dbg("{%s%s%s} output dts %li", FMT_M(output->file_name), (long) output->encoder->mux_dts);

	av_write_frame(output->fmtctx, enc->avpkt);

	return 0;
}


int output_add(output_t *output, AVFrame *frame) {
	if (!output)
		return -1;
	if (!output->encoder) // not ready - not configured
		return -1;
	if (!output->fmtctx) // output not open
		return -1;
	return encoder_input_fifo(output->encoder, frame, output_got_packet, output, NULL);
}


static void create_parent_dirs(char *dir) {
	char *p = dir;

	// skip root
	if (*p == G_DIR_SEPARATOR)
		p++;

	while (1) {
		// find next dir separator
		p = strchr(p, G_DIR_SEPARATOR);
		if (!p)
			break;
		// check/create dir
		*p = '\0';
		// create with 0700 first, then chmod
		if (mkdir(dir, 0700)) {
			int existed = errno == EEXIST;
			if (!existed)
				ilog(LOG_WARN, "Failed to create directory '%s': %s", dir, strerror(errno));
			*p++ = G_DIR_SEPARATOR;
			if (!existed) // no point in continuing
				break;
			continue;
		}
		if (output_chmod_dir && chmod(dir, output_chmod_dir))
			ilog(LOG_WARN, "Failed to change mode of '%s': %s", dir, strerror(errno));
		if (output_chown != -1 || output_chgrp != -1)
			if (chown(dir, output_chown, output_chgrp))
				ilog(LOG_WARN, "Failed to change owner/group of '%s': %s",
						dir, strerror(errno));
		*p++ = G_DIR_SEPARATOR;
	}
}

static output_t *output_alloc(const char *path, const char *name) {
	output_t *ret = g_slice_alloc0(sizeof(*ret));
	ret->file_path = g_strdup(path);
	ret->file_name = g_strdup(name);
	ret->full_filename = g_strdup_printf("%s/%s", path, name);
	ret->file_format = output_file_format;
	ret->encoder = encoder_new();
	ret->channel_mult = 1;
	ret->requested_format.format = -1;
	ret->actual_format.format = -1;
	ret->start_time = now_double();

	return ret;
}

static void output_append_str_from_ht(GString *f, metadata_ht ht, const str *s) {
	str_q *q = t_hash_table_lookup(ht, s);
	if (!q || q->length == 0) {
		ilog(LOG_WARN, "Key '{" STR_FORMAT "}' used in file name pattern not present in metadata",
				STR_FMT(s));
		return;
	}
	if (q->length > 1)
		ilog(LOG_WARN, "Key '{" STR_FORMAT "}' used in file name pattern present in metadata %u times, "
				"only using first occurrence",
				STR_FMT(s), q->length);
	g_autoptr(char) esc = g_uri_escape_string(q->head->data->s, NULL, false);
	g_string_append(f, esc);
}

static output_t *output_new(const char *path, const metafile_t *mf, const char *type, const char *kind,
		const char *label)
{
	// construct output file name
	struct timeval now;
	struct tm tm;
	g_autoptr(char) escaped_callid = g_uri_escape_string(mf->call_id, NULL, false);
	const char *ax = escaped_callid;

	gettimeofday(&now, NULL);
	localtime_r(&now.tv_sec, &tm);

	g_autoptr(GString) f = g_string_new("");
	const char *pattern = mf->output_pattern ?: output_pattern;

	for (const char *p = pattern; *p; p++) {
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
				g_string_append(f, escaped_callid);
				break;
			case 'r':
				g_string_append(f, mf->random_tag);
				break;
			case 't':
				g_string_append(f, type);
				break;
			case 'l':
				g_string_append(f, label);
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
			case 'u':
				g_string_append_printf(f, "%06li", (long) now.tv_usec);
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
			case '{':
				// find matching end '}'
				p++;
				end = strchr(p, '}');
				if (!end) {
					ilog(LOG_ERR, "Missing ending brace '}' in file name pattern");
					break;
				}
				str fmt = STR_LEN((char *) p, end - p);
				p = end; // skip over {...}
				output_append_str_from_ht(f, mf->metadata_parsed, &fmt);
				break;
			default:
				ilog(LOG_ERR, "Invalid output pattern (unknown format character '%c')", *p);
				break;
		}
	}

done:;
	output_t *ret = output_alloc(path, f->str);
	create_parent_dirs(ret->full_filename);
	ret->kind = kind;

	return ret;
}

static output_t *output_new_from_full_path(const char *path, char *name, const char *kind) {
	output_t *ret = output_alloc(path, name);
	create_parent_dirs(ret->full_filename);
	ret->kind = kind;

	return ret;
}

output_t *output_new_ext(metafile_t *mf, const char *type, const char *kind, const char *label) {
	const char *output_path = mf->output_path ?: output_dir;
	output_t *ret;
	dbg("Metadata %s, output destination %s", mf->metadata, mf->output_dest);
	if (mf->output_dest) {
		char *path = g_strdup(mf->output_dest);
		char *sep = strrchr(path, '/');
		if (sep) {
			char *filename = sep + 1;
			*sep = 0;
			ret = output_new_from_full_path(path, filename, kind);
			ret->skip_filename_extension = TRUE;
		}
		else
			ret = output_new_from_full_path(output_path, path, kind);
		g_free(path);
	}
	else
		ret = output_new(output_path, mf, type, kind, label);

	return ret;
}

int output_config(output_t *output, const format_t *requested_format, format_t *actual_format) {
	const char *err;
	int av_ret = 0;

	format_t req_fmt = *requested_format;

	// if we've already done this and don't care about the sample format,
	// restore the already determined sample format
	if (req_fmt.format == -1 && output->requested_format.format != -1)
		req_fmt.format = output->requested_format.format;

	// anything to do?
	if (G_LIKELY(format_eq(&req_fmt, &output->requested_format)))
		goto done;

	output_shutdown(output);

	err = "failed to alloc format context";
	output->fmtctx = avformat_alloc_context();
	if (!output->fmtctx)
		goto err;
	output->fmtctx->oformat = av_guess_format(output->file_format, NULL, NULL);
	err = "failed to determine output format";
	if (!output->fmtctx->oformat)
		goto err;

	// mask the channel multiplier from external view
	output->requested_format = *requested_format;
	req_fmt.channels *= output->channel_mult;

	if (encoder_config(output->encoder, output_codec, mp3_bitrate, 0, &req_fmt, &output->actual_format))
		goto err;

	if (output->actual_format.channels == req_fmt.channels)
		output->actual_format.channels /= output->channel_mult;
	// save the sample format
	if (requested_format->format == -1)
		output->requested_format.format = output->actual_format.format;

	err = "failed to alloc output stream";
	output->avst = avformat_new_stream(output->fmtctx, output->encoder->avc.codec);
	if (!output->avst)
		goto err;
	output->avst->time_base = output->encoder->avc.avcctx->time_base;

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 0, 0)
	// move the avcctx to avst as we already have an initialized avcctx
	if (output->avst->codec) {
		avcodec_close(output->avst->codec);
		avcodec_free_context(&output->avst->codec);
	}
	output->avst->codec = output->encoder->avc.avcctx;
#endif

#if LIBAVFORMAT_VERSION_INT >= AV_VERSION_INT(57, 26, 0) // exact version? present in 57.56
	avcodec_parameters_from_context(output->avst->codecpar, output->encoder->avc.avcctx);
#endif

	char *full_fn = NULL;
	char suff[16] = "";
	for (int i = 1; i < 20; i++) {
		if (!output->skip_filename_extension) {
			full_fn = g_strdup_printf("%s%s.%s", output->full_filename, suff, output->file_format);
		}
		else {
			full_fn = g_strdup_printf("%s%s", output->full_filename, suff);
		}
		if (!g_file_test(full_fn, G_FILE_TEST_EXISTS))
			goto got_fn;
		ilog(LOG_INFO, "Storing record in %s", full_fn);
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

	if (output_chmod)
		if (chmod(output->filename, output_chmod))
			ilog(LOG_WARN, "Failed to change file mode of '%s%s%s': %s",
					FMT_M(output->filename), strerror(errno));

	if (output_chown != -1 || output_chgrp != -1)
		if (chown(output->filename, output_chown, output_chgrp))
			ilog(LOG_WARN, "Failed to change file owner/group of '%s%s%s': %s",
					FMT_M(output->filename), strerror(errno));

	if (flush_packets) {
		output->fmtctx->flags |= AVFMT_FLAG_FLUSH_PACKETS;
	}

	db_config_stream(output);
	ilog(LOG_INFO, "Opened output media file '%s' for writing", full_fn);
done:
	if (actual_format)
		*actual_format = output->actual_format;
	return 0;

err:
	output_shutdown(output);
	ilog(LOG_ERR, "Error configuring media output: %s", err);
	if (av_ret)
		ilog(LOG_ERR, "Error returned from libav: %s", av_error(av_ret));
	return -1;
}


static bool output_shutdown(output_t *output) {
	if (!output)
		return false;
	if (!output->fmtctx)
		return false;

	ilog(LOG_INFO, "Closing output media file '%s'", output->filename);

	bool ret = false;
	if (output->fmtctx->pb) {
		av_write_trailer(output->fmtctx);
		avio_closep(&output->fmtctx->pb);
		ret = true;
	}
	avformat_free_context(output->fmtctx);

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57, 0, 0)
	// avoid double free - avcctx already freed
	output->encoder->avc.avcctx = NULL;
#endif

	encoder_close(output->encoder);

	output->fmtctx = NULL;
	output->avst = NULL;

	return ret;
}


void output_close(metafile_t *mf, output_t *output, tag_t *tag, bool discard) {
	if (!output)
		return;
	if (!discard) {
		if (output_shutdown(output)) {
			db_close_stream(output);
			notify_push_output(output, mf, tag);
		}
		else
			db_delete_stream(mf, output);
	}
	else {
		output_shutdown(output);
		if (unlink(output->filename))
			ilog(LOG_WARN, "Failed to unlink '%s%s%s': %s",
					FMT_M(output->filename), strerror(errno));
		db_delete_stream(mf, output);
	}
	encoder_free(output->encoder);
	g_clear_pointer(&output->full_filename, g_free);
	g_clear_pointer(&output->file_path, g_free);
	g_clear_pointer(&output->file_name, g_free);
	g_clear_pointer(&output->filename, g_free);
	g_slice_free1(sizeof(*output), output);
}


void output_init(const char *format) {
	str codec;

	if (!strcmp(format, "wav")) {
		codec = STR("PCM-S16LE");
		output_file_format = "wav";
	}
	else if (!strcmp(format, "mp3")) {
		codec = STR("MP3");
		output_file_format = "mp3";
	}
	else
		die("Unknown output format '%s'", format);

	output_codec = codec_find(&codec, MT_AUDIO);
	assert(output_codec != NULL);
}
