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
#include "resample.h"
#include "fix_frame_channel_layout.h"


#define DEFAULT_AVIO_BUFSIZE 4096

//static int output_codec_id;
static codec_def_t *output_codec;
static const char *output_file_format;

int mp3_bitrate;



static bool output_shutdown(output_t *output, FILE **, GString **);
static bool output_config_(sink_t *, output_t *output, const format_t *requested_format,
		format_t *actual_format);



static int output_got_packet(encoder_t *enc, void *u1, void *u2) {
	output_t *output = u1;

	dbg("{%s%s%s} output avpkt size is %i", FMT_M(output->file_name), (int) enc->avpkt->size);
	dbg("{%s%s%s} output pkt pts/dts is %li/%li", FMT_M(output->file_name), (long) enc->avpkt->pts,
			(long) enc->avpkt->dts);
	dbg("{%s%s%s} output dts %li", FMT_M(output->file_name), (long) output->encoder->mux_dts);

	av_write_frame(output->fmtctx, enc->avpkt);

	return 0;
}


bool sink_add(sink_t *sink, AVFrame *frame) {
	if (!sink)
		return false;

	// copy/init from frame
	if (G_UNLIKELY(sink->format.format == -1))
		sink->format.format = frame->format;
	if (G_UNLIKELY(sink->format.channels == -1))
		sink->format.channels = GET_CHANNELS(frame);
	if (G_UNLIKELY(sink->format.clockrate == -1))
		sink->format.clockrate = frame->sample_rate;

	format_t actual_format;
	if (!sink->config(sink, &sink->format, &actual_format))
		return false;

	AVFrame *copy_frame = av_frame_clone(frame);
	if (!copy_frame)
		return false;
	AVFrame *dec_frame = resample_frame(&sink->resampler, copy_frame, &actual_format);
	if (!dec_frame) {
		av_frame_free(&copy_frame);
		return false;
	}

	bool ok = sink->add(sink, dec_frame);

	if (dec_frame != copy_frame)
		av_frame_free(&copy_frame);

	return ok;
}


static bool output_add(sink_t *sink, AVFrame *frame) {
	bool ret = false;

	output_t *output = sink->output;
	if (!output->encoder) // not ready - not configured
		goto out;
	if (!output->fmtctx) // output not open
		goto out;
	ret = encoder_input_fifo(output->encoder, frame, output_got_packet, output, NULL) == 0;

out:
	av_frame_free(&frame);
	return ret;
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

void sink_init(sink_t *sink) {
	*sink = (__typeof(*sink)) {
		.mixer_idx = -1u,
	};
	format_init(&sink->format);
}

static bool output_config__(sink_t *s, const format_t *requested_format, format_t *actual_format) {
	return output_config_(s, s->output, requested_format, actual_format);
}

static output_t *output_alloc(const char *path, const char *name) {
	output_t *ret = g_new0(output_t, 1);
	ret->file_path = g_strdup(path);
	ret->file_name = g_strdup(name);
	ret->full_filename = g_strdup_printf("%s/%s", path, name);
	ret->file_format = output_file_format;
	ret->encoder = encoder_new();
	ret->requested_format.format = -1;
	ret->actual_format.format = -1;
	ret->start_time_us = now_us();

	sink_init(&ret->sink);
	ret->sink.output = ret;
	ret->sink.add = output_add;
	ret->sink.config = output_config__;

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

	ret->sink.format.format = AV_SAMPLE_FMT_S16;
	if (resample_audio > 0)
		ret->sink.format.clockrate = resample_audio;

	return ret;
}

#if LIBAVFORMAT_VERSION_INT >= AV_VERSION_INT(61, 0, 0)
static int output_avio_write(void *opaque, const uint8_t *buf, int buf_size) {
#else
static int output_avio_write(void *opaque, uint8_t *buf, int buf_size) {
#endif
	output_t *o = opaque;
	ssize_t written = fwrite(buf, buf_size, 1, o->fp);
	if (written == 1)
		return buf_size;
	return AVERROR(errno);
}

static int64_t output_avio_seek(void *opaque, int64_t offset, int whence) {
	output_t *o = opaque;
	fseek(o->fp, offset, whence);
	return ftell(o->fp);
}

#if LIBAVFORMAT_VERSION_INT >= AV_VERSION_INT(61, 0, 0)
static int output_avio_mem_write(void *opaque, const uint8_t *buf, int buf_size) {
#else
static int output_avio_mem_write(void *opaque, uint8_t *buf, int buf_size) {
#endif
	output_t *o = opaque;
	g_string_overwrite_len(o->membuf, o->mempos, (const char *) buf, buf_size);
	o->mempos += buf_size;
	return buf_size;
}

static int64_t output_avio_mem_seek(void *opaque, int64_t offset, int whence) {
	output_t *o = opaque;
	if (whence == SEEK_SET)
		o->mempos = offset;
	else if (whence == SEEK_CUR)
		o->mempos += offset;
	else if (whence == SEEK_END)
		o->mempos = o->membuf->len + offset;
	return o->mempos;
}

static bool output_config_(sink_t *sink, output_t *output, const format_t *requested_format,
		format_t *actual_format)
{
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

	output_shutdown(output, NULL, NULL);

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

	if (encoder_config(output->encoder, output_codec, mp3_bitrate, 0, &req_fmt, &output->actual_format))
		goto err;

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

	if ((output_storage & OUTPUT_STORAGE_MEMORY))
		goto no_output_file;

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

	err = "failed to open output file";
	output->fp = fopen(full_fn, (output_storage & OUTPUT_STORAGE_DB) ? "wb+" : "wb");
	if (!output->fp)
		goto err;

	if (output_buffer > 0) {
		err = "failed to alloc I/O buffer";
		output->iobuf = g_malloc(output_buffer);
		if (!output->iobuf)
			goto err;

		err = "failed to set I/O buffer";
		if (setvbuf(output->fp, output->iobuf, _IOFBF, output_buffer))
			goto err;
	}
	else {
		err = "failed to set unuffered I/O";
		if (setvbuf(output->fp, NULL, _IONBF, 0))
			goto err;
	}

no_output_file:
	err = "failed to alloc avio buffer";
	void *avio_buf = av_malloc(DEFAULT_AVIO_BUFSIZE);
	if (!avio_buf)
		goto err;

	if (!(output_storage & OUTPUT_STORAGE_MEMORY))
		output->avioctx = avio_alloc_context(avio_buf, DEFAULT_AVIO_BUFSIZE, 1, output,
				NULL, output_avio_write, output_avio_seek);
	else {
		output->membuf = g_string_new("");
		output->avioctx = avio_alloc_context(avio_buf, DEFAULT_AVIO_BUFSIZE, 1, output,
				NULL, output_avio_mem_write, output_avio_mem_seek);
	}
	err = "failed to alloc AVIOContext";
	if (!output->avioctx) {
		av_freep(&avio_buf);
		goto err;
	}

	output->fmtctx->pb = output->avioctx;

	err = "failed to write header";
	av_ret = avformat_write_header(output->fmtctx, NULL);
	if (av_ret)
		goto err;

	if (output_chmod && output->filename)
		if (chmod(output->filename, output_chmod))
			ilog(LOG_WARN, "Failed to change file mode of '%s%s%s': %s",
					FMT_M(output->filename), strerror(errno));

	if ((output_chown != -1 || output_chgrp != -1) && output->filename)
		if (chown(output->filename, output_chown, output_chgrp))
			ilog(LOG_WARN, "Failed to change file owner/group of '%s%s%s': %s",
					FMT_M(output->filename), strerror(errno));

	if (flush_packets) {
		output->fmtctx->flags |= AVFMT_FLAG_FLUSH_PACKETS;
	}

	db_config_stream(output);
	ilog(LOG_INFO, "Opened output media file '%s' for writing", full_fn ?: "(mem stream)");
done:
	if (actual_format)
		*actual_format = output->actual_format;
	return true;

err:
	output_shutdown(output, NULL, NULL);
	ilog(LOG_ERR, "Error configuring media output: %s", err);
	if (av_ret)
		ilog(LOG_ERR, "Error returned from libav: %s", av_error(av_ret));
	return false;
}


int output_config(output_t *output, const format_t *requested_format, format_t *actual_format) {
	return output_config_(NULL, output, requested_format, actual_format) ? 0 : -1;
}


static bool output_shutdown(output_t *output, FILE **fp, GString **gs) {
	if (!output)
		return false;
	if (!output->fmtctx)
		return false;

	ilog(LOG_INFO, "Closing output media file '%s'", output->filename ?: "(mem stream)");

	bool ret = false;
	if (output->fmtctx->pb)
		av_write_trailer(output->fmtctx);
	if (output->fp) {
		if (ftell(output->fp)) {
			ret = true;
			if (fp && (output_storage & OUTPUT_STORAGE_DB)) {
				*fp = output->fp;
				output->fp = NULL;
			}
		}
		if (output->fp)
			fclose(output->fp);
		output->fp = NULL;
	}
	else if (output->membuf) {
		if (output->membuf->len) {
			if (gs) {
				*gs = output->membuf;
				output->membuf = NULL;
			}
			ret = true;
		}
	}
	if (output->avioctx) {
		if (output->avioctx->buffer)
			av_freep(&output->avioctx->buffer);
		av_freep(&output->avioctx);
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


void sink_close(sink_t *sink) {
	resample_shutdown(&sink->resampler);
}


void output_close(metafile_t *mf, output_t *output, tag_t *tag, bool discard) {
	if (!output)
		return;
	if (!discard) {
		GString *membuf = NULL;
		FILE *fp = NULL;
		if (output_shutdown(output, &fp, &membuf)) {
			db_close_stream(output, fp, membuf);
			notify_push_output(output, mf, tag);
		}
		else {
			db_delete_stream(mf, output);
			if (membuf)
				g_string_free(membuf, TRUE);
		}
	}
	else {
		output_shutdown(output, NULL, NULL);
		if (output->filename && unlink(output->filename))
			ilog(LOG_WARN, "Failed to unlink '%s%s%s': %s",
					FMT_M(output->filename), strerror(errno));
		db_delete_stream(mf, output);
	}
	encoder_free(output->encoder);
	g_clear_pointer(&output->full_filename, g_free);
	g_clear_pointer(&output->file_path, g_free);
	g_clear_pointer(&output->file_name, g_free);
	g_clear_pointer(&output->filename, g_free);
	g_clear_pointer(&output->iobuf, g_free);
	if (output->membuf)
		g_string_free(output->membuf, TRUE);
	sink_close(&output->sink);
	g_free(output);
}


void output_init(const char *format) {
	str codec;

	if (!strcmp(format, "wav")) {
		codec = STR("X-L16");
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
