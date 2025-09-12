#include "tls_send.h"
#include <glib.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "log.h"
#include "types.h"
#include "resample.h"
#include "main.h"
#include "streambuf.h"
#include "fix_frame_channel_layout.h"
#include "output.h"
#include "tag.h"


static ssize_t ssrc_tls_write(void *, const void *, size_t);
static ssize_t ssrc_tls_read(void *, void *, size_t);
static void tls_fwd_state(tls_fwd_t *tls_fwd);

static struct streambuf_funcs ssrc_tls_funcs = {
	.write = ssrc_tls_write,
	.read = ssrc_tls_read,
};

static void ssrc_tls_log_errors(void) {
	int i;
	char err[160];
	while ((i = ERR_get_error())) {
		ERR_error_string(i, err);
		dbg("TLS error: %s", err);
	}
}

static int ssrc_tls_check_blocked(SSL *ssl, int ret) {
	if (!ssl)
		return 0;
	int err = SSL_get_error(ssl, ret);
	dbg("TLS error code: %i -> %i", ret, err);
	switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			return 0; // eof
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			errno = EAGAIN;
			return -1;
		case SSL_ERROR_SYSCALL:
			return -1;
	}
	errno = EFAULT;
	return -1;
}

static ssize_t ssrc_tls_write(void *fd, const void *b, size_t s) {
	SSL *ssl = fd;
	ssrc_tls_log_errors();
	int ret = SSL_write(ssl, b, s);
	if (ret > 0)
		return ret;
	return ssrc_tls_check_blocked(ssl, ret);
}
static ssize_t ssrc_tls_read(void *fd, void *b, size_t s) {
	SSL *ssl = fd;
	ssrc_tls_log_errors();
	int ret = SSL_read(ssl, b, s);
	if (ret > 0)
		return ret;
	return ssrc_tls_check_blocked(ssl, ret);
}


void tls_fwd_free(tls_fwd_t **p) {
	tls_fwd_t *tls_fwd = *p;
	tls_fwd_shutdown(tls_fwd);
	g_clear_pointer(p, g_free);
}

void tls_fwd_shutdown(tls_fwd_t *tls_fwd) {
	if (!tls_fwd)
		return;
	streambuf_destroy(tls_fwd->stream);
	tls_fwd->stream = NULL;
	if (tls_fwd->ssl) {
		SSL_free(tls_fwd->ssl);
		tls_fwd->ssl = NULL;
	}
	if (tls_fwd->ssl_ctx) {
		SSL_CTX_free(tls_fwd->ssl_ctx);
		tls_fwd->ssl_ctx = NULL;
	}
	close_socket(&tls_fwd->sock);
	av_frame_free(&tls_fwd->silence_frame);
	sink_close(&tls_fwd->sink);
	tls_fwd->sent_intro = 0;
	ZERO(tls_fwd->poller);
}


static bool tls_fwd_connect(tls_fwd_t *tls_fwd) {
	// initialise the connection
	ZERO(tls_fwd->poller);
	if (!tls_disable) {
		dbg("Starting TLS connection to %s", endpoint_print_buf(&tls_send_to_ep));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		tls_fwd->ssl_ctx = SSL_CTX_new(TLS_client_method());
#else
		tls_fwd->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
		if (!tls_fwd->ssl_ctx) {
			ilog(LOG_ERR, "Failed to create TLS context");
			tls_fwd_shutdown(tls_fwd);
			return false;
		}
		tls_fwd->ssl = SSL_new(tls_fwd->ssl_ctx);
		if (!tls_fwd->ssl) {
			ilog(LOG_ERR, "Failed to create TLS connection");
			tls_fwd_shutdown(tls_fwd);
			return false;
		}
	} else {
		dbg("Starting TCP connection to %s", endpoint_print_buf(&tls_send_to_ep));
	}
	int status = connect_socket_nb(&tls_fwd->sock, SOCK_STREAM, &tls_send_to_ep);
	if (status < 0) {
		ilog(LOG_ERR, "Failed to open/connect TLS/TCP socket to %s: %s",
			endpoint_print_buf(&tls_send_to_ep),
			strerror(errno));
		tls_fwd_shutdown(tls_fwd);
		return false;
	}

	tls_fwd->poller.state = PS_CONNECTING;
	if (!tls_disable) {
		if (SSL_set_fd(tls_fwd->ssl, tls_fwd->sock.fd) != 1) {
			ilog(LOG_ERR, "Failed to set TLS fd");
			tls_fwd_shutdown(tls_fwd);
			return false;
		}
		tls_fwd->stream = streambuf_new_ptr(&tls_fwd->poller, tls_fwd->ssl, &ssrc_tls_funcs);
	} else {
		tls_fwd->stream = streambuf_new(&tls_fwd->poller, tls_fwd->sock.fd);
	}

	tls_fwd_state(tls_fwd);

	return true;
}

static void tls_fwd_state(tls_fwd_t *tls_fwd) {
	if (!tls_fwd)
		return;

	int ret;

	ssrc_tls_log_errors();

	if (tls_fwd->poller.state == PS_CLOSED)
		tls_fwd_connect(tls_fwd);

	if (tls_fwd->poller.state == PS_CONNECTING) {
		int status = connect_socket_retry(&tls_fwd->sock);
		if (status == 0) {
			if (tls_disable) {
				tls_fwd->poller.state = PS_OPEN;
				streambuf_writeable(tls_fwd->stream);
			} else {
				dbg("TLS connection to %s doing handshake",
					endpoint_print_buf(&tls_send_to_ep));
				tls_fwd->poller.state = PS_HANDSHAKE;
				if ((ret = SSL_connect(tls_fwd->ssl)) == 1) {
					dbg("TLS connection to %s established",
							endpoint_print_buf(&tls_send_to_ep));
					tls_fwd->poller.state = PS_OPEN;
					streambuf_writeable(tls_fwd->stream);
				}
				else
					ssrc_tls_check_blocked(tls_fwd->ssl, ret);
			}
		}
		else if (status < 0) {
			ilog(LOG_ERR, "Failed to connect TLS/TCP socket: %s", strerror(errno));
			tls_fwd_shutdown(tls_fwd);
		}
	}
	else if (tls_fwd->poller.state == PS_HANDSHAKE) {
		if (!tls_disable) {
			if ((ret = SSL_connect(tls_fwd->ssl)) == 1) {
				dbg("TLS connection to %s established",
						endpoint_print_buf(&tls_send_to_ep));
				tls_fwd->poller.state = PS_OPEN;
				streambuf_writeable(tls_fwd->stream);
			}
			else
				ssrc_tls_check_blocked(tls_fwd->ssl, ret);
		}
	}
	else if (tls_fwd->poller.state == PS_WRITE_BLOCKED) {
		tls_fwd->poller.state = PS_OPEN;
		streambuf_writeable(tls_fwd->stream);
	}
	else if (tls_fwd->poller.state == PS_ERROR)
		tls_fwd_shutdown(tls_fwd);
	ssrc_tls_log_errors();
}


static void tls_fwd_silence_frames_upto(tls_fwd_t *tls_fwd, AVFrame *frame, int64_t upto) {
	unsigned int silence_samples = tls_fwd->format.clockrate / 100;

	while (tls_fwd->in_pts < upto) {
		if (G_UNLIKELY(upto - tls_fwd->in_pts > tls_fwd->format.clockrate * 30)) {
			ilog(LOG_WARN, "More than 30 seconds of silence needed to fill mix buffer, resetting");
			tls_fwd->in_pts = upto;
			break;
		}
		if (G_UNLIKELY(!tls_fwd->silence_frame)) {
			tls_fwd->silence_frame = av_frame_alloc();
			tls_fwd->silence_frame->format = tls_fwd->format.format;
			DEF_CH_LAYOUT(&tls_fwd->silence_frame->CH_LAYOUT, tls_fwd->format.channels);
			tls_fwd->silence_frame->nb_samples = silence_samples;
			tls_fwd->silence_frame->sample_rate = tls_fwd->format.clockrate;
			if (av_frame_get_buffer(tls_fwd->silence_frame, 0) < 0) {
				ilog(LOG_ERR, "Failed to get silence frame buffers");
				return;
			}
			int planes = av_sample_fmt_is_planar(tls_fwd->silence_frame->format) ? tls_fwd->format.channels : 1;
			for (int i = 0; i < planes; i++)
				memset(tls_fwd->silence_frame->extended_data[i], 0, tls_fwd->silence_frame->linesize[0]);
		}

		dbg("pushing silence frame into TLS-formward stream (%lli < %llu)",
				(long long unsigned) tls_fwd->in_pts,
				(long long unsigned) upto);

		tls_fwd->silence_frame->pts = tls_fwd->in_pts;
		tls_fwd->silence_frame->nb_samples = MIN(silence_samples, upto - tls_fwd->in_pts);
		tls_fwd->in_pts += tls_fwd->silence_frame->nb_samples;

		CH_LAYOUT_T channel_layout;
		DEF_CH_LAYOUT(&channel_layout, tls_fwd->format.channels);
		tls_fwd->silence_frame->CH_LAYOUT = channel_layout;

		int linesize = av_get_bytes_per_sample(frame->format) * tls_fwd->silence_frame->nb_samples;
		dbg("Writing %u bytes PCM to TLS", linesize);
		streambuf_write(tls_fwd->stream, (char *) tls_fwd->silence_frame->extended_data[0], linesize);
	}
}


static bool tls_fwd_add(sink_t *sink, AVFrame *frame) {
	tls_fwd_t **p = sink->tls_fwd;
	tls_fwd_t *tls_fwd = *p;

	tls_fwd_state(tls_fwd);

	// if we're in the middle of a disconnect then ssrc_tls_state may have destroyed the streambuf
	// so we need to skip the below to ensure we only send metadata for the new connection
	// once we've got a new streambuf
	if (!tls_fwd || !tls_fwd->stream) {
		av_frame_free(&frame);
		return false;
	}

	if (!tls_fwd->sent_intro) {
		ssrc_t *ssrc = tls_fwd->ssrc;
		metafile_t *metafile = tls_fwd->metafile;
		tag_t *tag = NULL;

		if (ssrc && ssrc->stream)
			tag = tag_get(metafile, ssrc->stream->tag);

		if (tag && tag->metadata) {
			dbg("Writing tag metadata header to TLS");
			streambuf_write(tls_fwd->stream, tag->metadata, strlen(tag->metadata) + 1);
		}
		else if (metafile->metadata) {
			dbg("Writing call metadata header to TLS");
			streambuf_write(tls_fwd->stream, metafile->metadata, strlen(metafile->metadata) + 1);
		}
		else {
			ilog(LOG_WARN, "No metadata present for forwarding connection");
			streambuf_write(tls_fwd->stream, "\0", 1);
		}
		tls_fwd->sent_intro = 1;
	}

	tls_fwd_silence_frames_upto(tls_fwd, frame, frame->pts);
	uint64_t next_pts = frame->pts + frame->nb_samples;
	if (next_pts > tls_fwd->in_pts)
		tls_fwd->in_pts = next_pts;

	int linesize = av_get_bytes_per_sample(frame->format) * frame->nb_samples * GET_CHANNELS(frame);
	dbg("Writing %u bytes PCM to TLS", linesize);
	streambuf_write(tls_fwd->stream, (char *) frame->extended_data[0], linesize);

	av_frame_free(&frame);

	return true;
}


static bool tls_fwd_config(sink_t *sink, const format_t *requested_format, format_t *actual_format) {
	tls_fwd_t *tls_fwd = *sink->tls_fwd;
	*actual_format = sink->format;
	tls_fwd->format = sink->format;
	return true;
}


bool tls_fwd_new(tls_fwd_t **tlsp) {
	if (*tlsp)
		return true;

	tls_fwd_t *tls_fwd = *tlsp = g_new0(tls_fwd_t, 1);

	if (!tls_fwd_connect(tls_fwd)) {
		tls_fwd_free(tlsp);
		return false;
	}

	sink_init(&tls_fwd->sink);
	tls_fwd->sink.tls_fwd = tlsp;
	tls_fwd->sink.add = tls_fwd_add;
	tls_fwd->sink.config = tls_fwd_config;

	tls_fwd->sink.format.format = AV_SAMPLE_FMT_S16;
	tls_fwd->sink.format.clockrate = tls_resample;
	tls_fwd->sink.format.channels = 1;

	return true;
}


void tls_fwd_init(stream_t *stream, metafile_t *mf, ssrc_t *ssrc) {
	if ((!stream->forwarding_on && !mf->forwarding_on) || !tls_send_to_ep.port || tls_mixed) {
		tls_fwd_free(&ssrc->tls_fwd);
		return;
	}

	if (!tls_fwd_new(&ssrc->tls_fwd))
		return;

	ssrc->tls_fwd->ssrc = ssrc;
	ssrc->tls_fwd->metafile = mf;
}
