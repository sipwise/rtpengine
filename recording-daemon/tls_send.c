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


static ssize_t ssrc_tls_write(void *, const void *, size_t);
static ssize_t ssrc_tls_read(void *, void *, size_t);

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


void ssrc_tls_shutdown(ssrc_t *ssrc) {
	if (!ssrc->tls_fwd.stream)
		return;
	streambuf_destroy(ssrc->tls_fwd.stream);
	ssrc->tls_fwd.stream = NULL;
	resample_shutdown(&ssrc->tls_fwd.resampler);
	if (ssrc->tls_fwd.ssl) {
		SSL_free(ssrc->tls_fwd.ssl);
		ssrc->tls_fwd.ssl = NULL;
	}
	if (ssrc->tls_fwd.ssl_ctx) {
		SSL_CTX_free(ssrc->tls_fwd.ssl_ctx);
		ssrc->tls_fwd.ssl_ctx = NULL;
	}
	close_socket(&ssrc->tls_fwd.sock);
	ssrc->tls_fwd.sent_intro = 0;
}


void ssrc_tls_state(ssrc_t *ssrc) {
	int ret;

	ssrc_tls_log_errors();
	if (ssrc->tls_fwd.poller.state == PS_CONNECTING) {
		int status = connect_socket_retry(&ssrc->tls_fwd.sock);
		if (status == 0) {
			if (tls_disable) {
				ssrc->tls_fwd.poller.state = PS_OPEN;
				streambuf_writeable(ssrc->tls_fwd.stream);
			} else {
				dbg("TLS connection to %s doing handshake",
					endpoint_print_buf(&tls_send_to_ep));
				ssrc->tls_fwd.poller.state = PS_HANDSHAKE;
				if ((ret = SSL_connect(ssrc->tls_fwd.ssl)) == 1) {
					dbg("TLS connection to %s established",
							endpoint_print_buf(&tls_send_to_ep));
					ssrc->tls_fwd.poller.state = PS_OPEN;
					streambuf_writeable(ssrc->tls_fwd.stream);
				}
				else
					ssrc_tls_check_blocked(ssrc->tls_fwd.ssl, ret);
			}
		}
		else if (status < 0) {
			ilog(LOG_ERR, "Failed to connect TLS/TCP socket: %s", strerror(errno));
			ssrc_tls_shutdown(ssrc);
		}
	}
	else if (ssrc->tls_fwd.poller.state == PS_HANDSHAKE) {
		if (!tls_disable) {
			if ((ret = SSL_connect(ssrc->tls_fwd.ssl)) == 1) {
				dbg("TLS connection to %s established",
						endpoint_print_buf(&tls_send_to_ep));
				ssrc->tls_fwd.poller.state = PS_OPEN;
				streambuf_writeable(ssrc->tls_fwd.stream);
			}
			else
				ssrc_tls_check_blocked(ssrc->tls_fwd.ssl, ret);
		}
	}
	else if (ssrc->tls_fwd.poller.state == PS_WRITE_BLOCKED) {
		ssrc->tls_fwd.poller.state = PS_OPEN;
		streambuf_writeable(ssrc->tls_fwd.stream);
	}
	else if (ssrc->tls_fwd.poller.state == PS_ERROR)
		ssrc_tls_shutdown(ssrc);
	ssrc_tls_log_errors();
}


void ssrc_tls_fwd_silence_frames_upto(ssrc_t *ssrc, AVFrame *frame, int64_t upto) {
	unsigned int silence_samples = ssrc->tls_fwd.format.clockrate / 100;

	while (ssrc->tls_fwd.in_pts < upto) {
		if (G_UNLIKELY(upto - ssrc->tls_fwd.in_pts > ssrc->tls_fwd.format.clockrate * 30)) {
			ilog(LOG_WARN, "More than 30 seconds of silence needed to fill mix buffer, resetting");
			ssrc->tls_fwd.in_pts = upto;
			break;
		}
		if (G_UNLIKELY(!ssrc->tls_fwd.silence_frame)) {
			ssrc->tls_fwd.silence_frame = av_frame_alloc();
			ssrc->tls_fwd.silence_frame->format = ssrc->tls_fwd.format.format;
			DEF_CH_LAYOUT(&ssrc->tls_fwd.silence_frame->CH_LAYOUT, ssrc->tls_fwd.format.channels);
			ssrc->tls_fwd.silence_frame->nb_samples = silence_samples;
			ssrc->tls_fwd.silence_frame->sample_rate = ssrc->tls_fwd.format.clockrate;
			if (av_frame_get_buffer(ssrc->tls_fwd.silence_frame, 0) < 0) {
				ilog(LOG_ERR, "Failed to get silence frame buffers");
				return;
			}
			int planes = av_sample_fmt_is_planar(ssrc->tls_fwd.silence_frame->format) ? ssrc->tls_fwd.format.channels : 1;
			for (int i = 0; i < planes; i++)
				memset(ssrc->tls_fwd.silence_frame->extended_data[i], 0, ssrc->tls_fwd.silence_frame->linesize[0]);
		}

		dbg("pushing silence frame into TLS-formward stream (%lli < %llu)",
				(long long unsigned) ssrc->tls_fwd.in_pts,
				(long long unsigned) upto);

		ssrc->tls_fwd.silence_frame->pts = ssrc->tls_fwd.in_pts;
		ssrc->tls_fwd.silence_frame->nb_samples = MIN(silence_samples, upto - ssrc->tls_fwd.in_pts);
		ssrc->tls_fwd.in_pts += ssrc->tls_fwd.silence_frame->nb_samples;

		CH_LAYOUT_T channel_layout;
		DEF_CH_LAYOUT(&channel_layout, ssrc->tls_fwd.format.channels);
		ssrc->tls_fwd.silence_frame->CH_LAYOUT = channel_layout;

		int linesize = av_get_bytes_per_sample(frame->format) * ssrc->tls_fwd.silence_frame->nb_samples;
		dbg("Writing %u bytes PCM to TLS", linesize);
		streambuf_write(ssrc->tls_fwd.stream, (char *) ssrc->tls_fwd.silence_frame->extended_data[0], linesize);
	}
}


void tls_fwd_init(stream_t *stream, metafile_t *mf, ssrc_t *ssrc) {
	if ((!stream->forwarding_on && !mf->forwarding_on) || !tls_send_to_ep.port) {
		ssrc_tls_shutdown(ssrc);
		return;
	}
	if (ssrc->tls_fwd.stream)
		return;

	// initialise the connection
	ZERO(ssrc->tls_fwd.poller);
	if (!tls_disable) {
		dbg("Starting TLS connection to %s", endpoint_print_buf(&tls_send_to_ep));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ssrc->tls_fwd.ssl_ctx = SSL_CTX_new(TLS_client_method());
#else
		ssrc->tls_fwd.ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
		if (!ssrc->tls_fwd.ssl_ctx) {
			ilog(LOG_ERR, "Failed to create TLS context");
			ssrc_tls_shutdown(ssrc);
			return;
		}
		ssrc->tls_fwd.ssl = SSL_new(ssrc->tls_fwd.ssl_ctx);
		if (!ssrc->tls_fwd.ssl) {
			ilog(LOG_ERR, "Failed to create TLS connection");
			ssrc_tls_shutdown(ssrc);
			return;
		}
	} else {
		dbg("Starting TCP connection to %s", endpoint_print_buf(&tls_send_to_ep));
	}
	int status = connect_socket_nb(&ssrc->tls_fwd.sock, SOCK_STREAM, &tls_send_to_ep);
	if (status < 0) {
		ilog(LOG_ERR, "Failed to open/connect TLS/TCP socket to %s: %s",
			endpoint_print_buf(&tls_send_to_ep),
			strerror(errno));
		ssrc_tls_shutdown(ssrc);
		return;
	}

	ssrc->tls_fwd.poller.state = PS_CONNECTING;
	if (!tls_disable) {
		if (SSL_set_fd(ssrc->tls_fwd.ssl, ssrc->tls_fwd.sock.fd) != 1) {
			ilog(LOG_ERR, "Failed to set TLS fd");
			ssrc_tls_shutdown(ssrc);
			return;
		}
		ssrc->tls_fwd.stream = streambuf_new_ptr(&ssrc->tls_fwd.poller, ssrc->tls_fwd.ssl, &ssrc_tls_funcs);
	} else {
		ssrc->tls_fwd.stream = streambuf_new(&ssrc->tls_fwd.poller, ssrc->tls_fwd.sock.fd);
	}
	ssrc_tls_state(ssrc);

	ssrc->tls_fwd.format = (format_t) {
		.clockrate = tls_resample,
		.channels = 1,
		.format = AV_SAMPLE_FMT_S16,
	};
}
