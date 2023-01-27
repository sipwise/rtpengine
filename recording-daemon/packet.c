#include "packet.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <glib.h>
#include <unistd.h>
#include <openssl/err.h>
#include "types.h"
#include "log.h"
#include "rtplib.h"
#include "str.h"
#include "decoder.h"
#include "rtcplib.h"
#include "main.h"
#include "output.h"
#include "db.h"
#include "streambuf.h"
#include "resample.h"
#include "tag.h"


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

static void packet_free(void *p) {
	packet_t *packet = p;
	if (!packet)
		return;
	free(packet->buffer);
	g_slice_free1(sizeof(*packet), packet);
}


static void ssrc_tls_shutdown(ssrc_t *ssrc) {
	if (!ssrc->tls_fwd_stream)
		return;
	streambuf_destroy(ssrc->tls_fwd_stream);
	ssrc->tls_fwd_stream = NULL;
	resample_shutdown(&ssrc->tls_fwd_resampler);
	if (ssrc->ssl)
		SSL_free(ssrc->ssl);
	ssrc->ssl = NULL;
	if (ssrc->ssl_ctx)
		SSL_CTX_free(ssrc->ssl_ctx);
	ssrc->ssl_ctx = NULL;
	close_socket(&ssrc->tls_fwd_sock);
	ssrc->sent_intro = 0;
}


void ssrc_tls_state(ssrc_t *ssrc) {
	int ret;

	ssrc_tls_log_errors();
	if (ssrc->tls_fwd_poller.state == PS_CONNECTING) {
		int status = connect_socket_retry(&ssrc->tls_fwd_sock);
		if (status == 0) {
			dbg("TLS connection to %s doing handshake",
				endpoint_print_buf(&tls_send_to_ep));
			ssrc->tls_fwd_poller.state = PS_HANDSHAKE;
			if ((ret = SSL_connect(ssrc->ssl)) == 1) {
				dbg("TLS connection to %s established",
						endpoint_print_buf(&tls_send_to_ep));
				ssrc->tls_fwd_poller.state = PS_OPEN;
				streambuf_writeable(ssrc->tls_fwd_stream);
			}
			else
				ssrc_tls_check_blocked(ssrc->ssl, ret);
		}
		else if (status < 0) {
			ilog(LOG_ERR, "Failed to connect TLS socket: %s", strerror(errno));
			ssrc_tls_shutdown(ssrc);
		}
	}
	else if (ssrc->tls_fwd_poller.state == PS_HANDSHAKE) {
		if ((ret = SSL_connect(ssrc->ssl)) == 1) {
			dbg("TLS connection to %s established",
					endpoint_print_buf(&tls_send_to_ep));
			ssrc->tls_fwd_poller.state = PS_OPEN;
			streambuf_writeable(ssrc->tls_fwd_stream);
		}
		else
			ssrc_tls_check_blocked(ssrc->ssl, ret);
	}
	else if (ssrc->tls_fwd_poller.state == PS_WRITE_BLOCKED) {
		ssrc->tls_fwd_poller.state = PS_OPEN;
		streambuf_writeable(ssrc->tls_fwd_stream);
	}
	else if (ssrc->tls_fwd_poller.state == PS_ERROR)
		ssrc_tls_shutdown(ssrc);
	ssrc_tls_log_errors();
}


void ssrc_close(ssrc_t *s) {
	output_close(s->metafile, s->output, tag_get(s->metafile, s->stream->tag));
	s->output = NULL;
	for (int i = 0; i < G_N_ELEMENTS(s->decoders); i++) {
		decoder_free(s->decoders[i]);
		s->decoders[i] = NULL;
	}
	ssrc_tls_shutdown(s);
}

void ssrc_free(void *p) {
	ssrc_t *s = p;
	packet_sequencer_destroy(&s->sequencer);
	ssrc_close(s);
	g_slice_free1(sizeof(*s), s);
}

// mf must be unlocked; returns ssrc locked
static ssrc_t *ssrc_get(stream_t *stream, unsigned long ssrc) {
	metafile_t *mf = stream->metafile;
	pthread_mutex_lock(&mf->lock);
	ssrc_t *ret = g_hash_table_lookup(mf->ssrc_hash, GUINT_TO_POINTER(ssrc));
	if (ret)
		goto out;

	ret = g_slice_alloc0(sizeof(*ret));
	pthread_mutex_init(&ret->lock, NULL);
	ret->metafile = mf;
	ret->stream = stream;
	ret->ssrc = ssrc;
	packet_sequencer_init(&ret->sequencer, packet_free);

	g_hash_table_insert(mf->ssrc_hash, GUINT_TO_POINTER(ssrc), ret);

out:
	pthread_mutex_lock(&ret->lock);
	pthread_mutex_unlock(&mf->lock);

	dbg("Init for SSRC %s%lx%s of stream #%lu", FMT_M(ret->ssrc), stream->id);

	if (mf->recording_on && !ret->output && output_single) {
		dbg("Metadata %s, output destination %s", mf->metadata, mf->output_dest);
		if (mf->output_dest) {
			char path[PATH_MAX];
			size_t copied = g_strlcpy(path, mf->output_dest, sizeof(path));
			if (G_UNLIKELY(copied >= sizeof(path)))
				ilog(LOG_ERR, "Output file path truncated: %s", mf->output_dest);
			char *sep = strrchr(path, '/');
			if (sep) {
				char *filename = sep + 1;
				*sep = 0;
				ret->output = output_new_from_full_path(path, filename, "single");
				ret->output->skip_filename_extension = TRUE;
			}
			else {
				ret->output = output_new_from_full_path(output_dir, path, "single");
			}
		}
		else {
			char buf[16];
			snprintf(buf, sizeof(buf), "%08lx", ssrc);
			tag_t *tag = tag_get(mf, stream->tag);
			ret->output = output_new(output_dir, mf->parent, buf, "single", tag->label);
		}
		db_do_stream(mf, ret->output, stream, ssrc);
	}
	if ((stream->forwarding_on || mf->forwarding_on) && !ret->tls_fwd_stream && tls_send_to_ep.port) {
		// initialise the connection
		ZERO(ret->tls_fwd_poller);
		dbg("Starting TLS connection to %s", endpoint_print_buf(&tls_send_to_ep));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ret->ssl_ctx = SSL_CTX_new(TLS_client_method());
#else
		ret->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
		if (!ret->ssl_ctx) {
			ilog(LOG_ERR, "Failed to create TLS context");
			ssrc_tls_shutdown(ret);
			goto tls_out;
		}
		ret->ssl = SSL_new(ret->ssl_ctx);
		if (!ret->ssl) {
			ilog(LOG_ERR, "Failed to create TLS connection");
			ssrc_tls_shutdown(ret);
			goto tls_out;
		}
		int status = connect_socket_nb(&ret->tls_fwd_sock, SOCK_STREAM, &tls_send_to_ep);
		if (status < 0) {
			ilog(LOG_ERR, "Failed to open/connect TLS socket to %s: %s",
				endpoint_print_buf(&tls_send_to_ep),
				strerror(errno));
			ssrc_tls_shutdown(ret);
			goto tls_out;
		}

		ret->tls_fwd_poller.state = PS_CONNECTING;
		if (SSL_set_fd(ret->ssl, ret->tls_fwd_sock.fd) != 1) {
			ilog(LOG_ERR, "Failed to set TLS fd");
			ssrc_tls_shutdown(ret);
			goto tls_out;
		}
		ret->tls_fwd_stream = streambuf_new_ptr(&ret->tls_fwd_poller, ret->ssl, &ssrc_tls_funcs);

		ssrc_tls_state(ret);

		ret->tls_fwd_format = (format_t) {
			.clockrate = tls_resample,
			.channels = 1,
			.format = AV_SAMPLE_FMT_S16,
		};
tls_out:
		;
	}
	else if (!(stream->forwarding_on || mf->forwarding_on) && ret->tls_fwd_stream)
		ssrc_tls_shutdown(ret);

	return ret;
}


// ssrc is locked
static void packet_decode(ssrc_t *ssrc, packet_t *packet) {
	// determine payload type and run decoder
	unsigned int payload_type = packet->rtp->m_pt & 0x7f;
	// check if we have a decoder for this payload type yet
	if (G_UNLIKELY(!ssrc->decoders[payload_type])) {
		metafile_t *mf = ssrc->metafile;
		pthread_mutex_lock(&mf->payloads_lock);
		char *payload_str = mf->payload_types[payload_type];
		char *format = mf->payload_formats[payload_type];
		int ptime = mf->payload_ptimes[payload_type];
		pthread_mutex_unlock(&mf->payloads_lock);

		if (!payload_str) {
			const struct rtp_payload_type *rpt = rtp_get_rfc_payload_type(payload_type);
			if (!rpt) {
				ilog(LOG_WARN, "Unknown RTP payload type %u", payload_type);
				return;
			}
			payload_str = rpt->encoding_with_params.s;
		}

		dbg("payload type for %u is %s", payload_type, payload_str);

		pthread_mutex_lock(&mf->mix_lock);
		output_t *outp = NULL;
		if (mf->mix_out)
			outp = mf->mix_out;
		else if (ssrc->output)
			outp = ssrc->output;
		ssrc->decoders[payload_type] = decoder_new(payload_str, format, ptime, outp);
		pthread_mutex_unlock(&mf->mix_lock);
		if (!ssrc->decoders[payload_type]) {
			ilog(LOG_WARN, "Cannot decode RTP payload type %u (%s)",
					payload_type, payload_str);
			return;
		}
	}

	if (decoder_input(ssrc->decoders[payload_type], &packet->payload, ntohl(packet->rtp->timestamp),
			ssrc))
		ilog(LOG_ERR, "Failed to decode media packet");
}


// ssrc is locked and must be unlocked when returning
static void ssrc_run(ssrc_t *ssrc) {
	while (1) {
		// see if we have a packet with the correct seq nr in the queue
		packet_t *packet = packet_sequencer_next_packet(&ssrc->sequencer);
		if (G_UNLIKELY(packet == NULL))
			break;

		dbg("processing packet seq %i", packet->p.seq);

		packet_decode(ssrc, packet);

		packet_free(packet);
		dbg("packets left in queue: %i", g_tree_nnodes(ssrc->sequencer.packets));
	}

	pthread_mutex_unlock(&ssrc->lock);
}


// stream is unlocked, buf is malloc'd
void packet_process(stream_t *stream, unsigned char *buf, unsigned len) {
	packet_t *packet = g_slice_alloc0(sizeof(*packet));
	packet->buffer = buf; // handing it over

	// XXX more checking here
	str bufstr;
	str_init_len(&bufstr, packet->buffer, len);
	packet->ip = (void *) bufstr.s;
	// XXX kernel already does this - add metadata?
	if (packet->ip->version == 4) {
		if (str_shift(&bufstr, packet->ip->ihl << 2))
			goto err;
	}
	else {
		packet->ip = NULL;
		packet->ip6 = (void *) bufstr.s;
		if (str_shift(&bufstr, sizeof(*packet->ip6)))
			goto err;
	}

	packet->udp = (void *) bufstr.s;
	str_shift(&bufstr, sizeof(*packet->udp));

	if (rtcp_demux_is_rtcp(&bufstr))
		goto ignore; // for now

	if (rtp_payload(&packet->rtp, &packet->payload, &bufstr))
		goto err;
	if (rtp_padding(packet->rtp, &packet->payload))
		goto err;

	packet->p.seq = ntohs(packet->rtp->seq_num);
	unsigned long ssrc_num = ntohl(packet->rtp->ssrc);
	log_info_ssrc = ssrc_num;
	dbg("packet parsed successfully, seq %u", packet->p.seq);

	// insert into ssrc queue
	ssrc_t *ssrc = ssrc_get(stream, ssrc_num);
	if (packet_sequencer_insert(&ssrc->sequencer, &packet->p) < 0)
		goto dupe;

	// got a new packet, run the decoder
	ssrc_run(ssrc);
	log_info_ssrc = 0;
	return;

dupe:
	dbg("skipping dupe packet (new seq %i prev seq %i)", packet->p.seq, ssrc->sequencer.seq);
	pthread_mutex_unlock(&ssrc->lock);
	packet_free(packet);
	log_info_ssrc = 0;
	return;

err:
	ilog(LOG_WARN, "Failed to parse packet headers");
ignore:
	packet_free(packet);
	log_info_ssrc = 0;
}
