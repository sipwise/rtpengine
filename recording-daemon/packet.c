#include "packet.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <glib.h>
#include <unistd.h>
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


static void packet_free(void *p) {
	packet_t *packet = p;
	if (!packet)
		return;
	free(packet->buffer);
	g_slice_free1(sizeof(*packet), packet);
}


void ssrc_free(void *p) {
	ssrc_t *s = p;
	packet_sequencer_destroy(&s->sequencer);
	output_close(s->output);
	for (int i = 0; i < G_N_ELEMENTS(s->decoders); i++)
		decoder_free(s->decoders[i]);
	if (s->tcp_fwd_stream) {
		close_socket(&s->tcp_fwd_sock);
		streambuf_destroy(s->tcp_fwd_stream);
		s->tcp_fwd_stream = NULL;
		resample_shutdown(&s->tcp_fwd_resampler);
	}
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

	if (mf->recording_on && !ret->output && output_single) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s-%08lx", mf->parent, ssrc);
		ret->output = output_new(output_dir, buf);
		db_do_stream(mf, ret->output, "single", stream, ssrc);
	}
	if ((stream->forwarding_on || mf->forwarding_on) && !ret->tcp_fwd_stream) {
		ZERO(ret->tcp_fwd_poller);
		ilog(LOG_DEBUG, "Starting TCP connection to %s", endpoint_print_buf(&tcp_send_to_ep));
		int status = connect_socket_nb(&ret->tcp_fwd_sock, SOCK_STREAM, &tcp_send_to_ep);
		if (status >= 0) {
			ret->tcp_fwd_stream = streambuf_new(&ret->tcp_fwd_poller, ret->tcp_fwd_sock.fd);
			if (status == 1)
				ret->tcp_fwd_poller.blocked = 1;
			else {
				ilog(LOG_DEBUG, "TCP connection to %s established",
						endpoint_print_buf(&tcp_send_to_ep));
				ret->tcp_fwd_poller.connected = 1;
			}
		}
		else
			ilog(LOG_ERR, "Failed to open/connect TCP socket to %s: %s",
				endpoint_print_buf(&tcp_send_to_ep),
				strerror(errno));
		ret->tcp_fwd_format = (format_t) {
			.clockrate = tcp_resample,
			.channels = 1,
			.format = AV_SAMPLE_FMT_S16,
		};
	}
	else if (!(stream->forwarding_on || mf->forwarding_on) && ret->tcp_fwd_stream) {
		// XXX same as above - unify
		close_socket(&ret->tcp_fwd_sock);
		streambuf_destroy(ret->tcp_fwd_stream);
		ret->tcp_fwd_stream = NULL;
		resample_shutdown(&ret->tcp_fwd_resampler);
	}

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
		ssrc->decoders[payload_type] = decoder_new(payload_str, outp);
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
	if (packet_sequencer_insert(&ssrc->sequencer, &packet->p))
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
