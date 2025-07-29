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
#include "fix_frame_channel_layout.h"
#include "tls_send.h"
#include "mix.h"


static void packet_free(void *p) {
	packet_t *packet = p;
	if (!packet)
		return;
	free(packet->buffer);
	g_free(packet);
}

// appropriate lock must be held (ssrc or metafile)
void ssrc_close(ssrc_t *s) {
	output_close(s->metafile, s->output, tag_get(s->metafile, s->stream->tag), s->metafile->discard);
	s->output = NULL;
	for (int i = 0; i < G_N_ELEMENTS(s->decoders); i++) {
		decoder_free(s->decoders[i]);
		s->decoders[i] = NULL;
	}
	tls_fwd_shutdown(&s->tls_fwd);
}

void ssrc_free(void *p) {
	ssrc_t *s = p;
	packet_sequencer_destroy(&s->sequencer);
	ssrc_close(s);
	g_free(s);
}

// mf must be unlocked; returns ssrc locked
static ssrc_t *ssrc_get(stream_t *stream, unsigned long ssrc) {
	metafile_t *mf = stream->metafile;
	pthread_mutex_lock(&mf->lock);
	if (!mf->ssrc_hash) {
		pthread_mutex_unlock(&mf->lock);
		return NULL;
	}
	ssrc_t *ret = g_hash_table_lookup(mf->ssrc_hash, GUINT_TO_POINTER(ssrc));
	if (ret)
		goto out;

	ret = g_new0(__typeof(*ret), 1);
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

	if (mf->recording_on && output_single) {
		if (!ret->output) {
			char buf[16];
			snprintf(buf, sizeof(buf), "%08lx", ssrc);
			tag_t *tag = tag_get(mf, stream->tag);
			ret->output = output_new_ext(mf, buf, "single", tag->label);
		}

		db_do_stream(mf, ret->output, stream, ssrc);
	}

	tls_fwd_init(stream, mf, ret);

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
		ssrc->decoders[payload_type] = decoder_new(payload_str, format, ptime);

		mix_sink_init(&ssrc->decoders[payload_type]->mix_sink, ssrc, &mf->mix,
				resample_audio);
		mix_sink_init(&ssrc->decoders[payload_type]->tls_mix_sink, ssrc, &mf->tls_mix,
				tls_resample);

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
	packet_t *packet = g_new0(__typeof(*packet), 1);
	packet->buffer = buf; // handing it over

	// XXX more checking here
	str bufstr = STR_LEN(packet->buffer, len);
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

	if (!(packet->rtp = rtp_payload(&packet->payload, &bufstr)))
		goto err;
	if (!rtp_padding(packet->rtp, &packet->payload))
		goto err;

	packet->p.seq = ntohs(packet->rtp->seq_num);
	unsigned long ssrc_num = ntohl(packet->rtp->ssrc);
	log_info_ssrc = ssrc_num;
	dbg("packet parsed successfully, seq %u", packet->p.seq);

	// insert into ssrc queue
	ssrc_t *ssrc = ssrc_get(stream, ssrc_num);
	if (!ssrc) // stream shutdown
		goto out;
	if (packet_sequencer_insert(&ssrc->sequencer, &packet->p) < 0) {
		dbg("skipping dupe packet (new seq %i prev seq %i)", packet->p.seq, ssrc->sequencer.seq);
		goto skip;
	}

	// got a new packet, run the decoder
	ssrc_run(ssrc);
	log_info_ssrc = 0;
	return;

skip:
	pthread_mutex_unlock(&ssrc->lock);
out:
	packet_free(packet);
	log_info_ssrc = 0;
	return;

err:
	ilog(LOG_WARN, "Failed to parse packet headers");
ignore:
	packet_free(packet);
	log_info_ssrc = 0;
}
