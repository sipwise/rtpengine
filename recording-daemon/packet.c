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


static int ptr_cmp(const void *a, const void *b, void *dummy) {
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}


static void packet_free(void *p) {
	packet_t *packet = p;
	if (!packet)
		return;
	free(packet->buffer);
	g_slice_free1(sizeof(*packet), packet);
}


void ssrc_free(void *p) {
	ssrc_t *s = p;
	g_tree_destroy(s->packets);
	output_close(s->output);
	for (int i = 0; i < G_N_ELEMENTS(s->decoders); i++)
		decoder_close(s->decoders[i]);
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
	ret->packets = g_tree_new_full(ptr_cmp, NULL, NULL, packet_free);
	ret->seq = -1;

	char buf[256];
	snprintf(buf, sizeof(buf), "%s-%08lx", mf->parent, ssrc);
	if (output_single) {
		ret->output = output_new(output_dir, buf);
		db_do_stream(mf, ret->output, "single", stream->id, ssrc);
	}

	g_hash_table_insert(mf->ssrc_hash, GUINT_TO_POINTER(ssrc), ret);

out:
	pthread_mutex_lock(&ret->lock);
	pthread_mutex_unlock(&mf->lock);
	return ret;
}


struct tree_searcher {
	int find_seq,
	    found_seq;
};
static int ssrc_tree_search(const void *testseq_p, const void *ts_p) {
	struct tree_searcher *ts = (void *) ts_p;
	int testseq = GPOINTER_TO_INT(testseq_p);
	// called as a binary search test function. we're looking for the lowest
	// seq number that is higher than find_seq. if our test number is too low,
	// we proceed with higher numbers. if it's too high, we proceed to the lower
	// numbers, but remember the lowest we've seen along that path.
	if (G_UNLIKELY(testseq == ts->find_seq)) {
		// we've struck gold
		ts->found_seq = testseq;
		return 0;
	}
	if (testseq < ts->find_seq)
		return 1;
	// testseq > ts->find_seq
	if (ts->found_seq == -1 || testseq < ts->found_seq)
		ts->found_seq = testseq;
	return -1;
}


// ssrc is locked
static packet_t *ssrc_next_packet(ssrc_t *ssrc) {
	// see if we have a packet with the correct seq nr in the queue
	packet_t *packet = g_tree_lookup(ssrc->packets, GINT_TO_POINTER(ssrc->seq));
	if (G_LIKELY(packet != NULL)) {
		dbg("returning in-sequence packet (seq %i)", ssrc->seq);
		return packet;
	}

	// why not? do we have anything? (we should)
	int nnodes = g_tree_nnodes(ssrc->packets);
	if (G_UNLIKELY(nnodes == 0)) {
		dbg("packet queue empty");
		return NULL;
	}
	if (G_LIKELY(nnodes < 10)) { // XXX arbitrary value
		dbg("only %i packets in queue - waiting for more", nnodes);
		return NULL; // need to wait for more
	}

	// packet was probably lost. search for the next highest seq
	struct tree_searcher ts = { .find_seq = ssrc->seq + 1, .found_seq = -1 };
	packet = g_tree_search(ssrc->packets, ssrc_tree_search, &ts);
	if (packet) {
		// bullseye
		dbg("lost packet - returning packet with next seq %i", packet->seq);
		return packet;
	}
	if (G_UNLIKELY(ts.found_seq == -1)) {
		// didn't find anything. seq must have wrapped around. retry
		// starting from zero
		ts.find_seq = 0;
		packet = g_tree_search(ssrc->packets, ssrc_tree_search, &ts);
		if (packet) {
			dbg("lost packet - returning packet with next seq %i (after wrap)", packet->seq);
			return packet;
		}
		if (G_UNLIKELY(ts.found_seq == -1))
			abort();
	}

	// pull out the packet we found
	packet = g_tree_lookup(ssrc->packets, GINT_TO_POINTER(ts.found_seq));
	if (G_UNLIKELY(packet == NULL))
		abort();

	dbg("lost multiple packets - returning packet with next highest seq %i", packet->seq);
	return packet;
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

		ssrc->decoders[payload_type] = decoder_new(payload_str);
		if (!ssrc->decoders[payload_type]) {
			ilog(LOG_WARN, "Cannot decode RTP payload type %u (%s)",
					payload_type, payload_str);
			return;
		}
	}

	if (decoder_input(ssrc->decoders[payload_type], &packet->payload, ntohl(packet->rtp->timestamp),
			ssrc->output, ssrc->metafile))
		ilog(LOG_ERR, "Failed to decode media packet");
}


// ssrc is locked and must be unlocked when returning
static void ssrc_run(ssrc_t *ssrc) {
	while (1) {
		// see if we have a packet with the correct seq nr in the queue
		packet_t *packet = ssrc_next_packet(ssrc);
		if (G_UNLIKELY(packet == NULL))
			break;

		dbg("processing packet seq %i", packet->seq);
		g_tree_steal(ssrc->packets, GINT_TO_POINTER(packet->seq));

		packet_decode(ssrc, packet);

		ssrc->seq = (packet->seq + 1) & 0xffff;
		packet_free(packet);
		dbg("packets left in queue: %i", g_tree_nnodes(ssrc->packets));
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

	packet->seq = ntohs(packet->rtp->seq_num);
	unsigned long ssrc_num = ntohl(packet->rtp->ssrc);
	log_info_ssrc = ssrc_num;
	dbg("packet parsed successfully, seq %u", packet->seq);

	// insert into ssrc queue
	ssrc_t *ssrc = ssrc_get(stream, ssrc_num);

	// check seq for dupes
	if (G_UNLIKELY(ssrc->seq == -1)) {
		// first packet we see
		ssrc->seq = packet->seq;
		goto seq_ok;
	}

	int diff = packet->seq - ssrc->seq;
	if (diff >= 0x8000)
		goto dupe;
	if (diff < 0 && diff > -0x8000)
		goto dupe;
	// seq ok - fall thru
seq_ok:
	if (g_tree_lookup(ssrc->packets, GINT_TO_POINTER(packet->seq)))
		goto dupe;
	g_tree_insert(ssrc->packets, GINT_TO_POINTER(packet->seq), packet);

	// got a new packet, run the decoder
	ssrc_run(ssrc);
	log_info_ssrc = 0;
	return;

dupe:
	dbg("skipping dupe packet (new seq %i prev seq %i)", packet->seq, ssrc->seq);
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
