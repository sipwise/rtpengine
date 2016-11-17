#include "packet.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <glib.h>
#include <assert.h>
#include "types.h"
#include "log.h"
#include "rtplib.h"
#include "str.h"


static int packet_cmp(const void *A, const void *B, void *dummy) {
	const packet_t *a = A, *b = B;

	if (a->seq < b->seq)
		return -1;
	if (a->seq > b->seq)
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
	g_slice_free1(sizeof(*s), s);
}


// mf must be unlocked; returns ssrc locked
static ssrc_t *ssrc_get(metafile_t *mf, unsigned long ssrc) {
	pthread_mutex_lock(&mf->lock);
	ssrc_t *ret = g_hash_table_lookup(mf->ssrc_hash, GUINT_TO_POINTER(ssrc));
	if (ret)
		goto out;

	ret = g_slice_alloc0(sizeof(*ret));
	pthread_mutex_init(&ret->lock, NULL);
	ret->metafile = mf;
	ret->ssrc = ssrc;
	ret->packets = g_tree_new_full(packet_cmp, NULL, NULL, packet_free);
	ret->seq = -1;

	g_hash_table_insert(mf->ssrc_hash, GUINT_TO_POINTER(ssrc), ret);

out:
	pthread_mutex_lock(&ret->lock);
	pthread_mutex_unlock(&mf->lock);
	return ret;
}


static gboolean ssrc_tree_get_first(void *key, void *val, void *data) {
	packet_t **out = data;
	*out = val;
	return TRUE;
}


// ssrc is locked and must be unlocked when returning
static void ssrc_run(ssrc_t *ssrc) {
	// inspect first packet to see if seq is correct
	packet_t *first = NULL;
	g_tree_foreach(ssrc->packets, ssrc_tree_get_first, &first);
	assert(first != NULL);
	if (first->seq != ssrc->seq)
		goto out; // need to wait for more

	// determine payload type and run decoder
	unsigned int payload_type = first->rtp->m_pt & 0x7f;
	metafile_t *mf = ssrc->metafile;
	pthread_mutex_lock(&mf->payloads_lock);
	char *pt = mf->payload_types[payload_type];
	pthread_mutex_unlock(&mf->payloads_lock);

	dbg("processing packet seq %i, payload type is %s", first->seq, pt);
	g_tree_steal(ssrc->packets, first);
	dbg("packets left in queue: %i", g_tree_nnodes(ssrc->packets));
	ssrc->seq = (ssrc->seq + 1) & 0xffff;

	packet_free(first);

out:
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

	if (rtp_payload(&packet->rtp, &packet->payload, &bufstr))
		goto err;
	if (rtp_padding(packet->rtp, &packet->payload))
		goto err;

	packet->seq = ntohs(packet->rtp->seq_num);
	dbg("packet parsed successfully, seq %u", packet->seq);

	// insert into ssrc queue
	ssrc_t *ssrc = ssrc_get(stream->metafile, ntohl(packet->rtp->ssrc));

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
	if (g_tree_lookup(ssrc->packets, packet))
		goto dupe;
	g_tree_insert(ssrc->packets, packet, packet);

	// got a new packet, run the decoder
	ssrc_run(ssrc);
	return;

dupe:
	dbg("skipping dupe packet (new seq %i prev seq %i)", packet->seq, ssrc->seq);
	pthread_mutex_unlock(&ssrc->lock);
	return;

err:
	ilog(LOG_WARN, "Failed to parse packet headers");
	packet_free(packet);
}
