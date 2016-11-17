#include "packet.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <glib.h>
#include "types.h"
#include "log.h"
#include "rtplib.h"
#include "str.h"


static int packet_cmp(const void *A, const void *B) {
	const packet_t *a = A, *b = B;

	if (a->seq < b->seq)
		return -1;
	if (a->seq > b->seq)
		return 1;
	return 0;
}


// mf must be unlocked
static ssrc_t *ssrc_get(metafile_t *mf, unsigned long ssrc) {
	pthread_mutex_lock(&mf->lock);
	ssrc_t *ret = g_hash_table_lookup(mf->ssrc_hash, GUINT_TO_POINTER(ssrc));
	if (ret)
		goto out;

	ret = g_slice_alloc0(sizeof(*ret));
	ret->ssrc = ssrc;
	ret->packets = g_tree_new(packet_cmp);

	g_hash_table_insert(mf->ssrc_hash, GUINT_TO_POINTER(ssrc), ret);

out:
	pthread_mutex_unlock(&mf->lock);
	return ret;
}


static void packet_free(packet_t *packet) {
	if (!packet)
		return;
	free(packet->buffer);
	g_slice_free1(sizeof(*packet), packet);
}


// stream is unlocked, buf is malloc'd
void packet_process(stream_t *stream, unsigned char *buf, unsigned len) {
	packet_t *packet = g_slice_alloc0(sizeof(*packet));
	packet->buffer = buf;
	buf = NULL;

	// XXX more checking here
	str bufstr;
	str_init_len(&bufstr, packet->buffer, len);
	packet->ip = (void *) bufstr.s;
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

	packet->seq = ntohs(packet->rtp->seq_num);
	dbg("packet parsed successfully, seq %u", packet->seq);

	// insert into ssrc queue
	ssrc_t *ssrc = ssrc_get(stream->metafile, ntohl(packet->rtp->ssrc));
	g_tree_insert(ssrc->packets, packet, packet); // XXX check for collisions XXX locking

	return;

err:
	ilog(LOG_WARN, "Failed to parse packet headers");
	free(buf);
	packet_free(packet);
}
