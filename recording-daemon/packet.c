#include "packet.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <glib.h>
#include "types.h"
#include "log.h"
#include "rtplib.h"
#include "str.h"

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

	dbg("packet parsed successfully");
	goto out;

err:
	ilog(LOG_WARN, "Failed to parse packet headers");
out:
	free(buf);
	packet_free(packet);
}
