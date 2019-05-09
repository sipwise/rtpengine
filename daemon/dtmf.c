#include "dtmf.h"
#include "media_socket.h"
#include "log.h"
#include "call.h"
#include "dtmflib.h"



static GString *dtmf_json_print(struct media_packet *mp,
		struct telephone_event_payload *dtmf, int clockrate)
{
	if (!dtmf->end)
		return NULL;

	GString *buf = g_string_new("");

	if (!clockrate)
		clockrate = 8000;

	g_string_append_printf(buf, "{"
			"\"callid\":\"" STR_FORMAT "\","
			"\"source_tag\":\"" STR_FORMAT "\","
			"\"tags\":[",
			STR_FMT(&mp->call->callid),
			STR_FMT(&mp->media->monologue->tag));

	GList *tag_values = g_hash_table_get_values(mp->call->tags);
	int i = 0;
	for (GList *tag_it = tag_values; tag_it; tag_it = tag_it->next) {
		struct call_monologue *ml = tag_it->data;
		if (i != 0)
			g_string_append(buf, ",");
		g_string_append_printf(buf, "\"" STR_FORMAT "\"",
				STR_FMT(&ml->tag));
		i++;
	}
	g_list_free(tag_values);

	g_string_append_printf(buf, "],"
			"\"type\":\"DTMF\",\"timestamp\":%lu,\"source_ip\":\"%s\","
			"\"event\":%u,\"duration\":%u,\"volume\":%u}",
			(unsigned long) rtpe_now.tv_sec,
			sockaddr_print_buf(&mp->fsin.address),
			(unsigned int) dtmf->event,
			(ntohs(dtmf->duration) * (1000000 / clockrate)) / 1000,
			(unsigned int) dtmf->volume);

	return buf;
}

int dtmf_event(struct media_packet *mp, str *payload, int clockrate) {
	struct telephone_event_payload *dtmf;
	if (payload->len < sizeof(*dtmf)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Short DTMF event packet (len %u)", payload->len);
		return -1;
	}
	dtmf = (void *) payload->s;

	ilog(LOG_DEBUG, "DTMF event: event %u, volume %u, end %u, duration %u",
			dtmf->event, dtmf->volume, dtmf->end, dtmf->duration);

	int ret = 0;

	if (_log_facility_dtmf) {
		GString *buf = dtmf_json_print(mp, dtmf, clockrate);
		if (buf) {
			dtmflog(buf);
			ret = 1; // END event
		}
	}

	return ret;
}
