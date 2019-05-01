#include <math.h>
#include "dtmf.h"
#include "media_socket.h"
#include "log.h"
#include "call.h"



struct dtmf_freq {
	unsigned int prim,
		     sec;
};

static const struct dtmf_freq dtmf_freqs[] = {
	{ 941, 1336 }, /* 0 */
	{ 697, 1209 }, /* 1 */
	{ 697, 1336 }, /* 2 */
	{ 697, 1477 }, /* 3 */
	{ 770, 1209 }, /* 4 */
	{ 770, 1336 }, /* 5 */
	{ 770, 1477 }, /* 6 */
	{ 852, 1209 }, /* 7 */
	{ 852, 1336 }, /* 8 */
	{ 852, 1477 }, /* 9 */
	{ 941, 1209 }, /* 10 = * */
	{ 941, 1477 }, /* 11 = # */
	{ 697, 1633 }, /* 12 = A */
	{ 770, 1633 }, /* 13 = B */
	{ 852, 1633 }, /* 14 = C */
	{ 941, 1633 }, /* 15 = D */
};



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

INLINE double freq2iter(unsigned int hz, unsigned int sample_rate) {
	double ret = hz;
	ret *= 2 * M_PI;
	ret /= sample_rate;
	return ret;
}

void dtmf_samples(void *buf, unsigned long offset, unsigned long num, unsigned int event, unsigned int volume,
		unsigned int sample_rate)
{
	int16_t *samples = buf;
	const struct dtmf_freq *df;

	if (event > G_N_ELEMENTS(dtmf_freqs)) {
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Unsupported DTMF event %u", event);
		memset(buf, 0, num * 2);
		return;
	}
	df = &dtmf_freqs[event];

	// XXX initialise/save these when the DTMF event starts
	double vol = pow(1.122018, volume) / 2.0;

	double prim_freq = freq2iter(df->prim, sample_rate);
	double sec_freq = freq2iter(df->sec, sample_rate);

	num += offset; // end here
	while (offset < num) {
		double prim = sin(prim_freq * offset) / vol;
		double sec = sin(sec_freq * offset) / vol;
		int16_t sample = prim * 32767.0 + sec * 32767.0;
		*samples++ = sample;
		offset++;
	}
}
