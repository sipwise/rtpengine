#include "cdr.h"

#include <inttypes.h>

#include "rtplib.h"
#include "call.h"
#include "poller.h"
#include "str.h"

#define CDRBUFREMAINDER cdrbufend-cdrbufcur

static const char * const __term_reason_texts[] = {
	[TIMEOUT] = "TIMEOUT",
	[REGULAR] = "REGULAR",
	[FORCED] = "FORCED",
	[SILENT_TIMEOUT] = "SILENT_TIMEOUT",
	[FINAL_TIMEOUT] = "FINAL_TIMEOUT",
	[OFFER_TIMEOUT] = "OFFER_TIMEOUT",
};
static const char * const __tag_type_texts[] = {
	[FROM_TAG] = "FROM_TAG",
	[TO_TAG] = "TO_TAG",
};
const char * get_tag_type_text(enum tag_type t) {
	return get_enum_array_text(__tag_type_texts, t, "UNKNOWN");
}
const char *get_opmode_text(enum ng_opmode m) {
	return get_enum_array_text(ng_command_strings, m, "other");
}

static const char * get_term_reason_text(enum termination_reason t) {
	return get_enum_array_text(__term_reason_texts, t, "UNKNOWN");
}

void cdr_update_entry(call_t * c) {
	struct call_monologue *ml;
	struct timeval tim_result_duration;
	int cdrlinecnt = 0;
	g_autoptr(GString) cdr = g_string_new("");
	struct call_media *md;
	const rtp_payload_type *rtp_pt;
	struct packet_stream *ps=0;

	if (!IS_OWN_CALL(c))
		return;

	/* CDRs and statistics */
	if (_log_facility_cdr) {
		g_string_append_printf(cdr, "ci=%s, ",c->callid.s);
		g_string_append_printf(cdr, "created_from=%s, ", c->created_from);
		g_string_append_printf(cdr, "last_signal=%llu, ", (unsigned long long)c->last_signal);
		g_string_append_printf(cdr, "tos=%u, ", (unsigned int)c->tos);
	}

	for (__auto_type l = c->monologues.head; l; l = l->next) {
		ml = l->data;

		if (!ml->terminated.tv_sec) {
			gettimeofday(&ml->terminated, NULL);
			ml->term_reason = UNKNOWN;
		}

		timeval_subtract(&tim_result_duration,&ml->terminated,&ml->started);

		if (_log_facility_cdr) {
			g_string_append_printf(cdr,
				"ml%i_start_time=%" TIME_T_INT_FMT ".%06" TIME_T_INT_FMT ", "
				"ml%i_end_time=%" TIME_T_INT_FMT ".%06" TIME_T_INT_FMT ", "
				"ml%i_duration=%" TIME_T_INT_FMT ".%06" TIME_T_INT_FMT ", "
				"ml%i_termination=%s, "
				"ml%i_local_tag=%s, "
				"ml%i_local_tag_type=%s, ",
				cdrlinecnt, ml->started.tv_sec, ml->started.tv_usec,
				cdrlinecnt, ml->terminated.tv_sec, ml->terminated.tv_usec,
				cdrlinecnt, tim_result_duration.tv_sec, tim_result_duration.tv_usec,
				cdrlinecnt, get_term_reason_text(ml->term_reason),
				cdrlinecnt, ml->tag.s,
				cdrlinecnt, get_tag_type_text(ml->tagtype));

			g_auto(GQueue) mls = G_QUEUE_INIT; /* to avoid duplications */
			for (int i = 0; i < ml->medias->len; i++)
			{
				struct call_media * media = ml->medias->pdata[i];
				if (!media)
					continue;

				for (__auto_type sub = media->media_subscriptions.head; sub; sub = sub->next)
				{
					struct media_subscription * ms = sub->data;
					if (!g_queue_find(&mls, ms->monologue)) {
						g_string_append_printf(cdr, "ml%i_remote_tag=%s, ", cdrlinecnt, ms->monologue->tag.s);
						g_queue_push_tail(&mls, ms->monologue);
					}
				}
			}
		}

		for (unsigned int i = 0; i < ml->medias->len; i++) {
			md = ml->medias->pdata[i];
			if (!md)
				continue;

			rtp_pt = __rtp_stats_codec(md);

			/* add PayloadType(codec) info in CDR logging */
			if (_log_facility_cdr && rtp_pt) {
				g_string_append_printf(cdr, "payload_type=%u, ", rtp_pt->payload_type);
			} else if (_log_facility_cdr && !rtp_pt) {
				g_string_append_printf(cdr, "payload_type=unknown, ");
			}

			for (__auto_type o = md->streams.head; o; o = o->next) {
				ps = o->data;

				if (PS_ISSET(ps, FALLBACK_RTCP))
					continue;

				char *addr = sockaddr_print_buf(&ps->endpoint.address);
				char *local_addr = sockaddr_print_buf(&ps->last_local_endpoint.address);

				if (_log_facility_cdr) {
				    const char* protocol = (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? "rtcp" : "rtp";

				    if(!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) {
					g_string_append_printf(cdr,
						"ml%i_midx%u_%s_endpoint_ip=%s, "
						"ml%i_midx%u_%s_endpoint_port=%u, "
						"ml%i_midx%u_%s_local_relay_ip=%s, "
						"ml%i_midx%u_%s_local_relay_port=%u, "
						"ml%i_midx%u_%s_relayed_packets="UINT64F", "
						"ml%i_midx%u_%s_relayed_bytes="UINT64F", "
						"ml%i_midx%u_%s_relayed_errors="UINT64F", "
						"ml%i_midx%u_%s_last_packet="UINT64F", "
						"ml%i_midx%u_%s_in_tos_tclass=%" PRIu8 ", ",
						cdrlinecnt, md->index, protocol, addr,
						cdrlinecnt, md->index, protocol, ps->endpoint.port,
						cdrlinecnt, md->index, protocol, local_addr,
						cdrlinecnt, md->index, protocol, ps->last_local_endpoint.port,
						cdrlinecnt, md->index, protocol,
						atomic64_get_na(&ps->stats_in->packets),
						cdrlinecnt, md->index, protocol,
						atomic64_get_na(&ps->stats_in->bytes),
						cdrlinecnt, md->index, protocol,
						atomic64_get_na(&ps->stats_in->errors),
						cdrlinecnt, md->index, protocol,
						packet_stream_last_packet(ps),
						cdrlinecnt, md->index, protocol,
						atomic_get_na(&ps->stats_in->tos));
				    } else {
					g_string_append_printf(cdr,
						"ml%i_midx%u_%s_endpoint_ip=%s, "
						"ml%i_midx%u_%s_endpoint_port=%u, "
						"ml%i_midx%u_%s_local_relay_ip=%s, "
						"ml%i_midx%u_%s_local_relay_port=%u, "
						"ml%i_midx%u_%s_relayed_packets="UINT64F", "
						"ml%i_midx%u_%s_relayed_bytes="UINT64F", "
						"ml%i_midx%u_%s_relayed_errors="UINT64F", "
						"ml%i_midx%u_%s_last_packet="UINT64F", "
						"ml%i_midx%u_%s_in_tos_tclass=%" PRIu8 ", ",
						cdrlinecnt, md->index, protocol, addr,
						cdrlinecnt, md->index, protocol, ps->endpoint.port,
						cdrlinecnt, md->index, protocol, local_addr,
						cdrlinecnt, md->index, protocol, ps->last_local_endpoint.port,
						cdrlinecnt, md->index, protocol,
						atomic64_get_na(&ps->stats_in->packets),
						cdrlinecnt, md->index, protocol,
						atomic64_get_na(&ps->stats_in->bytes),
						cdrlinecnt, md->index, protocol,
						atomic64_get_na(&ps->stats_in->errors),
						cdrlinecnt, md->index, protocol,
						packet_stream_last_packet(ps),
						cdrlinecnt, md->index, protocol,
						atomic_get_na(&ps->stats_in->tos));
				    }
				}

			}
		}
		if (_log_facility_cdr)
		    ++cdrlinecnt;
	}
	/* log it */
	cdrlog(cdr->str);
}
