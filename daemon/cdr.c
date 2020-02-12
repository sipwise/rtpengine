#include <inttypes.h>
#include "rtplib.h"
#include "cdr.h"
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
static const char *const __opmode_texts[] = {
	[OP_OFFER] = "offer",
	[OP_ANSWER] = "answer",
};

const char * get_tag_type_text(enum tag_type t) {
	return get_enum_array_text(__tag_type_texts, t, "UNKNOWN");
}
const char *get_opmode_text(enum call_opmode m) {
	return get_enum_array_text(__opmode_texts, m, "other");
}

static const char * get_term_reason_text(enum termination_reason t) {
	return get_enum_array_text(__term_reason_texts, t, "UNKNOWN");
}

void cdr_update_entry(struct call* c) {
	GList *l;
	struct call_monologue *ml;
	struct timeval tim_result_duration;
	int printlen=0;
	int cdrlinecnt = 0;
	static const int CDRBUFLENGTH = 4096*2;
	char cdrbuffer[CDRBUFLENGTH];
	char* cdrbufcur = cdrbuffer;
	char* cdrbufend = cdrbuffer+CDRBUFLENGTH-1;
	struct call_media *md;
	GList *k, *o;
	const struct rtp_payload_type *rtp_pt;
	struct packet_stream *ps=0;

	if (IS_OWN_CALL(c)) {

		/* CDRs and statistics */
		if (_log_facility_cdr) {
			printlen = snprintf(cdrbufcur,CDRBUFREMAINDER,"ci=%s, ",c->callid.s);
			ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
			printlen = snprintf(cdrbufcur,CDRBUFREMAINDER,"created_from=%s, ", c->created_from);
			ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
			printlen = snprintf(cdrbufcur,CDRBUFREMAINDER,"last_signal=%llu, ", (unsigned long long)c->last_signal.tv_sec);
			ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
			printlen = snprintf(cdrbufcur,CDRBUFREMAINDER,"tos=%u, ", (unsigned int)c->tos);
			ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
		}

		for (l = c->monologues.head; l; l = l->next) {
			ml = l->data;

			if (!ml->terminated.tv_sec) {
				gettimeofday(&ml->terminated, NULL);
				ml->term_reason = UNKNOWN;
			}

			timeval_subtract(&tim_result_duration,&ml->terminated,&ml->started);

			if (_log_facility_cdr) {
				printlen = snprintf(cdrbufcur, CDRBUFREMAINDER,
					"ml%i_start_time=%ld.%06lu, "
					"ml%i_end_time=%ld.%06ld, "
					"ml%i_duration=%ld.%06ld, "
					"ml%i_termination=%s, "
					"ml%i_local_tag=%s, "
					"ml%i_local_tag_type=%s, "
					"ml%i_remote_tag=%s, ",
					cdrlinecnt, ml->started.tv_sec, ml->started.tv_usec,
					cdrlinecnt, ml->terminated.tv_sec, ml->terminated.tv_usec,
					cdrlinecnt, tim_result_duration.tv_sec, tim_result_duration.tv_usec,
					cdrlinecnt, get_term_reason_text(ml->term_reason),
					cdrlinecnt, ml->tag.s,
					cdrlinecnt, get_tag_type_text(ml->tagtype),
					cdrlinecnt, ml->active_dialogue ? ml->active_dialogue->tag.s : "(none)");
				ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
			}

			for (k = ml->medias.head; k; k = k->next) {
				md = k->data;

				rtp_pt = __rtp_stats_codec(md);

				/* add PayloadType(codec) info in CDR logging */
				if (_log_facility_cdr && rtp_pt) {
					printlen = snprintf(cdrbufcur, CDRBUFREMAINDER, "payload_type=%u, ", rtp_pt->payload_type);
					ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
				} else if (_log_facility_cdr && !rtp_pt) {
					printlen = snprintf(cdrbufcur, CDRBUFREMAINDER, "payload_type=unknown, ");
					ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
				}

				for (o = md->streams.head; o; o = o->next) {
					ps = o->data;

					if (PS_ISSET(ps, FALLBACK_RTCP))
						continue;

					char *addr = sockaddr_print_buf(&ps->endpoint.address);
                                        char *local_addr = ps->selected_sfd ? sockaddr_print_buf(&ps->selected_sfd->socket.local.address) : "0.0.0.0";

					if (_log_facility_cdr) {
					    const char* protocol = (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? "rtcp" : "rtp";

					    if(!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) {
						printlen = snprintf(cdrbufcur, CDRBUFREMAINDER,
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
							cdrlinecnt, md->index, protocol,
							(ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.packets),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.bytes),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.errors),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->last_packet),
							cdrlinecnt, md->index, protocol,
							ps->stats.in_tos_tclass);
						ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
					    } else {
#if (RE_HAS_MEASUREDELAY)
					    	printlen = snprintf(cdrbufcur, CDRBUFREMAINDER,
							"ml%i_midx%u_%s_endpoint_ip=%s, "
							"ml%i_midx%u_%s_endpoint_port=%u, "
					    	        "ml%i_midx%u_%s_local_relay_ip=%s, "
							"ml%i_midx%u_%s_local_relay_port=%u, "
							"ml%i_midx%u_%s_relayed_packets="UINT64F", "
							"ml%i_midx%u_%s_relayed_bytes="UINT64F", "
							"ml%i_midx%u_%s_relayed_errors="UINT64F", "
							"ml%i_midx%u_%s_last_packet="UINT64F", "
							"ml%i_midx%u_%s_in_tos_tclass=%" PRIu8 ", "
							"ml%i_midx%u_%s_delay_min=%.9f, "
							"ml%i_midx%u_%s_delay_avg=%.9f, "
							"ml%i_midx%u_%s_delay_max=%.9f, ",
							cdrlinecnt, md->index, protocol, addr,
							cdrlinecnt, md->index, protocol, ps->endpoint.port,
							cdrlinecnt, md->index, protocol, local_addr,
							cdrlinecnt, md->index, protocol, (unsigned int) (ps->sfd ? ps->sfd->fd.localport : 0),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.packets),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.bytes),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.errors),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->last_packet),
							cdrlinecnt, md->index, protocol,
							ps->stats.in_tos_tclass,
							cdrlinecnt, md->index, protocol, (double) ps->stats.delay_min / 1000000,
							cdrlinecnt, md->index, protocol, (double) ps->stats.delay_avg / 1000000,
							cdrlinecnt, md->index, protocol, (double) ps->stats.delay_max / 1000000);
						ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
#else
						printlen = snprintf(cdrbufcur, CDRBUFREMAINDER,
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
							cdrlinecnt, md->index, protocol,
							(ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.packets),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.bytes),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->stats.errors),
							cdrlinecnt, md->index, protocol,
							atomic64_get(&ps->last_packet),
							cdrlinecnt, md->index, protocol,
							ps->stats.in_tos_tclass);
						ADJUSTLEN(printlen,cdrbufend,cdrbufcur);
#endif
					    }
					}

				}
			}
			if (_log_facility_cdr)
			    ++cdrlinecnt;
		}
		/* log it */
		cdrlog(cdrbuffer);
	}
}

