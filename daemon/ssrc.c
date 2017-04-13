#include "ssrc.h"
#include <glib.h>
#include "aux.h"
#include "call.h"
#include "rtplib.h"



static void init_ssrc_ctx(struct ssrc_ctx *c, struct ssrc_entry *parent) {
	c->parent = parent;
}
static struct ssrc_entry *create_ssrc_entry(u_int32_t ssrc) {
	struct ssrc_entry *ent;
	ent = g_slice_alloc0(sizeof(struct ssrc_entry));
	ent->ssrc = ssrc;
	mutex_init(&ent->lock);
	ent->payload_type = -1;
	init_ssrc_ctx(&ent->input_ctx, ent);
	init_ssrc_ctx(&ent->output_ctx, ent);
	return ent;
}
static void add_ssrc_entry(struct ssrc_entry *ent, struct ssrc_hash *ht) {
	g_hash_table_replace(ht->ht, &ent->ssrc, ent);
}
static void free_sender_report(struct ssrc_sender_report_item *i) {
	g_slice_free1(sizeof(*i), i);
}
static void free_stats_block(struct ssrc_stats_block *ssb) {
	g_slice_free1(sizeof(*ssb), ssb);
}
static void free_ssrc_entry(struct ssrc_entry *e) {
	g_queue_clear_full(&e->sender_reports, (GDestroyNotify) free_sender_report);
	g_queue_clear_full(&e->stats_blocks, (GDestroyNotify) free_stats_block);
	g_slice_free1(sizeof(*e), e);
}

// returned as mos * 10 (i.e. 10 - 50 for 1.0 to 5.0)
static void mos_calc(struct ssrc_stats_block *ssb) {
	// as per https://www.pingman.com/kb/article/how-is-mos-calculated-in-pingplotter-pro-50.html
	int eff_rtt = ssb->rtt / 1000 + ssb->jitter * 2 + 10;
	double r; // XXX can this be done with int math?
	if (eff_rtt < 160)
		r = 93.2 - eff_rtt / 40.0;
	else
		r = 93.2 - (eff_rtt - 120) / 40.0;
	r = r - (ssb->packetloss * 2.5);
	double mos = 1.0 + (0.035) * r + (.000007) * r * (r-60) * (100-r);
	int64_t intmos = mos * 10.0;
	if (intmos < 0)
		intmos = 0;
	ssb->mos = intmos;
}

struct ssrc_entry *find_ssrc(u_int32_t ssrc, struct ssrc_hash *ht) {
	rwlock_lock_r(&ht->lock);
	struct ssrc_entry *ret = g_hash_table_lookup(ht->ht, &ssrc);
	rwlock_unlock_r(&ht->lock);
	return ret;
}
struct ssrc_entry *get_ssrc(u_int32_t ssrc, struct ssrc_hash *ht /* , int *created */) {
	struct ssrc_entry *ent;

restart:
	ent = find_ssrc(ssrc, ht);
	if (G_LIKELY(ent)) {
//		if (created)
//			*created = 0;
		return ent;
	}

	ent = create_ssrc_entry(ssrc);

	rwlock_lock_w(&ht->lock);

	if (G_UNLIKELY(g_hash_table_size(ht->ht) > 20)) { // arbitrary limit
		rwlock_unlock_w(&ht->lock);
		free_ssrc_entry(ent);
		ilog(LOG_INFO, "SSRC hash table exceeded size limit (trying to add %u)", ssrc);
		return NULL;
	}

	if (g_hash_table_lookup(ht->ht, &ssrc)) {
		// preempted
		rwlock_unlock_w(&ht->lock);
		free_ssrc_entry(ent);
		goto restart;
	}
	add_ssrc_entry(ent, ht);
	rwlock_unlock_w(&ht->lock);
//	if (created)
//		*created = 1;
	return ent;
}
void free_ssrc_hash(struct ssrc_hash **ht) {
	if (!*ht)
		return;
	g_hash_table_destroy((*ht)->ht);
	g_slice_free1(sizeof(**ht), *ht);
	*ht = NULL;
}


struct ssrc_hash *create_ssrc_hash(void) {
	struct ssrc_hash *ret;
	ret = g_slice_alloc0(sizeof(*ret));
	ret->ht = g_hash_table_new_full(uint32_hash, uint32_eq, NULL, (GDestroyNotify) free_ssrc_entry);
	rwlock_init(&ret->lock);
	return ret;
}

struct ssrc_ctx *get_ssrc_ctx(u_int32_t ssrc, struct ssrc_hash *ht, enum ssrc_dir dir) {
	struct ssrc_entry *s = get_ssrc(ssrc, ht /* , NULL */);
	if (G_UNLIKELY(!s))
		return NULL;
	return ((void *) s) + dir;
}



void ssrc_sender_report(struct call_media *m, const struct ssrc_sender_report *sr,
		const struct timeval *tv)
{
	struct call *c = m->call;
	struct ssrc_entry *e;
	struct ssrc_sender_report_item *seri;

	seri = g_slice_alloc(sizeof(*seri));
	seri->received = *tv;
	seri->report = *sr;
	seri->ntp_middle_bits = sr->ntp_msw << 16 | sr->ntp_lsw >> 16;

	ilog(LOG_DEBUG, "SR from %u: RTP TS %u PC %u OC %u NTP TS %u/%u=%f",
			sr->ssrc, sr->timestamp, sr->packet_count, sr->octet_count,
			sr->ntp_msw, sr->ntp_lsw, sr->ntp_ts);

	e = get_ssrc(sr->ssrc, c->ssrc_hash);
	if (G_UNLIKELY(!e)) {
		free_sender_report(seri);
		return;
	}

	mutex_lock(&e->lock);

	g_queue_push_tail(&e->sender_reports, seri);
	while (e->sender_reports.length > 10)
		free_sender_report(g_queue_pop_head(&e->sender_reports));

	mutex_unlock(&e->lock);
}
void ssrc_receiver_report(struct call_media *m, const struct ssrc_receiver_report *rr,
		const struct timeval *tv)
{
	struct call *c = m->call;

	ilog(LOG_DEBUG, "RR from %u about %u: FL %u TL %u HSR %u J %u LSR %u DLSR %u",
			rr->from, rr->ssrc, rr->fraction_lost, rr->packets_lost,
			rr->high_seq_received, rr->jitter, rr->lsr, rr->dlsr);

	if (!rr->lsr || !rr->dlsr)
		return; // no delay to be known

	struct ssrc_entry *e = get_ssrc(rr->ssrc, c->ssrc_hash);
	if (G_UNLIKELY(!e))
		return;

	struct ssrc_sender_report_item *seri;
	mutex_lock(&e->lock);
	// go through the list backwards until we find the SR referenced
	for (GList *l = e->sender_reports.tail; l; l = l->prev) {
		seri = l->data;
		if (seri->ntp_middle_bits != rr->lsr)
			continue;
		goto found;
	}

	// not found
	goto out_ul_e;

found:
	// `e` remains locked for access to `seri`
	ilog(LOG_DEBUG, "RR from %u reports delay %u from %u", rr->from, rr->dlsr, rr->ssrc);
	long long rtt = timeval_diff(tv, &seri->received);

	mutex_unlock(&e->lock);

	rtt -= (long long) rr->dlsr * 1000000LL / 65536LL;
	ilog(LOG_DEBUG, "Calculated round-trip time for %u is %lli us", rr->ssrc, rtt);

	if (rtt <= 0 || rtt > 10000000) {
		ilog(LOG_DEBUG, "Invalid RTT - discarding");
		goto out_nl;
	}

	e->last_rtt = rtt;

	struct ssrc_entry *other_e = get_ssrc(rr->from, c->ssrc_hash);
	if (G_UNLIKELY(!other_e))
		goto out_nl;

	// determine the clock rate for jitter values
	int pt = e->payload_type;
	if (pt < 0) {
		pt = other_e->payload_type;
		if (pt < 0) {
			ilog(LOG_DEBUG, "No payload type known for RTCP RR, discarding");
			goto out_nl;
		}
	}

	const struct rtp_payload_type *rpt = rtp_payload_type(pt, m->rtp_payload_types);
	if (!rpt) {
		ilog(LOG_INFO, "Invalid RTP payload type %i, discarding RTCP RR", pt);
		goto out_nl;
	}
	unsigned int jitter = rpt->clock_rate ? (rr->jitter * 1000 / rpt->clock_rate) : rr->jitter;
	ilog(LOG_DEBUG, "Calculated jitter for %u is %u ms", rr->ssrc, jitter);

	ilog(LOG_DEBUG, "Adding opposide side RTT of %u us", other_e->last_rtt);

	struct ssrc_stats_block *ssb = g_slice_alloc(sizeof(*ssb));
	*ssb = (struct ssrc_stats_block) {
		.jitter = jitter,
		.rtt = rtt + other_e->last_rtt,
		.reported = *tv,
		.packetloss = (unsigned int) rr->fraction_lost * 100 / 256,
	};

	mos_calc(ssb);
	ilog(LOG_DEBUG, "Calculated MOS from RR for %u is %.1f", rr->from, (double) ssb->mos / 10.0);

	// got a new stats block, add it to reporting ssrc
	mutex_lock(&other_e->lock);

	// discard stats block if last has been received less than a second ago
	if (G_LIKELY(other_e->stats_blocks.length > 0)) {
		struct ssrc_stats_block *last_ssb = g_queue_peek_tail(&other_e->stats_blocks);
		if (G_UNLIKELY(timeval_diff(tv, &last_ssb->reported) < 1000000)) {
			free_stats_block(ssb);
			goto out_ul_oe;
		}
	}

	g_queue_push_tail(&other_e->stats_blocks, ssb);

	if (G_UNLIKELY(!other_e->lowest_mos) || ssb->mos < other_e->lowest_mos->mos)
		other_e->lowest_mos = ssb;
	if (G_UNLIKELY(!other_e->highest_mos) || ssb->mos > other_e->highest_mos->mos)
		other_e->highest_mos = ssb;

	// running tally
	other_e->average_mos.jitter += ssb->jitter;
	other_e->average_mos.rtt += ssb->rtt;
	other_e->average_mos.packetloss += ssb->packetloss;
	other_e->average_mos.mos += ssb->mos;

	goto out_ul_oe;

out_ul_e:
	mutex_unlock(&e->lock);
	goto out_nl;
out_ul_oe:
	mutex_unlock(&other_e->lock);
	goto out_nl;
out_nl:
	;
}
