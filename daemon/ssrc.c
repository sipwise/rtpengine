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
static void free_rr_time(struct ssrc_rr_time_item *i) {
	g_slice_free1(sizeof(*i), i);
}
static void free_stats_block(struct ssrc_stats_block *ssb) {
	g_slice_free1(sizeof(*ssb), ssb);
}
static void free_ssrc_entry(struct ssrc_entry *e) {
	g_queue_clear_full(&e->sender_reports, (GDestroyNotify) free_sender_report);
	g_queue_clear_full(&e->rr_time_reports, (GDestroyNotify) free_rr_time);
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
	if (r < 0)
		r = 0;
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



static void *__do_time_report_item(struct call_media *m, size_t struct_size, size_t reports_queue_offset,
		const struct timeval *tv, u_int32_t ssrc, u_int32_t ntp_msw, u_int32_t ntp_lsw,
		GDestroyNotify free_func, struct ssrc_entry **e_p)
{
	struct call *c = m->call;
	struct ssrc_entry *e;
	struct ssrc_time_item *sti;

	sti = g_slice_alloc0(struct_size);
	sti->received = *tv;
	sti->ntp_middle_bits = ntp_msw << 16 | ntp_lsw >> 16;
	sti->ntp_ts = ntp_ts_to_double(ntp_msw, ntp_lsw);

	e = get_ssrc(ssrc, c->ssrc_hash);
	if (G_UNLIKELY(!e)) {
		free_func(sti);
		return NULL;
	}

	mutex_lock(&e->lock);

	GQueue *q = (((void *) e) + reports_queue_offset);

	g_queue_push_tail(q, sti);
	while (q->length > 10)
		free_func(g_queue_pop_head(q));

	*e_p = e;
	return sti;
}

static long long __calc_rtt(struct call *c, u_int32_t ssrc, u_int32_t ntp_middle_bits,
		u_int32_t delay, size_t reports_queue_offset, const struct timeval *tv, int *pt_p)
{
	if (pt_p)
		*pt_p = -1;

	if (!ntp_middle_bits || !delay)
		return 0;

	struct ssrc_entry *e = get_ssrc(ssrc, c->ssrc_hash);
	if (G_UNLIKELY(!e))
		return 0;

	if (pt_p)
		*pt_p = e->payload_type;

	struct ssrc_time_item *sti;
	GQueue *q = (((void *) e) + reports_queue_offset);
	mutex_lock(&e->lock);
	// go through the list backwards until we find the SR referenced
	for (GList *l = q->tail; l; l = l->prev) {
		sti = l->data;
		if (sti->ntp_middle_bits != ntp_middle_bits)
			continue;
		goto found;
	}

	// not found
	mutex_unlock(&e->lock);
	return 0;

found:;
	// `e` remains locked for access to `sti`
	long long rtt = timeval_diff(tv, &sti->received);

	mutex_unlock(&e->lock);

	rtt -= (long long) delay * 1000000LL / 65536LL;
	ilog(LOG_DEBUG, "Calculated round-trip time for %u is %lli us", ssrc, rtt);

	if (rtt <= 0 || rtt > 10000000) {
		ilog(LOG_DEBUG, "Invalid RTT - discarding");
		return 0;
	}

	e->last_rtt = rtt;

	return rtt;
}

void ssrc_sender_report(struct call_media *m, const struct ssrc_sender_report *sr,
		const struct timeval *tv)
{
	struct ssrc_entry *e;
	struct ssrc_sender_report_item *seri = __do_time_report_item(m, sizeof(*seri),
			G_STRUCT_OFFSET(struct ssrc_entry, sender_reports), tv, sr->ssrc,
			sr->ntp_msw, sr->ntp_lsw, (GDestroyNotify) free_sender_report, &e);
	if (!seri)
		return;

	seri->report = *sr;

	ilog(LOG_DEBUG, "SR from %u: RTP TS %u PC %u OC %u NTP TS %u/%u=%f",
			sr->ssrc, sr->timestamp, sr->packet_count, sr->octet_count,
			sr->ntp_msw, sr->ntp_lsw, seri->time_item.ntp_ts);

	mutex_unlock(&e->lock);
}
void ssrc_receiver_report(struct call_media *m, const struct ssrc_receiver_report *rr,
		const struct timeval *tv)
{
	struct call *c = m->call;

	ilog(LOG_DEBUG, "RR from %u about %u: FL %u TL %u HSR %u J %u LSR %u DLSR %u",
			rr->from, rr->ssrc, rr->fraction_lost, rr->packets_lost,
			rr->high_seq_received, rr->jitter, rr->lsr, rr->dlsr);

	int pt;

	long long rtt = __calc_rtt(c, rr->ssrc, rr->lsr, rr->dlsr,
			G_STRUCT_OFFSET(struct ssrc_entry, sender_reports), tv, &pt);

	struct ssrc_entry *other_e = get_ssrc(rr->from, c->ssrc_hash);
	if (G_UNLIKELY(!other_e))
		goto out_nl;

	// determine the clock rate for jitter values
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

out_ul_oe:
	mutex_unlock(&other_e->lock);
	goto out_nl;
out_nl:
	;
}

void ssrc_receiver_rr_time(struct call_media *m, const struct ssrc_xr_rr_time *rr,
		const struct timeval *tv)
{
	struct ssrc_entry *e;
	struct ssrc_rr_time_item *srti = __do_time_report_item(m, sizeof(*srti),
			G_STRUCT_OFFSET(struct ssrc_entry, rr_time_reports), tv, rr->ssrc,
			rr->ntp_msw, rr->ntp_lsw, (GDestroyNotify) free_rr_time, &e);
	if (!srti)
		return;

	ilog(LOG_DEBUG, "XR RR TIME from %u: NTP TS %u/%u=%f",
			rr->ssrc,
			rr->ntp_msw, rr->ntp_lsw, srti->time_item.ntp_ts);

	mutex_unlock(&e->lock);
}

void ssrc_receiver_dlrr(struct call_media *m, const struct ssrc_xr_dlrr *dlrr,
		const struct timeval *tv)
{
	ilog(LOG_DEBUG, "XR DLRR from %u about %u: LRR %u DLRR %u",
			dlrr->from, dlrr->ssrc,
			dlrr->lrr, dlrr->dlrr);

	__calc_rtt(m->call, dlrr->ssrc, dlrr->lrr, dlrr->dlrr,
			G_STRUCT_OFFSET(struct ssrc_entry, rr_time_reports), tv, NULL);
}

void ssrc_voip_metrics(struct call_media *m, const struct ssrc_xr_voip_metrics *vm,
		const struct timeval *tv)
{
	ilog(LOG_DEBUG, "XR VM from %u about %u: LR %u DR %u BD %u GD %u BDu %u GDu %u RTD %u "
			"ESD %u SL %u NL %u RERL %u GMin %u R %u eR %u MOSL %u MOSC %u RX %u "
			"JBn %u JBm %u JBam %u",
			vm->from, vm->ssrc,
			vm->loss_rate, vm->discard_rate, vm->burst_den, vm->gap_den,
			vm->burst_dur, vm->gap_dur, vm->rnd_trip_delay, vm->end_sys_delay,
			vm->signal_lvl, vm->noise_lvl, vm->rerl, vm->gmin, vm->r_factor,
			vm->ext_r_factor, vm->mos_lq, vm->mos_cq, vm->rx_config, vm->jb_nom,
			vm->jb_max, vm->jb_abs_max);

	struct call *c = m->call;
	struct ssrc_entry *e = get_ssrc(vm->ssrc, c->ssrc_hash);
	if (!e)
		return;
	e->last_rtt = vm->rnd_trip_delay;
}
