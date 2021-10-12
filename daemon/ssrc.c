#include "ssrc.h"
#include <glib.h>
#include "aux.h"
#include "call.h"
#include "rtplib.h"
#include "codeclib.h"



static void __free_ssrc_entry_call(void *e);


static void init_ssrc_ctx(struct ssrc_ctx *c, struct ssrc_entry_call *parent) {
	c->parent = parent;
	payload_tracker_init(&c->tracker);
	while (!c->ssrc_map_out)
		c->ssrc_map_out = ssl_random();
	atomic64_set_na(&c->last_sample, ssrc_timeval_to_ts(&rtpe_now));
}
static void init_ssrc_entry(struct ssrc_entry *ent, uint32_t ssrc) {
	ent->ssrc = ssrc;
	ent->last_used = rtpe_now.tv_sec;
	mutex_init(&ent->lock);
}
static struct ssrc_entry *create_ssrc_entry_call(void *uptr) {
	struct ssrc_entry_call *ent;
	ent = obj_alloc0("ssrc_entry_call", sizeof(*ent), __free_ssrc_entry_call);
	init_ssrc_ctx(&ent->input_ctx, ent);
	init_ssrc_ctx(&ent->output_ctx, ent);
	//ent->seq_out = ssl_random();
	//ent->ts_out = ssl_random();
	ent->lost_bits = -1;
	return &ent->h;
}
static void add_ssrc_entry(uint32_t ssrc, struct ssrc_entry *ent, struct ssrc_hash *ht) {
	init_ssrc_entry(ent, ssrc);
	g_hash_table_replace(ht->ht, &ent->ssrc, ent);
	obj_hold(ent); // HT entry
	g_queue_push_tail(&ht->q, ent);
	obj_hold(ent); // queue entry
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
static void __free_ssrc_entry_call(void *ep) {
	struct ssrc_entry_call *e = ep;
	g_queue_clear_full(&e->sender_reports, (GDestroyNotify) free_sender_report);
	g_queue_clear_full(&e->rr_time_reports, (GDestroyNotify) free_rr_time);
	g_queue_clear_full(&e->stats_blocks, (GDestroyNotify) free_stats_block);
	packet_sequencer_destroy(&e->sequencer);
}
static void ssrc_entry_put(void *ep) {
	struct ssrc_entry_call *e = ep;
	obj_put(&e->h);
}

// returned as mos * 10 (i.e. 10 - 50 for 1.0 to 5.0)
static void mos_calc(struct ssrc_stats_block *ssb) {
	uint64_t rtt = ssb->rtt;
	if (rtpe_config.mos == MOS_CQ && !rtt)
		return; // can not compute the MOS-CQ unless we have a valid RTT
	else if (rtpe_config.mos == MOS_LQ)
		rtt = 0; // ignore RTT

	// as per https://www.pingman.com/kb/article/how-is-mos-calculated-in-pingplotter-pro-50.html
	int eff_rtt = ssb->rtt / 1000 + ssb->jitter * 2 + 10;
	double r; // XXX can this be done with int math?
	if (eff_rtt < 160)
		r = 93.2 - eff_rtt / 40.0;
	else
		r = 93.2 - (eff_rtt - 120) / 10.0;
	r = r - (ssb->packetloss * 2.5);

	int64_t intmos;
	if (r < 0) {
		intmos = 10;
	} else {
		double mos = 1.0 + (0.035) * r + (.000007) * r * (r-60) * (100-r);
		intmos = mos * 10.0;
	}
	if (intmos < 10) // must be an invalid input
		intmos = 0;
	ssb->mos = intmos;
}

static void *find_ssrc(uint32_t ssrc, struct ssrc_hash *ht) {
	rwlock_lock_r(&ht->lock);
	struct ssrc_entry *ret = g_atomic_pointer_get(&ht->cache);
	if (!ret || ret->ssrc != ssrc) {
		ret = g_hash_table_lookup(ht->ht, &ssrc);
		if (ret) {
			obj_hold(ret);
			// cache shares the reference from ht
			g_atomic_pointer_set(&ht->cache, ret);
			ret->last_used = rtpe_now.tv_sec;
		}
	}
	else {
		obj_hold(ret);
		ret->last_used = rtpe_now.tv_sec;
	}
	rwlock_unlock_r(&ht->lock);
	return ret;
}

static int ssrc_time_cmp(const void *aa, const void *bb, void *pp) {
	const struct ssrc_entry *a = aa, *b = bb;
	if (a->last_used < b->last_used)
		return -1;
	if (a->last_used > b->last_used)
		return 1;
	return 0;
}

// returns a new reference
void *get_ssrc(uint32_t ssrc, struct ssrc_hash *ht /* , int *created */) {
	struct ssrc_entry *ent;

	if (!ht)
		return NULL;

restart:
	ent = find_ssrc(ssrc, ht);
	if (G_LIKELY(ent)) {
//		if (created)
//			*created = 0;
		return ent;
	}

	// use precreated entry if possible
	while (1) {
		ent = g_atomic_pointer_get(&ht->precreat);
		if (!ent)
			break; // create one ourselves
		if (g_atomic_pointer_compare_and_exchange(&ht->precreat, ent, NULL))
			break;
		// something got in the way - retry
	}
	if (G_UNLIKELY(!ent))
		ent = ht->create_func(ht->uptr);
	if (G_UNLIKELY(!ent))
		return NULL;

	rwlock_lock_w(&ht->lock);

	while (G_UNLIKELY(ht->q.length > 20)) { // arbitrary limit
		g_queue_sort(&ht->q, ssrc_time_cmp, NULL);
		struct ssrc_entry *old_ent = g_queue_pop_head(&ht->q);
		ilog(LOG_DEBUG, "SSRC hash table exceeded size limit (trying to add %s%x%s) - "
				"deleting SSRC %s%x%s",
				FMT_M(ssrc), FMT_M(old_ent->ssrc));
		g_atomic_pointer_set(&ht->cache, NULL);
		g_hash_table_remove(ht->ht, &old_ent->ssrc); // does obj_put
		obj_put(old_ent); // for the queue entry
	}

	if (g_hash_table_lookup(ht->ht, &ssrc)) {
		// preempted
		rwlock_unlock_w(&ht->lock);
		// return created entry if slot is still empty
		if (!g_atomic_pointer_compare_and_exchange(&ht->precreat, NULL, ent))
			obj_put(ent);
		goto restart;
	}
	add_ssrc_entry(ssrc, ent, ht);
	g_atomic_pointer_set(&ht->cache, ent);
	rwlock_unlock_w(&ht->lock);
//	if (created)
//		*created = 1;

	return ent;
}
void free_ssrc_hash(struct ssrc_hash **ht) {
	if (!*ht)
		return;
	g_hash_table_destroy((*ht)->ht);
	g_queue_clear_full(&(*ht)->q, ssrc_entry_put);
	if ((*ht)->precreat)
		obj_put((struct ssrc_entry *) (*ht)->precreat);
	g_slice_free1(sizeof(**ht), *ht);
	*ht = NULL;
}
void ssrc_hash_foreach(struct ssrc_hash *sh, void (*f)(void *)) {
	rwlock_lock_w(&sh->lock);

	for (GList *k = sh->q.head; k; k = k->next)
		f(k->data);
	if (sh->precreat)
		f(sh->precreat);

	rwlock_unlock_w(&sh->lock);
}


struct ssrc_hash *create_ssrc_hash_full(ssrc_create_func_t cfunc, void *uptr) {
	struct ssrc_hash *ret;
	ret = g_slice_alloc0(sizeof(*ret));
	ret->ht = g_hash_table_new_full(uint32_hash, uint32_eq, NULL, ssrc_entry_put);
	rwlock_init(&ret->lock);
	ret->create_func = cfunc;
	ret->uptr = uptr;
	ret->precreat = cfunc(uptr); // because object creation might be slow
	return ret;
}
struct ssrc_hash *create_ssrc_hash_call(void) {
	return create_ssrc_hash_full(create_ssrc_entry_call, NULL);
}

struct ssrc_ctx *get_ssrc_ctx(uint32_t ssrc, struct ssrc_hash *ht, enum ssrc_dir dir, void *ref) {
	struct ssrc_entry *s = get_ssrc(ssrc, ht /* , NULL */);
	if (G_UNLIKELY(!s))
		return NULL;
	struct ssrc_ctx *ret = ((void *) s) + dir;
	if (ref)
		ret->ref = ref;
	return ret;
}



static void *__do_time_report_item(struct call_media *m, size_t struct_size, size_t reports_queue_offset,
		const struct timeval *tv, uint32_t ssrc, uint32_t ntp_msw, uint32_t ntp_lsw,
		GDestroyNotify free_func, struct ssrc_entry **e_p)
{
	struct ssrc_entry *e;
	struct ssrc_time_item *sti;

	sti = g_slice_alloc0(struct_size);
	sti->received = *tv;
	sti->ntp_middle_bits = ntp_msw << 16 | ntp_lsw >> 16;
	sti->ntp_ts = ntp_ts_to_double(ntp_msw, ntp_lsw);

	e = get_ssrc(ssrc, m->monologue->ssrc_hash);
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

// call must be locked in R
static struct ssrc_entry_call *hunt_ssrc(struct call_monologue *ml, uint32_t ssrc) {
	for (GList *l = ml->subscriptions.head; l; l = l->next) {
		struct call_subscription *cs = l->data;
		struct call_monologue *other = cs->monologue;
		struct ssrc_entry_call *e = find_ssrc(ssrc, other->ssrc_hash);
		if (e)
			return e;
	}
	return NULL;
}

static long long __calc_rtt(struct call_monologue *ml, uint32_t ssrc, uint32_t ntp_middle_bits,
		uint32_t delay, size_t reports_queue_offset, const struct timeval *tv, int *pt_p)
{
	if (pt_p)
		*pt_p = -1;

	if (!ntp_middle_bits || !delay)
		return 0;

	struct ssrc_entry_call *e = find_ssrc(ssrc, ml->ssrc_hash);
	if (G_UNLIKELY(!e))
		return 0;

	if (pt_p)
		*pt_p = e->output_ctx.tracker.most[0] == 255 ? -1 : e->output_ctx.tracker.most[0];

	// grab the opposite side SSRC for the time reports
	uint32_t map_ssrc = e->output_ctx.ssrc_map_out;
	if (!map_ssrc)
		map_ssrc = e->h.ssrc;
	obj_put(&e->h);
	e = hunt_ssrc(ml, map_ssrc);
	if (G_UNLIKELY(!e))
		return 0;

	struct ssrc_time_item *sti;
	GQueue *q = (((void *) e) + reports_queue_offset);
	mutex_lock(&e->h.lock);
	// go through the list backwards until we find the SR referenced
	for (GList *l = q->tail; l; l = l->prev) {
		sti = l->data;
		if (sti->ntp_middle_bits != ntp_middle_bits)
			continue;
		goto found;
	}

	// not found
	mutex_unlock(&e->h.lock);
	obj_put(&e->h);
	return 0;

found:;
	// `e` remains locked for access to `sti`
	long long rtt = timeval_diff(tv, &sti->received);

	mutex_unlock(&e->h.lock);

	rtt -= (long long) delay * 1000000LL / 65536LL;
	ilog(LOG_DEBUG, "Calculated round-trip time for %s%x%s is %lli us", FMT_M(ssrc), rtt);

	if (rtt <= 0 || rtt > 10000000) {
		ilog(LOG_DEBUG, "Invalid RTT - discarding");
		obj_put(&e->h);
		return 0;
	}

	e->last_rtt = rtt;

	obj_put(&e->h);
	return rtt;
}

void ssrc_sender_report(struct call_media *m, const struct ssrc_sender_report *sr,
		const struct timeval *tv)
{
	struct ssrc_entry *e;
	struct ssrc_sender_report_item *seri = __do_time_report_item(m, sizeof(*seri),
			G_STRUCT_OFFSET(struct ssrc_entry_call, sender_reports), tv, sr->ssrc,
			sr->ntp_msw, sr->ntp_lsw, (GDestroyNotify) free_sender_report, &e);
	if (!seri)
		return;

	seri->report = *sr;

	ilog(LOG_DEBUG, "SR from %s%x%s: RTP TS %u PC %u OC %u NTP TS %u/%u=%f",
			FMT_M(sr->ssrc), sr->timestamp, sr->packet_count, sr->octet_count,
			sr->ntp_msw, sr->ntp_lsw, seri->time_item.ntp_ts);

	mutex_unlock(&e->lock);
	obj_put(e);
}
void ssrc_receiver_report(struct call_media *m, const struct ssrc_receiver_report *rr,
		const struct timeval *tv)
{
	ilog(LOG_DEBUG, "RR from %s%x%s about %s%x%s: FL %u TL %u HSR %u J %u LSR %u DLSR %u",
			FMT_M(rr->from), FMT_M(rr->ssrc), rr->fraction_lost, rr->packets_lost,
			rr->high_seq_received, rr->jitter, rr->lsr, rr->dlsr);

	int pt;

	long long rtt = __calc_rtt(m->monologue, rr->ssrc, rr->lsr, rr->dlsr,
			G_STRUCT_OFFSET(struct ssrc_entry_call, sender_reports), tv, &pt);

	struct ssrc_entry_call *other_e = get_ssrc(rr->from, m->monologue->ssrc_hash);
	if (G_UNLIKELY(!other_e))
		goto out_nl;

	// determine the clock rate for jitter values
	if (pt < 0) {
		ilog(LOG_DEBUG, "No payload type known for RTCP RR, discarding");
		goto out_nl_put;
	}

	const struct rtp_payload_type *rpt = rtp_payload_type(pt, &m->codecs);
	if (!rpt) {
		ilog(LOG_INFO, "Invalid RTP payload type %i, discarding RTCP RR", pt);
		goto out_nl_put;
	}
	unsigned int jitter = rpt->clock_rate ? (rr->jitter * 1000 / rpt->clock_rate) : rr->jitter;
	ilog(LOG_DEBUG, "Calculated jitter for %s%x%s is %u ms", FMT_M(rr->ssrc), jitter);

	ilog(LOG_DEBUG, "Adding opposide side RTT of %u us", other_e->last_rtt);

	long long rtt_end2end = other_e->last_rtt ? (rtt + other_e->last_rtt) : 0;
	if (other_e->last_rtt_xr > 0) { // use the RTT from RTCP-XR (in ms)
		rtt_end2end = (long long) other_e->last_rtt_xr * 1000LL;
	}
	struct ssrc_stats_block *ssb = g_slice_alloc(sizeof(*ssb));
	*ssb = (struct ssrc_stats_block) {
		.jitter = jitter,
		.rtt = rtt_end2end,
		.rtt_leg = rtt,
		.reported = *tv,
		.packetloss = (unsigned int) rr->fraction_lost * 100 / 256,
	};
	other_e->packets_lost = rr->packets_lost;
	mos_calc(ssb);
	ilog(LOG_DEBUG, "Calculated MOS from RR for %s%x%s is %.1f", FMT_M(rr->from), (double) ssb->mos / 10.0);

	// got a new stats block, add it to reporting ssrc
	mutex_lock(&other_e->h.lock);

	// discard stats block if last has been received less than a second ago
	if (G_LIKELY(other_e->stats_blocks.length > 0)) {
		struct ssrc_stats_block *last_ssb = g_queue_peek_tail(&other_e->stats_blocks);
		if (G_UNLIKELY(timeval_diff(tv, &last_ssb->reported) < 1000000)) {
			free_stats_block(ssb);
			goto out_ul_oe;
		}
	}

	g_queue_push_tail(&other_e->stats_blocks, ssb);

	if (ssb->mos && ((G_UNLIKELY(!other_e->lowest_mos) || ssb->mos < other_e->lowest_mos->mos)))
		other_e->lowest_mos = ssb;
	if (G_UNLIKELY(!other_e->highest_mos) || ssb->mos > other_e->highest_mos->mos)
		other_e->highest_mos = ssb;

	// running tally
	if (!ssb->mos) { // when we do not have the RTT for both legs, we have no MOS
		other_e->no_mos_count++;
	} else {
		other_e->average_mos.jitter += ssb->jitter;
		other_e->average_mos.mos += ssb->mos;
		other_e->average_mos.rtt += ssb->rtt;
		other_e->average_mos.rtt_leg += ssb->rtt_leg;
		other_e->average_mos.packetloss += ssb->packetloss;
	}

	goto out_ul_oe;

out_ul_oe:
	mutex_unlock(&other_e->h.lock);
	goto out_nl_put;
out_nl_put:
	obj_put(&other_e->h);
	goto out_nl;
out_nl:
	;
}

void ssrc_receiver_rr_time(struct call_media *m, const struct ssrc_xr_rr_time *rr,
		const struct timeval *tv)
{
	struct ssrc_entry *e;
	struct ssrc_rr_time_item *srti = __do_time_report_item(m, sizeof(*srti),
			G_STRUCT_OFFSET(struct ssrc_entry_call, rr_time_reports), tv, rr->ssrc,
			rr->ntp_msw, rr->ntp_lsw, (GDestroyNotify) free_rr_time, &e);
	if (!srti)
		return;

	ilog(LOG_DEBUG, "XR RR TIME from %s%x%s: NTP TS %u/%u=%f",
			FMT_M(rr->ssrc),
			rr->ntp_msw, rr->ntp_lsw, srti->time_item.ntp_ts);

	mutex_unlock(&e->lock);
	obj_put(e);
}

void ssrc_receiver_dlrr(struct call_media *m, const struct ssrc_xr_dlrr *dlrr,
		const struct timeval *tv)
{
	ilog(LOG_DEBUG, "XR DLRR from %s%x%s about %s%x%s: LRR %u DLRR %u",
			FMT_M(dlrr->from), FMT_M(dlrr->ssrc),
			dlrr->lrr, dlrr->dlrr);

	__calc_rtt(m->monologue, dlrr->ssrc, dlrr->lrr, dlrr->dlrr,
			G_STRUCT_OFFSET(struct ssrc_entry_call, rr_time_reports), tv, NULL);
}

void ssrc_voip_metrics(struct call_media *m, const struct ssrc_xr_voip_metrics *vm,
		const struct timeval *tv)
{
	ilog(LOG_DEBUG, "XR VM from %s%x%s about %s%x%s: LR %u DR %u BD %u GD %u BDu %u GDu %u RTD %u "
			"ESD %u SL %u NL %u RERL %u GMin %u R %u eR %u MOSL %u MOSC %u RX %u "
			"JBn %u JBm %u JBam %u",
			FMT_M(vm->from), FMT_M(vm->ssrc),
			vm->loss_rate, vm->discard_rate, vm->burst_den, vm->gap_den,
			vm->burst_dur, vm->gap_dur, vm->rnd_trip_delay, vm->end_sys_delay,
			vm->signal_lvl, vm->noise_lvl, vm->rerl, vm->gmin, vm->r_factor,
			vm->ext_r_factor, vm->mos_lq, vm->mos_cq, vm->rx_config, vm->jb_nom,
			vm->jb_max, vm->jb_abs_max);

	struct ssrc_entry_call *e = get_ssrc(vm->ssrc, m->monologue->ssrc_hash);
	if (!e)
		return;
	e->last_rtt_xr = vm->rnd_trip_delay;
	obj_put(&e->h);
}

static void __pt_sort(struct payload_tracker *t, int pt) {
	// bubble up?
	while (t->idx[pt] > 0) {
		int this_idx = t->idx[pt];
		int prev_idx = this_idx - 1;
		int prev_pt = t->most[prev_idx];
		if (G_LIKELY(t->count[prev_pt] >= t->count[pt]))
			break;
		// bubble up!
		ilog(LOG_DEBUG, "bubble up pt %i from idx %u to %u", pt, this_idx, prev_idx);
		// swap entries in "most" list
		int prev = t->most[prev_idx];
		t->most[prev_idx] = t->most[this_idx];
		t->most[this_idx] = prev;
		// adjust indexes
		t->idx[pt]--;
		t->idx[prev_pt]++;
	}

	// bubble down?
	while (t->idx[pt] < t->most_len - 1) {
		int this_idx = t->idx[pt];
		int next_idx = this_idx + 1;
		int next_pt = t->most[next_idx];
		if (G_LIKELY(t->count[next_pt] <= t->count[pt]))
			break;
		// bubble down!
		ilog(LOG_DEBUG, "bubble down pt %i from idx %u to %u", pt, this_idx, next_idx);
		// swap entries in "most" list
		int next = t->most[next_idx];
		t->most[next_idx] = t->most[this_idx];
		t->most[this_idx] = next;
		// adjust indexes
		t->idx[pt]++;
		t->idx[next_pt]--;
	}

}

void payload_tracker_init(struct payload_tracker *t) {
	mutex_init(&t->lock);
	memset(&t->last, -1, sizeof(t->last));
	memset(&t->count, 0, sizeof(t->count));
	memset(&t->idx, -1, sizeof(t->idx));
	memset(&t->most, -1, sizeof(t->most));
	t->last_idx = 0;
	t->most_len = 0;
}
//#define PT_DBG(x...) ilog(LOG_DEBUG, x)
#define PT_DBG(x...) ((void)0)
void payload_tracker_add(struct payload_tracker *t, int pt) {
	if (G_UNLIKELY(pt < 0) || G_UNLIKELY(pt >= 128))
		return;

	mutex_lock(&t->lock);

	PT_DBG("new pt: %i", pt);
	PT_DBG("last idx: %u", t->last_idx);
	int old_pt = t->last[t->last_idx];
	PT_DBG("old pt: %u", old_pt);

	if (G_LIKELY(old_pt != 255)) {
		// overwriting old entry. is it the same as the new one?
		if (G_LIKELY(old_pt == pt)) {
			PT_DBG("old pt == new pt");
			// no change
			goto out;
		}
		PT_DBG("decreasing old pt count from %u", t->count[old_pt]);
		// different: decrease old counter
		t->count[old_pt]--;
	}

	// fill in new entry
	t->last[t->last_idx++] = pt;
	if (t->last_idx >= G_N_ELEMENTS(t->last))
		t->last_idx = 0;

	// increase new counter
	PT_DBG("increasing new pt count from %u", t->count[pt]);
	t->count[pt]++;

	// is this a new entry?
	if (G_UNLIKELY(t->idx[pt] == 255)) {
		// put to the end of the "most" list
		PT_DBG("inserting new entry at pos %u", t->most_len);
		t->idx[pt] = t->most_len;
		t->most[t->most_len] = pt;
		t->most_len++;
	}

	// now bubble sort both new and old entries
	__pt_sort(t, pt);
	if (G_LIKELY(old_pt != 255))
		__pt_sort(t, old_pt);

out:
	mutex_unlock(&t->lock);
}
