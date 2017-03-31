#include "ssrc.h"
#include <glib.h>
#include "aux.h"
#include "call.h"



static struct ssrc_entry *create_ssrc_entry(u_int32_t ssrc) {
	struct ssrc_entry *ent;
	ent = g_slice_alloc0(sizeof(struct ssrc_entry));
	ent->ssrc = ssrc;
	mutex_init(&ent->lock);
	return ent;
}
static void add_ssrc_entry(struct ssrc_entry *ent, struct ssrc_hash *ht) {
	g_hash_table_replace(ht->ht, &ent->ssrc, ent);
}
static void free_sender_report(void *p) {
	struct ssrc_sender_report_item *i = p;
	g_slice_free1(sizeof(*i), i);
}
static void free_ssrc_entry(void *p) {
	struct ssrc_entry *e = p;
	g_queue_clear_full(&e->sender_reports, free_sender_report);
	g_slice_free1(sizeof(*e), e);
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
	ret->ht = g_hash_table_new_full(uint32_hash, uint32_eq, NULL, free_ssrc_entry);
	rwlock_init(&ret->lock);
	return ret;
}

struct ssrc_ctx *get_ssrc_ctx(u_int32_t ssrc, struct ssrc_hash *ht, enum ssrc_dir dir) {
	struct ssrc_entry *s = get_ssrc(ssrc, ht /* , NULL */);
	return ((void *) s) + dir;
}



void ssrc_sender_report(struct call *c, const struct ssrc_sender_report *sr,
		const struct timeval *tv)
{
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

	mutex_lock(&e->lock);

	g_queue_push_tail(&e->sender_reports, seri);

	mutex_unlock(&e->lock);
}
void ssrc_receiver_report(struct call *c, const struct ssrc_receiver_report *rr,
		const struct timeval *tv)
{
	ilog(LOG_DEBUG, "RR from %u about %u: FL %u TL %u HSR %u J %u LSR %u DLSR %u",
			rr->from, rr->ssrc, rr->fraction_lost, rr->packets_lost,
			rr->high_seq_received, rr->jitter, rr->lsr, rr->dlsr);

	if (!rr->lsr || !rr->dlsr)
		return; // no delay to be known

	struct ssrc_entry *e = get_ssrc(rr->ssrc, c->ssrc_hash);
	mutex_lock(&e->lock);
	// go through the list backwards until we find the SR referenced, up to 10 steps
	int i = 0;
	for (GList *l = e->sender_reports.tail; 
			l && i < 10;
			l = l->prev, i++)
	{
		struct ssrc_sender_report_item *seri = l->data;
		if (seri->ntp_middle_bits != rr->lsr)
			continue;
		ilog(LOG_DEBUG, "RR from %u reports delay %u from %u", rr->from, rr->dlsr, rr->ssrc);
		break;
	}
	mutex_unlock(&e->lock);
}
