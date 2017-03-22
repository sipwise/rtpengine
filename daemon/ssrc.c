#include "ssrc.h"
#include <glib.h>
#include "aux.h"



static struct ssrc_entry *create_ssrc_entry(u_int32_t ssrc) {
	struct ssrc_entry *ent;
	ent = g_slice_alloc0(sizeof(struct ssrc_entry));
	ent->ssrc = ssrc;
	return ent;
}
static void add_ssrc_entry(struct ssrc_entry *ent, struct ssrc_hash *ht) {
	g_hash_table_replace(ht->ht, &ent->ssrc, ent);
}
static void free_ssrc_entry(void *p) {
	g_slice_free1(sizeof(struct ssrc_entry), p);
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

