#include "ice.h"
#include <glib.h>
#include <sys/time.h>
#include <unistd.h>
#include "str.h"
#include "call.h"
#include "aux.h"
#include "log.h"
#include "obj.h"
#include "stun.h"



#if __DEBUG
#define ICE_DEBUG 1
#else
#define ICE_DEBUG 0
#endif

#if ICE_DEBUG
#define __DBG(x...) ilog(LOG_DEBUG, x)
#else
#define __DBG(x...) ((void)0)
#endif




#define PAIR_FORMAT STR_FORMAT":"STR_FORMAT":%lu"
#define PAIR_FMT(p) 								\
			STR_FMT(&(p)->local_intf->spec->ice_foundation),	\
			STR_FMT(&(p)->remote_candidate->foundation),		\
			(p)->remote_candidate->component_id




static void __ice_agent_free(void *p);
static void create_random_ice_string(struct call *call, str *s, int len);
static void __do_ice_checks(struct ice_agent *ag);
static struct ice_candidate_pair *__pair_lookup(struct ice_agent *, struct ice_candidate *cand,
		const struct local_intf *ifa);
static void __recalc_pair_prios(struct ice_agent *ag);
static void __role_change(struct ice_agent *ag, int new_controlling);
static void __get_complete_components(GQueue *out, struct ice_agent *ag, GTree *t, unsigned int);
static void __agent_schedule(struct ice_agent *ag, unsigned long);
static void __agent_schedule_abs(struct ice_agent *ag, const struct timeval *tv);
static void __agent_deschedule(struct ice_agent *ag);
static void __ice_agent_free_components(struct ice_agent *ag);
static void __agent_shutdown(struct ice_agent *ag);



static u_int64_t tie_breaker;

static mutex_t ice_agents_timers_lock = MUTEX_STATIC_INIT;
static cond_t ice_agents_timers_cond = COND_STATIC_INIT;
static GTree *ice_agents_timers;

static const char ice_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

const unsigned int ice_type_preferences[] = {
	[ICT_UNKNOWN]	= 0,
	[ICT_HOST]	= 126,
	[ICT_SRFLX]	= 100,
	[ICT_PRFLX]	= 110,
	[ICT_RELAY]	= 0,
};

const char * const ice_type_strings[] = {
	[ICT_UNKNOWN]	= "unknown",
	[ICT_HOST]	= "host",
	[ICT_SRFLX]	= "srflx",
	[ICT_PRFLX]	= "prflx",
	[ICT_RELAY]	= "relay",
};





enum ice_candidate_type ice_candidate_type(const str *s) {
	int i;
	for (i = 1; i < G_N_ELEMENTS(ice_type_strings); i++) {
		if (!str_cmp(s, ice_type_strings[i]))
			return i;
	}
	return ICT_UNKNOWN;
}

int ice_has_related(enum ice_candidate_type t) {
	if (t == ICT_HOST)
		return 0;
	/* ignoring ICT_UNKNOWN */
	return 1;
}



static u_int64_t __ice_pair_priority(const struct local_intf *ifa, struct ice_candidate *cand,
		int controlling)
{
	u_int64_t g, d;

	g = ice_priority(ICT_HOST, ifa->preference, cand->component_id);
	d = cand->priority;

	if (!controlling) {
		u_int64_t t = g;
		g = d;
		d = t;
	}

	return (MIN(g,d) << 32) + (MAX(g,d) << 1) + (g > d ? 1 : 0);
}
static void __do_ice_pair_priority(struct ice_candidate_pair *pair) {
	pair->pair_priority = __ice_pair_priority(pair->local_intf, pair->remote_candidate,
			AGENT_ISSET(pair->agent, CONTROLLING));
}
static void __new_stun_transaction(struct ice_candidate_pair *pair) {
	struct ice_agent *ag = pair->agent;

	g_hash_table_remove(ag->transaction_hash, pair->stun_transaction);
	random_string((void *) pair->stun_transaction, sizeof(pair->stun_transaction));
	g_hash_table_insert(ag->transaction_hash, pair->stun_transaction, pair);
}

/* agent must be locked */
static void __all_pairs_list(struct ice_agent *ag) {
	g_queue_clear(&ag->all_pairs_list);
	g_tree_get_values(&ag->all_pairs_list, ag->all_pairs);
}

/* agent must be locked */
static struct ice_candidate_pair *__pair_candidate(const struct local_intf *addr, struct ice_agent *ag,
		struct ice_candidate *cand, struct packet_stream *ps)
{
	struct ice_candidate_pair *pair;

	if (addr->spec->address.addr.family != cand->endpoint.address.family)
		return NULL;

	pair = g_slice_alloc0(sizeof(*pair));

	pair->agent = ag;
	pair->remote_candidate = cand;
	pair->local_intf = addr;
	pair->packet_stream = ps;
	if (cand->component_id != 1)
		PAIR_SET(pair, FROZEN);
	__do_ice_pair_priority(pair);
	__new_stun_transaction(pair);

	g_queue_push_tail(&ag->candidate_pairs, pair);
	g_hash_table_insert(ag->pair_hash, pair, pair);
	g_tree_insert(ag->all_pairs, pair, pair);

	ilog(LOG_DEBUG, "Created candidate pair "PAIR_FORMAT" between %s and %s, type %s", PAIR_FMT(pair),
			sockaddr_print_buf(&addr->spec->address.addr),
			endpoint_print_buf(&cand->endpoint),
			ice_candidate_type_str(cand->type));

	return pair;
}

static unsigned int __pair_hash(const void *p) {
	const struct ice_candidate_pair *pair = p;
	return g_direct_hash(pair->local_intf) ^ g_direct_hash(pair->remote_candidate);
}
static int __pair_equal(const void *a, const void *b) {
	const struct ice_candidate_pair *A = a, *B = b;
	return A->local_intf == B->local_intf
		&& A->remote_candidate == B->remote_candidate;
}
static unsigned int __cand_hash(const void *p) {
	const struct ice_candidate *cand = p;
	return endpoint_hash(&cand->endpoint) ^ cand->component_id;
}
static int __cand_equal(const void *a, const void *b) {
	const struct ice_candidate *A = a, *B = b;
	return endpoint_eq(&A->endpoint, &B->endpoint)
		&& A->component_id == B->component_id;
}
static unsigned int __found_hash(const void *p) {
	const struct ice_candidate *cand = p;
	return str_hash(&cand->foundation) ^ cand->component_id;
}
static int __found_equal(const void *a, const void *b) {
	const struct ice_candidate *A = a, *B = b;
	return str_equal(&A->foundation, &B->foundation)
		&& A->component_id == B->component_id;
}
static unsigned int __trans_hash(const void *p) {
	const u_int32_t *tp = p;
	return tp[0] ^ tp[1] ^ tp[2];
}
static int __trans_equal(const void *a, const void *b) {
	const u_int32_t *A = a, *B = b;
	return A[0] == B[0] && A[1] == B[1] && A[2] == B[2];
}
static int __pair_prio_cmp(const void *a, const void *b) {
	const struct ice_candidate_pair *A = a, *B = b;
	/* highest priority first */
	if (A->pair_priority < B->pair_priority)
		return 1;
	if (A->pair_priority > B->pair_priority)
		return -1;
	/* lowest component first */
	if (A->remote_candidate->component_id < B->remote_candidate->component_id)
		return -1;
	if (A->remote_candidate->component_id > B->remote_candidate->component_id)
		return 1;
	/* highest local preference first, which is lowest number first */
	if (A->local_intf->preference < B->local_intf->preference)
		return -1;
	if (A->local_intf->preference > B->local_intf->preference)
		return 1;
	return 0;
}

static void __ice_agent_initialize(struct ice_agent *ag) {
	struct call_media *media = ag->media;
	struct call *call = ag->call;

	ag->candidate_hash = g_hash_table_new(__cand_hash, __cand_equal);
	ag->pair_hash = g_hash_table_new(__pair_hash, __pair_equal);
	ag->transaction_hash = g_hash_table_new(__trans_hash, __trans_equal);
	ag->foundation_hash = g_hash_table_new(__found_hash, __found_equal);
	ag->agent_flags = 0;
	bf_copy(&ag->agent_flags, ICE_AGENT_CONTROLLING, &media->media_flags, MEDIA_FLAG_ICE_CONTROLLING);
	ag->logical_intf = media->logical_intf;
	ag->desired_family = media->desired_family;
	ag->nominated_pairs = g_tree_new(__pair_prio_cmp);
	ag->valid_pairs = g_tree_new(__pair_prio_cmp);
	ag->succeeded_pairs = g_tree_new(__pair_prio_cmp);
	ag->all_pairs = g_tree_new(__pair_prio_cmp);

	create_random_ice_string(call, &ag->ufrag[1], 8);
	create_random_ice_string(call, &ag->pwd[1], 26);

	atomic64_set(&ag->last_activity, poller_now);
}

static struct ice_agent *__ice_agent_new(struct call_media *media) {
	struct ice_agent *ag;
	struct call *call = media->call;

	ag = obj_alloc0("ice_agent", sizeof(*ag), __ice_agent_free);
	ag->call = obj_get(call);
	ag->media = media;
	mutex_init(&ag->lock);

	__ice_agent_initialize(ag);

	return ag;
}

/* called with the call lock held in W */
void ice_agent_init(struct ice_agent **agp, struct call_media *media) {
	struct ice_agent *ag;

	if (*agp)
		ag = *agp;
	else
		*agp = ag = __ice_agent_new(media);
}

static int __copy_cand(struct call *call, struct ice_candidate *dst, const struct ice_candidate *src) {
	int eq = (dst->priority == src->priority);
	*dst = *src;
	call_str_cpy(call, &dst->foundation, &src->foundation);
	return eq ? 0 : 1;
}

static void __ice_reset(struct ice_agent *ag) {
	__agent_deschedule(ag);
	AGENT_CLEAR2(ag, COMPLETED, NOMINATING);
	__ice_agent_free_components(ag);
	ZERO(ag->active_components);
	ZERO(ag->start_nominating);
	ZERO(ag->last_run);
	__ice_agent_initialize(ag);
}

/* if the other side did a restart */
static void __ice_restart(struct ice_agent *ag) {
	ilog(LOG_DEBUG, "ICE restart, resetting ICE agent");

	ag->ufrag[0] = STR_NULL;
	ag->pwd[0] = STR_NULL;
	__ice_reset(ag);
}

/* if we're doing a restart */
void ice_restart(struct ice_agent *ag) {
	ag->ufrag[1] = STR_NULL;
	ag->pwd[1] = STR_NULL;
	__ice_reset(ag);
}

/* called with the call lock held in W, hence agent doesn't need to be locked */
void ice_update(struct ice_agent *ag, struct stream_params *sp) {
	GList *l, *k;
	struct ice_candidate *cand, *dup;
	struct call_media *media;
	struct call *call;
	int recalc = 0;
	unsigned int comps;
	struct packet_stream *components[MAX_COMPONENTS], *ps;
	GQueue *candidates;

	if (!ag)
		return;

	atomic64_set(&ag->last_activity, poller_now);
	media = ag->media;
	call = media->call;

	__role_change(ag, MEDIA_ISSET(media, ICE_CONTROLLING));

	if (sp) {
		/* check for ICE restarts */
		if (ag->ufrag[0].s && sp->ice_ufrag.s && str_cmp_str(&ag->ufrag[0], &sp->ice_ufrag))
			__ice_restart(ag);
		else if (ag->pwd[0].s && sp->ice_pwd.s && str_cmp_str(&ag->pwd[0], &sp->ice_pwd))
			__ice_restart(ag);
		else if (ag->logical_intf != media->logical_intf)
			__ice_restart(ag);

		/* update remote info */
		if (sp->ice_ufrag.s)
			call_str_cpy(call, &ag->ufrag[0], &sp->ice_ufrag);
		if (sp->ice_pwd.s)
			call_str_cpy(call, &ag->pwd[0], &sp->ice_pwd);

		candidates = &sp->ice_candidates;
	}
	else /* this is a dummy update in case rtcp-mux has changed */
		candidates = &ag->remote_candidates;

	/* get our component streams */
	ZERO(components);
	comps = 0;
	for (l = media->streams.head; l; l = l->next)
		components[comps++] = l->data;
	if (comps == 2 && MEDIA_ISSET(media, RTCP_MUX))
		components[1] = NULL;

	comps = 0;
	for (l = candidates->head; l; l = l->next) {
		if (ag->remote_candidates.length >= MAX_ICE_CANDIDATES) {
			ilog(LOG_WARNING, "Maxmimum number of ICE candidates exceeded");
			break;
		}

		cand = l->data;

		/* skip invalid */
		if (!cand->component_id || cand->component_id > G_N_ELEMENTS(components))
			continue;
		ps = components[cand->component_id - 1];

		if (ps) /* only count active components */
			comps = MAX(comps, cand->component_id);

		dup = g_hash_table_lookup(ag->candidate_hash, cand);
		if (!sp && dup) /* this isn't a real update, so only check pairings */
			goto pair;

		/* check for duplicates */
		if (dup) {
			/* if this is peer reflexive, we've learned it through STUN.
			 * otherwise it's simply one we've seen before. */
			if (dup->type == ICT_PRFLX) {
				ilog(LOG_DEBUG, "Replacing previously learned prflx ICE candidate with "
						STR_FORMAT":%lu", STR_FMT(&cand->foundation),
						cand->component_id);
			}
			else {
				/* if the new one has higher priority then the old one, then we
				 * update it, otherwise we just drop it */
				if (cand->priority <= dup->priority) {
					ilog(LOG_DEBUG, "Dropping new ICE candidate "STR_FORMAT" in favour of "
							STR_FORMAT":%lu",
							STR_FMT(&cand->foundation),
							STR_FMT(&dup->foundation), cand->component_id);
					continue;
				}

				ilog(LOG_DEBUG, "Replacing known ICE candidate "STR_FORMAT" with higher "
						"priority "
						STR_FORMAT":%lu",
						STR_FMT(&dup->foundation),
						STR_FMT(&cand->foundation), cand->component_id);
			}

			/* priority and foundation may change */
			g_hash_table_remove(ag->foundation_hash, dup);
			recalc += __copy_cand(call, dup, cand);
		}
		else {
			ilog(LOG_DEBUG, "Learning new ICE candidate "STR_FORMAT":%lu",
					STR_FMT(&cand->foundation), cand->component_id);
			dup = g_slice_alloc(sizeof(*dup));
			__copy_cand(call, dup, cand);
			g_hash_table_insert(ag->candidate_hash, dup, dup);
			g_queue_push_tail(&ag->remote_candidates, dup);
		}

		g_hash_table_insert(ag->foundation_hash, dup, dup);

pair:
		if (!ps)
			continue;
		for (k = ag->logical_intf->list.head; k; k = k->next) {
			/* skip duplicates here also */
			if (__pair_lookup(ag, dup, k->data))
				continue;
			__pair_candidate(k->data, ag, dup, ps);
		}
	}

	if (comps)
		ag->active_components = comps;
	if (!ag->active_components) {
		/* determine components for tricke-ice case */
		comps = 2;
		if (!components[1])
			comps = 1;
		ag->active_components = comps;
	}

	/* if we're here, we can start our ICE checks */
	if (recalc)
		__recalc_pair_prios(ag);
	else
		__all_pairs_list(ag);

	if (comps)
		__do_ice_checks(ag);
	else
		__agent_shutdown(ag);
}


static void ice_candidate_free(void *p) {
	g_slice_free1(sizeof(struct ice_candidate), p);
}
void ice_candidates_free(GQueue *q) {
	g_queue_clear_full(q, ice_candidate_free);
}
static void ice_candidate_pair_free(void *p) {
	g_slice_free1(sizeof(struct ice_candidate_pair), p);
}
static void ice_candidate_pairs_free(GQueue *q) {
	g_queue_clear_full(q, ice_candidate_pair_free);
}


/* call must be locked */
void ice_shutdown(struct ice_agent **agp) {
	struct ice_agent *ag = *agp;
	if (!ag)
		return;

	__agent_deschedule(ag);

	*agp = NULL;
	obj_put(ag);
}
static void __ice_agent_free_components(struct ice_agent *ag) {
	g_queue_clear(&ag->triggered);
	g_hash_table_destroy(ag->candidate_hash);
	g_hash_table_destroy(ag->pair_hash);
	g_hash_table_destroy(ag->transaction_hash);
	g_hash_table_destroy(ag->foundation_hash);
	g_tree_destroy(ag->all_pairs);
	g_queue_clear(&ag->all_pairs_list);
	g_tree_destroy(ag->nominated_pairs);
	g_tree_destroy(ag->succeeded_pairs);
	g_tree_destroy(ag->valid_pairs);
	ice_candidates_free(&ag->remote_candidates);
	ice_candidate_pairs_free(&ag->candidate_pairs);
}
static void __ice_agent_free(void *p) {
	struct ice_agent *ag = p;

	__DBG("freeing ice_agent");

	__ice_agent_free_components(ag);
	mutex_destroy(&ag->lock);

	obj_put(ag->call);
}


static void __agent_schedule(struct ice_agent *ag, unsigned long usec) {
	struct timeval nxt;

	nxt = g_now;
	timeval_add_usec(&nxt, usec);
	__agent_schedule_abs(ag, &nxt);
}
static void __agent_schedule_abs(struct ice_agent *ag, const struct timeval *tv) {
	struct timeval nxt;
	long long diff;

	nxt = *tv;

	mutex_lock(&ice_agents_timers_lock);
	if (ag->last_run.tv_sec) {
		/* make sure we don't run more often than we should */
		diff = timeval_diff(&nxt, &ag->last_run);
		if (diff < TIMER_RUN_INTERVAL * 1000)
			timeval_add_usec(&nxt, TIMER_RUN_INTERVAL * 1000 - diff);
	}
	if (ag->next_check.tv_sec && timeval_cmp(&ag->next_check, &nxt) <= 0)
		goto nope; /* already scheduled sooner */
	if (!g_tree_remove(ice_agents_timers, ag))
		obj_hold(ag); /* if it wasn't removed, we make a new reference */
	ag->next_check = nxt;
	g_tree_insert(ice_agents_timers, ag, ag);
	cond_broadcast(&ice_agents_timers_cond);
nope:
	mutex_unlock(&ice_agents_timers_lock);
}
static void __agent_deschedule(struct ice_agent *ag) {
	int ret;
	mutex_lock(&ice_agents_timers_lock);
	if (!ag->next_check.tv_sec)
		goto nope; /* already descheduled */
	ret = g_tree_remove(ice_agents_timers, ag);
	ZERO(ag->next_check);
	if (ret)
		obj_put(ag);
nope:
	mutex_unlock(&ice_agents_timers_lock);
}

static int __ice_agent_timer_cmp(const void *a, const void *b) {
	const struct ice_agent *A = a, *B = b;
	int ret;
	/* zero timevals go last */
	if (A->next_check.tv_sec == 0 && B->next_check.tv_sec != 0)
		return 1;
	if (B->next_check.tv_sec == 0 && A->next_check.tv_sec == 0)
		return -1;
	if (A->next_check.tv_sec == 0 && B->next_check.tv_sec == 0)
		goto ptr;
	/* earlier timevals go first */
	ret = timeval_cmp(&A->next_check, &B->next_check);
	if (ret)
		return ret;
	/* equal timeval, so use pointer as tie breaker */
ptr:
	if (A < B)
		return -1;
	if (A > B)
		return 1;
	return 0;
}
void ice_init(void) {
	random_string((void *) &tie_breaker, sizeof(tie_breaker));
	ice_agents_timers = g_tree_new(__ice_agent_timer_cmp);
}



static void __fail_pair(struct ice_candidate_pair *pair) {
	ilog(LOG_DEBUG, "Setting ICE candidate pair "PAIR_FORMAT" as failed", PAIR_FMT(pair));
	PAIR_SET(pair, FAILED);
	PAIR_CLEAR(pair, IN_PROGRESS);
}

/* agent must NOT be locked, but call must be locked in R */
static void __do_ice_check(struct ice_candidate_pair *pair) {
	struct packet_stream *ps = pair->packet_stream;
	struct ice_agent *ag = pair->agent;
	u_int32_t prio, transact[3];

	if (PAIR_ISSET(pair, SUCCEEDED) && !PAIR_ISSET(pair, TO_USE))
		return;

	if (!ag->pwd[0].s)
		return;

	prio = ice_priority(ICT_PRFLX, pair->local_intf->preference,
			pair->remote_candidate->component_id);

	mutex_lock(&ag->lock);

	pair->retransmit = g_now;
	if (!PAIR_SET(pair, IN_PROGRESS)) {
		PAIR_CLEAR2(pair, FROZEN, FAILED);
		pair->retransmit_ms = STUN_RETRANSMIT_INTERVAL;
		pair->retransmits = 0;
	}
	else if (pair->retransmits > STUN_MAX_RETRANSMITS) {
		__fail_pair(pair);
		mutex_unlock(&ag->lock);
		return;
	}
	else {
		pair->retransmit_ms *= 2;
		pair->retransmits++;
	}
	timeval_add_usec(&pair->retransmit, pair->retransmit_ms * 1000);
	__agent_schedule_abs(pair->agent, &pair->retransmit);
	memcpy(transact, pair->stun_transaction, sizeof(transact));

	pair->was_controlling = AGENT_ISSET(ag, CONTROLLING);
	pair->was_nominated = PAIR_ISSET(pair, TO_USE);

	mutex_unlock(&ag->lock);

	ilog(LOG_DEBUG, "Sending %sICE/STUN request for candidate pair "PAIR_FORMAT" from %s to %s",
			PAIR_ISSET(pair, TO_USE) ? "nominating " : "",
			PAIR_FMT(pair), sockaddr_print_buf(&pair->local_intf->spec->address.addr),
			endpoint_print_buf(&pair->remote_candidate->endpoint));

	stun_binding_request(&pair->remote_candidate->endpoint, transact, &ag->pwd[0], ag->ufrag,
			AGENT_ISSET(ag, CONTROLLING), tie_breaker,
			prio, &pair->local_intf->spec->address.addr, &ps->sfd->socket,
			PAIR_ISSET(pair, TO_USE));

}

static int __component_find(const void *a, const void *b) {
	const struct ice_candidate_pair *A = a;
	unsigned int comp = GPOINTER_TO_UINT(b);
	if (A->remote_candidate->component_id == comp)
		return TRUE;
	return FALSE;
}
static struct ice_candidate_pair *__get_pair_by_component(GTree *t, unsigned int component) {
	return g_tree_find_first(t, __component_find, GUINT_TO_POINTER(component));
}
static void __get_pairs_by_component(GQueue *out, GTree *t, unsigned int component) {
	g_tree_find_all(out, t, __component_find, GUINT_TO_POINTER(component));
}

static void __get_complete_succeeded_pairs(GQueue *out, struct ice_agent *ag) {
	__get_complete_components(out, ag, ag->succeeded_pairs, ICE_PAIR_SUCCEEDED);
}
static void __get_complete_valid_pairs(GQueue *out, struct ice_agent *ag) {
	__get_complete_components(out, ag, ag->valid_pairs, ICE_PAIR_VALID);
}

static void __nominate_pairs(struct ice_agent *ag) {
	GQueue complete;
	GList *l;
	struct ice_candidate_pair *pair;

	ilog(LOG_DEBUG, "Start nominating ICE pairs");

	AGENT_SET(ag, NOMINATING);
	ZERO(ag->start_nominating);

	__get_complete_succeeded_pairs(&complete, ag);

	for (l = complete.head; l; l = l->next) {
		pair = l->data;
		ilog(LOG_DEBUG, "Nominating ICE pair "PAIR_FORMAT, PAIR_FMT(pair));
		PAIR_CLEAR(pair, IN_PROGRESS);
		PAIR_SET2(pair, NOMINATED, TO_USE);
		pair->retransmits = 0;
		__new_stun_transaction(pair);
		g_queue_push_tail(&ag->triggered, pair);
	}

	g_queue_clear(&complete);
}

/* call must be locked R or W, agent must not be locked */
static void __do_ice_checks(struct ice_agent *ag) {
	GList *l;
	struct ice_candidate_pair *pair, *highest = NULL, *frozen = NULL, *valid;
	struct packet_stream *ps;
	GQueue retransmits = G_QUEUE_INIT;
	struct timeval next_run = {0,0};
	int have_more = 0;

	if (!ag->pwd[0].s)
		return;

	atomic64_set(&ag->last_activity, poller_now);

	__DBG("running checks, call "STR_FORMAT" tag "STR_FORMAT"", STR_FMT(&ag->call->callid),
			STR_FMT(&ag->media->monologue->tag));

	mutex_lock(&ag->lock);

	/* check if we're done and should start nominating pairs */
	if (AGENT_ISSET(ag, CONTROLLING) && !AGENT_ISSET(ag, NOMINATING) && ag->start_nominating.tv_sec) {
		if (timeval_cmp(&g_now, &ag->start_nominating) >= 0)
			__nominate_pairs(ag);
		timeval_lowest(&next_run, &ag->start_nominating);
	}

	/* triggered checks are preferred */
	pair = g_queue_pop_head(&ag->triggered);
	if (pair) {
		PAIR_CLEAR(pair, TRIGGERED);
		next_run = g_now;
		goto check;
	}

	/* find the highest-priority non-frozen non-in-progress pair */
	for (l = ag->all_pairs_list.head; l; l = l->next) {
		pair = l->data;

		/* skip dead streams */
		ps = pair->packet_stream;
		if (!ps || !ps->sfd)
			continue;
		if (PAIR_ISSET(pair, FAILED))
			continue;
		if (PAIR_ISSET(pair, SUCCEEDED) && !PAIR_ISSET(pair, TO_USE))
			continue;

		valid = __get_pair_by_component(ag->valid_pairs, pair->remote_candidate->component_id);

		if (PAIR_ISSET(pair, IN_PROGRESS)) {
			/* handle retransmits */
			/* but only if our priority is lower than any valid pair */
			if (valid && valid->pair_priority > pair->pair_priority)
				continue;

			if (timeval_cmp(&pair->retransmit, &g_now) <= 0)
				g_queue_push_tail(&retransmits, pair); /* can't run check directly
									  due to locks */
			else
				timeval_lowest(&next_run, &pair->retransmit);
			continue;
		}

		/* don't do anything else if we already have a valid pair */
		if (valid)
			continue;
		/* or if we're in or past the final phase */
		if (AGENT_ISSET2(ag, NOMINATING, COMPLETED))
			continue;

		have_more = 1;

		/* remember the first frozen pair in case we find nothing else */
		if (PAIR_ISSET(pair, FROZEN)) {
			if (!frozen)
				frozen = pair;
			continue;
		}

		if (!highest)
			highest = pair;
	}

	if (highest)
		pair = highest;
	else if (frozen)
		pair = frozen;
	else
		pair = NULL;

check:
	mutex_unlock(&ag->lock);

	if (pair)
		__do_ice_check(pair);

	while ((pair = g_queue_pop_head(&retransmits)))
		__do_ice_check(pair);


	/* determine when to run next */
	if (have_more)
		__agent_schedule(ag, 0);
	else if (next_run.tv_sec)
		__agent_schedule_abs(ag, &next_run); /* for retransmits */
}

static void __agent_shutdown(struct ice_agent *ag) {
	ilog(LOG_DEBUG, "Shutting down ICE agent (nothing to do)");
	__agent_deschedule(ag);
}

/* agent must be locked for these */
static struct ice_candidate *__cand_lookup(struct ice_agent *ag, const endpoint_t *sin,
		unsigned int component)
{
	struct ice_candidate d;

	d.endpoint = *sin;
	d.component_id = component;
	return g_hash_table_lookup(ag->candidate_hash, &d);
}
static struct ice_candidate *__foundation_lookup(struct ice_agent *ag, const str *foundation,
		unsigned int component)
{
	struct ice_candidate d;

	d.foundation = *foundation;
	d.component_id = component;
	return g_hash_table_lookup(ag->foundation_hash, &d);
}
static struct ice_candidate_pair *__pair_lookup(struct ice_agent *ag, struct ice_candidate *cand,
		const struct local_intf *ifa)
{
	struct ice_candidate_pair p;

	p.local_intf = ifa;
	p.remote_candidate = cand;
	return g_hash_table_lookup(ag->pair_hash, &p);
}

static void __cand_ice_foundation(struct call *call, struct ice_candidate *cand) {
	char buf[64];
	int len;

	len = sprintf(buf, "%x%x%x", endpoint_hash(&cand->endpoint),
			cand->type, g_direct_hash(cand->transport));
	call_str_cpy_len(call, &cand->foundation, buf, len);
}

/* agent must be locked */
static struct ice_candidate_pair *__learned_candidate(struct ice_agent *ag, struct packet_stream *ps,
		const endpoint_t *src, const struct local_intf *ifa, unsigned long priority)
{
	struct ice_candidate *cand, *old_cand;
	struct ice_candidate_pair *pair;
	struct call *call = ag->call;

	cand = g_slice_alloc0(sizeof(*cand));
	cand->component_id = ps->component;
	cand->transport = ifa->spec->address.type;
	cand->priority = priority;
	cand->endpoint = *src;
	cand->type = ICT_PRFLX;
	__cand_ice_foundation(call, cand);

	old_cand = __foundation_lookup(ag, &cand->foundation, ps->component);
	if (old_cand && old_cand->priority > priority) {
		/* this is possible if two distinct requests are received from the same NAT IP
		 * address, but from different ports. we cannot distinguish such candidates and
		 * will drop the one with the lower priority */
		g_slice_free1(sizeof(*cand), cand);
		pair = __pair_lookup(ag, old_cand, ifa);
		if (pair)
			goto out; /* nothing to do */
		cand = old_cand;
		goto pair;
	}

	g_queue_push_tail(&ag->remote_candidates, cand);
	g_hash_table_insert(ag->candidate_hash, cand, cand);
	g_hash_table_insert(ag->foundation_hash, cand, cand);

pair:
	pair = __pair_candidate(ifa, ag, cand, ps);
	PAIR_SET(pair, LEARNED);
	__all_pairs_list(ag);

out:
	return pair;
}

/* agent must NOT be locked */
static void __trigger_check(struct ice_candidate_pair *pair) {
	struct ice_agent *ag = pair->agent;

	ilog(LOG_DEBUG, "Triggering check for "PAIR_FORMAT, PAIR_FMT(pair));

	mutex_lock(&ag->lock);
	pair->retransmits = 0;
	if (PAIR_CLEAR(pair, FAILED))
		PAIR_CLEAR(pair, IN_PROGRESS);
	if (ag->triggered.length < 4 * MAX_ICE_CANDIDATES && !PAIR_SET(pair, TRIGGERED))
		g_queue_push_tail(&ag->triggered, pair);
	mutex_unlock(&ag->lock);

	__agent_schedule(ag, 0);
}

/* agent must be locked */
/* also regenerates all_pairs_list */
static void __recalc_pair_prios(struct ice_agent *ag) {
	struct ice_candidate_pair *pair;
	GList *l;
	GQueue nominated, valid, succ, all;

	ilog(LOG_DEBUG, "Recalculating all ICE pair priorities");

	g_tree_remove_all(&nominated, ag->nominated_pairs);
	g_tree_remove_all(&succ, ag->succeeded_pairs);
	g_tree_remove_all(&valid, ag->valid_pairs);
	g_tree_remove_all(&all, ag->all_pairs);

	for (l = ag->candidate_pairs.head; l; l = l->next) {
		pair = l->data;
		__do_ice_pair_priority(pair);
		/* this changes the packets, so we must keep these from being seen as retransmits */
		__new_stun_transaction(pair);
	}

	g_tree_add_all(ag->nominated_pairs, &nominated);
	g_tree_add_all(ag->succeeded_pairs, &succ);
	g_tree_add_all(ag->valid_pairs, &valid);
	g_tree_add_all(ag->all_pairs, &all);
	__all_pairs_list(ag);
}

/* agent must NOT be locked */
static void __role_change(struct ice_agent *ag, int new_controlling) {
	if (new_controlling && !AGENT_SET(ag, CONTROLLING))
		;
	else if (!new_controlling && AGENT_CLEAR(ag, CONTROLLING))
		;
	else
		return;

	ilog(LOG_DEBUG, "ICE role change, now %s", new_controlling ? "controlling" : "controlled");

	/* recalc priorities and resort list */

	mutex_lock(&ag->lock);
	__recalc_pair_prios(ag);
	mutex_unlock(&ag->lock);
}

/* initializes "out" */
static void __get_complete_components(GQueue *out, struct ice_agent *ag, GTree *t, unsigned int flag) {
	GQueue compo1 = G_QUEUE_INIT;
	GList *l;
	struct ice_candidate_pair *pair1, *pairX;
	struct ice_candidate *cand;
	unsigned int i;

	__get_pairs_by_component(&compo1, t, 1);

	g_queue_init(out);

	for (l = compo1.head; l; l = l->next) {
		pair1 = l->data;

		g_queue_clear(out);
		g_queue_push_tail(out, pair1);

		for (i = 2; i <= ag->active_components; i++) {
			cand = __foundation_lookup(ag, &pair1->remote_candidate->foundation, i);
			if (!cand)
				goto next_foundation;
			pairX = __pair_lookup(ag, cand, pair1->local_intf);
			if (!pairX)
				goto next_foundation;
			if (!bf_isset(&pairX->pair_flags, flag))
				goto next_foundation;
			g_queue_push_tail(out, pairX);
		}
		goto found;

next_foundation:
		;
	}

	/* nothing found */
	g_queue_clear(out);

found:
	g_queue_clear(&compo1);
}

/* call(W) or call(R)+agent must be locked - no in_lock or out_lock must be held */
static int __check_valid(struct ice_agent *ag) {
	struct call_media *media = ag->media;
	struct packet_stream *ps;
	GList *l, *k;
	GQueue all_compos;
	struct ice_candidate_pair *pair;
	const struct local_intf *ifa;

	__get_complete_valid_pairs(&all_compos, ag);

	if (!all_compos.length) {
		ilog(LOG_DEBUG, "ICE not completed yet");
		return 0;
	}

	pair = all_compos.head->data;
	ilog(LOG_DEBUG, "ICE completed, using pair "PAIR_FORMAT, PAIR_FMT(pair));
	AGENT_SET(ag, COMPLETED);

	ifa = g_atomic_pointer_get(&media->local_intf);
	if (ifa != pair->local_intf
			&& g_atomic_pointer_compare_and_exchange(&media->local_intf, ifa,
				pair->local_intf))
		ilog(LOG_INFO, "ICE negotiated: local interface %s",
				sockaddr_print_buf(&pair->local_intf->spec->address.addr));

	for (l = media->streams.head, k = all_compos.head; l && k; l = l->next, k = k->next) {
		ps = l->data;
		pair = k->data;

		mutex_lock(&ps->out_lock);
		if (memcmp(&ps->endpoint, &pair->remote_candidate->endpoint, sizeof(ps->endpoint))) {
			ilog(LOG_INFO, "ICE negotiated: peer for component %u is %s", ps->component,
					endpoint_print_buf(&pair->remote_candidate->endpoint));
			ps->endpoint = pair->remote_candidate->endpoint;
		}
		mutex_unlock(&ps->out_lock);
	}

	call_media_unkernelize(media);

	g_queue_clear(&all_compos);
	return 1;
}


/* call is locked in R */
/* return values:
 * 1 = ICE completed, interfaces selected
 * 0 = packet processed
 * -1 = generic error, process packet as normal
 * -2 = role conflict
 */
int ice_request(struct packet_stream *ps, const endpoint_t *src, const sockaddr_t *dst,
		struct stun_attrs *attrs)
{
	struct call_media *media = ps->media;
	struct ice_agent *ag;
	const struct local_intf *ifa;
	const char *err;
	struct ice_candidate *cand;
	struct ice_candidate_pair *pair;
	int ret;

	__DBG("received ICE request from %s on %s", endpoint_print_buf(src), sockaddr_print_buf(dst));

	ag = media->ice_agent;
	if (!ag)
		return -1;

	atomic64_set(&ag->last_activity, poller_now);

	ifa = get_interface_from_address(ag->logical_intf, dst, NULL); /* XXX type */
	err = "ICE/STUN binding request received on unknown local interface address";
	if (!ifa)
		goto err;

	/* determine candidate pair */
	mutex_lock(&ag->lock);

	cand = __cand_lookup(ag, src, ps->component);

	if (!cand)
		pair = __learned_candidate(ag, ps, src, ifa, attrs->priority);
	else
		pair = __pair_lookup(ag, cand, ifa);

	err = "Failed to determine ICE candidate from STUN request";
	if (!pair)
		goto err_unlock;

	mutex_unlock(&ag->lock);

	/* determine role conflict */
	if (attrs->controlling && AGENT_ISSET(ag, CONTROLLING)) {
		if (tie_breaker >= attrs->tiebreaker)
			return -2;
		else
			__role_change(ag, 0);
	}
	else if (attrs->controlled && !AGENT_ISSET(ag, CONTROLLING)) {
		if (tie_breaker >= attrs->tiebreaker)
			__role_change(ag, 1);
		else
			return -2;
	}


	if (PAIR_ISSET(pair, SUCCEEDED))
		;
	else
		__trigger_check(pair);

	ret = 0;

	if (attrs->use && !PAIR_SET(pair, NOMINATED)) {
		ilog(LOG_DEBUG, "ICE pair "PAIR_FORMAT" has been nominated by peer", PAIR_FMT(pair));

		mutex_lock(&ag->lock);

		g_tree_insert(ag->nominated_pairs, pair, pair);

		if (PAIR_ISSET(pair, SUCCEEDED)) {
			PAIR_SET(pair, VALID);
			g_tree_insert(ag->valid_pairs, pair, pair);
		}

		if (!AGENT_ISSET(ag, CONTROLLING))
			ret = __check_valid(ag);

		mutex_unlock(&ag->lock);
	}

	return ret;

err_unlock:
	mutex_unlock(&ag->lock);
err:
	ilog(LOG_NOTICE, "%s (from %s on interface %s)", err, endpoint_print_buf(src), sockaddr_print_buf(dst));
	return 0;
}


static int __check_succeeded_complete(struct ice_agent *ag) {
	GQueue complete;
	int ret;

	__get_complete_succeeded_pairs(&complete, ag);
	if (complete.length) {
		struct ice_candidate_pair *pair = complete.head->data;
		ilog(LOG_DEBUG, "Best succeeded ICE pair with all components is "PAIR_FORMAT, PAIR_FMT(pair));
		ret = 1;
	}
	else {
		ilog(LOG_DEBUG, "No succeeded ICE pairs with all components yet");
		ret = 0;
	}
	g_queue_clear(&complete);
	return ret;
}

/* call is locked in R */
int ice_response(struct packet_stream *ps, const endpoint_t *src, const sockaddr_t *dst,
		struct stun_attrs *attrs, u_int32_t transaction[3])
{
	struct ice_candidate_pair *pair, *opair;
	struct ice_agent *ag;
	struct call_media *media = ps->media;
	const char *err;
	unsigned int component;
	struct ice_candidate *cand;
	const struct local_intf *ifa;
	int ret, was_ctl;

	__DBG("received ICE response from %s on %s", endpoint_print_buf(src), sockaddr_print_buf(dst));

	ag = media->ice_agent;
	if (!ag)
		return -1;

	atomic64_set(&ag->last_activity, poller_now);

	mutex_lock(&ag->lock);

	pair = g_hash_table_lookup(ag->transaction_hash, transaction);
	err = "ICE/STUN response with unknown transaction received";
	if (!pair)
		goto err_unlock;
	was_ctl = pair->was_controlling;

	mutex_unlock(&ag->lock);

	ifa = pair->local_intf;

	ilog(LOG_DEBUG, "Received ICE/STUN response code %u for candidate pair "PAIR_FORMAT" from %s to %s",
			attrs->error_code, PAIR_FMT(pair),
			endpoint_print_buf(&pair->remote_candidate->endpoint),
			sockaddr_print_buf(&ifa->spec->address.addr));

	/* verify endpoints */
	err = "ICE/STUN response received, but source address didn't match remote candidate address";
	if (!endpoint_eq(src, &pair->remote_candidate->endpoint))
		goto err;

	err = "ICE/STUN response received, but destination address didn't match local interface address";
	if (!sockaddr_eq(dst, &ifa->spec->address.addr)) /* XXX lots of references to this struct member */
		goto err;
	if (pair->packet_stream != ps)
		goto err;

	PAIR_CLEAR(pair, IN_PROGRESS);
	ret = 0;

	/* handle all errors */
	if (attrs->error_code) {
		err = "ICE/STUN error received";
		if (attrs->error_code != 487)
			goto err;
		__role_change(ag, !was_ctl);
		__trigger_check(pair);
		goto out;
	}

	/* we don't discover peer reflexive here (RFC 5245 7.1.3.2.1) as we don't expect to be behind NAT */
	/* we also skip parts of 7.1.3.2.2 as we don't do server reflexive */

	mutex_lock(&ag->lock);

	/* check if we're in the final (controlling) phase */
	if (pair->was_nominated && PAIR_CLEAR(pair, TO_USE)) {
		ilog(LOG_DEBUG, "Setting nominated ICE candidate pair "PAIR_FORMAT" as valid", PAIR_FMT(pair));
		PAIR_SET(pair, VALID);
		g_tree_insert(ag->valid_pairs, pair, pair);
		ret = __check_valid(ag);
		goto out_unlock;
	}

	if (PAIR_SET(pair, SUCCEEDED))
		goto out_unlock;

	ilog(LOG_DEBUG, "Setting ICE candidate pair "PAIR_FORMAT" as succeeded", PAIR_FMT(pair));
	g_tree_insert(ag->succeeded_pairs, pair, pair);

	if (!ag->start_nominating.tv_sec) {
		if (__check_succeeded_complete(ag)) {
			ag->start_nominating = g_now;
			timeval_add_usec(&ag->start_nominating, 100000);
			__agent_schedule_abs(ag, &ag->start_nominating);
		}
	}

	/* now unfreeze all other pairs from the same foundation */
	for (component = 1; component <= MAX_COMPONENTS; component++) {
		if (component == ps->component)
			continue;
		cand = __foundation_lookup(ag, &pair->remote_candidate->foundation, component);
		if (!cand)
			continue;
		opair = __pair_lookup(ag, cand, ifa);
		if (!opair)
			continue;

		if (PAIR_ISSET(opair, FAILED))
			continue;
		if (!PAIR_CLEAR(opair, FROZEN))
			continue;

		ilog(LOG_DEBUG, "Unfreezing related ICE pair "PAIR_FORMAT, PAIR_FMT(opair));
	}

	/* if this was previously nominated by the peer, it's now valid */
	if (PAIR_ISSET(pair, NOMINATED)) {
		PAIR_SET(pair, VALID);
		g_tree_insert(ag->valid_pairs, pair, pair);

		if (!AGENT_ISSET(ag, CONTROLLING))
			ret = __check_valid(ag);
	}

out_unlock:
	mutex_unlock(&ag->lock);
out:
	return ret;

err_unlock:
	mutex_unlock(&ag->lock);
err:
	if (err)
		ilog(LOG_NOTICE, "%s (from %s on interface %s)",
				err, endpoint_print_buf(src), sockaddr_print_buf(dst));

	if (pair && attrs->error_code)
		__fail_pair(pair);

	return 0;
}



void ice_thread_run(void *p) {
	struct ice_agent *ag;
	struct call *call;
	long long sleeptime;
	struct timeval tv;

	mutex_lock(&ice_agents_timers_lock);

	while (!g_shutdown) {
		gettimeofday(&g_now, NULL);

		/* lock our list and get the first element */
		ag = g_tree_find_first(ice_agents_timers, NULL, NULL);
		/* scheduled to run? if not, we just go to sleep, otherwise we remove it from the tree,
		 * steal the reference and run it */
		if (!ag)
			goto sleep;
		if (timeval_cmp(&g_now, &ag->next_check) < 0)
			goto sleep;

		g_tree_remove(ice_agents_timers, ag);
		ZERO(ag->next_check);
		ag->last_run = g_now;
		mutex_unlock(&ice_agents_timers_lock);

		/* this agent is scheduled to run right now */

		/* lock the call */
		call = ag->call;
		log_info_ice_agent(ag);
		rwlock_lock_r(&call->master_lock);

		/* and run our checks */
		__do_ice_checks(ag);

		/* finally, release our reference and start over */
		log_info_clear();
		rwlock_unlock_r(&call->master_lock);
		obj_put(ag);
		mutex_lock(&ice_agents_timers_lock);
		continue;

sleep:
		/* figure out how long we should sleep */
		sleeptime = ag ? timeval_diff(&ag->next_check, &g_now) : 100000;
		sleeptime = MIN(100000, sleeptime); /* 100 ms at the most */
		tv = g_now;
		timeval_add_usec(&tv, sleeptime);
		cond_timedwait(&ice_agents_timers_cond, &ice_agents_timers_lock, &tv);
		continue;
	}

	mutex_unlock(&ice_agents_timers_lock);
}

static void random_ice_string(char *buf, int len) {
	while (len--)
		*buf++ = ice_chars[random() % strlen(ice_chars)];
}

static void create_random_ice_string(struct call *call, str *s, int len) {
	char buf[30];

	assert(len < sizeof(buf));
	if (s->s)
		return;

	random_ice_string(buf, len);
	call_str_cpy_len(call, s, buf, len);
}

void ice_foundation(str *s) {
	str_init_len(s, malloc(ICE_FOUNDATION_LENGTH), ICE_FOUNDATION_LENGTH);
	random_ice_string(s->s, ICE_FOUNDATION_LENGTH);
}

void ice_remote_candidates(GQueue *out, struct ice_agent *ag) {
	GQueue all_compos;
	GList *l;
	struct ice_candidate_pair *pair;

	g_queue_init(out);

	mutex_lock(&ag->lock);
	__get_complete_valid_pairs(&all_compos, ag);
	mutex_unlock(&ag->lock);

	for (l = all_compos.head; l; l = l->next) {
		pair = l->data;
		g_queue_push_tail(out, pair->remote_candidate);
	}

	g_queue_clear(&all_compos);
}
