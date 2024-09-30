#ifndef __ICE_H__
#define __ICE_H__

#include <arpa/inet.h>
#include <glib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>

#include "str.h"
#include "obj.h"
#include "helpers.h"
#include "media_socket.h"
#include "socket.h"
#include "timerthread.h"
#include "types.h"
#include "call.h"

#define MAX_COMPONENTS			2
#define TIMER_RUN_INTERVAL		20 /* ms */
#define STUN_RETRANSMIT_INTERVAL	100 /* ms, with exponential backoff */
#define STUN_MAX_RETRANSMITS		7
#define MAX_ICE_CANDIDATES		100
#define ICE_FOUNDATION_LENGTH		16

#define ICE_AGENT_COMPLETED		0x0002
#define ICE_AGENT_CONTROLLING		0x0004
#define ICE_AGENT_NOMINATING		0x0008
#define ICE_AGENT_USABLE		0x0010
#define ICE_AGENT_LITE_SELF		0x0020

#define ICE_PAIR_FROZEN			0x0001
#define ICE_PAIR_IN_PROGRESS		0x0002
#define ICE_PAIR_FAILED			0x0004
#define ICE_PAIR_SUCCEEDED		0x0008
#define ICE_PAIR_NOMINATED		0x0010
#define ICE_PAIR_LEARNED		0x0020
#define ICE_PAIR_VALID			0x0040
#define ICE_PAIR_TO_USE			0x0080
#define ICE_PAIR_TRIGGERED		0x0100

#define PAIR_ISSET(p, f)	bf_isset(&(p)->pair_flags, ICE_PAIR_ ## f)
#define PAIR_SET(p, f)		bf_set(&(p)->pair_flags, ICE_PAIR_ ## f)
#define PAIR_SET2(p, f, g)	bf_set(&(p)->pair_flags, ICE_PAIR_ ## f | ICE_PAIR_ ## g)
#define PAIR_CLEAR(p, f)	bf_clear(&(p)->pair_flags, ICE_PAIR_ ## f)
#define PAIR_CLEAR2(p, f, g)	bf_clear(&(p)->pair_flags, ICE_PAIR_ ## f | ICE_PAIR_ ## g)

#define AGENT_ISSET(p, f)	bf_isset(&(p)->agent_flags, ICE_AGENT_ ## f)
#define AGENT_ISSET2(p, f, g)	bf_isset(&(p)->agent_flags, ICE_AGENT_ ## f | ICE_AGENT_ ## g)
#define AGENT_SET(p, f)		bf_set(&(p)->agent_flags, ICE_AGENT_ ## f)
#define AGENT_SET2(p, f, g)	bf_set(&(p)->agent_flags, ICE_AGENT_ ## f | ICE_AGENT_ ## g)
#define AGENT_CLEAR(p, f)	bf_clear(&(p)->agent_flags, ICE_AGENT_ ## f)
#define AGENT_CLEAR3(p, f, g, h) \
	bf_clear(&(p)->agent_flags, ICE_AGENT_ ## f | ICE_AGENT_ ## g | ICE_AGENT_ ## h)

struct logical_intf;
struct local_intf;
struct packet_stream;
struct call_media;
struct stream_params;
struct stun_attrs;
struct call_monologue;

enum ice_candidate_type {
	ICT_UNKNOWN = 0,
	ICT_HOST,
	ICT_SRFLX,
	ICT_PRFLX,
	ICT_RELAY,
	__ICT_LAST,
};

struct ice_candidate {
	str			foundation;
	unsigned long		component_id;
	socktype_t		*transport;
	unsigned long		priority;
	endpoint_t		endpoint;
	enum ice_candidate_type type;
	endpoint_t		related;
	str			ufrag;
};

struct ice_candidate_pair {
	struct ice_candidate	*remote_candidate;
	const struct local_intf	*local_intf;
	stream_fd	*sfd;
	atomic64		pair_flags;
	uint32_t		stun_transaction[3]; /* belongs to transaction_hash, thus agent->lock */
	unsigned int		retransmit_ms;
	struct timeval		retransmit;
	unsigned int		retransmits;
	struct ice_agent	*agent;
	uint64_t		pair_priority;
	unsigned int		was_controlling:1,
				was_nominated:1;
};

TYPED_GHASHTABLE_PROTO(candidate_ht, struct ice_candidate, struct ice_candidate)
TYPED_GHASHTABLE_PROTO(candidate_pair_ht, struct ice_candidate_pair, struct ice_candidate_pair)
TYPED_GHASHTABLE_PROTO(foundation_ht, struct ice_candidate, struct ice_candidate)
TYPED_GHASHTABLE_PROTO(priority_ht, void, struct ice_candidate)
TYPED_GHASHTABLE_PROTO(transaction_ht, uint32_t, struct ice_candidate_pair)

/* these are protected by the call's master_lock */
struct ice_agent {
	struct timerthread_obj	tt_obj;
	call_t		*call; /* main reference */
	struct call_media	*media;
	const struct logical_intf	*logical_intf;
	sockfamily_t		*desired_family;
	atomic64		last_activity;

	mutex_t			lock; /* for elements below. and call must be locked in R */
				/* lock order: in_lock first, then agent->lock */
	candidate_q		remote_candidates;
	candidate_pair_q	candidate_pairs; /* for storage */
	candidate_pair_q	triggered;
	candidate_ht		candidate_hash;
	priority_ht		cand_prio_hash;
	candidate_pair_ht	pair_hash;
	transaction_ht		transaction_hash;
	foundation_ht		foundation_hash;
	GTree			*all_pairs;
	candidate_pair_q	all_pairs_list; /* sorted through gtree */
	GTree			*nominated_pairs; /* nominated by peer */
	GTree			*succeeded_pairs; /* checked by us */
	GTree			*valid_pairs; /* succeeded and nominated */
	unsigned int		active_components;
	struct timeval		start_nominating;

	str			ufrag[2]; /* 0 = remote, 1 = local */
	str			pwd[2]; /* ditto */
	atomic64		agent_flags;
};




extern const unsigned int ice_type_preferences[];
extern const char * const ice_type_strings[];




void ice_init(void);
void ice_free(void);

enum ice_candidate_type ice_candidate_type(const str *s);
bool ice_has_related(enum ice_candidate_type);
void ice_foundation(str *);
bool ice_peer_address_known(struct ice_agent *, const endpoint_t *, struct packet_stream *,
		const struct local_intf *ifa);

void ice_agent_init(struct ice_agent **agp, struct call_media *media);
void ice_update(struct ice_agent *, struct stream_params *, bool allow_restart);
void ice_shutdown(struct ice_agent **);
void ice_restart(struct ice_agent *);

void ice_candidates_free(candidate_q *);
void ice_remote_candidates(candidate_q *, struct ice_agent *);

void ice_thread_launch(void);

int ice_request(stream_fd *, const endpoint_t *, struct stun_attrs *);
int ice_response(stream_fd *, const endpoint_t *src,
		struct stun_attrs *attrs, void *transaction);

void dequeue_sdp_fragments(struct call_monologue *);
bool trickle_ice_update(ng_buffer *ngbuf, call_t *call, sdp_ng_flags *flags,
		sdp_streams_q *streams);
void ice_fragments_cleanup(fragments_ht ht, bool all);

#include "call.h"


/* returns 0 if ICE still has work to do, 1 otherwise */
INLINE bool ice_has_finished(struct call_media *media) {
	if (!media)
		return true;
	if (!MEDIA_ISSET(media, ICE))
		return true;
	if (!media->ice_agent)
		return true;
	if (AGENT_ISSET(media->ice_agent, COMPLETED))
		return true;
	return false;
}
/* returns 1 if media has connectivity */
INLINE bool ice_is_usable(struct call_media *media) {
	if (!media)
		return true;
	if (!MEDIA_ISSET(media, ICE))
		return true;
	if (!media->ice_agent)
		return true;
	if (AGENT_ISSET(media->ice_agent, USABLE))
		return true;
	return false;
}
INLINE bool ice_is_restart(struct ice_agent *ag, struct stream_params *sp) {
	if (!ag || !sp)
		return false;
	struct call_media *media = ag->media;
	if (ag->ufrag[0].s && sp->ice_ufrag.s && str_cmp_str(&ag->ufrag[0], &sp->ice_ufrag))
		return true;
	else if (ag->pwd[0].s && sp->ice_pwd.s && str_cmp_str(&ag->pwd[0], &sp->ice_pwd))
		return true;
	else if (ag->logical_intf != media->logical_intf)
		return true;
	return false;

}
INLINE unsigned int ice_type_preference(enum ice_candidate_type type) {
	if (type >= __ICT_LAST)
		return 0;
	return ice_type_preferences[type];
}
/* local_pref starts with 0 */
INLINE uint32_t ice_priority_pref(unsigned int type_pref, unsigned int local_pref, unsigned int component) {
	return type_pref << 24 | (65535 - local_pref) << 8 | (256 - component);
}
INLINE uint32_t ice_priority(enum ice_candidate_type type, unsigned int local_pref, unsigned int component) {
	return ice_priority_pref(ice_type_preference(type), local_pref, component);
}
INLINE unsigned int ice_type_pref_from_prio(uint32_t prio) {
	return (prio & 0xff000000) >> 24;
}
INLINE unsigned int ice_local_pref_from_prio(uint32_t prio) {
	return 65535 - ((prio & 0xffff00) >> 8);
}
INLINE const char *ice_candidate_type_str(enum ice_candidate_type type) {
	if (type >= __ICT_LAST)
		return 0;
	return ice_type_strings[type];
}
INLINE int ice_ufrag_cmp(struct ice_agent *ag, const str *s) {
	if (!ag->ufrag[0].len) // fragment unknown
		return 0;
	return str_cmp_str0(&ag->ufrag[0], s);
}



#endif
