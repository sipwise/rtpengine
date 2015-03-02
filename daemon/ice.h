#ifndef __ICE_H__
#define __ICE_H__



#include <arpa/inet.h>
#include <glib.h>
#include <sys/time.h>
#include <sys/types.h>
#include "str.h"
#include "obj.h"
#include "aux.h"
#include "call.h"
#include "media_socket.h"
#include "socket.h"




#define MAX_COMPONENTS			2
#define TIMER_RUN_INTERVAL		20 /* ms */
#define STUN_RETRANSMIT_INTERVAL	100 /* ms, with exponential backoff */
#define STUN_MAX_RETRANSMITS		7
#define MAX_ICE_CANDIDATES		100
#define ICE_FOUNDATION_LENGTH		16



#define ICE_AGENT_COMPLETED		0x0002
#define ICE_AGENT_CONTROLLING		0x0004
#define ICE_AGENT_NOMINATING		0x0008

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
#define AGENT_CLEAR2(p, f, g)	bf_clear(&(p)->agent_flags, ICE_AGENT_ ## f | ICE_AGENT_ ## g)



struct logical_intf;
struct local_intf;
struct packet_stream;
struct call_media;
struct call;
struct stream_params;
struct stun_attrs;




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
};

struct ice_candidate_pair {
	struct ice_candidate	*remote_candidate;
	const struct local_intf	*local_intf;
	struct packet_stream	*packet_stream;
	volatile unsigned int	pair_flags;
	u_int32_t		stun_transaction[3]; /* belongs to transaction_hash, thus agent->lock */
	unsigned int		retransmit_ms;
	struct timeval		retransmit;
	unsigned int		retransmits;
	struct ice_agent	*agent;
	u_int64_t		pair_priority;
	int			was_controlling:1,
				was_nominated:1;
};

/* these are protected by the call's master_lock */
struct ice_agent {
	struct obj		obj;
	struct call		*call; /* main reference */
	struct call_media	*media;
	const struct logical_intf	*logical_intf;
	sockfamily_t		*desired_family;
	atomic64		last_activity;

	mutex_t			lock; /* for elements below. and call must be locked in R */
				/* lock order: in_lock first, then agent->lock */
	GQueue			remote_candidates;
	GQueue			candidate_pairs; /* for storage */
	GQueue			triggered;
	GHashTable		*candidate_hash;
	GHashTable		*pair_hash;
	GHashTable		*transaction_hash;
	GHashTable		*foundation_hash;
	GTree			*all_pairs;
	GQueue			all_pairs_list; /* sorted through gtree */
	GTree			*nominated_pairs; /* nominated by peer */
	GTree			*succeeded_pairs; /* checked by us */
	GTree			*valid_pairs; /* succeeded and nominated */
	unsigned int		active_components;
	struct timeval		start_nominating;

	str			ufrag[2]; /* 0 = remote, 1 = local */
	str			pwd[2]; /* ditto */
	volatile unsigned int	agent_flags;

	struct timeval		next_check; /* protected by ice_agents_timers_lock */
	struct timeval		last_run; /* ditto */
};




extern const unsigned int ice_type_preferences[];
extern const char * const ice_type_strings[];




void ice_init(void);

enum ice_candidate_type ice_candidate_type(const str *s);
int ice_has_related(enum ice_candidate_type);
void ice_foundation(str *);

void ice_agent_init(struct ice_agent **agp, struct call_media *media);
void ice_update(struct ice_agent *, struct stream_params *);
void ice_shutdown(struct ice_agent **);
void ice_restart(struct ice_agent *);

void ice_candidates_free(GQueue *);
void ice_remote_candidates(GQueue *, struct ice_agent *);

void ice_thread_run(void *);

int ice_request(struct packet_stream *, const endpoint_t *, const sockaddr_t *, struct stun_attrs *);
int ice_response(struct packet_stream *ps, const endpoint_t *src, const sockaddr_t *dst,
		struct stun_attrs *attrs, u_int32_t transaction[3]);

/* returns 0 if ICE still has work to do, 1 otherwise */
INLINE int ice_has_finished(struct call_media *media) {
	if (!media)
		return 1;
	if (!MEDIA_ISSET(media, ICE))
		return 1;
	if (!media->ice_agent)
		return 1;
	if (AGENT_ISSET(media->ice_agent, COMPLETED))
		return 1;
	return 0;
}
INLINE unsigned int ice_type_preference(enum ice_candidate_type type) {
	if (type >= __ICT_LAST)
		return 0;
	return ice_type_preferences[type];
}
/* local_pref starts with 0 */
INLINE u_int32_t ice_priority_pref(unsigned int type_pref, unsigned int local_pref, unsigned int component) {
	return type_pref << 24 | (65535 - local_pref) << 8 | (256 - component);
}
INLINE u_int32_t ice_priority(enum ice_candidate_type type, unsigned int local_pref, unsigned int component) {
	return ice_priority_pref(ice_type_preference(type), local_pref, component);
}
INLINE unsigned int ice_type_pref_from_prio(u_int32_t prio) {
	return (prio & 0xff000000) >> 24;
}
INLINE unsigned int ice_local_pref_from_prio(u_int32_t prio) {
	return 65535 - ((prio & 0xffff00) >> 8);
}
INLINE const char *ice_candidate_type_str(enum ice_candidate_type type) {
	if (type >= __ICT_LAST)
		return 0;
	return ice_type_strings[type];
}



#endif
