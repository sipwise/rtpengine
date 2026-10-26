#include "redis_sentinel.h"

#include <glib.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

#include "helpers.h"
#include "log_d.h"
#include "main.h"
#include "redis.h"

struct sentinel_node {
	char		*host;		/* as configured, for --redis-resolve-on-reconnect */
	endpoint_t	ep;
	bool		failing;	/* last query failed (logged once) */
};

struct redis_sentinel {
	struct sentinel_node	*nodes;
	unsigned int		num_nodes;
	char			*auth;
	char			*master_name;
	const char		*probe_auth;	/* data node password, for ROLE */

	/* published master: written by the thread, read by the connections */
	mutex_t			lock;
	cond_t			cond;
	bool			wake;
	endpoint_t		master;
	uint64_t		epoch;
	atomic64		gen;		/* 0: no master known yet */
	atomic64		limited_wake_us;

	/* thread only */
	bool			none_answered;	/* logged once */
	bool			epoch_back;	/* logged once */
	struct thread_waker	waker;
};

struct redis_sentinel *rtpe_redis_sentinel;


/* [PW@]HOST:PORT[,HOST:PORT...] */
struct redis_sentinel *redis_sentinel_new(const char *list, const char *master_name,
		const char *auth_env)
{
	if (!list || !*list || !master_name || !*master_name)
		return NULL;

	struct redis_sentinel *s = g_new0(struct redis_sentinel, 1);
	mutex_init(&s->lock);
	cond_init(&s->cond);
	g_autofree char *dup = g_strdup(list);
	g_auto(GStrv) items = NULL;
	char *hosts = dup;

	char *at = strrchr(hosts, '@');
	if (at) {
		*at = '\0';
		if (!*hosts)
			goto err;	// "@host:port": an empty password is a mistake
		s->auth = g_strdup(hosts);
		hosts = at + 1;
	}
	else {
		const char *env = getenv(auth_env);
		if (env && *env)
			s->auth = g_strdup(env);
	}

	items = g_strsplit(hosts, ",", -1);
	s->num_nodes = g_strv_length(items);
	if (!s->num_nodes)
		goto err;
	s->nodes = g_new0(struct sentinel_node, s->num_nodes);

	for (unsigned int i = 0; i < s->num_nodes; i++) {
		struct sentinel_node *n = &s->nodes[i];
		char *item = g_strstrip(items[i]);
		char *colon = strrchr(item, ':');
		if (!colon)
			goto err;
		if (!endpoint_parse_any_getaddrinfo_full(&n->ep, item) || !n->ep.port)
			goto err;
		n->host = g_strndup(item, colon - item);
	}

	s->master_name = g_strdup(master_name);
	return s;

err:
	redis_sentinel_free(s);
	return NULL;
}

void redis_sentinel_free(struct redis_sentinel *s) {
	if (!s)
		return;
	for (unsigned int i = 0; s->nodes && i < s->num_nodes; i++)
		g_free(s->nodes[i].host);
	g_free(s->nodes);
	g_free(s->auth);
	g_free(s->master_name);
	mutex_destroy(&s->lock);
	g_free(s);
}

void redis_sentinel_set_probe_auth(struct redis_sentinel *s, const char *auth) {
	s->probe_auth = auth;
}

const char *redis_sentinel_master_name(const struct redis_sentinel *s) {
	return s->master_name;
}


uint64_t redis_sentinel_gen(struct redis_sentinel *s) {
	return atomic64_get(&s->gen);
}

uint64_t redis_sentinel_get(struct redis_sentinel *s, endpoint_t *ep) {
	LOCK(&s->lock);
	*ep = s->master;
	return atomic64_get_na(&s->gen);
}

/* "limited": at most once per poll interval (NOREPLICAS lasts as long as the
 * master lacks replicas) */
void redis_sentinel_wake(struct redis_sentinel *s, bool limited) {
	if (limited) {
		int64_t now = now_us();
		int64_t last = atomic64_get(&s->limited_wake_us);
		if (last && now >= last && now - last < rtpe_config.redis_sentinel_interval * 1000LL)
			return;
		atomic64_set(&s->limited_wake_us, now);
	}
	LOCK(&s->lock);
	s->wake = true;
	cond_signal(&s->cond);
}


/* "name": what the TLS certificate must match, if not the address */
static redisContext *sentinel_connect(const endpoint_t *ep, const char *name, const char *auth) {
	char host[64];
	sockaddr_print(&ep->address, host, sizeof(host));
	int64_t connect_timeout = atomic_get_na(&rtpe_config.redis_connect_timeout) * 1000LL;
	// never without a command timeout ("rediscmdtimeout 0"): a server that
	// accepts but never answers would stop the thread for good
	int64_t cmd_timeout = atomic_get_na(&rtpe_config.redis_cmd_timeout) * 1000LL ? : 1000000;

	redisContext *ctx = redisConnectWithTimeout(host, ep->port, timeval_from_us(connect_timeout));
	if (!ctx)
		return NULL;
	const char *err = NULL;
	redisReply *rp = NULL;
	if (ctx->err || redisSetTimeout(ctx, timeval_from_us(cmd_timeout))
			|| redis_tls_start(ctx, name ? : host, 0, NULL))
		err = ctx->errstr;
	else if (auth && !(rp = redisCommand(ctx, "AUTH %s", auth)))
		err = ctx->errstr;
	else if (rp && rp->type == REDIS_REPLY_ERROR)
		err = "authentication failed";
	if (rp)
		freeReplyObject(rp);
	if (!err)
		return ctx;
	rlog(LOG_WARN | LOG_FLAG_LIMIT, "Redis Sentinel: cannot connect to %s: %s",
			endpoint_print_buf(ep), err);
	redisFree(ctx);
	return NULL;
}

static const char *reply_field(const redisReply *rp, const char *name) {
	for (size_t i = 0; i + 1 < rp->elements; i += 2) {
		const redisReply *k = rp->element[i], *v = rp->element[i + 1];
		if (k->type == REDIS_REPLY_STRING && v->type == REDIS_REPLY_STRING && !strcmp(k->str, name))
			return v->str;
	}
	return NULL;
}

static const char *sentinel_parse(const redisReply *rp, const redisReply *ra,
		endpoint_t *master, uint64_t *epoch)
{
	if (rp->type == REDIS_REPLY_ERROR)
		return rp->str;
	if (ra->type == REDIS_REPLY_ERROR)
		return ra->str;
	const char *epoch_s = rp->type == REDIS_REPLY_ARRAY ? reply_field(rp, "config-epoch") : NULL;
	if (!epoch_s || ra->type != REDIS_REPLY_ARRAY || ra->elements != 2
			|| ra->element[0]->type != REDIS_REPLY_STRING
			|| ra->element[1]->type != REDIS_REPLY_STRING)
		return "unexpected reply";
	char *end;
	*epoch = strtoull(epoch_s, &end, 10);
	if (end == epoch_s || *end)
		return "unexpected reply";
	unsigned long port = strtoul(ra->element[1]->str, &end, 10);
	if (end == ra->element[1]->str || *end || !port || port > 0xffff)
		return "unexpected reply";
	// a host name (announce-hostnames) is resolved here, in the thread
	if (!sockaddr_getaddrinfo(&master->address, ra->element[0]->str))
		return "cannot resolve the master's address";
	master->port = port;
	return NULL;
}

/* Epoch first, then address, so that a failover between the two replies can
 * only pair an older epoch with the newer address. (The "ip" of SENTINEL
 * MASTER switches seconds after the epoch.) */
static bool sentinel_query(struct redis_sentinel *s, struct sentinel_node *n,
		endpoint_t *master, uint64_t *epoch)
{
	if (rtpe_config.redis_resolve_on_reconnect) {
		sockaddr_t a;
		if (sockaddr_getaddrinfo(&a, n->host))
			n->ep.address = a;
	}

	redisContext *ctx = sentinel_connect(&n->ep, n->host, s->auth);
	if (!ctx) {
		n->failing = true;
		return false;
	}

	redisReply *rp = NULL, *ra = NULL;
	const char *err;
	redisAppendCommand(ctx, "SENTINEL MASTER %s", s->master_name);
	redisAppendCommand(ctx, "SENTINEL GET-MASTER-ADDR-BY-NAME %s", s->master_name);
	if (redisGetReply(ctx, (void **) &rp) != REDIS_OK || redisGetReply(ctx, (void **) &ra) != REDIS_OK)
		err = ctx->errstr;
	else
		err = sentinel_parse(rp, ra, master, epoch);

	if (err && !n->failing)
		rlog(LOG_WARN, "Redis Sentinel %s: cannot get the master of '%s': %s",
				endpoint_print_buf(&n->ep), s->master_name, err);
	else if (!err && n->failing)
		rlog(LOG_NOTICE, "Redis Sentinel %s answers again", endpoint_print_buf(&n->ep));
	n->failing = err != NULL;

	if (rp)
		freeReplyObject(rp);
	if (ra)
		freeReplyObject(ra);
	redisFree(ctx);
	return !err;
}

static bool sentinel_is_master(struct redis_sentinel *s, const endpoint_t *ep, uint64_t epoch) {
	// a data node: --redis-tls-server-name applies, as for the data connections
	redisContext *ctx = sentinel_connect(ep, rtpe_config.redis_tls_server_name, s->probe_auth);
	if (!ctx)
		return false;

	bool ret = false;
	redisReply *rp = redisCommand(ctx, "ROLE");
	if (rp && rp->type == REDIS_REPLY_ARRAY && rp->elements && rp->element[0]->type == REDIS_REPLY_STRING) {
		ret = !strcmp(rp->element[0]->str, "master");
		if (!ret)
			rlog(LOG_WARN | LOG_FLAG_LIMIT, "Redis Sentinel names %s as master of '%s' "
					"(config epoch %" PRIu64 "), but it is a %s: not used",
					endpoint_print_buf(ep), s->master_name, epoch, rp->element[0]->str);
	}
	else
		rlog(LOG_WARN | LOG_FLAG_LIMIT, "Redis Sentinel: cannot check the role of %s: %s",
				endpoint_print_buf(ep), !rp ? ctx->errstr
				: rp->type == REDIS_REPLY_ERROR ? rp->str : "unexpected reply");

	if (rp)
		freeReplyObject(rp);
	redisFree(ctx);
	return ret;
}

static void sentinel_publish(struct redis_sentinel *s, const endpoint_t *m, uint64_t epoch) {
	{
		LOCK(&s->lock);
		s->master = *m;
		s->epoch = epoch;
		atomic64_inc(&s->gen);
	}
	rlog(LOG_NOTICE, "Redis Sentinel: master of '%s' is now %s (config epoch %" PRIu64 ")",
			s->master_name, endpoint_print_buf(m), epoch);
}

/* true if the candidate is not a master: ask again soon */
static bool sentinel_round(struct redis_sentinel *s) {
	endpoint_t best = {0}, pub;
	uint64_t best_epoch = 0, pub_epoch, pub_gen;
	bool found = false;

	{
		LOCK(&s->lock);
		pub = s->master;
		pub_epoch = s->epoch;
		pub_gen = atomic64_get_na(&s->gen);
	}

	for (unsigned int i = 0; i < s->num_nodes; i++) {
		endpoint_t m = {0};
		uint64_t e = 0;
		if (!sentinel_query(s, &s->nodes[i], &m, &e))
			continue;
		// at the same epoch, keep the master in use (no flapping while
		// the Sentinels disagree)
		if (!found || e > best_epoch || (e == best_epoch && pub_gen && endpoint_eq(&m, &pub))) {
			best = m;
			best_epoch = e;
			found = true;
		}
	}

	if (!found) {
		if (!s->none_answered)
			rlog(LOG_ERR, "Redis Sentinel: no Sentinel answered for '%s'%s%s",
					s->master_name,
					pub_gen ? "; keeping " : "",
					pub_gen ? endpoint_print_buf(&pub) : "");
		s->none_answered = true;
		return false;
	}
	s->none_answered = false;

	// Never back to an older epoch: a demoted master still says "master"
	// until Sentinel reconfigures it. The master in use is kept for as long
	// as it answers as a master (its connection checks the role).
	if (pub_gen && best_epoch < pub_epoch) {
		if (!s->epoch_back)
			rlog(LOG_ERR, "Redis Sentinel: every Sentinel that answers names %s as master of '%s' "
					"at config epoch %" PRIu64 ", older than %" PRIu64 " (%s, in use): not "
					"followed. If the Sentinels were redeployed without their state, their "
					"epochs went back, and rtpengine must be restarted",
					endpoint_print_buf(&best), s->master_name, best_epoch, pub_epoch,
					endpoint_print_buf(&pub));
		s->epoch_back = true;
		return false;
	}
	s->epoch_back = false;

	if (pub_gen && endpoint_eq(&best, &pub)) {
		LOCK(&s->lock);
		s->epoch = best_epoch;
		return false;
	}

	if (!sentinel_is_master(s, &best, best_epoch))
		return true;

	sentinel_publish(s, &best, best_epoch);
	return false;
}

/* at startup: as for a data node, fails at once if nothing answers, and asks
 * again once a second (11 times) while the candidate is not a master */
bool redis_sentinel_discover(struct redis_sentinel *s) {
	for (int i = 0; i < 11; i++) {
		if (i)
			usleep(1000000);
		bool refused = sentinel_round(s);
		if (redis_sentinel_gen(s))
			return true;
		if (!refused)
			break;
	}
	return false;
}

void redis_sentinel_loop(struct redis_sentinel *s) {
	int64_t interval_us = rtpe_config.redis_sentinel_interval * 1000LL;
	int64_t next = now_us() + interval_us, last = 0;

	// a round is bounded by the timeouts; at shutdown, the waker ends the wait
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	s->waker.lock = &s->lock;
	s->waker.cond = &s->cond;
	thread_waker_add(&s->waker);

	while (!rtpe_shutdown) {
		{
			LOCK(&s->lock);
			// a wake-up comes at least 250 ms after the last round
			while (!rtpe_shutdown) {
				int64_t until = s->wake ? MIN(next, last + 250000) : next;
				if (now_us() >= until)
					break;
				cond_timedwait(&s->cond, &s->lock, until);
			}
			s->wake = false;
		}
		if (rtpe_shutdown)
			break;

		bool refused = sentinel_round(s);
		last = now_us();
		next = last + (refused ? MIN(250000, interval_us) : interval_us);
	}

	thread_waker_del(&s->waker);
}
