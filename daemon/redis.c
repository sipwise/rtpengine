#include <stdio.h>
#include <hiredis/hiredis.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <glib.h>

#include "redis.h"
#include "compat.h"
#include "aux.h"
#include "call.h"
#include "log.h"
#include "str.h"
#include "crypto.h"
#include "dtls.h"






INLINE redisReply *redis_expect(int type, redisReply *r) {
	if (!r)
		return NULL;
	if (r->type != type) {
		freeReplyObject(r);
		return NULL;
	}
	return r;
}

#if __YCM

/* format checking in YCM editor */

INLINE void redis_pipe(struct redis *r, const char *fmt, ...)
	__attribute__((format(printf,2,3)));
INLINE redisReply *redis_get(struct redis *r, int type, const char *fmt, ...)
	__attribute__((format(printf,3,4)));
static int redisCommandNR(redisContext *r, const char *fmt, ...)
	__attribute__((format(printf,2,3)));

#define PB "%.*s"
#define STR(x) (int) (x)->len, (x)->s
#define STR_R(x) (int) (x)->len, (x)->str
#define S_LEN(s,l) (int) (l), (s)

#else

#define PB "%b"
#define STR(x) (x)->s, (size_t) (x)->len
#define STR_R(x) (x)->str, (size_t) (x)->len
#define S_LEN(s,l) (s), (size_t) (l)

#endif

static void redis_pipe(struct redis *r, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	redisvAppendCommand(r->ctx, fmt, ap);
	va_end(ap);
	r->pipeline++;
}
static redisReply *redis_get(struct redis *r, int type, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;

	va_start(ap, fmt);
	ret = redis_expect(type, redisvCommand(r->ctx, fmt, ap));
	va_end(ap);

	return ret;
}
static int redisCommandNR(redisContext *r, const char *fmt, ...) {
	va_list ap;
	redisReply *ret;

	va_start(ap, fmt);
	ret = redisvCommand(r, fmt, ap);
	va_end(ap);

	if (ret)
		freeReplyObject(ret);

	return ret ? 0 : -1;
}



/* called with r->lock held */
static int redis_check_type(struct redis *r, char *key, char *suffix, char *type) {
	redisReply *rp;

	rp = redisCommand(r->ctx, "TYPE %s%s", key, suffix ? : "");
	if (!rp)
		return -1;
	if (rp->type != REDIS_REPLY_STATUS) {
		freeReplyObject(rp);
		return -1;
	}
	if (strcmp(rp->str, type) && strcmp(rp->str, "none"))
		redisCommandNR(r->ctx, "DEL %s%s", key, suffix ? : "");
	freeReplyObject(rp);
	return 0;
}




/* called with r->lock held */
static void redis_consume(struct redis *r) {
	redisReply *rp;

	while (r->pipeline) {
		if (redisGetReply(r->ctx, (void **) &rp) == REDIS_OK)
			freeReplyObject(rp);
		r->pipeline--;
	}
}




/* called with r->lock held if necessary */
static int redis_connect(struct redis *r, int wait, int role) {
	struct timeval tv;
	redisReply *rp;
	char *s;

	if (r->ctx)
		redisFree(r->ctx);
	r->ctx = NULL;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	r->ctx = redisConnectWithTimeout(r->host, r->port, tv);

	if (!r->ctx)
		goto err;
	if (r->ctx->err)
		goto err2;

	if (redisCommandNR(r->ctx, "PING"))
		goto err2;

	if (redisCommandNR(r->ctx, "SELECT %i", r->db))
		goto err2;

	while (wait-- >= 0) {
		ilog(LOG_INFO, "Asking Redis whether it's master or slave...");
		rp = redisCommand(r->ctx, "INFO");
		if (!rp) {
			goto err2;
		}

		s = strstr(rp->str, "role:");
		if (!s) {
			goto err3;
		}

		if (!memcmp(s, "role:master", 9)) {
			if (role == MASTER_REDIS_ROLE || role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis in master mode");
				goto done;
			} else if (role == SLAVE_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis in master mode, but wanted mode is slave; retrying...");
				goto next;
			}
		} else if (!memcmp(s, "role:slave", 8)) {
			if (role == SLAVE_REDIS_ROLE || role == ANY_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis in slave mode");
				goto done;
			} else if (role == MASTER_REDIS_ROLE) {
				ilog(LOG_INFO, "Connected to Redis in slave mode, but wanted mode is master; retrying...");
				goto next;
			}
		} else {
			goto err3;
		}

next:
		freeReplyObject(rp);
		usleep(1000000);
	}

	goto err2;

done:
	freeReplyObject(rp);
	redis_check_type(r, "calls", NULL, "set");
	return 0;

err3:
	freeReplyObject(rp);
err2:
	if (r->ctx->err)
		rlog(LOG_ERR, "Redis error: %s", r->ctx->errstr);
	redisFree(r->ctx);
	r->ctx = NULL;
err:
	rlog(LOG_ERR, "Failed to connect to master Redis database");
	return -1;
}



struct redis *redis_new(u_int32_t ip, u_int16_t port, int db, int role) {
	struct redis *r;

	r = g_slice_alloc0(sizeof(*r));

	r->ip = ip;
	sprintf(r->host, IPF, IPP(ip));
	r->port = port;
	r->db = db;
	mutex_init(&r->lock);

	if (redis_connect(r, 10, role))
		goto err;

	return r;

err:
	mutex_destroy(&r->lock);
	g_slice_free1(sizeof(*r), r);
	return NULL;
}



static void redis_close(struct redis *r) {
	if (r->ctx)
		redisFree(r->ctx);
	mutex_destroy(&r->lock);
	g_slice_free1(sizeof(*r), r);
}



/* called with r->lock held if necessary */
static void redis_check_conn(struct redis *r, int role) {
	if (redisCommandNR(r->ctx, "PING") == 0)
		return;
	rlog(LOG_INFO, "Lost connection to Redis");
	if (redis_connect(r, 1, role))
		abort();
}




/* called with r->lock held and c->master_lock held */
static void redis_delete_call(struct call *c, struct redis *r) {
	GSList *l, *n;
	GList *k;
	struct call_monologue *ml;
	struct call_media *media;

	redis_pipe(r, "SREM calls "PB"", STR(&c->callid));
	redis_pipe(r, "DEL call-"PB" tags-"PB" sfds-"PB" streams-"PB"", STR(&c->callid), STR(&c->callid),
			STR(&c->callid), STR(&c->callid));

	for (l = c->stream_fds; l; l = l->next)
		redis_pipe(r, "DEL sfd-%llu", (long long unsigned) l->data);

	for (l = c->streams; l; l = l->next)
		redis_pipe(r, "DEL stream-%llu", (long long unsigned) l->data);

	for (l = c->monologues; l; l = l->next) {
		ml = l->data;

		redis_pipe(r, "DEL tag-%llu other_tags-%llu medias-%llu",
			(long long unsigned) ml,
			(long long unsigned) ml,
			(long long unsigned) ml);

		for (k = ml->medias.head; k; k = k->next) {
			media = k->data;

			redis_pipe(r, "DEL media-%llu streams-%llu maps-%llu",
				(long long unsigned) k->data, (long long unsigned) k->data,
				(long long unsigned) k->data);

			for (n = media->endpoint_maps; n; n = n->next)
				redis_pipe(r, "DEL map-%llu sfds-%llu",
					(long long unsigned) n->data,
					(long long unsigned) n->data);
		}
	}

	redis_consume(r);
}




static int redis_get_hash(struct redis_hash *out, struct redis *r, const char *key, const redisReply *which) {
	redisReply *k, *v;
	int i;

	out->ht = g_hash_table_new(g_str_hash, g_str_equal);
	if (!out->ht)
		goto err;
	out->rr = redis_get(r, REDIS_REPLY_ARRAY, "HGETALL %s-"PB"", key, STR_R(which));
	if (!out->rr)
		goto err2;

	for (i = 1; i < out->rr->elements; i += 2) {
		k = out->rr->element[i - 1];
		v = out->rr->element[i];
		if (k->type != REDIS_REPLY_STRING || v->type != REDIS_REPLY_STRING)
			continue;

		if (g_hash_table_insert_check(out->ht, k->str, v) != TRUE)
			goto err3;
	}

	return 0;

err3:
	freeReplyObject(out->rr);
err2:
	g_hash_table_destroy(out->ht);
err:
	return -1;
}
/*
static struct redis_hash *redis_get_hash_new(struct redis *r, const char *key, const redisReply *which) {
	struct redis_hash *out;

	out = g_slice_alloc(sizeof(*out));
	if (!out)
		return NULL;
	if (!redis_get_hash(out, r, key, which))
		return out;
	g_slice_free1(sizeof(*out), out);
	return NULL;
}
*/



static void redis_destroy_hash(struct redis_hash *rh) {
	freeReplyObject(rh->rr);
	g_hash_table_destroy(rh->ht);
}
/*
static void redis_free_hash(struct redis_hash *rh) {
	redis_destroy_hash(rh);
	g_slice_free1(sizeof(*rh), rh);
}
*/
static void redis_destroy_list(struct redis_list *rl) {
	struct list_item *it;

	redis_destroy_hash(&rl->rh);
	while ((it = g_queue_pop_head(&rl->q)))
		g_slice_free1(sizeof(*it), it);
}



static int redis_get_list_hash(struct redis_list *out, struct redis *r, const char *key, const redisReply *id,
		const char *sub)
{
	redisReply *el;
	int i;
	struct list_item *it;

	g_queue_init(&out->q);
	out->rh.ht = g_hash_table_new(g_str_hash, g_str_equal);
	if (!out->rh.ht)
		return -1;

	out->rh.rr = redis_get(r, REDIS_REPLY_ARRAY, "LRANGE %s-"PB" 0 -1", key, STR_R(id));
	if (!out->rh.rr)
		goto err;

	for (i = 0; i < out->rh.rr->elements; i++) {
		el = out->rh.rr->element[i];
		if (el->type != REDIS_REPLY_STRING)
			continue;

		it = g_slice_alloc(sizeof(*it));
		if (!it)
			goto err2;

		it->id = el;

		if (redis_get_hash(&it->rh, r, sub, el))
			goto err3;

		if (g_hash_table_insert_check(out->rh.ht, el->str, it) != TRUE)
			goto err4;

		g_queue_push_tail(&out->q, it);
	}

	return 0;

err4:
	redis_destroy_hash(&it->rh);
err3:
	g_slice_free1(sizeof(*it), it);
err2:
	freeReplyObject(out->rh.rr);
err:
	g_hash_table_destroy(out->rh.ht);
	g_queue_clear(&out->q);
	return -1;
}



static int redis_hash_get_str(str *out, const struct redis_hash *h, const char *k) {
	redisReply *r;

	r = g_hash_table_lookup(h->ht, k);
	if (!r) {
		out->s = NULL;
		out->len = 0;
		return -1;
	}
	out->s = r->str;
	out->len = r->len;
	return 0;
}

/* we can do this because this happens during startup in a single thread */
static atomic64 strtoa64(const char *c, char **endp, int base) {
	u_int64_t u;
	atomic64 ret;

	u = strtoull(c, endp, base);
	atomic64_set_na(&ret, u);
	return ret;
}

define_get_int_type(time_t, time_t, strtoull);
define_get_int_type(int, int, strtol);
define_get_int_type(unsigned, unsigned int, strtol);
define_get_int_type(u16, u_int16_t, strtol);
define_get_int_type(u64, u_int64_t, strtoull);
define_get_int_type(a64, atomic64, strtoa64);

define_get_type_format(str, str);
define_get_type_format(u16, u_int16_t);
//define_get_type_format(u64, u_int64_t);
define_get_type_format(a64, atomic64);

static int redis_hash_get_c_buf_fn(unsigned char *out, size_t len, const struct redis_hash *h,
		const char *k, ...)
{
	va_list ap;
	str s;
	int ret;

	va_start(ap, k);
	ret = redis_hash_get_str_v(&s, h, k, ap);
	va_end(ap);
	if (ret)
		return -1;
	if (s.len > len)
		return -1;

	memcpy(out, s.s, s.len);

	return 0;
}

#define redis_hash_get_c_buf_f(o, h, f...) \
		redis_hash_get_c_buf_fn(o, sizeof(o), h, f)

static int redis_hash_get_bool_flag(const struct redis_hash *h, const char *k) {
	int i;

	if (redis_hash_get_int(&i, h, k))
		return 0;
	if (i)
		return -1;
	return 0;
}

static int redis_hash_get_endpoint(struct endpoint *out, const struct redis_hash *h, const char *k) {
	str s;

	if (redis_hash_get_str_f(&s, h, "%s-addr", k))
		return -1;
	if (inet_pton(AF_INET6, s.s, &out->ip46) != 1)
		return -1;
	if (redis_hash_get_u16_f(&out->port, h, "%s-port", k))
		return -1;

	return 0;
}
static int redis_hash_get_stats(struct stats *out, const struct redis_hash *h, const char *k) {
	if (redis_hash_get_a64_f(&out->packets, h, "%s-packets", k))
		return -1;
	if (redis_hash_get_a64_f(&out->bytes, h, "%s-bytes", k))
		return -1;
	if (redis_hash_get_a64_f(&out->errors, h, "%s-errors", k))
		return -1;
	return 0;
}
static void *redis_hash_get_ptr(struct redis_list *list, const char *key) {
	struct list_item *it;

	if (!strcmp(key, "0"))
		return NULL;
	it = g_hash_table_lookup(list->rh.ht, key);
	if (!it)
		return NULL;
	return it->ptr;
}
static void *redis_hash_get_ptr_rr(struct redis_list *list, const redisReply *rr) {
	if (rr->type != REDIS_REPLY_STRING)
		return NULL;
	return redis_hash_get_ptr(list, rr->str);
}
static void *redis_hash_get_ptr_hash(struct redis_list *list, struct redis_hash *rh, const char *key) {
	str s;

	if (redis_hash_get_str(&s, rh, key))
		return NULL;
	return redis_hash_get_ptr(list, s.s);
}

/* can return 1, 0 or -1 */
static int redis_hash_get_crypto_params(struct crypto_params *out, const struct redis_hash *h, const char *k) {
	str s;

	if (redis_hash_get_str_f(&s, h, "%s-crypto_suite", k))
		return 1;
	out->crypto_suite = crypto_find_suite(&s);
	if (!out->crypto_suite)
		return -1;

	if (redis_hash_get_c_buf_f(out->master_key, h, "%s-master_key", k))
		return -1;
	if (redis_hash_get_c_buf_f(out->master_salt, h, "%s-master_salt", k))
		return -1;

	if (!redis_hash_get_str_f(&s, h, "%s-mki", k)) {
		if (s.len > 255)
			return -1;
		out->mki = malloc(s.len);
		memcpy(out->mki, s.s, s.len);
	}

	return 0;
}
static int redis_hash_get_crypto_context(struct crypto_context *out, const struct redis_hash *h) {
	int ret;

	ret = redis_hash_get_crypto_params(&out->params, h, "");
	if (ret == 1)
		return 0;
	else if (ret)
		return -1;
	if (redis_hash_get_u64(&out->last_index, h, "last_index"))
		return -1;

	return 0;
}

static int redis_hash_build_list(struct redis *r, const char *key, redisReply *tag, struct redis_list *list,
		int (*func)(void *, void *), void *up) {
	redisReply *rr;
	void *ptr;
	int i, ret = -1;

	rr = redis_get(r, REDIS_REPLY_ARRAY, "LRANGE %s-"PB" 0 -1", key, STR_R(tag));
	if (!rr)
		return -1;

	for (i = 0; i < rr->elements; i++) {
		ptr = redis_hash_get_ptr_rr(list, rr->element[i]);
		if (!ptr)
			goto out;
		if (func(up, ptr))
			goto out;
	}

	ret = 0;
out:
	freeReplyObject(rr);
	return ret;
}
static int redis_build_other_tags(void *a, void *b) {
	struct call_monologue *A = a, *B = b;

	g_hash_table_insert(A->other_tags, &B->tag, B);
	return 0;
}
static int redis_build_streams(void *a, void *b) {
	struct call_media *med = a;
	struct packet_stream *ps = b;

	g_queue_push_tail(&med->streams, ps);
	ps->media = med;
	return 0;
}
static int redis_build_em_sfds(void *a, void *b) {
	struct endpoint_map *em = a;

	g_queue_push_tail(&em->sfds, b);
	return 0;
}




static int redis_sfds(struct call *c, struct redis_list *sfds) {
	GList *l;
	struct list_item *it;
	struct stream_fd *sfd;
	struct udp_fd fd;
	int port;

	for (l = sfds->q.head; l; l = l->next) {
		it = l->data;

		if (redis_hash_get_int(&port, &it->rh, "localport"))
			return -1;
		if (__get_consecutive_ports(&fd, 1, port, c))
			return -1;
		sfd = __stream_fd_new(&fd, c);
		if (redis_hash_get_crypto_context(&sfd->crypto, &it->rh))
			return -1;
		it->ptr = sfd;
	}
	return 0;
}

static int redis_streams(struct call *c, struct redis_list *streams) {
	GList *l;
	struct list_item *it;
	struct packet_stream *ps;

	for (l = streams->q.head; l; l = l->next) {
		it = l->data;

		ps = __packet_stream_new(c);
		if (!ps)
			return -1;

		atomic64_set_na(&ps->last_packet, time(NULL));
		if (redis_hash_get_unsigned((unsigned int *) &ps->ps_flags, &it->rh, "ps_flags"))
			return -1;
		if (redis_hash_get_endpoint(&ps->endpoint, &it->rh, "endpoint"))
			return -1;
		if (redis_hash_get_endpoint(&ps->advertised_endpoint, &it->rh, "advertised_endpoint"))
			return -1;
		if (redis_hash_get_stats(&ps->stats, &it->rh, "stats"))
			return -1;
		if (redis_hash_get_crypto_context(&ps->crypto, &it->rh))
			return -1;
		it->ptr = ps;

		PS_CLEAR(ps, KERNELIZED);
	}
	return 0;
}

static int redis_tags(struct call *c, struct redis_list *tags) {
	GList *l;
	struct list_item *it;
	struct call_monologue *ml;
	str s;

	for (l = tags->q.head; l; l = l->next) {
		it = l->data;

		ml = __monologue_create(c);
		if (!ml)
			return -1;

		if (redis_hash_get_time_t(&ml->created, &it->rh, "created"))
			return -1;
		if (!redis_hash_get_str(&s, &it->rh, "tag"))
			__monologue_tag(ml, &s);
		if (!redis_hash_get_str(&s, &it->rh, "via-branch"))
			__monologue_viabranch(ml, &s);
		redis_hash_get_time_t(&ml->deleted, &it->rh, "deleted");
		it->ptr = ml;
	}

	return 0;
}

static int redis_link_sfds(struct redis_list *sfds, struct redis_list *streams) {
	GList *l;
	struct list_item *it;
	struct stream_fd *sfd;

	for (l = sfds->q.head; l; l = l->next) {
		it = l->data;
		sfd = it->ptr;
		sfd->stream = redis_hash_get_ptr_hash(streams, &it->rh, "stream");
		if (!sfd->stream)
			return -1;
	}

	return 0;
}

static int redis_tags_populate(struct redis *r, struct redis_list *tags, struct redis_list *streams,
		struct redis_list *sfds)
{
	GList *l_tags, *l_medias, *l_ems;
	struct list_item *it_tag, *it_media, *it_em;
	struct call_monologue *ml;
	struct redis_list rl_medias, rl_ems;
	int i;
	struct call_media *med;
	str s;
	struct endpoint_map *em;
	struct callmaster *cm;
	struct in6_addr in6a;

	for (l_tags = tags->q.head; l_tags; l_tags = l_tags->next) {
		it_tag = l_tags->data;
		ml = it_tag->ptr;

		cm = ml->call->callmaster;

		if (redis_hash_build_list(r, "other_tags", it_tag->id, tags, redis_build_other_tags, ml))
			return -1;
		ml->active_dialogue = redis_hash_get_ptr_hash(tags, &it_tag->rh, "active");

		if (redis_get_list_hash(&rl_medias, r, "medias", it_tag->id, "media"))
			return -1;

		for (i = 1, l_medias = rl_medias.q.head; l_medias; i++, l_medias = l_medias->next) {
			it_media = l_medias->data;

			/* from call.c:__get_media() */
			med = g_slice_alloc0(sizeof(*med));
			med->monologue = ml;
			med->call = ml->call;
			med->index = i;
			g_queue_push_tail(&ml->medias, med);

			if (redis_hash_get_str(&s, &it_media->rh, "type"))
				goto free1;
			call_str_cpy(ml->call, &med->type, &s);

			if (redis_hash_get_str(&s, &it_media->rh, "protocol"))
				goto free1;
			med->protocol = transport_protocol(&s);

			if (redis_hash_get_int(&med->desired_family, &it_media->rh, "desired_family"))
				goto free1;

			if (redis_hash_get_str(&s, &it_media->rh, "interface")
					|| !(med->interface = get_local_interface(cm, &s, med->desired_family)))
			{
				rlog(LOG_ERR, "unable to find specified local interface");
				med->interface = get_local_interface(cm, NULL, med->desired_family);
			}

			if (redis_hash_get_str(&s, &it_media->rh, "local_address")
					|| inet_pton(AF_INET6, s.s, &in6a) != 1
					|| !(med->local_address = get_interface_from_address(med->interface,
							&in6a)))
			{
				rlog(LOG_ERR, "unable to find specified local address");
				med->local_address = get_any_interface_address(med->interface,
						med->desired_family);
			}

			if (redis_hash_get_unsigned(&med->sdes_in.tag, &it_media->rh, "sdes_in_tag"))
				goto free1;
			if (redis_hash_get_unsigned(&med->sdes_out.tag, &it_media->rh, "sdes_out_tag"))
				goto free1;
			if (redis_hash_get_unsigned((unsigned int *) &med->media_flags, &it_media->rh,
						"media_flags"))
				goto free1;
			if (redis_hash_get_crypto_params(&med->sdes_in.params, &it_media->rh, "sdes_in") < 0)
				goto free1;
			if (redis_hash_get_crypto_params(&med->sdes_out.params, &it_media->rh, "sdes_out") < 0)
				goto free1;
			/* XXX dtls */

			if (redis_hash_build_list(r, "streams", it_media->id, streams, redis_build_streams, med))
				goto free1;

			if (redis_get_list_hash(&rl_ems, r, "maps", it_media->id, "map"))
				goto free1;

			for (l_ems = rl_ems.q.head; l_ems; l_ems = l_ems->next) {
				it_em = l_ems->data;

				/* from call.c:__get_endpoint_map() */
				em = g_slice_alloc0(sizeof(*em));
				g_queue_init(&em->sfds);
				med->endpoint_maps = g_slist_prepend(med->endpoint_maps, em);

				if (redis_hash_get_endpoint(&em->endpoint, &it_em->rh, "endpoint"))
					goto free2;
				if (redis_hash_build_list(r, "sfds", it_em->id, sfds, redis_build_em_sfds, em))
					goto free2;
				em->wildcard = redis_hash_get_bool_flag(&it_em->rh, "wildcard");
			}
		}
	}

	return 0;

free2:
	med->endpoint_maps = g_slist_delete_link(med->endpoint_maps, med->endpoint_maps);
	g_slice_free1(sizeof(*em), em);
free1:
	g_queue_pop_tail(&ml->medias);
	g_queue_clear(&med->streams);
	g_slice_free1(sizeof(*med), med);
	return -1;
}

static int redis_link_streams(struct redis_list *streams, struct redis_list *sfds) {
	GList *l;
	struct list_item *it;
	struct packet_stream *ps;

	for (l = streams->q.head; l; l = l->next) {
		it = l->data;
		ps = it->ptr;

		ps->sfd = redis_hash_get_ptr_hash(sfds, &it->rh, "sfd");
		ps->rtp_sink = redis_hash_get_ptr_hash(streams, &it->rh, "rtp_sink");
		ps->rtcp_sink = redis_hash_get_ptr_hash(streams, &it->rh, "rtcp_sink");
		ps->rtcp_sibling = redis_hash_get_ptr_hash(streams, &it->rh, "rtcp_sibling");
	}

	return 0;
}





static void redis_restore_call(struct redis *r, struct callmaster *m, const redisReply *id) {
	struct redis_hash call;
	struct redis_list tags, sfds, streams;
	struct call *c = NULL;
	str s;
	const char *err;
	int i;

	err = "'call' data incomplete";
	if (redis_get_hash(&call, r, "call", id))
		goto err1;
	err = "'tags' incomplete";
	if (redis_get_list_hash(&tags, r, "tags", id, "tag"))
		goto err2;
	err = "'sfds' incomplete";
	if (redis_get_list_hash(&sfds, r, "sfds", id, "sfd"))
		goto err3;
	err = "'streams' incomplete";
	if (redis_get_list_hash(&streams, r, "streams", id, "stream"))
		goto err4;

	s.s = id->str;
	s.len = id->len;
	c = call_get_or_create(&s, m);
	err = "failed to create call struct";
	if (!c)
		goto err5;

	err = "missing 'created' timestamp";
	if (redis_hash_get_time_t(&c->created, &call, "created"))
		goto err6;
	err = "missing 'last signal' timestamp";
	if (redis_hash_get_time_t(&c->last_signal, &call, "last_signal"))
		goto err6;
	if (redis_hash_get_int(&i, &call, "tos"))
		c->tos = 184;
	else
		c->tos = i;
	redis_hash_get_time_t(&c->deleted, &call, "deleted");
	redis_hash_get_time_t(&c->ml_deleted, &call, "ml_deleted");
	if (!redis_hash_get_str(&s, &call, "created_from"))
		c->created_from = call_strdup(c, s.s);
	if (!redis_hash_get_str(&s, &call, "created_from_addr")) {
		parse_ip6_port(&c->created_from_addr.sin6_addr, &c->created_from_addr.sin6_port, s.s);
		c->created_from_addr.sin6_port = htons(c->created_from_addr.sin6_port);
		c->created_from_addr.sin6_family = AF_INET6;
	}

	err = "failed to create sfds";
	if (redis_sfds(c, &sfds))
		goto err6;
	err = "failed to create streams";
	if (redis_streams(c, &streams))
		goto err6;
	err = "failed to create tags";
	if (redis_tags(c, &tags))
		goto err6;

	err = "failed to link sfds";
	if (redis_link_sfds(&sfds, &streams))
		goto err6;
	err = "failed to populate tags";
	if (redis_tags_populate(r, &tags, &streams, &sfds))
		goto err6;
	err = "failed to link streams";
	if (redis_link_streams(&streams, &sfds))
		goto err6;

	err = NULL;
	obj_put(c);

err6:
	rwlock_unlock_w(&c->master_lock);
err5:
	redis_destroy_list(&streams);
err4:
	redis_destroy_list(&sfds);
err3:
	redis_destroy_list(&tags);
err2:
	redis_destroy_hash(&call);
err1:
	log_info_clear();
	if (err) {
		rlog(LOG_WARNING, "Failed to restore call ID '%.*s' from Redis: %s", REDIS_FMT(id), err);
		if (c) {
			call_destroy(c);
			obj_put(c);
		}
	}
}



struct thread_ctx {
	struct callmaster *m;
	GQueue r_q;
	mutex_t r_m;
};
#define RESTORE_NUM_THREADS 4

static void restore_thread(void *call_p, void *ctx_p) {
	struct thread_ctx *ctx = ctx_p;
	redisReply *call = call_p;
	struct redis *r;

	rlog(LOG_DEBUG, "Processing call ID '%.*s' from Redis", REDIS_FMT(call));

	mutex_lock(&ctx->r_m);
	r = g_queue_pop_head(&ctx->r_q);
	mutex_unlock(&ctx->r_m);

	redis_restore_call(r, ctx->m, call);

	mutex_lock(&ctx->r_m);
	g_queue_push_tail(&ctx->r_q, r);
	mutex_unlock(&ctx->r_m);
}

int redis_restore(struct callmaster *m, struct redis *r, int role) {
	redisReply *calls, *call;
	int i, ret = -1;
	GThreadPool *gtp;
	struct thread_ctx ctx;

	if (!r)
		return 0;

	log_level |= LOG_FLAG_RESTORE;

	rlog(LOG_DEBUG, "Restoring calls from Redis...");
	redis_check_conn(r, role);

	calls = redis_get(r, REDIS_REPLY_ARRAY, "SMEMBERS calls");

	if (!calls) {
		rlog(LOG_ERR, "Could not retrieve call list from Redis: %s", r->ctx->errstr);
		goto err;
	}

	ctx.m = m;
	mutex_init(&ctx.r_m);
	g_queue_init(&ctx.r_q);
	for (i = 0; i < RESTORE_NUM_THREADS; i++)
		g_queue_push_tail(&ctx.r_q, redis_new(r->ip, r->port, r->db, role));
	gtp = g_thread_pool_new(restore_thread, &ctx, RESTORE_NUM_THREADS, TRUE, NULL);

	for (i = 0; i < calls->elements; i++) {
		call = calls->element[i];
		if (call->type != REDIS_REPLY_STRING)
			continue;

		g_thread_pool_push(gtp, call, NULL);
	}

	g_thread_pool_free(gtp, FALSE, TRUE);
	while ((r = g_queue_pop_head(&ctx.r_q)))
		redis_close(r);
	ret = 0;
err:
	log_level &= ~LOG_FLAG_RESTORE;
	return ret;
}




static int redis_update_crypto_params(struct redis *r, const char *pref, void *suff,
		const char *key, const struct crypto_params *p)
{
	if (!p->crypto_suite)
		return -1;
	redis_pipe(r, "HMSET %s-%llu %s-crypto_suite %s %s-master_key "PB" %s-master_salt "PB"",
		pref,
		(long long unsigned) suff,
		key, p->crypto_suite->name,
		key, S_LEN(p->master_key, sizeof(p->master_key)),
		key, S_LEN(p->master_salt, sizeof(p->master_salt)));
	if (p->mki)
		redis_pipe(r, "HMSET %s-%llu %s-mki "PB"",
			pref,
			(long long unsigned) suff,
			key,
			S_LEN(p->mki, p->mki_len));

	return 0;
}
static void redis_update_crypto_context(struct redis *r, const char *pref, void *suff,
		const struct crypto_context *c)
{
	if (redis_update_crypto_params(r, pref, suff, "", &c->params))
		return;
	redis_pipe(r, "HMSET %s-%llu last_index "UINT64F"",
		pref,
		(long long unsigned) suff,
		c->last_index);
}
static void redis_update_endpoint(struct redis *r, const char *pref, void *suff,
		const char *key, const struct endpoint *e)
{
	char a[64];

	inet_ntop(AF_INET6, &e->ip46, a, sizeof(a));
	redis_pipe(r, "HMSET %s-%llu %s-addr %s %s-port %hu",
		pref,
		(long long unsigned) suff,
		key, a, key, (short unsigned) e->port);
}
static void redis_update_stats(struct redis *r, const char *pref, void *suff,
		const char *key, const struct stats *s)
{
	redis_pipe(r, "HMSET %s-%llu %s-packets "UINT64F" %s-bytes "UINT64F" %s-errors "UINT64F"",
		pref,
		(long long unsigned) suff,
		key, atomic64_get(&s->packets), key, atomic64_get(&s->bytes),
		key, atomic64_get(&s->errors));
}
static void redis_update_dtls_fingerprint(struct redis *r, const char *pref, void *suff,
		const struct dtls_fingerprint *f)
{
	if (!f->hash_func)
		return;
	redis_pipe(r, "HMSET %s-%llu hash_func %s fingerprint "PB"",
		pref,
		(long long unsigned) suff,
		f->hash_func->name,
		S_LEN(f->digest, sizeof(f->digest)));
}




/* must be called lock-free */
void redis_update(struct call *c, struct redis *r, int role) {
	GSList *l, *n;
	GList *k, *m;
	struct call_monologue *ml;
	struct call_media *media;
	struct packet_stream *ps;
	struct stream_fd *sfd;
	struct endpoint_map *ep;
	char a[64];

	if (!r)
		return;

	mutex_lock(&r->lock);
	redis_check_conn(r, role);

	rwlock_lock_r(&c->master_lock);

	redis_pipe(r, "SREM calls "PB"", STR(&c->callid));
	redis_pipe(r, "DEL call-"PB" tags-"PB" sfds-"PB" streams-"PB"", STR(&c->callid), STR(&c->callid),
		STR(&c->callid), STR(&c->callid));
	smart_ntop_port(a, &c->created_from_addr, sizeof(a));
	redis_pipe(r, "HMSET call-"PB" created %llu last_signal %llu tos %i deleted %llu "
			"ml_deleted %llu created_from %s created_from_addr %s",
		STR(&c->callid), (long long unsigned) c->created, (long long unsigned) c->last_signal,
		(int) c->tos, (long long unsigned) c->deleted, (long long unsigned) c->ml_deleted,
		c->created_from, a);
	/* XXX DTLS cert?? */

	for (l = c->stream_fds; l; l = l->next) {
		sfd = l->data;

		redis_pipe(r, "DEL sfd-%llu", (long long unsigned) sfd);
		redis_pipe(r, "HMSET sfd-%llu localport %hu stream %llu",
			(long long unsigned) sfd, (short unsigned) sfd->fd.localport,
			(long long unsigned) sfd->stream);
		redis_update_crypto_context(r, "sfd", sfd, &sfd->crypto);
		/* XXX DTLS?? */
		redis_pipe(r, "EXPIRE sfd-%llu 86400", (long long unsigned) sfd);
		redis_pipe(r, "LPUSH sfds-"PB" %llu", STR(&c->callid), (long long unsigned) sfd);
	}

	for (l = c->streams; l; l = l->next) {
		ps = l->data;

		mutex_lock(&ps->in_lock);
		mutex_lock(&ps->out_lock);

		redis_pipe(r, "DEL stream-%llu", (long long unsigned) ps);
		redis_pipe(r, "HMSET stream-%llu media %llu sfd %llu rtp_sink %llu "
			"rtcp_sink %llu rtcp_sibling %llu last_packet "UINT64F" "
			"ps_flags %u",
			(long long unsigned) ps,
			(long long unsigned) ps->media,
			(long long unsigned) ps->sfd,
			(long long unsigned) ps->rtp_sink,
			(long long unsigned) ps->rtcp_sink,
			(long long unsigned) ps->rtcp_sibling,
			atomic64_get(&ps->last_packet),
			ps->ps_flags);
		redis_update_endpoint(r, "stream", ps, "endpoint", &ps->endpoint);
		redis_update_endpoint(r, "stream", ps, "advertised_endpoint", &ps->advertised_endpoint);
		redis_update_stats(r, "stream", ps, "stats", &ps->stats);
		redis_update_crypto_context(r, "stream", ps, &ps->crypto);
		/* XXX DTLS?? */

		mutex_unlock(&ps->in_lock);
		mutex_unlock(&ps->out_lock);

		redis_pipe(r, "EXPIRE stream-%llu 86400", (long long unsigned) ps);
		redis_pipe(r, "LPUSH streams-"PB" %llu", STR(&c->callid), (long long unsigned) ps);
	}

	for (l = c->monologues; l; l = l->next) {
		ml = l->data;

		redis_pipe(r, "DEL tag-%llu other_tags-%llu medias-%llu",
			(long long unsigned) ml,
			(long long unsigned) ml,
			(long long unsigned) ml);
		redis_pipe(r, "HMSET tag-%llu created %llu active %llu deleted %llu",
			(long long unsigned) ml,
			(long long unsigned) ml->created,
			(long long unsigned) ml->active_dialogue,
			(long long unsigned) ml->deleted);
		if (ml->tag.s)
			redis_pipe(r, "HMSET tag-%llu tag "PB"",
				(long long unsigned) ml,
				STR(&ml->tag));
		if (ml->viabranch.s)
			redis_pipe(r, "HMSET tag-%llu via-branch "PB"",
				(long long unsigned) ml,
				STR(&ml->viabranch));

		k = g_hash_table_get_values(ml->other_tags);
		for (m = k; m; m = m->next) {
			redis_pipe(r, "RPUSH other_tags-%llu %llu",
				(long long unsigned) ml,
				(long long unsigned) m->data);
		}
		g_list_free(k);

		for (k = ml->medias.head; k; k = k->next) {
			media = k->data;

			redis_pipe(r, "DEL media-%llu streams-%llu maps-%llu",
				(long long unsigned) media, (long long unsigned) media,
				(long long unsigned) media);
			redis_pipe(r, "HMSET media-%llu "
				"type "PB" protocol %s desired_family %i "
				"sdes_in_tag %u sdes_out_tag %u interface "PB" local_address "IP6F" "
				"media_flags %u",
				(long long unsigned) media,
				STR(&media->type), media->protocol ? media->protocol->name : "",
				media->desired_family,
				media->sdes_in.tag, media->sdes_out.tag,
				STR(&media->interface->name), IP6P(&media->local_address->addr.s6_addr),
				media->media_flags);
			redis_update_crypto_params(r, "media", media, "sdes_in", &media->sdes_in.params);
			redis_update_crypto_params(r, "media", media, "sdes_out", &media->sdes_out.params);
			redis_update_dtls_fingerprint(r, "media", media, &media->fingerprint);

			for (m = media->streams.head; m; m = m->next) {
				redis_pipe(r, "RPUSH streams-%llu %llu",
					(long long unsigned) media,
					(long long unsigned) m->data);
			}

			for (n = media->endpoint_maps; n; n = n->next) {
				ep = n->data;

				redis_pipe(r, "DEL map-%llu sfds-%llu",
					(long long unsigned) ep,
					(long long unsigned) ep);
				redis_pipe(r, "HMSET map-%llu wildcard %i",
					(long long unsigned) ep,
					ep->wildcard);
				redis_update_endpoint(r, "map", ep, "endpoint", &ep->endpoint);

				for (m = ep->sfds.head; m; m = m->next) {
					redis_pipe(r, "RPUSH sfds-%llu %llu",
						(long long unsigned) ep,
						(long long unsigned) m->data);
				}

				redis_pipe(r, "EXPIRE map-%llu 86400", (long long unsigned) ep);
				redis_pipe(r, "EXPIRE sfds-%llu 86400", (long long unsigned) ep);
				redis_pipe(r, "LPUSH maps-%llu %llu",
					(long long unsigned) media, (long long unsigned) ep);
			}

			redis_pipe(r, "EXPIRE media-%llu 86400", (long long unsigned) media);
			redis_pipe(r, "EXPIRE streams-%llu 86400", (long long unsigned) media);
			redis_pipe(r, "EXPIRE maps-%llu 86400", (long long unsigned) media);
			redis_pipe(r, "LPUSH medias-%llu %llu",
				(long long unsigned) ml, (long long unsigned) media);
		}

		redis_pipe(r, "EXPIRE tag-%llu 86400", (long long unsigned) ml);
		redis_pipe(r, "EXPIRE other_tags-%llu 86400", (long long unsigned) ml);
		redis_pipe(r, "EXPIRE medias-%llu 86400", (long long unsigned) ml);
		redis_pipe(r, "LPUSH tags-"PB" %llu", STR(&c->callid), (long long unsigned) ml);
	}

	redis_pipe(r, "EXPIRE call-"PB" 86400", STR(&c->callid));
	redis_pipe(r, "EXPIRE tags-"PB" 86400", STR(&c->callid));
	redis_pipe(r, "EXPIRE sfds-"PB" 86400", STR(&c->callid));
	redis_pipe(r, "EXPIRE streams-"PB" 86400", STR(&c->callid));
	redis_pipe(r, "SADD calls "PB"", STR(&c->callid));

	redis_consume(r);
	mutex_unlock(&r->lock);
	rwlock_unlock_r(&c->master_lock);
}





/* must be called lock-free */
void redis_delete(struct call *c, struct redis *r, int role) {
	if (!r)
		return;

	mutex_lock(&r->lock);
	redis_check_conn(r, role);
	rwlock_lock_r(&c->master_lock);

	redis_delete_call(c, r);

	rwlock_unlock_r(&c->master_lock);
	mutex_unlock(&r->lock);
}





void redis_wipe(struct redis *r, int role) {
	if (!r)
		return;

	mutex_lock(&r->lock);
	redis_check_conn(r, role);
	redisCommandNR(r->ctx, "DEL calls");
	mutex_unlock(&r->lock);
}
