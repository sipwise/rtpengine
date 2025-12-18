#include "netfilter_api.h"

//#include <asm/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <glib.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>


struct nfapi_socket {
	int fd;
	struct sockaddr_nl addr; // local
	uint16_t seq;
	GHashTable *msgs;
	uint16_t last_seq;
	uint16_t err_seq;
};

struct nfapi_buf {
	GString *s; // buffer
	ssize_t last_hdr;
	GQueue nested;
	GString *readable;
	uint16_t seq;
};


static const struct sockaddr_nl zero_nl_sockaddr = { .nl_family = AF_NETLINK };


nfapi_socket *nfapi_socket_open(void) {
	int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
	if (fd == -1)
		return NULL;

	int ret = bind(fd, (struct sockaddr *) &zero_nl_sockaddr, sizeof(zero_nl_sockaddr));
	if (ret != 0) {
		close(fd);
		return NULL;
	}

	struct sockaddr_nl saddr;
	socklen_t slen = sizeof(saddr);
	ret = getsockname(fd, (struct sockaddr *) &saddr, &slen);
	if (slen < sizeof(saddr)) {
		close(fd);
		return NULL;
	}

	nfapi_socket *s = g_new0(__typeof(*s), 1);
	s->fd = fd;
	s->addr = saddr;
	s->msgs = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

	return s;
}

void nfapi_socket_close(nfapi_socket *s) {
	if (s->fd != -1)
		close(s->fd);
	g_hash_table_destroy(s->msgs);
	g_free(s);
}

const char *nfapi_err_msg(nfapi_socket *s) {
	const char *m = g_hash_table_lookup(s->msgs, GUINT_TO_POINTER(s->err_seq));
	return m ?: "?";
}


nfapi_buf *nfapi_buf_new(nfapi_socket *s) {
	nfapi_buf *b = g_new0(__typeof(*b), 1);
	b->s = g_string_new("");
	b->last_hdr = -1;
	b->readable = g_string_new("");
	b->seq = ++s->seq;
	return b;
}

void nfapi_buf_free(nfapi_buf *b) {
	g_string_free(b->s, TRUE);
	g_string_free(b->readable, TRUE);
	g_free(b);
}


static void readable_vadd(GString *r, const char *fmt, va_list va) {
	if (r->len > 0)
		g_string_append_c(r, ' ');
	g_string_append_vprintf(r, fmt, va);
}
static void readable_add(GString *r, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	readable_vadd(r, fmt, va);
	va_end(va);
}

static void *buf_add_store(GString *b, size_t s, ssize_t *store) {
	size_t cur = b->len;
	g_string_set_size(b, cur + s);
	if (store)
		*store = cur;
	return b->str + cur;
}

static struct nlmsghdr *hdr_add(nfapi_buf *b, size_t s) {
	return buf_add_store(b->s, s, &b->last_hdr);
}

static struct nlmsghdr *hdr_get_last(nfapi_buf *b) {
	assert(b->last_hdr != -1);
	return (struct nlmsghdr *) (b->s->str + b->last_hdr);
}

static void *item_add(nfapi_buf *b, size_t s) {
	void *ret = buf_add_store(b->s, s, NULL);
	__auto_type hdr = hdr_get_last(b);
	hdr->nlmsg_len += s;
	for (__auto_type l = b->nested.head; l; l = l->next) {
		size_t off = (size_t) l->data;
		struct nlattr *attr = (struct nlattr *) (b->s->str + off);
		attr->nla_len += s;
	}
	return ret;
}

static void add_msg(nfapi_buf *b, uint16_t type, uint16_t family, uint16_t flags, uint16_t seq, uint16_t res_id) {
	struct nlmsghdr *hdr = hdr_add(b, sizeof(*hdr));
	*hdr = (__typeof(*hdr)) {
		.nlmsg_type = type,
		.nlmsg_flags = flags,
		.nlmsg_seq = seq,
		.nlmsg_pid = 0,
		.nlmsg_len = sizeof(*hdr),
	};
	struct nfgenmsg *fam = item_add(b, sizeof(*fam));
	*fam = (__typeof(*fam)) {
		.nfgen_family = family,
		.version = NFNETLINK_V0,
		.res_id = htons(res_id),
	};
}

void nfapi_add_msg(nfapi_buf *b, uint16_t type, uint16_t family, uint16_t flags, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	readable_vadd(b->readable, fmt, va);
	va_end(va);

	return add_msg(b, (NFNL_SUBSYS_NFTABLES << 8) | type, family, flags, b->seq, 0);
}

void nfapi_batch_begin(nfapi_buf *b) {
	add_msg(b, NFNL_MSG_BATCH_BEGIN, AF_UNSPEC, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
}
void nfapi_batch_end(nfapi_buf *b) {
	add_msg(b, NFNL_MSG_BATCH_END, AF_UNSPEC, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
}



void nfapi_add_attr(nfapi_buf *b, uint16_t type, const void *data, size_t len, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	readable_vadd(b->readable, fmt, va);
	va_end(va);

	struct nlattr *attr = item_add(b, sizeof(*attr));
	*attr = (__typeof(*attr)) {
		.nla_type = type,
		.nla_len = sizeof(*attr) + len,
	};
	void *d = item_add(b, NFA_ALIGN(len));
	memset(d, 0, NFA_ALIGN(len));
	memcpy(d, data, len);
}


void nfapi_nested_begin(nfapi_buf *b, uint16_t type, const char *name) {
	g_queue_push_tail(&b->nested, (void *) b->s->len);
	nfapi_add_attr(b, type | NLA_F_NESTED, NULL, 0, "%s: [", name);
}

void nfapi_nested_end(nfapi_buf *b) {
	readable_add(b->readable, "]");
	assert(b->nested.length != 0);
	g_queue_pop_tail(&b->nested);
}



bool nfapi_send_buf(nfapi_socket *s, nfapi_buf *b) {
	char *msg = g_string_free(b->readable, FALSE);
	g_hash_table_replace(s->msgs, GUINT_TO_POINTER(b->seq), msg);
	b->readable = g_string_new("");

	s->last_seq = b->seq;

	ssize_t ret = sendto(s->fd, b->s->str, b->s->len, 0, (struct sockaddr *) &zero_nl_sockaddr,
			sizeof(zero_nl_sockaddr));
	if (ret != b->s->len)
		return false;
	return true;
}

const char *nfapi_recv_iter(nfapi_socket *s, const nfapi_callbacks *c, void *userdata) {
	while (true) {
		int8_t buf[8192];

		union {
			struct sockaddr_storage sst;
			struct sockaddr_nl ssn;
		} ss;
		socklen_t ssl = sizeof(ss);
		errno = 0;
		ssize_t r = recvfrom(s->fd, buf, sizeof(buf), 0, (struct sockaddr *) &ss.sst, &ssl);

		if (r < 0 || r > sizeof(buf)
				|| ssl < sizeof(ss.ssn)
				|| ss.ssn.nl_family != AF_NETLINK
				|| ss.ssn.nl_pid != 0)
			return "error while receiving from netlink socket";

		if (r == 0)
			return NULL;

		size_t off = 0;
		while (off < r) {
			const struct nlmsghdr *hdr;
			if (off + sizeof(hdr) > r)
				return "message too short for header";

			hdr = (struct nlmsghdr *) (buf + off);
			uint16_t subsys = NFNL_SUBSYS_ID(hdr->nlmsg_type);
			uint16_t type = NFNL_MSG_TYPE(hdr->nlmsg_type);

			if (hdr->nlmsg_len == 0)
				return "zero length message";

			size_t next = off + sizeof(*hdr);

			off += hdr->nlmsg_len;

			assert(hdr->nlmsg_pid == s->addr.nl_pid);

			if (subsys == NFNL_SUBSYS_NFTABLES) {
				struct nfgenmsg *fam;
				if (next + sizeof(*fam) > r)
					return "message too short for genmsg";

				fam = (struct nfgenmsg *) (buf + next);
				next += sizeof(*fam);

				if (next > off)
					return "message too short after genmsg";

				if (fam->version != NFNETLINK_V0)
					return "netlink version not v0";

				switch (type) {
					case NFT_MSG_NEWRULE:
						if (c && c->rule)
							c->rule(buf + next, off - next, userdata);
						break;

					case NFT_MSG_NEWCHAIN:
						if (c && c->chain)
							c->chain(buf + next, off - next, userdata);
						break;

					default:
						abort();
				};
			}
			else {
				if (type == NLMSG_DONE) {
					if (hdr->nlmsg_seq != s->last_seq)
						continue;
					return NULL;
				}

				if (type == NLMSG_ERROR) {
					struct nlmsgerr *err;
					errno = ERANGE;
					if (next + sizeof(*err) > r)
						return "error but also message too short";

					err = (struct nlmsgerr *) (buf + next);

					if (err->error == 0) {
						if (hdr->nlmsg_seq != s->last_seq)
							continue;
						return NULL;
					}

					errno = -err->error;
					s->err_seq = hdr->nlmsg_seq;
					return "error returned from netlink, see errno";
				}
				else
					abort();
			}
		}
	}
}

#define foreach_nlattr(l, attr, type, data, data_len, fail_ret) \
	size_t __off = 0; \
 \
	while (__off < l) { \
		const struct nlattr *attr; \
		errno = EMSGSIZE; \
		if (__off + sizeof(*attr) > l) \
			return fail_ret; \
 \
		attr = (struct nlattr *) (buf + __off); \
		errno = ERANGE; \
		if (attr->nla_len == 0 || __off + attr->nla_len > l) \
			return fail_ret; \
 \
		uint16_t type = attr->nla_type & NLA_TYPE_MASK; \
 \
		const int8_t *data = buf + __off + sizeof(*attr); \
		size_t data_len __attribute__((unused)) = attr->nla_len - sizeof(*attr); \
 \
		__off += NFA_ALIGN(attr->nla_len); \


static bool nested_expr_iter(const int8_t *buf, size_t l,
		const char **name, const int8_t **expr_data, size_t *expr_len)
{
	foreach_nlattr(l, attr, type, data, data_len, false)
		switch (type) {
			case NFTA_EXPR_NAME:
				*name = (char *) data;
				break;
			case NFTA_EXPR_DATA:
				*expr_data = data;
				*expr_len = data_len;
				break;
		}
	}

	return true;
}

static bool nested_verdict_iter(const int8_t *buf, size_t l, int32_t *code, const char **chain) {
	foreach_nlattr(l, attr, type, data, data_len, false)
		switch (type) {
			case NFTA_VERDICT_CODE:
				if (data_len != sizeof(int32_t))
					return false;
				*code = ntohl(*(int32_t *) data);
				break;

			case NFTA_VERDICT_CHAIN:
				*chain = (char *) data;
				break;
		}
	}

	return true;
}

static bool nested_immediate_iter(const int8_t *buf, size_t l, int32_t *code, const char **chain) {
	foreach_nlattr(l, attr, type, data, data_len, false)
		if (type == NFTA_DATA_VERDICT) {
			if (!nested_verdict_iter(data, data_len, code, chain))
				return false;
		}
	}

	return true;
}

static const char *expr_iter(const int8_t *buf, size_t l, const nfapi_callbacks *c, void *userdata) {
	foreach_nlattr(l, attr, type, data, data_len, "error in expression message format")
		if (type != NFTA_LIST_ELEM)
			return "not a list element";

		const char *name = NULL;
		const int8_t *expr_data = NULL;
		size_t expr_len = 0;

		if (!nested_expr_iter(data, data_len, &name, &expr_data, &expr_len))
			return "error in expression items";

		if (!name)
			return "expression has no name";

		if (c && c->expression) {
			const char *err = c->expression(name, expr_data, expr_len, userdata);
			if (err)
				return err;
		}
	}

	return NULL;
}

const char *nfapi_rule_iter(const int8_t *buf, size_t l, const nfapi_callbacks *c, void *userdata) {
	//const char *table = NULL;
	//const char *chain = NULL;
	int64_t handle = -1;

	foreach_nlattr(l, attr, type, data, data_len, "error in rule message format")
		switch (type) {
			case NFTA_RULE_TABLE:
				//table = data;
				//printf("table %s\n", data);
				break;

			case NFTA_RULE_CHAIN:
				//chain = data;
				//printf("chain %s\n", data);
				break;

			case NFTA_RULE_HANDLE:
				if (data_len != sizeof(handle))
					return "handle size incorrect";
				handle = *(int64_t *) data;
				if (c && c->handle)
					c->handle(handle, userdata);
				break;

			case NFTA_RULE_USERDATA:;
				const struct {
					uint16_t len;
					char comment[];
				} *comment = (void *) data;
				if (c && c->comment && data_len <= ntohs(comment->len) + 2)
					c->comment(comment->comment, userdata);
				break;

			case NFTA_RULE_EXPRESSIONS:;
				const char *err = expr_iter(data, data_len, c, userdata);
				if (err)
					return err;
				break;
		}
	}

	return NULL;
}

const char *nfapi_get_immediate_chain(const int8_t *buf, size_t l) {
	const char *chain = NULL;
	int32_t verdict_code = 0;

	foreach_nlattr(l, attr, type, data, data_len, NULL)
		if (type == NFTA_IMMEDIATE_DATA && data_len >= sizeof(struct nlattr)) {
			if (!nested_immediate_iter(data, data_len, &verdict_code, &chain))
				return NULL;
		}
	}

	if ((verdict_code == NFT_JUMP || verdict_code == NFT_GOTO) && chain)
		return chain;

	return NULL;
}

const char *nfapi_get_target(const int8_t *buf, size_t l, void *info, size_t *info_len) {
	const char *tg = NULL;

	size_t buf_len = 0;
	if (info_len && info) {
		buf_len = *info_len;
		*info_len = 0;
	}

	foreach_nlattr(l, attr, type, data, data_len, NULL)
		switch (type) {
			case NFTA_TARGET_NAME:
				tg = (char *) data;
				break;

			case NFTA_TARGET_INFO:
				if (!buf_len)
					break;
				buf_len = MIN(buf_len, data_len);
				memcpy(info, data, buf_len);
				*info_len = buf_len;
				break;
		}
	}

	return tg;
}
