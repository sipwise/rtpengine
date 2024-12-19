#include "nftables.h"

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "helpers.h"

#include "xt_RTPENGINE.h"

struct iterate_callbacks {
	// called for each expression
	int (*parse_expr)(struct nftnl_expr *e, void *data);

	// called after all expressions have been parsed
	void (*rule_final)(struct nftnl_rule *r, struct iterate_callbacks *);

	// called after all rules have been iterated
	const char *(*iterate_final)(struct mnl_socket *nl, int family, const char *chain,
			uint32_t *seq, struct iterate_callbacks *);

	// common arguments
	const char *chain;
	const char *base_chain;

	// scratch area for rule callbacks, set to zero for every rule
	union {
		bool rule_matched;
	} rule_scratch;

	// scratch area for rule iterating
	union {
		GQueue handles;
		bool rule_matched;
	} iterate_scratch;
};

struct add_rule_callbacks {
	const char *(*callback)(struct nftnl_rule *, int family, struct add_rule_callbacks *);
	const char *chain;
	const char *base_chain;
	int table;
	bool append;
};



typedef struct nftnl_expr _nftnl_expr;
typedef struct nftnl_rule _nftnl_rule;
typedef struct nftnl_chain _nftnl_chain;
typedef struct nftnl_table _nftnl_table;
typedef struct mnl_socket _mnl_socket;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(_nftnl_expr, nftnl_expr_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(_nftnl_rule, nftnl_rule_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(_nftnl_chain, nftnl_chain_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(_nftnl_table, nftnl_table_free);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(_mnl_socket, mnl_socket_close);



static int match_immediate(struct nftnl_expr *e, void *data) {
	struct iterate_callbacks *callbacks = data;

	uint32_t len;
	const char *n = nftnl_expr_get(e, NFTNL_EXPR_NAME, &len);
	// match jumps to our configured chain
	if (!strcmp(n, "immediate")) {
		n = nftnl_expr_get(e, NFTNL_EXPR_IMM_CHAIN, &len);
		if (n && !strcmp(n, callbacks->chain))
			callbacks->rule_scratch.rule_matched = true;
	}
	return 0;
}

static int match_rtpe(struct nftnl_expr *e, void *data) {
	struct iterate_callbacks *callbacks = data;

	uint32_t len;
	const char *n = nftnl_expr_get(e, NFTNL_EXPR_NAME, &len);
	// match top-level targets
	if (!strcmp(n, "target")) {
		n = nftnl_expr_get(e, NFTNL_EXPR_TG_NAME, &len);
		if (n && !strcmp(n, "RTPENGINE"))
			callbacks->rule_scratch.rule_matched = true;
	}
	return 0;
}

static int match_immediate_rtpe(struct nftnl_expr *e, void *data) {
	match_immediate(e, data);
	match_rtpe(e, data);
	return 0;
}


static void check_matched_queue(struct nftnl_rule *r, struct iterate_callbacks *callbacks) {
	if (!callbacks->rule_scratch.rule_matched)
		return;

	uint64_t handle = nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE);
	g_queue_push_tail(&callbacks->iterate_scratch.handles, g_slice_dup(uint64_t, &handle));
}


static void check_matched_flag(struct nftnl_rule *r, struct iterate_callbacks *callbacks) {
	if (callbacks->rule_scratch.rule_matched)
		callbacks->iterate_scratch.rule_matched = true;
}


static int nftables_do_rule(const struct nlmsghdr *nlh, void *data) {
	struct iterate_callbacks *callbacks = data;

	g_autoptr(_nftnl_rule) r = nftnl_rule_alloc();
	if (!r)
		return MNL_CB_ERROR;

	if (nftnl_rule_nlmsg_parse(nlh, r) < 0)
		return MNL_CB_OK;

	memset(&callbacks->rule_scratch, 0, sizeof(callbacks->rule_scratch));

	if (nftnl_expr_foreach(r, callbacks->parse_expr, callbacks) < 0)
		return MNL_CB_OK;

	if (callbacks->rule_final)
		callbacks->rule_final(r, callbacks);

	return MNL_CB_OK;
}


static const char *__read_response(struct mnl_socket *nl, uint32_t seq, mnl_cb_t cb_data, void *data,
		const char *err1, const char *err2)
{
	uint32_t portid = mnl_socket_get_portid(nl);
	char buf[MNL_SOCKET_BUFFER_SIZE];

	while (true) {
		int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret < 0)
			return err1;
		if (ret == 0)
			break;

		ret = mnl_cb_run(buf, ret, 0, portid, cb_data, data);
		if (ret < 0)
			return err2;
		if (ret == 0)
			break;
	}

	return NULL;
}

// macro for customised error strings
#define read_response(instance, ...) __read_response(__VA_ARGS__, \
		"failed to receive from netlink socket for " instance, \
	"error returned from netlink for " instance)


static const char *iterate_rules(struct mnl_socket *nl, int family, const char *chain,
		uint32_t *seq,
		struct iterate_callbacks *callbacks)
{
	g_autoptr(_nftnl_rule) r = nftnl_rule_alloc();
	if (!r)
		return "failed to allocate rule for iteration";

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, "filter");
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
			NLM_F_DUMP, *seq);

	nftnl_rule_nlmsg_build_payload(nlh, r);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return "failed to write to netlink socket for iteration";

	const char *err = read_response("iterate rules", nl, *seq, nftables_do_rule, callbacks);
	if (err)
		return err;

	if (callbacks->iterate_final)
		err = callbacks->iterate_final(nl, family, chain, seq, callbacks);
	if (err)
		return err;

	return NULL;
}


static bool set_rule_handle(struct nftnl_rule *r, void *data) {
	uint64_t *handle = data;
	nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, *handle);
	return true;
}


static const char *__batch_request(struct mnl_socket *nl, int family, uint32_t *seq,
		uint16_t type, uint16_t flags,
		union {
			void (*table_fn)(struct nlmsghdr *, const struct nftnl_table *);
			void (*rule_fn)(struct nlmsghdr *, struct nftnl_rule *);
			void (*chain_fn)(struct nlmsghdr *, const struct nftnl_chain *);
			void (*generic_fn)(struct nlmsghdr *, void *);
		}  __attribute__ ((__transparent_union__)) build_payload,
		void *ptr,
		const char *err1, const char *err2, const char *err3)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), (*seq)++);
	mnl_nlmsg_batch_next(batch);

	uint32_t req_seq = *seq;
	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			type, family,
			flags | NLM_F_ACK, (*seq)++);
	build_payload.generic_fn(nlh, ptr);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), (*seq)++);
	mnl_nlmsg_batch_next(batch);

	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0)
		return err1;

	mnl_nlmsg_batch_stop(batch);

	return __read_response(nl, req_seq, NULL, NULL, err2, err3);
}

// macro for customised error strings
#define batch_request(instance, ...) __batch_request(__VA_ARGS__, \
		"failed to write to netlink socket for " instance, \
		"failed to receive from netlink socket for " instance, \
		"error returned from netlink for " instance)


static const char *delete_rules(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq,
		bool (*callback)(struct nftnl_rule *r, void *data), void *data)
{
	g_autoptr(_nftnl_rule) r = nftnl_rule_alloc();
	if (!r)
		return "failed to allocate rule for deletion";

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, "filter");
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

	if (callback) {
		if (!callback(r, data))
			return NULL;
	}

	return batch_request("delete rule", nl, family, seq, NFT_MSG_DELRULE, 0,
			nftnl_rule_nlmsg_build_payload, r);
}



static const char *iterate_delete_rules(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq,
		struct iterate_callbacks *callbacks)
{

	while (callbacks->iterate_scratch.handles.length) {
		uint64_t *handle = g_queue_pop_head(&callbacks->iterate_scratch.handles);
		// transfer to stack and free
		uint64_t h = *handle;
		g_slice_free(uint64_t, handle);

		const char *err = delete_rules(nl, family, chain, seq, set_rule_handle, &h);
		if (err)
			return err;
	}
	return NULL;
}


static const char *local_input_chain(struct nftnl_chain *c) {
	nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, 0);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	return NULL;
}


static int nftables_do_chain(const struct nlmsghdr *nlh, void *data) {
	bool *exists = data;

	g_autoptr(_nftnl_chain) c = nftnl_chain_alloc();
	if (!c)
		return MNL_CB_ERROR;

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		return MNL_CB_OK;

	*exists = true;

	return MNL_CB_OK;
}


static const char *chain_exists(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq) {
	g_autoptr(_nftnl_chain) c = nftnl_chain_alloc();

	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, "filter");
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, family,
			NLM_F_ACK, *seq);

	nftnl_chain_nlmsg_build_payload(nlh, c);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return "failed to write to netlink socket for chain exists";

	bool exists = false;
	const char *err = read_response("get chain", nl, *seq, nftables_do_chain, &exists);
	if (err)
		return err;

	return exists ? NULL : "doesn't exist";
}


static const char *add_chain(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq,
		const char *(*callback)(struct nftnl_chain *))
{
	if (chain_exists(nl, family, chain, seq) == NULL)
		return NULL;

	g_autoptr(_nftnl_chain) c = nftnl_chain_alloc();
	if (!c)
		return "failed to allocate chain for adding";

	nftnl_chain_set_u32(c, NFTNL_CHAIN_FAMILY, family);
	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, "filter");
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);

	if (callback) {
		const char *err = callback(c);
		if (err)
			return err;
	}

	return batch_request("add chain", nl, family, seq, NFT_MSG_NEWCHAIN, NLM_F_CREATE,
			nftnl_chain_nlmsg_build_payload, c);
}


static const char *add_rule(struct mnl_socket *nl, int family, uint32_t *seq,
		struct add_rule_callbacks callbacks)
{
	g_autoptr(_nftnl_rule) r = nftnl_rule_alloc();
	if (!r)
		return "failed to allocate rule for adding";

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, "filter");

	const char *err = callbacks.callback(r, family, &callbacks);
	if (err)
		return err;

	return batch_request("add rule", nl, family, seq, NFT_MSG_NEWRULE,
			(callbacks.append ? NLM_F_APPEND : 0) | NLM_F_CREATE,
			nftnl_rule_nlmsg_build_payload, r);
}


static const char *udp_filter(struct nftnl_rule *r, int family) {
	g_autoptr(_nftnl_expr) e = NULL;

	static const uint8_t proto = IPPROTO_UDP;

	e = nftnl_expr_alloc("payload");
	if (!e)
		return "failed to allocate payload expr for UDP filter";

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
	if (family == NFPROTO_IPV4)
		nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, protocol));
	else if (family == NFPROTO_IPV6)
		nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct ip6_hdr, ip6_nxt));
	else
		return "unsupported address family for UDP filter";
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, sizeof(proto));

	nftnl_rule_add_expr(r, e);
	e = NULL;

	e = nftnl_expr_alloc("cmp");
	if (!e)
		return "failed to allocate cmp expr for UDP filter";

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, &proto, sizeof(proto));

	nftnl_rule_add_expr(r, e);
	e = NULL;

	e = nftnl_expr_alloc("counter");
	if (!e)
		return "failed to allocate counter expr for UDP filter";
	nftnl_rule_add_expr(r, e);
	e = NULL;

	return NULL;
}


static const char *input_immediate(struct nftnl_rule *r, int family, struct add_rule_callbacks *callbacks) {
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, callbacks->base_chain);

	const char *err = udp_filter(r, family);
	if (err)
		return err;

	g_autoptr(_nftnl_expr) e = nftnl_expr_alloc("immediate");
	if (!e)
		return "failed to allocate immediate expr";

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, 0);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, NFT_JUMP);
	nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, callbacks->chain);

	nftnl_rule_add_expr(r, e);
	e = NULL;

	return NULL;
}


static const char *rtpe_target_base(struct nftnl_rule *r, struct add_rule_callbacks *callbacks) {
	g_autoptr(_nftnl_expr) e = nftnl_expr_alloc("target");
	if (!e)
		return "failed to allocate target expr for RTPENGINE";

	nftnl_expr_set_str(e, NFTNL_EXPR_TG_NAME, "RTPENGINE");
	nftnl_expr_set_u32(e, NFTNL_EXPR_TG_REV, 0);

	struct xt_rtpengine_info *info = malloc(sizeof(*info));
	if (!info)
		return "failed to allocate target info for RTPENGINE";
	*info = (__typeof__(*info)) { .id = callbacks->table };

	nftnl_expr_set(e, NFTNL_EXPR_TG_INFO, info, sizeof(*info));

	nftnl_rule_add_expr(r, e);
	e = NULL;

	return NULL;
}


static const char *rtpe_target(struct nftnl_rule *r, int family, struct add_rule_callbacks *callbacks) {
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, callbacks->chain);

	const char *err = rtpe_target_base(r, callbacks);
	if (err)
		return err;

	g_autoptr(_nftnl_expr) e = nftnl_expr_alloc("counter");
	if (!e)
		return "failed to allocate counter expr for RTPENGINE";
	nftnl_rule_add_expr(r, e);
	e = NULL;

	return NULL;
}


static const char *rtpe_target_filter(struct nftnl_rule *r, int family, struct add_rule_callbacks *callbacks) {
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, callbacks->chain);

	const char *err = rtpe_target_base(r, callbacks);
	if (err)
		return err;

	err = udp_filter(r, family);
	if (err)
		return err;

	return NULL;
}


static const char *delete_chain(struct mnl_socket *nl, int family, uint32_t *seq, const char *chain) {
	g_autoptr(_nftnl_chain) c = nftnl_chain_alloc();
	if (!c)
		return "failed to allocate chain for deletion";

	nftnl_chain_set_u32(c, NFTNL_RULE_FAMILY, family);
	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, "filter");
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);

	return batch_request("delete chain", nl, family, seq, NFT_MSG_DELCHAIN, 0,
			nftnl_chain_nlmsg_build_payload, c);
}


static const char *nftables_shutdown_family(struct mnl_socket *nl, int family, uint32_t *seq,
		const char *chain, const char *base_chain, nftables_args *dummy)
{
	const char *err;

	if (!base_chain || strcmp(base_chain, "none")) {
		// clean up rules in legacy `INPUT` chain
		err = iterate_rules(nl, family, "INPUT", seq,
				&(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_matched_queue,
					.iterate_final = iterate_delete_rules,
				});
		if (err)
			return err;

		// clean up rules in `input` chain
		err = iterate_rules(nl, family, "input", seq,
				&(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_matched_queue,
					.iterate_final = iterate_delete_rules,
				});
		if (err)
			return err;
	}

	if (base_chain && strcmp(base_chain, "none")) {
		// clean up rules in other base chain chain if any
		err = iterate_rules(nl, family, base_chain, seq,
				&(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_matched_queue,
					.iterate_final = iterate_delete_rules,
				});
		if (err)
			return err;
	}

	// clear out custom chain if it already exists
	err = delete_rules(nl, family, chain, seq, NULL, NULL);
	if (err) {
		if (errno != ENOENT) // ignore trying to delete stuff that doesn't exist
			return err;
	}

	err = delete_chain(nl, family, seq, chain);
	if (err) {
		if (errno != ENOENT && errno != EBUSY) // ignore trying to delete stuff that doesn't exist
			return err;
	}

	return NULL;
}


static const char *add_table(struct mnl_socket *nl, int family, uint32_t *seq) {
	g_autoptr(_nftnl_table) t = nftnl_table_alloc();
	if (!t)
		return "failed to allocate table";

	nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
	nftnl_table_set_str(t, NFTNL_TABLE_NAME, "filter");

	return batch_request("add table", nl, family, seq, NFT_MSG_NEWTABLE, NLM_F_CREATE,
			nftnl_table_nlmsg_build_payload, t);
}


static const char *nftables_setup_family(struct mnl_socket *nl, int family, uint32_t *seq,
		const char *chain, const char *base_chain, nftables_args *args)
{
	const char *err = nftables_shutdown_family(nl, family, seq, chain, base_chain, NULL);
	if (err)
		return err;

	// create the table in case it doesn't exist
	err = add_table(nl, family, seq);
	if (err)
		return err;

	if (base_chain) {
		// add custom chain
		err = add_chain(nl, family, chain, seq, NULL);
		if (err)
			return err;

		if (strcmp(base_chain, "none")) {
			// make sure we have a local input base chain
			err = add_chain(nl, family, base_chain, seq, local_input_chain);
			if (err)
				return err;

			// add jump rule from input base chain to custom chain
			err = add_rule(nl, family, seq, (struct add_rule_callbacks) {
					.callback = input_immediate,
					.chain = chain,
					.base_chain = base_chain,
					.append = args->append,
				});
			if (err)
				return err;
		}

		// add rule for kernel forwarding
		return add_rule(nl, family, seq, (struct add_rule_callbacks) {
				.callback = rtpe_target,
				.chain = chain,
				.table = args->table,
			});
	}
	else {
		// create custom base chain
		err = add_chain(nl, family, chain, seq, local_input_chain);
		if (err)
			return err;

		// add rule for kernel forwarding
		return add_rule(nl, family, seq, (struct add_rule_callbacks) {
				.callback = rtpe_target_filter,
				.chain = chain,
				.table = args->table,
			});
	}
}


static const char *nftables_do(const char *chain, const char *base_chain,
		const char *(*do_func)(struct mnl_socket *nl, int family, uint32_t *seq,
			const char *chain, const char *base_chain, nftables_args *args),
		nftables_args *args)
{
	if (!chain || !chain[0])
		return NULL;
	if (!base_chain[0])
		base_chain = NULL;

	g_autoptr(_mnl_socket) nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!nl)
		return "failed to open netlink socket";

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return "failed to bind netlink socket";

	uint32_t seq = time(NULL);

	const char *err = NULL;

	if (args->family == 0 || args->family == NFPROTO_IPV4)
		err = do_func(nl, NFPROTO_IPV4, &seq, chain, base_chain, args);
	if (err)
		return err;

	if (args->family == 0 || args->family == NFPROTO_IPV6)
		err = do_func(nl, NFPROTO_IPV6, &seq, chain, base_chain, args);
	if (err)
		return err;

	return NULL;
}


static const char *nftables_check_family(struct mnl_socket *nl, int family, uint32_t *seq,
		const char *chain, const char *base_chain, nftables_args *dummy)
{
	// look for our custom module rule in the specified chain

	struct iterate_callbacks callbacks = {
		.parse_expr = match_rtpe,
		.rule_final = check_matched_flag,
	};

	iterate_rules(nl, family, chain, seq, &callbacks);

	if (!callbacks.iterate_scratch.rule_matched)
		return "RTPENGINE rule not found";

	// look for a rule to jump from a base chain to our custom chain

	callbacks = (__typeof__(callbacks)) {
		.parse_expr = match_immediate,
		.chain = chain,
		.rule_final = check_matched_flag,
	};

	iterate_rules(nl, family, "INPUT", seq, &callbacks);
	iterate_rules(nl, family, "input", seq, &callbacks);

	if (base_chain && strcmp(base_chain, "none"))
		iterate_rules(nl, family, base_chain, seq, &callbacks);

	if (!callbacks.iterate_scratch.rule_matched)
		return "immediate-goto rule not found";

	return NULL;
}


const char *nftables_setup(const char *chain, const char *base_chain, nftables_args args) {
	return nftables_do(chain, base_chain, nftables_setup_family, &args);
}

const char *nftables_shutdown(const char *chain, const char *base_chain, nftables_args args) {
	return nftables_do(chain, base_chain, nftables_shutdown_family, &args);
}

int nftables_check(const char *chain, const char *base_chain, nftables_args args) {
	const char *err = nftables_do(chain, base_chain, nftables_check_family, &args);
	if (err) {
		printf("Netfilter rules check NOT successful: %s\n", err);
		return 1;
	}

	printf("Netfilter rules check SUCCESSFUL\n");
	return 0;
}
